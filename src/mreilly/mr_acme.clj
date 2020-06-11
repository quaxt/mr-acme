(ns mreilly.mr-acme
  (:require [clojure.java [io :as io]]
            [clojure.java.shell :refer [sh with-sh-dir]]
            [clojure.string :as str]
            [clojure.data.json :as json])
  (:import
   [java.net URL]
   [java.nio.file Files OpenOption Paths StandardCopyOption]
   [java.nio ByteBuffer]
   [java.nio.charset StandardCharsets]
   [java.util Base64]
   [java.security MessageDigest KeyStore KeyPair KeyPairGenerator
    PKCS10
    KeyStore$PasswordProtection
    Signature
    Security]
   [org.apache.http.impl.client HttpClients]
   [org.apache.http.client.methods HttpGet HttpHead HttpPost]
   [org.apache.http.util EntityUtils]
   [org.apache.http.entity StringEntity]))

(defn to-base64[src]
  (let [encoded (.encode (.withoutPadding (Base64/getUrlEncoder)) src)
        bytes (if (instance? ByteBuffer encoded)
                (.array encoded)
                encoded)]
    (String. bytes
             StandardCharsets/ISO_8859_1)))

(defn string-to-base64[str]
  (let [bytes (.getBytes str StandardCharsets/UTF_8)]
    (to-base64 bytes)))

(defn big-int-to-base64[big-int]
  (to-base64 (let [array  (.toByteArray big-int)]
               (if (zero? (aget array 0))
                 (ByteBuffer/wrap array 1 (dec (alength array)))
                 array))))


(defn to-json-web-key[key]
  (sorted-map 
   "e" (big-int-to-base64 (.getPublicExponent key))
   "kty" "RSA"
   "n" (big-int-to-base64 (.getModulus key))))

(defn gen-key-pair[]
  (let [keyGen (KeyPairGenerator/getInstance "RSA")]
    (.initialize keyGen 4096)
    (.genKeyPair keyGen)))

(defn get-path [first & rest]
  (Paths/get first
             (into-array String rest)))

(defn new-buffered-writer [path & options]
  (Files/newBufferedWriter path
             (into-array OpenOption options)))

(defn copy-file [source-path dest-path]
  (io/copy (io/file source-path) (io/file dest-path)))

(defn delete-file [path]
  (Files/deleteIfExists path))

(defn create-key-store[]
  (let [dir "/home/mreilly/wa/mr-acme/pg3"
        fname "keystore.p12"
        account-alias "account-key"
        domain-alias  "domain-key"]
    (delete-file (get-path dir fname))
    (with-sh-dir dir
      (sh
       "keytool" "-genkeypair" "-storepass" "changeit" "-keyalg" "rsa" "-keystore" fname "-dname" "CN=Michael, OU=unknown, O=unknown, L=unknown, ST=unknown, C=unknown" "-keysize" "4096" "-alias" account-alias "-keypass" "changeit")
      (sh
       "keytool" "-genkeypair" "-storepass" "changeit" "-keyalg" "rsa" "-keystore" fname "-dname" "CN=Michael, OU=unknown, O=unknown, L=unknown, ST=unknown, C=unknown" "-keysize" "4096" "-alias" domain-alias "-keypass" "changeit"))))

(defn get-csr
  [dir
   fname
   account-alias
   domain-alias]
  (with-sh-dir dir    
    (sh "keytool" "-certreq" "-storepass" "changeit" "-keystore" fname "-alias" domain-alias "-ext" "SAN=dns:mr.quaxt.ie" "-keypass" "changeit")))

(defn set-headers[request headers]
  (doseq [[name value] headers]
    (.setHeader request name value)))

(defn curl[{:keys [url method body headers] :or {method :get}}]
  (println "url=" url)
  (let [http-client (HttpClients/createDefault)
        request  (case method
                   :head (HttpHead. url)
                   :get (HttpGet. url)
                   :post (let [requestEntity (StringEntity. body)
                         post  (HttpPost. url)]
                     (.setEntity post requestEntity)
                     post))
        _ (when headers (set-headers request headers))
        response (.execute http-client request)
        status-line (.getStatusLine response)
        cooked {:headers (let [xs (.getAllHeaders response)]
                           (areduce xs i ret (array-map)
                                    (let [header (aget xs i)]
                                      (assoc ret (.getName header) (.getValue header)))))
                
                :reason (.getReasonPhrase status-line)
                :status-code (.getStatusCode status-line)}
        entity (.getEntity response)]
    (if entity (assoc cooked :body (EntityUtils/toString (.getEntity response)))
        cooked)))

(defn sign[data key]
  (let [sig  (Signature/getInstance "SHA256withRSA")]
    (.initSign sig key)
    (.update sig data)
    (.sign sig)))

(defn raw-send-signed-request [{:keys [url payload err-msg dir
                                   private-key alg account-headers jwk]
                            :or {depth 0}}]
  
  (let [payload64 (if payload
                    (string-to-base64 (json/write-str payload))
                    "")
        new-nonce  (-> (curl {:url (dir "newNonce") :method :head})
                       (get-in [:headers "Replay-Nonce"]))
        protected  {"url" url, "alg" alg, "nonce" new-nonce}
        protected (merge protected
                         (if account-headers 
                           {"kid" (account-headers "Location")}
                           {"jwk" jwk}))
        protected64 (string-to-base64 (json/write-str protected))
        protected-input (-> (str protected64 \. payload64)
                            (.getBytes StandardCharsets/UTF_8))
        out (sign protected-input private-key)
        data (json/write-str
              {"protected" protected64
               "payload" payload64
               "signature" (to-base64 out)})]
    (curl {:url url :method :post
           :body data
           :headers {"Accept-Language" "en",
                     "Content-Type" "application/jose+json"}})))

(defn- bad-nonce [cnt]
  (println "bad nonce retry " cnt))

(defn- bad-nonce? [response]
  (and
   (= 400
      (:status-code response))
   (= "urn:ietf:params:acme:error:badNonce"
      ((-> response :body json/read-str) "type"))))

(defn send-signed-request
  "like raw-send-signed but retries requests if response is 400 bad nonce"
  [request]
  (loop [cnt 0]
    (let [response (raw-send-signed-request request)]
      (if (and (< cnt 100) (bad-nonce? response))
        (do
          (bad-nonce cnt)
          (recur (inc cnt)))
        response))))

(defn create-account[]
  (let [dir (json/read-str (:body (curl {:url "https://pebble:14000/dir"})))
        new-account-url (get dir "newAccount")
        new-nonce (get dir "newNonce")
        nonce-resp (curl {:url new-nonce :method :head})
        nonce (get-in nonce-resp [:headers "Replay-Nonce"])]
    (send-signed-request {:url new-account-url
                          :dir dir
                          :method :post
                          :body "{\"not\":  \"valid body\"}"
                          :headers
                          {"Accept-Language" "en",
                           "Content-Type" "application/jose+json"}})))

(defn get-key-pair
  [keystore alias password] 
  (let[ key (.getKey  keystore alias (.toCharArray password))
       cert (.getCertificate keystore alias)
       publicKey (.getPublicKey cert)]
    (KeyPair. publicKey key)))

(defn load-key-store
  [ keystoreFile
   password ]
  (let [keystoreUri  (.toUri keystoreFile)
        keystoreUrl  (.toURL keystoreUri)
        keystore  (KeyStore/getInstance (KeyStore/getDefaultType))]
(with-open [is  (.openStream keystoreUrl)]
    (.load keystore is (when password  (.toCharArray password))))
      keystore))

(defn hexify "Convert byte sequence to hex string" [coll]
  (let [hex [\0 \1 \2 \3 \4 \5 \6 \7 \8 \9 \a \b \c \d \e \f]]
      (letfn [(hexify-byte [b]
        (let [v (bit-and b 0xFF)]
          [(hex (bit-shift-right v 4)) (hex (bit-and v 0x0F))]))]
        (apply str (mapcat hexify-byte coll)))))

(defn update-contact
  "the headers passed in here will be the ones returned in the new-account request"
  [headers jwk directory contact private-key]
  (send-signed-request
                   {:account-headers headers
                    :private-key private-key
                    :url (headers "Location")
                    :dir directory
                    :payload  {"contact" contact}
                    :alg "RS256"
                    :jwk jwk}))

(defn new-account
  [private-key directory reg-payload jwk]
  (send-signed-request
   {:private-key private-key
    :url (directory "newAccount")
    :dir directory
    :payload reg-payload
    :alg "RS256"
    :jwk jwk}))

(defn new-order
  [headers private-key directory domains jwk]
  (let [order-payload  {"identifiers"
                        (for [d domains]
                          {"type" "dns", "value" d})
                        }]
    (send-signed-request
     {:account-headers headers
      :private-key private-key
      :url (directory "newOrder")
      :dir directory
      :payload order-payload
      :alg "RS256"
      :jwk jwk})))

(defn get-authorizations
  [account-headers private-key directory jwk order]
  (doall (for [auth-url  (order  "authorizations")]
           (assoc (send-signed-request
                  {:account-headers account-headers
                   :private-key private-key
                   :url auth-url
                   :dir directory
                   ;;:payload order-payload
                   :alg "RS256"
                   :jwk jwk})
                  :authorization-url auth-url))))

(defn get-thumbprint
  "the computation specified in
   [RFC7638], using the SHA-256 digest [FIPS180-4]."
  [jwk]
  (to-base64 
   (.digest 
    (MessageDigest/getInstance "SHA-256") 
    (.getBytes  (json/write-str jwk)
                StandardCharsets/UTF_8))))

(defn do-until [pred task]
  (let [ret  (task)]
    (if (pred ret) ret
        (do (Thread/sleep 2000)
            (recur pred task)))))

(defn validate
  "satisfy http-challenge for the authorization"
  [authorization thumbprint jwk well-known-dir account-headers private-key directory]
  (let [authorization-url (:authorization-url authorization)
        authorization (-> authorization  :body
                          json/read-str)
        domain-name (get-in authorization ["identifier" "value"])
        _ (println "validating " domain-name)
        challenge (->> (authorization "challenges")
                       (filter
                        #(= (% "type") "http-01"))
                       first)
        token (challenge "token")
        challenge-url (challenge "url")]
    (spit 
     (new-buffered-writer 
      (get-path well-known-dir token)) 
     (str token \. 
          (get-thumbprint jwk)))
    (send-signed-request
            {:account-headers account-headers
             :private-key private-key
             :url challenge-url
             :payload {}
             :dir directory
             :alg "RS256"
             :jwk jwk})
    (do-until
     #(-> %
          :body
          json/read-str
          (get "status")
          (= "pending")
          not)
     #(send-signed-request
            {:account-headers account-headers
             :private-key private-key
             :url authorization-url
             :dir directory
             :alg "RS256"
             :jwk jwk}))))

(def xxx (let [contact ["mailto:bogus@test.com"]
               domains ["mr.quaxt.ie"]
               well-known-dir "/var/www/challenges/"
               private-key (.getPrivate
                            (get-key-pair 
                             (load-key-store
                              (get-path "/home/mreilly/wa/mr-acme/pg3/keystore.p12")
                              "changeit")
                             "account-key" "changeit"))
               jwk (to-json-web-key private-key)
               directory-url "https://pebble:14000/dir"
               directory (-> (curl {:url directory-url})
                             :body
                             json/read-str)
               _ (println "Directory found!")
               _ (println "Registering account...")
               reg-payload  {"termsOfServiceAgreed" true}
               account (new-account private-key directory reg-payload jwk)
               account-headers (:headers account)
               _ (println (if (= 201 (:status-code account))
                            "Registered!"
                            "Already registered!"))
               account (if contact
                         (update-contact account-headers jwk directory contact private-key)
                         account)
               _ (println "Creating new order...")
               order-resp (new-order account-headers private-key directory domains jwk)
               _ (println "Order created!")
               order (json/read-str (:body order-resp))
               authorizations (get-authorizations account-headers private-key directory jwk order)
               thumbprint (get-thumbprint jwk)
               validations (doall (map (fn[authorization]
                                         (validate
                                          authorization thumbprint jwk
                                          well-known-dir account-headers
                                          private-key directory)) authorizations))
               _ (println "validation done")]
      ;; now send csr and poll until cert arrives     
           validations))
;; => #'mreilly.mr-acme/xxx
xxx





(defn make-csr[domain-key-pair]
  (let[
       CN  "Mr Foo"
       OU  "Foo Department"
       O  "Foo Ltd."
       L  "Foosville"
       S  "Foouisiana"
       C  "GB"
       pkcs10 (PKCS10. (.getPublic domain-key-pair))
       signature  (doto (Signature/getInstance "SHA1WithRSA")
                    (.initSign (.getPrivate domain-key-pair))) 
       
       x500Name  (X500Name. CN, OU, O, L, S, C)]
    (.encodeAndSign pkcs10 (X500Signer. signature, x500Name))
    (with-open [bs (ByteArrayOutputStream.)
                ps (PrintStream. bs)]
      (.print pkcs10 ps)
      (.toByteArray bs))))


(make-csr (get-key-pair
           (load-key-store
                              (get-path "/home/mreilly/wa/mr-acme/pg3/keystore.p12")
                              "changeit")
                             "domain-key" "changeit"))


(get-csr [ "/home/mreilly/wa/mr-acme/pg3"
          "keystore.p12"
          "domain-key"])