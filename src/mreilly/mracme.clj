(ns mreilly.mracme
  (:import (java.io Reader)
           (java.nio.charset StandardCharsets)
           (java.security Security MessageDigest)
           (java.util Base64)
           (org.bouncycastle.asn1 ASN1ObjectIdentifier)
           (org.bouncycastle.asn1.x509 X509Name
                                       GeneralNames)
           (org.bouncycastle.jce.provider BouncyCastleProvider)
           (org.bouncycastle.openssl PEMParser)
           (org.bouncycastle.openssl.jcajce JcaPEMKeyConverter)
           (org.bouncycastle.util BigIntegers))
  (:require [clojure.data.json :as json])
  (:gen-class))

 

(def common-name ;(ASN1ObjectIdentifier. "2.5.4.3")
  X509Name/CN
  )
(def extension-request        (ASN1ObjectIdentifier. "1.2.840.113549.1.9.14"))
(def subject-alternative-name (ASN1ObjectIdentifier. "2.5.29.17"))

(defn init[]
  (Security/addProvider (BouncyCastleProvider.)))

(init)

(defn parse-pem
  [pem-file]
  (with-open [rdr (clojure.java.io/reader pem-file)]
    (let [pp (PEMParser. rdr)]
      (.readObject pp))))

(defn to-rsa-private-key [private-key-info]
  (let [converter  (.setProvider (JcaPEMKeyConverter.) "BC")]
    (.getPrivateKey converter private-key-info)))

(defn bigint-to-bytes-without-leading-zero[big-int]
  (BigIntegers/asUnsignedByteArray big-int))

(defn to-base64[bytes]  
  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bytes))

(defn bigint-to-base64[big-int]  
  (to-base64 (bigint-to-bytes-without-leading-zero big-int)))


(defn parse-account-key[account-key-file]
  (let [pk (to-rsa-private-key (parse-pem account-key-file))]
    (sorted-map 
     "e" (bigint-to-base64 (.getPublicExponent pk))
     "kty" "RSA"
     "n" (bigint-to-base64 (.getModulus pk)))))

(defn sha256[text]
  (let [digest (MessageDigest/getInstance "SHA-256")]
    (.digest  digest (.getBytes text StandardCharsets/UTF_8))))

;; thumbprint
(let [jwk (parse-account-key "/home/mreilly/acme-tiny/scratch/account.key")]
  (to-base64 (sha256 (json/write-str jwk))))
 
;; Parsing CSR...

(defn parse-csr[csr-filename]
  (parse-pem csr-filename))

(defn rdn-first-value [rdn-array]
  (.toString (.getValue (.getFirst (aget rdn-array 0)))))

(defn get-common-name [csr]
  (rdn-first-value (.getRDNs (.getSubject csr) common-name)))

(get-common-name (parse-csr "/home/mreilly/acme-tiny/scratch/domain.csr"))


(defn asn1-set-to-seq[asn1-set]
  (let [size (.size asn1-set)]
    (loop [idx 0
           acc []]
      (if (= idx size)
        acc
        (recur (inc idx) (conj acc (.getObjectAt asn1-set idx)))))))



(defn get-extensions[csr]
  (flatten  (map
             (fn[attribute] (asn1-set-to-seq (.getAttrValues attribute)))
             (seq (.getAttributes csr extension-request)))))

(defn octet-string-to-names[octet-string]
  (map (fn[n] (.toString
               (.getName n)))
       (seq (.getNames (GeneralNames/getInstance (.getOctets octet-string))))))

(defn subject-alt-names[csr]
  (let [der-seq (flatten (map asn1-set-to-seq (flatten (map asn1-set-to-seq (get-extensions csr)))))]
    (loop [der-seq der-seq acc []]
      (let [[name octet-string & rst] der-seq]
        (if name
          (recur rst
                 (if (= subject-alternative-name name)
                   (into acc (octet-string-to-names octet-string))
                   acc))
          acc)))))

(defn get-domains[csr]
  (into
   (sorted-set (get-common-name csr))
   (subject-alt-names csr)))

(get-domains (parse-csr "/home/mreilly/acme-tiny/scratch/domain.csr"))



;; Found domains: acme-test.mreilly.munichre.cloud
;; Getting directory...
;; Directory found!
;; Registering account...
;; Registered!
;; Creating new order...
;; Order created!
;; Verifying acme-test.mreilly.munichre.cloud...
;; acme-test.mreilly.munichre.cloud verified!
;; Signing certificate...
;; Certificate signed!

