package mracme;

import clojure.java.api.Clojure;
import clojure.lang.IFn;
import clojure.lang.IFn.DDDDL;

import java.io.File;
import java.io.FileFilter;
import java.util.concurrent.Callable;

public class Main {
    public String howdy() {
        return "Hi there";
    }

    public static Object callClojure(String ns, String fn) throws Exception {
        // load Clojure lib. See https://clojure.github.io/clojure/javadoc/clojure/java/api/Clojure.html
        IFn require = Clojure.var("clojure.core", "require");
        require.invoke(Clojure.read(ns));

        return ((Callable) Clojure.var(ns, fn)).call();
    }

    public static IFn getFn(String ns, String fn) throws Exception {
        // load Clojure lib. See https://clojure.github.io/clojure/javadoc/clojure/java/api/Clojure.html
        IFn require = Clojure.var("clojure.core", "require");
        require.invoke(Clojure.read(ns));

        return Clojure.var(ns, fn);
    }
    
    public static void main(String[] args) throws Exception {
        // Clojure fns are callable
        IFn fn = getFn("mr-acme", "create-hello-fn");
        System.out.println("fn says " + fn.invoke(new Main()));
    }
}
