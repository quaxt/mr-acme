package example;

import clojure.java.api.Clojure;
import clojure.lang.IFn;

import java.io.File;
import java.io.FileFilter;
import java.util.concurrent.Callable;

public class Main {
    public static Object callClojure(String ns, String fn) throws Exception {
        // load Clojure lib. See https://clojure.github.io/clojure/javadoc/clojure/java/api/Clojure.html
        IFn require = Clojure.var("clojure.core", "require");
        require.invoke(Clojure.read(ns));

        return ((Callable) Clojure.var(ns, fn)).call();
    }
    public static void main(String[] args) throws Exception {
        // Clojure fns are callable
        Callable fn = (Callable) callClojure("mr-acme", "create-hello-fn");
        System.out.println("fn says " + fn.call());

    }


}
