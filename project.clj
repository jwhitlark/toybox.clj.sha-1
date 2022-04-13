(defproject toybox.clj.sha-1 "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.11.1"]
                 [clojurewerkz/buffy "1.1.0"]
                 [defun "0.3.1"]
                 ]

  :java-source-paths ["src"]
  :profiles {:uberjar {:aot :all}
             :dev {:source-paths ["dev"]
                   :dependencies [[org.clojure/tools.namespace "1.2.0"]
                                  [org.clojure/java.classpath "1.0.0"]
                                  [com.gfredericks/test.chuck "0.2.13"]
                                  [org.clojure/tools.trace "0.7.11"]
                                  [org.clojure/test.check "1.1.1"]]}})
