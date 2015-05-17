(defproject toybox.clj.sha-1 "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.7.0-beta2"]
                 [clojurewerkz/buffy "1.0.1"]
                 ]

  :java-source-paths ["src"]
  :profiles {:uberjar {:aot :all}
             :dev {:source-paths ["dev"]
                   :dependencies [[org.clojure/tools.namespace "0.2.10"]
                                  [org.clojure/java.classpath "0.2.2"]
                                  [criterium "0.4.3"]
                                  [com.gfredericks/test.chuck "0.1.17"]
                                  [org.clojure/tools.trace "0.7.8"]
                                  [org.clojure/test.check "0.8.0-ALPHA"]]}}


)
