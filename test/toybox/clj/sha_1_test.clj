(ns toybox.clj.sha-1-test
  (:require [clojure.test :refer :all]
            [com.gfredericks.test.chuck.clojure-test :refer [checking]]
            [clojure.test.check :as tc]
            [clojurewerkz.buffy.core :as bin]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [toybox.clj.sha-1 :refer :all])
  (:import [java.security MessageDigest]
           [Digest]))

(deftest check-known-correct-sha-1
  (testing "Known correct, from Wikipedia spec."
    (is (= (toHexString (known-correct-sha1 ""))
           "da39a3ee5e6b4b0d3255bfef95601890afd80709"))
    (is (= (toHexString (known-correct-sha1 "The quick brown fox jumps over the lazy dog"))
           "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"))))

(deftest my-sha
  (testing "Array is correct size"
    (is (= 64 (.maxCapacity (bin/buffer (make-spec "")))))
    (is (= 64 (.maxCapacity (bin/buffer (make-spec "foo")))))
    (is (= 64 (.maxCapacity (bin/buffer (make-spec "berfin"))))))
  (testing "First split works"
    (is (= 16 (count (make-words (make-spec "")))))
    (is (= 16 (count (make-words (make-spec "foo")))))
    (is (= 16 (count (make-words (make-spec "berfin"))))))
  (testing "View bits"
    (is (= "1" (view-bits 1)))
    (is (= "101" (view-bits 5)))
    (is (= (apply str (repeat 32 "1")) (view-bits 0xffffffff)))
    (is (= (apply str (repeat 36 "1")) (view-bits 0xfffffffff)))
    (is (= (apply str "1" (repeat 31 "0")) (view-bits 0x80000000))))
  (testing "Truncate long to int (32 bits)"
    (is (= 1 (long->int 1)))
    (is (= 5 (long->int 5)))
    (is (= 0xffffffff (long->int 0xffffffff)))
    (is (= 0xffffffff (long->int 0xfffffffff))))
  (testing "Rotate left"
    (is (= 0 (rotate-left 0)))
    (is (= 2 (rotate-left 1)))
    (is (= 1 (rotate-left 0x80000000)))
    (is (= 0 (rotate-left 0 4)))
    (is (= 16 (rotate-left 1 4)))
    (is (= 8 (rotate-left 0x80000000 4))))
  (testing "Testing extend words"
    (is (= 80 (count (extend-words (make-words (make-spec ""))))))
    (is (= 80 (count (extend-words (make-words (make-spec "foo"))))))
    (is (= 80 (count (extend-words (make-words (make-spec "berfin")))))))
  (testing "Compare sections to Java impl."
    ;; so, pad works, rotate works, extend-words, index-words, and final works.
    ;; extend-words and index-words were manually compared
    (is (= (->> (byte-array 0) (.padTheMessage (Digest.)) (apply vector))
           (->> (make-spec "") (bin/buffer) (.array) (apply vector))))
    (is (= (->> (.getBytes "b") (.padTheMessage (Digest.)) (apply vector))
           (->> (make-spec "b") (bin/buffer) (.array) (apply vector))))

    (is (= (.rotateLeft (Digest.) 10 2)
           (rotate-left 10 2)))
    (is (= (.rotateLeft (Digest.) (.intValue 0x80000000) 4)
           (rotate-left (.intValue 0x80000000) 4)))
    ;; (is (= (known-correct-sha1 "") ;; following line is what runs the printout.
    ;;        (rest (apply vector (.toByteArray (final (apply vector (.digestIt (Digest.) (byte-array 0)))))))))

    )

  (testing "End to end"
    (is (= (known-correct-sha1 "") (sha1 "")))
    (is (= (known-correct-sha1 "b") (sha1 "b")))
    (is (= (known-correct-sha1 "berfin") (sha1 "berfin")))
    (is (= (known-correct-sha1 "The quick brown fox jumps over the lazy dog") (sha1 "The quick brown fox jumps over the lazy dog")))
    (is (= (known-correct-sha1 "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.")
           (sha1 "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.")))
    )


  )

;; after last transform.
;; H0:-633756690
;; H1:1584089869
;; H2:844480495
;; H3:-1788864368
;; H4:-1344796919

#_ (deftest unsearched-failure
     (checking "incorrect" 100 [i gen/pos-int]
               (is (< i 50))
               (is (= i i))))
