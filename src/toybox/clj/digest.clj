(ns toybox.clj.digest
  (:require [clojure.pprint :as pp :refer [pprint]]
            [clojure.string :as str]
            [clojure.reflect :as r]
            [clojurewerkz.buffy.core :as buffy]
            [toybox.clj.util.b-tools :refer :all]
            [clojurewerkz.buffy.util :refer [hex-dump] :as util])
  (:import [java.security MessageDigest]


           [java.nio ByteBuffer]
           [java.util BitSet]
           ))

(defn known-correct-sha1 [s]
  (apply vector (.digest (MessageDigest/getInstance "SHA1") (.getBytes s))))

(def empty-msg "")
(def short-msg "The quick brown fox jumps over the lazy dog")
(def long-msg "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.")

(def initial-h {:h0 0x67452301
                :h1 0xEFCDAB89
                :h2 0x98BADCFE
                :h3 0x10325476
                :h4 0xC3D2E1F0})

(def k1 0x5A827999)
(def k2 0x6ED9EBA1)
(def k3 0x8F1BBCDC)
(def k4 0xCA62C1D6)

(declare extend-words)

(def chunk-size 512)

(defn pad-length [msg]
  (- 64 (mod (+ 8 (count msg)) 64)))

(defn make-spec [msg]
  (let [ msg-spec (buffy/spec :msg (buffy/string-type (count msg))
                            :padding (buffy/bit-type 1)
                            :rest-padding (buffy/bit-type (dec (pad-length msg)))
                            :msg-size (buffy/long-type))
        buf (buffy/compose-buffer msg-spec :buffer-type :heap)]
    (buffy/set-field buf :msg msg)
    (buffy/set-field buf :padding [false false false false false false false true])
    (buffy/set-field buf :msg-size (len-bits msg))
    buf))

;; split into 16 32-bit words (big endian)
(defn make-chunks [msg]
  (->> (make-spec msg)
    buffy/buffer
    (.array)
    (apply vector)
    (partition 4)
    (map bytes->int)
    (partition 16)
    (map #(into [] %))
    (map extend-words)
    (map index-items)))

(defn next-word [wds]
  (let [rev-wds (reverse wds)]
    (-> (nth rev-wds 2)
        (bit-xor (nth rev-wds 7))
        (bit-xor (nth rev-wds 13))
        (bit-xor (nth rev-wds 15))
        rotate-left
        (->> (conj wds)))))

(defn extend-words [init-wds]
  ;; Extend the sixteen 32-bit words into eighty 32-bit words:
  ;; for i from 16 to 79
  ;; w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1

  ;; 16 = (w 13) xor (w 8) xor (w 2) xor (w 0) , leftrotate 1

  (->> init-wds
       (iterate next-word)
       (drop-while #(> 80 (count %)))
       first))

(defn proc-main [{:keys [h0 h1 h2 h3 h4]}
                 {:keys [a b c d e]}]
  ;; Add this chunk's hash to result so far:
  {:h0 (+ h0 a)
   :h1 (+ h1 b)
   :h2 (+ h2 c)
   :h3 (+ h3 d)
   :h4 (+ h4 e)})

(defn subproc [a b c d e f wd k]
  {:a (.intValue (apply + [(rotate-left a 5) f e k wd]))
   :b a
   :c (rotate-left b 30)
   :d c
   :e d})

(defn main-loop [{:keys [h0 h1 h2 h3 h4] :as h-all} chunk]
  (loop [a h0, b h1, c h2, d h3, e h4, idx-wd (first chunk), remaining (rest chunk)]
    (let [[i wd] idx-wd
          nxt (cond
                (<= 0 i 19)
                  (let [f (bit-or (bit-and b c) (bit-and (bit-not b) d))]
                    (subproc a b c d e f wd k1))

                (<= 20 i 39)
                  (let [f (-> b (bit-xor c) (bit-xor d))]
                    (subproc a b c d e f wd k2))

                (<= 40 i 59)
                  (let [f (bit-or
                           (bit-or (bit-and b c)
                                   (bit-and b d))
                           (bit-and c d))]
                    (subproc a b c d e f wd k3))

                (<= 60 i 79)
                  (let [f  (-> b (bit-xor c) (bit-xor d))]
                    (subproc a b c d e f wd k4)))]

      (if (not (seq remaining))
        (proc-main h-all nxt)
        (recur (:a nxt) (:b nxt) (:c nxt) (:d nxt) (:e nxt) (first remaining) (rest remaining))))))

(def tb #(->big (long->int %)))

(defn final
  "Produce the final hash value (big-endian) as a 160 bit number"
  [{:keys [h0 h1 h2 h3 h4]}]
  (-> (.shiftLeft (tb h0) 128)
      (.or (.shiftLeft (tb h1) 96))
      (.or (.shiftLeft (tb h2) 64))
      (.or (.shiftLeft (tb h3) 32))
      (.or             (tb h4))))

(defn sha1 [msg]
  (->> (make-chunks msg)
       (reduce main-loop initial-h)
       (final)
       (.toByteArray)
       (concat (repeat 20 0)) ;; lame hack,
       (apply vector)
       (take-last 20)))
