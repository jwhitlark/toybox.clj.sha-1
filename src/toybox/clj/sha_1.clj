(ns toybox.clj.sha-1
  (:require [clojure.pprint :as pp :refer [pprint]]
            [clojure.string :as str]
            [clojure.reflect :as r]
            [clojurewerkz.buffy.core :as bin]
            [clojurewerkz.buffy.util :refer [hex-dump] :as util])
  (:import [java.security MessageDigest]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]
           [java.nio ByteBuffer]
           [java.util BitSet]
           ))

;; binary numbers can be represented as 2rX (i.e. 2r1001)

(def empty-msg "")
(def short-msg "The quick brown fox jumps over the lazy dog")
(def long-msg "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.")

;; HMAC stuff, needs to go elsewhere.
#_ (defn- secretKeyInst [key mac]
  (SecretKeySpec. (.getBytes key) (.getAlgorithm mac)))

#_ (defn sign [key string]
  "Returns the signature of a string with a given
    key, using a SHA-256 HMAC."
  (let [mac (Mac/getInstance "HMACSHA256")
        secretKey (secretKeyInst key mac)]
    (-> (doto mac
          (.init secretKey)
          (.update (.getBytes string)))
        .doFinal)))

;; (toHexString (sign "key" "The quick brown fox jumps over the lazy dog"))
;; f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8

(defn known-correct-sha1 [s]
  (apply vector (.digest (MessageDigest/getInstance "SHA1") (.getBytes s))))

(defn toHexString [bytes]
  "Convert bytes to a String"
  (apply str (map #(format "%02x" %) bytes)))

(defn len-bits
  "Return the string length in bits, as a Long."
  [s] (* Byte/SIZE (count s)))

(defn view-bits [i]
  (Long/toBinaryString i))

;; TODO: Rename. mask-int, mask-32-bits, mask-32, lower-32 ? (jw 15-05-17)
(defn long->int [l]
  (bit-and l 0xffffffff))

(defn ->big [l]
  (-> l (.toString) (BigInteger.)))

(defn unsign [b]
  (Byte/toUnsignedInt b))

(defn bytes->int [bts] ;; TODO: Write as a reducer? (jw 15-05-17)
  (-> (unsign (first bts))
      (bit-shift-left 8) (bit-or (unsign (nth bts 1)))
      (bit-shift-left 8) (bit-or (unsign (nth bts 2)))
      (bit-shift-left 8) (bit-or (unsign (nth bts 3)))))

(defn rotate-left
  ([x] (rotate-left x 1))
  ([x n]
   (.intValue (bit-or (bit-shift-left x n )
                      (unsigned-bit-shift-right (long->int x)
                                                (- Integer/SIZE n))))))

(defn index-items [items]
  (map-indexed (fn [idx x] [idx x]) items))

;; Real implementation.

(def h0 0x67452301)
(def h1 0xEFCDAB89)
(def h2 0x98BADCFE)
(def h3 0x10325476)
(def h4 0xC3D2E1F0)

(def k1 0x5A827999)
(def k2 0x6ED9EBA1)
(def k3 0x8F1BBCDC)
(def k4 0xCA62C1D6)

(def chunk-size 512)
(def max-padding (-> (- chunk-size Long/SIZE)
                     (/ 8)))

(defn pad-length [msg]
  (- max-padding (mod (count msg) max-padding)))

;; FIXME: ONLY works for msgs < 56 bytes, as a first pass (jw 15-05-12)

(defn make-spec [msg]
  (let [ msg-spec (bin/spec :msg (bin/string-type (count msg))
                            :padding (bin/bit-type 1)
                            :rest-padding (bin/bit-type (dec (pad-length msg))) ;;(- max-padding (count msg))
                            :msg-size (bin/long-type))
        buf (bin/compose-buffer msg-spec :buffer-type :heap)]
    (bin/set-field buf :msg msg)
    (bin/set-field buf :padding [false false false false false false false true])
    (bin/set-field buf :msg-size (len-bits msg))
    buf))

;; split into 512 bit chunks
(defn make-chunks [b]
  (->> b
       bin/buffer
       (.array)
       (apply vector)
       (partition 4)
       (map bytes->int)
       (into []))
)

;; split into 16 32-bit words (big endian)
(defn make-words [b]
  (->> b
    bin/buffer
    (.array)
    (apply vector)
    (partition 4)
    (map bytes->int)
    (into [])))

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

(defn subproc [i a b c d e f wd k]
  (let
      ;; temp = (a leftrotate 5) + f + e + k + w[i]
      [temp (.intValue (apply + [(rotate-left a 5) f e k wd]))
       r {:e d ;; e = d
          :d c ;; d = c
          :c (rotate-left b 30) ;; c = b leftrotate 30
          :b a ;; b = a
          :a temp ;; a = temp
          }]
    (spit "mine.txt" (format "i: %d, w: %d, a: %d, b: %d, c: %d, d: %d, e: %d, f: %d, K: %d\n" i, wd, (:a r) (:b r) (:c r) (:d r) (:e r) f k) :append true)
    r
    ))

;; need to group a-b-c-d-e
(defn main-loop [chunk]
  (spit "mine.txt" "")
  (loop [a h0, b h1, c h2, d h3, e h4, idx-wd (first chunk) remaining (rest chunk)]
    ;; (pprint [a, b, c, d, e, idx-wd])
    (let [[i wd] idx-wd
          nxt (cond
                ;; if 0 ≤ i ≤ 19 then
                (<= 0 i 19)
                  (let
                      ;; f = (b and c) or ((not b) and d)
                      [f (bit-or (bit-and b c) (bit-and (bit-not b) d))]
                    ;; k = 0x5A827999 ;; k1
                    (subproc i a b c d e f wd k1))

                ;; else if 20 ≤ i ≤ 39
                (<= 20 i 39)
                  (let
                      ;; f = b xor c xor d
                      [f (-> b (bit-xor c) (bit-xor d))]
                    ;; k = 0x6ED9EBA1 ;; k2
                    (subproc i a b c d e f wd k2))

                ;; else if 40 ≤ i ≤ 59
                (<= 40 i 59)
                  (let
                      ;; f = (b and c) or (b and d) or (c and d)
                      [f  (bit-or
                           (bit-or (bit-and b c)
                                   (bit-and b d))
                           (bit-and c d))]
                    ;; k = 0x8F1BBCDC ;; k3
                    (subproc i a b c d e f wd k3))

                ;; else if 60 ≤ i ≤ 79
                (<= 60 i 79)
                  (let
                      ;; f = b xor c xor d
                      [f  (-> b (bit-xor c) (bit-xor d))]
                    ;; k = 0xCA62C1D6 ;; k4
                    (subproc i a b c d e f wd k4))
                )]
      (if (not (seq remaining))
        nxt
        (recur (:a nxt) (:b nxt) (:c nxt) (:d nxt) (:e nxt) (first remaining) (rest remaining))
        )
      )))

;; Add this chunk's hash to result so far:
;; h0 = h0 + a
;; h1 = h1 + b
;; h2 = h2 + c
;; h3 = h3 + d
;; h4 = h4 + e

(defn proc-main [res]

  {:h0 (+ h0 (:a res))
   :h1 (+ h1 (:b res))
   :h2 (+ h2 (:c res))
   :h3 (+ h3 (:d res))
   :h4 (+ h4 (:e res))})

(defn res->vec [res]
  [(:h0 res) (:h1 res) (:h2 res) (:h3 res) (:h4 res)])

(defn final
  "Produce the final hash value (big-endian) as a 160 bit number"
  [[h0 h1 h2 h3 h4]]
  ;;hh = (h0 leftshift 128) or (h1 leftshift 96) or (h2 leftshift 64) or (h3 leftshift 32) or h4
  ;; NOTE: Here we do need to mask off the longs before we process them.
  (-> (.shiftLeft (->big (long->int h0)) 128)         ;(h0 leftshift 128)
      (.or (.shiftLeft (->big (long->int h1)) 96)) ;or (h1 leftshift 96)
      (.or (.shiftLeft (->big (long->int h2)) 64)) ;or (h2 leftshift 64)
      (.or (.shiftLeft (->big (long->int h3)) 32)) ;or (h3 leftshift 32)
      (.or (->big (long->int h4)))                  ;or h4
      ))

(defn sha1 [msg]
  (->> (make-spec msg)
       (make-words)
       (extend-words)
       (index-items)
       (main-loop)
       (proc-main)
       res->vec
       (final)
       (.toByteArray)
       (apply vector)
       (take-last 20) ;; get rid of BigInt leading zero
       ))

;; misc, might be useful...

;; (defn byte->ubyte [b]
;;   (int (bit-and b 255)))

;; (defn ubyte->byte [b]
;;   (if (>= b 128)
;;     (byte (- b 256))
;;     (byte b)))

;; (defn ubyte [val]
;;   (if (>= val 128)
;;     (byte (- val 256))
;;     (byte val)))
