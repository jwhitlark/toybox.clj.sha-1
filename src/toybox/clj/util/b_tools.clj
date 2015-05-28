(ns toybox.clj.util.b-tools)


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
