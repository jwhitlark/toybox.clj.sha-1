(ns user
  (:require [toybox.clj.digest :as d]))

(comment
  (->> (d/sha1 "foo\n")
       (map (partial format "%02x"))
       (apply str)),
  )