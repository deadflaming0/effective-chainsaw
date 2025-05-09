(ns effective-chainsaw.internals.common
  (:import (java.security GeneralSecurityException))
  (:require [clojure.math :as math]))

(defn merge-bytes
  "Merges byte arrays (or flat sequences of byte arrays) into a single byte array.
  Avoids Clojure-native data structures as they can add GC overhead, boxing and intermediate sequences.
  Does not work when input has depth > 1."
  [& inputs]
  (let [result (java.io.ByteArrayOutputStream.)]
    (doseq [input inputs]
      (if (sequential? input)
        (doseq [sub input]
          (.write result sub))
        (.write result input)))
    (.toByteArray result)))

(defn slice-bytes
  [a start end]
  (java.util.Arrays/copyOfRange a start end))

(defn integer->byte-array
  "Converts an integer x into a byte-array of length n in big endian format."
  [x n]
  (let [ba (byte-array n)]
    (reduce #(let [index' (- n 1 %2)
                   value' (int (mod %1 256))]
               (aset-byte ba index' (unchecked-byte value'))
               (.shiftRight (BigInteger. (str %1)) 8))
            (BigInteger. (str x))
            (range n))
    ba))

(defn byte-array->integer
  "Converts a byte array of any length into an integer."
  [X]
  (reduce #(+ (bit-shift-left %1 8)
              (bit-and %2 0xff))
          0
          X))

(defn- byte->bits
  [b]
  (map #(bit-and (bit-shift-right b %) 1)
       (range 7 -1 -1)))

(defn- bits->integer
  [bs]
  (reduce #(+ (bit-shift-left %1 1) %2) 0 bs))

(defn byte-array->base-2b
  "Divides input into output-length blocks, each having an integer in the range [0, ..., 2^base - 1].
  Used by WOTS+ and FORS; in the former base will be lg_w, whereas in the latter base will be a.
  In FIPS-205 lg_w is 4, and a can be 6, 8, 9, 12, or 14."
  [input base output-length]
  (let [input-length (count input)
        valid-length? (>= (math/ceil (/ (* output-length base) 8)) input-length)]
    (if valid-length?
      (let [input-as-bits (mapcat byte->bits input)
            partitions (partition-all base input-as-bits)
            blocks (map bits->integer partitions)]
        (take output-length blocks))
      (throw (GeneralSecurityException. "Cannot convert input to base 2^b: length is too small")))))
