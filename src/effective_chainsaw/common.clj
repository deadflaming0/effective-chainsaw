(ns effective-chainsaw.common
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

(defn equal-bytes?
  [lhs rhs]
  (java.util.Arrays/equals lhs rhs))

(defn validate-length!
  [s input]
  (let [size (if (.isArray (class input))
               (alength input)
               (count input))]
    (if (= size s)
      input
      (throw (Exception. (format "Input does not contain %s elements, %s has size %s" s input size))))))

(defn integer->byte-array
  [x n]
  (byte-array (map #(unchecked-byte (bit-shift-right x (* 8 (- n 1 %))))
                   (range n))))

(defn byte-array->integer
  [X]
  (reduce #(+ %1 (bit-and %2 0xff)) 0 X))

(defn- byte->bits
  [b]
  (map #(bit-and (bit-shift-right b %) 1)
       (range 7 -1 -1)))

(defn- bits->integer
  [bs]
  (reduce #(+ (bit-shift-left %1 1) %2) 0 bs))

(defn byte-array->base-2b
  "Divides X into output-length blocks, each having an integer in the range [0, ..., 2^base - 1].
  Used by WOTS+ and FORS; in the former base will be lg_w, whereas in the latter base will be a.
  In FIPS-205 lg_w is 4, and a can be 6, 8, 9, 12, or 14."
  [X base output-length]
  (validate-length! (int (math/ceil (/ (* output-length base) 8))) X)
  (let [blocks (map bits->integer (partition base (mapcat byte->bits X)))]
    (take-last output-length blocks)))
