(ns effective-chainsaw.common)

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

(defn compare-bytes
  [lhs rhs]
  (java.util.Arrays/equals lhs rhs))

(defn int->byte-array
  [x n]
  (byte-array
   (map #(unchecked-byte (bit-shift-right x (* 8 (- n 1 %))))
        (range n))))

(defn byte-array->int
  [X]
  (let [bb (java.nio.ByteBuffer/wrap X)]
    (.getInt bb)))

(defn validate-length!
  [s input]
  (let [size (if (.isArray (class input))
               (alength input)
               (count input))]
    (if (= size s)
      input
      (throw (Exception. (format "Input does not contain %s elements, %s has size %s" s input size))))))
