(ns effective-chainsaw.common)

(defn konkat
  "Concatenates byte arrays (or flat sequences of byte arrays) into a single byte array.
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

(defn ensure-correct-size!
  [s input]
  (let [size (if (.isArray (class input))
               (alength input)
               (count input))]
    (if (= size s)
      input
      (throw (Exception. (format "Input does not contain %s elements, %s has size %s" s input size))))))

(defn int->byte-array
  [x n]
  (let [bb (java.nio.ByteBuffer/allocate n)]
    (.position bb (- n 4)) ;; int = 4 bytes
    (.putInt bb x)
    (.array bb)))

(defn byte-array->int
  [X]
  (let [bb (java.nio.ByteBuffer/wrap X)]
    (.getInt bb)))
