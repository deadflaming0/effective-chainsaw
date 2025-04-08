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
  "This is an awful implementation, I know."
  [x n]
  (let [[result _]
        (reduce (fn [[result total] curr]
                  (aset-byte result (- n 1 curr) (mod total 256)) ;; :boom:?
                  [result (bit-shift-right total 8)])
                [(byte-array n) x]
                (range n))]
    result))

(defn byte-array->int
  "Replace this with something that does not uses ByteBuffer."
  [X]
  (let [bb (java.nio.ByteBuffer/wrap X)]
    (.getInt bb)))
