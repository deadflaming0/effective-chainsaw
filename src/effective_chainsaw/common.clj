(ns effective-chainsaw.common)

(defn konkat
  "Concatenates the different input values in a single byte array.
  For instance: H_msg(R, pk-seed, pk-root, M) = SHAKE256(R || pk-seed || pk-root || M).
  This function acts like `||`, essentially."
  [& inputs]
  (byte-array (apply concat (map seq inputs))))
