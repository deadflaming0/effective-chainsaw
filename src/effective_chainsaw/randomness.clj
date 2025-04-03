(ns effective-chainsaw.randomness
  (:import (java.security SecureRandom)))

(defn random-bytes
  [n]
  (let [seed (byte-array n)]
    (.nextBytes (SecureRandom.) seed)
    seed))
