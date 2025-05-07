(ns effective-chainsaw.api
  (:require [effective-chainsaw.building-blocks.parameter-sets :as parameter-sets]
            [effective-chainsaw.building-blocks.slh-dsa :as slh-dsa]
            [effective-chainsaw.internals.common :as common]
            [effective-chainsaw.internals.randomness :as randomness]))

(defn generate-key-pair
  "Generates an SLH-DSA key pair."
  [parameter-set-name]
  (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
        n (-> parameter-set-data :parameters :n)
        sk-seed (randomness/random-bytes n)
        sk-prf (randomness/random-bytes n)
        pk-seed (randomness/random-bytes n)]
    (slh-dsa/generate-key-pair parameter-set-data sk-seed sk-prf pk-seed)))

(defn- prepend-context!
  [M context]
  (let [context-length (count context)]
    (cond
      (zero? context-length) M
      (< context-length 255) (common/merge-bytes
                              (common/integer->byte-array 0 1)
                              (common/integer->byte-array context-length 1)
                              context
                              M)
      :else (throw (Exception. "Context length must be < 255 bytes")))))

(defn sign
  "Generates a pure SLH-DSA signature (pre-hash mode is not supported yet)."
  ([parameter-set-name M context private-key]
   (sign parameter-set-name M context private-key (:pk-seed private-key)))
  ([parameter-set-name M context private-key additional-randomness]
   (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
         M' (prepend-context! M context)]
     (slh-dsa/sign parameter-set-data M' private-key additional-randomness))))

(defn verify
  "Verifies a pure SLH-DSA signature (pre-hash mode is not supported yet)."
  [parameter-set-name M signature context public-key]
  (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
        M' (prepend-context! M context)]
    (slh-dsa/verify parameter-set-data M' signature public-key)))
