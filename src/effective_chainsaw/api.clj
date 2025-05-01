(ns effective-chainsaw.api
  (:require [effective-chainsaw.building-blocks.parameter-sets :as parameter-sets]
            [effective-chainsaw.building-blocks.slh-dsa :as slh-dsa]
            [effective-chainsaw.building-blocks.xmss :as xmss]
            [effective-chainsaw.internals.address :as address]
            [effective-chainsaw.internals.common :as common]))

(defn generate-key-pair
  [parameter-set-name sk-seed sk-prf pk-seed]
  (let [{:keys [parameters] :as parameter-set-data} (parameter-sets/parameter-set-data parameter-set-name)
        {:keys [d h']} parameters
        adrs (-> (address/new-address)
                 (address/set-layer-address (dec d)))
        pk-root (xmss/subtree parameter-set-data sk-seed 0 h' pk-seed adrs)]
    {:private-key
     {:sk-seed sk-seed
      :sk-prf sk-prf
      :pk-seed pk-seed
      :pk-root pk-root}
     :public-key
     {:pk-seed pk-seed
      :pk-root pk-root}}))

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
  ([parameter-set-name M context private-key]
   (sign parameter-set-name M context private-key (:pk-seed private-key)))
  ([parameter-set-name M context private-key additional-randomness]
   (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
         M' (prepend-context! M context)]
     (slh-dsa/sign* parameter-set-data M' private-key additional-randomness))))

(defn verify
  [parameter-set-name M signature context public-key]
  (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
        M' (prepend-context! M context)]
    (slh-dsa/verify* parameter-set-data M' signature public-key)))
