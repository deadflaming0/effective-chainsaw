(ns effective-chainsaw.slh-dsa
  (:require [effective-chainsaw.address :as address]
            [effective-chainsaw.parameter-sets :as parameter-sets]
            [effective-chainsaw.xmss :as xmss]))

;; technically this almost mirrors `slh_keygen_internal`, but it only serves as a way to compute `pk-root`
(defn pk-root
  [parameter-set-name sk-seed pk-seed]
  (let [{:keys [parameters] :as parameter-set-data} (parameter-sets/parameter-set-data parameter-set-name)
        {:keys [d h']} parameters
        adrs (-> (address/new-address)
                 (address/set-layer-address (dec d)))
        pk-root (xmss/subtree parameter-set-data
                              sk-seed
                              0
                              h'
                              pk-seed
                              adrs)]
    pk-root))
