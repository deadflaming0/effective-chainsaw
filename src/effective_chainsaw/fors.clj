(ns effective-chainsaw.fors
  (:require [effective-chainsaw.address :as address]))

(defn generate-private-key
  "Generates a FORS private-key value."
  [{:keys [functions]} sk-seed pk-seed adrs idx]
  (let [key-pair-address (address/get-key-pair-address adrs)
        sk-adrs (-> adrs
                    (address/set-type-and-clear :fors-prf)
                    (address/set-key-pair-address key-pair-address)
                    (address/set-tree-index idx))
        PRF (:PRF functions)]
    (PRF pk-seed sk-seed sk-adrs)))
