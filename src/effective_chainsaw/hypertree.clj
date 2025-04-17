(ns effective-chainsaw.hypertree
  (:require [clojure.math :as math]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.xmss :as xmss]))

(defn sign
  "Generates a hypertree signature."
  [{:keys [parameters] :as parameter-set-data} M sk-seed pk-seed idx_tree idx_leaf]
  (let [adrs (-> (address/new-address)
                 (address/set-tree-address idx_tree))
        leaf-xmss-signature (xmss/sign parameter-set-data
                                       M
                                       sk-seed
                                       idx_leaf
                                       pk-seed
                                       adrs)
        leaf-xmss-public-key (xmss/compute-public-key-from-signature parameter-set-data
                                                                     idx_leaf
                                                                     leaf-xmss-signature
                                                                     M
                                                                     pk-seed
                                                                     adrs)
        {:keys [d h']} parameters
        {:keys [hypertree-signature]}
        (reduce (fn [{:keys [hypertree-signature root' idx_tree']} j]
                  (let [idx_leaf' (mod idx_tree' (int (math/pow 2 h')))
                        new-idx_tree (bit-shift-right idx_tree' h')
                        adrs' (-> adrs
                                  (address/set-layer-address j)
                                  (address/set-tree-address new-idx_tree))
                        xmss-signature (xmss/sign parameter-set-data
                                                  root'
                                                  sk-seed
                                                  idx_leaf'
                                                  pk-seed
                                                  adrs')]
                    (if (< j d)
                      (let [xmss-public-key (xmss/compute-public-key-from-signature parameter-set-data
                                                                                    idx_leaf'
                                                                                    xmss-signature
                                                                                    root'
                                                                                    pk-seed
                                                                                    adrs')]
                        {:hypertree-signature (conj hypertree-signature xmss-signature)
                         :root' xmss-public-key
                         :idx_tree' new-idx_tree})
                      hypertree-signature)))
                {:hypertree-signature [leaf-xmss-signature]
                 :root' leaf-xmss-public-key
                 :idx_tree' idx_tree}
                (range 1 d))]
    hypertree-signature))

(defn verify
  [{:keys [parameters] :as parameter-set-data} M hypertree-signature pk-seed idx_tree idx_leaf pk-root]
  (let [adrs (-> (address/new-address)
                 (address/set-tree-address idx_tree))
        leaf-xmss-signature (first hypertree-signature)
        leaf-public-key' (xmss/compute-public-key-from-signature parameter-set-data
                                                                 idx_leaf
                                                                 leaf-xmss-signature
                                                                 M
                                                                 pk-seed
                                                                 adrs)
        {:keys [d h']} parameters
        {:keys [public-key']} (reduce (fn [{:keys [public-key' idx_tree']} j]
                                        (let [idx_leaf' (mod idx_tree' (int (math/pow 2 h')))
                                              new-idx_tree (bit-shift-right idx_tree' h')
                                              adrs' (-> adrs
                                                        (address/set-layer-address j)
                                                        (address/set-tree-address new-idx_tree))
                                              xmss-signature (nth hypertree-signature j)
                                              new-public-key (xmss/compute-public-key-from-signature parameter-set-data
                                                                                                     idx_leaf'
                                                                                                     xmss-signature
                                                                                                     public-key'
                                                                                                     pk-seed
                                                                                                     adrs')]
                                          {:public-key' new-public-key
                                           :idx_tree' new-idx_tree}))
                                      {:public-key' leaf-public-key'
                                       :idx_tree' idx_tree}
                                      (range 1 d))]
    (common/equal-bytes? pk-root public-key')))
