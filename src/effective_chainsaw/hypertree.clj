(ns effective-chainsaw.hypertree
  (:require [clojure.math :as math]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.xmss :as xmss]))

(defn sign
  "Generates a hypertree signature."
  [{:keys [parameters] :as parameter-set-data} M sk-seed pk-seed tree-index leaf-index]
  (let [adrs (-> (address/new-address)
                 (address/set-tree-address tree-index))
        leaf-xmss-signature (xmss/sign parameter-set-data
                                       M
                                       sk-seed
                                       leaf-index
                                       pk-seed
                                       adrs)
        leaf-xmss-public-key (xmss/compute-public-key-from-signature parameter-set-data
                                                                     leaf-index
                                                                     leaf-xmss-signature
                                                                     M
                                                                     pk-seed
                                                                     adrs)
        {:keys [d h']} parameters
        {:keys [hypertree-signature]} (reduce (fn [{:keys [hypertree-signature current-root tree-index]} j]
                                                (let [leaf-index' (mod tree-index (int (math/pow 2 h')))
                                                      tree-index' (bit-shift-right tree-index h')
                                                      adrs' (-> adrs
                                                                (address/set-layer-address j)
                                                                (address/set-tree-address tree-index'))
                                                      xmss-signature' (xmss/sign parameter-set-data
                                                                                 current-root
                                                                                 sk-seed
                                                                                 leaf-index'
                                                                                 pk-seed
                                                                                 adrs')]
                                                  (if (< j d) ;; TODO: is this really necessary?
                                                    (let [xmss-public-key' (xmss/compute-public-key-from-signature parameter-set-data
                                                                                                                   leaf-index'
                                                                                                                   xmss-signature'
                                                                                                                   current-root
                                                                                                                   pk-seed
                                                                                                                   adrs')]
                                                      {:hypertree-signature (conj hypertree-signature xmss-signature')
                                                       :current-root xmss-public-key'
                                                       :tree-index tree-index'})
                                                    hypertree-signature)))
                                              {:hypertree-signature [leaf-xmss-signature]
                                               :current-root leaf-xmss-public-key
                                               :tree-index tree-index}
                                              (range 1 d))]
    hypertree-signature))

(defn verify
  "Verifies a hypertree signature."
  [{:keys [parameters] :as parameter-set-data} M hypertree-signature pk-seed tree-index leaf-index pk-root]
  (let [adrs (-> (address/new-address)
                 (address/set-tree-address tree-index))
        leaf-xmss-signature (first hypertree-signature)
        leaf-xmss-public-key (xmss/compute-public-key-from-signature parameter-set-data
                                                                     leaf-index
                                                                     leaf-xmss-signature
                                                                     M
                                                                     pk-seed
                                                                     adrs)
        {:keys [d h']} parameters
        {:keys [current-root]} (reduce (fn [{:keys [current-root tree-index]} j]
                                         (let [leaf-index' (mod tree-index (int (math/pow 2 h')))
                                               tree-index' (bit-shift-right tree-index h')
                                               adrs' (-> adrs
                                                         (address/set-layer-address j)
                                                         (address/set-tree-address tree-index'))
                                               xmss-signature' (nth hypertree-signature j)
                                               xmss-public-key' (xmss/compute-public-key-from-signature parameter-set-data
                                                                                                        leaf-index'
                                                                                                        xmss-signature'
                                                                                                        current-root
                                                                                                        pk-seed
                                                                                                        adrs')]
                                           {:current-root xmss-public-key'
                                            :tree-index tree-index'}))
                                       {:current-root leaf-xmss-public-key
                                        :tree-index tree-index}
                                       (range 1 d))]
    (common/equal-bytes? pk-root current-root)))
