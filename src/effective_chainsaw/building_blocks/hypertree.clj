(ns effective-chainsaw.building-blocks.hypertree
  (:require [clojure.math :as math]
            [crypto.equality :refer [eq?]]
            [effective-chainsaw.building-blocks.wots :as wots]
            [effective-chainsaw.building-blocks.xmss :as xmss]
            [effective-chainsaw.internals.address :as address]
            [effective-chainsaw.internals.common :as common]))

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
                                                (let [leaf-index' (.mod tree-index
                                                                        (BigInteger/valueOf (int (math/pow 2 h'))))
                                                      tree-index' (.shiftRight tree-index h')
                                                      adrs' (-> adrs
                                                                (address/set-layer-address j)
                                                                (address/set-tree-address tree-index'))
                                                      xmss-signature' (xmss/sign parameter-set-data
                                                                                 current-root
                                                                                 sk-seed
                                                                                 leaf-index'
                                                                                 pk-seed
                                                                                 adrs')
                                                      xmss-public-key' (xmss/compute-public-key-from-signature parameter-set-data
                                                                                                               leaf-index'
                                                                                                               xmss-signature'
                                                                                                               current-root
                                                                                                               pk-seed
                                                                                                               adrs')]
                                                  {:hypertree-signature (common/merge-bytes hypertree-signature xmss-signature')
                                                   :current-root xmss-public-key'
                                                   :tree-index tree-index'}))
                                              {:hypertree-signature leaf-xmss-signature
                                               :current-root leaf-xmss-public-key
                                               :tree-index tree-index}
                                              (range 1 d))]
    hypertree-signature))

(defn- extract-xmss-signature
  [hypertree-signature {:keys [h' n lg_w]} j]
  (let [{:keys [len]} (wots/get-additional-values {:n n :lg_w lg_w})
        from (* j (+ h' len) n)
        to (* (inc j) (+ h' len) n)]
    (common/slice-bytes hypertree-signature
                        from
                        to)))

(defn verify
  "Verifies a hypertree signature."
  [{:keys [parameters] :as parameter-set-data} M hypertree-signature pk-seed tree-index leaf-index pk-root]
  (let [adrs (-> (address/new-address)
                 (address/set-tree-address tree-index))
        leaf-xmss-signature (extract-xmss-signature hypertree-signature parameters 0)
        leaf-xmss-public-key (xmss/compute-public-key-from-signature parameter-set-data
                                                                     leaf-index
                                                                     leaf-xmss-signature
                                                                     M
                                                                     pk-seed
                                                                     adrs)
        {:keys [d h']} parameters
        {:keys [current-root]} (reduce (fn [{:keys [current-root tree-index]} j]
                                         (let [leaf-index' (.mod tree-index
                                                                 (BigInteger/valueOf (math/pow 2 h')))
                                               tree-index' (.shiftRight tree-index h')
                                               adrs' (-> adrs
                                                         (address/set-layer-address j)
                                                         (address/set-tree-address tree-index'))
                                               xmss-signature' (extract-xmss-signature hypertree-signature parameters j)
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
    (eq? pk-root current-root)))
