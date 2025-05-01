(ns effective-chainsaw.building-blocks.xmss
  (:require [clojure.math :as math]
            [effective-chainsaw.building-blocks.wots :as wots]
            [effective-chainsaw.internals.address :as address]
            [effective-chainsaw.internals.common :as common]))

(defn subtree
  "Computes the root of a Merkle subtree of WOTS+ public keys."
  [{:keys [functions] :as parameter-set-data} sk-seed index height pk-seed adrs]
  ;; TODO: add validation
  (if (zero? height)
    (let [wots-pk-adrs (-> adrs
                           (address/set-type-and-clear :wots-hash)
                           (address/set-key-pair-address index))
          wots-public-key (wots/generate-public-key parameter-set-data
                                                    sk-seed
                                                    pk-seed
                                                    wots-pk-adrs)]
      wots-public-key)
    (let [left-node (subtree parameter-set-data sk-seed (* 2 index) (dec height) pk-seed adrs)
          right-node (subtree parameter-set-data sk-seed (inc (* 2 index)) (dec height) pk-seed adrs)
          H (:H functions)
          node-adrs (-> adrs
                        (address/set-type-and-clear :tree)
                        (address/set-tree-height height)
                        (address/set-tree-index index))
          node (H pk-seed node-adrs (common/merge-bytes left-node right-node))]
      node)))

(defn sign
  "Generates an XMSS signature."
  [{:keys [parameters] :as parameter-set-data} M sk-seed index pk-seed adrs]
  (let [authentication-path (pmap (fn [j]
                                    (let [k (bit-xor (int (math/floor (/ index (int (math/pow 2 j))))) 1)]
                                      (subtree parameter-set-data sk-seed k j pk-seed adrs)))
                                  (range (:h' parameters)))
        wots-signature (wots/sign parameter-set-data
                                  M
                                  sk-seed
                                  pk-seed
                                  (-> adrs
                                      (address/set-type-and-clear :wots-hash)
                                      (address/set-key-pair-address index)))]
    (common/merge-bytes wots-signature authentication-path)))

(defn- extract-wots-signature
  [xmss-signature {:keys [n lg_w]}]
  (let [{:keys [len]} (wots/get-additional-values {:n n :lg_w lg_w})]
    (common/slice-bytes xmss-signature
                        0
                        (* len n))))

(defn- extract-authentication-path-segment
  [xmss-signature {:keys [n lg_w]} k]
  (let [{:keys [len]} (wots/get-additional-values {:n n :lg_w lg_w})
        wots-signature-length (* len n)
        from (+ wots-signature-length (* k n))
        to (+ from n)]
    (common/slice-bytes xmss-signature
                        from
                        to)))

(defn compute-public-key-from-signature
  "Computes an XMSS public key from an XMSS signature."
  [{:keys [parameters functions] :as parameter-set-data} index xmss-signature M pk-seed adrs]
  (let [wots-signature (extract-wots-signature xmss-signature parameters)
        node-0 (wots/compute-public-key-from-signature parameter-set-data
                                                       wots-signature
                                                       M
                                                       pk-seed
                                                       (-> adrs
                                                           (address/set-type-and-clear :wots-hash)
                                                           (address/set-key-pair-address index)))
        node-0-adrs (-> adrs
                        (address/set-type-and-clear :tree)
                        (address/set-tree-index index))
        H (:H functions)
        [public-key _] (reduce (fn [[node' adrs'] k]
                                 (let [adrs'' (address/set-tree-height adrs' (inc k))
                                       tree-index' (address/get-tree-index adrs'')
                                       authentication-path-segment (extract-authentication-path-segment xmss-signature
                                                                                                        parameters
                                                                                                        k)]
                                   (if (even? (int (math/floor (/ index (int (math/pow 2 k))))))
                                     (let [adrs''' (address/set-tree-index adrs'' (int (/ tree-index' 2)))]
                                       [(H pk-seed adrs''' (common/merge-bytes node'
                                                                               authentication-path-segment))
                                        adrs'''])
                                     (let [adrs''' (address/set-tree-index adrs'' (int (/ (dec tree-index') 2)))]
                                       [(H pk-seed adrs''' (common/merge-bytes authentication-path-segment
                                                                               node'))
                                        adrs''']))))
                               [node-0 node-0-adrs]
                               (range (:h' parameters)))]
    public-key))
