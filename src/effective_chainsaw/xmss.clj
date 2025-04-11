(ns effective-chainsaw.xmss
  (:require [clojure.math :as math]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.wots :as wots]))

(defn subtree
  "Computes the root of a Merkle subtree of WOTS+ public keys."
  [{:keys [functions] :as parameter-set-data} sk-seed i z pk-seed adrs]
  (if (zero? z)
    (let [public-key (wots/generate-public-key parameter-set-data
                                               sk-seed
                                               pk-seed
                                               (-> adrs
                                                   (address/set-type-and-clear :wots-hash)
                                                   (address/set-key-pair-address i)))]
      public-key)
    (let [left-node (subtree parameter-set-data sk-seed (* 2 i) (dec z) pk-seed adrs)
          right-node (subtree parameter-set-data sk-seed (inc (* 2 i)) (dec z) pk-seed adrs)
          H (:H functions)
          node (H pk-seed
                  (-> adrs
                      (address/set-type-and-clear :tree)
                      (address/set-tree-height z)
                      (address/set-tree-index i))
                  (common/merge-bytes left-node right-node))]
      node)))

(defn sign
  "Generates an XMSS signature."
  [{:keys [parameters] :as parameter-set-data} M sk-seed idx pk-seed adrs]
  (let [authentication-path (map (fn [j]
                                   (let [k (bit-xor (int (math/floor (/ idx (int (math/pow 2 j))))) 1)]
                                     (subtree parameter-set-data sk-seed k j pk-seed adrs)))
                                 (range (:h' parameters)))
        wots-signature (wots/sign parameter-set-data
                                  M
                                  sk-seed
                                  pk-seed
                                  (-> adrs
                                      (address/set-type-and-clear :wots-hash)
                                      (address/set-key-pair-address idx)))]
    [wots-signature authentication-path]))

(defn compute-public-key-from-signature
  "Computes an XMSS public key from an XMSS signature."
  [{:keys [parameters functions] :as parameter-set-data} idx [wots-signature authentication-path] M pk-seed adrs]
  (let [node-0 (wots/compute-public-key-from-signature parameter-set-data
                                                       wots-signature
                                                       M
                                                       pk-seed
                                                       (-> adrs
                                                           (address/set-type-and-clear :wots-hash)
                                                           (address/set-key-pair-address idx)))
        H (:H functions)
        [public-key' _] (reduce (fn [[node adrs'] k]
                                  (let [new-adrs (address/set-tree-height adrs' (inc k))
                                        tree-index (address/get-tree-index new-adrs)
                                        authentication-path-segment (nth authentication-path k)]
                                    (if (even? (int (math/floor (/ idx (int (math/pow 2 k))))))
                                      (let [new-adrs' (address/set-tree-index new-adrs (int (/ tree-index 2)))]
                                        [(H pk-seed
                                            new-adrs'
                                            (common/merge-bytes node authentication-path-segment))
                                         new-adrs'])
                                      (let [new-adrs' (address/set-tree-index new-adrs (int (/ (dec tree-index) 2)))]
                                        [(H pk-seed
                                            new-adrs'
                                            (common/merge-bytes authentication-path-segment node))
                                         new-adrs']))))
                                [node-0
                                 (-> adrs
                                     (address/set-type-and-clear :tree)
                                     (address/set-tree-index idx))]
                                (range (:h' parameters)))]
    public-key'))
