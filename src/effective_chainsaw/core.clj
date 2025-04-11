(ns effective-chainsaw.core
  (:require [clojure.math :as math]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.parameter-sets :as parameter-sets]
            [effective-chainsaw.primitives :as primitives]
            [effective-chainsaw.randomness :as randomness]
            [effective-chainsaw.wots :as wots]))

(def parameter-set-name :slh-dsa-shake-128s)

(def parameter-set-data
  (parameter-sets/parameter-set-data parameter-set-name))

(def n (-> parameter-set-data :parameters :n))

(def sk-seed (randomness/random-bytes n))
(def pk-seed (randomness/random-bytes n))
(def adrs (address/new-address))

(def M
  (primitives/shake256 (byte-array [0x42 0x41 0x4e 0x41 0x4e 0x41]) (* n 8))) ;; BANANA

(defn xmss-node
  "Computes the root of a Merkle subtree of WOTS+ public keys."
  [{:keys [functions] :as parameter-set-data} sk-seed i z pk-seed adrs]
  ;; add validation (`i` and `z`)
  (if (zero? z)
    (let [adrs' (-> adrs
                    (address/set-type-and-clear :wots-hash)
                    (address/set-key-pair-address i))
          node (wots/generate-public-key parameter-set-data sk-seed pk-seed adrs')]
      node)
    (let [left-node (xmss-node parameter-set-data sk-seed (* 2 i) (dec z) pk-seed adrs)
          right-node (xmss-node parameter-set-data sk-seed (inc (* 2 i)) (dec z) pk-seed adrs)
          adrs' (-> adrs
                    (address/set-type-and-clear :tree)
                    (address/set-tree-height z)
                    (address/set-tree-index i))
          H (:H functions)
          node (H pk-seed
                  adrs'
                  (common/konkat left-node right-node))]
      node)))

(defn xmss-sign
  "Generates an XMSS signature."
  [{:keys [parameters] :as parameter-set-data} M sk-seed idx pk-seed adrs]
  (let [authentication-path (map (fn [j]
                                   (let [k (bit-xor (int (math/floor (/ idx (int (math/pow 2 j))))) 1)]
                                     (xmss-node parameter-set-data sk-seed k j pk-seed adrs)))
                                 (range (:h' parameters)))
        adrs' (-> adrs
                  (address/set-type-and-clear :wots-hash)
                  (address/set-key-pair-address idx))
        signature (wots/sign parameter-set-data M sk-seed pk-seed adrs')]
    [signature authentication-path]))

(def xmss-signature (xmss-sign parameter-set-data M sk-seed 3 pk-seed adrs))

(defn xmss-compute-public-key-from-signature
  "Computes an XMSS public key from an XMSS signature."
  [{:keys [parameters functions] :as parameter-set-data} idx [signature authentication-path] M pk-seed adrs]
  (let [adrs' (-> adrs
                  (address/set-type-and-clear :wots-hash)
                  (address/set-key-pair-address idx))
        node-0 (wots/compute-public-key-from-signature parameter-set-data signature M pk-seed adrs')
        adrs'' (-> adrs
                   (address/set-type-and-clear :tree)
                   (address/set-tree-index idx))
        H (:H functions)
        candidate-public-key (reduce (fn [node k]
                                       (let [adrs''' (address/set-tree-height adrs'' (inc k))
                                             tree-index (address/get-tree-index adrs''')
                                             authentication-path-segment (nth authentication-path k)]
                                         (if (even? (int (math/floor (/ idx (int (math/pow 2 k)))))) ;; argh
                                           (H pk-seed
                                              (address/set-tree-index adrs''' (int (/ tree-index 2)))
                                              (common/konkat node authentication-path-segment))
                                           (H pk-seed
                                              (address/set-tree-index adrs''' (int (/ (dec tree-index) 2)))
                                              (common/konkat authentication-path-segment node)))))
                                     node-0
                                     (range (:h' parameters)))]
    candidate-public-key))

(xmss-compute-public-key-from-signature parameter-set-data 3 xmss-signature M pk-seed adrs)
