(ns effective-chainsaw.hypertree
  (:require [clojure.math :as math]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.parameter-sets :as parameter-sets]
            [effective-chainsaw.primitives :as primitives]
            [effective-chainsaw.randomness :as randomness]
            [effective-chainsaw.xmss :as xmss]))

(def parameter-set-name :slh-dsa-shake-128s)

(def parameter-set-data
  (parameter-sets/parameter-set-data parameter-set-name))

(def n (-> parameter-set-data :parameters :n))

(def sk-seed (randomness/random-bytes n))
(def pk-seed (randomness/random-bytes n))

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
        signature [leaf-xmss-signature]
        leaf-xmss-public-key (xmss/compute-public-key-from-signature parameter-set-data
                                                                     idx_leaf
                                                                     leaf-xmss-signature
                                                                     M
                                                                     pk-seed
                                                                     adrs)
        {:keys [d h']} parameters
        {:keys [signature]} (reduce (fn [{:keys [signature root' idx_tree']} j]
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
                                            {:signature (conj signature xmss-signature)
                                             :root' xmss-public-key
                                             :idx_tree' new-idx_tree})
                                          signature)))
                                    {:signature signature
                                     :root' leaf-xmss-public-key
                                     :idx_tree' idx_tree}
                                    (range 1 d))]
    signature))

(def M
  (primitives/shake256 (byte-array [0x0c 0x0c 0x63 0x72 0x6f 0x63 0x6f 0x64 0x69 0x6c 0x6f 0x0a])
                       128))

(def hypertree-signature
  (sign parameter-set-data M sk-seed pk-seed 0 0))

(defn verify
  [{:keys [parameters] :as parameter-set-data} M signature pk-seed idx_tree idx_leaf pk-root]
  (let [adrs (-> (address/new-address)
                 (address/set-tree-address idx_tree))
        leaf-xmss-signature (first signature)
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
                                              xmss-signature (nth signature j)
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
    (common/compare-bytes pk-root public-key')))

(def d (-> parameter-set-data :parameters :d))

(def h' (-> parameter-set-data :parameters :h'))

(def adrs
  (-> (address/new-address)
      (address/set-layer-address (dec d))))

(def pk-root
  (xmss/subtree parameter-set-data sk-seed 0 h' pk-seed adrs))

(verify parameter-set-data M hypertree-signature pk-seed 0 0 pk-root)
