(ns effective-chainsaw.fors
  (:require [clojure.math :as math]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]))

(defn generate-private-key
  "Generates a FORS private-key value."
  [{:keys [functions]} sk-seed pk-seed adrs idx]
  (let [key-pair-address (address/get-key-pair-address adrs)
        private-key-adrs (-> adrs
                             (address/set-type-and-clear :fors-prf)
                             (address/set-key-pair-address key-pair-address)
                             (address/set-tree-index idx))
        PRF (:PRF functions)]
    (PRF pk-seed sk-seed private-key-adrs)))

(defn subtree ;; same as xmss... merge?
  "Computes the root of a Merkle subtree of FORS public values."
  [{:keys [functions] :as parameter-set-data} sk-seed i z pk-seed adrs]
  ;; add validation
  (if (zero? z)
    (let [private-key (generate-private-key parameter-set-data sk-seed pk-seed adrs i)
          F (:F functions)
          node (F pk-seed
                  (-> adrs
                      (address/set-tree-height 0)
                      (address/set-tree-index i))
                  private-key)]
      node)
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
  "Generates a FORS signature."
  [{:keys [parameters] :as parameter-set-data} message-digest sk-seed pk-seed adrs]
  (let [{:keys [a k]} parameters
        indices (common/byte-array->base-2b message-digest a k)
        t (int (math/pow 2 a))
        fors-signature (reduce (fn [fors-signature' i]
                                 (let [index (nth indices i)
                                       private-key (generate-private-key parameter-set-data
                                                                         sk-seed
                                                                         pk-seed
                                                                         adrs
                                                                         (+ (* i t) index))
                                       authentication-path (map (fn [j]
                                                                  (let [s (bit-xor (int (math/floor (/ index (math/pow 2 j)))) 1)
                                                                        authentication-path-segment (subtree parameter-set-data
                                                                                                             sk-seed
                                                                                                             (+ (* i (int (math/pow 2 (- a j)))) s)
                                                                                                             j
                                                                                                             pk-seed
                                                                                                             adrs)]
                                                                    authentication-path-segment))
                                                                (range a))]
                                   (conj fors-signature' private-key authentication-path)))
                               []
                               (range k))]
    fors-signature))

(defn compute-public-key-from-signature
  "Computes a FORS public key from a FORS signature."
  [{:keys [parameters functions]} fors-signature message-digest pk-seed adrs]
  (let [{:keys [a k]} parameters
        {:keys [F H T_l]} functions
        indices (common/byte-array->base-2b message-digest a k)
        partitioned (partition 2 fors-signature) ;; pairs of fors signature + authentication path
        t (int (math/pow 2 a))
        fors-public-keys (reduce (fn [root i]
                                   (let [[private-key authentication-path] (nth partitioned i)
                                         index (nth indices i)
                                         adrs' (-> adrs
                                                   (address/set-tree-height 0)
                                                   (address/set-tree-index (+ (* i t) index)))
                                         node-0 (F pk-seed adrs' private-key)
                                         [root' _] (reduce (fn [[node adrs'] j]
                                                             (let [new-adrs (address/set-tree-height adrs' (inc j))
                                                                   tree-index (address/get-tree-index new-adrs)
                                                                   authentication-path-segment (nth authentication-path j)]
                                                               (if (even? (int (math/floor (/ index (int (math/pow 2 j))))))
                                                                 (let [new-adrs' (address/set-tree-index new-adrs (int (/ tree-index 2)))]
                                                                   [(H pk-seed new-adrs' (common/merge-bytes node authentication-path-segment))
                                                                    new-adrs'])
                                                                 (let [new-adrs' (address/set-tree-index new-adrs (int (/ (dec tree-index) 2)))]
                                                                   [(H pk-seed new-adrs' (common/merge-bytes authentication-path-segment node))
                                                                    new-adrs']))))
                                                           [node-0 adrs']
                                                           (range a))]
                                     (conj root root')))
                                 []
                                 (range k))
        key-pair-address (address/get-key-pair-address adrs)
        fors-pk-adrs (-> adrs
                         (address/set-type-and-clear :fors-roots)
                         (address/set-key-pair-address key-pair-address))
        public-key (T_l pk-seed fors-pk-adrs fors-public-keys)]
    public-key))
