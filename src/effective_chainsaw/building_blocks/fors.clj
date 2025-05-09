(ns effective-chainsaw.building-blocks.fors
  (:require [clojure.math :as math]
            [effective-chainsaw.internals.address :as address]
            [effective-chainsaw.internals.common :as common]))

(defn generate-private-key
  "Generates a FORS private-key value."
  [{:keys [functions]} sk-seed pk-seed adrs index]
  (let [key-pair-address (address/get-key-pair-address adrs)
        private-key-adrs (-> adrs
                             (address/set-type-and-clear :fors-prf)
                             (address/set-key-pair-address key-pair-address)
                             (address/set-tree-index index))
        PRF (:PRF functions)]
    (PRF pk-seed sk-seed private-key-adrs)))

(defn subtree
  "Computes the root of a Merkle subtree of FORS public values."
  [{:keys [functions] :as parameter-set-data} sk-seed index height pk-seed adrs]
  ;; TODO: add validation
  (if (zero? height)
    (let [private-key (generate-private-key parameter-set-data sk-seed pk-seed adrs index)
          node-adrs (-> adrs
                        (address/set-tree-height 0)
                        (address/set-tree-index index))
          F (:F functions)
          node (F pk-seed node-adrs private-key)]
      node)
    (let [left-node (subtree parameter-set-data sk-seed (* 2 index) (dec height) pk-seed adrs)
          right-node (subtree parameter-set-data sk-seed (inc (* 2 index)) (dec height) pk-seed adrs)
          node-adrs (-> adrs
                        (address/set-tree-height height)
                        (address/set-tree-index index))
          H (:H functions)
          node (H pk-seed node-adrs (common/merge-bytes left-node right-node))]
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
                                       authentication-path (pmap (fn [j]
                                                                   (let [s (bit-xor (int (math/floor (/ index (int (math/pow 2 j))))) 1)
                                                                         authentication-path-segment (subtree parameter-set-data
                                                                                                              sk-seed
                                                                                                              (+ (* i (int (math/pow 2 (- a j)))) s)
                                                                                                              j
                                                                                                              pk-seed
                                                                                                              adrs)]
                                                                     authentication-path-segment))
                                                                 (range a))]
                                   (common/merge-bytes fors-signature' private-key authentication-path)))
                               (byte-array 0)
                               (range k))]
    fors-signature))

(defn- extract-fors-signature-segment
  [fors-signature {:keys [a n]} i]
  (let [private-key-from (* i (inc a) n)
        private-key-to (* (inc (* i (inc a))) n)
        authentication-path-from private-key-to
        authentication-path-to (* (inc i) (inc a) n)]
    [(common/slice-bytes fors-signature
                         private-key-from
                         private-key-to)
     (common/slice-bytes fors-signature
                         authentication-path-from
                         authentication-path-to)]))

(defn- extract-authentication-path-segment
  [authentication-path n j]
  (let [from (* j n)
        to (+ from n)]
    (common/slice-bytes authentication-path
                        from
                        to)))

(defn compute-public-key-from-signature
  "Computes a FORS public key from a FORS signature."
  [{:keys [parameters functions]} fors-signature message-digest pk-seed adrs]
  (let [{:keys [a k n]} parameters
        indices (common/byte-array->base-2b message-digest a k)
        t (int (math/pow 2 a))
        {:keys [F H T_l]} functions
        fors-public-keys (reduce (fn [root i]
                                   (let [[private-key
                                          authentication-path] (extract-fors-signature-segment
                                                                fors-signature
                                                                parameters
                                                                i)
                                         index (nth indices i)
                                         adrs' (-> adrs
                                                   (address/set-tree-height 0)
                                                   (address/set-tree-index (+ (* i t) index)))
                                         node-0 (F pk-seed adrs' private-key)
                                         [root' _] (reduce (fn [[node' adrs'] j]
                                                             (let [adrs'' (address/set-tree-height adrs' (inc j))
                                                                   tree-index (address/get-tree-index adrs'')
                                                                   authentication-path-segment (extract-authentication-path-segment
                                                                                                authentication-path
                                                                                                n
                                                                                                j)]
                                                               (if (even? (int (math/floor (/ index (int (math/pow 2 j))))))
                                                                 (let [adrs''' (address/set-tree-index adrs'' (int (/ tree-index 2)))]
                                                                   [(H pk-seed adrs''' (common/merge-bytes node'
                                                                                                           authentication-path-segment))
                                                                    adrs'''])
                                                                 (let [adrs''' (address/set-tree-index adrs'' (int (/ (dec tree-index) 2)))]
                                                                   [(H pk-seed adrs''' (common/merge-bytes authentication-path-segment
                                                                                                           node'))
                                                                    adrs''']))))
                                                           [node-0
                                                            adrs']
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
