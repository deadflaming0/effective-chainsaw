(ns effective-chainsaw.building-blocks.slh-dsa
  (:require [clojure.math :as math]
            [effective-chainsaw.building-blocks.fors :as fors]
            [effective-chainsaw.building-blocks.hypertree :as hypertree]
            [effective-chainsaw.building-blocks.xmss :as xmss]
            [effective-chainsaw.internals.address :as address]
            [effective-chainsaw.internals.common :as common]))

(defn generate-key-pair
  [{:keys [parameters] :as parameter-set-data} sk-seed sk-prf pk-seed]
  (let [{:keys [d h']} parameters
        adrs (-> (address/new-address)
                 (address/set-layer-address (dec d)))
        pk-root (xmss/subtree parameter-set-data sk-seed 0 h' pk-seed adrs)]
    {:private-key
     {:sk-seed sk-seed
      :sk-prf sk-prf
      :pk-seed pk-seed
      :pk-root pk-root}
     :public-key
     {:pk-seed pk-seed
      :pk-root pk-root}}))

(defn- parse-digest
  [digest {:keys [k a h d]}]
  (let [message-digest-size-in-bytes (int (math/ceil (/ (* k a) 8)))
        tree-index-size-in-bytes (int (math/ceil (/ (- h (/ h d)) 8)))
        leaf-index-size-in-bytes (int (math/ceil (/ h (* 8 d))))

        from-0 0
        to-0 message-digest-size-in-bytes
        from-1 to-0
        to-1 (+ from-1 tree-index-size-in-bytes)
        from-2 to-1
        to-2 (+ from-2 leaf-index-size-in-bytes)

        message-digest-bytes (common/slice-bytes digest from-0 to-0)

        tree-index-bytes (common/slice-bytes digest from-1 to-1)
        tree-index-bytes-to-integer (BigInteger. 1 tree-index-bytes)
        tree-index (.mod tree-index-bytes-to-integer
                         (.pow BigInteger/TWO (- h (/ h d))))

        leaf-index-bytes (common/slice-bytes digest from-2 to-2)
        leaf-index-bytes-to-integer (BigInteger. 1 leaf-index-bytes)
        leaf-index (.mod leaf-index-bytes-to-integer
                         (.pow BigInteger/TWO (/ h d)))]
    [message-digest-bytes
     tree-index
     leaf-index]))

(defn- fors-address
  [tree-index leaf-index]
  (-> (address/new-address)
      (address/set-tree-address tree-index)
      (address/set-type-and-clear :fors-tree)
      (address/set-key-pair-address leaf-index)))

(defn sign
  [{:keys [parameters functions] :as parameter-set-data} M {:keys [sk-seed sk-prf pk-seed pk-root]} additional-randomness]
  (let [{:keys [PRF_msg H_msg]} functions
        randomizer (PRF_msg sk-prf
                            additional-randomness
                            M)
        digest (H_msg randomizer
                      pk-seed
                      pk-root
                      M)
        [message-digest tree-index leaf-index] (parse-digest digest parameters)
        fors-adrs (fors-address tree-index leaf-index)
        fors-signature (fors/sign parameter-set-data
                                  message-digest
                                  sk-seed
                                  pk-seed
                                  fors-adrs)
        fors-public-key (fors/compute-public-key-from-signature parameter-set-data
                                                                fors-signature
                                                                message-digest
                                                                pk-seed
                                                                fors-adrs)
        hypertree-signature (hypertree/sign parameter-set-data
                                            fors-public-key
                                            sk-seed
                                            pk-seed
                                            tree-index
                                            leaf-index)]
    (common/merge-bytes randomizer
                        fors-signature
                        hypertree-signature)))

(defn- parse-signature
  [signature {:keys [n k a]}]
  (let [first-cut n
        second-cut (* (+ 1 (* k (inc a))) n)]
    [(common/slice-bytes signature 0 first-cut)
     (common/slice-bytes signature first-cut second-cut)
     (common/slice-bytes signature second-cut (alength signature))]))

(defn verify
  [{:keys [parameters functions] :as parameter-set-data} M signature {:keys [pk-seed pk-root]}]
  (let [{:keys [sig-bytes]} parameters]
    (if (not= sig-bytes (count signature))
      false
      (let [[randomizer fors-signature hypertree-signature] (parse-signature signature parameters)
            {:keys [H_msg]} functions
            digest (H_msg randomizer
                          pk-seed
                          pk-root
                          M)
            [message-digest tree-index leaf-index] (parse-digest digest parameters)
            fors-adrs (fors-address tree-index leaf-index)
            fors-public-key (fors/compute-public-key-from-signature parameter-set-data
                                                                    fors-signature
                                                                    message-digest
                                                                    pk-seed
                                                                    fors-adrs)]
        (hypertree/verify parameter-set-data
                          fors-public-key
                          hypertree-signature
                          pk-seed
                          tree-index
                          leaf-index
                          pk-root)))))
