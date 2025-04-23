(ns effective-chainsaw.building-blocks.slh-dsa
  (:require [clojure.math :as math]
            [effective-chainsaw.building-blocks.fors :as fors]
            [effective-chainsaw.building-blocks.hypertree :as hypertree]
            [effective-chainsaw.internals.address :as address]
            [effective-chainsaw.internals.common :as common]))

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
        message-digest (common/slice-bytes digest from-0 to-0)
        tree-index (mod (common/byte-array->integer
                         (common/slice-bytes digest from-1 to-1))
                        (long (math/pow 2 (- h (/ h d)))))
        leaf-index (mod (common/byte-array->integer
                         (common/slice-bytes digest from-2 to-2))
                        (int (math/pow 2 (/ h d))))]
    [message-digest tree-index leaf-index]))

(defn- fors-address
  [tree-index leaf-index]
  (-> (address/new-address)
      (address/set-tree-address tree-index)
      (address/set-type-and-clear :fors-tree)
      (address/set-key-pair-address leaf-index)))

(defn sign*
  [{:keys [parameters functions] :as parameter-set-data} M {:keys [sk-seed sk-prf pk-seed pk-root]} additional-randomness]
  (let [{:keys [PRF_msg H_msg]} functions
        randomizer (PRF_msg sk-prf pk-seed M)
        digest (H_msg randomizer additional-randomness pk-root M)
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
    [randomizer fors-signature hypertree-signature]))

(defn verify*
  [{:keys [parameters functions] :as parameter-set-data} M [randomizer fors-signature hypertree-signature :as slh-dsa-signature] {:keys [pk-seed pk-root]}]
  (let [{:keys [sig-bytes]} parameters
        _ (common/validate-length! sig-bytes (apply concat (flatten slh-dsa-signature)))
        {:keys [H_msg]} functions
        digest (H_msg randomizer pk-seed pk-root M)
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
                      pk-root)))
