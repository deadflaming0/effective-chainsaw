(ns effective-chainsaw.fors-test
  (:require [clojure.math :as math]
            [clojure.test :refer :all]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.fors :as fors]
            [effective-chainsaw.hypertree :as hypertree]
            [effective-chainsaw.parameter-sets :as parameter-sets]
            [effective-chainsaw.randomness :as randomness]
            [effective-chainsaw.slh-dsa :as slh-dsa]))

(def parameter-set-name :slh-dsa-shake-128s)

(def parameter-set-data
  (parameter-sets/parameter-set-data parameter-set-name))

(def n (-> parameter-set-data :parameters :n))

(def sk-seed (randomness/random-bytes n))
(def pk-seed (randomness/random-bytes n))
(def adrs (address/new-address))

(deftest subtree-test
  (testing "generates a fors public value when depth (z) = 0"
    (let [i 1
          root-node (fors/subtree parameter-set-data sk-seed i 0 pk-seed adrs)
          fors-private-key (fors/generate-private-key parameter-set-data sk-seed pk-seed adrs i)
          F (-> parameter-set-data :functions :F)
          fors-public-value (F pk-seed
                               (-> adrs
                                   (address/set-tree-height 0)
                                   (address/set-tree-index i))
                               fors-private-key)]
      (is (common/equal-bytes? root-node fors-public-value))))

  (testing "correctly computes internal nodes when depth (z) > 0"
    (let [root-node (fors/subtree parameter-set-data sk-seed 1 1 pk-seed adrs)
          left-child (fors/subtree parameter-set-data sk-seed 2 0 pk-seed adrs)
          right-child (fors/subtree parameter-set-data sk-seed 3 0 pk-seed adrs)
          H (-> parameter-set-data :functions :H)
          root-node' (H pk-seed
                        (-> adrs
                            (address/set-type-and-clear :tree)
                            (address/set-tree-height 1)
                            (address/set-tree-index 1))
                        (common/merge-bytes left-child right-child))]
      (is (common/equal-bytes? root-node root-node'))))

  (testing "produces consistent output for identical inputs"
    (let [root-node (fors/subtree parameter-set-data sk-seed 1 1 pk-seed adrs)
          root-node' (fors/subtree parameter-set-data sk-seed 1 1 pk-seed adrs)]
      (is (common/equal-bytes? root-node root-node')))))

(def k (-> parameter-set-data :parameters :k))
(def a (-> parameter-set-data :parameters :a))

(def message-digest
  (randomness/random-bytes (int (math/ceil (/ (* k a) 8))))) ;; from algorithm 19, line 6 (slh_sign_internal)

(deftest sign-test
  (testing "outputs fors private keys along with their authentication paths"
    (let [fors-signature (fors/sign parameter-set-data message-digest sk-seed pk-seed adrs)
          grouped-elements (group-by count fors-signature)
          fors-private-keys (get grouped-elements n) ;; implicit check for each fors private key length
          authentication-paths (get grouped-elements a)] ;; implicit check for each authentication path length
      (is (= k
             (count fors-private-keys)
             (count authentication-paths)))
      (is (= (count (apply concat (flatten fors-signature)))
             (* k (inc a) n))))))

(deftest compute-public-key-from-signature-test
  (testing "a public key derived from a fors signature, signed by the hypertree, yields the hypertree public key"
    (let [fors-signature (fors/sign parameter-set-data message-digest sk-seed pk-seed adrs)
          public-key' (fors/compute-public-key-from-signature parameter-set-data fors-signature message-digest pk-seed adrs)
          hypertree-signature (hypertree/sign parameter-set-data public-key' sk-seed pk-seed 0 0)
          pk-root (slh-dsa/pk-root parameter-set-name sk-seed pk-seed)]
      (is (hypertree/verify parameter-set-data public-key' hypertree-signature pk-seed 0 0 pk-root)))))
