(ns effective-chainsaw.xmss-test
  (:require [clojure.math :as math]
            [clojure.test :refer :all]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.parameter-sets :as parameter-sets]
            [effective-chainsaw.primitives :as primitives]
            [effective-chainsaw.randomness :as randomness]
            [effective-chainsaw.wots :as wots]
            [effective-chainsaw.xmss :as xmss]))

(def parameter-set-name :slh-dsa-shake-128s)

(def parameter-set-data
  (parameter-sets/parameter-set-data parameter-set-name))

(def n (-> parameter-set-data :parameters :n))
(def h' (-> parameter-set-data :parameters :h'))

(def sk-seed (randomness/random-bytes n))
(def pk-seed (randomness/random-bytes n))
(def adrs (address/new-address))

(deftest subtree-test
  (testing "generates a wots+ public key when z = 0"
    (let [root-node (xmss/subtree parameter-set-data sk-seed 1 0 pk-seed adrs)
          wots-public-key (wots/generate-public-key parameter-set-data
                                                    sk-seed
                                                    pk-seed
                                                    (-> adrs
                                                        (address/set-type-and-clear :wots-hash)
                                                        (address/set-key-pair-address 1)))]
      (is (common/compare-bytes root-node wots-public-key))))

  (testing "correctly computes internal nodes when z > 0"
    (let [root-node (xmss/subtree parameter-set-data sk-seed 1 1 pk-seed adrs)
          left-child (xmss/subtree parameter-set-data sk-seed 2 0 pk-seed adrs)
          right-child (xmss/subtree parameter-set-data sk-seed 3 0 pk-seed adrs)
          H (-> parameter-set-data :functions :H)
          root-node' (H pk-seed
                        (-> adrs
                            (address/set-type-and-clear :tree)
                            (address/set-tree-height 1)
                            (address/set-tree-index 1))
                        (common/merge-bytes left-child right-child))]
      (is (common/compare-bytes root-node root-node'))))

  (testing "produces consistent output for identical inputs"
    (let [root-node (xmss/subtree parameter-set-data sk-seed 1 1 pk-seed adrs)
          root-node' (xmss/subtree parameter-set-data sk-seed 1 1 pk-seed adrs)]
      (is (common/compare-bytes root-node root-node')))))

(def M
  (primitives/shake256 (byte-array [0x42 0x41 0x4e 0x41 0x4e 0x41]) n)) ;; BANANA

(deftest sign-test
  (testing "generates wots+ signature and authentication path of correct length (based on h')"
    (let [idx 3
          [wots-signature authentication-path] (xmss/sign parameter-set-data
                                                          M
                                                          sk-seed
                                                          idx
                                                          pk-seed
                                                          adrs)
          wots-signature' (wots/sign parameter-set-data
                                     M
                                     sk-seed
                                     pk-seed
                                     (-> adrs
                                         (address/set-type-and-clear :wots-hash)
                                         (address/set-key-pair-address idx)))]
      (is (every? true? (map common/compare-bytes wots-signature wots-signature')))
      (is (= h' (count authentication-path)))))

  (testing "includes correct sibling nodes in authentication path for given index"
    (let [idx 5
          [_ authentication-path] (xmss/sign parameter-set-data
                                             M
                                             sk-seed
                                             idx
                                             pk-seed
                                             adrs)]
      (is (every? (fn [j]
                    (let [k (bit-xor (int (math/floor (/ idx (math/pow 2 j)))) 1)
                          authentication-path-segment (nth authentication-path j)
                          authentication-path-segment' (xmss/subtree parameter-set-data sk-seed k j pk-seed adrs)]
                      (common/compare-bytes authentication-path-segment authentication-path-segment')))
                  (range h'))))))

(deftest compute-public-key-from-signature-test
  (let [root-node (xmss/subtree parameter-set-data sk-seed 0 h' pk-seed adrs)
        idx 5
        [wots-signature authentication-path :as signature] (xmss/sign parameter-set-data M sk-seed idx pk-seed adrs)]

    (testing "reconstructs public key matching merkle root for a valid signature"
      (let [public-key' (xmss/compute-public-key-from-signature parameter-set-data idx signature M pk-seed adrs)]
        (is (common/compare-bytes root-node public-key'))))

    (testing "reconstruction fails when message is modified"
      (let [M' (byte-array (concat [127] (rest M)))
            public-key' (xmss/compute-public-key-from-signature parameter-set-data idx signature M' pk-seed adrs)]
        (is (not (common/compare-bytes root-node public-key')))))

    (testing "reconstruction fails when index is incorrect"
      (let [idx' 10
            public-key' (xmss/compute-public-key-from-signature parameter-set-data idx' signature M pk-seed adrs)]
        (is (not (common/compare-bytes root-node public-key')))))

    (testing "reconstruction fails when authentication path is tampered"
      (let [authentication-path' (shuffle authentication-path)
            signature' [wots-signature authentication-path']
            public-key' (xmss/compute-public-key-from-signature parameter-set-data idx signature' M pk-seed adrs)]
        (is (not (common/compare-bytes root-node public-key')))))))
