(ns effective-chainsaw.xmss-test
  (:require [clojure.test :refer :all]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.parameter-sets :as parameter-sets]
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
  (testing "generates a wots+ public key when depth (z) = 0"
    (let [i 1
          root-node (xmss/subtree parameter-set-data sk-seed i 0 pk-seed adrs)
          wots-public-key (wots/generate-public-key parameter-set-data
                                                    sk-seed
                                                    pk-seed
                                                    (-> adrs
                                                        (address/set-type-and-clear :wots-hash)
                                                        (address/set-key-pair-address 1)))]
      (is (common/equal-bytes? root-node wots-public-key))))

  (testing "correctly computes internal nodes when depth (z) > 0"
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
      (is (common/equal-bytes? root-node root-node'))))

  (testing "produces consistent output for identical inputs"
    (let [root-node (xmss/subtree parameter-set-data sk-seed 1 1 pk-seed adrs)
          root-node' (xmss/subtree parameter-set-data sk-seed 1 1 pk-seed adrs)]
      (is (common/equal-bytes? root-node root-node')))))

(def M (randomness/random-bytes n))

(deftest sign-test
  (testing "generates wots+ signature and authentication path"
    (let [idx 3
          [wots-signature
           authentication-path
           :as xmss-signature] (xmss/sign parameter-set-data M sk-seed idx pk-seed adrs)
          wots-signature' (wots/sign parameter-set-data
                                     M
                                     sk-seed
                                     pk-seed
                                     (-> adrs
                                         (address/set-type-and-clear :wots-hash)
                                         (address/set-key-pair-address idx)))
          {:keys [len]} (wots/get-additional-values (:parameters parameter-set-data))]
      (is (every? true? (map common/equal-bytes? wots-signature wots-signature')))
      (is (= h' (count authentication-path)))
      (is (every? (partial = n) (map count authentication-path)))
      (is (= (count (apply concat (flatten xmss-signature)))
             (* (+ h' len) n))))))

(deftest compute-public-key-from-signature-test
  (let [root-node (xmss/subtree parameter-set-data sk-seed 0 h' pk-seed adrs)
        idx 5
        [wots-signature
         authentication-path
         :as xmss-signature] (xmss/sign parameter-set-data M sk-seed idx pk-seed adrs)]

    (testing "reconstructs a public key that matches the merkle root for a valid signature"
      (let [public-key' (xmss/compute-public-key-from-signature parameter-set-data idx xmss-signature M pk-seed adrs)]
        (is (common/equal-bytes? root-node public-key'))))

    (testing "reconstruction fails when message is modified"
      (let [M' (byte-array (concat [127] (rest M)))
            public-key' (xmss/compute-public-key-from-signature parameter-set-data idx xmss-signature M' pk-seed adrs)]
        (is (not (common/equal-bytes? root-node public-key')))))

    (testing "reconstruction fails when index is incorrect"
      (let [idx' 10
            public-key' (xmss/compute-public-key-from-signature parameter-set-data idx' xmss-signature M pk-seed adrs)]
        (is (not (common/equal-bytes? root-node public-key')))))

    (testing "reconstruction fails when authentication path is tampered with"
      (let [authentication-path' (shuffle authentication-path)
            xmss-signature' [wots-signature authentication-path']
            public-key' (xmss/compute-public-key-from-signature parameter-set-data idx xmss-signature' M pk-seed adrs)]
        (is (not (common/equal-bytes? root-node public-key')))))))
