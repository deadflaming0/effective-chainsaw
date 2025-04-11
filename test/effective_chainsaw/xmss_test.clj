(ns effective-chainsaw.xmss-test
  (:require [clojure.test :refer :all]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.parameter-sets :as parameter-sets]
            [effective-chainsaw.primitives :as primitives]
            [effective-chainsaw.randomness :as randomness]
            [effective-chainsaw.xmss :as xmss]))

(def parameter-set-name :slh-dsa-shake-128s)

(def parameter-set-data
  (parameter-sets/parameter-set-data parameter-set-name))

(def n (-> parameter-set-data :parameters :n))
(def h' (-> parameter-set-data :parameters :h'))

(def sk-seed (randomness/random-bytes n))
(def pk-seed (randomness/random-bytes n))
(def adrs (address/new-address))

(def M
  (primitives/shake256 (byte-array [0x42 0x41 0x4e 0x41 0x4e 0x41]) (* n 8))) ;; BANANA

(deftest everything-test
  (testing "everything works"
    (let [root-node (xmss/subtree parameter-set-data
                                  sk-seed
                                  0
                                  h'
                                  pk-seed
                                  adrs)
          idx 3
          signature (xmss/sign parameter-set-data
                               M
                               sk-seed
                               idx
                               pk-seed
                               adrs)
          public-key' (xmss/compute-public-key-from-signature parameter-set-data
                                                              idx
                                                              signature
                                                              M
                                                              pk-seed
                                                              adrs)]
      (is (java.util.Arrays/equals root-node public-key')))))
