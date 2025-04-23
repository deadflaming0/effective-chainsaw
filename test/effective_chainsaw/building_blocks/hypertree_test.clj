(ns effective-chainsaw.building-blocks.hypertree-test
  {:clj-kondo/config '{:linters {:refer-all {:level :off}}}}
  (:require [clojure.test :refer :all]
            [effective-chainsaw.building-blocks.hypertree :as hypertree]
            [effective-chainsaw.building-blocks.parameter-sets :as parameter-sets]
            [effective-chainsaw.building-blocks.xmss :as xmss]
            [effective-chainsaw.internals.address :as address]
            [effective-chainsaw.internals.randomness :as randomness]))

(def parameter-set-name :slh-dsa-shake-128s)

(def parameter-set-data
  (parameter-sets/parameter-set-data parameter-set-name))

(def n (-> parameter-set-data :parameters :n))

(def sk-seed (randomness/random-bytes n))
(def pk-seed (randomness/random-bytes n))

(def d (-> parameter-set-data :parameters :d))
(def h' (-> parameter-set-data :parameters :h'))

(def adrs (-> (address/new-address)
              (address/set-layer-address (dec d))))

(def pk-root (xmss/subtree parameter-set-data sk-seed 0 h' pk-seed adrs))

(def M (randomness/random-bytes n))

(deftest hypertree-roundtrip-test
  (testing "signs and verifies correctly (roundtrip test)"
    (let [signature (hypertree/sign parameter-set-data M sk-seed pk-seed 0 0)]
      (is (hypertree/verify parameter-set-data M signature pk-seed 0 0 pk-root)))))
