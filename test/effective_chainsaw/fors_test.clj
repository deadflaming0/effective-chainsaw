(ns effective-chainsaw.fors-test
  (:require [clojure.test :refer :all]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.fors :as fors]
            [effective-chainsaw.parameter-sets :as parameter-sets]
            [effective-chainsaw.randomness :as randomness]))

(def parameter-set-name :slh-dsa-shake-128s)

(def parameter-set-data
  (parameter-sets/parameter-set-data parameter-set-name))

(def n (-> parameter-set-data :parameters :n))

(def sk-seed (randomness/random-bytes n))
(def pk-seed (randomness/random-bytes n))
(def adrs (address/new-address))

(def k (-> parameter-set-data :parameters :k))
(def a (-> parameter-set-data :parameters :a))

(deftest generate-private-key-test
  (testing "generated private key has length `n`"
    (let [private-key (fors/generate-private-key parameter-set-data sk-seed pk-seed adrs 5)]
      (is (= n (count private-key))))))
