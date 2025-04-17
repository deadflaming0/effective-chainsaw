(ns effective-chainsaw.hypertree-test
  (:require [clojure.test :refer :all]
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

(def pk-root (slh-dsa/pk-root parameter-set-name sk-seed pk-seed))

(def M (randomness/random-bytes n))

(deftest hypertree-roundtrip-test
  (testing "sign and verify roundtrip"
    (let [signature (hypertree/sign parameter-set-data M sk-seed pk-seed 0 0)]
      (is (hypertree/verify parameter-set-data M signature pk-seed 0 0 pk-root)))))
