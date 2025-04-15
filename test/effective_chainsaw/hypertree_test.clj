(ns effective-chainsaw.hypertree-test
  (:require [clojure.test :refer :all]
            [effective-chainsaw.hypertree :as hypertree]
            [effective-chainsaw.parameter-sets :as parameter-sets]
            [effective-chainsaw.primitives :as primitives]
            [effective-chainsaw.randomness :as randomness]
            [effective-chainsaw.slh-dsa :as slh-dsa]))

(def parameter-set-name :slh-dsa-shake-128s)

(def parameter-set-data
  (parameter-sets/parameter-set-data parameter-set-name))

(def n (-> parameter-set-data :parameters :n))

(def sk-seed (randomness/random-bytes n))
(def pk-seed (randomness/random-bytes n))

(def pk-root (slh-dsa/pk-root parameter-set-name sk-seed pk-seed))

(def M
  (primitives/shake256
   (byte-array [0x0c 0x0c 0x63 0x72 0x6f 0x63 0x6f 0x64 0x69 0x6c 0x6f 0x0a]) n))

(deftest hypertree-roundtrip-test
  (testing "sign and verify roundtrip"
    (let [signature (hypertree/sign parameter-set-data M sk-seed pk-seed 0 0)]
      (is (hypertree/verify parameter-set-data M signature pk-seed 0 0 pk-root)))))
