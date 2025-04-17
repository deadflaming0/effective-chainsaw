(ns effective-chainsaw.wots-test
  (:require [clojure.test :refer :all]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.parameter-sets :as parameter-sets]
            [effective-chainsaw.randomness :as randomness]
            [effective-chainsaw.wots :as wots]))

(def parameter-set-name :slh-dsa-shake-128s)

(def parameter-set-data
  (parameter-sets/parameter-set-data parameter-set-name))

(def n (-> parameter-set-data :parameters :n))

(def M (randomness/random-bytes n))

(deftest generate-public-key-test
  (let [sk-seed (randomness/random-bytes n)
        pk-seed (randomness/random-bytes n)
        adrs (address/new-address)
        public-key (wots/generate-public-key parameter-set-data sk-seed pk-seed adrs)]

    (testing "generated public key is deterministic given same inputs"
      (let [public-key' (wots/generate-public-key parameter-set-data sk-seed pk-seed adrs)]
        (is (common/equal-bytes? public-key public-key'))))

    (testing "public key changes with sk-seed variation"
      (let [sk-seed' (randomness/random-bytes 16)
            public-key' (wots/generate-public-key parameter-set-data sk-seed' pk-seed adrs)]
        (is (not (common/equal-bytes? public-key public-key')))))

    (testing "public key changes with pk-seed variation"
      (let [pk-seed' (randomness/random-bytes 16)
            public-key' (wots/generate-public-key parameter-set-data sk-seed pk-seed' adrs)]
        (is (not (common/equal-bytes? public-key public-key')))))

    (testing "public key changes with address variation"
      (let [adrs' (doto
                   (address/new-address)
                    (java.util.Arrays/fill (byte 122)))
            public-key' (wots/generate-public-key parameter-set-data sk-seed pk-seed adrs')]
        (is (not (common/equal-bytes? public-key public-key')))))

    (testing "public key has length n"
      (is (= n (count public-key))))))

(deftest sign-test
  (let [sk-seed (randomness/random-bytes n)
        pk-seed (randomness/random-bytes n)
        adrs (address/new-address)
        signature (wots/sign parameter-set-data M sk-seed pk-seed adrs)]

    (testing "signature is deterministic given same inputs"
      (let [signature' (wots/sign parameter-set-data M sk-seed pk-seed adrs)]
        (is (every? true? (map common/equal-bytes? signature signature')))))

    (testing "signature changes with message variation"
      (let [M' (byte-array (concat (butlast M) [127]))
            signature' (wots/sign parameter-set-data M' sk-seed pk-seed adrs)]
        (is (some false? (map common/equal-bytes? signature signature')))))

    (testing "signature changes with sk-seed variation"
      (let [sk-seed' (randomness/random-bytes n)
            signature' (wots/sign parameter-set-data M sk-seed' pk-seed adrs)]
        (is (some false? (map common/equal-bytes? signature signature')))))

    (testing "signature changes with pk-seed variation"
      (let [pk-seed' (randomness/random-bytes n)
            signature' (wots/sign parameter-set-data M sk-seed pk-seed' adrs)]
        (is (some false? (map common/equal-bytes? signature signature')))))

    (testing "signature changes with adrs variation"
      (let [adrs' (doto
                   (address/new-address)
                    (java.util.Arrays/fill (byte 122)))
            signature' (wots/sign parameter-set-data M sk-seed pk-seed adrs')]
        (is (some false? (map common/equal-bytes? signature signature')))))

    (testing "signature conforms to expected structure: len byte arrays of length n"
      (let [{:keys [len]} (wots/get-additional-values (:parameters parameter-set-data))]
        (is (= (count signature) len))
        (is (every? bytes? signature)))
      (is (every? (partial = n) (map count signature))))))

(deftest compute-public-key-from-signature-test
  (let [sk-seed (randomness/random-bytes n)
        pk-seed (randomness/random-bytes n)
        adrs (address/new-address)
        public-key (wots/generate-public-key parameter-set-data sk-seed pk-seed adrs)
        signature (wots/sign parameter-set-data M sk-seed pk-seed adrs)]

    (testing "computed public key from valid signature equals original"
      (let [public-key' (wots/compute-public-key-from-signature parameter-set-data signature M pk-seed adrs)]
        (is (common/equal-bytes? public-key public-key'))))

    (testing "computed public key changes when message changes"
      (let [M' (byte-array (concat (butlast M) [127]))
            public-key' (wots/compute-public-key-from-signature parameter-set-data signature M' pk-seed adrs)]
        (is (not (common/equal-bytes? public-key public-key')))))

    (testing "computed public key changes when signature is mutated"
      (let [signature' (shuffle signature)
            public-key' (wots/compute-public-key-from-signature parameter-set-data signature' M pk-seed adrs)]
        (is (not (common/equal-bytes? public-key public-key')))))))
