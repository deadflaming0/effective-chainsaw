(ns effective-chainsaw.api-test
  {:clj-kondo/config '{:linters {:refer-all {:level :off}
                                 :unresolved-symbol {:level :off}}}}
  (:import (java.security GeneralSecurityException))
  (:require [clojure.spec.alpha :as s]
            [clojure.spec.test.alpha :as stest]
            [clojure.string :as string]
            [clojure.test :refer :all]
            [clojure.test.check :as tc]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [effective-chainsaw.api :as api]
            [effective-chainsaw.building-blocks.parameter-sets :as parameter-sets]
            [effective-chainsaw.building-blocks.slh-dsa :as slh-dsa]
            [effective-chainsaw.specs :as specs]
            [test-vectors :as test-vectors]))

(defn- get-parameter-set-name
  [test-group]
  (-> test-group :parameterSet string/lower-case keyword))

(defn- generate-test-name
  [parameter-set-name test-group test-case]
  (format "parameter set %s, group %s, case %s"
          (name parameter-set-name)
          (:tgId test-group)
          (:tcId test-case)))

(defn- normalize
  [m] ;; used in `generate-key-pair-test`
  (into {} (map (fn [[k v]]
                  [k (if (instance? (Class/forName "[B") v)
                       (seq v)
                       v)])
                m)))

(deftest generate-key-pair-test
  (testing "official test vectors"
    (doseq [test-group (test-vectors/generate-key-pair-test-groups)]
      (let [parameter-set-name (get-parameter-set-name test-group)]
        (doseq [test-case (:tests test-group)]
          (testing (generate-test-name parameter-set-name test-group test-case)
            (let [m (test-vectors/test-case->normalized-map parameter-set-name :generate-key-pair test-case)
                  {:keys [sk-seed sk-prf pk-seed]} (:input m)
                  {:keys [expected-private-key expected-public-key]} (:output m)
                  {:keys [private-key public-key]} (slh-dsa/generate-key-pair
                                                    (parameter-sets/parameter-set-data parameter-set-name)
                                                    sk-seed
                                                    sk-prf
                                                    pk-seed)]
              (is (= (normalize expected-private-key)
                     (normalize private-key)))
              (is (= (normalize expected-public-key)
                     (normalize public-key))))))))))

(deftest sign-test
  (testing "official test vectors"
    (doseq [test-group (test-vectors/sign-test-groups)]
      (let [parameter-set-name (get-parameter-set-name test-group)]
        (doseq [test-case (:tests test-group)]
          (testing (generate-test-name parameter-set-name test-group test-case)
            (let [m (test-vectors/test-case->normalized-map parameter-set-name :sign test-case)
                  {:keys [M context private-key additional-randomness]} (:input m)
                  {:keys [expected-signature]} (:output m)
                  signature (if (:deterministic test-group)
                              (api/sign parameter-set-name M context private-key)
                              (api/sign parameter-set-name M context private-key additional-randomness))]
              (is (= (seq expected-signature) (seq signature)))))))))
  (testing "throws exception when context string is too long"
    (is (thrown? GeneralSecurityException
                 (api/sign :slh-dsa-shake-128s (byte-array 1) (byte-array 256) {})))))

(deftest verify-test
  (testing "official test vectors"
    (doseq [test-group (test-vectors/verify-test-groups)]
      (let [parameter-set-name (get-parameter-set-name test-group)]
        (doseq [test-case (:tests test-group)]
          (testing (generate-test-name parameter-set-name test-group test-case)
            (let [m (test-vectors/test-case->normalized-map parameter-set-name :verify test-case)
                  {:keys [M signature context public-key]} (:input m)
                  {:keys [expected-test-passed?]} (:output m)]
              (is (= expected-test-passed?
                     (api/verify parameter-set-name M signature context public-key))))))))))

(deftest lifecycle-test
  (stest/instrument [`api/generate-key-pair
                     `api/generate-context
                     `api/sign
                     `api/verify])
  (try
    (tc/quick-check
     15 ;; key gen + sig gen + sig ver is slooow, that's why only 15
     (prop/for-all
      [parameter-set-name (s/gen ::specs/parameter-set-name)
       message (s/gen ::specs/message)]
      (let [{:keys [private-key public-key]} (api/generate-key-pair parameter-set-name)
            context (gen/generate (s/gen ::specs/context))
            signature (api/sign parameter-set-name message context private-key)
            verification-result (api/verify parameter-set-name message signature context public-key)]
        (is (true? verification-result)))))
    (finally
      (stest/unstrument [`api/generate-key-pair
                         `api/generate-context
                         `api/sign
                         `api/verify]))))
