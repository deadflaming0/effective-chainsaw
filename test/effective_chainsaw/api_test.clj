(ns effective-chainsaw.api-test
  {:clj-kondo/config '{:linters {:refer-all {:level :off}}}}
  (:require [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as string]
            [clojure.test :refer :all]
            [effective-chainsaw.api :as api]
            [effective-chainsaw.building-blocks.parameter-sets :as parameter-sets]))

(defn- hexadecimal-string->byte-array
  [x]
  (byte-array
   (map #(unchecked-byte (Integer/parseInt (apply str %) 16))
        (partition 2 x))))

(defn- byte-array->hexadecimal-string
  [x]
  (apply str (map #(format "%02x" %) x)))

(defn- file-name->test-type
  [file-name]
  (cond
    (string/includes? file-name "keyGen") :generate-key-pair
    (string/includes? file-name "sigGen") :sign
    (string/includes? file-name "sigVer") :verify))

(defn read-test-files!
  []
  (let [test-files (filter #(.isFile %)
                           (file-seq (io/file "test/effective_chainsaw/_test_files/")))]
    (reduce (fn [prev curr]
              (with-open [r (io/reader curr)]
                (merge prev
                       {(file-name->test-type (.getName curr))
                        (json/read r :key-fn keyword)})))
            {}
            test-files)))

(defonce test-files (read-test-files!))

(defn- sk->private-key
  [sk {:keys [n]}]
  (let [[sk-seed-as-str
         sk-prf-as-str
         pk-seed-as-str
         pk-root-as-str] (map #(hexadecimal-string->byte-array (apply str %))
                              (partition (* n 2) sk))]
    {:sk-seed sk-seed-as-str
     :sk-prf sk-prf-as-str
     :pk-seed pk-seed-as-str
     :pk-root pk-root-as-str}))

(defn- private-key->sk
  [{:keys [sk-seed sk-prf pk-seed pk-root]}]
  (->> [sk-seed sk-prf pk-seed pk-root]
       (mapcat byte-array->hexadecimal-string)
       (apply str)
       string/upper-case))

(defn- pk->public-key
  [pk {:keys [n]}]
  (let [[pk-seed-as-str
         pk-root-as-str] (map #(hexadecimal-string->byte-array (apply str %))
                              (partition (* n 2) pk))]
    {:pk-seed pk-seed-as-str
     :pk-root pk-root-as-str}))

(defn- public-key->pk
  [{:keys [pk-seed pk-root]}]
  (->> [pk-seed pk-root]
       (mapcat byte-array->hexadecimal-string)
       (apply str)
       string/upper-case))

(defn- shake-test-group?
  [test-group]
  (string/includes? (:parameterSet test-group) "SHAKE"))

(defn- no-prehash-test-group?
  [test-group]
  (= "none" (:preHash test-group)))

(defn- test-type->filtered-test-groups
  [test-type filters]
  (let [test-groups (-> test-files test-type :testGroups)]
    (filter (apply every-pred filters) test-groups)))

(def generate-key-pair-test-groups
  (test-type->filtered-test-groups
   :generate-key-pair
   [shake-test-group?]))

(def sign-test-groups
  (test-type->filtered-test-groups
   :sign
   [shake-test-group?
    no-prehash-test-group?]))

(def verify-test-groups
  (test-type->filtered-test-groups
   :verify
   [shake-test-group?
    no-prehash-test-group?]))

(defn- get-parameter-set-name
  [test-group]
  (-> test-group :parameterSet string/lower-case keyword))

(defn- generate-test-name
  [parameter-set-name test-group test-case]
  (format "parameter set %s, group %s, case %s"
          (name parameter-set-name)
          (:tgId test-group)
          (:tcId test-case)))

(deftest generate-key-pair-test
  (doseq [test-group generate-key-pair-test-groups]
    (let [parameter-set-name (get-parameter-set-name test-group)]
      (doseq [test-case (:tests test-group)]
        (testing (generate-test-name parameter-set-name test-group test-case)
          (let [{:keys [skSeed skPrf pkSeed sk pk]} test-case
                sk-seed (hexadecimal-string->byte-array skSeed)
                sk-prf (hexadecimal-string->byte-array skPrf)
                pk-seed (hexadecimal-string->byte-array pkSeed)
                {:keys [private-key public-key]} (api/generate-key-pair parameter-set-name
                                                                        sk-seed
                                                                        sk-prf
                                                                        pk-seed)]
            (is (= sk (private-key->sk private-key)))
            (is (= pk (public-key->pk public-key)))))))))

(deftest sign-test
  (doseq [test-group sign-test-groups]
    (let [parameter-set-name (get-parameter-set-name test-group)
          {:keys [parameters]} (parameter-sets/parameter-set-data parameter-set-name)]
      (doseq [test-case (:tests test-group)]
        (testing (generate-test-name parameter-set-name test-group test-case)
          (let [{:keys [context message sk additionalRandomness signature]} test-case
                context (hexadecimal-string->byte-array context)
                M (hexadecimal-string->byte-array message)
                private-key (sk->private-key sk parameters)
                additional-randomness (hexadecimal-string->byte-array additionalRandomness)
                signature (hexadecimal-string->byte-array signature)
                signature' (if (:deterministic test-group)
                             (api/sign parameter-set-name M context private-key)
                             (api/sign parameter-set-name M context private-key additional-randomness))]
            (is (= (byte-array->hexadecimal-string signature)
                   (byte-array->hexadecimal-string signature')))))))))

(deftest verify-test
  (doseq [test-group verify-test-groups]
    (let [parameter-set-name (get-parameter-set-name test-group)
          {:keys [parameters]} (parameter-sets/parameter-set-data parameter-set-name)]
      (doseq [test-case (:tests test-group)]
        (testing (generate-test-name parameter-set-name test-group test-case)
          (let [{:keys [message signature pk testPassed reason]} test-case
                M (hexadecimal-string->byte-array message)
                signature (hexadecimal-string->byte-array signature)
                public-key (pk->public-key pk parameters)
                test-passed? (boolean testPassed)]
            (case reason
              ("invalid signature - too large"
               "invalid signature - too small")
              (is (thrown? Exception (api/verify parameter-set-name M signature nil public-key)))

              ("modified message"
               "modified signature - R"
               "modified signature - SIGFORS"
               "modified signature - SIGHT"
               "valid signature and message - signature should verify successfully")
              (is (= test-passed? (api/verify parameter-set-name M signature nil public-key))))))))))
