(ns effective-chainsaw.api-test
  {:clj-kondo/config '{:linters {:refer-all {:level :off}}}}
  (:require [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as string]
            [clojure.test :refer :all]
            [effective-chainsaw.api :as api]))

(defn- hexadecimal-string->byte-array
  [x]
  (byte-array
    (map #(unchecked-byte (Integer/parseInt (apply str %) 16))
         (partition 2 x))))

(defn byte-array->hexadecimal-string
  [x]
  (apply str (map #(format "%02x" %) x)))

(defn- file-name->target
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
                (merge
                  prev
                  {(file-name->target (.getName curr))
                   (json/read r :key-fn keyword)})))
            {}
            test-files)))

(def test-files (read-test-files!))

(defn- sk->private-key
  [sk {:keys [n]}]
  (let [[sk-seed-as-str
         sk-prf-as-str
         pk-seed-as-str
         pk-root-as-str] (map #(hexadecimal-string->byte-array
                                 (apply str %))
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
         pk-root-as-str] (map #(hexadecimal-string->byte-array
                                 (apply str %))
                              (partition (* n 2) pk))]
    {:pk-seed pk-seed-as-str
     :pk-root pk-root-as-str}))

(defn- public-key->pk
  [{:keys [pk-seed pk-root]}]
  (->> [pk-seed pk-root]
       (mapcat byte-array->hexadecimal-string)
       (apply str)
       string/upper-case))

(deftest generate-key-pair-test
  (let [test-groups (-> test-files :generate-key-pair :testGroups)
        shake-test-groups (filter #(string/includes? (:parameterSet %) "SHAKE") test-groups)]
    (doseq [shake-test-group shake-test-groups]
      (let [parameter-set-name (-> shake-test-group :parameterSet string/lower-case keyword)]
        (doseq [shake-test (:tests shake-test-group)]
          (testing (str (name parameter-set-name) ", #" (:tgId shake-test-group) "." (:tcId shake-test))
            (let [{:keys [skSeed skPrf pkSeed sk pk]} shake-test
                  sk-seed (hexadecimal-string->byte-array skSeed)
                  sk-prf (hexadecimal-string->byte-array skPrf)
                  pk-seed (hexadecimal-string->byte-array pkSeed)
                  {:keys [private-key public-key]} (api/generate-key-pair parameter-set-name
                                                                          sk-seed
                                                                          sk-prf
                                                                          pk-seed)]
              (is (= sk (private-key->sk private-key)))
              (is (= pk (public-key->pk public-key))))))))))
