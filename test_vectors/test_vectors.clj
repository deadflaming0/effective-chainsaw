(ns test-vectors
  (:require [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as string]))

(defn- file-name->test-type
  [file-name]
  (cond
    (string/includes? file-name "keyGen") :generate-key-pair
    (string/includes? file-name "sigGen") :sign
    (string/includes? file-name "sigVer") :verify))

(defn- read-test-files!
  []
  (let [test-files (filter #(.isFile %)
                           (file-seq (io/file "test_vectors/files/")))]
    (reduce (fn [prev curr]
              (with-open [r (io/reader curr)]
                (merge prev
                       {(file-name->test-type (.getName curr))
                        (json/read r :key-fn keyword)})))
            {}
            test-files)))

(def ^:private test-files (read-test-files!))

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

(defn- hexadecimal-string->byte-array
  [x]
  (byte-array
   (map #(unchecked-byte (Integer/parseInt (apply str %) 16))
        (partition 2 x))))

(defn- sk->private-key
  [sk n]
  (let [[sk-seed-as-str
         sk-prf-as-str
         pk-seed-as-str
         pk-root-as-str] (map #(hexadecimal-string->byte-array (apply str %))
                              (partition (* n 2) sk))]
    {:sk-seed sk-seed-as-str
     :sk-prf sk-prf-as-str
     :pk-seed pk-seed-as-str
     :pk-root pk-root-as-str}))

(defn- pk->public-key
  [pk n]
  (let [[pk-seed-as-str
         pk-root-as-str] (map #(hexadecimal-string->byte-array (apply str %))
                              (partition (* n 2) pk))]
    {:pk-seed pk-seed-as-str
     :pk-root pk-root-as-str}))

(defn- get-n
  [parameter-set-name]
  (case parameter-set-name
    (:slh-dsa-shake-128s
     :slh-dsa-shake-128f) 16
    (:slh-dsa-shake-192s
     :slh-dsa-shake-192f) 24
    (:slh-dsa-shake-256s
     :slh-dsa-shake-256f) 32))

(defn test-case->normalized-map
  [parameter-set-name test-type test-case]
  (let [n (get-n parameter-set-name)]
    (case test-type
      :generate-key-pair
      {:input {:sk-seed (hexadecimal-string->byte-array (:skSeed test-case))
               :sk-prf (hexadecimal-string->byte-array (:skPrf test-case))
               :pk-seed (hexadecimal-string->byte-array (:pkSeed test-case))}
       :output {:expected-private-key (sk->private-key (:sk test-case) n)
                :expected-public-key (pk->public-key (:pk test-case) n)}}

      :sign
      {:input {:M (hexadecimal-string->byte-array (:message test-case))
               :context (hexadecimal-string->byte-array (:context test-case))
               :private-key (sk->private-key (:sk test-case) n)
               :additional-randomness (hexadecimal-string->byte-array (:additionalRandomness test-case))}
       :output {:expected-signature (hexadecimal-string->byte-array (:signature test-case))}}

      :verify
      {:input {:M (hexadecimal-string->byte-array (:message test-case))
               :signature (hexadecimal-string->byte-array (:signature test-case))
               :context (hexadecimal-string->byte-array (:context test-case))
               :public-key (pk->public-key (:pk test-case) n)}
       :output {:expected-test-passed? (:testPassed test-case)
                :expected-reason (:reason test-case)}})))

(defn generate-key-pair-test-groups
  []
  (test-type->filtered-test-groups
   :generate-key-pair
   [shake-test-group?]))

(defn sign-test-groups
  []
  (test-type->filtered-test-groups
   :sign
   [shake-test-group?
    no-prehash-test-group?]))

(defn verify-test-groups
  []
  (test-type->filtered-test-groups
   :verify
   [shake-test-group?
    no-prehash-test-group?]))
