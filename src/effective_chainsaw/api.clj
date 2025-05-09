(ns effective-chainsaw.api
  (:import (java.security GeneralSecurityException))
  (:require [clojure.spec.alpha :as s]
            [effective-chainsaw.building-blocks.parameter-sets :as parameter-sets]
            [effective-chainsaw.building-blocks.slh-dsa :as slh-dsa]
            [effective-chainsaw.internals.common :as common]
            [effective-chainsaw.internals.randomness :as randomness]
            [effective-chainsaw.specs :as specs]))

(defn generate-key-pair
  "Generates an SLH-DSA key pair."
  [parameter-set-name]
  (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
        n (-> parameter-set-data :parameters :n)
        sk-seed (randomness/random-bytes n)
        sk-prf (randomness/random-bytes n)
        pk-seed (randomness/random-bytes n)]
    (slh-dsa/generate-key-pair parameter-set-data sk-seed sk-prf pk-seed)))

(s/fdef generate-key-pair
  :args (s/cat :parameter-set-name ::specs/parameter-set-name)
  :ret ::specs/key-pair
  :fn (fn [{:keys [args ret]}]
        (let [parameter-set-name (:parameter-set-name args)
              n (-> (parameter-sets/parameter-set-data parameter-set-name) :parameters :n)
              pub-key (:public-key ret)
              pri-key (:private-key ret)]
          (and (= (count (:sk-seed pri-key)) n)
               (= (count (:sk-prf pri-key)) n)
               (= (count (:pk-seed pri-key)) n)
               (= (count (:pk-root pri-key)) n)
               (= (:pk-seed pri-key) (:pk-seed pub-key))
               (= (:pk-root pri-key) (:pk-seed pri-key))))))

(defn export-key-pair!
  []
  (throw (UnsupportedOperationException. "We are not there yet, sorry!")))

(defn import-key-pair!
  []
  (throw (UnsupportedOperationException. "We are not there yet, sorry!")))

(def ^:private max-context-length 255)

(defn- prepend-context!
  [M context]
  (let [context-length (count context)]
    (cond
      (zero? context-length)
      M

      (<= context-length specs/max-context-length)
      (common/merge-bytes
       (common/integer->byte-array 0 1)
       (common/integer->byte-array context-length 1)
       context
       M)

      :else
      (throw (GeneralSecurityException. (format "Context length must be < %s bytes"
                                                specs/max-context-length))))))

(defn generate-context
  ([]
   (generate-context specs/max-context-length))
  ([n]
   (randomness/random-bytes n)))

(s/fdef generate-context
  :args (s/or :without-n (s/cat)
              :with-n (s/cat :n ::specs/n))
  :ret ::specs/context
  :fn (fn [{:keys [args ret]}]
        (let [ret-length (count ret)]
          (case (first args)
            :without-n (= ret-length max-context-length)
            :with-n (= ret-length (-> args second :n))))))

(defn sign
  "Generates a pure SLH-DSA signature (pre-hash mode is not supported yet)."
  ([parameter-set-name M context private-key]
   (sign parameter-set-name M context private-key (:pk-seed private-key)))
  ([parameter-set-name M context private-key additional-randomness]
   (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
         M' (prepend-context! M context)]
     (slh-dsa/sign parameter-set-data M' private-key additional-randomness))))

(s/fdef sign
  :args (s/or
         :deterministic
         (s/cat :parameter-set-name ::specs/parameter-set-name
                :M ::specs/message
                :context ::specs/context
                :private-key ::specs/private-key)
         :non-deterministic
         (s/cat :parameter-set-name ::specs/parameter-set-name
                :M ::specs/message
                :context ::specs/context
                :private-key ::specs/private-key
                :additional-randomness ::specs/additional-randomness))
  :ret bytes?
  :fn (fn [{:keys [args ret]}]
        (let [parameter-set-name (-> args second :parameter-set-name)
              sig-bytes (-> (parameter-sets/parameter-set-data parameter-set-name)
                            :parameters
                            :sig-bytes)]
          (= (count ret) sig-bytes))))

(defn verify
  "Verifies a pure SLH-DSA signature (pre-hash mode is not supported yet)."
  [parameter-set-name M signature context public-key]
  (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
        M' (prepend-context! M context)]
    (slh-dsa/verify parameter-set-data M' signature public-key)))

(s/fdef verify
  :args (s/cat :parameter-set-name ::specs/parameter-set-name
               :M ::specs/message
               :signature ::specs/signature
               :context ::specs/context
               :public-key ::specs/public-key)
  :ret boolean?)
