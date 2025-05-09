(ns effective-chainsaw.api
  (:import (java.security GeneralSecurityException))
  (:require [effective-chainsaw.building-blocks.parameter-sets :as parameter-sets]
            [effective-chainsaw.building-blocks.slh-dsa :as slh-dsa]
            [effective-chainsaw.internals.common :as common]
            [effective-chainsaw.internals.randomness :as randomness]))

(defn generate-key-pair
  "Generates an SLH-DSA key pair."
  [parameter-set-name]
  (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
        n (-> parameter-set-data :parameters :n)
        sk-seed (randomness/random-bytes n)
        sk-prf (randomness/random-bytes n)
        pk-seed (randomness/random-bytes n)]
    (slh-dsa/generate-key-pair parameter-set-data sk-seed sk-prf pk-seed)))

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

      (<= context-length max-context-length)
      (common/merge-bytes
       (common/integer->byte-array 0 1)
       (common/integer->byte-array context-length 1)
       context
       M)

      :else
      (throw (GeneralSecurityException. (format "Context length must be < %s bytes"
                                                max-context-length))))))

(defn generate-context
  ([]
   (generate-context max-context-length))
  ([n]
   (randomness/random-bytes n)))

(defn sign
  "Generates a pure SLH-DSA signature (pre-hash mode is not supported yet)."
  ([parameter-set-name M context private-key]
   (sign parameter-set-name M context private-key (:pk-seed private-key)))
  ([parameter-set-name M context private-key additional-randomness]
   (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
         M' (prepend-context! M context)]
     (slh-dsa/sign parameter-set-data M' private-key additional-randomness))))

(defn verify
  "Verifies a pure SLH-DSA signature (pre-hash mode is not supported yet)."
  [parameter-set-name M signature context public-key]
  (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
        M' (prepend-context! M context)]
    (slh-dsa/verify parameter-set-data M' signature public-key)))

(comment
  ;; "Talk is cheap. Show me the code."

  ;; Options currently available:
  ;; - :slh-dsa-shake-128s
  ;; - :slh-dsa-shake-128f
  ;; - :slh-dsa-shake-192s
  ;; - :slh-dsa-shake-192f
  ;; - :slh-dsa-shake-256s
  ;; - :slh-dsa-shake-256f
  ;; Where:
  ;; - Suffix `s` stands for "relatively small signatures" (slower computation)
  ;; - Suffix `f` stands for "relatively fast signatures" (faster computation)
  ;; - SHA2 parameter sets are not available

  (def parameter-set-name :slh-dsa-shake-128s)

  ;; Returns a map of:
  ;; - :private-key: contains :sk-seed, :sk-prf, :pk-seed, and :pk-root
  ;; - :public-key: contains :pk-seed and :pk-root
  ;; Note: all values are byte arrays of length `n` (depends on the chosen parameter set)
  (def key-pair (generate-key-pair parameter-set-name))

  (def message
    (.getBytes "Toda família feliz é igual, enquanto que cada família infeliz é infeliz à sua maneira." "UTF-8"))

  ;; Context can be `nil`, and optionally you may provide a size to the context string, though this is seldom used
  (def context (generate-context))

  (def signature (sign parameter-set-name message context (:private-key key-pair)))

  ;; Signature must verify correctly:
  (verify parameter-set-name message signature context (:public-key key-pair)) ; true

  ;; If the message is changed...
  (def changed-message
    (.getBytes "Changed message...?" "UTF-8"))

  ;; ...the signature verification will fail:
  (verify parameter-set-name changed-message signature context (:public-key key-pair)) ; false

  ;; If we copy the correct signature but change only a single byte...
  (def changed-signature
    (byte-array (concat (butlast signature) [0x01])))

  ;; ...signature verification will also fail:
  (verify parameter-set-name message changed-signature context (:public-key key-pair)) ; false

  ;; Finally, even if only the context is changed...
  (def changed-context (generate-context))

  ;; ...the signature verification fails:
  (verify parameter-set-name message signature changed-context (:public-key key-pair)) ; false
  )
