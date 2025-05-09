# effective-chainsaw

[![PR Check (Clojure)](https://github.com/deadflaming0/effective-chainsaw/actions/workflows/clojure-pr-check.yaml/badge.svg)](https://github.com/deadflaming0/effective-chainsaw/actions/workflows/clojure-pr-check.yaml)

A Clojure implementation of [FIPS-205 (SLH-DSA)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf). Unreviewed. Do not use this.

## API

```clojure
;; "Talk is cheap. Show me the code."

(require '[effective-chainsaw.api :as api])

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
(def key-pair (api/generate-key-pair parameter-set-name))

(def message
  (.getBytes "Toda família feliz é igual, enquanto que cada família infeliz é infeliz à sua maneira." "UTF-8"))

;; Context can be `nil`, and optionally you may provide a size to the context string, though this is seldom used
(def context (api/generate-context))

(def signature (api/sign parameter-set-name message context (:private-key key-pair)))

;; Signature must verify correctly:
(api/verify parameter-set-name
            message
            signature
            context
            (:public-key key-pair)) ; true

;; If the message is changed...
(def changed-message
  (.getBytes "Changed message...?" "UTF-8"))

;; ...the signature verification will fail:
(api/verify parameter-set-name
            changed-message
            signature
            context
            (:public-key key-pair)) ; false

;; If we copy the correct signature but change only a single byte...
(def changed-signature
  (byte-array (concat (butlast signature) [0x01])))

;; ...signature verification will also fail:
(api/verify parameter-set-name
            message
            changed-signature
            context
            (:public-key key-pair)) ; false

;; Finally, even if only the context is changed...
(def changed-context (api/generate-context))

;; ...the signature verification fails:
(api/verify parameter-set-name
            message
            signature
            changed-context
            (:public-key key-pair)) ; false
```
