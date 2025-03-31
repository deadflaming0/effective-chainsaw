(ns effective-chainsaw.core
  (:import
    (org.bouncycastle.crypto.digests SHA256Digest SHA512Digest SHAKEDigest)
    (org.bouncycastle.crypto.macs HMac)
    (org.bouncycastle.crypto.generators MGF1BytesGenerator)))

;; in order to instantiate for shake and sha2 we'll need:

;; 1) shake:
;; * shake256

(SHAKEDigest. 256)

;; 2) sha2:
;; security category 1:
;; * mgf1-sha-256
;; * sha-256
;; * hmac-sha-256
;; security category 3 and 5:
;; * mgf1-sha-512
;; * sha-512
;; * sha-256
;; * hmac-sha-512

;; 1:
(MGF1BytesGenerator. (SHA256Digest.))
(SHA256Digest.)
(HMac. (SHA256Digest.))

;; 3 and 5:
(MGF1BytesGenerator. (SHA512Digest.))
(SHA512Digest.)
(HMac. (SHA512Digest.))

;; building blocks:

;; * H_msg
;; * PRF
;; * PRF_msg
;; * F
;; * H
;; * Tl

(def parameter-set->parameters+functions
  {:slh-dsa-sha2-128s {:parameters
                       {:n 16
                        :h 63
                        :d 7
                        :h' 9 ;; find out a consistent way to name keys (when super/sub)
                        :a 12
                        :k 14
                        :lg_w 4
                        :m 30
                        :security-category 1}
                       :functions
                       {:H_msg (fn [input]
                                 input)}}})

(defn- parameter-sets
  []
  (set (keys parameter-set->parameters+functions)))

(parameter-sets)

(defn- setup
  [parameter-set]
  (get parameter-set->parameters+functions parameter-set))

(setup :slh-dsa-sha2-128s) ;; returns parameters + instantiations of H_msg/PRF/PRF_msg/F/H/Tl?
