(ns effective-chainsaw.core
  (:import (org.bouncycastle.crypto.digests SHA256Digest SHA512Digest SHAKEDigest)
           (org.bouncycastle.crypto.generators MGF1BytesGenerator)
           (org.bouncycastle.crypto.macs HMac)
           (org.bouncycastle.util.encoders Hex)))

;; shake specific:
(defn shake256-algorithm [] (SHAKEDigest. 256))

;; sha2, security category 1:
(defn sha-256-algorithm [] (SHA256Digest.))
(defn mgf1-sha-256-algorithm [] (MGF1BytesGenerator. (sha-256-algorithm)))
(defn hmac-sha-256-algorithm [] (HMac. (sha-256-algorithm)))

;; sha2, security category 3 and 5:
(defn sha-512-algorithm [] (SHA512Digest.))
(defn mgf1-sha-512-algorithm [] (MGF1BytesGenerator. (sha-512-algorithm)))
(defn hmac-sha-512-algorithm [] (HMac. (sha-512-algorithm)))

(def parameter-set->parameters ;; add sha2 variants later
  {:slh-dsa-shake-128s {:n 16
                        :h 63
                        :d 7
                        :h' 9
                        :a 12
                        :k 14
                        :lg_w 4
                        :m 30}
   :slh-dsa-shake-128f {:n 16
                        :h 66
                        :d 22
                        :h' 3
                        :a 6
                        :k 33
                        :lg_w 4
                        :m 34}
   :slh-dsa-shake-192s {:n 24
                        :h 63
                        :d 7
                        :h' 9
                        :a 14
                        :k 17
                        :lg_w 4
                        :m 39}
   :slh-dsa-shake-192f {:n 24
                        :h 66
                        :d 22
                        :h' 3
                        :a 8
                        :k 33 :lg_w 4
                        :m 42}
   :slh-dsa-shake-256s {:n 32
                        :h 64
                        :d 8
                        :h' 8
                        :a 14
                        :k 22
                        :lg_w 4
                        :m 47}
   :slh-dsa-shake-256f {:n 32
                        :h 68
                        :d 17
                        :h' 4
                        :a 9
                        :k 35
                        :lg_w 4
                        :m 49}})

(defn shake256
  [input output-size-in-bits] ;; assumes `input` is ready to be used
  (let [shake256 (shake256-algorithm)
        input-size (count input)
        output-size-in-bytes (quot output-size-in-bits 8) ;; not sure about this, but i think shake uses the second argument as bits, not bytes
        output (byte-array output-size-in-bytes)]
    (.update shake256 input 0 input-size)
    (.doFinal shake256 output 0 output-size-in-bytes)
    (Hex/toHexString output)))

(defn konkat
  "Concatenates the different input values in a single byte array.
  For instance: H_msg(R, pk-seed, pk-root, M) = SHAKE256(R || pk-seed || pk-root || M).
  This function acts like `||` as it varies depending on the type (byte array or string)."
  [& inputs]
  (byte-array (apply concat (map seq inputs))))

(defn augment-parameter-set
  [parameter-set-name]
  (let [parameters (get parameter-set->parameters parameter-set-name)
        functions (case parameter-set-name
                    (:slh-dsa-shake-128s
                      :slh-dsa-shake-128f
                      :slh-dsa-shake-192s
                      :slh-dsa-shake-192f
                      :slh-dsa-shake-256s
                      :slh-dsa-shake-256f) ;; shake specific
                    {:H_msg (fn [R pk-seed pk-root M]
                              (shake256 (konkat R pk-seed pk-root M)
                                        (* 8 (:m parameters))))
                     :PRF (fn [pk-seed sk-seed adrs]
                            (shake256 (konkat pk-seed adrs sk-seed)
                                      (* 8 (:n parameters))))
                     :PRF_msg (fn [sk-prf opt_rand M]
                                (shake256 (konkat sk-prf opt_rand M)
                                          (* 8 (:n parameters))))
                     :F (fn [pk-seed adrs M_1]
                          (shake256 (konkat pk-seed adrs M_1)
                                    (* 8 (:n parameters))))
                     :H (fn [pk-seed adrs M_2]
                          (shake256 (konkat pk-seed adrs M_2)
                                    (* 8 (:n parameters))))
                     :T_l (fn [pk-seed adrs M_l]
                            (shake256 (konkat pk-seed adrs M_l)
                                      (* 8 (:n parameters))))}

                    (:slh-dsa-sha2-128s
                      :slh-dsa-sha2-128f) ;; security category 1, requires ADRS implementation (and its compression)
                    (throw (UnsupportedOperationException. "Nice game, pretty boy; but no."))

                    (:slh-dsa-sha2-192s
                      :slh-dsa-sha2-192f
                      :slh-dsa-sha2-256s
                      :slh-dsa-sha2-256f) ;; security category 3 and 5, requires ADRS implementation (and its compression)
                    (throw (UnsupportedOperationException. "Nice game, pretty boy; but no.")))]
    {parameter-set-name
     {:parameters parameters
      :functions functions}}))

(def ps-name :slh-dsa-shake-128s)

(def H_msg
  (-> ps-name
      augment-parameter-set
      ps-name
      :functions
      :H_msg))

(def ba1 (byte-array 0x01))
(def ba2 (byte-array 0x02))
(def ba3 (byte-array 0x03))
(def ba4 (byte-array 0x04))

(count (H_msg ba1 ba2 ba3 ba4)) ; 60 (i.e. 30 bytes -> 240 bits)
