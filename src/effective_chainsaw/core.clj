(ns effective-chainsaw.core
  (:require [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.primitives :as primitives]
            [effective-chainsaw.randomness :as randomness]
            [effective-chainsaw.wots :as wots]))

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
                        :k 33
                        :lg_w 4
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

(defn augment-parameter-set
  [parameter-set-name]
  (let [parameters (get parameter-set->parameters parameter-set-name)
        functions (case parameter-set-name
                    (:slh-dsa-shake-128s
                     :slh-dsa-shake-128f
                     :slh-dsa-shake-192s
                     :slh-dsa-shake-192f
                     :slh-dsa-shake-256s
                     :slh-dsa-shake-256f) ;; shake-specific functions
                    {:H_msg (fn [R pk-seed pk-root M]
                              (primitives/shake256 (common/konkat R pk-seed pk-root M)
                                                   (* 8 (:m parameters))))
                     :PRF (fn [pk-seed sk-seed adrs]
                            (primitives/shake256 (common/konkat pk-seed adrs sk-seed)
                                                 (* 8 (:n parameters))))
                     :PRF_msg (fn [sk-prf opt_rand M]
                                (primitives/shake256 (common/konkat sk-prf opt_rand M)
                                                     (* 8 (:n parameters))))
                     :F (fn [pk-seed adrs M_1] ;; special case of `T_l` but `M` has size n
                          (primitives/shake256 (common/konkat pk-seed adrs M_1)
                                               (* 8 (:n parameters))))
                     :H (fn [pk-seed adrs M_2] ;; special case of `T_l` but `M` has size 2n
                          (primitives/shake256 (common/konkat pk-seed adrs M_2)
                                               (* 8 (:n parameters))))
                     :T_l (fn [pk-seed adrs M_l] ;; used when compressing WOTS+ public values into a public key
                            (primitives/shake256 (common/konkat pk-seed adrs M_l)
                                                 (* 8 (:n parameters))))}

                    (:slh-dsa-sha2-128s
                     :slh-dsa-sha2-128f) ;; security category 1, requires ADRS implementation (and its compression)
                    (throw (UnsupportedOperationException. "Nice game, pretty boy; gtfo"))

                    (:slh-dsa-sha2-192s
                     :slh-dsa-sha2-192f
                     :slh-dsa-sha2-256s
                     :slh-dsa-sha2-256f) ;; security category 3 and 5, requires ADRS implementation (and its compression)
                    (throw (UnsupportedOperationException. "Nice game, pretty boy; gtfo")))]
    {:parameters parameters
     :functions functions}))

(def ps-name :slh-dsa-shake-128s)
(def augmented (-> ps-name augment-parameter-set)) ;; "global" arguments
(def parameters (:parameters augmented))
(def functions (:functions augmented))

;; 5) winternitz one-time signature plus scheme

(def n (:n parameters))
(def lg_w (:lg_w parameters))

(def sk-seed (randomness/random-bytes 16))
(def pk-seed (randomness/random-bytes 16))
(def adrs (address/new-address))

;; naive testing
(let [wots-additional-values (wots/additional-values n lg_w)
      public-key (wots/generate-public-key functions wots-additional-values sk-seed pk-seed adrs)
      M (primitives/shake256 (byte-array [0x42 0x41 0x4e 0x41 0x4e 0x41]) 128) ;; BANANA
      signature (wots/sign functions wots-additional-values M sk-seed pk-seed adrs)
      candidate-public-key (wots/compute-public-key-from-signature functions wots-additional-values signature M pk-seed adrs)]
  (wots/signature-verifies? public-key candidate-public-key))
