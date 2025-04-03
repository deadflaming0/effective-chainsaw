(ns effective-chainsaw.core
  (:require [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.primitives :as primitives]
            [effective-chainsaw.randomness :as randomness]))

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
                     :F (fn [pk-seed adrs M_1]
                          (primitives/shake256 (common/konkat pk-seed adrs M_1)
                                               (* 8 (:n parameters))))
                     :H (fn [pk-seed adrs M_2]
                          (primitives/shake256 (common/konkat pk-seed adrs M_2)
                                               (* 8 (:n parameters))))
                     :T_l (fn [pk-seed adrs M_l]
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
(def augmented (-> ps-name augment-parameter-set))
(def parameters (:parameters augmented))
(def functions (:functions augmented))

;; 5) winternitz one-time signature plus scheme

(def n (:n parameters))
(def lg_w (:lg_w parameters))

(defn- log2
  [x]
  (quot (Math/log x) (Math/log 2)))

(defn additional-wots-values
  "Given the two main WOTS+ parameters `n` and `lg_w`, derive four additional values: `w`, `len_1`, `len_2`, and `len`.
  - `w` represents the length of the chain created from the secret values;
  - `len_1` is the length of the array after conversion of the 8n-bit message into base-w integers;
  - `len_2` is the length of the base-w checksum that is appended to the converted array."
  [n lg_w]
  (let [w (int (Math/pow 2 lg_w))
        len_1 (int (Math/ceil (quot (* 8 n) lg_w)))
        len_2 (inc (int (Math/floor (quot (log2 (* len_1 (dec w))) lg_w))))
        len (+ len_1 len_2)]
    {:w w
     :len_1 len_1
     :len_2 len_2
     :len len}))

(def additional-values (additional-wots-values n lg_w))

(defn- chain
  "Chaining function used in WOTS+."
  [{:keys [F]} X i s pk-seed adrs]
  (reduce (fn [tmp j]
            (let [adrs' (address/set-hash-address adrs j)]
              (F pk-seed adrs' tmp)))
          X (range (dec (+ i s)))))

(def X (randomness/random-bytes 16))
(def pk-seed (randomness/random-bytes 16))
(def adrs (address/new-address))

(chain functions X 1 5 pk-seed adrs)

(defn wots-pkgen
  "Generates a WOTS+ public key."
  [{:keys [PRF T_l] :as functions} {:keys [len w]} sk-seed pk-seed adrs]
  (let [key-pair-address (address/get-key-pair-address adrs)
        sk-adrs adrs ;; copy address to create key generation key address
        sk-adrs' (-> sk-adrs
                     (address/set-type-and-clear :wots-prf)
                     (address/set-key-pair-address key-pair-address))
        tmps (map (fn [i] ;; FIXME: this is not right
                    (let [sk-adrs'' (address/set-chain-address sk-adrs' i)
                          sk (PRF pk-seed sk-seed sk-adrs'') ;; compute secret value for chain `i`
                          adrs' (address/set-chain-address adrs i)]
                      (chain functions sk 0 (dec w) pk-seed adrs'))) ;; compute public value for chain `i`
                  (range (dec len)))
        wotspk-adrs adrs ;; copy address to create wots+ public key address
        wotspk-adrs' (-> wotspk-adrs
                         (address/set-type-and-clear :wots-pk)
                         (address/set-key-pair-address key-pair-address))]
    (T_l pk-seed wotspk-adrs' (last tmps)))) ;; compress public key

(wots-pkgen functions additional-values (randomness/random-bytes 16) pk-seed adrs)

;; no idea how to test this, but essentially:
;; - given a secret key, we compute the corresponding public key
;; - we sign the message with the secret key, applying the chain function accordingly
;; - we compute a candidate public key from a signature
;; this way, we can check whether the implementation is correct, since the candidate public key would be different from the original public key

;; same idea from now on: parameters + functions ("global" arguments), then "local" arguments (e.g. specific to wots+), then the remaining arguments

(defn wots-sign
  "Generates a WOTS+ signature on an n-byte message."
  [{:keys [PRF] :as functions} {:keys [len_1 w len_2 len]} M sk-seed pk-seed adrs])
