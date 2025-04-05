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
        tmps (map (fn [i]
                    (let [sk-adrs'' (address/set-chain-address sk-adrs' i)
                          sk (PRF pk-seed sk-seed sk-adrs'') ;; compute secret value for chain `i`
                          adrs' (address/set-chain-address adrs i)]
                      (chain functions sk 0 (dec w) pk-seed adrs'))) ;; compute public value for chain `i`
                  (range len))
        wotspk-adrs adrs ;; copy address to create wots+ public key address
        wotspk-adrs' (-> wotspk-adrs
                         (address/set-type-and-clear :wots-pk)
                         (address/set-key-pair-address key-pair-address))
        pk (T_l pk-seed wotspk-adrs' tmps)] ;; compress public key
    pk))

(wots-pkgen functions additional-values (randomness/random-bytes 16) pk-seed adrs)

;; no idea how to test this, but essentially:
;; - given a secret key, we compute the corresponding public key
;; - we sign the message with the secret key, applying the chain function accordingly
;; - we compute a candidate public key from a signature
;; this way, we can check whether the implementation is correct, since the candidate public key would be different from the original public key

;; same idea from now on: parameters + functions ("global" arguments), then "local" arguments (e.g. specific to wots+), then the remaining arguments

(defn- byte->bits
  [b]
  (map #(bit-and (bit-shift-right b %) 1)
       (range 7 -1 -1)))

(defn- byte-array->bits
  [X]
  (mapcat byte->bits X))

(defn- bits->integer
  [bits]
  (reduce #(+ (bit-shift-left %1 1) %2) 0 bits))

(defn base_2b
  "Divides X into 2^b blocks, ending with an array of out_len length.
  Used by WOTS+ and FORS; in the former b will be lg_w, whereas in the latter b will be a.
  In FIPS-205 lg_w is 4, and a can be 6, 8, 9, 12, or 14."
  [X b out_len]
  (when-not (>= (alength X) (int (Math/ceil (quot (* out_len b) 8))))
    (throw (Exception. (format "X is too short (size %s)!" (alength X)))))
  (let [base (int (Math/pow 2 b))
        something (->> X
                       byte-array->bits
                       (partition base)
                       #_(map bits->integer))]
    something))

(def M (byte-array [24, 88, -75, 123, 18, -92, 8, 90, -27, 108, -66, 116, 68, -19, -26, 121,
                    10, 98, -30, 4, 70, 5, 71, -69, 73, 56, 10, 110, 10, 93, -46, -63])) ;; shake256("banana")
(count (base_2b M (:lg_w parameters) (:len_1 additional-values)))

(defn wots-sign
  "Generates a WOTS+ signature on an n-byte message."
  [{:keys [PRF] :as functions} {:keys [len_1 w len_2 len]} M sk-seed pk-seed adrs]
  ;; 1) convert the n-byte message M into 2 arrays:
  ;; - the first (len_1 length) is the message converted into base-w integers
  ;; - the second (len_2 length) is the checksum, also in base-w integers, calculated from M
  ;; 2) concatenate the 2 arrays together
  ;; 3) for each base-w integer from this new array apply the chaining function d times, where d is the value itself
  ;; 4) concatenate the len pieces of signature into a single one
  ;; 5) return the final signature of length len

  ;; another way of seeing this, taken from nist sp 800-208, figure 3:
  ;; | digest/checksum | private key | signature              | public key |
  ;; |-----------------|-------------|------------------------|------------|
  ;; | 6 (digest)      | x0          | H^6(x0) (H applied 6x) | H^w-1(x0)  |
  ;; | 3 (digest)      | x1          | H^3(x1)                | H^w-1(x1)  |
  ;; | f (digest)      | x2          | H^15(x2)               | H^w-1(x2)  |
  ;; | 1 (digest)      | x3          | H^1(x3)                | H^w-1(x3)  |
  ;; | e (digest)      | x4          | H^14(x4)               | H^w-1(x4)  |
  ;; | 9 (digest)      | x5          | H^9(x5)                | H^w-1(x5)  |
  ;; | 0 (digest)      | x6          | H^0(x6) = x6           | H^w-1(x6)  |
  ;; | b (digest)      | x7          | H^11(x7)               | H^w-1(x7)  |
  ;; | 3 (checksum)    | x8          | H^3(x8)                | H^w-1(x8)  |
  ;; | d (checksum)    | x9          | H^13(x9)               | H^w-1(x9)  |
  ;; the final signature is the concatenation of all signature elements
  )
