(ns effective-chainsaw.core
  (:import (java.security SecureRandom)
           (org.bouncycastle.crypto.digests SHA256Digest SHA512Digest SHAKEDigest)
           (org.bouncycastle.crypto.generators MGF1BytesGenerator)
           (org.bouncycastle.crypto.macs HMac)
           (org.bouncycastle.util.encoders Hex)))

;; 4) functions and addressing

;; 4.1) hash functions and pseudorandom functions

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

(defn shake256
  "Bytes in, bytes out."
  [input output-size-in-bits] ;; assumes input is ready to be used, properly concatenated
  (let [shake256 (shake256-algorithm)
        input-size (count input)
        output-size-in-bytes (quot output-size-in-bits 8)
        output (byte-array output-size-in-bytes)]
    (.update shake256 input 0 input-size)
    (.doFinal shake256 output 0 output-size-in-bytes)
    output))

(defn konkat
  "Concatenates the different input values in a single byte array.
  For instance: H_msg(R, pk-seed, pk-root, M) = SHAKE256(R || pk-seed || pk-root || M).
  This function acts like `||` as it varies depending on the type."
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
                     :slh-dsa-shake-256f) ;; shake-specific functions
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

(def H_msg (:H_msg functions))

(def ba1 (byte-array 0x01))
(def ba2 (byte-array 0x02))
(def ba3 (byte-array 0x03))
(def ba4 (byte-array 0x04))

(count (H_msg ba1 ba2 ba3 ba4)) ; 60 (i.e. 30 bytes -> 240 bits)

;; 4.2 - 4.4) addresses

;; - an address (adrs) is a byte array of size 32 and conforms to word boundaries, with each word being 4 bytes long
;; - values are encoded as unsigned integers in big-endian byte order
;; - 1st word (4 bytes): layer address: height of an xmss tree within the hypertree
;;   - trees in the bottom layer have height 0, the tree in the top layer has height d-1
;; - 2nd, 3rd and 4th words (12 bytes): tree address: position of an xmss tree within a layer of the hypertree
;;   - the leftmost tree in a layer has tree address of 0, the rightmost has tree address 2^(d-1-L)h' - 1 where L is the layer
;; - 5th word (4 bytes): type of the address, drives the remaining 12 bytes; there are 7 different types
;;   - every time the address type changes, the final 12 bytes are initialized to 0

;; overall structure of an address: [ layer address || tree address || type || ????? ]

(def addresses-types
  {:wots-hash 0
   :wots-pk 1
   :tree 2
   :fors-tree 3
   :fors-roots 4
   :wots-prf 5
   :fors-prf 6})

(def address-size 32) ;; understand how to deal with compressed addresses

(defn new-address
  []
  (byte-array address-size))

(defn- ensure-correct-size!
  [adrs]
  (let [size (alength adrs)]
    (if (= size address-size)
      adrs
      (throw (Exception. (format "adrs does not contain %s bytes, %s has size %s" address-size adrs size))))))

(defn- to-byte-array [x n] ;; assumes big-endian byte order
  (let [buffer (java.nio.ByteBuffer/allocate n)]
    (.position buffer (- n 4))
    (.putInt buffer x)
    (.array buffer)))

(defn- to-int [X]
  (let [buffer (java.nio.ByteBuffer/wrap X)]
    (.getInt buffer)))

(defn- segment
  [adrs start end]
  (java.util.Arrays/copyOfRange adrs start end))

(defn set-layer-address
  [adrs l]
  (ensure-correct-size!
   (konkat
    (to-byte-array l 4)
    (segment adrs 4 32))))

(defn set-tree-address
  [adrs t]
  (ensure-correct-size!
   (konkat
    (segment adrs 0 4)
    (to-byte-array t 12)
    (segment adrs 16 32))))

(defn set-type-and-clear
  [adrs Y] ;; Y is a keyword converted to integer internally
  (ensure-correct-size!
   (konkat
    (segment adrs 0 16)
    (to-byte-array (get addresses-types Y) 4)
    (to-byte-array 0 12))))

(defn set-key-pair-address
  [adrs i]
  (ensure-correct-size!
   (konkat
    (segment adrs 0 20)
    (to-byte-array i 4)
    (segment adrs 24 32))))

(defn set-chain-address
  [adrs i]
  (ensure-correct-size!
   (konkat
    (segment adrs 0 24)
    (to-byte-array i 4)
    (segment adrs 28 32))))

(def set-tree-height set-chain-address)

(defn set-hash-address
  [adrs i]
  (ensure-correct-size!
   (konkat
    (segment adrs 0 28)
    (to-byte-array i 4))))

(def set-tree-index set-hash-address)

(defn get-key-pair-address
  [adrs]
  (to-int (segment adrs 20 24)))

(defn get-tree-index
  [adrs]
  (to-int (segment adrs 28 32)))

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
            (let [adrs' (set-hash-address adrs j)]
              (F pk-seed adrs' tmp)))
          X (range (dec (+ i s)))))

(defn random-bytes
  [n]
  (let [seed (byte-array n)]
    (.nextBytes (SecureRandom.) seed)
    seed))

(def X (random-bytes 16))
(def pk-seed (random-bytes 16))
(def adrs (new-address))

(chain functions X 1 5 pk-seed adrs)

(defn wots-pkgen
  "Generates a WOTS+ public key."
  [{:keys [PRF T_l] :as functions} {:keys [len w]} sk-seed pk-seed adrs]
  (let [key-pair-address (get-key-pair-address adrs)
        sk-adrs adrs ;; copy address to create key generation key address
        sk-adrs' (-> sk-adrs
                     (set-type-and-clear :wots-prf)
                     (set-key-pair-address key-pair-address))
        tmps (map (fn [i]
                    (let [sk-adrs'' (set-chain-address sk-adrs' i)
                          sk (PRF pk-seed sk-seed sk-adrs'') ;; compute secret value for chain `i`
                          adrs' (set-chain-address adrs i)]
                      (chain functions sk 0 (dec w) pk-seed adrs'))) ;; compute public value for chain `i`
                  (range (dec len)))
        wotspk-adrs adrs ;; copy address to create wots+ public key address
        wotspk-adrs' (-> wotspk-adrs
                         (set-type-and-clear :wots-pk)
                         (set-key-pair-address key-pair-address))]
    (T_l pk-seed wotspk-adrs' (last tmps)))) ;; compress public key

(wots-pkgen functions additional-values (random-bytes 16) pk-seed adrs)

;; no idea how to test this, but essentially, we:
;; - given a secret key, we compute the corresponding public key
;; - we sign the message with the secret key, applying the chain function accordingly
;; - we compute a candidate public key from a signature
;; this way, we can check whether the implementation is correct, since the candidate public key would be different from the original public key

;; same idea from now on: parameters + functions ("global" arguments), then "local" arguments (e.g. specific to wots+), then the remaining arguments

(defn wots-sign
  "Generates a WOTS+ signature on an n-byte message."
  [{:keys [PRF] :as functions} {:keys [len_1 w len_2 len]} M sk-seed pk-seed adrs])
