(ns effective-chainsaw.wots
  (:require [clojure.math :as math]
            [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]))

(defn- log2
  [x]
  (/ (math/log x) (math/log 2)))

(defn- get-additional-values
  "Given the two main WOTS+ parameters `n` and `lg_w`, derive four additional values: `w`, `len_1`, `len_2`, and `len`.
  - `w` represents the length of the chain created from the secret values;
  - `len_1` is the length of the array after conversion of the 8n-bit message into base-w integers;
  - `len_2` is the length of the base-w checksum that is appended to the converted array."
  [{:keys [n lg_w]}]
  (let [w (int (math/pow 2 lg_w))
        len_1 (int (math/ceil (/ (* 8 n) lg_w)))
        len_2 (inc (int (math/floor (/ (log2 (* len_1 (dec w))) lg_w))))
        len (+ len_1 len_2)]
    {:w w
     :len_1 len_1
     :len_2 len_2
     :len len}))

(defn- chain
  "Chaining function used in WOTS+."
  [{:keys [F]} X i s pk-seed adrs]
  (reduce #(F pk-seed (address/set-hash-address adrs %2) %1)
          X (range i (+ i s))))

(defn generate-public-key
  "Generates a WOTS+ public key."
  [{:keys [parameters functions]} sk-seed pk-seed adrs]
  (let [{:keys [w len]} (get-additional-values parameters)
        {:keys [PRF T_l]} functions
        key-pair-address (address/get-key-pair-address adrs)
        sk-adrs (-> adrs
                    (address/set-type-and-clear :wots-prf)
                    (address/set-key-pair-address key-pair-address))
        public-values (map (fn [index]
                             (let [secret-key (PRF pk-seed sk-seed (address/set-chain-address sk-adrs index))] ;; compute secret value for chain `index`
                               (chain functions secret-key 0 (dec w) pk-seed (address/set-chain-address adrs index)))) ;; compute public value for chain `index`
                           (range len))
        wots-pk-adrs (-> adrs
                         (address/set-type-and-clear :wots-pk)
                         (address/set-key-pair-address key-pair-address))
        public-key (T_l pk-seed wots-pk-adrs public-values)] ;; compress public key
    public-key))

(defn- calculate-checksum
  "Calculates the checksum of chunks."
  [chunks lg_w w len_2]
  (let [left-shift-by (mod (- 8 (mod (* len_2 lg_w) 8)) 8)
        checksum (reduce (fn [accumulator i]
                           (- i 1 (+ accumulator w)))
                         0 chunks)
        checksum-size (int (math/ceil (/ (* len_2 lg_w) 8)))]
    (common/int->byte-array (bit-shift-left checksum left-shift-by) checksum-size)))

(defn sign
  "Generates a WOTS+ signature on an n-byte message.

  Steps:
  1) Convert the n-byte message M into 2 arrays:
  - The first (len_1 length) is the message converted into base-w integers
  - The second (len_2 length) is the checksum, also in base-w integers, calculated from previous step
  2) Concatenate the 2 arrays together
  3) For each base-w integer from this new array apply the chaining function d times, where d is the value itself
  4) Concatenate the len pieces of signature into a single one
  5) Return the final signature of length len

  Another way of seeing this, taken from NISP SP 800-208, figure 3:
  | Digest/Checksum | Private key | Signature              | Public key |
  |-----------------|-------------|------------------------|------------|
  | 6 (digest)      | x0          | H^6(x0) (H applied 6x) | H^w-1(x0)  |
  | 3 (digest)      | x1          | H^3(x1)                | H^w-1(x1)  |
  | F (digest)      | x2          | H^15(x2)               | H^w-1(x2)  |
  | 1 (digest)      | x3          | H^1(x3)                | H^w-1(x3)  |
  | E (digest)      | x4          | H^14(x4)               | H^w-1(x4)  |
  | 9 (digest)      | x5          | H^9(x5)                | H^w-1(x5)  |
  | 0 (digest)      | x6          | H^0(x6) = x6           | H^w-1(x6)  |
  | B (digest)      | x7          | H^11(x7)               | H^w-1(x7)  |
  | 3 (checksum)    | x8          | H^3(x8)                | H^w-1(x8)  |
  | D (checksum)    | x9          | H^13(x9)               | H^w-1(x9)  |

  The final signature is the concatenation of all signature elements."
  [{:keys [parameters functions]} M sk-seed pk-seed adrs]
  (let [{:keys [lg_w]} parameters
        {:keys [w len_1 len_2 len]} (get-additional-values parameters)
        {:keys [PRF]} functions
        message (common/base_2b M lg_w len_1)
        checksum (common/base_2b (calculate-checksum message lg_w w len_2) lg_w len_2)
        message+checksum (common/merge-bytes message checksum)
        key-pair-address (address/get-key-pair-address adrs)
        sk-adrs (-> adrs
                    (address/set-type-and-clear :wots-prf)
                    (address/set-key-pair-address key-pair-address))
        signature-elements (map-indexed
                            (fn [index item]
                              (let [secret-key (PRF pk-seed sk-seed (address/set-chain-address sk-adrs index))]
                                (chain functions
                                       secret-key
                                       0
                                       item
                                       pk-seed
                                       (address/set-chain-address adrs index))))
                            message+checksum)]
    (common/validate-length! len signature-elements)))

(defn compute-public-key-from-signature
  "Computes a WOTS+ public key from a message and its signature."
  [{:keys [parameters functions]} signature M pk-seed adrs]
  (let [{:keys [lg_w]} parameters
        {:keys [w len_1 len_2 len]} (get-additional-values parameters)
        {:keys [T_l]} functions
        message (common/base_2b M lg_w len_1)
        checksum (common/base_2b (calculate-checksum message lg_w w len_2) lg_w len_2)
        message+checksum (common/merge-bytes message checksum)
        public-values (map (fn [index]
                             (let [signature-element (nth signature index)
                                   message+checksum-element (nth message+checksum index)]
                               (chain functions
                                      signature-element
                                      message+checksum-element
                                      (- w 1 message+checksum-element)
                                      pk-seed
                                      (address/set-chain-address adrs index))))
                           (range len))
        key-pair-address (address/get-key-pair-address adrs)
        wots-pk-adrs (-> adrs
                         (address/set-type-and-clear :wots-pk)
                         (address/set-key-pair-address key-pair-address))
        public-key' (T_l pk-seed wots-pk-adrs public-values)]
    public-key'))
