(ns effective-chainsaw.address
  (:require [effective-chainsaw.common :as common]))

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

(def ^:private addresses-types
  {:wots-hash 0
   :wots-pk 1
   :tree 2
   :fors-tree 3
   :fors-roots 4
   :wots-prf 5
   :fors-prf 6})

(def ^:private address-size 32) ;; understand how to deal with compressed addresses

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
   (common/konkat
    (to-byte-array l 4)
    (segment adrs 4 32))))

(defn set-tree-address
  [adrs t]
  (ensure-correct-size!
   (common/konkat
    (segment adrs 0 4)
    (to-byte-array t 12)
    (segment adrs 16 32))))

(defn set-type-and-clear
  [adrs Y] ;; Y is a keyword converted to integer internally
  (ensure-correct-size!
   (common/konkat
    (segment adrs 0 16)
    (to-byte-array (get addresses-types Y) 4)
    (to-byte-array 0 12))))

(defn set-key-pair-address
  [adrs i]
  (ensure-correct-size!
   (common/konkat
    (segment adrs 0 20)
    (to-byte-array i 4)
    (segment adrs 24 32))))

(defn set-chain-address
  [adrs i]
  (ensure-correct-size!
   (common/konkat
    (segment adrs 0 24)
    (to-byte-array i 4)
    (segment adrs 28 32))))

(def set-tree-height set-chain-address)

(defn set-hash-address
  [adrs i]
  (ensure-correct-size!
   (common/konkat
    (segment adrs 0 28)
    (to-byte-array i 4))))

(def set-tree-index set-hash-address)

(defn get-key-pair-address
  [adrs]
  (to-int (segment adrs 20 24)))

(defn get-tree-index
  [adrs]
  (to-int (segment adrs 28 32)))

(defn new-address
  []
  (byte-array address-size))
