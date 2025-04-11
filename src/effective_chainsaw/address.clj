(ns effective-chainsaw.address
  (:require [effective-chainsaw.common :as common]))

(def ^:private addresses-types
  {:wots-hash 0
   :wots-pk 1
   :tree 2
   :fors-tree 3
   :fors-roots 4
   :wots-prf 5
   :fors-prf 6})

(def ^:private address-size 32) ;; understand how to deal with compressed addresses

(def ^:private ensure-correct-size!
  (partial common/ensure-correct-size! address-size))

(defn set-layer-address
  [adrs l]
  (ensure-correct-size!
   (common/konkat
    (common/int->byte-array l 4)
    (common/segment adrs 4 32))))

(defn set-tree-address
  [adrs t]
  (ensure-correct-size!
   (common/konkat
    (common/segment adrs 0 4)
    (common/int->byte-array t 12)
    (common/segment adrs 16 32))))

(defn set-type-and-clear
  [adrs Y] ;; Y is a keyword converted to integer internally
  (ensure-correct-size!
   (common/konkat
    (common/segment adrs 0 16)
    (common/int->byte-array (get addresses-types Y) 4)
    (common/int->byte-array 0 12))))

(defn set-key-pair-address
  [adrs i]
  (ensure-correct-size!
   (common/konkat
    (common/segment adrs 0 20)
    (common/int->byte-array i 4)
    (common/segment adrs 24 32))))

(defn set-chain-address
  [adrs i]
  (ensure-correct-size!
   (common/konkat
    (common/segment adrs 0 24)
    (common/int->byte-array i 4)
    (common/segment adrs 28 32))))

(def set-tree-height set-chain-address)

(defn set-hash-address
  [adrs i]
  (ensure-correct-size!
   (common/konkat
    (common/segment adrs 0 28)
    (common/int->byte-array i 4))))

(def set-tree-index set-hash-address)

(defn get-key-pair-address
  [adrs]
  (common/byte-array->int (common/segment adrs 20 24)))

(defn get-tree-index
  [adrs]
  (common/byte-array->int (common/segment adrs 28 32)))

(defn new-address
  []
  (byte-array address-size))
