(ns effective-chainsaw.address
  (:require [effective-chainsaw.common :as common]))

(def ^:private address-size 32) ;; understand how to deal with compressed addresses

(def ^:private validate-length!
  (partial common/validate-length! address-size))

(defn set-layer-address
  [adrs l]
  (validate-length!
   (common/merge-bytes
    (common/integer->byte-array l 4)
    (common/slice-bytes adrs 4 32))))

(defn set-tree-address
  [adrs t]
  (validate-length!
   (common/merge-bytes
    (common/slice-bytes adrs 0 4)
    (common/integer->byte-array t 12)
    (common/slice-bytes adrs 16 32))))

(def ^:private addresses-types
  {:wots-hash 0
   :wots-pk 1
   :tree 2
   :fors-tree 3
   :fors-roots 4
   :wots-prf 5
   :fors-prf 6})

(defn set-type-and-clear
  [adrs Y] ;; Y is a keyword converted to integer internally
  (validate-length!
   (common/merge-bytes
    (common/slice-bytes adrs 0 16)
    (common/integer->byte-array (get addresses-types Y) 4)
    (common/integer->byte-array 0 12))))

(defn set-key-pair-address
  [adrs i]
  (validate-length!
   (common/merge-bytes
    (common/slice-bytes adrs 0 20)
    (common/integer->byte-array i 4)
    (common/slice-bytes adrs 24 32))))

(defn set-chain-address
  [adrs i]
  (validate-length!
   (common/merge-bytes
    (common/slice-bytes adrs 0 24)
    (common/integer->byte-array i 4)
    (common/slice-bytes adrs 28 32))))

(def set-tree-height set-chain-address)

(defn set-hash-address
  [adrs i]
  (validate-length!
   (common/merge-bytes
    (common/slice-bytes adrs 0 28)
    (common/integer->byte-array i 4))))

(def set-tree-index set-hash-address)

(defn get-key-pair-address
  [adrs]
  (common/byte-array->integer (common/slice-bytes adrs 20 24)))

(defn get-tree-index
  [adrs]
  (common/byte-array->integer (common/slice-bytes adrs 28 32)))

(defn new-address
  []
  (byte-array address-size))
