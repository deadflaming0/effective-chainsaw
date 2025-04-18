(ns effective-chainsaw.api
  (:require [effective-chainsaw.address :as address]
            [effective-chainsaw.common :as common]
            [effective-chainsaw.parameter-sets :as parameter-sets]
            [effective-chainsaw.randomness :as randomness]
            [effective-chainsaw.slh-dsa :as slh-dsa]
            [effective-chainsaw.xmss :as xmss]))

(defn generate-key-pair
  [parameter-set-name]
  (let [{:keys [parameters] :as parameter-set-data} (parameter-sets/parameter-set-data parameter-set-name)
        {:keys [n d h']} parameters
        sk-seed (randomness/random-bytes n)
        sk-prf (randomness/random-bytes n)
        pk-seed (randomness/random-bytes n)
        adrs (-> (address/new-address)
                 (address/set-layer-address (dec d)))
        pk-root (xmss/subtree parameter-set-data sk-seed 0 h' pk-seed adrs)]
    {:private-key
     {:sk-seed sk-seed
      :sk-prf sk-prf
      :pk-seed pk-seed
      :pk-root pk-root}
     :public-key
     {:pk-seed pk-seed
      :pk-root pk-root}}))

(defn- validate-and-prepend-context!
  [M context]
  (let [context-length (count context)]
    (if (> 255 context-length)
      (common/merge-bytes
       (common/integer->byte-array 0 1)
       (common/integer->byte-array context-length 1)
       context
       M)
      (throw (Exception. "Context length must be < 255 bytes")))))

(defn sign
  [parameter-set-name M context private-key]
  (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
        M' (validate-and-prepend-context! M context)]
    (slh-dsa/sign* parameter-set-data M' private-key)))

(defn verify
  [parameter-set-name M signature context public-key]
  (let [parameter-set-data (parameter-sets/parameter-set-data parameter-set-name)
        M' (validate-and-prepend-context! M context)]
    (slh-dsa/verify* parameter-set-data M' signature public-key)))

(comment
  (do
    (def parameter-set-name :slh-dsa-shake-128s)

    (def key-pair (time (generate-key-pair parameter-set-name)))
    ; (out) "Elapsed time: 4209.8285 msecs"

    (def M (byte-array [0x01 0x02 0x03 0x04 0x05]))
    (def context (byte-array [0xff]))

    (def signature (time (sign parameter-set-name M context (:private-key key-pair))))
    ; (out) "Elapsed time: 33267.328916 msecs"

    (assert (time (verify parameter-set-name M signature context (:public-key key-pair)))
            "NOOO!!!!!"))
  ; (out) "Elapsed time: 37.39175 msecs"
  )
