(ns effective-chainsaw.building-blocks.parameter-sets
  (:require [effective-chainsaw.internals.common :as common]
            [effective-chainsaw.internals.primitives :as primitives]))

(def parameter-set->parameters ;; add sha2 variants later
  {:slh-dsa-shake-128s {:n 16 :h 63 :d 7 :h' 9 :a 12 :k 14 :lg_w 4 :m 30 :pk-bytes 32 :sig-bytes 7856}
   :slh-dsa-shake-128f {:n 16 :h 66 :d 22 :h' 3 :a 6 :k 33 :lg_w 4 :m 34 :pk-bytes 32 :sig-bytes 17088}
   :slh-dsa-shake-192s {:n 24 :h 63 :d 7 :h' 9 :a 14 :k 17 :lg_w 4 :m 39 :pk-bytes 48 :sig-bytes 16224}
   :slh-dsa-shake-192f {:n 24 :h 66 :d 22 :h' 3 :a 8 :k 33 :lg_w 4 :m 42 :pk-bytes 48 :sig-bytes 35664}
   :slh-dsa-shake-256s {:n 32 :h 64 :d 8 :h' 8 :a 14 :k 22 :lg_w 4 :m 47 :pk-bytes 64 :sig-bytes 29792}
   :slh-dsa-shake-256f {:n 32 :h 68 :d 17 :h' 4 :a 9 :k 35 :lg_w 4 :m 49 :pk-bytes 64 :sig-bytes 49856}})

(defn parameter-set-data
  [parameter-set-name]
  (let [{:keys [m n] :as parameters} (get parameter-set->parameters parameter-set-name)
        functions (case parameter-set-name
                    (:slh-dsa-shake-128s
                     :slh-dsa-shake-128f
                     :slh-dsa-shake-192s
                     :slh-dsa-shake-192f
                     :slh-dsa-shake-256s
                     :slh-dsa-shake-256f) ;; shake-specific functions
                    {:H_msg (fn [R pk-seed pk-root M]
                              (primitives/shake256 (common/merge-bytes R pk-seed pk-root M) m))
                     :PRF (fn [pk-seed sk-seed adrs]
                            (primitives/shake256 (common/merge-bytes pk-seed adrs sk-seed) n))
                     :PRF_msg (fn [sk-prf additional-randomness M]
                                (primitives/shake256 (common/merge-bytes sk-prf additional-randomness M) n))
                     :F (fn [pk-seed adrs M_1]
                          (primitives/shake256 (common/merge-bytes pk-seed adrs M_1) n))
                     :H (fn [pk-seed adrs M_2]
                          (primitives/shake256 (common/merge-bytes pk-seed adrs M_2) n))
                     :T_l (fn [pk-seed adrs M_l]
                            (primitives/shake256 (common/merge-bytes pk-seed adrs M_l) n))}

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
