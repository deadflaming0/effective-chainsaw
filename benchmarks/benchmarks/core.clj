(ns benchmarks.core
  (:require [criterium.core :refer [quick-bench with-progress-reporting]]
            [effective-chainsaw.api :as api]
            [effective-chainsaw.building-blocks.parameter-sets :as parameter-sets]))

;; TODO: Consider using test vectors (1 case per group)

(defn- benchmark-key-pair-generation!
  []
  (println "Running benchmark for: `generate-key-pair`.")
  (doseq [parameter-set-name (keys parameter-sets/parameter-set->parameters)]
    (println "Parameter set:" parameter-set-name)
    (with-progress-reporting
      (quick-bench (api/generate-key-pair parameter-set-name)
                   :verbose)))
  (println "Done!"))

(def M
  (byte-array
   [0x54 0x6f 0x64 0x61 0x73 0x20 0x61 0x73 0x20 0x66 0x61 0x6d 0x69 0x6c 0x69 0x61
    0x73 0x20 0x66 0x65 0x6c 0x69 0x7a 0x65 0x73 0x20 0x73 0x65 0x20 0x70 0x61 0x72
    0x65 0x63 0x65 0x6d 0x2c 0x20 0x63 0x61 0x64 0x61 0x20 0x66 0x61 0x6d 0x69 0x6c
    0x69 0x61 0x20 0x69 0x6e 0x66 0x65 0x6c 0x69 0x7a 0x20 0x65 0x20 0x69 0x6e 0x66
    0x65 0x6c 0x69 0x7a 0x20 0x61 0x20 0x73 0x75 0x61 0x20 0x6d 0x61 0x6e 0x65 0x69
    0x72 0x61 0x2e]))

(def context
  (byte-array [0x01 0x02 0x03]))

(defn- benchmark-signing!
  []
  (println "Running benchmark for: `sign`.")
  (doseq [parameter-set-name (keys parameter-sets/parameter-set->parameters)]
    (println "Parameter set:" parameter-set-name)
    (let [key-pair (api/generate-key-pair parameter-set-name)]
      (with-progress-reporting
        (quick-bench (api/sign parameter-set-name M context (:private-key key-pair))
                     :verbose))))
  (println "Done!"))

(defn- benchmark-verifying!
  []
  (println "Running benchmark for: `verify`.")
  (doseq [parameter-set-name (keys parameter-sets/parameter-set->parameters)]
    (println "Parameter set:" parameter-set-name)
    (let [key-pair (api/generate-key-pair parameter-set-name)
          signature (api/sign parameter-set-name M context (:private-key key-pair))]
      (with-progress-reporting
        (quick-bench (api/verify parameter-set-name M signature context (:public-key key-pair))
                     :verbose))))
  (println "Done!"))

(defn- run-benchmarks!
  []
  (benchmark-key-pair-generation!)
  (benchmark-signing!)
  (benchmark-verifying!))

(defn -main
  []
  (println "Running benchmarks...")
  (run-benchmarks!)
  (println "Done."))
