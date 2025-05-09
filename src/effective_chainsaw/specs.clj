(ns effective-chainsaw.specs
  (:require [clojure.spec.alpha :as s]
            [effective-chainsaw.building-blocks.parameter-sets :as parameter-sets]))

(s/def ::parameter-set-name (set (keys parameter-sets/parameter-set->parameters)))

(s/def ::sk-seed bytes?)
(s/def ::sk-prf bytes?)
(s/def ::pk-seed bytes?)
(s/def ::pk-root bytes?)

(s/def ::private-key (s/keys :req-un [::sk-seed ::sk-prf ::pk-seed ::pk-root]))
(s/def ::public-key (s/keys :req-un [::pk-seed ::pk-root]))

(s/def ::key-pair (s/keys :req-un [::private-key ::public-key]))

(def max-context-length 255)
(s/def ::n (s/int-in 1 (inc max-context-length)))
(s/def ::context bytes?)

(s/def ::message bytes?)
(s/def ::additional-randomness bytes?)

(s/def ::signature bytes?)
