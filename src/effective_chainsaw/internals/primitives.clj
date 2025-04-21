(ns effective-chainsaw.internals.primitives
  (:import (org.bouncycastle.crypto.digests SHAKEDigest)))

(defn- shake256-algorithm [] (SHAKEDigest. 256))

(defn shake256
  "Bytes in, bytes out."
  [input output-size]
  (let [shake256 (shake256-algorithm)
        input-size (count input)
        output (byte-array output-size)]
    (.update shake256 input 0 input-size)
    (.doFinal shake256 output 0 output-size)
    output))
