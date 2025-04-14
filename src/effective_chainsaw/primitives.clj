(ns effective-chainsaw.primitives
  (:import (org.bouncycastle.crypto.digests SHAKEDigest)))

(defn- shake256-algorithm [] (SHAKEDigest. 256))

(defn shake256
  "Bytes in, bytes out."
  [input output-size-in-bits]
  (let [shake256 (shake256-algorithm)
        input-size (count input)
        output-size-in-bytes (quot output-size-in-bits 8)
        output (byte-array output-size-in-bytes)]
    (.update shake256 input 0 input-size)
    (.doFinal shake256 output 0 output-size-in-bytes)
    output))
