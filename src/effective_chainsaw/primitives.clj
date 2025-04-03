(ns effective-chainsaw.primitives
  (:import (org.bouncycastle.crypto.digests SHA256Digest SHA512Digest SHAKEDigest)
           (org.bouncycastle.crypto.generators MGF1BytesGenerator)
           (org.bouncycastle.crypto.macs HMac)))

(defn- shake256-algorithm [] (SHAKEDigest. 256))

(defn- sha-256-algorithm [] (SHA256Digest.))
(defn- mgf1-sha-256-algorithm [] (MGF1BytesGenerator. (sha-256-algorithm)))
(defn- hmac-sha-256-algorithm [] (HMac. (sha-256-algorithm)))

(defn- sha-512-algorithm [] (SHA512Digest.))
(defn- mgf1-sha-512-algorithm [] (MGF1BytesGenerator. (sha-512-algorithm)))
(defn- hmac-sha-512-algorithm [] (HMac. (sha-512-algorithm)))

(defn shake256
  "Bytes in, bytes out."
  [input output-size-in-bits] ;; assumes input is ready to be used, properly concatenated
  (let [shake256 (shake256-algorithm) ;; probably not a good idea, lol
        input-size (count input)
        output-size-in-bytes (quot output-size-in-bits 8)
        output (byte-array output-size-in-bytes)]
    (.update shake256 input 0 input-size)
    (.doFinal shake256 output 0 output-size-in-bytes)
    output))
