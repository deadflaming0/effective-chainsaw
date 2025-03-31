(ns effective-chainsaw.core-test
  (:require [clojure.test :refer :all]
            [effective-chainsaw.core :as core]))

(deftest lalala-test
  (testing "this is a test"
    (is (zero? (inc -1)))))

(run-tests)
