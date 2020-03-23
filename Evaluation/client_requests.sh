#!/bin/bash

for i in {1..1300}
do
  echo "Request to be sent: $i"
  TORSOCKS_USERNAME=abcdefg$i
  export TORSOCKS_USERNAME
  TORSOCKS_PASSWORD=abcdefg$i
  export TORSOCKS_PASSWORD
  (torsocks curl --connect-timeout 1 http://cmpk7m2lv25krppuinqhevg4vqojzpmmmx4rjr6iaoqh4t672deadaad.onion/ > /dev/null; echo "$i" >> cnt)&
  sleep 0.2
done