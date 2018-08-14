#!/bin/bash

if [ $# -ne 2 ]; then
	echo "incorrect usage"
	echo "first arg is all caps mode"
	echo "second arg is keylist"
	exit 1
fi

nice -n -20 time python ../aesbrute/aes_brute.py -c flag $2 ./test/$1.txt
