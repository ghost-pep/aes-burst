#!/bin/bash

if [ $# -ne 3 ]; then
	echo "incorrect usage"
	echo "first arg is all caps mode"
	echo "second arg is num threads"
	echo "third arg is keylist"
	exit 1
fi

#set priority to highest on the CPU then time the execution time
nice -n -20 time ./aesburst-multi -t $2 -m $1 -c flag $3 ./test/$1.txt
