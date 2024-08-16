#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Not enought arguments."
	echo "$0 <s | c>"
	echo "	s - server"
	echo "	c - client"
	exit
fi

PATH=$PATH:$(pwd)/bin/
PYTHONPATH=$PYTHONPATH:$(pwd)/packages/sev-snp-measure

if [ "$1" == 's' ]; then
	./ssl_echo s 7002 
fi

if [ "$1" == 'c' ]; then
	./ssl_echo c localhost 7020
fi
