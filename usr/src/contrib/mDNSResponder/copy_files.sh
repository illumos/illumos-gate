#!/bin/ksh

if [ ! -d "$1" ]; then
  echo "\"$1\" should be source repository root directory"
  exit 1
fi

for f in LICENSE */*
do
	cp $1/$f $f
done
