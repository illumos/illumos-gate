#!/bin/bash

rm -f smatch_db.sqlite

./build_smatch_db.sh $*
../smatch $*

rm smatch_db.sqlite

