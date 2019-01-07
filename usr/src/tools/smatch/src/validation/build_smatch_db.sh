#!/bin/bash

../smatch --info $* > warns.txt
../smatch_data/db/create_db.sh warns.txt > /dev/null 2>&1

