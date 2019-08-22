#!/bin/bash

if [[ -z "$AWK" || -z "$WORKDIR" ]]; then
    printf '$AWK and $WORKDIR must be set\n' >&2
    exit 1
fi

SCRIPT=$WORKDIR/test.temp.script
echo 'BEGIN { while( getline > 0) { print } }' > $SCRIPT

$AWK -f $SCRIPT $SCRIPT $SCRIPT
