#!/bin/bash

if [[ -z "$AWK" ]]; then
    printf '$AWK must be set\n' >&2
    exit 1
fi

$AWK 'BEGIN { for (i = 1; i <= 128*64+1; i++) print "abcdefgh123456\n" }' 2>&1 | \
    $AWK 'BEGIN { RS = ""; ORS = "\n\n" }; { print }' 2>&1 | \
    $AWK '/^[^a]/; END{ print NR }'
