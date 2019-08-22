#!/bin/bash

if [[ -z "$AWK" ]]; then
    printf '$AWK must be set\n' >&2
    exit 1
fi

$AWK 'BEGIN { ORS = ""; n = "\n"; for (i = 1; i <= 10; i++) n = (n n); \
    for (i = 1; i <= 128; i++) print n; print "abc\n" }' | \
    $AWK 'BEGIN { RS = ""; ORS = "\n\n" };{ print }' 2>&1 | \
    $AWK '/^[^a]/; END { print NR }'
