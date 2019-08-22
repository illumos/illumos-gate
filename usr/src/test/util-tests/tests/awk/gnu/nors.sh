#!/bin/bash

if [[ -z "$AWK" ]]; then
    printf '$AWK must be set\n' >&2
    exit 1
fi

echo A B C D E | tr -d '\12\15' | $AWK '{ print $NF }' - nors.in
