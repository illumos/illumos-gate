#!/bin/bash

if [[ -z "$AWK" || -z "$WORKDIR" ]]; then
    printf '$AWK and $WORKDIR must be set\n' >&2
    exit 1
fi

SCRIPT=$WORKDIR/test.temp.run
cat > $SCRIPT <<EOF
#!$AWK -f 
{ print }
EOF

chmod a+rx $SCRIPT
printf 'a\nb\nc\nd\n' | $SCRIPT
