#!/bin/ksh

DIR=$(dirname $(whence $0))
. ${DIR}/json_common

BASELINE="$(cat <<EOF
{\
}
EOF)"

OUTPUT="$(${DIR}/../../bin/print_json <<'EOF'
/*
 * Emit a blank object.
 */
EOF)"

complete
