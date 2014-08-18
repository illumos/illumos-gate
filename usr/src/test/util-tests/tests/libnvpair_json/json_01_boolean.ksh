#!/bin/ksh

DIR=$(dirname $(whence $0))
. ${DIR}/json_common

BASELINE="$(cat <<EOF
{\
"bool0":true,\
"a fact":true,\
"a fiction":false,\
"1":true,\
" ":true\
}
EOF)"

OUTPUT="$(${DIR}/../../bin/print_json <<'EOF'
/*
 * add_boolean calls nvlist_add_boolean(), which the JSON formatter
 * will emit as a true-valued boolean.
 */
add_boolean "bool0";
add_boolean_value "a fact" "true";
add_boolean_value "a fiction" "false";
add_boolean "1";

/*
 * Test a key with a whitespace-only name:
 */
add_boolean " ";
EOF)"

complete
