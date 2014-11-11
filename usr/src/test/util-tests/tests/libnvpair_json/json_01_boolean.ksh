#!/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2014, Joyent, Inc.
#

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
