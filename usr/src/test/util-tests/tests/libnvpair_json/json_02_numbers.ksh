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
"byte":255,\
"uint8_0":0,\
"uint8_100":100,\
"uint8_255":255,\
"uint16":12345,\
"uint32":23423423,\
"uint64":19850709000000,\
"int16_small":-32768,\
"int8_neg":-128,\
"int8_pos":127,\
"int16_big":32767,\
"int32":-1270000,\
"int64":-12700000000001,\
"double_small":0.000023,\
"double_big":2342300000000.000000\
}
EOF)"

OUTPUT="$(${DIR}/../../bin/print_json <<'EOF'
add_byte "byte" "0";
add_byte "byte" "255";

add_uint8 "uint8_0" "0";
add_uint8 "uint8_100" "100";
add_uint8 "uint8_255" "255";

add_uint16 "uint16" "12345";
add_uint32 "uint32" "23423423";
add_uint64 "uint64" "19850709000000";

add_int16 "int16_small" "-32768";
add_int8 "int8_neg" "-128";
add_int8 "int8_pos" "127";
add_int16 "int16_big" "32767";

add_int32 "int32" "-1270000";
add_int64 "int64" "-12700000000001";

add_double "double_small" "0.000023423";
add_double "double_big" "0.000023423e17";
EOF)"

complete
