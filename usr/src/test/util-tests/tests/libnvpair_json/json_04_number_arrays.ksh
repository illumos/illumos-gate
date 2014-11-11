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
"byte_array":[0,1,2,10,15,100,103,127,128,254,255],\
"uint8_array":[128,254,255,10,15,100,103,127,0,1,2],\
"uint16_array":[0,1000,2000,3210,4321,5432,10000,15000,16384,\
17992,35012,65535,0],\
"uint32_array":[0,4294967295,4026531855,1,2,1000,501],\
"uint64_array":[19850907,0,18446744073709551615],\
"int8_array":[39,39,39,39,39,39,39,-128,-127,0,127],\
"int16_array":[7532,-32768,0,32767,0,-32768,100],\
"int32_array":[-2147483648,0,32767,-32768,2147483647],\
"int64_array":[0,0,9223372036854775807,1,1,1,-9223372036854775808,0]\
}
EOF)"

OUTPUT="$(${DIR}/../../bin/print_json <<'EOF'
add_byte_array "byte_array"
  "0" "1" "2" "10" "15" "100" "103" "127" "128" "254" "255";

add_uint8_array "uint8_array"
  "128" "254" "255" "10" "15" "100" "103" "127" "0" "1" "2";

add_uint16_array "uint16_array"
  "0" "1000" "2000" "3210" "4321" "5432" "10000" "15000" "16384"
  "17992" "35012" "65535" "0";

add_uint32_array "uint32_array"
  "0" "4294967295" "4026531855" "1" "2" "1000" "501";

add_uint64_array "uint64_array"
  "19850907" "0" "18446744073709551615";

add_int8_array "int8_array"
  "39" "39" "39" "39" "39" "39" "39" "-128" "-127" "0" "127";

add_int16_array "int16_array"
  "7532" "-32768" "0" "32767" "0" "-32768" "100";

add_int32_array "int32_array"
  "-2147483648" "0" "32767" "-32768" "2147483647";

add_int64_array "int64_array"
  "0" "0" "9223372036854775807" "1" "1" "1" "-9223372036854775808" "0";
EOF)"

complete
