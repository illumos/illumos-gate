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
"boolean_array":[],\
"byte_array":[],\
"uint8_array":[],\
"uint16_array":[],\
"uint32_array":[],\
"uint64_array":[],\
"int8_array":[],\
"int16_array":[],\
"int32_array":[],\
"int64_array":[],\
"string_array":[],\
"object_array":[{}]\
}
EOF)"

OUTPUT="$(${DIR}/../../bin/print_json <<'EOF'
add_boolean_array "boolean_array";

add_byte_array "byte_array";

add_uint8_array "uint8_array";
add_uint16_array "uint16_array";
add_uint32_array "uint32_array";
add_uint64_array "uint64_array";

add_int8_array "int8_array";
add_int16_array "int16_array";
add_int32_array "int32_array";
add_int64_array "int64_array";

add_string_array "string_array";

/*
 * The testing DSL does not presently support the generation of a completely
 * empty object array.  Thus, the following directive will produce an array
 * with a single keyless object:
 */
add_object_array "object_array";
end;
EOF)"

complete
