#!/bin/sh

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
# Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
#

ICONV=${ICONV:-/usr/bin/iconv}
#ICONV=${ROOT}/usr/bin/iconv

# test name, file a, file b
check() {
  if ! cmp -s "$2" "$3" ; then
    echo "TEST FAIL: $1"
    exit 1
  fi
  echo "TEST PASS: $1"
}


# fromcs, tocs, in, out
test_conv() {
  echo "$3" > in
  echo "$4" > o1
  $ICONV -f "$1" -t "$2" < in > o2
  check "${1}:${2}" o1 o2
  rm in o1 o2
}

mkmap_one() {
  echo '<code_set_name> one'
  echo 'CHARMAP'
  echo '<NULL>\t\x00'
  for i in 8 9 a b c d e f
  do
    for j in 0 1 2 3 4 5 6 7 8 9 a b c d e f
    do
      echo "<c1-$i$j>\t\x$i$j"
    done
  done
  echo 'END CHARMAP'
}

mkmap_two() {
  echo '<code_set_name> two'
  echo 'CHARMAP'
  echo '<NULL>\t\x00'
  for i in 8 9 a b c d e f
  do
    for j in 0 1 2 3 4 5 6 7 8 9 a b c d e f
    do
      echo "<c1-$i$j>\t\x20\x$i$j"
    done
  done
  echo 'END CHARMAP'
}

# write 1023 bytes of space
wr1023() {
  n=1023
  while [[ $n -gt 0 ]]; do
    echo ' \c'
   ((n-=1))
  done
}

# two-byte utf-8 crossing 1024 byte boundary
mkbuf_utf8() {
  wr1023
  echo '\0303\0240'
}

# one-byte 8859-1 at 1024 byte boundary
mkbuf_8859() {
  wr1023
  echo '\0340'
}

# Test some simple, built-in conversions

test_conv ascii utf-8 abcdef abcdef
test_conv utf-8 ascii abcdef abcdef
test_conv ascii ucs-2le abc 'a\0b\0c\0\n\0\c'
test_conv ucs-2le ascii 'a\0b\0c\0\n\0\c' abc

# Test user-provided charmap

mkmap_one > one.cm
mkmap_two > two.cm
test_conv ./one.cm ./two.cm '\0200\0201\0202\c' ' \0200 \0201 \0202\c'
rm one.cm two.cm

# test crossing 1024 byte buffer boundary

mkbuf_utf8 > in
mkbuf_8859 > o1
$ICONV -f UTF-8 -t 8859-1 < in > o2
check "boundary" o1 o2
rm in o1 o2

exit 0
