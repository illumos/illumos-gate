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

function complete {
  if [[ "${PRINT_OUTPUT}" ]]; then
    printf "%s\n" "${OUTPUT}"
    exit 0
  elif [[ "${OUTPUT}" == "${BASELINE}" ]]; then
    printf "TEST PASS: %s\n" "$(basename $0)"
    exit 0
  else
    printf "TEST FAIL: %s\n" "$(basename $0)"
    printf "EXPECTED: %s\n" "${BASELINE}"
    printf "ACTUAL:   %s\n" "${OUTPUT}"
    exit 1
  fi
}
