#!/usr/bin/ksh
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
# Copyright 2026 Oxide Computer Company
#

#
# A shell stage is joined to the following dcmd with |, never a second !.
# Using ! as the separator is rejected: ! already begins a shell escape, and
# shell commands can legitimately contain !.
#

export SHELL=/bin/sh

$MDB -e "::echo 1 2 3 ! 'cat' ! ::map ."
exit $?
