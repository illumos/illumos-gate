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
# Copyright 2022 Toomas Soome <tsoome@me.com>
#

This is source tree snapshot of loader and related parts from
freebsd source.

Directory tree layout:

usr/src/boot is the root directory of the imported snapshot,
containing Makefile and licence notes for build and packaging.

Directories from freebsd userland (freebsd /usr/src tree):
include

Directories from freebsd kernel tree are located in sys subdirectory
(freebsd /usr/src/sys tree):

platform specific include files:

sys/amd64
sys/i386
sys/x86

sys and ufs include files:
sys/sys
sys/ufs

zfs boot module import in freebsd:
sys/cddl

Note, some of the directories are not 1:1 mapping in this source import,
because of differences of build systems used in illumos and freebsd.
Also some differences are due to fact, we do not need all the variants of
stage1/stage2 boot blocks which are built in freebsd due to the historical
or technical reasons.

Feb, 2022
