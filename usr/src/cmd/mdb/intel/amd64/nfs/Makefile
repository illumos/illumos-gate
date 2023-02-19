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
# Copyright 2021 Tintri by DDN, Inc. All rights reserved.

MDBTGT		= kvm
MODULE		= nfs.so
MODSRCS_DIR	= ../../../common/modules/nfs
MODSRCS		= nfs.c svc.c rfs4.c nfssrv.c idmap.c nfs_clnt.c common.c nfs_stat.c

include ../../../../Makefile.cmd
include ../../../../Makefile.cmd.64
include ../../Makefile.amd64
include ../../../Makefile.module

CPPFLAGS	+= -I$(SRC)/uts/common

CSTD=   $(CSTD_GNU99)

