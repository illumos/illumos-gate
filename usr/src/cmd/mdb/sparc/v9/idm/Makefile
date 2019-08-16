#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

MODULE = idm.so
MDBTGT = kvm

MODSRCS = idm.c

ISCSITBASE = ../../../../../uts/common/io/comstar/port/iscsit
ISCSIBASE = ../../../../../uts/common/io/scsi/adapters/iscsi
ISERBASE = ../../../../../uts/common

include ../../../../Makefile.cmd
include ../../../../Makefile.cmd.64
include ../../Makefile.sparcv9
include ../../../Makefile.module

CPPFLAGS += -I$(ISCSITBASE)
CPPFLAGS += -I$(ISCSIBASE)
CPPFLAGS += -I$(ISERBASE)

CERRWARN += $(CNOWARN_UNINIT)
