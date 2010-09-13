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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

MODULE = intr.so
MDBTGT = kvm

MODSRCS = intr.c

MDB_DIR= $(ROOT)/usr/lib/mdb/kvm/sparcv9
MDB_INTR=intr.so
MDB_PCIPSY=pcipsy.so
MDB_PCISCH=pcisch.so
MDB_PX=px.so
MDB_NIUMX=niumx.so

KMDB_DIR= $(ROOT)/kernel/kmdb/sparcv9
KMDB_INTR=intr
KMDB_PCIPSY=pcipsy
KMDB_PCISCH=pcisch
KMDB_PX=px
KMDB_NIUMX=niumx

include ../../../../Makefile.cmd
include ../../../../Makefile.cmd.64
include ../../Makefile.sparcv9
include ../../../Makefile.module

CPPFLAGS += -I$(SRC)/uts/common
CPPFLAGS += -I$(SRC)/uts/sun4
CPPFLAGS += -I$(SRC)/uts/sun4/io/px
CPPFLAGS += -I$(SRC)/uts/sun4u
CPPFLAGS += -I$(SRC)/uts/sun4v/io/niumx
CPPFLAGS += -I$(SRC)/uts/sparc/v9

MODSRCS_DIR = ../../../sparc/modules/intr

install: all
	-$(RM) $(MDB_DIR)/$(MDB_PCIPSY)
	-$(RM) $(MDB_DIR)/$(MDB_PCISCH)
	-$(RM) $(MDB_DIR)/$(MDB_PX)
	-$(RM) $(MDB_DIR)/$(MDB_NIUMX)
	-cd $(MDB_DIR); $(SYMLINK) $(MDB_INTR) $(MDB_PCIPSY)
	-cd $(MDB_DIR); $(SYMLINK) $(MDB_INTR) $(MDB_PCISCH)
	-cd $(MDB_DIR); $(SYMLINK) $(MDB_INTR) $(MDB_PX)
	-cd $(MDB_DIR); $(SYMLINK) $(MDB_INTR) $(MDB_NIUMX)
	-$(RM) $(KMDB_DIR)/$(KMDB_PCIPSY)
	-$(RM) $(KMDB_DIR)/$(KMDB_PCISCH)
	-$(RM) $(KMDB_DIR)/$(KMDB_PX)
	-$(RM) $(KMDB_DIR)/$(KMDB_NIUMX)
	-cd $(KMDB_DIR); $(SYMLINK) $(KMDB_INTR) $(KMDB_PCIPSY)
	-cd $(KMDB_DIR); $(SYMLINK) $(KMDB_INTR) $(KMDB_PCISCH)
	-cd $(KMDB_DIR); $(SYMLINK) $(KMDB_INTR) $(KMDB_PX)
	-cd $(KMDB_DIR); $(SYMLINK) $(KMDB_INTR) $(KMDB_NIUMX)
