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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/scadm/Makefile.com
#

#
#	Create default so empty rules don't
#	confuse make
#
CLASS		= 32

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/Makefile.psm

PROG		= scadm

FILEMODE	= 2755
DIRMODE		= 755

#IMPL = $(PLATFORM:sun%=sun)
IMPL = mpxu

mpxu_OBJS = boot_recv.o callback.o date.o download.o eventlog.o \
	help.o init.o modem_setup.o process_command.o reset.o \
	scadm.o send_event.o send_file.o set.o show.o status.o usage.o \
	user.o valid_srecord.o wrappers.o smq.o xsem.o consolelog.o \
	configlog.o

OBJS= $($(IMPL)_OBJS)

mpxu_SOURCES = boot_recv.c callback.c date.c download.c eventlog.c \
	help.c init.c modem_setup.c process_command.c reset.c \
	scadm.c send_event.c send_file.c set.c show.c status.c usage.c \
	user.c valid_srecord.c wrappers.c smq.c xsem.c consolelog.c \
	configlog.c

SOURCES= $($(IMPL)_SOURCES)

# allow additional kernel-architecture dependent objects to be specified.

OBJS		+= $(KARCHOBJS)

SRCS		= $(OBJS:%.o=%.c)

LINT_OBJS	= $(OBJS:%.o=%.ln)

POFILE		= scadm_$(PLATFORM).po
POFILES		= $(OBJS:%.o=%.po)


# These names describe the layout on the target machine

IFLAGS = -I$(SRCDIR) -I$(USR_PSM_INCL_DIR) \
	-I$(SRCDIR)/../../lib/librsc/sparc/mpxu/common \
	-I$(SRCDIR)/../../uts/sun4u -I$(SRCDIR)/../../../src/uts/sun4u

CPPFLAGS = $(IFLAGS) $(CPPFLAGS.master) -D_SYSCALL32

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-unused-variable

LINKED_DIRS     = $(PLATLINKS:%=$(USR_PLAT_DIR)/%)
LINKED_SBIN_DIRS = $(PLATLINKS:%=$(USR_PLAT_DIR)/%/sbin)

.PARALLEL: $(OBJS)

$(LINKED_SBIN_DIRS): $(LINKED_DIRS)
	-$(INS.dir)

%.o:	common/%.c
	$(COMPILE.c) -o $@ $<

%.o:	$(SRCDIR)/common/%.c
	$(COMPILE.c) -o $@ $<

%.ln:	common/%.c
	$(LINT.c) -c $@ $<

%.ln:	$(SRCDIR)/common/%.c
	$(LINT.c) -c $@ $<

%.po:   common/%.c
	$(COMPILE.cpp) $<  > $<.i
	$(BUILD.po)

%.po:   $(SRCDIR)/common/%.c
	$(COMPILE.cpp) $<  > $<.i
	$(BUILD.po)
