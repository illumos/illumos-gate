#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# Architecture independent makefile for svm utilities
#
# cmd/lvm/util/Makefile.com
#

# programs that are installed in /usr/sbin
PROG= \
	medstat \
	metaclear \
	metadetach \
	metahs \
	metaoffline \
	metaonline \
	metaparam \
	metarename \
	metareplace \
	metaroot \
	metaset \
	metasync \
	metattach \
	metaimport

# programs that are installed in /sbin, with links from /usr/sbin
ROOTFS_PROG = \
	metadb \
	metadevadm \
	metainit \
	metarecover \
	metastat

# programs that are installed in /usr/lib/lvm
METACLUST= metaclust

OBJECTS =  \
	medstat.o \
	metaclear.o \
	metadb.o \
	metadetach.o \
	metadevadm.o \
	metahs.o \
	metainit.o \
	metaoffline.o \
	metaonline.o \
	metaparam.o \
	metarecover.o \
	metarename.o \
	metareplace.o \
	metaroot.o \
	metaset.o \
	metastat.o \
	metasync.o \
	metattach.o \
	metaclust.o \
	metaimport.o

SRCS=	$(OBJECTS:%.o=../%.c)

include ../../../Makefile.cmd
include ../../Makefile.lvm

ROOTLIBSVM = $(ROOTLIB)/lvm

CLOBBERFILES += $(ROOTFS_PROG) $(METACLUST)

ROOTUSRSBINPROG = $(PROG:%=$(ROOTUSRSBIN)/%)

ROOTSBINPROG = $(ROOTFS_PROG:%=$(ROOTSBIN)/%)

ROOTUSRSBINLINKS = $(ROOTFS_PROG:%=$(ROOTUSRSBIN)/%)

POFILE= utilp.po
DEFINES += -DDEBUG
CPPFLAGS += $(DEFINES)

metainit := CPPFLAGS += -I$(SRC)/lib/lvm/libmeta/common/hdrs
metaset := LDFLAGS += -ldevid

LDLIBS +=	-lmeta

lint := LINTFLAGS += -m

install		:= TARGET = install
clean		:= TARGET = clean

.KEEP_STATE:

%.o:	../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

all:     $(PROG) $(METACLUST) $(ROOTFS_PROG)

catalog: $(POFILE)

$(PROG) $(ROOTFS_PROG): $$(@).o
	$(LINK.c) -o $@ $(@).o $(LDLIBS)
	$(POST_PROCESS)

$(METACLUST): $$(@).o
	$(LINK.c) -o $@ $(@).o $(LDLIBS)
	$(POST_PROCESS)


install: all .WAIT $(ROOTLIBSVM) $(ROOTUSRSBINPROG) $(ROOTSBINPROG) $(ROOTUSRSBINLINKS) $(ROOTLIBSVM)/$(METACLUST)

$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(@F) $@

cstyle:
	$(CSTYLE) $(SRCS)

lint:
	for f in $(SRCS) ; do \
		if [ $$f = "../metainit.c" ]; then \
		    $(LINT.c) $(LINTFLAGS) \
			-I$(SRC)/lib/lvm/libmeta/common/hdrs $$f ; \
		else \
			$(LINT.c) $(LINTFLAGS) $$f ; \
		fi \
	done

clean:
	$(RM) $(OBJECTS) $(PROG)

include ../../../Makefile.targ

${ROOTLIBSVM}/%: %
	${INS.file}

${ROOTLIBSVM}:
	${INS.dir}

