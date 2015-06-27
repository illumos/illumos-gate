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
# Copyright 2015 Nexenta Systems, Inc. All rights reserved.
#

PROG= format

COBJS=	add_definition.o analyze.o checkdev.o ctlr_scsi.o \
	defect.o init_menus.o io.o label.o main.o \
	menu.o menu_analyze.o menu_cache.o menu_command.o menu_defect.o \
	menu_partition.o misc.o modify_partition.o partition.o \
	prompts.o startup.o menu_scsi.o auto_sense.o disk_generic.o \
	menu_developer.o menu_fdisk.o

OBJS_sparc=   init_csparc.o ctlr_ata.o

OBJS_i386=    init_ci386.o ctlr_ata.o ix_altsctr.o

OBJS_=                non-existent

OBJS=  $(OBJS_$(MACH))  $(COBJS)

DATA= format.dat

include ../Makefile.cmd

CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-clobbered

SRCS= $(OBJS:.o=.c)

ROOTSYMLINK= $(ROOTETCPROG)
ROOTETCDATA= $(ROOTETC)/$(DATA)

$(ROOTETCDATA) := FILEMODE = 0644

LDLIBS_i386= -lfdisk 
LDLIBS_sparc=
LDLIBS +=	-ladm -lefi -ldiskmgt -lnvpair -ldevid -ldevinfo $(LDLIBS_$(MACH))

LINTFLAGS += -xerroff=E_NAME_DEF_NOT_USED2
CPPFLAGS    += -D_EXTVTOC

.KEEP_STATE:

all: $(PROG) $(DATA)

.PARALLEL: $(OBJS)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

#
# Install format as /usr/sbin/format, with link from /etc/format
#
install: $(ROOTUSRSBINPROG) $(ROOTSYMLINK) $(ROOTETCDATA)

$(ROOTSYMLINK):
	$(RM) $@; $(SYMLINK) ../usr/sbin/$(PROG) $@

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

sb: $(SRCS)
	$(COMPILE.c) -xsbfast $(SRCS)

include ../Makefile.targ
