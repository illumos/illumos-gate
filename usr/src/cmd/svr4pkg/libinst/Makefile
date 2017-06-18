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
# Copyright (c) 2017 Peter Tribble.
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= libinst.a

OBJS=	copyf.o         dockdeps.o      echo.o          eptstat.o       \
	finalck.o       findscripts.o   fixpath.o       flex_dev.o      \
	isreloc.o       lockinst.o      mntinfo.o       nblk.o          \
	ocfile.o        pathdup.o       pkgdbmerg.o     procmap.o       \
	pkgobjmap.o     ptext.o         putparam.o                      \
	qreason.o       qstrdup.o       setadmin.o      setlist.o       \
	srcpath.o       scriptvfy.o     doulimit.o      \
	dryrun.o        listmgr.o       is_local_host.o cvtpath.o       \
	depchk.o        pkgops.o        sml.o           log.o           \
	setup_temporary_directory.o     open_package_datastream.o       \
	unpack_package_from_stream.o
SRCS = $(OBJS:.o=.c)

include	$(SRC)/cmd/Makefile.cmd

#
# For messaging catalog
POFILE = libinst.po
MSGFILES=$(OBJS:%.o=%.i) 

CPPFLAGS +=	-I$(SRC)/cmd/svr4pkg/hdrs \
		-I$(SRC)/lib/libpkg/common \
		-I$(SRC)/lib/libinstzones/common \
		-D_FILE_OFFSET_BITS=64

# For VERBOSE mode
#CPPFLAGS +=	-DVERBOSE

# For stop-in-your-tracks debugging
#CPPFLAGS +=	-DBUG_DEBUG

# Lint flags 
#
LINTFLAGS += -un

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-clobbered
CERRWARN += -_gcc=-Wno-unused-variable

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(OBJS)
	$(POST_PROCESS_A)

install: all
	@echo "$(PROG) is a static library and will not be installed."

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

_msg: $(MSGDOMAINPOFILE)

clean:
	$(RM) $(OBJS) $(MSGFILES)

clobber: clean
	$(RM) $(PROG) $(POFILE)

include	$(SRC)/Makefile.msg.targ
