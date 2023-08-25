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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= hostid

include ../Makefile.cmd

# Currently, the only architecture-specific things are
# the SMF pieces that set up the software-defined hostid on
# non-sparc platforms.  These need to get installed on x86
# which is why we do this in a $MACH subdir.

sparc_SUBDIRS =
i386_SUBDIRS = smf

SUBDIRS = $($(MACH)_SUBDIRS)

all     :=	TARGET = all
install :=	TARGET = install
clean   :=	TARGET = clean
clobber :=	TARGET = clobber
lint    :=	TARGET = lint


.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG) $(SUBDIRS)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

clean:

lint:	lint_PROG

FRC:

include ../Makefile.targ
