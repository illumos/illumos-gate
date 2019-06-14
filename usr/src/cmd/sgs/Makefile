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
# Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2016 RackTop Systems.
# Copyright 2017 Joyent, Inc.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

include		$(SRC)/cmd/Makefile.cmd

# Note: Why SUBDIRS-common isn't sorted alphabetically
#
# The items under SGS are not independent of each other.
# They must be built in an order that ensures that
# all dependencies of an item have been built before the
# item itself.
#
SUBDIRS-common= libconv		\
		.WAIT		\
		libdl		\
		libelf		\
		liblddbg	\
		.WAIT		\
		libld		\
		libldmake	\
		libldstab	\
		librtld		\
		libcrle		\
		.WAIT		\
		0@0		\
		ld		\
		ldd		\
		lddstub		\
		rtld		\
		link_audit	\
		.WAIT		\
		librtld_db	\
		ldprof		\
		pvs		\
		crle		\
		ar		\
		dump		\
		elfdump		\
		elfedit		\
		elfwrap		\
		error		\
		gprof		\
		lari		\
		lex		\
		lorder		\
		m4		\
		mcs		\
		moe		\
		nm		\
		prof		\
		ranlib		\
		size		\
		symorder	\
		tsort		\
		unifdef		\
		yacc

SUBDIRS-i386=
SUBDIRS-sparc=	rtld.4.x

SUBDIRS=	$(SUBDIRS-common) $(SUBDIRS-$(MACH))

# Messaging support
#
POSUBDIRS=	m4		nm	tsort		yacc
POFILE=		sgs.po
POFILES=	$(POSUBDIRS:%=%/%.po)

MSGSUBDIRS=	ld		ldd		libld		liblddbg \
		libldstab	librtld		rtld		libelf \
		ldprof		libcrle		pvs		elfdump	\
		elfedit		crle		moe		lari \
		librtld_db	elfwrap		ar

MSGDIR=		messages


all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
delete :=	TARGET= delete
lint :=		TARGET= lint
_msg :=		TARGET= catalog
_msg_gettext :=	TARGET= catalog
_msg_sgsmsg :=	TARGET= catalog
chkmsg :=	TARGET= chkmsg


.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all install:	$(SUBDIRS)

include		$(SRC)/cmd/Makefile.targ

# Messaging support
#
_msg: _msg_gettext _msg_sgsmsg

_msg_gettext: $(MSGDOMAIN)/$(POFILE)

_msg_sgsmsg: $(MSGDIR)

$(MSGDOMAIN)/$(POFILE): \
		$(MSGDOMAIN) $(POFILE)

$(POFILE):	$(POSUBDIRS)
		$(RM) $(POFILE)
		cat $(POFILES) > $(POFILE)

$(MSGDIR):	$(MSGSUBDIRS) FRC
		@ cd $@; pwd; $(MAKE) $(TARGET)

chkmsg:		libconv $(MSGSUBDIRS) FRC

check:		chkmsg

# built from lib/Makefile
install_lib:	FRC
		@ cd lex; pwd; $(MAKE) $@
		@ cd yacc; pwd; $(MAKE) $@

lint:

delete clean clobber: $(SUBDIRS) $(MSGDIR)

$(SUBDIRS):	FRC
		@ cd $@; pwd; $(MAKE) $(TARGET)

FRC:

#
# Cross-reference customization: ignore the directories named by XRPRUNE,
# and tweak the file globs slightly.
#
XRPRUNE=	rtld.4.x abi
XRADD=		*.msg mapfile*
XRDEL=		Makefile* kobj_*

#
# Establish a set of directories for xref to search.  As there are duplicates
# of things like headers, and only one file will be added to the xref database,
# we want xref to list the source file.
#
XRDIRS=		. \
		../../common/elfcap \
		../../head \
		../../uts/common/krtld \
		../../uts/common/sys \
		../../uts/sparc/sys \
		../../uts/sparc/krtld \
		../../uts/intel/ia32/krtld \
		../../uts/intel/amd64/krtld

xref:		FRC
		@ $(RM) cscope.*
		xref -p -x cscope
