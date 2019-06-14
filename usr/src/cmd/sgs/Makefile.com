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
# Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2016 RackTop Systems.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

.KEEP_STATE:
.KEEP_STATE_FILE: .make.state.$(MACH)


include		$(SRC)/cmd/sgs/Makefile.var

i386_ARCH =	intel
sparc_ARCH =	sparc

ARCH =		$($(MACH)_ARCH)

# Establish any global flags.

# Setting DEBUG = -DDEBUG (or "make DEBUG=-DDEBUG ...") enables ASSERT()
# checking.  This is automatically enabled for DEBUG builds, not for non-debug
# builds.  Unset the global CSTD_GNU89 flag to insure we uncover all compiler
# warnings/errors.
DEBUG =
$(NOT_RELEASE_BUILD)DEBUG = -DDEBUG

CSTD_GNU89 =	$(CSTD_GNU99)

CFLAGS +=	$(CCVERBOSE) $(DEBUG) $(XFFLAG)
CFLAGS64 +=	$(CCVERBOSE) $(DEBUG) $(XFFLAG)

NATIVE_CFLAGS +=	$(CCVERBOSE) $(DEBUG) $(XFFLAG)

CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-value

#
# Location of the shared elfcap code
#
ELFCAP=		$(SRC)/common/elfcap

# Reassign CPPFLAGS so that local search paths are used before any parent
# $ROOT paths.
CPPFLAGS =	-I. -I../common -I$(SGSHOME)/include -I$(SGSHOME)/include/$(MACH) \
		$(CPPFLAGS.master) -I$(ELFCAP)

# PICS64 is unique to our environment
$(PICS64) :=	sparc_CFLAGS += -xregs=no%appl $(C_PICFLAGS)
$(PICS64) :=	sparcv9_CFLAGS += -xregs=no%appl $(C_PICFLAGS)
$(PICS64) :=	CPPFLAGS += -DPIC -D_REENTRANT

LDFLAGS +=	$(ZIGNORE)
DYNFLAGS +=	$(ZIGNORE)

# Establish the local tools, proto and package area.

SGSHOME =	$(SRC)/cmd/sgs
SGSCOMMON =	$(SGSHOME)/common
SGSTOOLS =	$(SGSHOME)/tools
SGSMSGID =	$(SGSHOME)/messages
SGSMSGDIR =	$(SGSHOME)/messages/$(MACH)
SGSONLD =	$(ROOT)/opt/SUNWonld
SGSRPATH =	/usr/lib
SGSRPATH64 =	$(SGSRPATH)/$(MACH64)

#
# Macros to be used to include link against libconv and include vernote.o
#
VERSREF =	-ulink_ver_string

LDLIBDIR =	-L$(SGSHOME)/libld/$(MACH)
LDLIBDIR64 =	-L$(SGSHOME)/libld/$(MACH64)

CONVLIBDIR =	-L$(SGSHOME)/libconv/$(MACH)
CONVLIBDIR64 =	-L$(SGSHOME)/libconv/$(MACH64)

ELFLIBDIR =	-L$(SGSHOME)/libelf/$(MACH)
ELFLIBDIR64 =	-L$(SGSHOME)/libelf/$(MACH64)

LDDBGLIBDIR =	-L$(SGSHOME)/liblddbg/$(MACH)
LDDBGLIBDIR64 =	-L$(SGSHOME)/liblddbg/$(MACH64)


# The cmd/Makefile.com and lib/Makefile.com define TEXT_DOMAIN.  We don't need
# this definition as the sgs utilities obtain their domain via sgsmsg(1l).

DTEXTDOM =

# Define any generic sgsmsg(1l) flags.  The default message generation system
# is to use gettext(3i), add the -C flag to switch to catgets(3c).

SGSMSG =		$(ONBLD_TOOLS)/bin/$(MACH)/sgsmsg
SGSMSG_PIGLATIN_NL =	perl $(SGSTOOLS)/common/sgsmsg_piglatin_nl.pl
CHKMSG =		$(SGSHOME)/tools/chkmsg.sh

SGSMSGVFLAG =
SGSMSGFLAGS =	$(SGSMSGVFLAG) -i $(SGSMSGID)/sgs.ident
CHKMSGFLAGS =	$(SGSMSGTARG:%=-m %) $(SGSMSGCHK:%=-m %)
