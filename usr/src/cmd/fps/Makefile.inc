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
# ident	"%Z%%M%	%I%	%E% SMI"
#

WS_ROOT     = $(ROOT)
PROTO       = $(WS_ROOT)
SRC_DIR     = $(WS_ROOT)/src 
HCK_LIBDIR  = $(PROTO)/lib
BINDIR      = $(PROTO)/usr/lib/fps
PKGARCHIVE  = $(WS_ROOT)/pkgarchive
PKGDEFS     = $(WS_ROOT)/pkgdefs

DBX = -xO3

INCDIR = .

INC_SPEC   = -I$(INCDIR)

MSGDIR     = $(PROTO)/lib/locale/C/LC_MESSAGES

# The main definitions for 32 and 64 bits:

CFLAGS = $(DBX)  $(INC_SPEC) -i  -xildoff $(DTEXTDOM)
CFLAGS64 = $(DBX) -xarch=v9a $(INC_SPEC) -i -xildoff -D_sparc64

EXTRA_LIBS =

COMPILE.cpp= $(CC) -E -C $(CFLAGS) $(CPPFLAGS)

TEST_LDFLAGS  =  -L$(HCK_LIBDIR)  $(TSTLIB.A) $(EXTRA_LIBS)


BITS = all

BIT64_SETUP =
OBJ_DIR     =  .
HCK_RUN_PATH = -R'$$ORIGIN/../lib'


INSTBINDIR = $(BINDIR)   # Default local ws install dir for bins

.SUFFIXES: $(SUFFIXES) .po
TEXT_DOMAIN =  SUNW_CDIA       # Initialize in individual Makefiles.
MSGROOT   = $(PROTO)/catalog
MSGDOMAIN= $(MSGROOT)/$(TEXT_DOMAIN)

MSGDOMAINPOFILE =  $(MSGDOMAIN)/$(POFILE)

DTEXTDOM=-DTEXT_DOMAIN=\"$(TEXT_DOMAIN)\"       # For messaging.

XGETTEXT= xgettext
XGETFLAGS= -c TRANSLATION_NOTE

# Following macro can be used to generate a .po file
# from any .c file.
# See example Makefile in tests/example dir for its use.

BUILD.po= $(XGETTEXT) $(XGETFLAGS) $<.i ;\
        $(RM)   $@ ;\
        sed "/^domain/d" < messages.po  > $@ ;\
        $(RM) messages.po $<.i

.c.po .cc.po : $$(INCLUDES)
	@echo Generating catalog file $@ from $<
	@$(COMPILE.cpp) $<  > $<.i
	@$(BUILD.po)

bits32 install32:=    	BITS = bits32

bits64:=    CFLAGS = $(DBX) -xarch=v9a $(INC_SPEC) -i -xildoff -D_sparc64
bits64:=    SVR4FLAGS = -xarch=v9a -xildoff
bits64:=    FBEFLAGS = -xarch=v9a -xildoff -D_sparc64
bits64:=    LDFLAGS += -xarch=v9a -xildoff

bits64 install64:=  HCK_LIBDIR = $(PROTO)/lib/sparcv9
bits64 install64:=  INSTBINDIR = $(PROTO)/usr/lib/fps
bits64 install64:=  BIT64_SETUP = (test -d sparcv9 || mkdir -m 775 sparcv9)
bits64 install64:=  OBJ_DIR = sparcv9
bits64 install64:=  LINK_PATH = -L$(PROTO)/lib/sparcv9
bits64 install64:=  HCK_RUN_PATH = -R'$$ORIGIN/../../lib/sparcv9'
bits64 install64:=  BITS = bits64


install:=	BITS = all
install32:=	BITS = bits32
install64:=	BITS = bits64

all        :=  TARGET = all
clean      :=  TARGET = clean
clobber    :=  TARGET = clobber
install    :=  TARGET = install
install64  :=  TARGET = install64
install32  :=  TARGET = install32


# Std macros
MV=             /usr/bin/mv -f
RM=             /usr/bin/rm -f
GREP=           /usr/bin/grep
SED=            /usr/bin/sed
CP=             /usr/bin/cp
CAT=            /usr/bin/cat

