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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2015 Igor Kozhukhov <ikozhukhov@gmail.com>
#

include	../Makefile.lib

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber

# capability NAMES generated source
NAMES= \
src/libc/xcurses/boolcode.c	src/libc/xcurses/boolfnam.c \
src/libc/xcurses/boolname.c	src/libc/xcurses/numcode.c \
src/libc/xcurses/numfnam.c	src/libc/xcurses/numname.c \
src/libc/xcurses/strcode.c	src/libc/xcurses/strfnam.c \
src/libc/xcurses/strname.c

GENERATED= \
$(NAMES)	src/libc/xcurses/keyindex.c	h/term.h

# definitions for install_h target
HDRS=		h/term.h h/curses.h h/unctrl.h

# extra clean-up work
CLOBBERFILES=	$(GENERATED)

.KEEP_STATE:

LIBS=		$(DYNLIB)

all: $(GENERATED) .WAIT $(SUBDIRS)

install: all .WAIT $(SUBDIRS)

clean clobber: $(SUBDIRS)
	$(RM) $(GENERATED)

# still need to implement cstyle check of term.h
# do this when we go through and make this library cstyle clean.
check: $(HDRS)

$(SUBDIRS):	$(GENERATED)
	@cd $@; pwd; $(MAKE) $(TARGET)

# derived C files
# mknames.awk defines functions so needs nawk
$(NAMES) : src/libc/xcurses/mknames.awk src/libc/xcurses/caps
	$(RM) $(NAMES)
	cd src/libc/xcurses; $(AWK) -f mknames.awk caps

h/term.h : src/libc/xcurses/mkterm.awk src/libc/xcurses/caps
	$(RM) $@
	cd src/libc/xcurses; $(AWK) -f mkterm.awk caps > term.h
	$(MV) src/libc/xcurses/term.h h/term.h

src/libc/xcurses/keyindex.c : src/libc/xcurses/mkkey.awk src/libc/xcurses/caps
	$(RM) $@
	cd src/libc/xcurses; $(AWK) -f mkkey.awk caps > keyindex.c
