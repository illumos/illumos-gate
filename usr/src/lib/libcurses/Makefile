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
#

include	../Makefile.lib

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

# conditional assignments
all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
test :=		TARGET= test

SCRFILES = screen/keycaps \
	screen/curses.h \
	screen/keyname.c \
	screen/termcap.c \
	screen/tifget.c \
	screen/tiget.c \
	screen/tifnames.c \
	screen/tnames.c \
	screen/tinames.c \
	screen/term.h

# definitions for install_h target
HDRS= 		curses.h term.h unctrl.h
HDRDIR=		screen

LIBRARY=	libcurses.a
TEXT_DOMAIN=	SUNW_OST_OSLIB
XGETFLAGS=	-a
MSGDIRS=	screen
POFILE=		$(LIBRARY:.a=.po)
POFILES=	generic.po
CLEANFILES +=	$(SCRFILES)

# term.h doesn't pass cstyle due to numerous lines exceeding the 80 character
# limit.  maketerm.ed can probably be fixed to prevent this, but it is arguable
# if this work would ever be worth it.
#
screen/term.check      := CSTYLE_TAIL = | grep -v "line > 80 characters" | true

.KEEP_STATE:

all: $(SCRFILES) .WAIT $(SUBDIRS)

install: all .WAIT $(SUBDIRS)

clean clobber lint test: $(SUBDIRS)

install_h: $(ROOTHDRS)

check:	$(CHECKHDRS)

scrfiles:	$(SCRFILES)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

ED = ed

screen/curses.h:	screen/curses.ed screen/keycaps screen/tmp
	(cd screen; $(ED) - < curses.ed)

screen/keycaps:		screen/caps
	grep "KEY_" screen/caps > screen/keycaps
	@if tail -1 screen/keycaps | grep 'KEY_MOUSE' > /dev/null;then :; \
		else echo new keys!! must change setkeymap.c; exit 1;fi

screen/keyname.c:    screen/keyname.sh screen/keycaps
	(cd screen; sh keyname.sh)

screen/termcap.c:    screen/termcap.ed
	(cd screen; $(ED) - < termcap.ed)
	(cd screen; $(RM) bool num str)

screen/tifget.c:     screen/tifget.ed
	(cd screen; $(ED) - < tifget.ed)

screen/tiget.c:      screen/tiget.ed
	(cd screen; $(ED) - < tiget.ed)

screen/tnames.c screen/tinames.c screen/tifnames.c \
screen/term.h:   screen/maketerm.ed
	(cd screen; $(ED) - < maketerm.ed)

screen/tmp:
	rm -rf $@
	mkdir $@

CLEANFILES += \
	screen/tmp/keycaps \
	screen/tmp/term.h.new1 \
	screen/tmp/term.h.new2

_msg:	$(MSGDOMAIN) .WAIT $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	$(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po:
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]* */*.[ch]*`
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

FRC:

include ../Makefile.targ
