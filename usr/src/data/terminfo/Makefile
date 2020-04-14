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
# Copyright 2017 Nexenta Systems, Inc.
#

TABSETSRC=	3101 \
		beehive \
		hds \
		hds3 \
		std \
		stdcrt \
		teleray \
		vt100 \
		wyse-adds \
		xerox1720
TERMCAPSRC=	termcap.src
TERMINFOSRC=	terminfo.src

#
# These represent the target termcap entries that we build from extra
# termcap and terminfo data. See extras/README.
#
EXTRATERM=	rxvt-unicode
EXTRATC=	$(EXTRATERM:%=extras/%.termcap)
EXTRATI=	r/rxvt-unicode

include		$(SRC)/data/Makefile.data

FILEMODE=	0644

ROOTTABDIR=	$(ROOTSHLIB)/tabset
ROOTTERMDIR=	$(ROOTSHLIB)/terminfo
DIRS=		$(ROOTTERMDIR) $(ROOTTABDIR)

ROOTSYMLINK=	$(ROOTETC)/termcap
RELROOTETC=	../usr/share/lib
ROOTLIBSYMLINK=	$(ROOTLIB)/tabset
RELROOTLIB=	../share/lib

ROOTSHSYMLINK=  $(ROOTSH)/terminfo

ROOTTABSET=	$(TABSETSRC:%=$(ROOTTABDIR)/%)

ROOTEXTRATI=	$(EXTRATI:%=$(ROOTTERMDIR)/%)

$(ROOTTABDIR)/%: tabset/%
		$(INS.file)

.KEEP_STATE:

all:		$(TERMCAPSRC) $(TERMINFOSRC)

$(DIRS):
		$(INS.dir)

$(ROOTTERMDIR)/s/sun: $(TERMINFOSRC)
		TERMINFO=$(ROOTTERMDIR) $(TIC) $(TERMINFOSRC) 2>/dev/null

$(ROOTSHLIB)/termcap: $(TERMCAPSRC) $(EXTRATC)
		echo $(EXTRATERM) $(EXTRATC)
		$(EGREP) -hv '^(#|$$)' $(TERMCAPSRC) $(EXTRATC) > $@

install:	all $(ROOTTERMDIR) $(ROOTTERMDIR)/s/sun $(ROOTTABDIR) \
		$(ROOTTABSET) $(ROOTSHLIB)/termcap  $(ROOTSYMLINK) \
		$(ROOTLIBSYMLINK) $(ROOTEXTRATI) $(ROOTSHSYMLINK)

$(ROOTSYMLINK):
		$(RM) $@; $(SYMLINK) $(RELROOTETC)/termcap $@

$(ROOTLIBSYMLINK):
		$(RM) $@; $(SYMLINK) $(RELROOTLIB)/tabset $@

$(ROOTSHSYMLINK):
		$(RM) $@; $(SYMLINK) $(RELROOTLIB)/terminfo $@

$(ROOTTERMDIR)/r/%: extras/%.terminfo
		TERMINFO=$(ROOTTERMDIR) $(TIC) $< 2>/dev/null

clean clobber:
