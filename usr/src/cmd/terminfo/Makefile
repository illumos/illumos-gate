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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG=	terminfo

TABSETSRC= \
	3101 beehive hds hds3 std stdcrt teleray vt100 wyse-adds xerox1720

TXTS=	Doc.sed README ckout cvt.ex cvt.sed $(TABSETSRCS) termcap 

TISRC=	adds.ti annarbor.ti ansi.ti att.ti beehive.ti \
	cdc.ti colorscan.ti datamedia.ti dec.ti diablo.ti \
	fortune.ti general.ti hardcopy.ti hazeltine.ti hds.ti \
	heath.ti homebrew.ti hp.ti lsi.ti microterm.ti \
	misc.ti pc.ti perkinelmer.ti print.ti screen.ti special.ti \
	sperry.ti tektronix.ti teleray.ti televideo.ti ti.ti \
	tymshare.ti visual.ti wyse.ti

PARTS=	header $(TISRC) trailer

include ../Makefile.cmd

DIRMODE=	0755
FILEMODE=	0644
TIC=		tic
CAT=		/usr/bin/cat
ECHO=		echo

ROOTSHARELIBDIR	= $(ROOT)/usr/share/lib
ROOTTABDIR	= $(ROOTSHARELIBDIR)/tabset
ROOTTERMDIR	= $(ROOTSHARELIBDIR)/terminfo
DIRS=		$(ROOTTERMDIR) $(ROOTTABDIR)

ROOTSYMLINK	= $(ROOTETC)/termcap
RELROOTETC	= ../usr/share/lib
ROOTLIBSYMLINK	= $(ROOTLIB)/tabset
RELROOTLIB	= ../share/lib

ROOTTABSET	= $(TABSETSRC:%=$(ROOTTABDIR)/%)

$(ROOTTABDIR)/% :	tabset/%
	$(INS.file)

$(ROOTSHARELIBDIR)/% :	%
	$(INS.file)

.KEEP_STATE:

all:		$(PROG).src $(TXTS)

$(DIRS):
	$(INS.dir)

$(PROG).src:	$(PARTS)
		@$(CAT) $(PARTS) > $(PROG).src

$(ROOTTERMDIR)/s/sun: $(PROG).src
	TERMINFO=$(ROOTTERMDIR) 2>&1 $(TIC) -v $(PROG).src > errs
	@$(ECHO) "\n`2>/dev/null cat errs|wc -l` entries have been compiled\n"
	@-(	2>/dev/null cat errs|grep -iv "^mkdir"|grep -iv "^create"|grep -iv "^link"|grep -vi terminfo.src|grep -vi touch|grep -vi "working"; \
	 	if [ $$? -ne 0 ] ; \
		then \
			$(ECHO) "\tNo errors\n"; \
		else \
			$(ECHO) "\n\tErrors can be found in `pwd`/errs\n"; \
		fi \
	)

#
#	Note that order is significant here. $(ROOTTERMDIR)/s/sun will set the
#	entire subtree to ownership root/bin.
#
install:	all $(ROOTTERMDIR) $(ROOTTERMDIR)/s/sun $(ROOTTABDIR) \
		$(ROOTTABSET) $(ROOTSHARELIBDIR)/termcap  $(ROOTSYMLINK) \
		$(ROOTLIBSYMLINK)

$(ROOTSYMLINK):
	-$(RM) $@; $(SYMLINK) $(RELROOTETC)/termcap $@

$(ROOTLIBSYMLINK):
	-$(RM) $@; $(SYMLINK) $(RELROOTLIB)/tabset $@

lint:

clean:
		$(RM) $(PROG).src errs

clobber: 	clean
