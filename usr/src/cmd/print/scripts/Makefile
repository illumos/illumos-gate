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

include			../Makefile.sp

ROOTPRINTLIB =		$(ROOTLIB)/print
ROOTLIBLPBIN =		$(ROOTLIBLP)/bin
ROOTVARLP =		$(ROOTVAR)/lp
ROOTVARLPPPD =		$(ROOTVARLP)/ppd

$(ROOTVARLP)		:= DIRMODE=0775

FILEMODE =		0755

MSGFILES =              lpadmin ppdmgr
POFILE =                scripts.po

PROG =			conv_lp conv_lpd Makefile.yp
ROOTLIBPRINTPROG=	$(PROG:%=$(ROOTPRINTLIB)/%)
$(ROOTLIBPRINTPROG)	:= FILEMODE=0555
$(ROOTPRINTLIB)/Makefile.yp		:= FILEMODE=0444

USRSBINPROG=		lpsystem ppdmgr
ROOTUSRSBINPROG=	$(USRSBINPROG:%=$(ROOTUSRSBIN)/%)
$(ROOTUSRSBINPROG)		:= FILEMODE=555

PCONF=			printers.conf
ROOTPCONF=		$(PCONF:%=$(ROOTETC)/%)
$(ROOTPCONF)		:= FILEMODE=644

MANUFALIASES=		manufaliases
ROOTMANUFALIASES=	$(MANUFALIASES:%=$(ROOTVARLPPPD)/%)
$(ROOTMANUFALIASES)	:= FILEMODE=444

LIBLPPROGS=		lpadmin \
			desktop-print-management \
			desktop-print-management-applet \
			desktop-print-management-prefs

ROOTLIBLPPROGS=		$(LIBLPPROGS:%=$(ROOTLIBLPBIN)/%)
$(ROOTLIBLPPROGS)		:= FILEMODE=555

LIBLINKS=		$(ROOTLIB)/lpadmin $(ROOTLIB)/lpsystem

APPFILES =	desktop-print-management.desktop
APPFILES +=	desktop-print-management-prefs.desktop
AUTOFILES =	desktop-print-management-applet.desktop

ROOTAPPDIR =		$(ROOT)/usr/share/applications
ROOTAUTODIR =		$(ROOT)/usr/share/gnome/autostart
ROOTAPPFILES =		$(APPFILES:%=$(ROOTAPPDIR)/%)
ROOTAUTOFILES =		$(AUTOFILES:%=$(ROOTAUTODIR)/%)

$(ROOTAPPFILES)		:= FILEMODE = 444
$(ROOTAUTOFILES)	:= FILEMODE = 444


.KEEP_STATE:

all :			$(PROG)

$(ROOTLIB)/print/%:	%
	$(INS.file)

$(ROOTLIBLPBIN)/%: %
	$(INS.file)

$(ROOTVARLPPPD)/%: %
	$(INS.file)

$(ROOTAPPDIR)/%:	%
	$(INS.file)

$(ROOTAUTODIR)/%:	%
	$(INS.file)

$(ROOTUSRSBIN) $(ROOTVARSPOOLPRINT) $(ROOTVARLP) $(ROOTVARLPPPD):
	$(INS.dir)

$(ROOTLIB)/lpadmin:
	$(RM) $@; $(SYMLINK) ../sbin/lpadmin $@

$(ROOTLIB)/lpsystem:
	$(RM) $@; $(SYMLINK) ../sbin/lpsystem $@

$(ROOTLNKPROGS) :	$(ROOTSTARTPROG)
			$(RM) $@; $(LN) $(ROOTSTARTPROG) $@

_msg:   $(POFILE)

$(POFILE): $(MSGFILES)
	grep gettext $(MSGFILES) | tr '`' ' ' | sed -e "s/gettext \"/gettext \(\"/" | sed -e "s/$$/);/"  > $(POFILE).i
	$(XGETTEXT) -s $(POFILE).i
	$(RM) $@ $(POFILE).i
	mv messages.po $(POFILE)

#
# Create a message file to test with
#
_msg_test:
	grep gettext $(MSGFILES) | tr '`' ' ' | sed -e "s/gettext \"/gettext \(\"/" | sed -e "s/$$/);/"  > $(POFILE).i
	$(XGETTEXT) -s -m "xxx" $(POFILE).i
	$(RM) $@ $(POFILE).i
	mv messages.po $(POFILE)

install:		$(ROOTLNKPROGS) \
			$(ROOTLIBPRINTPROG) $(ROOTSTARTPROG) \
			$(ROOTUSRSBIN) $(ROOTUSRSBINPROG) \
			$(ROOTVARSPOOLPRINT) $(ROOTPCONF) \
			$(ROOTLIBLPPROGS) $(LIBLINKS) \
			$(ROOTVARLP) $(ROOTVARLPPPD) \
			$(ROOTMANUFALIASES) \
			$(ROOTAPPFILES) $(ROOTAUTOFILES)

$(SYMLINKS1):
	$(RM) $@; $(SYMLINK) ../sbin/$(SBINPROG1) $@

$(SYMLINKS2):
	$(RM) $@; $(SYMLINK) ../sbin/$(SBINPROG2) $@

clean:
	$(RM) $(POFILE)

clobber: clean

strip lint:
