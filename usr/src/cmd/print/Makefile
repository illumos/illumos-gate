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
#
# cmd/print/Makefile
#

include ../Makefile.cmd

JAVA_SUBDIRS = printmgr

PRINT_SUBDIRS  =		\
		scripts		\
		lpget		\
		lpset		\
		conv_fix	\
		printer-info	\
		ppdmgr		\
		selector	\
		bsd-sysv-commands

SUBDIRS = $(PRINT_SUBDIRS) $(JAVA_SUBDIRS)

ROOTDIRS = 	$(ROOTLIB)/print 

all	:=	TARGET= all
install :=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint
strip	:=	TARGET= strip
_msg	:=      TARGET = _msg

# For testing message catalogs
_msg_test:=	TARGET = _msg_test

POFILE= print.po

.KEEP_STATE:

all install:	$(ROOTDIRS) $(SUBDIRS)

#
# We define our own definition for _msg here because most of these
# commands have the same PROG names as their counterparts in
# cmd/lp. Using the _msg rule defined in Makefile.cmd would 
# result in clobbering the cmd/lp message files.
# To get around this we will define one message file "print.po"
# for these commands (except java printmgr). To build
# this file we find all of the .c files and run xgettext on them.
# Then concatenate this with the scripts.po file.
#
_msg:   $(MSGDOMAIN) scripts $(JAVA_SUBDIRS)
	@$(RM)	$(POFILE)
	$(XGETTEXT) -s `/bin/find . -type d -name SCCS -prune -o -type f -name '*.c' -print`
	@/bin/cat messages.po scripts/scripts.po | sed '/domain/d' > $(POFILE)
	@$(RM) messages.po
	$(RM)  $(MSGDOMAIN)/$(POFILE)
	/bin/cp $(POFILE)    $(MSGDOMAIN)

#
# Create a message file to test with.
#
_msg_test: scripts
	@$(RM)  $(POFILE)
	$(XGETTEXT) -s -m "xxx" `/bin/find . -print | grep '\.c$$' | sed '/SCCS/d'`
	@/bin/cat messages.po scripts/scripts.po | sed '/domain/d' > $(POFILE)
	echo 'domain "SUNW_OST_OSCMD"' > SUNW_OST_OSCMD.po
	cat $(POFILE) >> SUNW_OST_OSCMD.po
	$(MSGFMT) SUNW_OST_OSCMD.po
	@$(RM) messages.po $(POFILE) SUNW_OST_OSCMD.po

clean strip cstyle lint:	$(SUBDIRS)

clobber: $(SUBDIRS)
	$(RM) $(POFILE) $(CLOBBERFILES)

$(ROOTDIRS) $(MSGDOMAIN):
	$(INS.dir)

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
