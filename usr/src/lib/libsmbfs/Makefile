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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libsmbfs/Makefile
#

include $(SRC)/lib/Makefile.lib

# ISA targets
SUBDIRS = $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

# conditional assignments
all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint

POFILE =	libsmbfs.po

.KEEP_STATE:

all install clean clobber lint:  $(SUBDIRS)

include $(SRC)/Makefile.msg.targ

MSGFILES=smb/cfopt.c smb/charsets.c smb/charsets.h smb/ctx.c smb/derparse.c \
	smb/derparse.h smb/file.c smb/keychain.c smb/mbuf.c smb/nb.c \
	smb/nb_name.c smb/nb_net.c smb/nbns_rq.c smb/netshareenum.c \
	smb/nls.c smb/print.c smb/queue.h smb/rap.c smb/rcfile.c \
	smb/rcfile_priv.h smb/rq.c smb/spnego.c smb/spnego.h \
	smb/spnegoparse.c smb/spnegoparse.h smb/subr.c smb/ui-sun.c

_msg:  $(MSGDOMAINPOFILE)

$(MSGDOMAINPOFILE): $(POFILE)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

install:	$(ROOTLIBS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/lib/Makefile.targ
