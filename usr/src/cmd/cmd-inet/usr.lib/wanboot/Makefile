#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include $(SRC)/cmd/Makefile.cmd

SUBDIR_SCR=	bootlog-cgi
SUBDIR_PGMS=	wanboot-cgi\
		keygen \
		keymgmt \
		hmac \
		encr \
		ickey \
		p12split \
		netbootinfo

SUBDIRS=	$(SUBDIR_SCR) $(SUBDIR_PGMS)

MSGFILES=	encr/encr.c hmac/hmac.c ickey/ickey.c keygen/keygen.c \
		keymgmt/keymgmt.c p12split/p12split.c netbootinfo/netbootinfo.c

POFILE=         wanboot.po
XGETFLAGS +=	-a -x wanboot.xcl

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint
_msg:=          TARGET= _msg

.KEEP_STATE:
.PARALLEL:	$(SUBDIRS)

all install:	$(SUBDIRS)

lint:		$(SUBDIR_PGMS)

clean:		$(SUBDIR_PGMS)

clobber:	$(SUBDIR_PGMS) local_clobber

local_clobber:
		$(RM) $(CLOBBERFILES)

$(POFILE):	pofile_MSGFILES

_msg:		$(MSGDOMAINPOFILE)

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ
