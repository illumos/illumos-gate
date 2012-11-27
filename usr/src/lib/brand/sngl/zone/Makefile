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
# Copyright 2012 Joyent, Inc.  All rights reserved.
#

PROGS =		sinstall
XMLDOCS=	config.xml platform.xml
CLOBBERFILES=	$(ROOTPROGS) $(ROOTXMLDOCS)

include $(SRC)/cmd/Makefile.cmd
include ../Makefile.sngl

.KEEP_STATE:

all:	$(PROGS)

POFILES =
POFILE =

install: $(PROGS) $(ROOTPROGS) $(ROOTXMLDOCS)
	crle -c $(ROOTBRANDDIR)/ld.sys.config \
		-l /lib:/system/usr/lib \
		-s /lib/secure:/system/usr/lib/secure
	crle -64 -c $(ROOTBRANDDIR)/ld.sys64.config \
		-l /lib/64:/system/usr/lib/64 \
		-s /lib/secure/64:/system/usr/lib/secure/64

lint:

clean:
	-$(RM) $(PROGS)

include $(SRC)/cmd/Makefile.targ
