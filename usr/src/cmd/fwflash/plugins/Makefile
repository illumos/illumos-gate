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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/fwflash/plugins
#

include $(SRC)/cmd/Makefile.cmd

COMMON_SUBDIRS=	transport
CLOSED_SUBDIRS= $(CLOSED)/cmd/fwflash/plugins 

SUBDIRS=	$(COMMON_SUBDIRS) $(CLOSED_SUBDIRS)

MSGSUBDIRS=	$(COMMON_SUBDIRS) $(CLOSED_SUBDIRS)

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg :=		TARGET= _msg
msg :=		TARGET= msg

include $(SRC)/cmd/fwflash/Makefile.com


.KEEP_STATE:

all:		$(SUBDIRS)
lint:		$(SUBDIRS)
install:	$(SUBDIRS)
clean:		$(SUBDIRS)
clobber:	$(SUBDIRS)


msg _msg:	$(MSGSUBDIRS)


$(SUBDIRS): FRC
	@if [ -f $@/Makefile ]; then \
		cd $@; pwd; $(MAKE) $(TARGET); \
	else \
		true; \
	fi

FRC:
