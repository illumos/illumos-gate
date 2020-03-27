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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include		$(SRC)/lib/Makefile.lib

HDRS =		libnwam.h libnwam_priv.h
SRCS =		libnwam_audit.c libnwam_backend.c libnwam_enm.c \
		libnwam_events.c libnwam_error.c libnwam_files.c \
		libnwam_known_wlan.c libnwam_loc.c libnwam_ncp.c \
		libnwam_object.c libnwam_util.c libnwam_values.c \
		libnwam_wlan.c
HDRDIR =	common
SUBDIRS=	$(MACH)
POFILE =	libnwam.po
MSGFILES =	common/*.c

XGETFLAGS =     -a -x libnwam.xcl

all :=		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install :=	TARGET = install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

install_h:	$(ROOTHDRS)

check:		$(CHECKHDRS)

$(POFILE):      pofile_MSGFILES

_msg:           $(MSGDOMAINPOFILE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/Makefile.msg.targ
include $(SRC)/lib/Makefile.targ
