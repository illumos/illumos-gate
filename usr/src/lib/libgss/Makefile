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

include ../Makefile.lib

LIBRARY=	libgss.a

# defines the duplicate sources we share with gsscred
GSSCRED_DIR = $(SRC)/cmd/gss/gsscred
DUPLICATE_SRC = gsscred_utils.c gsscred_file.c # gen_oids.c
CLEAN_SRC = $(DUPLICATE_SRC) gen_oids.c

SUBDIRS	= $(MACH)
$(BUILD64)SUBDIRS +=	$(MACH64)

ROOTDIRS= $(ROOT)/usr/include
GSSMECH_DIR=	$(ROOT)/usr/lib/gss

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=         TARGET= lint

POFILE =	$(LIBRARY:.a=.po)
XGETFLAGS+=	-a
MSGFILES =	`$(GREP) -l gettext *.[ch]`

.KEEP_STATE:

all clean clobber lint:  $(SUBDIRS)

install: $(GSSMECH_DIR) all .WAIT $(SUBDIRS)

check install_h:

_msg:	$(MSGDOMAINPOFILE)

$(POFILE):	pofile_MSGFILES

$(GSSMECH_DIR):
	$(INS.dir)

$(SUBDIRS):   FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

# include library targets
include ../Makefile.targ

include $(SRC)/Makefile.msg.targ
