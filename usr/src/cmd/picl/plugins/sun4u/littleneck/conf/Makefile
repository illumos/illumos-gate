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
# Copyright (c) 1999-2000 by Sun Microsystems, Inc.
# All rights reserved.
#

OBJECTS=

# include library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

include $(SRC)/cmd/picl/plugins/Makefile.com

UTSBASE= $(SRC)/uts

PLATFORM=SUNW,Sun-Fire-280R
install	:= FILEMODE = 0444

CONF=		platsvcd.conf psvcobj.conf
ROOTCONF=	$(CONF:%=$(USR_PSM_LIB_DIR)/%)

SRCS=

LIBS =		$(DYNLIB)

ZDEFS	=

.KEEP_STATE:

SUBDIRS=

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber

all:

install:	$(ROOTCONF)

$(USR_PSM_LIB_DIR):
	@cd $(UTSBASE)/sun4u/littleneck; pwd; $(MAKE) $(USR_PSM_LIB_DIR)

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

$(USR_PSM_LIB_DIR)/%: % $(USR_PSM_LIB_DIR)
	$(INS.file)

lint :

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
