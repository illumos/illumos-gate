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
#
# cmd/picl/plugins/sun4u/seattle/envmon/Makefile
#

include	$(SRC)/Makefile.psm

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Sun-Fire-V215

include	$(SRC)/cmd/picl/plugins/Makefile.com

ROOTLIBDIR	= $(ROOT_PLAT_PLUGINDIR)

CONFS		= piclenvmon.conf
ROOTCONF=       $(CONFS:%=$(ROOTLIBDIR)/%)
$(ROOTCONF)	:= FILEMODE = 0644
MAININFO=       $(CONFS:%.conf=%.info)

.KEEP_STATE:

SUBDIRS=

all	:=	TARGET= all
install :=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber

all:	$(CONFS)

install:	$(ROOTLIBDIR) $(ROOTCONF)

$(CONFS): $(MAININFO)
	@$(RM) -f $@
	@echo "# Copyright 2005 Sun Microsystems, Inc.  All rights reserved." \
	> $@
	@echo "# Use is subject to license terms." >> $@
	@echo "# This is a generated file. #ident lines identify sources" >> $@
	$(CPP) -P $(@:%.conf=%.info) | \
	$(SED) -e '/^[ 	]*$$/d' >> $@
	@$(CHMOD) 444 $@

# include library targets
include $(SRC)/lib/Makefile.targ
include	$(SRC)/cmd/picl/plugins/Makefile.targ

lint:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
