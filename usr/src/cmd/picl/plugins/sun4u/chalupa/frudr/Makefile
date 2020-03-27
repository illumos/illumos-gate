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
# Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
#
# cmd/picl/plugins/sun4u/chalupa/frudr/Makefile
#
include	$(SRC)/Makefile.psm

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Sun-Fire-V440

include	$(SRC)/cmd/picl/plugins/Makefile.com

ROOTLIBDIR	= $(ROOT_PLAT_PLUGINDIR)

CONFS		= fru_PS0.conf fru_PS1.conf
CONFS		+= fru_PSU0.conf fru_PSU1.conf fru_PSU2.conf fru_PSU3.conf
CONFS		+= fru_HDD0.conf fru_HDD1.conf fru_HDD2.conf
CONFS		+= fru_HDD3.conf
CONFS		+= fru_FT0.conf fru_FT1.conf fru_FT2.conf fru_FT3.conf
CONFS		+= fru_SC.conf
ROOTCONF=	$(CONFS:%=$(ROOTLIBDIR)/%)
$(ROOTCONF)	:= FILEMODE = 0644
MAININFO=	$(CONFS:%.conf=%.info)
OTHERINFOS	= fru_PS0_data.info fru_PS1_data.info
OTHERINFOS	+= fru_PSU0_data.info fru_PSU1_data.info fru_PSU2_data.info fru_PSU3_data.info
OTHERINFOS	+= fru_HDD0_data.info fru_HDD1_data.info
OTHERINFOS	+= fru_HDD2_data.info fru_HDD3_data.info
OTHERINFOS	+= fru_SC_data.info SB-tables.info

.KEEP_STATE:

SUBDIRS =

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber

all: $(LIBS) $(LIBLINKS) $(CONFS)

install:	$(ROOTLIBDIR) $(ROOTCONF)

$(CONFS): $(MAININFO) $(OTHERINFOS)
	@$(RM) -f $@
	@echo "# Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved." \
	> $@
	@echo "# This is a generated file. #ident lines identify sources" >> $@
	$(CPP) -P $(@:%.conf=%.info) | \
	$(SED) -e '/^[  ]*$$/d' >> $@
	@$(CHMOD) 644 $@

# include library targets
include $(SRC)/lib/Makefile.targ
include	$(SRC)/cmd/picl/plugins/Makefile.targ

lint:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
