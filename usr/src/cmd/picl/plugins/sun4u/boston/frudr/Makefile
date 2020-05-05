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
# cmd/picl/plugins/sun4u/boston/frudr/Makefile
#
include	$(SRC)/Makefile.psm

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Sun-Fire-V445
FRUDR_LINKTO_PLATFORM = SUNW,Sun-Fire-V240

include	$(SRC)/cmd/picl/plugins/Makefile.com

ROOTLIBDIR	= $(ROOT_PLAT_PLUGINDIR)

CONFS		= fru_PS0.conf fru_PS1.conf fru_PS2.conf fru_PS3.conf
CONFS		+= fru_HDD0.conf fru_HDD1.conf fru_HDD2.conf
CONFS		+= fru_HDD3.conf fru_HDD4.conf fru_HDD5.conf
CONFS		+= fru_HDD6.conf fru_HDD7.conf
CONFS		+= fru_SC.conf
CONFS		+= fru_usb-a-1.conf fru_usb-a-2.conf
CONFS		+= fru_usb-a-3.conf fru_usb-a-4.conf
CONFS		+= fru_FT0.conf fru_FT1.conf fru_FT2.conf
CONFS		+= fru_FT3.conf fru_FT4.conf fru_FT5.conf
ROOTCONF=	$(CONFS:%=$(ROOTLIBDIR)/%)
$(ROOTCONF)	:= FILEMODE = 0644
MAININFO=	$(CONFS:%.conf=%.info)
OTHERINFOS	= fru_PS0_data.info fru_PS1_data.info fru_PS2_data.info fru_PS3_data.info
OTHERINFOS	+= fru_HDD0_data.info fru_HDD1_data.info
OTHERINFOS	+= fru_HDD2_data.info fru_HDD3_data.info
OTHERINFOS	+= fru_HDD3_data.info fru_HDD4_data.info
OTHERINFOS	+= fru_HDD6_data.info fru_HDD7_data.info
OTHERINFOS	+= fru_SC_data.info SB-tables.info
OTHERINFOS	+= fru_usb-a-1_data.info fru_usb-a-2_data.info
OTHERINFOS	+= fru_usb-a-3_data.info fru_usb-a-4_data.info
OTHERINFOS	+= fru_FT0_data.info fru_FT1_data.info fru_FT2_data.info
OTHERINFOS	+= fru_FT3_data.info fru_FT4_data.info fru_FT5_data.info

.KEEP_STATE:

SUBDIRS =

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber

all: $(LIBS) $(LIBLINKS) $(CONFS)

install:	$(ROOTLIBDIR) $(ROOTCONF) $(FRUDR_LINK)
	$(MAKE) $(FRUDR_LINK)

$(CONFS): $(MAININFO) $(OTHERINFOS)
	@$(RM) -f $@
	@echo "# Copyright 2006 Sun Microsystems, Inc.  All rights reserved." \
	> $@
	@echo "# Use is subject to license terms." >> $@
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

FRUDR_LINK=`cd $(ROOT_PLATFORM)/lib/picl/plugins/; \
rm -f libpiclfrudr.so.1; \
rm -f libpiclfrudr.so; \
ln -s ../../../../$(FRUDR_LINKTO_PLATFORM)/lib/picl/plugins/libpiclfrudr.so.1   libpiclfrudr.so.1; \
ln -s ../../../../$(FRUDR_LINKTO_PLATFORM)/lib/picl/plugins/libpiclfrudr.so     libpiclfrudr.so;`
