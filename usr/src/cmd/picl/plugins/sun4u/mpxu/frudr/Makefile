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

include	$(SRC)/Makefile.psm

LIBRARY =	libpiclfrudr.a
VERS =		.1

OBJECTS =	piclfrudr.o

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Sun-Fire-V240

include	$(SRC)/cmd/picl/plugins/Makefile.com

SRCS =		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOTLIBDIR	= $(ROOT_PLAT_PLUGINDIR)

PLAT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Sun-Fire-V440

PLAT_LIB_DIR = $(PLAT_PLATFORM:%=%/lib)

PLAT_PICL_DIR = $(PLAT_LIB_DIR:%=%/picl)

PLAT_PLUGINS_DIRS = $(PLAT_PICL_DIR:%=%/plugins)

USR_PLAT_PLUGINS_DYNLIBS = $(PLAT_PLUGINS_DIRS:%=%/$(DYNLIB))
USR_PLAT_PLUGINS_LIBLINKS = $(PLAT_PLUGINS_DIRS:%=%/$(LIBLINKS))
MPXU_DYNLIB_DIR = ../../../../SUNW,Sun-Fire-V240/lib/picl/plugins

CONFS		= fru_PS0.conf fru_PS1.conf
CONFS		+= fru_HDD0.conf fru_HDD1.conf fru_HDD2.conf
CONFS		+= fru_HDD3.conf
CONFS		+= fru_SC.conf
CONFS		+= fru_usb-a-1.conf fru_usb-a-2.conf
ROOTCONF=	$(CONFS:%=$(ROOTLIBDIR)/%)
$(ROOTCONF)	:= FILEMODE = 0644
MAININFO=	$(CONFS:%.conf=%.info)
OTHERINFOS	= fru_PS0_data.info fru_PS1_data.info
OTHERINFOS	+= fru_HDD0_data.info fru_HDD1_data.info
OTHERINFOS	+= fru_HDD2_data.info fru_HDD3_data.info
OTHERINFOS	+= fru_SC_data.info SB-tables.info
OTHERINFOS	+= fru_usb-a-1_data.info fru_usb-a-2_data.info

CPPFLAGS +=	-D_REENTRANT
CPPFLAGS +=	-I$(SRC)/cmd/picl/plugins/lib/picld_pluginutil
CPPFLAGS +=	-I$(SRC)/uts/sun4u/mpxu
CPPFLAGS +=	-I$(SRC)/uts/sun4u/ -I$(SRC)/uts/common/
CPPFLAGS +=	-I$(SRC)/uts/sun4u/sys/i2c/clients

CFLAGS +=	$(CCVERBOSE)

DYNFLAGS +=	-R/usr/platform/\$$PLATFORM/lib/picl/plugins
DYNFLAGS +=	-R/usr/platform/sun4u/lib/picl/plugins:/usr/lib/picl/plugins
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/lib/picld_pluginutil/$(MACH)
LDLIBS +=	-L$(DEVTREE_SRC_DIR)
LDLIBS +=	-L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/memcfg
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/devtree
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/piclevent
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/sun4u/envmon
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/frutree
LDLIBS +=	-L$(ROOT)/usr/lib/picl/plugins
LDLIBS +=	-lc -ldevinfo -ldevice
LDLIBS +=	-lpicltree -lpicld_pluginutil -lnvpair -lkstat
LDLIBS +=	-lpiclevent -lpiclenvmon -lpiclfrutree

.KEEP_STATE:

SUBDIRS =

POFILE = piclfrudr.po

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

all: $(LIBS) $(LIBLINKS) $(CONFS)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS) $(ROOTCONF) \
		$(PLAT_PLATFORM) $(PLAT_LIB_DIR) $(PLAT_PICL_DIR) \
		$(USR_PLAT_PLUGINS_DYNLIBS) $(USR_PLAT_PLUGINS_LIBLINKS)

$(CONFS): $(MAININFO) $(OTHERINFOS)
	@$(RM) -f $@
	@echo "# Copyright 2003 Sun Microsystems, Inc. " \
	"All rights reserved." > $@
	@echo "# This is a generated file. #ident lines identify sources" >> $@
	$(CPP) -P $(@:%.conf=%.info) | \
	$(SED) -e '/^[  ]*$$/d' >> $@
	@$(CHMOD) 644 $@

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/mpxu_$(POFILE)

$(MSGDOMAIN):
	$(INS.dir)

$(LIBLINKS):	FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

# include library targets
include $(SRC)/lib/Makefile.targ
include	$(SRC)/cmd/picl/plugins/Makefile.targ

$(ROOT_PLAT_PLUGINDIR)/%: % $(ROOT_PLAT_PLUGINDIR)
	$(INS.file) ;\
	$(RM) -r $(ROOT_PLAT_PLUGINDIR)/$(LIBLINKS) ;\
	$(SYMLINK) ./$(DYNLIB) $(ROOT_PLAT_PLUGINDIR)/$(LIBLINKS)

$(PLAT_PLATFORM):
	$(INS.dir)
$(PLAT_LIB_DIR):
	$(INS.dir)
$(PLAT_PICL_DIR):
	$(INS.dir)

$(PLAT_PLUGINS_DIRS):
	$(INS.dir)

$(USR_PLAT_PLUGINS_DYNLIBS): $(PLAT_PLUGINS_DIRS)
	$(RM) -r $@ ;\
	$(SYMLINK) $(MPXU_DYNLIB_DIR)/$(DYNLIB) $@

$(USR_PLAT_PLUGINS_LIBLINKS): $(PLAT_PLUGINS_DIRS)
	$(RM) -r $@ ;\
	$(SYMLINK) $(MPXU_DYNLIB_DIR)/$(DYNLIB) $@

lint:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
