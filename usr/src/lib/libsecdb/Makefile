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
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../Makefile.lib

SUBDIRS =	help $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

MSGSUBDIRS=	help

all:=		TARGET= all
clean:=		TARGET= clean
clobber:=	TARGET= clobber
install:=	TARGET= install
_msg:=		TARGET= _msg

.KEEP_STATE:

ROOTETC =		$(ROOT)/etc
ROOTETCSECURITY =	$(ROOTETC)/security

EFILES =	user_attr
EFILESRC =	$(EFILES:%=%)
ETCFILES =	$(EFILES:%=$(ROOTETC)/%)
ETCDFILES =	$(EFILES:%=$(ROOTETC)/%.d/SUNWcs)

ESDFILES =	auth_attr exec_attr prof_attr
ESFILES =		$(ESDFILES) policy.conf
ESSRC =			$(ESFILES:%=%)
ETCSECURITYFILES =	$(ESFILES:%=$(ROOTETCSECURITY)/%)
ETCSECURITYDFILES =	$(ESDFILES:%=$(ROOTETCSECURITY)/%.d/SUNWcs)


MFSTFILES =	rbac.xml
MANIFESTDIR =	$(ROOT)/lib/svc/manifest/system
MANIFEST =	$(MFSTFILES:%=$(MANIFESTDIR)/%)
$(MANIFEST) :=	FILEMODE = 0444

METHODFILES =	svc-rbac
METHODDIR =	$(ROOT)/lib/svc/method
METHOD =	$(METHODFILES:%=$(METHODDIR)/%)
$(METHOD) :=	FILEMODE = 0555

SCRIPTS =		i.rbac r.rbac
CLASS_SCR_SRC_DIR =	common
INSTALL_DIR =		$(ROOT)/usr/sadm/install

CLASS_SCR_DIR =		$(INSTALL_DIR)/scripts

CLASS_SCR_FILES =	$(SCRIPTS:%=$(CLASS_SCR_DIR)/%)
$(CLASS_SCR_FILES) :=	FILEMODE = 0555

all clean clobber delete install package: $(SUBDIRS)
_msg: $(MSGSUBDIRS)

install:	install_data

install_data:	$(ETCSECURITYFILES) $(ETCSECURITYDFILES) $(ETCFILES) \
		$(ETCDFILES) $(CLASS_SCR_FILES) $(MANIFESTDIR) $(MANIFEST) \
		$(METHODDIR) $(METHOD)

ATTR_FILES =	auth_attr exec_attr prof_attr user_attr
${ATTR_FILES}:	$$@.txt ${CLASS_SCR_SRC_DIR}/i.rbac
	> $@
	$(ECHO) $@.txt $@ | $(SHELL) ${CLASS_SCR_SRC_DIR}/i.rbac

$(ETCSECURITYDFILES) $(ETCDFILES): $$(@D)

$(ETCSECURITYFILES) $(ETCFILES): $(ETCSECURITY) $(ROOTETCSECURITY)

$(ETCSECURITY)/%: %
	$(INS.file)

$(ROOTETCSECURITY):
	$(INS.dir)

$(ROOTETCSECURITY)/%: %
	$(INS.file)

$(ROOTETCSECURITY)/%.d/SUNWcs: %
	$(INS.rename)

$(ROOTETC)/% : %
	$(INS.file)

$(ROOTETC)/%.d/SUNWcs: %
	$(INS.rename)

$(MANIFESTDIR):
	$(INS.dir)

$(MANIFESTDIR)/% : %
	$(INS.file)

$(METHODDIR):
	$(INS.dir)

$(METHODDIR)/% : %
	$(INS.file)

$(CLASS_SCR_FILES): $(INSTALL_DIR) $(CLASS_SCR_DIR)

$(INSTALL_DIR):
	$(INS.dir)

$(CLASS_SCR_DIR):
	$(INS.dir)

$(CLASS_SCR_DIR)/%: $(CLASS_SCR_SRC_DIR)/%
	$(INS.file)

clobber clean:
	$(RM) $(ATTR_FILES)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
