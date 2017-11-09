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
# Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../Makefile.lib

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

XGETFLAGS_ADT += -a

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
delete :=	TARGET= delete
install :=	TARGET= install
lint :=		TARGET= lint
package :=	TARGET= package

.KEEP_STATE:

COMMONDIR = common

#
# Macros for libbsm header files. These define user-level only interfaces.
#
GENHDRS = audit_uevents.h
HDRS = libbsm.h devices.h devalloc.h adt.h adt_event.h audit_private.h 
GENSRCS =	$(COMMONDIR)/adt_xlate.c $(COMMONDIR)/adt_event.h
COMMONHDRS =	$(HDRS:%=$(COMMONDIR)/%)
ROOTHDRDIR = 	$(ROOT)/usr/include/bsm
ROOTCHDRS = 	$(HDRS:%=$(ROOTHDRDIR)/%)
ROOTHDRS = 	$(GENHDRS:%=$(ROOTHDRDIR)/%)

CHECKCHDRS =	$(COMMONHDRS:%.h=%.check)
CHECKHDRS =	$(GENHDRS:%.h=%.check)

$(ROOTHDRS) := 	FILEMODE = 0644
$(ROOTCHDRS) :=	FILEMODE = 0644

all install lint package: $(GENSRCS) $(SUBDIRS)
clean clobber delete: $(SUBDIRS)

#
# Macros for libbsm database files. These should probably be installed
# from somewhere else. Until we find that better place, install them
# from here.
#

ROOTETCSECURITY = 	$(ROOT)/etc/security
$(ROOTETCSECURITY) := 	DIRMODE = 0755

ESFILES =		audit_class audit_event
ESSRC =			$(ESFILES:%=%.txt)
ETCSECURITYFILES =	$(ESFILES:%=$(ROOTETCSECURITY)/%)
$(ETCSECURITYFILES) :=	FILEMODE = 0644

#
# /etc/security/audit/localhost/files is a symbolic link to /var/audit.
# This is provided so that auditreduce will work in the default configuration.
#
RESA=$(ROOTETCSECURITY)/audit
RESAL=$(RESA)/localhost
VARAUDIT=$(ROOT)/var/audit
AUDITDIRS=$(RESA) $(RESAL) $(VARAUDIT)
$(AUDITDIRS) := FILEMODE = 0750

ARSYMLNK=$(RESAL)/files

#
# message catalogue file
#
MSGFILES =	`$(GREP) -l gettext $(COMMONDIR)/*.c`
POFILE =	libbsm.po

#
# Definitions for XML (DTD AND XSL)
#
DTD =		adt_record.dtd.1
XSL =		adt_record.xsl.1
ROOTXMLDIR =	$(ROOT)/usr/share/lib/xml
ROOTDTDDIR=	$(ROOTXMLDIR)/dtd
ROOTXSLDIR=	$(ROOTXMLDIR)/style
ROOTDTD=	$(DTD:%=$(ROOTDTDDIR)/%)
ROOTXSL=	$(XSL:%=$(ROOTXSLDIR)/%)
ROOTXMLDIRS =	$(ROOTXMLDIR) $(ROOTDTDDIR) $(ROOTXSLDIR)
ROOTXMLFILES =	$(ROOTDTD) $(ROOTXSL)

$(ROOTXMLDIRS) :=  FILEMODE = 755

$(ROOTXMLFILES) :=  FILEMODE = 444


CPPFLAGS += -I$(COMMONDIR)
CPPFLAGS += -D_REENTRANT

CLEANFILES += $(GENSRCS) $(GENHDRS)

ADTXMLFILE =	$(COMMONDIR)/adt.xml
ADTXSDFILE =	$(COMMONDIR)/adt.xsd
AUDITXML =	auditxml

.KEEP_STATE:

install: install_dirs install_data

#		$(ROOTUSRLIB) $(ROOTLIBS) $(ROOTLINKS)

install_h: $(ROOTHDRDIR) $(ROOTHDRS) $(ROOTCHDRS)

check:	$(CHECKHDRS) $(CHECKCHDRS)
	xmllint --schema $(ADTXSDFILE) --noout $(ADTXMLFILE)

install_data: $(ESSRC) $(RESSRC) $(ROOTETCSECURITY) $(ETCSECURITYFILES) \
	$(ROOTXMLFILES)

install_dirs: $(AUDITDIRS) $(ARSYMLNK) $(ROOTXMLDIRS)

audit_uevents.h: mkhdr.sh audit_event.txt
	sh mkhdr.sh

$(COMMONDIR)/adt_event.check:	$(COMMONDIR)/adt_event.h
	$(DOT_C_CHECK) $<

clean clobber: clean_files

clean_files:
	-$(RM) $(CLEANFILES)

$(GENSRCS): $(ADTXMLFILE) $(AUDITXML)
	$(PERL) -I. $(AUDITXML) -o $(COMMONDIR) $(ADTXMLFILE)

$(ETCSECURITYFILES) $(RESA): \
	$(ETCSECURITY) \
	$(ROOTETCSECURITY)

$(RESAL): $(RESA)

$(ARSYMLNK): $(RESAL)

$(ROOTHDRDIR):
	$(INS.dir)

$(ROOTHDRDIR)/%:%
	$(INS.file)

$(ROOTHDRDIR)/%:$(COMMONDIR)/%
	$(INS.file)

$(ROOTXMLDIRS):
	$(INS.dir)

$(ROOTDTDDIR)/% $(ROOTXSLDIR)/%: %
	$(INS.file)

$(AUDITDIRS):
	$(INS.dir)

$(ARSYMLNK): 
	$(RM) $@
	$(SYMLINK) ../../../../var/audit $@

$(ETCSECURITY)/%: %.txt
	$(INS.rename)

$(ROOTETCSECURITY):
	$(INS.dir)

$(ROOTETCSECURITY)/%: %.txt
	$(INS.rename)

$(POFILE):	 pofile_MSGFILES

_msg:	$(MSGDOMAINPOFILE)

# has strings but doesn't use gettext
adt_xlate.po: $(COMMONDIR)/adt_xlate.c
	$(RM) adt_xlate.po
	$(XGETTEXT) $(XGETFLAGS_ADT) $(COMMONDIR)/adt_xlate.c
	$(SED) "/^domain/d" < messages.po > adt_xlate.po
	$(RM) messages.po

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
include ../../Makefile.msg.targ
