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

PROTOCOL_DIR= $(ROOTHDRDIR)/rpcsvc
PROTOCOL_SRCDIR= $(SRC)/head/rpcsvc
PROTOCOL_UTS_SRCDIR= $(SRC)/uts/common/rpc

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

# objects are listed by source directory

# common utility code used in more than one directory
RPC_DERIVED_FILES=

GEN_DERIVED_FILES= \
	nis/gen/nis_clnt.h


PROTOCOL_FILES= \
	$(PROTOCOL_DIR)/daemon_utils.h	\
	$(PROTOCOL_DIR)/nis.x		\
	$(PROTOCOL_DIR)/nis.h		\
	$(PROTOCOL_DIR)/nis_object.x

PROTOCOL_FILES_UTS= \
	$(PROTOCOL_DIR)/key_prot.x

DERIVED_FILES= $(GEN_DERIVED_FILES) $(RPC_DERIVED_FILES)

#
# Make sure they get cleaned when necessary
#
CLEANFILES += $(DERIVED_FILES)

# include library definitions
include ../Makefile.lib

# header file delivered to /usr/include; internal to ON build process
HDRS =		nss.h
HDRDIR =	nss

LIBRARY= libnsl.a
TEXT_DOMAIN= SUNW_OST_NETRPC
POFILE= $(LIBRARY:.a=.po)
POFILES= generic.po _errlst.po

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
delete :=	TARGET= delete
install :=	TARGET= install
lint :=		TARGET= lint
_msg :=		TARGET= _msg
package :=	TARGET= package


.KEEP_STATE:

all:		$(PROTOCOL_DIR) $(DERIVED_FILES) .WAIT $(SUBDIRS)

headers:	$(PROTOCOL_DIR) .WAIT $(PROTOCOL_FILES) $(PROTOCOL_FILES_UTS) \
		$(DERIVED_FILES)

install:	all .WAIT $(SUBDIRS)

install_h:	$(ROOTHDRS)

# nss.h isn't delivered; no reason to check
check:

clean clobber delete lint package:	$(SUBDIRS)

$(PROTOCOL_DIR):
	$(INS.dir)

$(PROTOCOL_DIR)/%.h:	$(PROTOCOL_SRCDIR)/%.h
	$(INS.file)

$(PROTOCOL_DIR)/nis.h:	$(PROTOCOL_SRCDIR)/nis.x $(PROTOCOL_SRCDIR)/nis_object.x
	$(RPCGEN) -C -h $(PROTOCOL_SRCDIR)/nis.x > nis-tmp.h
	$(SED) -e '/EDIT_START/,$$ d' < nis-tmp.h > nis.h
	$(RM) $@
	$(INS) -s -m $(FILEMODE) -f $(@D) nis.h
	$(RM) nis.h nis-tmp.h

$(PROTOCOL_DIR)/%.x:	$(PROTOCOL_SRCDIR)/%.x
	$(INS.file)

$(PROTOCOL_DIR)/%.x:	$(PROTOCOL_UTS_SRCDIR)/%.x
	$(INS.file)

#
# Rules for building the derived files
#
# Derived header files
#
nis/gen/nis_clnt.h: $(PROTOCOL_DIR)/nis.x $(PROTOCOL_DIR)/nis_object.x 
	$(RPCGEN) -C -h $(PROTOCOL_DIR)/nis.x > nis_clnt-gen.h
	$(SED) -n -e '/EDIT_START/,$$ p' < nis_clnt-gen.h |\
	$(SED) -e 's/_3_svc/_svc/' |\
	$(SED) -e 's/_3/_clnt/' > $@
	$(RM) nis_clnt-gen.h

#
# Derived source files
#

# include library targets
include ../Makefile.targ

_msg: $(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

_errlst.po:
	$(RM) messages.po
	$(XGETTEXT) -a nsl/_errlst.c
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

generic.po:
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext */*.[ch] nis/*/*.[ch]*`
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

$(MSGDOMAIN):
	$(INS.dir)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
