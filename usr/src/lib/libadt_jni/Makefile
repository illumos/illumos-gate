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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include		../Makefile.lib

POFILE	=	libadt_jni.po
MSGFILES=	`$(GREP) -l gettext */*.[ch]`
GENSRCS	=	common/adt_jni_event.c common/mapfile-vers com/sun/audit/AuditEvent.java
LIBBSMDIR =	../libbsm
ADTXMLFILE =	$(LIBBSMDIR)/common/adt.xml
AUDITXML =	./auditxml_jni

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all	:=	TARGET= all
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
install :=	TARGET= install

.KEEP_STATE:

CLEANFILES += $(GENSRCS)

all install: $(GENSRCS) com/sun .WAIT $(SUBDIRS)

com/sun $(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(GENSRCS):  $(AUDITXML) $(ADTXMLFILE)
	$(PERL) -I $(LIBBSMDIR) $(AUDITXML) $(ADTXMLFILE)

clean clobber: com/sun $(SUBDIRS)
	-$(RM) $(CLEANFILES)

$(POFILE): pofile_MSGFILES

_msg: $(MSGDOMAINPOFILE)

include $(SRC)/Makefile.msg.targ

FRC:

