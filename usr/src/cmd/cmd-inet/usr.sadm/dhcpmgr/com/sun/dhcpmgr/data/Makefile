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
# Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/cmd-inet/usr.sadm/dhcpmgr/com/sun/dhcpmgr/data/Makefile
#

CONFIG_INTERFACE = DhcpConfigOpts.java

CLASSFILES =	Macro.class \
		OptionValueFactory.class \
		AsciiOptionValue.class \
		BogusOptionValue.class \
		BooleanOptionValue.class \
		IncludeOptionValue.class \
		IPOptionValue.class \
		NumberOptionValue.class \
		OctetOptionValue.class \
		OptionsTable.class \
		StandardOptions.class \
		Option.class \
		DhcptabRecord.class \
		DhcpClientRecord.class \
		DhcpClientFlagTypes.class \
		IPInterface.class \
		ExportHeader.class \
		Network.class \
		IPAddress.class \
		DhcpdOptions.class \
		DhcpDatastore.class \
		DhcpResource.class \
		OptionContext.class \
		OptionType.class \
		ActionError.class \
		DhcpClientFlagType.class \
		DhcpConfigOpts.class \
		ResourceStrings.class \
		ValidationException.class

SUBDIRS =	qualifier

all     :=	TARGET= all
install :=	TARGET= install
clean   :=	TARGET= clean
clobber :=	TARGET= clobber
lint    :=	TARGET= lint
_msg    :=	TARGET= _msg

include		$(SRC)/Makefile.master

CLASSPATH=	$(SRC)/cmd/cmd-inet/usr.sadm/dhcpmgr

JAVAFILES =	$(CLASSFILES:.class=.java)

MSGDIR=		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr/data
MSGDIRS =       $(ROOT)/usr/share/lib/locale \
                $(ROOT)/usr/share/lib/locale/com \
                $(ROOT)/usr/share/lib/locale/com/sun \
		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr \
		$(MSGDIR)

MSGFILES=	ResourceBundle.properties
MSGS=		$(MSGFILES:%=$(MSGDIR)/%)

CLEANFILES=	*.class $(CONFIG_INTERFACE)
CLOBBERFILES=

.KEEP_STATE:

all: $(SUBDIRS) $(CONFIG_INTERFACE) $(CLASSFILES)

install: $(SUBDIRS) all

$(CONFIG_INTERFACE): $(SRC)/lib/libdhcpsvc/head/dhcp_svc_confkey.m4
	$(M4) -Djava $? > $@

_msg: $(SUBDIRS) $(MSGDIRS) $(MSGS)

$(MSGDIR)/%: %
	$(INS.file)

$(MSGDIRS):
	$(INS.dir)

lint:

clean: $(SUBDIRS) FRC
	$(RM) $(CLEANFILES)

clobber: clean

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
