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
# cmd/cmd-inet/usr.sadm/dhcpmgr/com/sun/dhcpmgr/client/Makefile
#

# Place high-level classes first in order to minimize build time.
CLASSFILES =	DhcpmgrApplet.class \
                AddressView.class \
                OptionView.class \
                MacroView.class \
                RelayView.class \
                CreateMacroDialog.class \
                DeleteMacroDialog.class \
                CreateOptionDialog.class \
                DeleteOptionDialog.class \
                CreateAddressDialog.class \
                DeleteAddressDialog.class \
                AddressWizard.class \
                ModifyAddressesDialog.class \
                ReleaseAddressDialog.class \
                DisableServiceDialog.class \
                ConfigureRelayDialog.class \
                ConfigureChoiceDialog.class \
                ConfigWizard.class \
                ServerOptionsDialog.class \
                DeleteNetworksDialog.class \
                UnconfigureDialog.class \
		ExportWizard.class \
		ImportWizard.class \
		ConvertWizard.class \
		DSWizard.class \
		SUNWModule.class \
		DSModule.class \
		DSModuleListener.class \
		DSModuleEvent.class \
		MacroNameField.class \
		OptionNameField.class \
		DhcptabNameField.class \
		SelectOptionDialog.class \
		DataManager.class \
		MultipleOperationDialog.class \
		DhcpmgrDialog.class \
		ViewMacroDialog.class \
		ErrorTable.class \
		ResourceStrings.class

SUBDIRS =	SUNWbinfiles SUNWfiles

all     :=	TARGET= all
install :=	TARGET= install
clean   :=	TARGET= clean
clobber :=	TARGET= clobber
lint    :=	TARGET= lint
_msg    :=	TARGET= _msg

include		$(SRC)/Makefile.master

CLASSPATH=	$(SRC)/cmd/cmd-inet/usr.sadm/dhcpmgr

JAVAFILES =	$(CLASSFILES:.class=.java)

MSGDIR=		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr/client
MSGDIRS =       $(ROOT)/usr/share/lib/locale \
                $(ROOT)/usr/share/lib/locale/com \
                $(ROOT)/usr/share/lib/locale/com/sun \
		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr \
		$(MSGDIR)

MSGFILES=	ResourceBundle.properties \
		OptionDescriptions.properties
MSGS=		$(MSGFILES:%=$(MSGDIR)/%)

CLEANFILES=	*.class
CLOBBERFILES=

.KEEP_STATE:

all: $(CLASSFILES) $(SUBDIRS)

install: all $(SUBDIRS)

_msg: $(MSGDIRS) $(MSGS) $(SUBDIRS)

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
