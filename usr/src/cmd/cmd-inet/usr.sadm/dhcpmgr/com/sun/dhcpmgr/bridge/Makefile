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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/cmd-inet/usr.sadm/dhcpmgr/com/sun/dhcpmgr/bridge/Makefile
#

JNIHDR_FILES =	com_sun_dhcpmgr_bridge_Bridge.h

CLASSFILES = 	Bridge.class \
		BridgeException.class \
		HostExistsException.class \
		NoHostsEntryException.class \
		NoEntryException.class \
		ExistsException.class \
		NoTableException.class \
		TableExistsException.class \
		NoDefaultsException.class \
		NotRunningException.class \
		InvalidRsrcException.class \
		InvalidPathException.class \
		DsymException.class \
		WordexpException.class \
		ResourceStrings.class

JNICLASSFILES =	Bridge.class

include		$(SRC)/lib/Makefile.lib

CLASSPATH=	$(SRC)/cmd/cmd-inet/usr.sadm/dhcpmgr

JAVAFILES =	$(CLASSFILES:.class=.java)

MSGDIR =	$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr/bridge
MSGDIRS =	$(ROOT)/usr/share/lib/locale \
		$(ROOT)/usr/share/lib/locale/com \
		$(ROOT)/usr/share/lib/locale/com/sun \
		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr \
		$(MSGDIR)

MSGFILES =	ResourceBundle.properties
MSGS =		$(MSGFILES:%=$(MSGDIR)/%)

CLEANFILES=	*.class $(JNIHDR_FILES)
CLOBBERFILES=

.KEEP_STATE:

all: $(CLASSFILES) $(JNIHDR_FILES)

install: all

#
# Build jni header file
# Use $@ instead of the "unreliable" $*
#
$(JNIHDR_FILES): $(JNICLASSFILES)
	$(JAVAH) -jni -classpath $(CLASSPATH) \
		`$(ECHO) $@ | sed 's/.h$$//' | tr _ .`

_msg: $(MSGDIRS) $(MSGS)

$(MSGDIR)/%: %
	$(INS.file)

$(MSGDIRS):
	$(INS.dir)

include $(SRC)/lib/Makefile.targ
