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
# cmd/cmd-inet/usr.sadm/dhcpmgr/com/sun/dhcpmgr/server/Makefile
#


# Place high-level classes first in order to minimize build time.
CLASSFILES = 	DhcpMgrImpl.class \
		DhcpNetMgrImpl.class \
		DhcpServiceMgrImpl.class \
		DhcptabMgrImpl.class


include		$(SRC)/lib/Makefile.lib

CLASSPATH=	$(SRC)/cmd/cmd-inet/usr.sadm/dhcpmgr

JAVAFILES =	$(CLASSFILES:.class=.java)

MSGDIR =	$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr/server
MSGDIRS =	$(ROOT)/usr/share/lib/locale \
		$(ROOT)/usr/share/lib/locale/com \
		$(ROOT)/usr/share/lib/locale/com/sun \
		$(ROOT)/usr/share/lib/locale/com/sun/dhcpmgr \
		$(MSGDIR)


CLEANFILES=	*.class
CLOBBERFILES=

.KEEP_STATE:

all: $(CLASSFILES)

install: all

_msg: 

include $(SRC)/lib/Makefile.targ
