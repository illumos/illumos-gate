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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/lp/client/lib/Makefile
#

LIBRARY =	libprint.a
VERS=.2

FILEMODE=	0555

NS_CMN =	ns_bsd_addr.o ns_cmn_kvp.o ns_cmn_printer.o
NS_SWITCH = 	nss_printer.o nss_convert.o nss_write.o nss_ldap.o
NS_SUPPORT =	ns.o ${NS_CMN} ${NS_SWITCH}

OBJECTS =	network.o job.o list.o misc.o $(NS_SUPPORT)


include		../Makefile.lib

MAPFILES=	mapfile-vers
MAPOPTS=	$(MAPFILES:%=-M %)

CPPFLAGS +=	-I../../head -I../ -I.  -D_REENTRANT
LDLIBS +=	-lnsl -lsocket -lc -lldap
DYNFLAGS +=	$(MAPOPTS)


LIBS = $(DYNLIB)	# could be += for static and dynamic
# for messaging catalog
#
POFILE= bsd.po
SRCS= $(OBJECTS:%.o=%.c)
XGETFLAGS +=-a
 
.KEEP_STATE:
  
_msg:	$(POFILE)

$(POFILE):      $(SRCS)
	$(RM)	$@
	$(COMPILE.cpp)   $(SRCS) > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS)        $(POFILE).i
	sed "/^domain/d"        messages.po > $@
	$(RM) messages.po $(POFILE).i

all :	$(LIBS) 

install:	$(ROOTLIBDIR) $(ROOTLIBS) $(ROOTLINKS)

# definitions for lint

$(LINTLIB):= SRCS = llib-lprint
CLEANFILES +=	$(LINTLIB) $(LINTOUT)

lint:	lintcheck

cstyle:
	cstyle $(SRCS)

strip :

$(ROOTLIBDIR):
	$(INS.dir)

include		../Makefile.targ
