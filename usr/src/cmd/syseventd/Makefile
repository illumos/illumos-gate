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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/syseventd/Makefile
#

#
#  The syseventd source is organized in a two-level hierarchy,
#  with the top level for daemons and modules.  Daemons (cmds)
#  need to be built with the usr/src/cmd hierarchy of Makefiles
#  for the proper set of cc flags etc., whereas loadable modules
#  need usr/src/lib.  Each bottom-level Makefile includes
#  the relevant set of common Makefiles (for daemons or modules),
#  and also inherit the upper level set of common Makefiles
#  for all syseventd components.
#
#
#			   usr/src/cmd/syseventd
#			          |
#			       Makefile
#			       Makefile.com
#			       Makefile.targ
#			           |
#	 	------------------------------------------
#	 	|                  |                     |
#	    daemons		modules			etc
#	       |		   |                     |
#	    Makefile		Makefile	      Makefile
#	    Makefile.com	Makefile.com
#	    Makefile.targ	Makefile.targ
#               |                     |
#         ------------------          ------------------
#         |		  |	     |		       |
#    syseventd	syseventconfd	devfsadmd_mod	sysevent_conf_mod
#
#     Makefile	   Makefile	   Makefile	    Makefile
#

MANIFEST=	sysevent.xml
SVCMETHOD=	svc-syseventd

include ../Makefile.cmd

.PARALLEL:

SUBDIRS=			\
	etc			\
	daemons			\
	modules

ROOTMANIFESTDIR=	$(ROOTSVCSYSTEM)

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint
_msg:=		TARGET= _msg

$(ROOTMANIFEST):=	FILEMODE= 444

.KEEP_STATE:

all clean clobber lint _msg: $(SUBDIRS)

install: $(SUBDIRS) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

FRC:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)
