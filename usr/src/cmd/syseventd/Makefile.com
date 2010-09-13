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
# Compile flags & libraries for all sysevent daemons and modules
#
# NOTE: any library added to the next line must be present in the CD miniroot
#	together with all of their dependencies.
#
LDLIBS += -lsysevent

CPPFLAGS += -D_POSIX_PTHREAD_SEMANTICS
CPPFLAGS += -D_REENTRANT
CFLAGS += $(CCVERBOSE)
LINTFLAGS += -m

#
# install specifics - directories
#

ROOTETC=$(ROOT)/etc
ROOTLIB=$(ROOT)/usr/lib

ROOTLIBSYSEVENTDIR = $(ROOTLIB)/sysevent
ROOTLIBSYSEVENTSYSEVENTD = $(ROOTLIBSYSEVENTDIR)/syseventd
ROOTLIBSYSEVENTSYSEVENTCONFD = $(ROOTLIBSYSEVENTDIR)/syseventconfd
ROOTLIBSYSEVENTMODULEDIR= $(ROOTLIBSYSEVENTDIR)/modules
ROOTETCSYSEVENTDIR = $(ROOTETC)/sysevent
ROOTETCSYSEVENTCONFIGDIR= $(ROOTETCSYSEVENTDIR)/config

#
# To play well with what we inherit from Makefile.lib
#
LIBLINKS =
DYNLIB = 	$(LIBRARY:%=%.so)
LIBS =		$(DYNLIB)
ROOTLIBDIR =	$(ROOTLIBSYSEVENTMODULEDIR)

#
# install macro for syseventd & syseventconfd
#
ROOTLIBSYSEVENTSYSEVENTD = $(PROG:%=$(ROOTLIBSYSEVENTDIR)/%)

#
# install macro for /etc/sysevent/config files
#
ROOTETCSYSEVENTCONFIGFILES= $(CONFIG_FILES:%=$(ROOTETCSYSEVENTCONFIGDIR)/%)

#
# explicit permissions
#

$(ROOTETCSYSEVENTCONFIGFILES) :=	FILEMODE= 0444
