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
# Copyright (c) 1996-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"

#
# snmp/Makefile
#

# OPTIONAL_INCLUDE_FILE1:sh = /bin/sh ../misc.sh ../../cmd/Makefile.cmd
# include $(OPTIONAL_INCLUDE_FILE1)

include $(SRC)/cmd/Makefile.cmd

 
#
# all
#

all:
	cd snmplib; $(MAKE) all
	cd agent; $(MAKE) all
	cd parser; $(MAKE) all
	cd snmprelayd; $(MAKE) all
	cd trapsend; $(MAKE) all
	cd mib; $(MAKE) all

install:
	cd snmplib; $(MAKE) install
	cd agent; $(MAKE) install
	cd parser; $(MAKE) install
	cd snmprelayd; $(MAKE) install
	cd trapsend; $(MAKE) install
	cd mib; $(MAKE) install

#
# clean
#

clean:
	cd snmplib; $(MAKE) clean
	cd agent; $(MAKE) clean
	cd parser; $(MAKE) clean
	cd snmprelayd; $(MAKE) clean
	cd trapsend; $(MAKE) clean
	cd mib; $(MAKE) clean

# Need to include a lint target for Solaris 2.6 integration

lint:
	cd snmplib; $(MAKE) lint
	cd agent; $(MAKE) lint
	cd parser; $(MAKE) lint
	cd snmprelayd; $(MAKE) lint
	cd trapsend; $(MAKE) lint
	cd mib; $(MAKE) lint

# Need a realclobber target with sccs clean

realclobber:
	cd snmplib; $(MAKE) realclobber
	cd agent; $(MAKE) realclobber
	cd parser; $(MAKE) realclobber
	cd snmprelayd; $(MAKE) realclobber
	cd trapsend; $(MAKE) realclobber
	cd mib; $(MAKE) realclobber


# OPTIONAL_INCLUDE_FILE2:sh = /bin/sh ../misc.sh ../../cmd/Makefile.targ
# include $(OPTIONAL_INCLUDE_FILE2)

include $(SRC)/cmd/Makefile.targ
