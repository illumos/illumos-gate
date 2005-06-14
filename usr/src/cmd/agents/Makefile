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
# Copyright (c) 1998, 2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"

# cmd/agents/Makefile

#########################################################
#
# Makefile for the Solstice Enterprise Agent
#
# Targets:
#	all - compile everything
#	install - create installation directories and copy files
#	package - create packages in installation directory
#	clean - remove all .o's, binaries, libraries, detritus
#	clobber - make clean plus removing sources. Forces sccs get
#	lint - run lint on the source files
#
#########################################################

# OPTIONAL_INCLUDE_FILE:sh = /bin/sh misc.sh ../Makefile.cmd
# include $(OPTIONAL_INCLUDE_FILE)

include $(SRC)/cmd/Makefile.cmd

# Use $TARG_SYS for OS dependent variables
#
# TARG_SYS gets defined as SVR4 or SUNOS
#
TARG_SYS:sh =                           \
 (                                      \
   UNAME=` uname -r 2>/dev/null` ||.;   \
   case $UNAME in                       \
   '') echo SUNOS;;                     \
   4.*) echo SUNOS;;                    \
   5.*) echo SVR4;;                     \
   A.09.*) echo HPUX9;;                 \
   *)  echo SVR4;;                      \
   esac                                 \
 )

ROOTDIR	: sh=echo ${ROOTDIR:-"`pwd`"}
PKGLOC	: sh=echo ${PKGLOC:-'${ROOTDIR}/PACKAGES.`uname -p`'}

#
# all
#

all:
	cd snmp; $(MAKE) all
	cd dmi2.0; $(MAKE) all
	cd agents; $(MAKE) all

DIRMODE=	0755
OWNER=		root
GROUP=		sys
ROOTVAR=	$(ROOT)/var

ROOTDIRS=	$(ROOTETC)/dmi \
		$(ROOTETC)/dmi/ciagent \
		$(ROOTETC)/dmi/conf \
		$(ROOTETC)/snmp \
		$(ROOTETC)/snmp/conf \
		$(ROOTLIB)/dmi \
		$(ROOTLIB)/snmp \
		$(ROOTBIN) \
		$(ROOTVAR)/dmi \
		$(ROOTVAR)/dmi/db \
		$(ROOTVAR)/dmi/map \
		$(ROOTVAR)/dmi/mif \
		$(ROOTVAR)/snmp \
		$(ROOTVAR)/snmp/mib

$(ROOTDIRS):
	$(INS.dir)

#
# Need a "make install" target for integrating into Solaris 2.6.
#

install: $(ROOTDIRS)
	cd snmp; $(MAKE) install
	cd dmi2.0; $(MAKE) install
	cd agents; $(MAKE) install
	

#
# clean
#

clean:
	cd snmp; $(MAKE) clean
	cd dmi2.0; $(MAKE) clean
	cd agents; $(MAKE) clean

# Need a lint target for Solaris2.6 integration.

lint:
	cd snmp; $(MAKE) lint
	cd dmi2.0; $(MAKE) lint
	cd agents; $(MAKE) lint

# We need a real make clobber with sccs clean.

realclobber:
	cd snmp; $(MAKE) realclobber
	cd dmi2.0; $(MAKE) realclobber
	cd agents; $(MAKE) realclobber

package:
	cd ../../pkgdefs; pwd; $(MAKE) awk_pkginfo
	cd ../../pkgdefs/SUNWmibii; pwd; $(MAKE) install
	cd ../../pkgdefs/SUNWsacom; pwd; $(MAKE) install
	cd ../../pkgdefs/SUNWsadmi; pwd; $(MAKE) install
	cd ../../pkgdefs/SUNWsasnm; pwd; $(MAKE) install

include $(SRC)/cmd/Makefile.targ
