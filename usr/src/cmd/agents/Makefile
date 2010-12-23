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

# cmd/agents/Makefile

#########################################################
#
# Makefile for the Solstice Enterprise Agent
#
# Targets:
#	all - compile everything
#	install - create installation directories and copy files
#	package - create packages in installation directory
#	clean - remove all intermediate files
#	clobber - make clean plus removing deliverable files
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

$(CLOSED_BUILD)AGENTS= $(CLOSED)/cmd/agents/agents

all	:=		TARGET = all
clean	:=		TARGET = clean
install	:=		TARGET = install
lint	:=		TARGET = lint
clobber :=		TARGET = clobber

SUBDIRS = snmp $(AGENTS)

#
# all
#

all: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

DIRMODE=	0755
ROOTVAR=	$(ROOT)/var

ROOTDIRS=	$(ROOTETC)/snmp \
		$(ROOTETC)/snmp/conf \
		$(ROOTLIB)/snmp \
		$(ROOTBIN) \
		$(ROOTVAR)/snmp \
		$(ROOTVAR)/snmp/mib

$(ROOTDIRS):
	$(INS.dir)

#
# Need a "make install" target for integrating into Solaris 2.6.
#

install: $(ROOTDIRS) $(SUBDIRS)

#
# clean
#

clean: $(SUBDIRS)

clobber: $(SUBDIRS)

# Need a lint target for Solaris2.6 integration.

lint:  $(SUBDIRS)

include $(SRC)/cmd/Makefile.targ
