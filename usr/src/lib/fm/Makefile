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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../Makefile.lib

common_SUBDIRS = \
	libfmd_agent \
	libdiagcode \
	libdiskstatus \
	libfmd_adm \
	libfmd_log \
	libfmd_msg \
	libfmd_snmp \
	libfmevent \
	topo

sparc_SUBDIRS = \
	libmdesc \
	libldom

i386_SUBDIRS =

SUBDIRS = $(common_SUBDIRS) $($(MACH)_SUBDIRS)

libldom: libmdesc libfmd_agent

libfmd_snmp: libfmd_adm topo

topo: $($(MACH)_SUBDIRS) libfmd_agent libdiskstatus

include ./Makefile.subdirs
