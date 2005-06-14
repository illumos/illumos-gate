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
#ident	"%Z%%M%	%I%	%E% SMI"

include ../../Makefile.cmd

OWNER = root
GROUP = sys
FILEMODE = 0444

ROOTPROFILE = $(ROOT)/var/svc/profile

PROFILESRCS = \
	generic_open.xml \
	generic_limited_net.xml \
	inetd_generic.xml \
	inetd_upgrade.xml \
	ns_dns.xml \
	ns_files.xml \
	ns_ldap.xml \
	ns_nis.xml \
	ns_nisplus.xml \
	ns_none.xml \
	platform_SUNW,Sun-Fire-15000.xml \
	platform_SUNW,Sun-Fire-880.xml \
	platform_SUNW,Sun-Fire.xml \
	platform_SUNW,Ultra-Enterprise-10000.xml \
	platform_SUNW,UltraSPARC-IIi-Netract.xml \
	platform_i86pc.xml \
	platform_none.xml

PROFILES = $(PROFILESRCS:%=$(ROOTPROFILE)/%)

install: $(PROFILES)
	$(RM) $(ROOTPROFILE)/generic.xml
	$(LN) -s generic_open.xml $(ROOTPROFILE)/generic.xml
	$(RM) $(ROOTPROFILE)/platform.xml
	# SUNW,Sun-Fire-V890
	$(RM) $(ROOTPROFILE)/platform_SUNW,Sun-Fire-V890.xml
	$(LN) $(ROOTPROFILE)/platform_SUNW,Sun-Fire-880.xml \
	    $(ROOTPROFILE)/platform_SUNW,Sun-Fire-V890.xml
	# SUNW,UltraSPARC-IIe-NetraCT-[46]0
	$(RM) $(ROOTPROFILE)/platform_SUNW,UltraSPARC-IIe-NetraCT-40.xml
	$(RM) $(ROOTPROFILE)/platform_SUNW,UltraSPARC-IIe-NetraCT-60.xml
	$(LN) $(ROOTPROFILE)/platform_SUNW,UltraSPARC-IIi-Netract.xml \
	$(ROOTPROFILE)/platform_SUNW,UltraSPARC-IIe-NetraCT-40.xml
	$(LN) $(ROOTPROFILE)/platform_SUNW,UltraSPARC-IIi-Netract.xml \
	    $(ROOTPROFILE)/platform_SUNW,UltraSPARC-IIe-NetraCT-60.xml

$(ROOTPROFILE)/%: %
	$(INS.file)

all lint clobber clean _msg:
