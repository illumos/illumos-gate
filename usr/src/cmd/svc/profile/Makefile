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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# Copyright 2019 Peter Tribble.
# Copyright 2019 Joyent, Inc.
#

include ../../Makefile.cmd

FILEMODE = 0444

ROOTPROFILE = $(ROOT)/etc/svc/profile

PROFILESRCS = \
	generic.xml \
	generic_open.xml \
	generic_limited_net.xml \
	inetd_generic.xml \
	inetd_upgrade.xml \
	ns_dns.xml \
	ns_files.xml \
	ns_ldap.xml \
	ns_nis.xml \
	ns_none.xml \
	platform_SUNW,SPARC-Enterprise.xml \
	platform_SUNW,Sun-Fire-880.xml \
	platform_SUNW,Sun-Fire.xml \
	platform_none.xml \
	platform_sun4v.xml

PROFILES = $(PROFILESRCS:%=$(ROOTPROFILE)/%)

PROFILES_open = generic_open.xml inetd_generic.xml
PROFILES_limited = generic_limited_net.xml
CHECK_OPEN = check_open
CHECK_LMTD = check_limited

COMM =	/usr/bin/comm
TEE =	/usr/bin/tee
TEST =	/usr/bin/test
LISTSVCS = listsvcs.pl

install: all $(PROFILES)
	$(CP) platform_none.xml $(ROOTPROFILE)/platform.xml
	# SUNW,Sun-Fire-V890
	$(RM) $(ROOTPROFILE)/platform_SUNW,Sun-Fire-V890.xml
	$(LN) $(ROOTPROFILE)/platform_SUNW,Sun-Fire-880.xml \
	    $(ROOTPROFILE)/platform_SUNW,Sun-Fire-V890.xml

$(ROOTPROFILE)/%: %
	$(INS.file)

all:	$(CHECK_OPEN) $(CHECK_LMTD)

#
#	Enforce consistency between open and limited profiles per README
#
$(CHECK_OPEN) :=	PROFILES_CHECKED = open
$(CHECK_OPEN) :=	PROFILES_COVERING = limited
$(CHECK_LMTD) :=	PROFILES_CHECKED = limited
$(CHECK_LMTD) :=	PROFILES_COVERING = open
$(CHECK_OPEN) $(CHECK_LMTD): \
	$(LISTSVCS) $(PROFILES_open) $(PROFILES_limited)
	@$(ECHO) Check for enabled $(PROFILES_CHECKED) services \
		not covered by $(PROFILES_COVERING) profile
	@$(PERL) -w $(LISTSVCS) -e $(PROFILES_$(PROFILES_CHECKED)) > $@.enabled
	@$(PERL) -w $(LISTSVCS) $(PROFILES_$(PROFILES_COVERING)) > $@.all
	@$(COMM) -23 $@.enabled $@.all | $(TEE) $@.notcovered
	@$(TEST) ! -s $@.notcovered && $(TOUCH) $@

_msg:

clobber clean:
	$(RM) $(CHECK_OPEN)* $(CHECK_LMTD)*
