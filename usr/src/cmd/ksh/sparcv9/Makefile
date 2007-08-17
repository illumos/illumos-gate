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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

# Specify the MACH we currently use to build and test ksh
CMDTRANSMACH= $(MACH64)

include ../../Makefile.cmd
include ../../Makefile.cmd.64

include ../Makefile.com

install: all $(ROOTPROG64)
	@ \
	(print "# Installing 64bit $(PROG) aliases $(USRKSH_ALIAS_LIST)" ; \
	set -o xtrace ; \
	for i in $(USRKSH_ALIAS_LIST) ; do \
		[[ "$$i" = "$(PROG)" ]] && continue ; \
		$(RM) "$(ROOTBIN64)/$$i" ; \
		$(LN) "$(ROOTBIN64)/$(PROG)" "$(ROOTBIN64)/$$i" ; \
	done \
	)

include ../../Makefile.targ
