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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

METASSIST_TOPLEVEL = ..

# Files to be copied to /etc/default
DEFAULTFILES = \
	metassist.xml.dfl

include $(METASSIST_TOPLEVEL)/../../Makefile.cmd
include $(METASSIST_TOPLEVEL)/Makefile.env

# Files to be copied to /usr/share/lib/xml/dtd
DTDFILES = \
	volume-config.dtd \
	volume-defaults.dtd \
	volume-request.dtd

# Files to be copied to /usr/share/lib/xml/style
STYLEFILES = \
	volume-command.xsl

include $(METASSIST_TOPLEVEL)/Makefile.targ
