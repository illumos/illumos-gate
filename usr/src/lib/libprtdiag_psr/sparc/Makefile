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
# Copyright 2019 Peter Tribble.
#
# lib/libprtdiag_psr/sparc/Makefile

PRTDIAG_PLATFORMS=	desktop tazmo javelin sunfire serengeti \
			montecarlo littleneck daktari cherrystone \
			lw8 snowbird ontario schumacher opl montoya monza

all :=		TARGET= all
lint :=		TARGET= lint
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
_msg :=		TARGET= _msg

.KEEP_STATE:

all lint clean clobber install _msg : $(PRTDIAG_PLATFORMS)

$(PRTDIAG_PLATFORMS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

