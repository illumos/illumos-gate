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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# As per $(SRC)/lib/README.Makefiles, this could've been as easy as
#
#include	$(SRC)/lib/Makefile.spec.arch
#
# ... but we don't want/need to deliver 64 bit libraries; thus we need
# to override the inclusion of the Makefile and build only the targets
# for $(MACH) instead of $(MACH)_ARCHITECTURES
#
all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
lint		:=	TARGET= lint

.KEEP_STATE:

all install clean clobber: $(MACH)

$(MACH): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

IGNORE=		_msg catalog install_h delete \
		package tcov debug private_h \
		check analyse test dynamic lint
$(IGNORE):

FRC:
