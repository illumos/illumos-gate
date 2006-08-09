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
# lib/libdscp/spec/Makefile
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

SUBDIRS=	sparc

all	:= TARGET= all
install	:= TARGET= install
clean	:= TARGET= clean
clobber	:= TARGET= clobber
lint	:= TARGET= lint

.KEEP_STATE:

all install clean clobber: ${SUBDIRS}

${SUBDIRS}: FRC
	@cd $@; pwd; ${MAKE} ${TARGET}

#
# This will make sure that any target not
# explicitly defined will not break the build.
#
# XXX pmake on intel does not like the following rules
# %: ignore_and_exit_quietly
# ignore_and_exit_quietly:
#
# So here it is manually
#
IGNORE=		_msg catalog install_h delete \
		package tcov debug private_t \
		check analyze test dynamic lint

${IGNORE}:

FRC:
