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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# uts/common/inet/ip/Makefile

all install clean clobber:

#
# EXPORT DELETE START
# Special target to clean up the source tree for export distribution
# Warning: This target changes the source tree
# include global definitions
include ../../../../Makefile.master

BOWDLERIZED=sadb.c ipsecesp.c ipsecah.c spd.c ip_if.c ip.c ip6.c 

EXPORT_SRC:
	for f in ${BOWDLERIZED}; do \
		rm -f $${f}+; \
		sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
			< $${f} > $${f}+; \
		${MV} $${f}+ $${f}; \
	done
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile ${BOWDLERIZED}

# CRYPT DELETE START
# Special target to clean up the source tree for domestic distribution
# Warning: This target changes the source tree

CRYPT_SRC:
	sed -e "/^# CRYPT DELETE START/,/^# CRYPT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile

# CRYPT DELETE END
# EXPORT DELETE END
