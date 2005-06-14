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
# Copyright (c) 1997-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"

# include global definitions
include ../../../../Makefile.master

# EXPORT DELETE START

all:
	@$(ECHO) " This Makefile is used to clean up the source tree\n" \
		"for export distribution.\n" \
		"[Usage]: make [EXPORT_SRC] [CRYPT_SRC]\n\n" \
		"WARNING: EXPORT_SRC, CRYPT_SRC targets change the\n" \
		"source tree and remove the Makefile."

# Special target to clean up the source tree for export distribution
# Warning: This target changes the source tree and removes this Makefile

EXPORT_SRC:
	$(RM) gssapiP_dummy.h+ mechglueP.h+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< gssapiP_dummy.h > gssapiP_dummy.h+
	$(MV) gssapiP_dummy.h+ gssapiP_dummy.h
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< mechglueP.h > mechglueP.h+
	$(MV) mechglueP.h+ mechglueP.h
	$(RM) Makefile
	$(CHMOD) 444 gssapiP_dummy.h mechglueP.h

# CRYPT DELETE START
# Special target to clean up the source tree for export distribution
# Warning: This target changes the source tree.

CRYPT_SRC:
	$(RM) mechglueP.h+ Makefile+
	sed -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< mechglueP.h > mechglueP.h+
	$(MV) mechglueP.h+ mechglueP.h
	sed -e "/^# CRYPT DELETE START/,/^# CRYPT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 mechglueP.h Makefile
	
# CRYPT DELETE END
# EXPORT DELETE END
