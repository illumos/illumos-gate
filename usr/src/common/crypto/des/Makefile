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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# common/crypto/des/Makefile
#
# include global definitions
include $(SRC)/Makefile.master

.KEEP_STATE:

FRC:

# EXPORT DELETE START
EXPORT_SRC:
	$(RM) Makefile+ des_impl.c+ des_impl.h+ des_ks.c+ sun4u/des_crypt_asm.s+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< des_impl.c > des_impl.c+
	$(MV) des_impl.c+ des_impl.c
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< des_ks.c > des_ks.c+
	$(MV) des_ks.c+ des_ks.c
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< sun4u/des_crypt_asm.s > sun4u/des_crypt_asm.s+
	$(MV) sun4u/des_crypt_asm.s+ sun4u/des_crypt_asm.s
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(RM) Makefile
	$(MV) Makefile+ Makefile 
	$(CHMOD) 444 Makefile des_impl.c des_impl.h des_ks.c sun4u/des_crypt_asm.s

# EXPORT DELETE END
