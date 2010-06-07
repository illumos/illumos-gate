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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# lib/pkcs11/libsoftcrypto/sun4v/sparcv9/Makefile
#

CLASS = 64

include ../Makefile.com
include $(SRC)/lib/Makefile.lib.64

# E_NAME_MULTIPLY_DEF2 is for arcfour_key_init and arcfour_crypt in
# different implementations of arcfour_crypt.c
LINTFLAGS64 += -D$(PLATFORM) -erroff=E_NAME_MULTIPLY_DEF2

install:  all $(SOFT_PSR64_LINKS) $(USR_PSM_LIBS64)

include $(SRC)/Makefile.psm.targ
