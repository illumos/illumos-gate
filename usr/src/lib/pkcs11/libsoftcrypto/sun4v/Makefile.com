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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# lib/pkcs11/libsoftcrypto/sun4v/Makefile.com
#

LIBRARY = libsoftcrypto_psr.a
VERS= .1
PLATFORM = sun4v
MODULE = libsoftcrypto_psr.so.1

include $(SRC)/Makefile.psm
include ../Makefile.links
include ../../Makefile.com

# Platform-specific settings
ARCFOUR_PSM_OBJS=  arcfour_crypt.o
ARCFOUR_PSM_SRC=   $(ARCFOUR_DIR)/sun4v/arcfour_crypt.c 
BIGNUM_FLAGS += -DUMUL64
SRCS= $(ARCFOUR_PSM_SRC) $(BIGNUM_SRC)

MAPFILES= ../mapfile-vers
OBJECTS= $(ARCFOUR_PSM_OBJS) $(BIGNUM_OBJS)

# Compiler settings
sparc_XARCH =      -m32 -xarch=sparc
sparcv9_XARCH =    -m64 -xarch=sparcvis

# Niagara perf options as per $SRC/uts/sun4v/arcfour
CFLAGS +=   -xO5 -xbuiltin=%all -dalign -D$(PLATFORM)
CFLAGS64 += -D$(PLATFORM)
ASFLAGS +=  -DPIC

# For bignum
LDLIBS +=   -lc

$(USR_PSM_LIB_DIR)/% := FILEMODE = 755

pics/arcfour_crypt.o: $(ARCFOUR_DIR)/sun4v/arcfour_crypt.c
	$(COMPILE.c) -o $@ $(ARCFOUR_DIR)/sun4v/arcfour_crypt.c
	$(POST_PROCESS_O)
