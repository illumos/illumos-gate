#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at src/OPENSOLARIS.LICENSE.
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
# Copyright (c) 2018, Joyent, Inc.

SRCS	=	iscii91%UTF-8.c \
		UTF-8%iscii91.c \
		iscii91%pc-iscii.c \
		pc-iscii%iscii91.c \
		iscii91%ea-iscii.c \
		ea-iscii%iscii91.c

dummy: all

include $(SRC)/lib/iconv_modules/Makefile.iconv

CPPFLAGS += -I../include

# needs work
SMOFF += index_overflow

all: $(PROGS)
