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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# 

PROG= installboot

EINFO_SRC= ./../common/bblk_einfo.c
UTILS_SRC =./../common/boot_utils.c
EXTRA_SRC =./../common/mboot_extra.c

OBJS= installboot.o bblk_einfo.o  boot_utils.o mboot_extra.o
SRCS= installboot.c $(UTILS_SRC) $(EINFO_SRC) $(EXTRA_SRC)

include ../Makefile.com

CPPFLAGS += -I$(SRC)/uts/common

LDLIBS += -lmd5

C99MODE=	$(C99_ENABLE)

LINTFLAGS += -erroff=E_BAD_PTR_CAST_ALIGN

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

boot_utils.o:	$(UTILS_SRC)
		$(COMPILE.c) -o $@ $(UTILS_SRC)

mboot_extra.o:	$(EXTRA_SRC)
		$(COMPILE.c) -o $@ $(EXTRA_SRC)

bblk_einfo.o:	$(EINFO_SRC)
		$(COMPILE.c) -o $@ $(EINFO_SRC)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../Makefile.targ
