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

MANIFEST = mpxio-upgrade.xml
SVCMETHOD = mpxio-upgrade

include ../Makefile.cmd

SHFILES = stmsboot
STMSBOOT_UTIL = stmsboot_util
OBJS = $(STMSBOOT_UTIL).o
SRCS = $(OBJS:%.o=%.c)

POFILES = $(SRCS:.c=.po) $(SHFILES:%=%.po)
POFILE = pstmsboot.po
CLOBBERFILES = $(SHFILES) $(STMSBOOT_UTIL) $(POFILE) $(OBJS)
ROOTFSLIB_MPXIO = $(ROOT)/lib/mpxio

ROOTMANIFESTDIR = $(ROOTSVCSYSTEMDEVICE)
LDLIBS += -ldevinfo -ldevid -lnvpair -lumem
CERRWARN += $(CNOWARN_UNINIT)

.KEEP_STATE:

all: $(STMSBOOT_UTIL) $(SHFILES)

install: all					\
	$(ROOTFSLIB_MPXIO)			\
	$(ROOTFSLIB_MPXIO)/$(STMSBOOT_UTIL)	\
	$(ROOTMANIFEST)				\
	$(ROOTSVCMETHOD)			\
	$(ROOTUSRSBIN)/stmsboot

check:	$(CHKMANIFEST)
	$(CSTYLE) -pP $(SRCS)

clean:
	$(RM) $(POFILES)

lint:	lint_SRCS

$(STMSBOOT_UTIL): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $< $(LDLIBS)
	$(POST_PROCESS)

include ../Makefile.targ

$(ROOTFSLIB_MPXIO):
	$(INS.dir)

$(ROOTFSLIB_MPXIO)/%: %
	$(INS.file)

$(POFILE): $(POFILES)
	$(RM) $@; cat $(POFILES) > $@
