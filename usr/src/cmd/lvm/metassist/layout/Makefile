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

METASSIST_TOPLEVEL = ..

SRCS=	\
	layout.c \
	layout_concat.c \
	layout_device_cache.c \
	layout_device_util.c \
	layout_discovery.c \
	layout_dlist_util.c \
	layout_hsp.c \
	layout_messages.c \
	layout_mirror.c \
	layout_request.c \
	layout_slice.c \
	layout_stripe.c \
	layout_svm_util.c \
	layout_validate.c

OBJS = $(SRCS:%.c=%.o)
HDRS = $(SRCS:%.c=%.h)
MSGFILES = $(SRCS:%.c=%.i)

include $(METASSIST_TOPLEVEL)/../../Makefile.cmd
include $(METASSIST_TOPLEVEL)/Makefile.env

INCLUDES += -I../common -I../controller -I../../../../lib/libdiskmgt/common \
            -I../../../../lib/lvm/libmeta/common/hdrs
CFLAGS   += $(INCLUDES)

POFILE = layoutp.po

include $(METASSIST_TOPLEVEL)/Makefile.targ

# Build .po file from message files
$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

cstyle:
	$(CSTYLE) $(CSTYLE_FLAGS) $(SRCS) $(HDRS)

hdrchk:
	$(HDRCHK) $(HDRCHK_FLAGS) $(HDRS)
