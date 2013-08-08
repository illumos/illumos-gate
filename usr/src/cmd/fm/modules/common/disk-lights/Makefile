#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2013, Joyent, Inc. All rights reserved.
#

MODULE = disk-lights
CLASS = common
SRCS = disk_lights.c

include ../../Makefile.plugin

LINTFLAGS += -L$(ROOT)/usr/lib/fm
LDLIBS += -ltopo
LDFLAGS += -L$(ROOT)/usr/lib/fm -R/usr/lib/fm
