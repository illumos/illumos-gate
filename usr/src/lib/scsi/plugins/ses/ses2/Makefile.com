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

MODULE =	ses2
SRCS =		ses2.c			\
		ses2_element.c		\
		ses2_element_ctl.c	\
		ses2_enclosure.c	\
		ses2_enclosure_ctl.c	\
		ses2_pages.c

SRCDIR =	../common
PLUGINTYPE =	framework

include ../../Makefile.lib

CERRWARN += 	-_gcc=-Wno-switch
