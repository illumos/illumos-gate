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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 

LIBRARY = libinet.a
LOCOBJS = ipv4.o icmp4.o udp.o mac.o ethernet.o dhcpv4.o ibd.o
CMNOBJS = ipv4_sum.o udp_sum.o octet.o scan.o dhcpinfo.o
OBJECTS = $(LOCOBJS) $(CMNOBJS)

include ../Makefile.com

CMNDIR  = $(CMNNETDIR)/dhcp
SRCS	= $(LOCOBJS:%.o=$(SRCDIR)/%.c) $(CMNOBJS:%.o=$(CMNDIR)/%.c)
LDLIBS += -lsock
CPPFLAGS += $(SOCKCPPFLAGS) -I$(TOPDIR)/psm/stand

CERRWARN += -_gcc=-Wno-char-subscripts
CERRWARN += $(CNOWARN_UNINIT)

include ../Makefile.targ
