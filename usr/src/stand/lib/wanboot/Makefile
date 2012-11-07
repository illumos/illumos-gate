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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 

LIBRARY = libwanboot.a
LOCOBJS = http_aux.o bootinfo_aux.o
CMNOBJS = boot_http.o parseURL.o bootlog.o auxutil.o p12access.o \
	  p12auxpars.o p12err.o p12misc.o http_errorstr.o bootconf.o bootinfo.o
OBJECTS = $(LOCOBJS) $(CMNOBJS)

include ../Makefile.com

CMNDIR  = $(CMNNETDIR)/wanboot
SRCS	= $(LOCOBJS:%.o=$(SRCDIR)/%.c) $(CMNOBJS:%.o=$(CMNDIR)/%.c)
LDLIBS += -lcrypto -lsock -linet -lssl -lnvpair

CPPFLAGS += -I$(CMNNETDIR)/dhcp -I$(TOPDIR)/common/net/wanboot/crypt \
	-I../inet $(DHCPCPPFLAGS) $(SOCKCPPFLAGS)

#
# several objects need access to openssl headers, now in ../openssl
#
CPPFLAGS += -I..

CERRWARN += -_gcc=-Wno-char-subscripts
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-value

include ../Makefile.targ
