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

LIBRARY		= libsa.a
LOCOBJS		= assert.o ctype.o errno.o libintl.o malloc.o memlist.o \
		  standalloc.o stdio.o stdlib.o strdup.o strings.o \
		  time.o unistd.o
CMNOBJS		= cache.o diskread.o fsswitch.o promfs.o

sparc_CMNUTILOBJS = memchr.o memmove.o
CMNUTILOBJS	= $($(MACH)_CMNUTILOBJS) \
		  bsearch.o memcmp.o memcpy.o memset.o qsort.o \
		  string.o strtol.o strtoul.o

i386_MACHOBJS	= get.o map_prog.o
sparc_MACHOBJS	= prom_misc.o
MACHOBJS	= $($(MACH)_MACHOBJS)

i386_ASMOBJS	= _setjmp.o samuldiv64.o
sparc_ASMOBJS	= _setjmp.o
ASMOBJS		= $($(MACH)_ASMOBJS)

OBJECTS		= $(LOCOBJS) $(CMNOBJS) $(CMNUTILOBJS) $(MACHOBJS) $(ASMOBJS)

include ../Makefile.com

CMNDIR		= ../fs/common
CMNUTILDIR	= $(TOPDIR)/common/util
SRCS		= $(LOCOBJS:%.o=$(SRCDIR)/%.c) $(CMNOBJS:%.o=$(CMNDIR)/%.c) \
	  	  $(CMNUTILOBJS:%.o=$(CMNUTILDIR)/%.c) \
	  	  $($(MACH)_ASMOBJS:%.o=$(MACH)/%.s) \
		  $($(MACH)_OBJS:%.o=$(MACH)/%.c)

LDLIBS += -lsock
CPPFLAGS += $(SOCKCPPFLAGS)

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)

objs/%.o: $(MACH)/%.s
	  $(COMPILE.s) -o $@ $<
	  $(POST_PROCESS_O)

objs/%.o: $(MACH)/%.c
	  $(COMPILE.c) -o $@ $<
	  $(POST_PROCESS_O)

objs/%.o: $(CMNUTILDIR)/%.c
	  $(COMPILE.c) -o $@ $<
	  $(POST_PROCESS_O)

include ../Makefile.targ
