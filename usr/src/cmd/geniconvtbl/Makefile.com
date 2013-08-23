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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

$(NOT_NATIVE)NATIVE_BUILD = $(POUND_SIGN)

ITM	= geniconvtbl.so
PROG	= geniconvtbl

SRCSH1  = iconv_tm.h hash.h
SRCCH1  = itmcomp.h itm_util.h maptype.h
SRCSC1  = itmcomp.c assemble.c disassemble.c itm_util.c
SRCY1   = itm_comp.y
SRCL1   = itm_comp.l
SRCI1   = geniconvtbl.c


YTABC   = y.tab.c
YTABH   = y.tab.h
LEXYY   = lex.yy.c
YOUT    = y.output
MAPFILE	= ../mapfile



SRCSH	= $(SRCSH1:%.h=../%.h)
SRCCH	= $(SRCCH1:%.h=../%.h)
SRCSC	= $(SRCSC1:%.c=../%.c)
SRCI	= $(SRCI1:%.c=../%.c)
SRCY    = $(SRCY1:%.y=../%.y)
SRCL    = $(SRCL1:%.l=../%.l)

SRCYC	= $(SRCY:%.y=%.c)
SRCLC	= $(SRCL:%.l=%.c)

SRCS    = $(SRCSC) $(YTABC) $(LEXYY)
HDRS	= $(SRCCH1) $(ERNOSTRH)



SED	= sed
LEXSED	= ../lex.sed
YACCSED	= ../yacc.sed



# include ../../../lib/Makefile.lib
include ../../Makefile.cmd


ROOTDIRS32=	$(ROOTLIB)/iconv
ROOTDIRS64=	$(ROOTLIB)/iconv/$(MACH64)
ROOTITM32 =	$(ROOTDIRS32)/$(ITM)
ROOTITM64 =	$(ROOTDIRS64)/$(ITM)

#
# definition for some useful target like clean, 
OBJS	= $(SRCSC1:%.c=%.o) $(YTABC:.c=.o) $(LEXYY:.c=.o)

CHECKHDRS = $(HDRS%.h=%.check)

CLOBBERFILES=	$(ITM) $(SRCYC)
CLEANFILES = 	$(OBJS) $(YTABC) $(YTABH) $(LEXYY) $(YOUT) \
		$(POFILES) $(POFILE)

CPPFLAGS	+= -I. -I..
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-implicit-function-declaration
YFLAGS		+= -d -v
CFLAGS 		+= -D_FILE_OFFSET_BITS=64

$(ITM) :=	CFLAGS += $(GSHARED) $(C_PICFLAGS) $(ZTEXT) -h $@
$(ITM) :=	CPPFLAGS += -D_REENTRANT 
$(ITM) :=	sparc_CFLAGS += -xregs=no%appl
$(ITM) :=	sparcv9_CFLAGS += -xregs=no%appl

LDLIBS += -lgen

MY_NATIVE_CPPFLAGS = -D_FILE_OFFSET_BITS=64 -I. -I..
MY_NATIVE_LDFLAGS = $(MAPFILE.NES:%=-M%) $(MAPFILE.PGA:%=-M%) $(MAPFILE.NED:%=-M%)
MY_NATIVE_LDLIBS = -lgen

#
# Message catalog
#
POFILES= $(SRCSC1:%.c=%.po) $(SRCI1:%.c=%.po) \
		$(SRCY1:%.y=%.po) $(SRCL1:%.l=%.po)

POFILE= geniconvtbl_.po





.KEEP_STATE:

.PARALLEL: $(ITM) $(OBJS)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ITM): $(SRCI)
	$(CC) $(CFLAGS) $(CPPFLAGS) -M$(MAPFILE) -o $@ $(SRCI) $(LDLIBS)
	$(POST_PROCESS_SO)

$(YTABC) $(YTABH): $(SRCY)
	$(YACC) $(YFLAGS) $(SRCY)
	@ $(MV) $(YTABC) $(YTABC)~
	@ $(SED) -f $(YACCSED) $(YTABC)~ > $(YTABC)
	@ $(RM) $(YTABC)~

$(LEXYY): $(SRCL) $(YTABH)
	$(LEX) -t $(SRCL) | $(SED) -f $(LEXSED) > $(LEXYY)


$(POFILE):  .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) >$@

$(POFILES): $(SRCSC) $(SRCI) $(SRCY) $(SRCL)

%.po:	../%.c
	$(COMPILE.cpp) $<  > $<.i
	$(BUILD.po)


lint : lint_SRCS1  lint_SRCS2


lint_SRCS1: $(SRCS)
	$(LINT.c) $(SRCS) $(LDLIBS)

lint_SRCS2: $(SRCI)
	$(LINT.c) $(SRCI) $(LDLIBS)



hdrchk: $(HDRCHECKS)

cstyle: $(SRCS)
	$(DOT_C_CHECK)

clean:
	$(RM) $(CLEANFILES)

debug:
	$(MAKE)	all COPTFLAG='' COPTFLAG64='' CFLAGS='-g -DDEBUG'


%.o:	%.c 
	$(COMPILE.c) $<

%.o:	../%.c
	$(COMPILE.c) $<



# install rule
# 
$(ROOTDIRS32)/%: $(ROOTDIRS32) %
	-$(INS.file)

$(ROOTDIRS64)/%: $(ROOTDIRS64) %
	-$(INS.file)

$(ROOTDIRS32): $(ROOTLIB)
	-$(INS.dir)

$(ROOTDIRS64): $(ROOTDIRS32)
	-$(INS.dir)

$(ROOTLIB) $(ROOTBIN):
	-$(INS.dir)

include ../../Makefile.targ

