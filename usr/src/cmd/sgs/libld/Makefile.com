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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY =	libld.a
VERS =		.4

COMOBJS =	debug.o		globals.o	util.o

COMOBJS32 =	args32.o	entry32.o	exit32.o	groups32.o \
		ldentry32.o	ldlibs32.o	ldmain32.o	libs32.o \
		files32.o	map32.o		order32.o	outfile32.o \
		place32.o	relocate32.o	resolve32.o	sections32.o \
		sunwmove32.o	support32.o	syms32.o	update32.o \
		version32.o

COMOBJS64 =	args64.o	entry64.o	exit64.o	groups64.o \
		ldentry64.o	ldlibs64.o	ldmain64.o	libs64.o \
		files64.o	map64.o		order64.o	outfile64.o \
		place64.o	relocate64.o	resolve64.o	sections64.o \
		sunwmove64.o	support64.o	syms64.o	update64.o \
		version64.o

TOOLOBJS =	alist.o		assfail.o	findprime.o	string_table.o \
		strhash.o
AVLOBJ =	avl.o

G_MACHOBJS32 =	doreloc32.o
G_MACHOBJS64 =	doreloc64.o

BLTOBJ =	msg.o
ELFCAPOBJ =	elfcap.o

OBJECTS =	$(BLTOBJ) $(G_MACHOBJS32) $(G_MACHOBJS64) \
		$(L_MACHOBJS32) $(L_MACHOBJS64) \
		$(COMOBJS) $(COMOBJS32) $(COMOBJS64) \
		$(TOOLOBJS) $(E_TOOLOBJS) $(AVLOBJ) $(ELFCAPOBJ)

include 	$(SRC)/lib/Makefile.lib
include 	$(SRC)/cmd/sgs/Makefile.com

SRCDIR =	../common
ELFCAP=		$(SRC)/common/elfcap

# Building SUNWonld results in a call to the `package' target.  Requirements
# needed to run this application on older releases are established:
#   dlopen/dlclose requires libdl.so.1 prior to 5.10
# 
DLLIB =		$(VAR_DL_LIB)
package	:=	DLLIB = $(VAR_PKG_DL_LIB)

CPPFLAGS +=	-DUSE_LIBLD_MALLOC -I$(SRCBASE)/lib/libc/inc \
		    -I$(SRCBASE)/uts/common/krtld -I$(ELFCAP) \
		    $(VAR_LIBLD_CPPFLAGS) -DDO_RELOC_LIBLD
LDLIBS +=	$(CONVLIBDIR) $(CONV_LIB) $(LDDBGLIBDIR) $(LDDBG_LIB) \
		    $(ELFLIBDIR) -lelf $(DLLIB) -lc

LINTFLAGS +=	-u -D_REENTRANT
LINTFLAGS64 +=	-u -D_REENTRANT

DYNFLAGS +=	$(BDIRECT) $(VERSREF) \
		$(ZLAZYLOAD) $(USE_PROTO) '-R$$ORIGIN'

$(VAR_POUND_3)DEFS=
native:=	DYNFLAGS	+= $(CONVLIBDIR)

BLTDEFS =	msg.h
BLTDATA =	msg.c
BLTMESG =	$(SGSMSGDIR)/libld

BLTFILES =	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM =	../common/libld.msg
SGSMSGSPARC =	../common/libld.sparc.msg
SGSMSGINTEL =	../common/libld.intel.msg
SGSMSGTARG =	$(SGSMSGCOM)
SGSMSGALL =	$(SGSMSGCOM) $(SGSMSGSPARC) $(SGSMSGINTEL)

SGSMSGFLAGS1 =	$(SGSMSGFLAGS) -m $(BLTMESG)
SGSMSGFLAGS2 =	$(SGSMSGFLAGS) -h $(BLTDEFS) -d $(BLTDATA) -n libld_msg

CHKSRCS =	$(SRCBASE)/uts/common/krtld/reloc.h \
		$(COMOBJS32:%32.o=../common/%.c) \
		$(L_MACHOBJS32:%32.o=../common/%.c) \
		$(L_MACHOBJS64:%64.o=../common/%.c)

SRCS =		../common/llib-lld
LIBSRCS =	$(TOOLOBJS:%.o=$(SGSTOOLS)/common/%.c) \
		$(E_TOOLOBJS:%.o=$(SGSTOOLS)/common/%.c) \
		$(COMOBJS:%.o=../common/%.c) \
		$(AVLOBJS:%.o=$(VAR_AVLDIR)/%.c) \
		$(BLTDATA)

LINTSRCS =	$(LIBSRCS) ../common/lintsup.c
LINTSRCS32 =	$(COMOBJS32:%32.o=../common/%.c) \
		$(L_MACHOBJS32:%32.o=../common/%.c)
LINTSRCS64 =	$(COMOBJS64:%64.o=../common/%.c) \
		$(L_MACHOBJS64:%64.o=../common/%.c)

CLEANFILES +=	$(LINTOUTS) $(BLTFILES)
CLOBBERFILES +=	$(DYNLIB) $(LINTLIBS) $(LIBLINKS)

ROOTFS_DYNLIB =	$(DYNLIB:%=$(ROOTFS_LIBDIR)/%)
