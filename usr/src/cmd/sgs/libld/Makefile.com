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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY=	libld.a
VERS=		.2

G_MACHOBJS=	doreloc.o
L_MACHOBJS= 	machrel.o	machsym.o

TOOLOBJS=	alist.o		assfail.o	findprime.o	string_table.o \
		strhash.o
AVLOBJ=		avl.o
COMOBJS=	entry.o		files.o		globals.o	libs.o \
		order.o		outfile.o	place.o		relocate.o \
		resolve.o	sections.o	support.o	sunwmove.o \
		syms.o		update.o	util.o		version.o \
		args.o		debug.o		ldentry.o	groups.o \
		ldlibs.o	ldmain.o	exit.o		map.o
COMOBJS64=	$(COMOBJS:%.o=%64.o)
BLTOBJ=		msg.o
ELFCAPOBJ=	elfcap.o

OBJECTS=	$(BLTOBJ)  $(G_MACHOBJS)  $(L_MACHOBJS)  $(COMOBJS) \
		$(TOOLOBJS) $(AVLOBJ) $(ELFCAPOBJ)

include 	$(SRC)/lib/Makefile.lib
include 	$(SRC)/cmd/sgs/Makefile.com

PLAT=		$(VAR_PLAT_$(BASEPLAT))
MAPFILES=	../common/mapfile-vers
MAPOPTS=	$(MAPFILES:%=-M%)

ELFCAP=		$(SRC)/common/elfcap

# Building SUNWonld results in a call to the `package' target.  Requirements
# needed to run this application on older releases are established:
#   dlopen/dlclose requires libdl.so.1 prior to 5.10
# 
DLLIB =		$(VAR_DL_LIB)
package	:=	DLLIB = $(VAR_PKG_DL_LIB)

CPPFLAGS +=	-DUSE_LIBLD_MALLOC -I$(SRCBASE)/uts/common/krtld \
		-I$(ELFCAP) -D_REENTRANT $(VAR_LIBLD_CPPFLAGS)
LLDLIBS=	$(LDDBGLIBDIR) $(LDDBG_LIB) $(ELFLIBDIR) -lelf $(DLLIB)
LDLIBS +=	$(CONVLIBDIR) -lconv $(LLDLIBS) -lc
LINTFLAGS +=	-u $(LDDBGLIBDIR) $(CONVLIBDIR) \
		-erroff=E_NAME_DECL_NOT_USED_DEF2
LINTFLAGS64 +=	-u $(LDDBGLIBDIR64) $(CONVLIBDIR64) \
		-erroff=E_NAME_DECL_NOT_USED_DEF2 \
		-erroff=E_CAST_INT_TO_SMALL_INT
ORIGIN =	'-R$$ORIGIN'
HSONAME =	-h$(SONAME)
DYNFLAGS +=	$(BDIRECT) $(VERSREF) \
		$(ZLAZYLOAD) $(MAPOPTS) $(USE_PROTO) $(ORIGIN)

$(VAR_POUND_3)DEFS=
$(VAR_POUND_3)native:=	MAPOPTS	=
native:=	DYNFLAGS	+= $(CONVLIBDIR)

BLTDEFS=	msg.h
BLTDATA=	msg.c
BLTMESG=	$(SGSMSGDIR)/libld

BLTFILES=	$(BLTDEFS) $(BLTDATA) $(BLTMESG)

SGSMSGCOM=	../common/libld.msg
SGSMSGSPARC=	../common/libld.sparc.msg
SGSMSGINTEL=	../common/libld.intel.msg
SGSMSGTARG=	$(SGSMSGCOM)
SGSMSGALL=	$(SGSMSGCOM) $(SGSMSGSPARC) $(SGSMSGINTEL)

SGSMSGFLAGS1=	$(SGSMSGFLAGS) -m $(BLTMESG)
SGSMSGFLAGS2=	$(SGSMSGFLAGS) -h $(BLTDEFS) -d $(BLTDATA) -n libld_msg

SRCS=		../common/llib-lld
LIBSRCS=	$(TOOLOBJS:%.o=$(SGSTOOLS)/common/%.c) \
		$(COMOBJS:%.o=../common/%.c) $(BLTDATA) \
		$(AVLOBJS:%.o=$(VAR_AVLDIR)/%.c) \
		$(G_MACHOBJS:%.o=$(SRCBASE)/uts/$(PLAT)/krtld/%.c)

LINTSRCS32 = $(L_MACHSRCS32)
LINTSRCS64 = $(L_MACHSRCS64)
LINTSRCS = $(LIBSRCS)

CLEANFILES +=	$(LINTOUTS) $(BLTFILES)
CLOBBERFILES +=	$(DYNLIB) $(LINTLIBS) $(LIBLINKS)

ROOTFS_DYNLIB=	$(DYNLIB:%=$(ROOTFS_LIBDIR)/%)
