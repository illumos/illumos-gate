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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

include		../../../../../lib/Makefile.lib
include		../../../Makefile.com

CAP_LIB=	cap.so
CAP_OBJ=	cap_msg.o cap32.o cap64.o

DYN_LIB=	dyn.so
DYN_OBJ=	dyn_msg.o dyn32.o dyn64.o

EHDR_LIB=	ehdr.so
EHDR_OBJ=	ehdr_msg.o ehdr32.o ehdr64.o

PHDR_LIB=	phdr.so
PHDR_OBJ=	phdr_msg.o phdr32.o phdr64.o

SHDR_LIB=	shdr.so
SHDR_OBJ=	shdr_msg.o shdr32.o shdr64.o

STR_LIB=	str.so
STR_OBJ=	str_msg.o str32.o str64.o

SYM_LIB=	sym.so
SYM_OBJ=	sym_msg.o sym32.o sym64.o

SYMINFO_LIB=	syminfo.so
SYMINFO_OBJ=	syminfo_msg.o syminfo32.o syminfo64.o

ELFEDITLIBS=	$(CAP_LIB) $(DYN_LIB) $(EHDR_LIB) $(PHDR_LIB) \
		$(SHDR_LIB) $(STR_LIB) $(SYM_LIB) $(SYMINFO_LIB)

PICDIR=		pics

CAP_PICS=	$(CAP_OBJ:%.o=$(PICDIR)/%.o)
DYN_PICS=	$(DYN_OBJ:%.o=$(PICDIR)/%.o)
EHDR_PICS=	$(EHDR_OBJ:%.o=$(PICDIR)/%.o)
PHDR_PICS=	$(PHDR_OBJ:%.o=$(PICDIR)/%.o)
SHDR_PICS=	$(SHDR_OBJ:%.o=$(PICDIR)/%.o)
STR_PICS=	$(STR_OBJ:%.o=$(PICDIR)/%.o)
SYM_PICS=	$(SYM_OBJ:%.o=$(PICDIR)/%.o)
SYMINFO_PICS=	$(SYMINFO_OBJ:%.o=$(PICDIR)/%.o)

LDLIBS +=	$(ELFLIBDIR) -lelf $(LDDBGLIBDIR) -llddbg \
		$(CONVLIBDIR) -lconv -lc

$(CAP_LIB):=		PICS = $(CAP_PICS)
$(DYN_LIB):=		PICS = $(DYN_PICS)
$(EHDR_LIB):=		PICS = $(EHDR_PICS)
$(PHDR_LIB):=		PICS = $(PHDR_PICS)
$(SHDR_LIB):=		PICS = $(SHDR_PICS)
$(STR_LIB):=		PICS = $(STR_PICS)
$(SYM_LIB):=		PICS = $(SYM_PICS)
$(SYMINFO_LIB):=	PICS = $(SYMINFO_PICS)

$(CAP_LIB):=		SONAME = $(CAP_LIB)
$(DYN_LIB):=		SONAME = $(DYN_LIB)
$(EHDR_LIB):=		SONAME = $(EHDR_LIB)
$(PHDR_LIB):=		SONAME = $(PHDR_LIB)
$(SHDR_LIB):=		SONAME = $(SHDR_LIB)
$(STR_LIB):=		SONAME = $(STR_LIB)
$(SYM_LIB):=		SONAME = $(SYM_LIB)
$(SYMINFO_LIB):=	SONAME = $(SYMINFO_LIB)

# All the modules use a shared mapfile
MAPFILES = ../common/mapfile-vers

CPPFLAGS +=	-I../../../include -I../../../include/$(MACH) \
		-I$(SRC)/lib/libc/inc  -D_REENTRANT
LLDFLAGS =	'-R$$ORIGIN/../../../lib'
LLDFLAGS64 =	'-R$$ORIGIN/../../../../lib/$(MACH64)'
LDFLAGS +=	$(LLDFLAGS)
DYNFLAGS +=	$(VERSREF)

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	$(CNOWARN_UNINIT)

BLTDEFS =	$(ELFEDITLIBS:%.so=%_msg.h)
BLTDATA =	$(ELFEDITLIBS:%.so=%_msg.c)
BLTFILES =	$(BLTDEFS) $(BLTDATA)

CLEANFILES +=	$(BLTFILES) $(PICDIR)/*
CLOBBERFILES +=	$(ELFEDITLIBS)

ROOTELFEDITDIR=		$(ROOT)/usr/lib/elfedit
ROOTELFEDITDIR64=	$(ROOT)/usr/lib/elfedit/$(MACH64)
ROOTELFEDITLIBS=	$(ROOTELFEDITDIR)/$(MTARG)$(CAP_LIB) \
			$(ROOTELFEDITDIR)/$(MTARG)$(DYN_LIB) \
			$(ROOTELFEDITDIR)/$(MTARG)$(EHDR_LIB) \
			$(ROOTELFEDITDIR)/$(MTARG)$(PHDR_LIB) \
			$(ROOTELFEDITDIR)/$(MTARG)$(SHDR_LIB) \
			$(ROOTELFEDITDIR)/$(MTARG)$(STR_LIB) \
			$(ROOTELFEDITDIR)/$(MTARG)$(SYM_LIB) \
			$(ROOTELFEDITDIR)/$(MTARG)$(SYMINFO_LIB)


FILEMODE=	0755

.PARALLEL:	$(ELFEDITLIBS)
