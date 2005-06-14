#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1996 by Sun Microsystems, Inc.
# All Rights Reserved.
#

all:	libs

include ../../Makefile.cmd
include ../Makefile.cmd

LIBNAME=	libparse

SOURCE=	parse.c parse_conf.c clk_meinberg.c clk_schmid.c clk_rawdcf.c \
	clk_dcf7000.c clk_trimtaip.c clk_trimtsip.c clk_rcc8000.c

OBJS=	parse.o parse_conf.o clk_meinberg.o clk_schmid.o clk_rawdcf.o \
	clk_dcf7000.o clk_trimtaip.o clk_trimtsip.o clk_rcc8000.o

install: all

libs: $(LIBNAME).a

$(LIBNAME).a:	$(OBJS)
	$(AR) r $@ $(OBJS)

$(OBJS) :=	CLOCKDEFS += -UPARSESTREAM
$(OBJS) :=	CFLAGS += $(CLOCKDEFS)

lintlib:	llib-l$(LIBNAME).ln

llib-l$(LIBNAME).ln:	$(SOURCE)
	$(LINT.c) -C$(LIBNAME) $(INCL) $(CLOCKDEFS) $(AUTHDEFS) $(LIBDEFS) $(SOURCE) >lintlib.errs

lint:
	$(LINT.c) -u $(DEFS) $(INCL) $(CLOCKDEFS) $(AUTHDEFS) $(LIBDEFS) $(SOURCE) >lint.errs

clobber clean:
	$(RM) $(OBJS) $(LIBNAME).a lint.errs lintlib.errs llib-l$(LIBNAME).ln

.PARALLEL:
