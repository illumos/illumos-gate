#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.
#

include		../../Makefile.cmd

PROG =		eqn

CSRCS =		diacrit.c eqnbox.c font.c fromto.c funny.c	\
		glob.c integral.c io.c lex.c lookup.c		\
		mark.c matrix.c move.c over.c paren.c		\
		pile.c shift.c size.c sqrt.c text.c

SRCS =		$(CSRCS:%=../%)

YACCSRC =	e.y

COBJS =		$(CSRCS:%.c=%.o)
OBJS =		$(YACCSRC:%.y=%.o) $(COBJS)

#
# for message catalog
#
POFILE= eqn.d.po
POFILES= $(SRCS:%.c=%.po) e.po

CLEANFILES =	y.tab.c y.tab.h $(YACCSRC:%.y=%.c) $(YACCSRC:%.y=%.def)

YFLAGS =	-d
CPPFLAGS =	-I. -I.. $(CPPFLAGS.master)
LDFLAGS +=	$(MAPFILE.NGB:%=-Wl,-M%)

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	$(CNOWARN_UNINIT)

# because of labels from yacc
e.o := CERRWARN += -_gcc=-Wno-unused-label

# not linted
SMATCH=off

.KEEP_STATE:

all :		$(PROG)

catalog:        $(POFILE)

$(POFILE):      e.def $(POFILES)
	$(RM)	$@
	cat     $(POFILES)      > $@

$(PROG) :	$(OBJS) $(MAPFILE.NGB)
		$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
		$(POST_PROCESS)

$(YACCSRC:%.y=%.c) + $(YACCSRC:%.y=%.def) : ../$(YACCSRC)
		$(YACC.y) ../$(YACCSRC)
		$(MV) y.tab.c $(YACCSRC:%.y=%.c)
		$(MV) y.tab.h $(YACCSRC:%.y=%.def)

$(COBJS) :	$$(@:%.o=../%.c)
		$(COMPILE.c) ../$(@:%.o=%.c)

install :	all $(ROOTPROG)

clean:
		$(RM) $(OBJS) $(CLEANFILES)

include		../../Makefile.targ
