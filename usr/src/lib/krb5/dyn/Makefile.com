#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/dyn/Makefile.com
#

LIBRARY= libdyn.a
VERS= .1

DYNOBJS= \
	dyn_create.o \
        dyn_put.o \
        dyn_debug.o \
        dyn_delete.o \
        dyn_size.o \
        dyn_append.o \
        dyn_realloc.o \
        dyn_paranoid.o \
        dyn_insert.o \
        dyn_initzero.o

OBJECTS= $(DYNOBJS)

# include library definitions
include ../../Makefile.lib

SRCS=	$(DYNOBJS:%.o=../%.c)
LIBS=		$(DYNLIB)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5


#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS +=     -D_REENTRANT -DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 \
		-DHAVE_UNISTD_H=1 -DHAVE_UMASK=1 -DHAVE_SRAND48=1 \
		-DHAVESRAND=1 -DHAVESRANDOM=1 -DHAVE_RE_COMP=1 \
		-DHAVE_RE_EXEC=1 -DHAVE_REGCOMP=1 -DHAVE_REGEXEC=1 \
		-DHAVE_COMPILE=1

CFLAGS +=	$(CCVERBOSE) -I..
LDLIBS +=	-lc

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

$(DYNLIB):	$(MAPFILE)

$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile

# include library targets
include ../../Makefile.targ

FRC:
