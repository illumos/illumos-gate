#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/ss/Makefile.com
#

LIBRARY= libss.a
VERS= .1

SSOBJS= \
	data.o \
	error.o \
	execute_cmd.o \
	help.o \
	invocation.o \
	list_rqs.o \
	listen.o \
	pager.o \
	parse.o \
	prompt.o \
	request_tbl.o \
	requests.o \
	std_rqs.o

OBJECTS= $(SSOBJS)

# include library definitions
include ../../Makefile.lib

SRCS=	$(SSOBJS:%.o=../%.c)

LIBS=		$(DYNLIB)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS +=     -DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 -DHAS_STRDUP=1 \
		-DUSE_DIRENT_H=1 -DWAIT_USES_INT=1 -DPOSIX_SIGNALS=1 \
		-D_REENTRANT -DUSE_SIGPROCMASK=1 -DRETSIGTYPE=void \
		-DHAVE_STDARG_H=1 -DHAVE_STDLIB_H=1 -DHAVE_COMPILE=1 \
		-DHAVE_UNISTD_H=1 -DHAVE_UMASK=1 -DHAVE_SRAND48=1 \
		-DHAVESRAND=1 -DHAVESRANDOM=1 -DHAVE_RE_COMP=1 \
		-DHAVE_RE_EXEC=1 -DHAVE_REGCOMP=1 -DHAVE_REGEXEC=1 \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/krb5

CFLAGS +=	$(CCVERBOSE) -I..

DYNFLAGS +=	$(KRUNPATH) $(KMECHLIB)

LDLIBS +=	-lc

$(PICS) :=      CFLAGS += $(XFFLAG)

.KEEP_STATE:

all:	$(LIBS)

lint: lintcheck

$(DYNLIB):	$(MAPFILE)

$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile

# include library targets
include ../../Makefile.targ
