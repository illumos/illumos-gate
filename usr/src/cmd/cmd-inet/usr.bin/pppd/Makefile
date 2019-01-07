#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/cmd-inet/usr.bin/pppd/Makefile
#
# Copyright (c) 2019, Joyent, Inc.

include		../../../Makefile.cmd
include		Makefile.def

PROG=		pppd
SUBDIRS=	plugins
OBJS=		auth.o ccp.o chap.o demand.o fsm.o ipcp.o ipv6cp.o \
		lcp.o magic.o main.o options.o sys-solaris.o upap.o utils.o \
		multilink.o cbcp.o

# Object tdb.o used only for Multilink; not supported yet.

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint

LDLIBS +=	-lpam -lmd -lsocket -lnsl -ldlpi

#
# We need absolute path to /etc/ppp/plugins and /usr/lib/inet/ppp, not
# that of the proto area
#
LDFLAGS +=	-R$(ETCPPPPLUGINDIR_ABS) -R$(LIBPPPPLUGINDIR_ABS)

CPPFLAGS +=	-DPLUGIN -DSVR4 -DSOL2 -DINET6
CPPFLAGS +=	-D_PATH_VARRUN='"/var/run/"'
CPPFLAGS +=	-DNEGOTIATE_FCS -DCBCP_SUPPORT -DALLOW_PAM -DHAS_SHADOW
CPPFLAGS +=	-DHAVE_MMAP -DCOMP_TUNE -DMUX_FRAME
$(NOT_RELEASE_BUILD)CPPFLAGS +=	-DDEBUG

.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all:		$(PROG) $(SUBDIRS)

# MS-CHAP support
CPPFLAGS +=	-DHAVE_CRYPT_H -DUSE_CRYPT -DHAVE_LIBMD
CPPFLAGS +=	-DCHAPMS -DMSLANMAN
CPPFLAGS +=	-DCHAPMSV2
OBJS +=		chap_ms.o
EXOBJS +=	mschap_test.o
CLOBBERFILES +=	mschap_test

CERRWARN +=	-_gcc=-Wno-uninitialized

# main() is too hairy for smatch
SMATCH=off

# This is used *only* for testing the portability of the libraries
# required for MS-CHAPv1.  It is not needed in any normal system and
# is not built by default.
mschap_test:	mschap_test.o chap_ms.o
	$(LINK.c) -o mschap_test mschap_test.o chap_ms.o $(LDFLAGS) -lmd
	@echo "Run with 'mschap_test 00000000000000000000000000000000 hello'"
	@echo
	@echo "Output should be:"
	@echo
	@echo " MS-CHAPv1 with LAN Manager -- 49 bytes:"
	@echo "  C9 CA EE 9B 1C A7 87 04"
	@echo "  79 36 8C 55 AB 88 EC 5A"
	@echo "  57 E9 A1 B7 95 40 C3 74"
	@echo "  F4 D9 9D AF 82 64 DC 3C"
	@echo "  53 F9 BC 92 14 B5 5D 9E"
	@echo "  78 C4 21 48 9D B7 A8 B4"
	@echo "  01"
	@echo "  MS-CHAPv2 -- 49 bytes:"
	@echo "  xx xx xx xx xx xx xx xx"
	@echo "  xx xx xx xx xx xx xx xx"
	@echo "  00 00 00 00 00 00 00 00"
	@echo "  xx xx xx xx xx xx xx xx"
	@echo "  xx xx xx xx xx xx xx xx"
	@echo "  xx xx xx xx xx xx xx xx"
	@echo "  00"

LINTFLAGS +=	-erroff=E_NAME_DEF_NOT_USED2

SRCS=		$(OBJS:%.o=%.c)

.PARALLEL:	$(OBJS)

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ROOTPROG):=	FILEMODE = 04555

ASPPP2PPPD=	$(ROOTUSRSBIN)/asppp2pppd
$(ASPPP2PPPD):=	FILEMODE = 0550

install:	$(PROG) .WAIT $(SUBDIRS) $(ROOTPROG) $(ETCPPPDIR) $(ASPPP2PPPD)

$(ETCPPPDIR)/%:	%
	$(INS.file)

$(ETCPPPDIR):
	$(INS.dir)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

LINTOBJS=$(OBJS:%.o=%.ln)
CLOBBERFILES +=	$(LINTOBJS)

clean:		$(SUBDIRS)
	$(RM) $(OBJS) $(EXOBJS)

sha1.ln:=	LINTFLAGS += -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED

# Not using the default lint target here so that we can disable
# warnings per module as needed.
lint:		$(SUBDIRS) $(LINTOBJS)
	$(LINT.c) $(LINTOBJS) $(LDLIBS)

clobber:	$(SUBDIRS)

include		../../../Makefile.targ
