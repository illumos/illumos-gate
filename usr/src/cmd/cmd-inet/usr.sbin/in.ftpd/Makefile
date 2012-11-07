#
# Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
#

PROG=		in.ftpd ftpcount ftpshut ftprestart privatepw
SCRIPTS=	ftpaddhost ftpconfig
MANIFEST=	ftp.xml
SVCMETHOD=	svc-ftp

include		../../../Makefile.cmd

COMMON_OBJS=	COPYRIGHT.o vers.o
FTPD_OBJS=	$(COMMON_OBJS) ftpd.o ftpcmd.o glob.o logwtmp.o popen.o \
		access.o extensions.o realpath.o acl.o private.o \
		authenticate.o conversions.o rdservers.o paths.o hostacc.o \
		routevector.o restrict.o domain.o wu_fnmatch.o timeout.o \
		getpwnam.o inet.o xferlog.o gssutil.o privs.o
FTPCOUNT_OBJS=	$(COMMON_OBJS) ftpcount.o rdservers.o inet.o
FTPSHUT_OBJS=	$(COMMON_OBJS) ftpshut.o rdservers.o inet.o
FTPREST_OBJS=	$(COMMON_OBJS) ftprestart.o rdservers.o inet.o
CKCONFIG_OBJS=	$(COMMON_OBJS) ckconfig.o rdservers.o inet.o
PRIVATE_OBJS=	$(COMMON_OBJS) privatepw.o
OBJS=		$(FTPD_OBJS) ftpcount.o ftpshut.o ftprestart.o ckconfig.o \
		privatepw.o
SRCS=		$(OBJS:%.o=%.c)
CONFIGFILES=	ftpaccess ftpconversions ftpgroups ftphosts ftpservers ftpusers
ETCFTPDDIR=	$(ROOTETC)/ftpd
ETCFTPDFILES=	$(CONFIGFILES:%=$(ETCFTPDDIR)/%)
$(ETCFTPDFILES):=	FILEMODE= 0644
ROOTUSRSBINSCRIPTS=	$(SCRIPTS:%=$(ROOTUSRSBIN)/%)
ROOTFTPCOUNT=	$(ROOTUSRSBIN)/ftpcount
ROOTFTPWHO=	$(ROOTUSRSBIN)/ftpwho

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)

# I18n
POFILE=		in.ftpd_all.po
POFILES=	$(SCRIPTS:%=%.po)

# When building for Solaris 8 add to CPPFLAGS:
# -Ddn_skipname=__dn_skipname -DSOLARIS_NO_AUDIT_FTPD_LOGOUT
CLOBBERFILES +=	ckconfig ftpwho $(SCRIPTS)
CPPFLAGS +=	-DBSD_COMP -D_FILE_OFFSET_BITS=64 -DINET6 -DSOLARIS_BSM_AUDIT \
		-DSOLARIS_ETC_FTPUSERS -DSENDFILE -DCLOSEFROM -DUSE_GSS \
		-DSOLARIS_GSS_USEROK -DSOLARIS_PRIVS
LDLIBS +=	-lsocket -lnsl -lpam -lbsm -lsendfile -lgss
YFLAGS +=	-d

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-clobbered
CERRWARN +=	-_gcc=-Wno-address

in.ftpd :=	LDFLAGS += $(MAPFILE.NGB:%=-M%)

# tcov output relies on atexit(3C) registered functions being called, so stop
# _exit() from being used. Passing -l to yacc stops it generating #line
# directives which don't work with tcov.
tcov :=		CFLAGS += -xa
tcov :=		CPPFLAGS += -D_exit=exit
tcov :=		YFLAGS += -l

.KEEP_STATE:

all tcov:	$(PROG) ckconfig ftpwho $(CONFIGFILES) $(SCRIPTS)

in.ftpd:	$(FTPD_OBJS) $(MAPFILE.NGB)
		$(LINK.c) $(FTPD_OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

ftpcount:	$(FTPCOUNT_OBJS)
		$(LINK.c) $(FTPCOUNT_OBJS) -o $@ -lsocket -lnsl
		$(POST_PROCESS)

ftpwho:		ftpcount
		$(RM) $@
		$(LN) ftpcount $@

ftpshut:	$(FTPSHUT_OBJS)
		$(LINK.c) $(FTPSHUT_OBJS) -o $@ -lsocket -lnsl
		$(POST_PROCESS)

ftprestart:	$(FTPREST_OBJS)
		$(LINK.c) $(FTPREST_OBJS) -o $@ -lsocket -lnsl
		$(POST_PROCESS)

ckconfig:	$(CKCONFIG_OBJS)
		$(LINK.c) $(CKCONFIG_OBJS) -o $@ -lsocket -lnsl
		$(POST_PROCESS)

privatepw:	$(PRIVATE_OBJS)
		$(LINK.c) $(PRIVATE_OBJS) -o $@
		$(POST_PROCESS)

# This causes y.tab.c to be renamed to ftpcmd.c, needed by tcov.
ftpcmd.c:	ftpcmd.y

$(ETCFTPDDIR)/%: %
		$(INS.file)

$(POFILE):	$(POFILES)
		$(RM) $@
		cat $(POFILES) >$@

$(ROOTFTPWHO):	$(ROOTFTPCOUNT)
		$(RM) $@
		$(LN) $(ROOTFTPCOUNT) $@

install:	all $(ROOTUSRSBINPROG) $(ROOTFTPWHO) $(ROOTUSRSBINSCRIPTS) \
		$(ETCFTPDFILES) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:		$(CHKMANIFEST)

clean:
		$(RM) $(OBJS) *.d *.tcov y.tab.h y.tab.c ftpcmd.c

lint:		lint_SRCS

include		../../../Makefile.targ
