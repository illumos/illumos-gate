#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/ldap/Makefile.com
# Native LDAP II commands (makestyle clean).
#
include $(SRC)/cmd/Makefile.cmd

LINTOUT=	lint.out

LDAPMOD=	ldapmodify
LDAPADD=	ldapadd
LDAPPROG=	ldapmodrdn ldapsearch ldapdelete $(LDAPMOD)
LDAPSRCS=	$(LDAPPROG:%=../common/%.c)
LDAPOBJS=	$(LDAPPROG:%=%.o)

#ldap common
# convutf8 used to be a C++ file, but there's no need.  It's all C code.
LDAPCOMM_CC=	# convutf8
LDAPCOMM_C=     common ldaptool-sasl fileurl convutf8
LDAPCOMM=       $(LDAPCOMM_C) $(LDAPCOMM_CC)
LDAPCOMMOBJS=   $(LDAPCOMM:%=%.o)

# LDAP Naming service commands
# idsconfig command
IDSCONFIGPROG=	idsconfig
IDSCONFIGSRC=	idsconfig.sh

# ldaplist command
LDAPLISTPROG=	ldaplist
LDAPLISTSRCS=	ldaplist.c mapping.c printResult.c
LDAPLISTOBJS=	$(LDAPLISTSRCS:%.c=%.o)

# ldapaddent command
LDAPADDENTPROG=	ldapaddent
LDAPADDENTSRCS=	ldapaddent.c ldapaddrbac.c
LDAPADDENTOBJS=	$(LDAPADDENTSRCS:%.c=%.o)

# ldapclient command
LDAPCLIENTPROG=	ldapclient
LDAPCLIENTSRCS=	ldapclient.c
LDAPCLIENTOBJS=	$(LDAPCLIENTSRCS:%.c=%.o)


NSLDAPOBJS=	$(LDAPLISTOBJS) $(LDAPADDENTOBJS) $(LDAPCLIENTOBJS)
NSLDAPSRCS=	$(LDAPLISTSRCS) $(LDAPADDENTSRCS) $(LDAPCLIENTSRCS)

OBJS=		$(LDAPOBJS) $(NSLDAPOBJS) $(LDAPCOMMOBJS)
SRCS=		$(LDAPSRCS) $(NSLDAPSRCS)
ROOTUSRSBIN=	$(ROOT)/usr/sbin
ROOTUSRLIBLDAP=	$(ROOT)/usr/lib/ldap

ROOTSCRIPT=	$(IDSCONFIGPROG:%=$(ROOTUSRLIBLDAP)/%)
ROOTSBIN=	$(LDAPADDENTPROG:%=$(ROOTUSRSBIN)/%) \
		$(LDAPCLIENTPROG:%=$(ROOTUSRSBIN)/%)

PROG=		$(LDAPPROG) $(LDAPLISTPROG)
ROOTADD=	$(ROOTBIN)/$(LDAPADD)
ROOTMOD=	$(ROOTBIN)/$(LDAPMOD)
ALLPROG=	all $(ROOTADD)

CLOBBERFILES += $(OBJS) $(PROG) $(LDAPCLIENTPROG) $(LDAPADDENTPROG) \
		$(IDSCONFIGPROG) $(LINTOUT)

# creating /var/ldap directory
ROOTVAR_LDAP=	$(ROOT)/var/ldap
$(ROOTVAR_LDAP) :=				OWNER=		root
$(ROOTVAR_LDAP) :=				GROUP=		sys

all:=           TARGET= all
install:=       TARGET= install
clean:=         TARGET= clean
clobber:=       TARGET= clobber
lint:=          TARGET= lint

CPPFLAGS +=	-DSUN -DSVR4 -D_SYS_STREAM_H -DSOLARIS_LDAP_CMD
CFLAGS +=	-I ../../../lib/libldap5/include/ldap \
		-I ../../../lib/libsldap/common \
		-I ../../../lib/libnsl/include/rpcsvc \
		-DNO_LIBLCACHE -DLDAP_REFERRALS -DNET_SSL -DLDAPSSLIO \
		-DHAVE_SASL_OPTIONS -DSOLARIS_LDAP_CMD
LINTFLAGS +=	-I ../../../lib/libldap5/include/ldap \
		-I ../../../lib/libsldap/common \
		-I ../../../lib/libnsl/include/rpcsvc
LDLIBS +=	$(COMPLIB)

ldapmodrdn :=	LDLIBS += -lldap
ldapsearch :=	LDLIBS += -lldap
ldapdelete :=	LDLIBS += -lldap
ldapmodify :=	LDLIBS += -lldap
ldaplist :=	LDLIBS += -lsldap
ldapaddent :=	LDLIBS += -lsldap -lnsl
ldapclient :=	LDLIBS += -lsldap -lscf

lint :=		LDLIBS += -lldap

.KEEP_STATE:

all:	$(PROG) $(LDAPCLIENTPROG) $(LDAPADDENTPROG) $(IDSCONFIGPROG)

$(LDAPADD):	$(LDAPMOD)
		@$(RM) $(LDAPADD); $(LN) $(LDAPMOD) $(LDAPADD)

$(LDAPPROG):	../common/$$@.c $(LDAPCOMMOBJS)
		$(LINK.c) -o $@ ../common/$@.c $(LDAPCOMMOBJS) $(LDLIBS)
		$(POST_PROCESS)

$(LDAPCOMM_CC:%=%.o):	../common/$$(@:%.o=%.cc)
		$(COMPILE.cc) -o $@ ../common/$(@:%.o=%.cc)
		$(POST_PROCESS_O)

$(LDAPCOMM_C%=%.o):	../common/$$(@:%.o=%.c)
		$(COMPILE.c) -o $@ ../common/$(@:%.o=%.c)
		$(POST_PROCESS_O)

%.o:		../common/%.c
		$(COMPILE.c) -o $@ $<
		$(POST_PROCESS_O)

%.o:		../ns_ldap/%.c
		$(COMPILE.c) -o $@ $<
		$(POST_PROCESS_O)

idsconfig:	../ns_ldap/$$@.sh
		$(CP) ../ns_ldap/$(IDSCONFIGSRC) $(IDSCONFIGPROG)
		$(CHMOD) 755 $(IDSCONFIGPROG)

ldaplist:	$(LDAPLISTOBJS)
		$(LINK.c) -o $@ $(LDAPLISTOBJS) $(LDLIBS)
		$(POST_PROCESS)

ldapaddent:	$(LDAPADDENTOBJS)
		$(LINK.c) -o $@ $(LDAPADDENTOBJS) $(LDLIBS)
		$(POST_PROCESS)

ldapclient:	$(LDAPCLIENTOBJS)
		$(LINK.c) -o $@ $(LDAPCLIENTOBJS) $(LDLIBS)
		$(POST_PROCESS)

install: all $(ROOTVAR_LDAP) $(ROOTUSRLIBLDAP) $(ROOTADD) $(ROOTSBIN) \
		$(ROOTSCRIPT)

$(ROOTUSRLIBLDAP):
		$(INS.dir)

$(ROOTVAR_LDAP):
		$(INS.dir)

$(ROOTADD):	$(ROOTPROG)
		$(RM) $@
		$(LN) $(ROOTMOD) $@

$(ROOTUSRLIBLDAP)/%:	%
		$(INS.file)

FRC:

clean:

lint: lintns_ldaplist lintns_ldapaddent lintns_ldapclient \
	$(LDAPPROG:%=lintc_%) $(LDAPMOD:%=lintc_%)

lintns_ldaplist:
	$(LINT.c) $(LDAPLISTSRCS:%=../ns_ldap/%) $(LDLIBS) -lsldap \
		> $(LINTOUT) 2>&1

lintns_ldapaddent:
	$(LINT.c) $(LDAPADDENTSRCS:%=../ns_ldap/%) $(LDLIBS) -lsldap -lnsl \
		>> $(LINTOUT) 2>&1

lintns_ldapclient:
	$(LINT.c) $(LDAPCLIENTSRCS:%=../ns_ldap/%) $(LDLIBS) -lsldap -lscf \
		>> $(LINTOUT) 2>&1

lintc_%:
	$(LINT.c) $(@:lintc_%=../common/%.c) $(LDAPCOMM) $(LDLIBS) \
		>> $(LINTOUT) 2>&1

include $(SRC)/cmd/Makefile.targ
