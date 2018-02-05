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
# Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
#
# cmd/ldap/Makefile.com
# Native LDAP II commands (makestyle clean).
#
include $(SRC)/cmd/Makefile.cmd

LDAPMOD=	ldapmodify
LDAPADD=	ldapadd
LDAPPROG=	ldapmodrdn ldapsearch ldapdelete $(LDAPMOD)
LDAPSRCS=	$(LDAPPROG:%=../common/%.c)
LDAPOBJS=	$(LDAPPROG:%=%.o)

#ldap common
LDAPCOMMSRC=	common.c ldaptool-sasl.c fileurl.c convutf8.c
LDAPCOMMOBJS=	$(LDAPCOMMSRC:%.c=%.o)

# LDAP Naming service commands
# idsconfig command
IDSCONFIGPROG=	idsconfig
IDSCONFIGSRC=	idsconfig.sh

# ldaplist command
LDAPLISTPROG=	ldaplist
LDAPLISTSRCS=	ldaplist.c mapping.c printResult.c standalone.c
LDAPLISTOBJS=	$(LDAPLISTSRCS:%.c=%.o)

# ldapaddent command
LDAPADDENTPROG=	ldapaddent
LDAPADDENTSRCS=	ldapaddent.c ldapaddrbac.c ldapaddtsol.c standalone.c
LDAPADDENTOBJS=	$(LDAPADDENTSRCS:%.c=%.o)

# ldapclient command
LDAPCLIENTPROG=	ldapclient
LDAPCLIENTSRCS=	ldapclient.c standalone.c
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

LINTFLAGS += -erroff=E_INCONS_ARG_DECL2
LINTFLAGS += -erroff=E_INCONS_VAL_TYPE_DECL2

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized

all:=           TARGET= all
install:=       TARGET= install
clean:=         TARGET= clean
clobber:=       TARGET= clobber
lint:=          TARGET= lint

# C Pre-Processor flags used by C, CC & lint
CPPFLAGS +=	-DSUN -DSVR4 -DSOLARIS_LDAP_CMD \
		-I $(SRC)/lib/libldap5/include/ldap \
		-I $(SRC)/lib/libsldap/common \
		-I $(SRC)/lib/libnsl/include/rpcsvc \
		-DNO_LIBLCACHE -DLDAP_REFERRALS -DNET_SSL -DLDAPSSLIO \
		-DHAVE_SASL_OPTIONS -DSOLARIS_LDAP_CMD
LDLIBS +=	$(COMPLIB)

ldapmodrdn :=	LDLIBS += -lldap
ldapsearch :=	LDLIBS += -lldap
ldapdelete :=	LDLIBS += -lldap
ldapmodify :=	LDLIBS += -lldap
ldaplist :=	LDLIBS += -lsldap
ldapaddent :=	LDLIBS += -lsldap -lnsl -lsecdb
ldapclient :=	LDLIBS += -lsldap -lscf

ldaplist :=	CSTD = $(CSTD_GNU99)
ldapaddent :=	CSTD = $(CSTD_GNU99)
ldapclient :=	CSTD = $(CSTD_GNU99)

lint :=		LDLIBS += -lldap

.KEEP_STATE:

all:	$(PROG) $(LDAPCLIENTPROG) $(LDAPADDENTPROG) $(IDSCONFIGPROG)

$(LDAPADD):	$(LDAPMOD)
		@$(RM) $(LDAPADD); $(LN) $(LDAPMOD) $(LDAPADD)

$(LDAPPROG):	../common/$$@.c $(LDAPCOMMOBJS)
		$(LINK.c) -o $@ ../common/$@.c $(LDAPCOMMOBJS) $(LDLIBS)
		$(POST_PROCESS)

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
	$(RM) $(OBJS)

# Not linted Mozilla upstream commands
lint: lintns_ldaplist lintns_ldapaddent lintns_ldapclient

lintns_ldaplist := CSTD = $(CSTD_GNU99)

lintns_ldaplist:
	$(LINT.c) $(LDAPLISTSRCS:%=../ns_ldap/%) $(LDLIBS) -lsldap

lintns_ldapaddent := CSTD = $(CSTD_GNU99)

lintns_ldapaddent:
	$(LINT.c) $(LDAPADDENTSRCS:%=../ns_ldap/%) $(LDLIBS) -lsldap -lnsl \
		-lsecdb

lintns_ldapclient := CSTD = $(CSTD_GNU99)

lintns_ldapclient:
	$(LINT.c) $(LDAPCLIENTSRCS:%=../ns_ldap/%) $(LDLIBS) -lsldap -lscf

lintc_%:
	$(LINT.c) $(@:lintc_%=../common/%.c) $(LDAPCOMMSRC:%=../common/%) \
		 $(LDLIBS)

include $(SRC)/cmd/Makefile.targ
