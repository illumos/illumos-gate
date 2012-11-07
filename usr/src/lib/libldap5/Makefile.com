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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY= libldap.a
VERS= .5

# Definition of all the objects macros
# The LDAP specific objects

BEROBJS=	bprint.o	decode.o 	encode.o       io.o

LDAPOBJS=  abandon.o add.o bind.o cache.o charray.o \
        charset.o compare.o compat.o control.o countvalues.o \
        delete.o disptmpl.o dsparse.o error.o extendop.o free.o freevalues.o \
        friendly.o getattr.o getdn.o getdxbyname.o getentry.o \
        getfilter.o getoption.o getvalues.o memcache.o message.o \
        modify.o open.o os-ip.o proxyauthctrl.o psearch.o referral.o \
        rename.o request.o reslist.o result.o saslbind.o sasl.o \
        sbind.o search.o setoption.o sort.o sortctrl.o srchpref.o \
        tmplout.o ufn.o unbind.o unescape.o url.o ldaputf8.o vlistctrl.o \
        cram_md5.o secutil.o spagectrl.o digest_md5.o

SSLDAPOBJS=	clientinit.o ldapsinit.o errormap.o

PRLDAPOBJS=	ldappr-dns.o	ldappr-error.o	ldappr-public.o \
		ldappr-io.o	ldappr-threads.o

UTILOBJS= log.o line64.o

# Grouping it all together
OBJECTS=	$(BEROBJS) $(LDAPOBJS) $(SSLDAPOBJS) $(PRLDAPOBJS) \
		$(UTILOBJS)

# include library definitions
include ../../Makefile.lib

NSS_LIBS=	-lnspr4 -lplc4 -lnss3 -lssl3
NSS_HDRS=	$(ADJUNCT_PROTO)/usr/include/mps
NSS_LDPATH=	/usr/lib/mps
NSS_LDPATH64=	$(NSS_LDPATH)/64	


LDAP_FLAGS=     -DSVR4 -DSYSV -D__svr4 -D__svr4__ -DSOLARIS \
                -D_SOLARIS_SDK \
                -DUSE_WAITPID -DNEEDPROTOS \
                -DNET_SSL  -DNO_LIBLCACHE -DLDAP_REFERRALS \
                -DNS_DOMESTIC -DLDAP_SSLIO_HOOKS -DSTR_TRANSLATION \
                -DLDAP_SASLIO_HOOKS


# Include directories for all files
COM_INC=	-I$(SRC)/lib/libldap5/include/ldap \
		-I$(NSS_HDRS)

SRCS=		$(BEROBJS:%.o=../sources/ldap/ber/%.c) \
		$(LDAPOBJS:%.o=../sources/ldap/common/%.c) \
		$(SSLDAPOBJS:%.o=../sources/ldap/ssldap/%.c) \
		$(PRLDAPOBJS:%.o=../sources/ldap/prldap/%.c) \
		$(UTILOBJS:%.o=../sources/ldap/util/%.c)

LIBS =		$(DYNLIB) $(LINTLIB)
DYNFLAGS +=	$(ZNODELETE)

CPPFLAGS=	$(COM_INC) $(CPPFLAGS.master)

# definitions for lint

$(LINTLIB):= 	SRCS=../sources/ldap/common/llib-lldap
$(LINTLIB):= 	LINTFLAGS=-nvx 
$(LINTLIB):= 	TARGET_ARCH=

LINTOUT=	lint.out

LINTSRC=	$(LINTLIB:%.ln=%)
ROOTLINTDIR=	$(ROOTLIBDIR)
ROOTLINT=	$(LINTSRC:%=$(ROOTLINTDIR)/%)


CLEANFILES += 	$(LINTOUT) $(LINTLIB)

# Local Libldap definitions
LOCFLAGS +=	 $(XSTRCONST) -D_REENTRANT

# Following values defined in Makefile.master are overwritten here.
#sparc_C_PICFLAGS =	$(sparc_C_BIGPICFLAGS)
sparcv9_C_PICFLAGS =	$(sparcv9_C_BIGPICFLAGS)
#i386_C_PICFLAGS =	$(i386_C_BIGPICFLAGS)
#amd64_C_PICFLAGS =	$(amd64_C_BIGPICFLAGS)

CFLAGS +=	$(CCVERBOSE) $(LOCFLAGS)
CFLAGS64 +=	$(LOCFLAGS)

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-type-limits
CERRWARN +=	-_gcc=-Wno-unused-function
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-unused-value
CERRWARN +=	-_gcc=-Wno-address

LDLIBS +=	-lsasl -lsocket -lnsl -lmd -lc

.KEEP_STATE:

# include library targets
include ../../Makefile.targ

pics/%.o: ../sources/ldap/ber/%.c
	$(COMPILE.c) $(LDAP_FLAGS) $(COM_INC) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../sources/ldap/common/%.c
	$(COMPILE.c) $(LDAP_FLAGS) $(COM_INC) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../sources/ldap/ssldap/%.c
	$(COMPILE.c) $(LDAP_FLAGS) $(COM_INC) -w -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../sources/ldap/prldap/%.c
	$(COMPILE.c) $(LDAP_FLAGS) $(COM_INC) -w -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../sources/ldap/util/%.c
	$(COMPILE.c) $(LDAP_FLAGS) $(COM_INC) -w -o $@ $<
	$(POST_PROCESS_O)

# install rule for lint library target
$(ROOTLINTDIR)/%: ../sources/ldap/common/%
	$(INS.file)
