#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libldap4/Makefile.com
#

LIBRARY= libldap.a
VERS= .4

LDAPOBJS=	abandon.o             getentry.o            referral.o \
		add.o                 getfilter.o           regex.o \
		addentry.o            getmsg.o              rename.o \
		bind.o                getref.o              request.o \
		cache.o               getvalues.o           result.o \
		charset.o             kbind.o               saslbind.o \
		cldap.o               sbind.o 		    compare.o    \
		search.o 	      controls.o            sort.o \
		delete.o              srchpref.o	    disptmpl.o \
		tmplout.o 	      dsparse.o             \
		error.o               ufn.o \
		extensions.o          unbind.o 	            extop.o    \
		url.o         \
		free.o   modify.o              utils.o \
		friendly.o            modrdn.o    notif.o    Version.o \
		getattr.o             open.o                \
		getdn.o               option.o \
		getdxbyname.o         os-ip.o               sortctrl.o \
		vlistctrl.o

BEROBJS=	bprint.o	      decode.o \
		encode.o 	   \
		io.o		      i18n.o

UTILOBJS=	line64.o	log.o


SECOBJS=	cram_md5.o	secutil.o

OBJECTS=	$(LDAPOBJS)	$(BEROBJS)	$(UTILOBJS)	$(SECOBJS)

include ../../Makefile.lib

LDAPINC=	$(SRC)/lib/libldap4/include
LDAP_FLAGS=	-DLDAP_REFERRALS -DCLDAP -DLDAP_DNS -DSUN

MAPFILE=	$(MAPDIR)/mapfile

SRCS=		$(LDAPOBJS:%.o=../common/%.c)	$(BEROBJS:%.o=../ber/%.c) \
		$(UTILOBJS:%.o=../util/%.c)	$(SECOBJS:%.o=../sec/%.c) 

LIBS =		$(DYNLIB)

$(LINTLIB):= 	SRCS=../common/llib-lldap

LINTSRC=	$(LINTLIB:%.ln=%)
ROOTLINTDIR=	$(ROOTLIBDIR)
ROOTLINT=	$(LINTSRC:%=$(ROOTLINTDIR)/%)


CLEANFILES += 	$(LINTOUT) $(LINTLIB)
CLOBBERFILES +=	$(MAPFILE)

# Local Libldap definitions

LOCFLAGS +=	-D_SYS_STREAM_H -D_REENTRANT -DSVR4 -DSUNW_OPTIONS \
		-DTHREAD_SUNOS5_LWP -DSOUNDEX -DSTR_TRANSLATION \
		$(LDAP_FLAGS) -I$(LDAPINC)

CPPFLAGS =	$(LOCFLAGS) $(CPPFLAGS.master)
CFLAGS +=	$(CCVERBOSE)
DYNFLAGS +=	-M $(MAPFILE)
LDLIBS +=	-lsocket -lnsl -lresolv -lc -lmd

.KEEP_STATE:

lint: lintcheck

$(DYNLIB):	$(MAPFILE)

$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile

# include library targets
include ../../Makefile.targ

objs/%.o pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: ../ber/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: ../util/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

objs/%.o pics/%.o: ../sec/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)
