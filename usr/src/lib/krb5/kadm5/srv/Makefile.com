#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/kadm5/srv/Makefile.com
#

LIBRARY= libkadm5srv.a
VERS= .1

SRV_OBJS = svr_policy.o \
        svr_principal.o \
        server_acl.o \
        server_kdb.o \
        server_misc.o \
        server_init.o \
        server_dict.o \
        svr_iters.o \
        svr_chpass_util.o \
        adb_xdr.o \
        adb_policy.o \
        adb_free.o \
        adb_openclose.o	\
	xdr_alloc.o \
	logger.o \
	chgpwd.o

SHARED_OBJS =  \
        misc_free.o \
        kadm_rpc_xdr.o \
        chpass_util.o \
        alt_prof.o \
	kadm_host_srv_names.o \
        str_conv.o

OBJECTS= $(SHARED_OBJS) $(SRV_OBJS)

# include library definitions
include ../../../Makefile.lib

SRCS=		$(SRV_OBJS:%.o=../%.c) \
		$(SHARED_OBJS:%.o=../../%.c)

KRB5LIB= 	$(ROOT)/usr/lib/krb5
LIBS=		$(DYNLIB)


include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(LIBRARY:%.a=%.po)
POFILES = generic.po

#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS += -I.. -I../.. -I../../.. \
	-I$(SRC)/lib/krb5/kdb \
	-I$(SRC)/cmd/krb5/iprop \
	-I$(SRC)/lib/gss_mechs/mech_krb5/include \
	-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
	-I$(SRC)/uts/common/gssapi/include/ \
	-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
	-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/os \
	-DHAVE_STDLIB_H -DUSE_SOLARIS_SHARED_LIBRARIES \
	-DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 -DSETRPCENT_TYPE=void \
	-DENDRPCENT_TYPE=void -DHAVE_SYS_ERRLIST=1 -DNEED_SYS_ERRLIST=1 \
	-DHAVE_SYSLOG_H=1 -DHAVE_OPENLOG=1 -DHAVE_SYSLOG=1 -DHAVE_CLOSELOG=1 \
	-DHAVE_STEP=1 -DHAVE_RE_COMP=1 -DHAVE_RE_EXEC=1 -DHAVE_REGCOMP=1 \
	-DHAVE_REGEXEC=1 -DHAVE_STRFTIME=1 -DHAVE_VSPRINTF=1

CFLAGS +=	$(CCVERBOSE) -I..

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

$(DYNLIB):	$(MAPFILE)

$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile

# include library targets
include ../../../Makefile.targ

pics/%.o: ../../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

FRC:

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../*.[ch] ../../*.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
