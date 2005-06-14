#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/kdb/Makefile.com
#

LIBRARY= libkdb.a
VERS= .1

# kdb
KDBOBJS= \
        keytab.o \
        encrypt_key.o \
        decrypt_key.o \
	kdb_convert.o \
        kdb_cpw.o \
        kdb_db2.o \
	kdb_log.o \
        kdb_xdr.o \
        verify_mky.o \
        fetch_mkey.o \
        setup_mkey.o \
        store_mkey.o

DERIVED_OBJS= \
	iprop_xdr.o

# Definitions needed to rpcgen iprop-related files
ISRCHDR= ../iprop.h
ISRCXDR= ../iprop_xdr.c
KRB5IPROPDIR=	$(SRC)/cmd/krb5/iprop
CMD= grep -v "usr/src/cmd/krb5/iprop" > $@

# libkdb5 needs to link against some files from kadm5
KADM5DIR=       $(SRC)/lib/krb5/kadm5
KADM5OBJS= alt_prof.o str_conv.o
KADM5SRCS= $(KADM5DIR)/$(KADM5OBJS:%.o=%.c)

OBJECTS= $(KDBOBJS) $(KADM5OBJS) $(DERIVED_OBJS)

# include library definitions
include ../../Makefile.lib

SRCS=		$(KDBOBJS:%.o=../%.c)
SRCS+=		$(DERIVED_OBJS:%.o=../%.c)
SRCS+=		$(KADM5SRCS)

LIBS=		$(DYNLIB)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(LIBRARY:%.a=%.po)
POFILES = generic.po

# override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS +=	-DHAVE_CONFIG_H \
		-I$(KRB5IPROPDIR) \
		-I$(SRC)/lib/krb5 \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/krb5/os \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5 \
		-I$(SRC)/uts/common/gssapi/include/ \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include

CFLAGS +=	$(CCVERBOSE) -I..

DYNFLAGS +=	$(KRUNPATH) $(KMECHLIB)
LDLIBS +=	-L $(ROOTLIBDIR) -ldb2 -lc -lnsl

.KEEP_STATE:

all:	$(LIBS)

# Rules to rpcgen-erate derived files from the iprop.x spec file
$(ISRCHDR):	$(KRB5IPROPDIR)/iprop.x
	$(RM)	$@
	$(RPCGEN) -h $(KRB5IPROPDIR)/iprop.x > $@

$(ISRCXDR):	$(ISRCHDR) $(KRB5IPROPDIR)/iprop.x
	$(RM) $@
	$(RPCGEN) -c $(KRB5IPROPDIR)/iprop.x | $(CMD)

CLEANFILES +=	$(ISRCHDR) $(ISRCXDR)

# Explicitly state the dependancy on iprop.h
$(LIBS): $(ISRCHDR)

# We turn off ptr-cast warnings, since we're doing mmapping in kdb_log
LINTFLAGS +=	-erroff=E_BAD_PTR_CAST_ALIGN

lint:	lintcheck

$(DYNLIB):	$(MAPFILE)

$(MAPFILE):
	@cd $(MAPDIR); $(MAKE) mapfile

# include library targets
include ../../Makefile.targ

FRC:

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../*.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
