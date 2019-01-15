#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= krb5kdc
MANIFEST=	krb5kdc.xml

OBJS	= \
	dispatch.o\
	do_as_req.o\
	do_tgs_req.o\
	extern.o\
	kdc_preauth.o\
	kdc_util.o\
	main.o\
	network.o\
	policy.o\
	replay.o \
	sock2p.o

SRCS	= $(OBJS:.o=.c)

DEFS =  -DHAVE_LIBSOCKET=1 -DHAVE_LIBNSL=1 \
	-DHAVE_SYSLOG_H=1 -DHAVE_STDARG_H=1 \
	-DHAVE_SYS_SELECT_H=1 -DHAVE_OPENLOG=1 \
	-DHAVE_SYSLOG=1 -DHAVE_CLOSELOG=1 -DHAVE_STRFTIME=1\
	-DHAVE_VSPRINTF=1 -DHAVE_COMPILE=1 -DHAVE_STEP=1 \
	-DHAVE_NETINET_IN_H=1 -DHAVE_INET_NTOP=1 \
	-DHAVE_SYS_SOCKIO_H=1 -DHAVE_SYS_SELECT_H=1

CLOBBERFILES += $(RSRC) 

include ../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(PROG).po
POFILES = generic.po

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKSECURITY)

CFLAGS += $(CCOPTS) $(DEFS) $(LOCALINCLUDE)
# The SET macros in network.c will be mis-optimized if GCC believes it
# may rely on undefined signed overflow behaviour.
CFLAGS += -_gcc=-fno-strict-overflow

CPPFLAGS += \
	-I$(SRC)/lib/gss_mechs/mech_krb5/include \
	-I$(SRC)/lib/gss_mechs/mech_krb5/include/krb5\
	-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
	-DHAVE_SYSLOG_H=1 

CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-unused-function
CERRWARN += -_gcc=-Wno-type-limits
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-parentheses

# not linted
SMATCH=off

LDFLAGS += $(KRUNPATH) $(KERBRUNPATH)
LDLIBS += -L$(ROOT_KLIBDIR) -L$(KRB5LIB) \
	  -lmech_krb5 -lkdb -lkadm5srv -lnsl -lsocket -lbsm -lc

.KEEP_STATE:

all: $(PROG) 

$(PROG):       $(OBJS)  
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(KRB5LIBPROG):=	FILEMODE = 500

install: $(KRB5LIBPROG) $(ROOTSVCMETHOD) $(ROOTMANIFEST)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

include ../../Makefile.targ

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po

FRC:
