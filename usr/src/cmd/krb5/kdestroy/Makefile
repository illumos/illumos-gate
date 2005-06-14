#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG= kdestroy

OBJS	= kdestroy.o kwarnd_clnt_stubs.o kwarnd_clnt.o kwarnd_handle.o kwarnd_xdr.o krpc_sys.o

SRCS	= kdestroy.c krpc_sys.c \
	../kwarn/kwarnd_clnt_stubs.c \
	../kwarn/kwarnd_clnt.c \
	../kwarn/kwarnd_handle.c \
	../kwarn/kwarnd_xdr.c

include ../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = kdestroy.po 
POFILES = generic.po 

CPPFLAGS += -I../../../lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include \
		-I../kwarn

i386_CPPFLAGS =
sparc_CPPFLAGS += -D$(MACH)

LDFLAGS += $(KRUNPATH)
LDLIBS += $(KMECHLIB) -lnsl

.KEEP_STATE:
all: $(PROG)

krpc_sys.o: krpc_sys.c 
	$(COMPILE.c)  -o  $@ krpc_sys.c
	$(POST_PROCESS_O)

%.o: ../kwarn/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(PROG):       $(OBJS)  
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: $(KRB5PROG)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

include ../../Makefile.targ

$(POFILE): $(DERIVED_FILES) .WAIT $(POFILES) 
	$(RM) $@ 
	$(CAT) $(POFILES) > $@ 

generic.po: 
	$(RM) messages.po 
	$(XGETTEXT) $(XGETFLAGS) `($(GREP) -l gettext *.[ch] || echo /dev/null)` 
	$(SED) "/^domain/d" messages.po > $@ 
	$(RM) messages.po 

