#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= kdestroy

OBJS	= kdestroy.o krpc_sys.o

SRCS	= kdestroy.c krpc_sys.c

include ../../Makefile.cmd
include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-parentheses

# not linted
SMATCH=off

POFILE = kdestroy.po 
POFILES = generic.po 

CPPFLAGS += -I../../../lib/gss_mechs/mech_krb5/include \
		-I$(SRC)/uts/common/gssapi/mechs/krb5/include


i386_CPPFLAGS =
sparc_CPPFLAGS += -D$(MACH)

LDFLAGS += $(KRUNPATH)
LDLIBS += $(KMECHLIB)

.KEEP_STATE:
all: $(PROG)

krpc_sys.o: krpc_sys.c 
	$(COMPILE.c)  -o  $@ krpc_sys.c
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

