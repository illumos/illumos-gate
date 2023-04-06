#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
#

SHELL= /usr/bin/ksh93

CTOOLS= proto lcgen
SHTOOLS= iffe package gentab

TOOLS= $(CTOOLS) $(SHTOOLS) probe
OBJS= $(CTOOLS:%=%.o)

include $(SRC)/cmd/Makefile.cmd
include ../Makefile.ast
include $(SRC)/Makefile.native

NATIVE_LIBS += libc.so

all install install_h: $(TOOLS)
_msg _feature:

clean clobber:
	$(RM) $(OBJS) $(TOOLS)

package:
	$(RM) $@
	# The string returned by 'package' must match the value used by
	# AT&T upstream, which is "i386" or "sun4", regardless of whether
	# building 32- or 64-bit objects.
	{ \
		[[ $(MACH) == i386 ]] && arch=i386 || arch=sun4; \
		print -e "#!/bin/sh\n\necho sol11.$$arch" > $@; \
	}
	$(CHMOD) +x $@

%.o: $(C_ASTINIT)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: $(C_AST)/src/lib/libast/port/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

AST_SH_ASSEMBLE= \
	{ \
		tf=$$(mktemp /tmp/ast.XXXXXXXXXX) && \
		print 'USAGE_LICENSE="[-author?ATT]"' > $$tf && \
		cat $< >> $$tf && \
		mv $$tf $@; \
	}

%: $(C_ASTINIT)/%.sh
	$(RM) $@
	$(AST_SH_ASSEMBLE)
	$(CHMOD) +x $@

%: $(C_AST)/src/lib/libpp/%.sh
	$(RM) $@
	$(AST_SH_ASSEMBLE)
	$(CHMOD) +x $@

$(CTOOLS): $(OBJS)
	$(LINK.c) $@.o -o $@
	$(POST_PROCESS)

probe: $(C_ASTINIT)/C+probe $(C_ASTINIT)/make.probe
	$(CAT) $(C_ASTINIT)/C+probe $(C_ASTINIT)/make.probe > $@
	$(CHMOD) +x $@

STACKPROTECT= none

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-implicit-fallthrough
CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += $(CNOWARN_UNINIT)
SMATCH= off

.KEEP_STATE:
.PARALLEL: $(TOOLS)
