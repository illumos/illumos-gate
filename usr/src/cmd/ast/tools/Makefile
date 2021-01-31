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

CTOOLS= mamake ratz release proto lcgen
SHTOOLS= iffe mamprobe mprobe package gentab

TOOLS= $(CTOOLS) $(SHTOOLS) probe
OBJS= $(CTOOLS:%=%.o)

include $(SRC)/cmd/Makefile.cmd
include ../Makefile.ast

CC= $(NATIVECC)
LD= $(NATIVELD)
CFLAGS= $(NATIVE_CFLAGS)

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
		print "#!/bin/sh"; \
		[[ $(MACH) == i386 ]] && arch=i386 || arch=sun4; \
		print "echo sol11.$$arch"; \
	} >; $@
	$(CHMOD) +x $@

%.o: $(C_ASTINIT)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: $(C_AST)/src/lib/libast/port/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%: $(C_ASTINIT)/%.sh
	$(RM) $@
	{ \
		echo 'USAGE_LICENSE="[-author?ATT]"'; \
		cat $<; \
	} >; $@
	$(CHMOD) +x $@

%: $(C_AST)/src/lib/libpp/%.sh
	$(RM) $@
	{ \
		echo 'USAGE_LICENSE="[-author?ATT]"'; \
		cat $<; \
	} >; $@
	$(CHMOD) +x $@

$(CTOOLS): $(OBJS)
	$(LINK.c) $@.o -o $@ $(LDLIBS)
	$(POST_PROCESS)

probe: $(C_ASTINIT)/C+probe $(C_ASTINIT)/make.probe
	$(CAT) $(C_ASTINIT)/C+probe $(C_ASTINIT)/make.probe > $@
	$(CHMOD) +x $@

STACKPROTECT= none

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-implicit-fallthrough
CERRWARN += -_gcc=-Wno-unused-but-set-variable
CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += $(CNOWARN_UNINIT)
SMATCH= off

.KEEP_STATE:
.PARALLEL: $(TOOLS)
