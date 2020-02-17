#
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2020 Joyent, Inc.

ROUTEDPROG=	in.routed
ROUTEDOBJS=	common.o if.o input.o main.o output.o parms.o radix.o \
                rdisc.o table.o trace.o
ROUTEDSRCS=	$(ROUTEDOBJS:.o=.c)
RTQUERYPROG=	rtquery
RTQUERYOBJS=	common.o rtquery.o
RTQUERYSRCS=	$(RTQUERYOBJS:.o=.c)
POFILEOBJS=	$(ROUTEDOBJS) $(RTQUERYOBJS)	

PROG=		$(ROUTEDPROG) $(RTQUERYPROG)
SRCS=		$(ROUTEDSRCS) $(RTQUERYSRCS)

MANIFEST=		route.xml
SVCMETHOD=		svc-route

include		../../../Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKROUTING)

#
# in.routed uses ancillary data features available through
# the Open Group's Networking Services standard.  The following
# pre-processor definitions enable these features.
#
_D_XOPEN_EXTN = -D_XOPEN_SOURCE=500 -D__EXTENSIONS__

# Turning on __EXTENSIONS__ breaks lint, and we need __EXTENSIONS__.
# This is really a lint problem, so around the breakage.
LINTFLAGS += -erroff=E_FUNC_DECL_VAR_ARG2 -erroff=E_INCONS_VAL_TYPE_DECL2 \
	     -erroff=E_INCONS_ARG_DECL2 -erroff=E_INCONS_ARG_USED2

CPPFLAGS +=	$(_D_XOPEN_EXTN)
CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
# not linted
SMATCH=off

LDLIBS +=	-lxnet -lmd
CLEAN_FILES +=	$(ROUTEDOBJS) $(RTQUERYOBJS)
CLOBBERFILES +=	$(ROUTEDPROG) $(RTQUERYPROG)
#
# Message catalog
#
POFILE=		in.routed.po
POFILES=  $(POFILEOBJS:.o=.po)
#
$(ROUTEDPROG):=	LDLIBS += -lkstat
lint	:=	LDLIBS += -lkstat

# This needs to be done because of SPARC/x86 differences.  On x86,
# double has required alignment of only 4 bytes, but on SPARC it's 8
# bytes.  This means that sockaddr_in can be casted to
# sockaddr_storage without complaint on x86, but requires a
# suppression directive on SPARC.
LINTFLAGS +=	-erroff=E_SUPPRESSION_DIRECTIVE_UNUSED

CTFCONVERT_HOOK = && $(CTFCONVERT_O)
CTFMERGE_HOOK = && $(CTFMERGE) -L VERSION -o $@ $(ROUTEDOBJS)
$(ROUTEDOBJS) := CFLAGS += $(CTF_FLAGS)
$(RTQUERYOBJS) := CFLAGS += $(CTF_FLAGS)

.KEEP_STATE:

.PARALLEL: $(ROUTEDPROG) $(RTQUERYOBJS)

all:	$(PROG)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

$(ROUTEDPROG):	$(ROUTEDOBJS)
	$(LINK.c) -o $@ $(ROUTEDOBJS) $(LDLIBS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

$(RTQUERYPROG): $(RTQUERYOBJS)
	$(LINK.c) -o $@ $(RTQUERYOBJS) $(LDLIBS) -lresolv $(CTFMERGE_HOOK)
	$(POST_PROCESS)

lint:
	$(LINT.c) $(ROUTEDSRCS) $(LDLIBS)
	$(LINT.c) $(RTQUERYSRCS) $(LDLIBS)

install:	all $(ROOTUSRSBINPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:		$(CHKMANIFEST)

clean:
	$(RM) $(CLEAN_FILES)

include		../../../Makefile.targ
