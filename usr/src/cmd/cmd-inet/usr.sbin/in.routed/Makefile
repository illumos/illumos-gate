#
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2020 Joyent, Inc.

ROUTEDPROG=	in.routed
ROUTEDOBJS=	common.o if.o input.o main.o output.o parms.o radix.o \
                rdisc.o table.o trace.o
RTQUERYPROG=	rtquery
RTQUERYOBJS=	common.o rtquery.o
POFILEOBJS=	$(ROUTEDOBJS) $(RTQUERYOBJS)

PROG=		$(ROUTEDPROG) $(RTQUERYPROG)

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

install:	all $(ROOTUSRSBINPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:		$(CHKMANIFEST)

clean:
	$(RM) $(CLEAN_FILES)

include		../../../Makefile.targ
