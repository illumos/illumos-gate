#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/valtools/Makefile
#

PROG= ckint ckitem ckpath ckrange ckstr ckyorn \
      ckkeywd ckdate cktime ckuid ckgid

POFILES= ckdate.po ckgid.po ckint.po ckitem.po \
	ckkeywd.po ckpath.po ckrange.po ckstr.po \
	cktime.po ckuid.po ckyorn.po puttext.po

include ../Makefile.cmd

LIBADMDIR=	../../lib/libadm/inc
CPPFLAGS +=	-I$(LIBADMDIR)
CFLAGS +=	$(CCVERBOSE)
LDLIBS += -ladm
POFILE= valtools.po
CLOBBERFILES +=	puttext $(POFILES) $(POFILE)
CLEANFILES += puttext

VCKS=	valint helpint errint  \
	helpitem erritem  \
        valpath helppath errpath  \
	valrange helprange errange  \
	valstr helpstr errstr  \
	valyorn helpyorn erryorn  \
	valtime helptime errtime  \
	valdate helpdate errdate  \
	dispuid valuid helpuid erruid  \
	dispgid valgid helpgid errgid

DISPS=	dispuid dispgid

ROOTSADMDIR=	$(ROOT)/usr/sadm/bin

ROOTPUTTEXT=	$(ROOTSADMDIR)/puttext
ROOTVCKS=	$(VCKS:%=$(ROOTSADMDIR)/%)
ROOTDISPS=	$(DISPS:%=$(ROOTBIN)/%)


# valtool install rules
$(ROOTSADMDIR)/%: %
	$(INS.file)

# there is a special case here for errange
#
$(ROOTSADMDIR)/disp% \
$(ROOTSADMDIR)/val% \
$(ROOTSADMDIR)/help% \
$(ROOTSADMDIR)/err% \
$(ROOTSADMDIR)/er% \
$(ROOTBIN)/disp%: $(ROOTBIN)/ck%
	$(RM) $@; $(LN) $< $@


.KEEP_STATE:

.PARALLEL:	 $(PROG) puttext

all: $(PROG) puttext

install: all $(ROOTSADMDIR) $(ROOTPROG) $(ROOTPUTTEXT) $(ROOTVCKS) $(ROOTDISPS)

$(ROOTSADMDIR):
	$(INS.dir)

$(POFILE):	$(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

clean:

lint:
	$(LINT.c) ckint.c   $(LDLIBS)
	$(LINT.c) ckitem.c  $(LDLIBS)
	$(LINT.c) ckpath.c  $(LDLIBS)
	$(LINT.c) ckrange.c $(LDLIBS)
	$(LINT.c) ckstr.c   $(LDLIBS)
	$(LINT.c) ckyorn.c  $(LDLIBS)
	$(LINT.c) ckkeywd.c $(LDLIBS)
	$(LINT.c) ckdate.c  $(LDLIBS)
	$(LINT.c) cktime.c  $(LDLIBS)
	$(LINT.c) ckuid.c   $(LDLIBS)
	$(LINT.c) ckgid.c   $(LDLIBS)
	$(LINT.c) puttext.c $(LDLIBS)

include ../Makefile.targ
