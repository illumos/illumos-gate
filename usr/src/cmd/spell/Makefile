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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

HASHPROG=	hashmk1 spellin1
SHPROG=		spell compress
HASHTAB=	hlista hlistb hstop
BINPROG=	spellprog spellin hashmake hashcheck
PROG=		$(SHPROG) $(BINPROG) $(HASHPROG) $(HASHTAB) spellhist

SPELLPROGSRC=	spellprog.c hash.c hashlook.c huff.c
SPELLPROGOBJ=	$(SPELLPROGSRC:%.c=%.o)

SPELLINSRC=	spellin.c huff.c
SPELLINOBJ=	$(SPELLINSRC:%.c=%.o)

HASHCHECKSRC=	hashcheck.c hash.c huff.c
HASHCHECKOBJ=	$(HASHCHECKSRC:%.c=%.o)

HASHMAKESRC=	hashmake.c hash.c
HASHMAKEOBJ=	$(HASHMAKESRC:%.c=%.o)

SRCS= $(SPELLPROGSRC) spellin.c hashcheck.c hashmake.c
OBJS= $(SRCS:%.c=%.o)

WORDS=	american british local list extra stop
TXTS=	compress.sh spell.sh

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses

XGETFLAGS += -a -x spell.xcl

CLOBBERFILES += htemp1 htemp2

ROOTSPELLD = $(ROOTLIB)/spell
ROOTVARADMD = $(ROOT)/var/adm
ROOTDIRS= $(ROOTSPELLD)

BINF= spell
SPELLF= spellprog hashmake hashcheck spellin hstop hlistb hlista compress
VARADMF= spellhist

ROOTBINF = $(BINF:%=$(ROOTBIN)/%)
ROOTSPELLF = $(SPELLF:%=$(ROOTSPELLD)/%)
ROOTVARADMF = $(VARADMF:%=$(ROOTVARADMD)/%)

HASHFILEMODE = 0644
$(ROOTSPELLD)/hstop $(ROOTSPELLD)/hlistb \
$(ROOTSPELLD)/hlista :=	FILEMODE =	0644
$(ROOTVARADMF) :=	FILEMODE =	0666

spellin1 hashmk1 := CC = $(NATIVECC)
spellin1 hashmk1 := POST_PROCESS =
spellin1 hashmk1 := CPPFLAGS =
spellin1 hashmk1 := LDFLAGS = $(BDIRECT)

$(ROOTSPELLD)/% $(ROOTVARADMD)/% : %
	$(INS.file)

.KEEP_STATE:

all:	$(PROG) $(TXTS)

spellprog:		$(SPELLPROGOBJ)
			$(LINK.c) $(SPELLPROGOBJ) -o $@ $(LDLIBS)
			$(POST_PROCESS)

spellin spellin1:	$(SPELLINOBJ)
			$(LINK.c) $(SPELLINOBJ) -o $@ $(LDLIBS)
			$(POST_PROCESS)

spellhist:
			$(ECHO) '\c' > spellhist

hashcheck:		$(HASHCHECKOBJ)
			$(LINK.c) $(HASHCHECKOBJ) -o $@ $(LDLIBS)
			$(POST_PROCESS)

hashmake hashmk1:	$(HASHMAKEOBJ)
			$(LINK.c) $(HASHMAKEOBJ) -o $@ $(LDLIBS)
			$(POST_PROCESS)

htemp1:	list local extra hashmk1
	$(RM) $@; cat list local extra | $(_SH_) ./hashmk1 > $@

hlista: american $(HASHPROG) htemp1
	$(RM) htemp2; ./hashmk1 <american |sort -u - htemp1 >htemp2
	$(RM) $@; ./spellin1 `wc htemp2|sed -n 's/\([^ ]\) .*/\1/p'`<htemp2 >$@
	$(RM) htemp2

hlistb: british $(HASHPROG) htemp1
	$(RM) htemp2; ./hashmk1 <british |sort -u - htemp1 >htemp2
	$(RM) $@; ./spellin1 `wc htemp2|sed -n 's/\([^ ]\) .*/\1/p'`<htemp2 >$@
	$(RM) htemp2

hstop:	stop $(HASHPROG)
	$(RM) htemp2; ./hashmk1 <stop | sort -u >htemp2
	$(RM) $@; ./spellin1 `wc htemp2|sed -n 's/\([^ ]\) .*/\1/p'`<htemp2 >$@
	$(RM) htemp2

install: all $(ROOTDIRS) $(ROOTBINF) $(ROOTSPELLF) $(ROOTVARADMF)

$(ROOTDIRS):
	$(INS.dir)

lint:	lint_SRCS

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
