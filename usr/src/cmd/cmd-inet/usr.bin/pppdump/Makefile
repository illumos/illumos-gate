#
# Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
#
# cmd/cmd-inet/usr.bin/pppdump/Makefile
#

PROG=		pppdump
OBJS=		bsd-comp.o deflate.o pppdump.o zlib.o
SRCS=		$(OBJS:%.o=%.c)

include		../../../Makefile.cmd

CPPFLAGS +=	-DPPP_DEFS_IN_NET

.KEEP_STATE:

.PARALLEL:	$(OBJS)

all: $(PROG)

CLOBBERFILES += THIRDPARTYLICENSE

all install: THIRDPARTYLICENSE

THIRDPARTYLICENSE: LICENSE.top COPYING.top
	$(RM) $@
	$(CAT) LICENSE.top COPYING.top > $@

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ROOTMAN1M)/pppdump.1m:=	FILEMODE=0444
$(ROOTMAN1M)/%:	%
	$(INS.file)
$(ROOTMAN1M):
	$(INS.dir)

ROOTSRC= $(ROOT)/usr/share/src/ppputil
TOPFILES=	Makefile CHANGES COPYING INSTALL LICENSE README
ROOTTOPFILES=	$(TOPFILES:%=$(ROOTSRC)/%)
$(ROOTTOPFILES) := FILEMODE= 0444
ROOTDIST= $(ROOTSRC)/pppdump
DISTFILES=	Makefile bsd-comp.c deflate.c ppp-comp.h pppdump.1m pppdump.c \
		zlib.c zlib.h
ROOTDISTFILES=	$(DISTFILES:%=$(ROOTDIST)/%)
$(ROOTDISTFILES) := FILEMODE= 0444

install: all $(ROOTPROG) install_src install_man

install_man:	$(ROOTMAN1M) $(ROOTMAN1M)/pppdump.1m

install_src:	$(ROOTSRC) .WAIT $(ROOTTOPFILES) $(ROOTDIST) .WAIT \
		$(ROOTDISTFILES)

$(ROOTSRC) $(ROOTDIST):
	$(INS.dir)

$(ROOTSRC)/%: %.top
	$(INS.rename)

$(ROOTDIST)/Makefile%:	Makefile%.dist
	$(INS.rename)

$(ROOTDIST)/%: %
	$(INS.file)

clean:
	$(RM) $(OBJS)

lint:

include		../../../Makefile.targ
