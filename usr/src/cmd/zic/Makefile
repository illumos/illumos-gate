#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

NATIVE=native
PROG= zic
KSHPROG= tzselect
NPROG= $(NATIVE)/$(PROG)

# "etcetera" must be listed before "backward" because it sets up links that
# "backward" needs.
TZFILES= africa antarctica asia australasia etcetera europe \
	 factory northamerica pacificnew solar87 solar88 solar89 \
	 southamerica backward
# Don't build the systemv timezones, but do install the source file.
SRCFILES = $(TZFILES) systemv README
TABFILES = continent.tab country.tab zone_sun.tab

OBJS= zic.o scheck.o ialloc.o
SRCS= $(OBJS:%.o=%.c)
NOBJS= $(OBJS:%=$(NATIVE)/%)

CLOBBERFILES= $(NOBJS) $(KSHPROG) $(NPROG) $(NATIVE)/zic.c $(NATIVE)/tzfile.h

include ../Makefile.cmd

NCPPFLAGS=	-I$(NATIVE)
ROOTTZD=	$(ROOTSHLIB)/zoneinfo
ROOTTZSRCD=	$(ROOTSHLIB)/zoneinfo/src
ROOTTZTABD=	$(ROOTSHLIB)/zoneinfo/tab
DIRS=  $(ROOTTZSRCD) $(ROOTTZTABD)

CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized

ROOTLIBTZSRCFILES=	$(SRCFILES:%=$(ROOTTZSRCD)/%)
ROOTLIBTZTABFILES=	$(TABFILES:%=$(ROOTTZTABD)/%)
ROOTKSHPROG=	$(ROOTBIN)/$(KSHPROG)

$(ROOTLIBTZSRCFILES):=	FILEMODE=	0644
$(ROOTLIBTZTABFILES):=	FILEMODE=	0644

#
# Message catalog
#
POFILE2=tzselect.po
POFILE3=zoneinfo.po
POFILES3=$(TABFILES)
TEXT_DOMAIN2=SUNW_OST_ZONEINFO
MSGDOMAIN2=$(MSGROOT)/$(TEXT_DOMAIN2)

# NB: $(POFILE2) is under SCM.
CLOBBERFILES += $(POFILE) $(POFILE3)

.KEEP_STATE:

all: $(PROG) $(NPROG) $(KSHPROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(DIRS) $(ROOTTZSRCD) $(ROOTTZTABD) $(ROOTUSRSBINPROG) \
		$(ROOTLIBTZSRCFILES) $(ROOTLIBTZTABFILES) $(ROOTKSHPROG)
	$(NPROG) -d $(ROOTTZD) $(TZFILES)

$(NPROG): $(NATIVE) $(NOBJS)
	$(NATIVECC) -o $@ $(NOBJS)

#
# XXX
# There is a .ksh rule in Makefile.targ, but we need our custom POFILE rules.
#
$(KSHPROG):	$(KSHPROG).ksh
	$(RM) $@
	$(CAT) $(KSHPROG).ksh > $@
	$(CHMOD) +x $@

$(ROOTTZSRCD)/%: %
	$(INS.file)

$(ROOTTZTABD)/%: %
	$(INS.file)

$(DIRS):
	$(INS.dir)

$(NATIVE):
	-@mkdir -p $@

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

$(NOBJS): $$(@F:.o=.c)
	$(NATIVECC) -O $(NCPPFLAGS) -c -o $@ $(@F:.o=.c)

$(NATIVE)/zic.o: $(NATIVE)/tzfile.h

#$(NATIVE)/scheck.o: scheck.c
#	$(NATIVECC) -c -o $@ scheck.c

#$(NATIVE)/ialloc.o: ialloc.c
#	$(NATIVECC) -c -o $@ ialloc.c

$(NATIVE)/tzfile.h: $(ROOT)/usr/include/tzfile.h
	$(RM) $@; cp $(ROOT)/usr/include/tzfile.h $@

#
# From ../Makefile.targ
#
clobber: clean
	-$(RM) $(PROG) $(CLOBBERFILES)

lint_PROG:
	$(LINT.c) $(PROG).c $(LDLIBS)

lint_SRCS:
	$(LINT.c) $(SRCS) $(LDLIBS)

#
# For message catalogue files
#
_msg: $(MSGDOMAIN) $(POFILE) $(POFILE2) $(MSGDOMAIN2) $(POFILE3)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)
	$(RM) $(MSGDOMAIN)/$(POFILE2)
	$(CP) $(POFILE2) $(MSGDOMAIN)
	$(RM) $(MSGDOMAIN2)/$(POFILE3)
	$(CP) $(POFILE3) $(MSGDOMAIN2)/$(POFILE3)

$(MSGDOMAIN) $(DCMSGDOMAIN) $(MSGDOMAIN2):
	$(INS.dir)

$(POFILE3):	$(POFILES3)
	$(RM) $@
	@/bin/sh ./do_pofile.sh > $@
 
