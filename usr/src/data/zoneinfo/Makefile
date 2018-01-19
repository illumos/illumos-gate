#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# "etcetera" must be listed before "backward" because it sets up links that
# "backward" needs.
TZFILES=	africa \
		antarctica \
		asia \
		australasia \
		etcetera \
		europe \
		factory \
		northamerica \
		southamerica \
		backward

# Don't build the systemv timezones, but do install the source file.
SRCFILES=	$(TZFILES) systemv README
TABFILES=	continent.tab country.tab zone_sun.tab

include		$(SRC)/data/Makefile.data

ROOTTZD=	$(ROOTSHLIB)/zoneinfo
ROOTTZSRCD=	$(ROOTSHLIB)/zoneinfo/src
ROOTTZTABD=	$(ROOTSHLIB)/zoneinfo/tab
DIRS=		$(ROOTTZSRCD) $(ROOTTZTABD)

ROOTLIBTZSRCFILES=$(SRCFILES:%=$(ROOTTZSRCD)/%)
ROOTLIBTZTABFILES=$(TABFILES:%=$(ROOTTZTABD)/%)

$(ROOTLIBTZSRCFILES):=FILEMODE=0644
$(ROOTLIBTZTABFILES):=FILEMODE=0644

# Message catalog
TEXT_DOMAIN=	SUNW_OST_ZONEINFO
MSGDOMAIN=	$(MSGROOT)/$(TEXT_DOMAIN)
POFILE=		zoneinfo.po

.KEEP_STATE:

all:		$(TZFILES) $(TABFILES)

install:	$(DIRS) $(ROOTTZSRCD) $(ROOTTZTABD) $(ROOTLIBTZSRCFILES) \
		$(ROOTLIBTZTABFILES)
		$(ZIC) -d $(ROOTTZD) $(TZFILES)

$(ROOTTZSRCD)/%: %
		$(INS.file)

$(ROOTTZTABD)/%: %
		$(INS.file)

$(DIRS):
		$(INS.dir)

clean:

# For message catalogue files
_msg:		$(MSGDOMAIN) $(POFILE)
		$(RM) $(MSGDOMAIN)/$(POFILE)
		$(CP) $(POFILE) $(MSGDOMAIN)/$(POFILE)

$(MSGDOMAIN):
		$(INS.dir)

$(POFILE):	$(TABFILES) do_pofile.sh
		$(RM) $@
		@/bin/sh do_pofile.sh > $@

include		$(SRC)/data/Makefile.targ
