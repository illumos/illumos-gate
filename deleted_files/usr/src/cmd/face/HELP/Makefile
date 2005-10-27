#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1990 by Sun Microsystems, Inc.
#
# cmd/face/HELP/Makefile

include		../../Makefile.cmd
include		../src/Makefile.com

SUBDIRS=	dos mail spell programs pref lp

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint

VMBIN=		$(ROOTVMSYS)/bin
VMLIB=		$(ROOTVMSYS)/lib

# HELP bin install

ROOTDIR=	$(ROOTVMSYS)/HELP

HELPFILES=	update unix undelete time show-path select security run rename \
		refresh redescribe print prev-frm organize open next-frm move \
		help goto frm-mgmt find exit display delete create copy close \
		cleanup cancel \
		T.m.frmlist T.m.found \
		T.hwaste T.husers T.htoc T.hspell1 T.hsend1 T.hsec9 T.hsec8 \
		T.hsec7 T.hsec6 T.hsec5 T.hsec4 T.hsec3 T.hsec2 T.hsec10 \
		T.hsec1 T.hprog T.hprin1 T.horg3 T.horg2 T.horg1 T.hoffice \
		T.hmerror T.hmail T.hfind4 T.hfind3 T.hfind2 T.hfind1 \
		T.hfilecab T.hface T.hcreate T.hattface T.h7.cmd T.h55.waste \
		T.h43.fold T.h41.obj T.h3.frames T.h1.help T.f.propts

ROOTBIN=	$(HELPFILES:%=$(ROOTDIR)/%)

FILEMODE=	755

# install rules

$(ROOTDIR)/% : %
	$(INS.file)

.KEEP_STATE:

all: $(HELPFILES) $(SUBDIRS)

install: all $(ROOTDIR) $(ROOTBIN) $(SUBDIRS)

$(ROOTDIR):
	-$(INS.dir)

clean clobber:

lint:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
