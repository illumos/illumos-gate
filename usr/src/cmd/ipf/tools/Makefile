#
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/ipf/tools/Makefile
#
#

LICENCE= IPFILTER.LICENCE

include ../../Makefile.cmd

$(64ONLY)SUBDIRS= $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

USRLIBIPF=		$(ROOTLIB)/ipf
USRLIBIPFLICENCE=	$(LICENCE:%=$(USRLIBIPF)/%) 

FILEMODE= 0755
OWNER= root
GROUP= sys

$(USRLIBIPFLICENCE):=FILEMODE= 0644
$(USRLIBIPFLICENCE):=GROUP= bin

all:=           TARGET= all
install:=       TARGET= install
clean:=         TARGET= clean
clobber:=       TARGET= clobber
lint:=          TARGET= lint

$(USRLIBIPF):
	$(INS.dir)

$(USRLIBIPF)/% : %
	$(INS.file)

.KEEP_STATE:

all:		$(SUBDIRS) 

clean clobber lint: $(SUBDIRS)

install:	all $(SUBDIRS) $(USRLIBIPF) \
		$(USRLIBIPFLICENCE)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(MFLAGS) $(TARGET)


FRC:

include ../../Makefile.targ
