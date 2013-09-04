#
#
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# cmd/troff/nroff.d/terms.d/Makefile
#

include 	../../../Makefile.cmd

ROOTNTERM =	$(ROOTSHLIB)/nterm

FILEMODE =	644

FILES1 =	tab.2631 tab.2631-c tab.2631-e tab.lp
FILES2 =	tab.300 tab.300-12 tab.300s tab.300s-12 tab.382	\
		tab.4000a tab.450 tab.450-12 tab.832
FILES3 =	tab.37 tab.8510 tab.X tab.tn300
FILES =		$(FILES1) $(FILES2) $(FILES3)

ROOTFILES =	$(FILES:%=$(ROOTNTERM)/%)

LNKFILES =	tab.300S tab.300S-12 tab.4000A
ROOTLNKFILES =	$(LNKFILES:%=$(ROOTNTERM)/%)

$(ROOTNTERM)/tab.300S :=	ROOTLNKDEST = $(ROOTNTERM)/tab.300s
$(ROOTNTERM)/tab.300S-12 :=	ROOTLNKDEST = $(ROOTNTERM)/tab.300s-12
$(ROOTNTERM)/tab.4000A :=	ROOTLNKDEST = $(ROOTNTERM)/tab.4000a

TXTS =		README 

.KEEP_STATE :

all :		$(TXTS) $(FILES)

install :	all $(ROOTNTERM) $(ROOTFILES) $(ROOTLNKFILES)

$(FILES1) :	$$(@:tab.%=a.%) b.lp
		cat $(@:tab.%=a.%) b.lp >$@
$(FILES2) :	$$(@:tab.%=a.%) b.300
		cat $(@:tab.%=a.%) b.300 >$@
$(FILES3) :	$$(@:tab.%=ab.%)
		cat $(@:tab.%=ab.%) > $@

$(ROOTNTERM) :
		$(INS.dir)

$(ROOTNTERM)/% :	%
		$(INS.file)

$(ROOTLNKFILES) :	$$(ROOTLNKDEST)
			-$(RM) $@; $(LN) $(ROOTLNKDEST) $@

clean lint strip :

clobber:
	$(RM) $(FILES)
