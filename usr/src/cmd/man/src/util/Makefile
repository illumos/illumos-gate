#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include		../../../Makefile.cmd

BINPROG =	nsgmls instant

SGMLUTILDOCBOOKDIR = $(CLOSED)/cmd/man/src/util/docbook
SGMLUTILSOLBOOKV1DIR = $(CLOSED)/cmd/man/src/util/solbookv1
SGMLUTILSOLBOOKV2DIR = solbookv2

LIBSHELL =	sgml2roff
SGMLENTS =      aap-shortref.gml \
		allisoents.gml \
		ati-dflt.dcl \
		ati-eqn1.gml \
		ati-graph.gml \
		ati-math.elm \
		ati-num.gml \
		ati-tbl.elm \
		atilogo.eps \
		basic.dcl \
		cals-tbl.elm \
		capref.gml \
		caution.eps \
		core.gml \
		ereview.gml \
		html-latin.sgml \
		iso-amsa.gml \
		iso-amsb.gml \
		iso-amsc.gml \
		iso-amsn.gml \
		iso-amso.gml \
		iso-amsr.gml \
		iso-box.gml \
		iso-cyr1.gml \
		iso-cyr2.gml \
		iso-dia.gml \
		iso-grk1.gml \
		iso-grk2.gml \
		iso-grk3.gml \
		iso-grk4.gml \
		iso-lat1.gml \
		iso-lat2.gml \
		iso-num.gml \
		iso-pub.gml \
		iso-tech.gml \
		sun_iso.gml \
		synref.gml \
		warn.eps
DOCBOOKDTD =	docbook.dtd
CATALOG =	catalog
SOLBOOKV2 =	solbook.dcl \
		solbook.dtd
SOLBOOKV1 =	solbook.dtd
TPTFILES =	docbook-to-man.ts \
		roff.cmap \
		roff.sdata

PROG =		$(BINPROG) 

SHSRCS =	sgml2roff.sh

PROGDIR =	$(ROOTLIB)/sgml
SGMLSHLIB =	$(ROOTSHLIB)/sgml
SGMLSHLIBLOCALE =	$(ROOTSHLIB)/sgml/locale
SGMLSHLIBLOCALEC =	$(ROOTSHLIB)/sgml/locale/C
SGMLENTSDIR =	$(ROOTSHLIB)/sgml/locale/C/entities
SGMLDTDDIR = 	$(ROOTSHLIB)/sgml/locale/C/dtds
DOCBOOKDIR =	$(SGMLDTDDIR)/docbook
SOLBOOKV1DIR =	$(SGMLDTDDIR)/solbookv1
SOLBOOKV2DIR =	$(SGMLDTDDIR)/solbookv2
TPTDIR =	$(ROOTSHLIB)/sgml/locale/C/transpec

ROOTPROG =	$(BINPROG:%=$(PROGDIR)/%)
ROOTLIBSHELL =	$(LIBSHELL:%=$(PROGDIR)/%)
ROOTENTS =	$(SGMLENTS:%=$(SGMLENTSDIR)/%)
$(CLOSED_BUILD)ROOTDOCBOOK =	$(DOCBOOKDTD:%=$(DOCBOOKDIR)/%)
$(CLOSED_BUILD)ROOTSOLBOOKV1 =	$(SOLBOOKV1:%=$(SOLBOOKV1DIR)/%)
ROOTSOLBOOKV2 = $(SOLBOOKV2:%=$(SOLBOOKV2DIR)/%)
ROOTCATALOG =	$(CATALOG:%=$(SGMLDTDDIR)/%)
ROOTTPT =	$(TPTFILES:%=$(TPTDIR)/%)

CLOBBERFILES +=	$(LIBSHELL) 

FILEMODE = 	0644
$(ROOTPROG) 	:=	FILEMODE = 0755
$(ROOTLIBSHELL) :=	FILEMODE = 0755

.KEEP_STATE :

all :		$(PROG) $(LIBSHELL) 

install :	all $(PROGDIR) $(SGMLSHLIB) $(SGMLSHLIBLOCALE) \
	$(SGMLSHLIBLOCALEC) $(SGMLDTDDIR) $(SGMLENTSDIR) $(ROOTPROG) \
	$(ROOTLIBSHELL) $(TPTDIR) $(ROOTENTS) $(ROOTCATALOG) $(ROOTTPT) \
	$(ROOTDOCBOOK) $(ROOTSOLBOOKV1) $(ROOTSOLBOOKV2)

$(PROGDIR) :	
		$(INS.dir) 

$(SGMLSHLIB) :	
		$(INS.dir) 

$(SGMLSHLIBLOCALE) :	
		$(INS.dir) 

$(SGMLSHLIBLOCALEC) :	
		$(INS.dir) 

$(SGMLDTDDIR) :	
		$(INS.dir)

$(SGMLENTSDIR) :
		$(INS.dir) 

$(TPTDIR) :	
		$(INS.dir)

$(ROOTPROG) :	instant nsgmls

instant :	FRC
		@cd $@.src; pwd; $(MAKE) $(TARGET)
		$(CP) $@.src/$@ .

nsgmls :	FRC
		@cd $@.src; pwd; $(MAKE) $(TARGET)
		$(CP) $@.src/$@/$@ .

sgml2roff :	sgml2roff.sh
		cat $@.sh > $@

FRC:

clean : _localclean

_localclean:
		@cd instant.src; pwd; $(MAKE) clean
		@cd nsgmls.src; pwd; $(MAKE) clean

$(CLOSED_BUILD)CLOSED_CLOBBER = closed_clobber

clobber : clean _localclobber $(CLOSED_CLOBBER)

_localclobber:
		@cd instant.src; pwd; $(MAKE) clobber
		@cd nsgmls.src; pwd; $(MAKE) clobber
		@cd solbookv2; pwd; $(MAKE) clobber
		$(RM) instant nsgmls sgml2roff
		$(RM) -r $(PROGDIR)
		$(RM) -r $(ROOTSHLIB)/sgml

closed_clobber:
	@cd $(SGMLUTILSOLBOOKV1DIR); pwd; $(MAKE) clobber

$(PROGDIR)/%:	%
		$(INS.file)

$(SGMLENTSDIR)/%:	%
		$(INS.file)

$(SGMLDTDDIR)/%:	%
		$(INS.file)

$(TPTDIR)/%:	%
		$(INS.file)

$(ROOTDOCBOOK):
		cd $(SGMLUTILDOCBOOKDIR); pwd; $(MAKE) install; cd ..; pwd


$(ROOTSOLBOOKV1):
		cd $(SGMLUTILSOLBOOKV1DIR); pwd; $(MAKE) install; cd ..; pwd


$(ROOTSOLBOOKV2):
		cd $(SGMLUTILSOLBOOKV2DIR); pwd; $(MAKE) install; cd ..; pwd
