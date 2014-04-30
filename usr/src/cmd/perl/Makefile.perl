#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
#
# Copyright (c) 2014 Racktop Systems.
# Copyright 2014, OmniTI Computer Consulting, Inc. All right reserved.
#

include $(SRC)/lib/Makefile.lib

PERL_VERSION = 5.16.1

PERL_ARCH = i86pc-solaris-thread-multi-64int
$(SPARC_BLD)PERL_ARCH = sun4-solaris-thread-multi-64int
PERL_ARCH64 = i86pc-solaris-thread-multi-64
$(SPARC_BLD)PERL_ARCH64 = sun4-solaris-thread-multi-64


PERLDIR = $(ADJUNCT_PROTO)/usr/perl5/$(PERL_VERSION)
PERLLIBDIR = $(PERLDIR)/lib/$(PERL_ARCH)
PERLLIBDIR64 = $(PERLDIR)/lib/$(PERL_ARCH64)
PERLINCDIR = $(PERLLIBDIR)/CORE
PERLINCDIR64 = $(PERLLIBDIR64)/CORE

PERLMOD = $(MODULE).pm
PERLEXT = $(MACH)/$(MODULE).so
PERLEXT64 = $(MACH64)/$(MODULE).so

ROOTPERLDIR = $(ROOT)/usr/perl5/$(PERL_VERSION)
ROOTPERLLIBDIR = $(ROOTPERLDIR)/lib/$(PERL_ARCH)
ROOTPERLMODDIR = $(ROOTPERLLIBDIR)/Sun/Solaris
ROOTPERLEXTDIR = $(ROOTPERLLIBDIR)/auto/Sun/Solaris/$(MODULE)
ROOTPERLLIBDIR64 = $(ROOTPERLDIR)/lib/$(PERL_ARCH64)
ROOTPERLMODDIR64 = $(ROOTPERLLIBDIR64)/Sun/Solaris
ROOTPERLEXTDIR64 = $(ROOTPERLLIBDIR64)/auto/Sun/Solaris/$(MODULE)

ROOTPERLMOD = $(ROOTPERLMODDIR)/$(MODULE).pm
ROOTPERLEXT = $(ROOTPERLEXTDIR)/$(MODULE).so
ROOTPERLMOD64 = $(ROOTPERLMODDIR64)/$(MODULE).pm
ROOTPERLEXT64 = $(ROOTPERLEXTDIR64)/$(MODULE).so

XSUBPP = $(PERLDIR)/bin/$(MACH)/perl $(PERLDIR)/lib/ExtUtils/xsubpp \
	-typemap $(PERLDIR)/lib/ExtUtils/typemap

XSUBPP64 = $(PERLDIR)/bin/$(MACH64)/perl $(PERLDIR)/lib/ExtUtils/xsubpp \
	-typemap $(PERLDIR)/lib/ExtUtils/typemap

C99MODE = $(C99_ENABLE)
