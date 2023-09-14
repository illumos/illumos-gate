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
# Copyright 2015, OmniTI Computer Consulting, Inc. All rights reserved.
# Copyright 2016 RackTop Systems.
#

include $(SRC)/lib/Makefile.lib

PERLDIR = $(ADJUNCT_PROTO)/usr/perl5/$(PERL_VERSION)
PERLLIBDIR = $(PERLDIR)/lib/$(PERL_ARCH)
PERLINCDIR = $(PERLLIBDIR)/CORE
PERLLIBDIR64 = $(PERLDIR)/lib/$(PERL_ARCH64)
PERLINCDIR64 = $(PERLLIBDIR64)/CORE

PERLBINDIR = $(PERLDIR)/bin
PERLBINDIR64 = $(PERLDIR)/bin
$(BUILDPERL64)PERLBINDIR = $(PERLDIR)/bin/$(MACH)
$(BUILDPERL32)PERLBINDIR64 = $(PERLDIR)/bin/$(MACH64)

PERLMOD = ../$(MODULE).pm
PERLEXT = $(MODULE).so
PERLXS = ../$(MODULE).xs

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

XSUBPP = $(PERLBINDIR)/perl $(PERLDIR)/lib/ExtUtils/xsubpp \
	-typemap $(PERLDIR)/lib/ExtUtils/typemap
XSUBPP64 = $(PERLBINDIR64)/perl $(PERLDIR)/lib/ExtUtils/xsubpp \
	-typemap $(PERLDIR)/lib/ExtUtils/typemap

# CFLAGS for perl, specifically.
# When building for Perl older than 5.38 we need to define PERL_USE_SAFE_PUTENV
PERL_USE_SAFE_PUTENV:sh = if test ${PERL_VERSION/5.} -lt 38 ; then echo -DPERL_USE_SAFE_PUTENV ; fi
PCFLAGS= -DPERL_EUPXS_ALWAYS_EXPORT -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 \
	$(PERL_USE_SAFE_PUTENV) -D_TS_ERRNO
PCFLAGS64= -DPERL_EUPXS_ALWAYS_EXPORT -D_LARGEFILE_SOURCE64 \
	$(PERL_USE_SAFE_PUTENV) -D_TS_ERRNO

CSTD = $(CSTD_GNU99)
ZGUIDANCE =
SONAME = $(PERLEXT)

CLEANFILES += $(PERLEXT) $(MODULE).o $(MODULE).c
