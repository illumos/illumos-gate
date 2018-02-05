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
# Copyright 2015, OmniTI Computer Consulting, Inc. All rights reserved.
#

include $(SRC)/lib/Makefile.lib

# PERL_VERSION and PERL_ARCH used to be set here,
# but as they were also needed in usr/src/pkg/Makefile,
# the definition was moved to usr/src/Makefile.master

PERLDIR = $(ADJUNCT_PROTO)/usr/perl5/$(PERL_VERSION)
PERLLIBDIR = $(PERLDIR)/lib/$(PERL_ARCH)
PERLINCDIR = $(PERLLIBDIR)/CORE

PERLMOD = $(MODULE).pm
PERLEXT = $(MACH)/$(MODULE).so

ROOTPERLDIR = $(ROOT)/usr/perl5/$(PERL_VERSION)
ROOTPERLLIBDIR = $(ROOTPERLDIR)/lib/$(PERL_ARCH)
ROOTPERLMODDIR = $(ROOTPERLLIBDIR)/Sun/Solaris
ROOTPERLEXTDIR = $(ROOTPERLLIBDIR)/auto/Sun/Solaris/$(MODULE)

ROOTPERLMOD = $(ROOTPERLMODDIR)/$(MODULE).pm
ROOTPERLEXT = $(ROOTPERLEXTDIR)/$(MODULE).so

CSTD = $(CSTD_GNU99)
