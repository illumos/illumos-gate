# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# gss_mechs/mech_krb5/spec/Makefile.spec

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5
include $(SRC)/lib/Makefile.spec

ABILINK=	$(ABILIBNAME).so$(VERS)

#
# usr/lib/gss/abi targets
#

ROOTABIDIR=		$(ROOT)$(KLIBDIR)/abi
ROOTABIDIR_REL=		../../abi

RELABIDIR64=		../../../../gss/abi/$(MACH64)
ROOTABIDIR64=		$(ROOTABIDIR)/$(MACH64)

ROOTABIDIR64_REL=	../$(ROOTABIDIR_REL)/$(MACH64)
GSSABIDIR64=		$(ROOT)/usr/lib/$(MACH64)/gss/abi

ROOTABILIB=		$(ROOTABIDIR)/$(ABILIB)
ROOTABILIB_REL=		$(ROOTABIDIR_REL)/$(ABILIB)
ROOTABILIB64=		$(ROOTABIDIR64)/$(ABILIB)
ROOTABILIB64_REL=	$(ROOTABIDIR64_REL)/$(ABILIB)

ROOTABILINK=		$(ROOTABIDIR)/$(ABILINK)
ROOTABILINK64=		$(ROOTABIDIR64)/$(ABILINK)
RELABILINK64=		$(RELABIDIR64)/$(ABILINK)
GSSABILINK64=		$(GSSABIDIR64)/$(ABILINK)

$(ROOTABIDIR) $(ROOTABIDIR64) $(GSSABIDIR64):
	$(INS.dir)

$(ROOTABILIB) $(ROOTABILIB64): $(SPECMAP) $(ABILIB)
	$(INS.abilib)

