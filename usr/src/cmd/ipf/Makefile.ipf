#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#cmd/ipf/Makefile.ipf
#


LIBIPF=		../../lib/$(MACH)/libipf.a
LIBIPF64=		../../lib/$(MACH64)/libipf.a

COMMONIPF=	$(SRC)/common/ipf
KERNELIPF=	$(SRC)/uts/common/inet/ipf

MINOR=		echo $(RELEASE) | cut -d. -f2
CPPFLAGS	+= -I$(COMMONIPF) -I$(KERNELIPF) -DSUNDDI \
		   -DSOLARIS2=$(MINOR:sh)
