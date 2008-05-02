#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBS = -lsocket -lnsl

LIBNTP_A= libntp/libntp.a
LIBPARSE_A= libparse/libparse.a
LLIBNTP_A= libntp/llib-llibntp.ln

DEFS=	-DSYS_SOLARIS -DPPS -DHAVE_CONFIG_H

CLOCKDEFS=-DGOES -DGPSTM -DOMEGA -DCLOCK_MEINBERG -DCLOCK_SCHMID \
	-DCLOCK_DCF7000 -DCLOCK_TRIMTAIP -DCLOCK_TRIMTSIP -DCLOCK_RAWDCF \
	-DCLOCK_RCC8000

ROOTINETLIB=	$(ROOT)/usr/lib/inet
ROOTINETLIBPROG=	$(PROG:%=$(ROOTINETLIB)/%)

ROOTETCINET=	$(ROOT)/etc/inet
ROOTETCINETPROG=	$(PROG:%=$(ROOTETCINET)/%)
ROOTETCINETFILES=	$(FILES:%=$(ROOTETCINET)/%)

INCL=	-I../include
CFLAGS += $(DEFS) $(INCL)

$(ROOTINETLIB):
	$(INS.dir)

$(ROOTINETLIB)/%: % $(ROOTINETLIB)
	$(INS.file)

$(ROOTETCINET):
	$(INS.dir)

$(ROOTETCINET)/%: % $(ROOTETCINET)
	$(INS.file)
