#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../Makefile.cmd

SUBDIRS=libntp libparse xntpd ntpq ntpdate ntptrace xntpdc etc.inet

all :=		TARGET=all
install :=	TARGET=install
clobber :=	TARGET=clobber
clean :=	TARGET=clean
lint :=		TARGET=lint

all install clobber clean lint:	$(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(MFLAGS) $(TARGET)

install_h check _msg _dc:

FRC:

# EXPORT DELETE START
EXPORT_SRC:
	$(RM) Makefile+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< libntp/authdes.c >libntp/authdes.c+
	$(MV) libntp/authdes.c+ libntp/authdes.c
	sed -e "/^EXPORT_SRC:/,/^$$/d" < Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile libntp/authdes.c

# EXPORT DELETE END
