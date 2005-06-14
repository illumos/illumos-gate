#
# Copyright 1997-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/krb5/kadmin/Makefile

include ../../Makefile.cmd

SUBDIRS= cli dbutil ktutil kpasswd server kclient
# EXPORT DELETE START
SUBDIRS += gui
# EXPORT DELETE END

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
delete :=	TARGET= delete
install :=	TARGET= install
lint :=		TARGET= lint
catalog :=	TARGET= catalog
package :=	TARGET= package
_msg:=          TARGET= _msg

_msg:	$(SUBDIRS)

.KEEP_STATE:

all clean clobber delete install lint catalog package: $(SUBDIRS)

# install rule for install_h target

install: $(SUBDIRS)

check: $(CHECKHDRS)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

# EXPORT DELETE START
EXPORT_SRC:
	$(RM) -r gui
	$(RM) Makefile+
	$(SED) -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
                < Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile
# EXPORT DELETE END
