#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/krb5/Makefile
#
# Build everything in parallel; use .WAIT for dependencies
.PARALLEL:

SUBDIRS= \
	kwarn	.WAIT	\
	krb5kdc \
	kadmin	\
	kdestroy	\
	kinit	\
	klist \
	kproplog \
	krb5-config \
	slave \
	ldap_util

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
delete :=	TARGET= delete
install :=	TARGET= install
lint :=		TARGET= lint
catalog :=	TARGET= catalog
package :=	TARGET= package
_msg :=		TARGET= _msg

_msg:	$(SUBDIRS)

.KEEP_STATE:

all clean clobber delete install lint catalog package: $(SUBDIRS)

check: $(CHECKHDRS)

# ldap_util has a dependency on kadmin/cli/getdate.o
ldap_util: kadmin

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
