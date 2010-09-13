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
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../Makefile.lib

SUBDIRS=        $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=          TARGET= all
clean :=        TARGET= clean
clobber :=      TARGET= clobber
install :=      TARGET= install
lint :=         TARGET= lint

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

check: $(CHECKHDRS)

$(SUBDIRS):      FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ

# EXPORT DELETE START
EXPORT_SRC:
	$(RM) common/des.c+ common/des_crypt.c+ common/des_soft.c+ \
		common/des_decrypt.c+ common/des_encrypt.c+  \
		Makefile+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" < \
		common/des.c > common/des.c+
	$(MV) common/des.c+ common/des.c
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" < \
		common/des_crypt.c > common/des_crypt.c+
	$(MV) common/des_crypt.c+ common/des_crypt.c
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" < \
		common/des_soft.c > common/des_soft.c+
	$(MV) common/des_soft.c+ common/des_soft.c
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" < \
		common/des_encrypt.c > common/des_encrypt.c+
	$(MV) common/des_encrypt.c+ common/des_encrypt.c
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" < \
		common/des_decrypt.c > common/des_decrypt.c+
	$(MV) common/des_decrypt.c+ common/des_decrypt.c
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile common/des.c common/des_crypt.c \
		common/des_soft.c common/des_encrypt.c common/des_decrypt.c
# EXPORT DELETE END
