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

# Note, to build SASL msg file go to $SRC/lib/libsasl and make _msg
# target there.  Messages in sasl_plugins will be picked up from there.

include	../Makefile.lib

SUBDIRS =	cram digestmd5 gssapi plain

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint

.KEEP_STATE:

all clean clobber install lint: $(SUBDIRS)

install_h check:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

# EXPORT DELETE START
# CRYPT DELETE START
# Special target to clean up the source tree for export distribution
# Warning: This target changes the source tree
EXPORT_SRC:
	$(RM) 	Makefile+ \
		digestmd5/digestmd5.c+ \
		gssapi/gssapi.c+

	$(SED) -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< digestmd5/digestmd5.c > digestmd5/digestmd5.c+
	$(MV) digestmd5/digestmd5.c+ digestmd5/digestmd5.c

	$(SED) -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< gssapi/gssapi.c > gssapi/gssapi.c+
	$(MV) gssapi/gssapi.c+ gssapi/gssapi.c

	$(CHMOD) 444 \
		Makefile \
		digestmd5/digestmd5.c \
		gssapi/gssapi.c

CRYPT_SRC:
	$(RM) Makefile+

	$(SED) -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< digestmd5/digestmd5.c | $(SED) -e "/EXPORT DELETE/d" \
		> digestmd5/digestmd5.c+
	$(MV) digestmd5/digestmd5.c+ digestmd5/digestmd5.c

	$(SED) -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< gssapi/gssapi.c | $(SED) -e "/EXPORT DELETE/d" \
		> gssapi/gssapi.c+
	$(MV) gssapi/gssapi.c+ gssapi/gssapi.c

	$(SED) -e "/^# CRYPT DELETE START/,/^# CRYPT DELETE END/d" \
		< Makefile | $(SED) -e "/^# EXPORT DELETE/d" > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile digestmd5/digestmd5.c gssapi/gssapi.c

# CRYPT DELETE END
# EXPORT DELETE END

include ../Makefile.targ

.PARALLEL: $(SUBDIRS)
