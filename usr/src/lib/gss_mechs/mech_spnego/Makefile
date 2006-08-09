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

#
# This make file will build mech_spnego.so.1. This shared object
# contains all the functionality needed to support the 
# SPNEGO GSS-API mechanism. 
#

include ../../Makefile.lib

SUBDIRS= $(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

HDRS	=	gssapiP_spnego.h
HDRDIR	=	mech

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=         TARGET= lint

.KEEP_STATE:

all clean clobber install lint:  $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

# EXPORT DELETE START
# Special target to clean up the source tree for export distribution
# Warning: This target changes the source tree
EXPORT_SRC:
	$(RM) Makefile+ mech/spnego_mech.c+
	sed -e "/EXPORT DELETE START/,/EXPORT DELETE END/d" \
		< mech/spnego_mech.c > mech/spnego_mech.c+ 
	$(MV) mech/spnego_mech.c+ mech/spnego_mech.c
	sed -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile mech/spnego_mech.c

# CRYPT DELETE START
# Special target to clean up the source tree for domestic distribution
# Warning: This target changes the source tree
CRYPT_SRC:
	$(RM) Makefile+ mech/spnego_mech.c+
	sed -e "/CRYPT DELETE START/,/CRYPT DELETE END/d" \
		< mech/spnego_mech.c > mech/spnego_mech.c+ 
	$(MV) mech/spnego_mech.c+ mech/spnego_mech.c
	sed -e "/^# CRYPT DELETE START/,/^# CRYPT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile mech/spnego_mech.c

# CRYPT DELETE END
# EXPORT DELETE END
