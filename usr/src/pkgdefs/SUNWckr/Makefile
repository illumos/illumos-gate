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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../Makefile.com

DATAFILES +=	i.etcsystem i.kcfconfbase i.manifest i.preserve i.renameold \
		i.scsivhciconf i.mptconf

MACHDATAFILES += i.sdconf
CLOBBERFILES += $(MACHDATAFILES)

LICENSEFILES_i386 = \
	../../uts/intel/io/acpica/THIRDPARTYLICENSE \
	../../common/crypto/arcfour/amd64/THIRDPARTYLICENSE \
	../../common/crypto/sha1/amd64/THIRDPARTYLICENSE \
	../../common/crypto/sha2/amd64/THIRDPARTYLICENSE

LICENSEFILES += \
	../../common/crypto/ecc/THIRDPARTYLICENSE \
	../../common/mpi/THIRDPARTYLICENSE \
	../../uts/common/inet/ip/THIRDPARTYLICENSE.rts \
	../../uts/common/inet/tcp/THIRDPARTYLICENSE \
	../../uts/common/io/THIRDPARTYLICENSE.etheraddr \
	../../uts/common/sys/THIRDPARTYLICENSE.icu \
	../../uts/common/sys/THIRDPARTYLICENSE.unicode \
	$(LICENSEFILES_$(MACH))

.KEEP_STATE:

all: $(FILES) $(MACHDATAFILES) depend preinstall postinstall

install: all pkg

include ../Makefile.targ
