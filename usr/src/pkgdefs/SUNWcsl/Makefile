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

include ../Makefile.com

.KEEP_STATE:

LICENSEFILES_i386 = lic_AMD 
LICENSEFILES += $(LICENSEFILES_$(MACH)) \
	../../common/mpi/THIRDPARTYLICENSE \
	../../lib/libast/THIRDPARTYLICENSE \
	../../lib/libbsdmalloc/THIRDPARTYLICENSE \
	../../lib/libcmd/THIRDPARTYLICENSE \
	../../lib/libdll/THIRDPARTYLICENSE \
	../../lib/libkmf/THIRDPARTYLICENSE \
	../../lib/libldap5/THIRDPARTYLICENSE \
	../../lib/libshell/THIRDPARTYLICENSE \
	../../lib/libsum/THIRDPARTYLICENSE \
	../../lib/libwrap/THIRDPARTYLICENSE \
	../../lib/pam_modules/authtok_check/THIRDPARTYLICENSE \
	../../lib/passwdutil/THIRDPARTYLICENSE

all: $(FILES)

install: all pkg

include ../Makefile.targ

