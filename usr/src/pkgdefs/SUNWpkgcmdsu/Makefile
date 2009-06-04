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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/pkgdefs/Makefile.com


DATAFILES += depend
LICENSEFILES += $(ATT) $(SRC)/lib/libpkg/THIRDPARTYLICENSE
CLOBBERFILES += action

ACTION_SUNWpkgcmdsr=grep SUNWpkgcmdsr depend > /dev/null || \
	( chmod 666 depend; \
	echo "P SUNWpkgcmdsr	Package Commands (Root)" >> depend; \
	chmod 444 depend );

ACTION_SUNWwbsup=grep SUNWwbsup depend > /dev/null || \
	( chmod 666 depend; \
	echo "P SUNWwbsup             WAN boot support" \
	chmod 444 depend )

ACTION_SUNopenssl-libraries=grep SUNWopenssl-libraries depend > /dev/null || \
	( chmod 666 depend; \
	echo "P SUNWopenssl-libraries OpenSSL Libraries (Usr) >> depend; \
	chmod 444 depend )

ACTION_SUNWwsr2=grep SUNWwsr2 depend > /dev/null || \
	( chmod 666 depend; \
	echo "P SUNWwsr2  Solaris Product Registry & Web Start runtime support"\
	>> depend; \
	chmod 444 depend );


.KEEP_STATE:

all: $(FILES) action

install: all pkg

# action is a pseudotarget denoting completed work on the depend file
action: depend
	$(ACTION_SUNWpkgcmdsr)
	$(ACTION_SUNWwbsup)
	$(ACTION_SUNWopenssl-libraries)
	$(ACTION_SUNWwsr2)
	touch $@

include $(SRC)/pkgdefs/Makefile.targ
