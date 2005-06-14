#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 1996-1997, 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../Makefile.com

DATAFILES += depend
CLOBBERFILES += action

ACTION_SUNWsprot=grep SUNWsprot depend > /dev/null || \
	( chmod 666 depend; \
	echo "P SUNWsprot     SPARCompilers Bundled tools" >> depend; \
	chmod 444 depend );

ACTION_SUNWlibC=grep SUNWlibC depend > /dev/null || \
	( chmod 666 depend; \
	echo "P SUNWlibC      Sun Workshop Compilers Bundled libC" >> depend; \
	chmod 444 depend );

ACTION_SUNWnisr=grep SUNWnisr depend > /dev/null || \
	( chmod 666 depend; \
	echo "P SUNWnisr      Network Information System, (Root)" >> depend; \
	chmod 444 depend )

ACTION_SUNWnisu=grep SUNWnisu depend > /dev/null || \
	( chmod 666 depend; \
	echo "P SUNWnisu      Network Information System, (Usr)" >> depend; \
	chmod 444 depend )

ACTION_SUNWnskit=grep SUNWnskit depend > /dev/null || \
	( chmod 666 depend; \
	echo "I SUNWnskit     BCP NIS Server for 5.x" >> depend; \
	chmod 444 depend )

ACTION_SUNWnsktr=grep SUNWnsktr depend > /dev/null || \
	( chmod 666 depend; \
	echo "I SUNWnsktr     NIS Server for Solaris (root)" >> depend; \
	chmod 444 depend )

ACTION_SUNWnsktu=grep SUNWnsktu depend > /dev/null || \
	( chmod 666 depend; \
	echo "I SUNWnsktu     NIS Server for Solaris (usr)" >> depend; \
	chmod 444 depend )

ACTION_SUNWypr=grep SUNWypr depend > /dev/null || \
	( chmod 666 depend; \
	echo "P SUNWypr       NIS Server for Solaris 2.6 and above (root)" >> depend; \
	chmod 444 depend )

.KEEP_STATE:

all: $(FILES) action

install: all pkg

# action is a pseudotarget denoting completed work on the depend file
action: depend
	$(ACTION_SUNWsprot)
	$(ACTION_SUNWnisr)
	$(ACTION_SUNWnisu)
	$(ACTION_SUNWnskit)
	$(ACTION_SUNWnsktr)
	$(ACTION_SUNWnsktu)
	$(ACTION_SUNWypr)
	touch $@

include ../Makefile.targ
