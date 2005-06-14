#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#ident	"%Z%%M%	%I%	%E% SMI"

function	crypt_genhash_impl
include		<crypt.h>
declaration	char * crypt_genhash_impl(char *ctbuffer, size_t ctbufflen, \
		    const char *plaintext, const char *switchsalt,\
		    const char **params)
version		SUNW_1.0
end

function	crypt_gensalt_impl
include		<crypt.h>
declaration	char *crypt_gensalt_impl(char *gsbuffer, size_t gsbufflen, \
		    const char *oldsalt, const struct passwd *userinfo, \
		    const char **params)
version		SUNW_1.0
end
