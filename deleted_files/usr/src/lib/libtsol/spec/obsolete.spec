#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	Obsolete interfaces to be removed from a future release.
#	Retained to aid 3rd party initial porting from TS8.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#

function	bcleartoh_r
include		<tsol/label.h>
declaration	char *bcleartoh_r(const bclear_t *clearance, char *hex);
version		SUNWprivate_1.1
end

function	bcleartoh
include		<tsol/label.h>
declaration	char *bcleartoh(const bclear_t *clearance);
version		SUNWprivate_1.1
end

function	bltocolor
include		<tsol/label.h>
declaration	char *bltocolor(const blevel_t *label);
version		SUNWprivate_1.1
end

function	bltocolor_r
include		<tsol/label.h>
declaration	char *bltocolor_r(const blevel_t *label, int size, \
		    char *color_name);
version		SUNWprivate_1.1
end

function	bsltoh
include		<tsol/label.h>
declaration	char *bsltoh(const bslabel_t *label);
version		SUNWprivate_1.1
end

function	bsltoh_r
include		<tsol/label.h>
declaration	char *bsltoh_r(const bslabel_t *label, char *hex);
version		SUNWprivate_1.1
end

function	bsltos
include		<tsol/label.h>
declaration	ssize_t bsltos(const bslabel_t *label, char **string, \
		    size_t str_len, int flags);
version		SUNWprivate_1.1
end

function	h_alloc
include		<tsol/label.h>
declaration	char *h_alloc(unsigned char id);
version		SUNWprivate_1.1
end

function	h_free
include		<tsol/label.h>
declaration	void h_free(char *hex);
version		SUNWprivate_1.1
end

function	htobclear
include		<tsol/label.h>
declaration	int htobclear(const char *s, bclear_t *clearance);
version		SUNWprivate_1.1
end

function	htobsl
include		<tsol/label.h>
declaration	int htobsl(const char *s, bslabel_t *label);
version		SUNWprivate_1.1
end

function	sbcleartos
include		<tsol/label.h>
declaration	char *sbcleartos(const bclear_t *clearance, int len);
version		SUNWprivate_1.1
end

function	sbsltos
include		<tsol/label.h>
declaration	char *sbsltos(const bslabel_t *label, int len);
version		SUNWprivate_1.1
end

function	stobclear
include		<tsol/label.h>
declaration	int stobclear(const char *string, bclear_t *clearance, \
		    int flags, int *error);
version		SUNWprivate_1.1
end

function	stobsl
include		<tsol/label.h>
declaration	int stobsl(const char *string, bslabel_t *label, int flags, \
		    int *error);
version		SUNWprivate_1.1
end
