/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Utils.xs contains XS wrappers for utility functions needed initially by
 * Sun::Solaris::Kstat, but that should prove generally useful as well.
 */

/* Solaris includes */
#include <libgen.h>
#include <libintl.h>

/* Perl XS includes */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/*
 * The XS code exported to perl is below here.  Note that the XS preprocessor
 * has its own commenting syntax, so all comments from this point on are in
 * that form.
 */

MODULE = Sun::Solaris::Utils PACKAGE = Sun::Solaris::Utils
PROTOTYPES: ENABLE

 #
 # See gmatch(3GEN)
 #

int
gmatch(str, pattern)
	char *str;
	char *pattern;

 #
 # See gettext(3C)
 #

char *
gettext(msgid)
	char *msgid

 #
 # See dcgettext(3C)
 #

char *
dcgettext(domainname, msgid, category)
	char *domainname
	char *msgid
	int  category

 #
 # See dgettext(3C)
 #

char *
dgettext(domainname, msgid)
	char *domainname
	char *msgid

 #
 # See textdomain(3C)
 #

char *
textdomain(domain)
	char *domain

 #
 # See bindtextdomain(3C)
 #

char *
bindtextdomain(domain, dirname)
	char *domain
	char *dirname
