/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include "libgrub_errno.h"

#define	MAKE_STRING(x)	# x

static const struct {
	int	ge_num;		/* error number */
	char	*ge_name;	/* error name */
	char	*ge_msg;	/* error message */
} _grub_errstr[] = {
/*
 * TRANSLATION_NOTE
 * The following message strings that begin with EG_ do not
 * need to be translated.
 */
#define	grub_errno_def(num, desc)	{ num,	MAKE_STRING(num),	desc},
#include "libgrub_errno.def"
};

#define	GRUB_ERRNO_INDEX(n)	((n) - (EG_START + 1))

const char *
grub_strerror(int err)
{
	return (err <= EG_START || err >= EG_END ?
	    strerror(err) :
	    dgettext(TEXT_DOMAIN, _grub_errstr[ GRUB_ERRNO_INDEX(err)].ge_msg));
}

const char *
grub_errname(int err)
{
	return (err <= EG_START || err >= EG_END ?
	    gettext("Not libgrubmgmt specific") :
	    gettext(_grub_errstr[ GRUB_ERRNO_INDEX(err)].ge_name));
}
