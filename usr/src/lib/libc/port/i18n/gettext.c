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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2015 Joyent, Inc.
 */

#pragma weak _bindtextdomain = bindtextdomain
#pragma weak _textdomain = textdomain
#pragma weak _gettext = gettext
#pragma weak _dgettext = dgettext
#pragma weak _dcgettext = dcgettext
#pragma weak _ngettext = ngettext
#pragma weak _dngettext = dngettext
#pragma weak _dcngettext = dcngettext
#pragma weak _bind_textdomain_codeset = bind_textdomain_codeset

#include "lint.h"
#include "mtlib.h"
#include <errno.h>
#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/param.h>
#include <libintl.h>
#include <thread.h>
#include <synch.h>
#include "libc.h"
#include "_loc_path.h"
#include "msgfmt.h"
#include "gettext.h"

#define	INIT_GT(def) \
	if (!global_gt) { \
		global_gt = (Gettext_t *)calloc(1, sizeof (Gettext_t)); \
		if (global_gt) \
			global_gt->cur_domain = (char *)default_domain; \
		else { \
			callout_lock_exit(); \
			return ((def)); \
		} \
	}

const char	*defaultbind = DEFAULT_BINDING;
const char	default_domain[] = DEFAULT_DOMAIN;
Gettext_t	*global_gt = NULL;

char *
bindtextdomain(const char *domain, const char *binding)
{
	char	*res;

	callout_lock_enter();
	INIT_GT(NULL);
	res = _real_bindtextdomain_u(domain, binding, TP_BINDING);
	callout_lock_exit();
	return (res);
}

char *
bind_textdomain_codeset(const char *domain, const char *codeset)
{
	char	*res;

	callout_lock_enter();
	INIT_GT(NULL);
	res = _real_bindtextdomain_u(domain, codeset, TP_CODESET);
	callout_lock_exit();
	return (res);
}

/*
 * textdomain() sets or queries the name of the current domain of
 * the active LC_MESSAGES locale category.
 */
char *
textdomain(const char *domain)
{
	char	*res;
	char	tmp_domain[TEXTDOMAINMAX + 1];

	callout_lock_enter();
	INIT_GT(NULL);
	res = _textdomain_u(domain, tmp_domain);
	if (res == NULL) {
		callout_lock_exit();
		return (NULL);
	}
	callout_lock_exit();
	return (CURRENT_DOMAIN(global_gt));
}

/*
 * gettext() is a pass-thru to _real_gettext_u() with a NULL pointer passed
 * for domain and LC_MESSAGES passed for category.
 */
char *
gettext(const char *msg_id)
{
	char	*res;
	int	errno_save = errno;

	callout_lock_enter();
	INIT_GT((char *)msg_id);
	res = _real_gettext_u(NULL, msg_id, NULL, 0, LC_MESSAGES, 0, NULL);
	callout_lock_exit();
	errno = errno_save;
	return (res);
}


/*
 * In dcgettext() call, domain is valid only for this call.
 */
char *
dgettext(const char *domain, const char *msg_id)
{
	char	*res;
	int	errno_save = errno;

	callout_lock_enter();
	INIT_GT((char *)msg_id);
	res = _real_gettext_u(domain, msg_id, NULL, 0, LC_MESSAGES, 0, NULL);
	callout_lock_exit();
	errno = errno_save;
	return (res);
}

char *
dgettext_l(const char *domain, const char *msg_id, locale_t loc)
{
	char	*res;
	int	errno_save = errno;

	callout_lock_enter();
	INIT_GT((char *)msg_id);
	res = _real_gettext_u(domain, msg_id, NULL, 0, LC_MESSAGES, 0, loc);
	callout_lock_exit();
	errno = errno_save;
	return (res);
}

char *
dcgettext(const char *domain, const char *msg_id, const int category)
{
	char	*res;
	int	errno_save = errno;

	callout_lock_enter();
	INIT_GT((char *)msg_id);
	res = _real_gettext_u(domain, msg_id, NULL, 0, category, 0, NULL);
	callout_lock_exit();
	errno = errno_save;
	return (res);
}

char *
ngettext(const char *msgid1, const char *msgid2, unsigned long int n)
{
	char	*res;
	int	errno_save = errno;

	callout_lock_enter();
	INIT_GT((char *)msgid1);
	res = _real_gettext_u(NULL, msgid1, msgid2, n, LC_MESSAGES, 1, NULL);
	callout_lock_exit();
	errno = errno_save;
	return (res);
}

char *
dngettext(const char *domain, const char *msgid1, const char *msgid2,
	unsigned long int n)
{
	char	*res;
	int	errno_save = errno;

	callout_lock_enter();
	INIT_GT((char *)msgid1);
	res = _real_gettext_u(domain, msgid1, msgid2, n, LC_MESSAGES, 1, NULL);
	callout_lock_exit();
	errno = errno_save;
	return (res);
}

char *
dcngettext(const char *domain, const char *msgid1, const char *msgid2,
	unsigned long int n, int category)
{
	char	*res;
	int	errno_save = errno;

	callout_lock_enter();
	INIT_GT((char *)msgid1);
	res = _real_gettext_u(domain, msgid1, msgid2, n, category, 1, NULL);
	callout_lock_exit();
	errno = errno_save;
	return (res);
}
