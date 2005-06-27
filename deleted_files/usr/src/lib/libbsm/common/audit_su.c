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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * BSM hooks for the su command
 */

#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>
#include <bsm/audit_private.h>
#include <limits.h>
#include <pwd.h>
#include <shadow.h>
#include <locale.h>
#include <unistd.h>
#include <string.h>
#include <generic.h>

#define	SU_IS_EXPIRED	1
#define	SU_NOT_EXPIRED	0

static auditinfo_addr_t su_ai;
static int su_expired; /* boolean, are we su-ing to an expired account? */
static char *su_user;
static char *invalid_user = "invalid user";

static void audit_su_init_expired();
static void audit_su();

extern int cannot_audit();

/*
 * Hooks that set private variables.
 */

/* ARGSUSED */
void
audit_su_init_info(char *username, char *ttyn)
{
	if (cannot_audit(0)) {
		return;
	}
	if (username != NULL) {
		su_user = strdup(username);
	} else {
		su_user = invalid_user;
	}
	audit_su_init_expired(username);
	(void) getaudit_addr(&su_ai, sizeof (su_ai));
	(void) aug_save_me();
}

static void
audit_su_init_expired(username)
	char *username;
{
	struct spwd *p_spwd;

	if (cannot_audit(0)) {
		return;
	}

	su_expired = SU_NOT_EXPIRED;

	if ((p_spwd = getspnam(username)) == NULL) {
		return;
	}

	if (p_spwd->sp_expire > 0 && p_spwd->sp_expire < DAY_NOW) {
		su_expired = SU_IS_EXPIRED;
	}
}

void
audit_su_reset_ai(void)
{
	au_mask_t new_users_mask;

	if (cannot_audit(0)) {
		return;
	}

	new_users_mask.am_success = 0;
	new_users_mask.am_failure = 0;

	(void) au_user_mask(su_user, &new_users_mask);
	su_ai.ai_mask.am_success |= new_users_mask.am_success;
	su_ai.ai_mask.am_failure |= new_users_mask.am_failure;

	(void) setaudit_addr(&su_ai, sizeof (su_ai));
}

void
audit_su_success()
{
	if (cannot_audit(0)) {
		return;
	}
	audit_su(dgettext(bsm_dom, "success"), 0);
}

void
audit_su_bad_username()
{
	if (cannot_audit(0)) {
		return;
	}
	audit_su(dgettext(bsm_dom, "bad username"), 1);
}

void
audit_su_bad_authentication()
{
	if (cannot_audit(0)) {
		return;
	}
	audit_su(dgettext(bsm_dom, "bad auth."), 2);
}

void
audit_su_bad_uid(uid)
uid_t uid;
{
	char    textbuf[BSM_TEXTBUFSZ];

	if (cannot_audit(0)) {
		return;
	}
	(void) snprintf(textbuf, sizeof (textbuf),
		dgettext(bsm_dom, "bad uid %ld"), uid);
	audit_su(textbuf, 3);
}

void
audit_su_unknown_failure()
{
	if (cannot_audit(0)) {
		return;
	}
	audit_su(dgettext(bsm_dom, "unknown failure"), 4);
}

/*
 * audit_su: The master hook for su.  It writes records to the audit trail.
 */

static void
audit_su(s, r)
char	*s;	/* string indication success, failure message */
int	r;	/* return code for return token */
{
	char	textbuf[BSM_TEXTBUFSZ];
	char	*exp;

	aug_save_event(AUE_su);
	aug_save_sorf(r);
	if (su_expired == SU_IS_EXPIRED) {
		exp = dgettext(bsm_dom, " (expired)");
	} else {
		exp = "";
	}
	(void) snprintf(textbuf, sizeof (textbuf),
		dgettext(bsm_dom, "%s for user %s%s"), s, su_user, exp);
	aug_save_text(textbuf);
	(void) aug_audit();
}
