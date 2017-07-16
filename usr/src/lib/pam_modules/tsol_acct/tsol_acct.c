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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libtsnet.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <zone.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_impl.h>

#include <tsol/label.h>

/*
 *	pam_tsol_account - Trusted Extensions account management.
 *		Validates that the user's label range contains
 *		the process label (label of the zone).
 */

static void
free_labels(m_range_t *r, m_label_t *l)
{
	m_label_free(r->lower_bound);
	m_label_free(r->upper_bound);
	free(r);
	m_label_free(l);
}

/* ARGSUSED */
int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int i;
	int debug = 0;
	int allow_unlabeled = 0;
	char *user;
	char *rhost;
	m_range_t *range;
	m_label_t *plabel;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "debug") == 0) {
			debug = 1;
		} else if (strcmp(argv[i], "allow_unlabeled") == 0) {
			allow_unlabeled = 1;
		} else {
			__pam_log(LOG_AUTH | LOG_ERR,
			    "pam_tsol_account: illegal option %s", argv[i]);
		}
	}

	/* Trusted Extensions not enabled */

	if (!is_system_labeled())
		return (PAM_IGNORE);

	(void) pam_get_item(pamh, PAM_USER, (void **)&user);

	(void) pam_get_item(pamh, PAM_RHOST, (void **)&rhost);

	if (debug) {
		__pam_log(LOG_AUTH | LOG_DEBUG,
		    "pam_tsol_account: allowed_unlabeled = %d, user %s, "
		    "rhost %s",
		    allow_unlabeled,
		    (user == NULL) ? "NULL" : (*user == '\0') ? "ZERO" :
		    user,
		    (rhost == NULL) ? "NULL" : (*rhost == '\0') ? "ZERO" :
		    rhost);
	}
	if (user == NULL || *user == '\0') {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_tsol_account: no user");
		return (PAM_USER_UNKNOWN);
	}

	if ((range = getuserrange(user)) == NULL) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_tsol_account: getuserrange(%s) failure", user);
		return (PAM_SYSTEM_ERR);
	}
	if ((plabel = m_label_alloc(MAC_LABEL)) == NULL) {
		__pam_log(LOG_AUTH | LOG_ERR,
		    "pam_tsol_account: out of memory");
		free_labels(range, NULL);
		return (PAM_BUF_ERR);
	}
	if (getplabel(plabel) < 0) {
		__pam_log(LOG_AUTH | LOG_CRIT,
		    "pam_tsol_account: Unable to get process label %m");
		free_labels(range, plabel);
		return (PAM_SYSTEM_ERR);
	}
	if (!blinrange(plabel, range)) {
		free_labels(range, plabel);
		return (PAM_PERM_DENIED);
	}

	free_labels(range, plabel);

	/* Remote Host Type Policy Check */

	if ((allow_unlabeled == 0) &&
	    (getzoneid() == GLOBAL_ZONEID) &&
	    (rhost != NULL && *rhost != '\0')) {
		tsol_host_type_t host_type;

		host_type = tsol_getrhtype(rhost);
		switch (host_type) {
		case SUN_CIPSO:
			break;

		case UNLABELED:
		default:
			return (PAM_PERM_DENIED);
		}
	}
	return (PAM_SUCCESS);
}
