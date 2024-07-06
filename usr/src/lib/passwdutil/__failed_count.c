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
 * Copyright 2024 OmniOS Community Edition (OmniOSce) Association.
 */

#include <string.h>
#include <syslog.h>
#include "passwdutil.h"

int
__incr_failed_count(const char *username, char *repname, int max_failures)
{
	int ret;
	void *buf;
	attrlist items[1];
	int repnum = name_to_int(repname);
	repops_t *ops;

	/* account locking only defined for files and ldap */
	if ((repnum != REP_FILES) &&
	    (repnum != REP_LDAP)) {
		return (PWU_SUCCESS);
	}

	ops = rops[repnum];
	if ((ops->lock != NULL) &&
	    (ret = ops->lock()) != PWU_SUCCESS) {
		return (ret);
	}

	items[0].type = ATTR_INCR_FAILED_LOGINS;
	items[0].next = NULL;
	if ((ret = ops->getpwnam(username, items, NULL, &buf)) != PWU_SUCCESS) {
		goto out;
	}

	/* We increment the failed count by one */
	if ((ret = ops->update(items, NULL, buf)) != PWU_SUCCESS) {
		goto out;
	}

	/* Did we just exceed "max_failures" ? */
	if (items[0].data.val_i >= max_failures) {
		syslog(LOG_AUTH|LOG_NOTICE,
		    "Excessive (%d) login failures for %s: locking account.",
		    max_failures, username);

		items[0].type = ATTR_LOCK_ACCOUNT;
		if ((ret = ops->update(items, NULL, buf)) != PWU_SUCCESS)
			goto out;
	}
	if (((ret = ops->putpwnam(username, NULL, NULL, buf)) ==
	    PWU_SUCCESS) &&
	    (items[0].type == ATTR_LOCK_ACCOUNT))
		ret = PWU_ACCOUNT_LOCKED;

out:
	if (ops->unlock != NULL) {
		ops->unlock();
	}

	return (ret);
}

/*
 * reset the failed count.
 * returns the number of failed logins before the reset, or an error (< 0)
 */
int
__rst_failed_count(const char *username, char *repname)
{
	int ret;
	void *buf;
	attrlist items[1];
	int repnum = name_to_int(repname);
	repops_t *ops;

	/* account locking only defined for files and ldap */
	if ((repnum != REP_FILES) &&
	    (repnum != REP_LDAP)) {
		return (PWU_SUCCESS);
	}

	ops = rops[repnum];
	if ((ops->lock != NULL) &&
	    (ret = ops->lock()) != PWU_SUCCESS) {
		return (ret);
	}

	items[0].type = ATTR_RST_FAILED_LOGINS;
	items[0].next = NULL;
	if ((ret = ops->getpwnam(username, items, NULL, &buf)) != PWU_SUCCESS)
		goto out;
	if ((ret = ops->update(items, NULL, buf)) != PWU_SUCCESS)
		goto out;
	ret = ops->putpwnam(username, NULL, NULL, buf);
out:
	if (ops->unlock != NULL) {
		ops->unlock();
	}

	return (ret != PWU_SUCCESS ? ret : items[0].data.val_i);
}
