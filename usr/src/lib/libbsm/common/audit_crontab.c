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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>
#include <bsm/audit_private.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>

#include <locale.h>
#include "generic.h"

#define	AUDIT_GET_DIFFS_NO_CRONTAB	1
#define	AUDIT_GET_DIFFS_CRONTAB		0
#define	AUDIT_GET_DIFFS_ERR		-1
#define	AUDIT_GET_DIFFS_NO_DIFFS	-2

static int	audit_crontab_get_diffs(char *cf, char *tmp_name,
		    char **bufptr);

int
audit_crontab_modify(char *path, char *tmp_path, int sorf)
{
	int r, create = 0;
	char *diffs = NULL;

	if (cannot_audit(0)) {
		return (0);
	} else {
		au_event_t event;
		char *anc_name;
		auditinfo_addr_t ai;

		if (getaudit_addr(&ai, sizeof (ai))) {
			return (-1);
		}

		r = audit_crontab_get_diffs(path, tmp_path, &diffs);

		if (r == AUDIT_GET_DIFFS_NO_DIFFS) {
			return (0);
		}
		if (diffs != NULL && r != AUDIT_GET_DIFFS_ERR) {
			aug_save_text(diffs);
			free(diffs);
		}

		if (r == AUDIT_GET_DIFFS_NO_CRONTAB) {
			create = 1;
			if (diffs == NULL)
				aug_save_text("");
		}

		/*
		 * create an ancilary file if audit characteristics exist
		 * else delete an ancilary if if one exists
		 */

		anc_name = audit_cron_make_anc_name(path);
		if (anc_name == NULL)
			r = -1;
		else if (audit_crontab_process_not_audited()) {
			(void) unlink(anc_name);
			free(anc_name);
		} else {
			r = audit_cron_setinfo(anc_name, &ai);
			free(anc_name);
		}
		aug_init();
		aug_save_auid(ai.ai_auid);
		aug_save_euid(geteuid());
		aug_save_egid(getegid());
		aug_save_uid(getuid());
		aug_save_gid(getgid());
		aug_save_pid(getpid());
		aug_save_asid(ai.ai_asid);
		aug_save_tid_ex(ai.ai_termid.at_port, ai.ai_termid.at_addr,
			ai.ai_termid.at_type);


		aug_save_path(path);
		event = (create) ? AUE_crontab_create : AUE_crontab_mod;
		aug_save_event(event);
		aug_save_sorf(sorf);

		if (aug_audit() != 0)
			return (-1);
		return (r);
	}
}

int
audit_crontab_delete(char *path, int sorf)
{
	int r = 0;

	if (cannot_audit(0)) {
		return (0);
	} else {
		char *anc_name;
		anc_name = audit_cron_make_anc_name(path);
		if (anc_name != NULL) {
			r = unlink(anc_name);
			free(anc_name);
		} else
			r = -1;

		aug_init();
		(void) aug_save_me();

		aug_save_path(path);
		aug_save_event(AUE_crontab_delete);
		aug_save_sorf(sorf);
		if (aug_audit() != 0)
			return (-1);
		return (r);
	}
}

/*
 * gets differences between old and new crontab files.
 * arguments:
 * cf        - name of crontab file
 * tmp_name  - name of new crontab file
 * bufptr    - pointer to an array of characters with
 *             either an error message or an output of "diff" command.
 *
 * results:
 * AUDIT_GET_DIFFS_ERR       - errors;
 *			file not exists (do not free *bufptr in this case)
 * AUDIT_GET_DIFFS_NO_DIFFS  - errors;
 *			file exists (do not free *bufptr in this case)
 * AUDIT_GET_DIFFS_CRONTAB      - OK, old crontab file exists.
 * AUDIT_GET_DIFFS_NO_CRONTAB   - OK. there is no crontab file.
 */
static int
audit_crontab_get_diffs(char *cf, char *tmp_name, char **bufptr)
{
	struct stat st, st_tmp;
	uid_t	euid;
	int	len, r = AUDIT_GET_DIFFS_CRONTAB;
	char	*buf = NULL, err_buf[128];

	(void) memset(err_buf, 0, 128);
	euid = geteuid();
	if (seteuid(0) == -1) {
		r = AUDIT_GET_DIFFS_ERR;
		(void) snprintf(err_buf, sizeof (err_buf),
		    "crontab: seteuid: %s\n", strerror(errno));
		goto exit_diff;
	}
	if (stat(cf, &st) == -1) {
		if (errno == ENOENT) {
			r = AUDIT_GET_DIFFS_NO_CRONTAB;
		} else {
			r = AUDIT_GET_DIFFS_ERR;
			(void) snprintf(err_buf, sizeof (err_buf),
				"crontab: %s: stat: %s\n",
				cf, strerror(errno));
			goto exit_diff;
		}
		len = 0;
	} else
		len = st.st_size;

	if (stat(tmp_name, &st_tmp) == -1) {
		r = AUDIT_GET_DIFFS_ERR;
		(void) snprintf(err_buf, sizeof (err_buf),
			"crontab: %s: stat: %s\n",
			tmp_name, strerror(errno));
		goto exit_diff;
	}

	if (st_tmp.st_size == 0 && len == 0) {
	/* there is no difference */
		r = AUDIT_GET_DIFFS_NO_DIFFS;
		*bufptr = NULL;
		goto exit_diff;
	}

exit_diff:
	/* return information on create or update crontab */
	(void) seteuid(euid);
	switch (r) {
	case AUDIT_GET_DIFFS_ERR:
		if (buf != NULL)
			free(buf);
		*bufptr = err_buf;
		break;
	case AUDIT_GET_DIFFS_NO_DIFFS:
		if (buf != NULL)
			free(buf);
		*bufptr = NULL;
		break;
	case AUDIT_GET_DIFFS_CRONTAB:
		if (buf != NULL) {
			if (strlen(buf) != 0) {
				*bufptr = buf;
			} else {
				r = AUDIT_GET_DIFFS_NO_DIFFS;
				*bufptr = NULL;
			}
		}
		break;
	case AUDIT_GET_DIFFS_NO_CRONTAB:
		if (buf != NULL) {
			if (strlen(buf) != 0) {
				*bufptr = buf;
			} else {
				*bufptr = NULL;
				free(buf);
			}
		}
		break;
	}

	return (r);
}

/*
 * audit_crontab_not_allowed determines if we have a case that should be audited
 * but we can't.  If auditing is enabled but the current process is not
 * audited, then the ruid of the user doing the editing must be the owner
 * id of the file to be edited.
 *
 * When audit_crontab_not_allowed is called, ruid is for the crontab file
 * to be modified or created.
 */

#define	PWD_BUFFER_SIZE	512

int
audit_crontab_not_allowed(uid_t ruid, char *user) {
	struct passwd		pwd;
	char			buffer[PWD_BUFFER_SIZE];
	int			rc = 0;		/* 0 == allow */

	if (!cannot_audit(0)) {			/* allow access if audit off */
		if (getpwnam_r(user, &pwd, buffer, PWD_BUFFER_SIZE) == NULL) {
			rc = 1;			/* deny access if invalid */
		} else if (ruid == pwd.pw_uid)
			rc = 0;			/* editing his own crontab */
		else
			rc = audit_crontab_process_not_audited();
	}
	return (rc);
}

int
audit_crontab_process_not_audited() {
	struct auditpinfo_addr	info;
	int	rc;

	info.ap_pid = getpid();
	if (auditon(A_GETPINFO_ADDR, (caddr_t)&info, sizeof (info)) != 0)
		rc = 0;			/* audit failure: not enabled */
	else
		rc = (info.ap_auid == AU_NOAUDITID);

	return (rc);
}
