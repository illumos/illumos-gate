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
#include <sys/systeminfo.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>
#include <bsm/audit_private.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <locale.h>
#include "generic.h"

#define	AUDIT_AT_TEXTBUF	256
static char textbuf[AUDIT_AT_TEXTBUF];

int
audit_at_create(char *path, int sorf)
{
	int r = 0;

	if (cannot_audit(0)) {
		return (0);
	} else {
		char *anc_name;
		auditinfo_addr_t ai;

		if (getaudit_addr(&ai, sizeof (ai))) {
			return (-1);
		}

		/*
		 * create an ancilary file if audit characteristics exist
		 */

		anc_name = audit_cron_make_anc_name(path);
		if (anc_name == NULL)
			r = -1;
		else if (audit_crontab_process_not_audited())
			free(anc_name);
		else {
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
		aug_save_event(AUE_at_create);
		aug_save_sorf(sorf);

		if (aug_audit() != 0)
			return (-1);

		return (r);
	}
}

int
audit_at_delete(char *name, char *path, int sorf)
{
	int r = 0, err = 0;
	char full_path[PATH_MAX];

	if (cannot_audit(0))
		return (0);

	if (path != NULL) {
		if (strlen(path) + strlen(name) + 2 > PATH_MAX)
			r = -2;		/* bad at-job name */
		else {
			(void) strcat(strcat(strcpy(full_path, path), "/"),
			    name);
			name = full_path;
		}
	}

	if (sorf == 0) {
		char *anc_name;
		anc_name = audit_cron_make_anc_name(name);
		r = unlink(anc_name);
		if (r == -1)
			err = errno;
		free(anc_name);
	}

	aug_init();
	(void) aug_save_me();
	if (r == -1) {
		(void) snprintf(textbuf, sizeof (textbuf),
			dgettext(bsm_dom, "ancillary file: %s"),
			strerror(err));
		aug_save_text(textbuf);
	} else if (r == -2) {
		aug_save_text(
			dgettext(bsm_dom, "bad format of at-job name"));
	}

	aug_save_path(name);
	aug_save_event(AUE_at_delete);
	aug_save_sorf(sorf);

	if (aug_audit() != 0)
		return (-1);
	return (r);
}
