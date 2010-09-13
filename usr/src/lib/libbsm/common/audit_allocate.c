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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <tsol/label.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_private.h>
#include <unistd.h>
#include <string.h>
#include <bsm/audit_uevents.h>
#include <generic.h>
#include <stdlib.h>
#include <alloca.h>

static int s_audit;	/* successful audit event */
static int f_audit;	/* failure audit event */

static int ad;		/* audit descriptor */

void
audit_allocate_argv(flg, argc, argv)
	int   flg;
	int   argc;
	char *argv[];
{
	int i;

	if (cannot_audit(0)) {
		return;
	}

	switch (flg) {
	case 0:
		s_audit = AUE_allocate_succ;
		f_audit = AUE_allocate_fail;
		break;
	case 1:
		s_audit = AUE_deallocate_succ;
		f_audit = AUE_deallocate_fail;
		break;
	case 2:
		s_audit = AUE_listdevice_succ;
		f_audit = AUE_listdevice_fail;
		break;
	}

	ad = au_open();

	for (i = 0; i < argc; i++)
		(void) au_write(ad, au_to_text(argv[i]));
}

void
audit_allocate_device(path)
	char *path;
{
	if (cannot_audit(0)) {
		return;
	}
	(void) au_write(ad, au_to_path(path));
}

int
audit_allocate_record(status)
	char	status;		/* success failure of operation */
{
	auditinfo_addr_t mask;		/* audit ID */
	au_event_t	event;		/* audit event number */
	uint32_t	policy;		/* audit policy */
	int		ng;		/* number of groups in process */

#ifdef DEBUG
	(void) printf("audit_allocate_record(%d)\n", status);
#endif

	if (cannot_audit(0)) {
		return (0);
	}

	if (getaudit_addr(&mask, sizeof (mask)) < 0) {
		if (!status)
			return (1);
		return (0);
	}

	if (auditon(A_GETPOLICY, (caddr_t)&policy, 0) < 0) {
		if (!status)
			return (1);
		return (0);
	}


		/* determine if we're preselected */
	if (status)
		event = f_audit;
	else
		event = s_audit;

	if (au_preselect(event, &mask.ai_mask, AU_PRS_BOTH, AU_PRS_REREAD)
		== NULL)
		return (0);

	(void) au_write(ad, au_to_me());	/* add subject token */
	if (is_system_labeled())
		(void) au_write(ad, au_to_mylabel());

	if (policy & AUDIT_GROUP) {	/* add optional group token */
		gid_t	*grplst;
		int	maxgrp = getgroups(0, NULL);

		grplst = alloca(maxgrp * sizeof (gid_t));

		if ((ng = getgroups(maxgrp, grplst)) < 0) {
			(void) au_close(ad, 0, 0);
			if (!status)
				return (1);
			return (0);
		}
		(void) au_write(ad, au_to_newgroups(ng, grplst));
	}

	if (status)
		(void) au_write(ad, au_to_exit(status, -1));
	else
		(void) au_write(ad, au_to_exit(0, 0));

		/* write audit record */
	if (au_close(ad, 1, event) < 0) {
		(void) au_close(ad, 0, 0);
		if (!status)
			return (1);
	}

	return (0);
}

void
audit_allocate_list(list)
	char *list;
{
	char *buf;
	char *file;
	char *last;

	if (cannot_audit(0)) {
		return;
	}

	if ((buf = strdup(list)) == NULL)
		return;

	for (file = strtok_r(buf, " ", &last); file;
	    file = strtok_r(NULL, " ", &last))
		(void) au_write(ad, au_to_path(file));

	free(buf);
}
