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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * svc-auditset - auditset transient service (AUDITSET_FMRI) startup method;
 * sets non-/attributable mask in the kernel context.
 */

#include <audit_scf.h>
#include <bsm/adt.h>
#include <bsm/libbsm.h>
#include <zone.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>

#if !defined(SMF_EXIT_ERR_OTHER)
#define	SMF_EXIT_ERR_OTHER	1
#endif

/*
 * update_kcontext() - updates the non-/attributable preselection masks in
 * the kernel context. Returns B_TRUE on success, B_FALSE otherwise.
 */
boolean_t
update_kcontext(int cmd, char *cmask)
{
	au_mask_t	bmask;

	(void) getauditflagsbin(cmask, &bmask);
	if (auditon(cmd, (caddr_t)&bmask, sizeof (bmask)) == -1) {
		(void) printf("Could not update kernel context (%s).\n",
		    cmd == A_SETAMASK ? "A_SETAMASK" : "A_SETKMASK");
		return (B_FALSE);
	}

#ifdef	DEBUG
	(void) printf("svc-auditset: %s mask set to %s",
	    cmd == A_SETAMASK ? "Attributable" : "Non-Attributable", cmask);
#endif

	return (B_TRUE);
}

int
main(void)
{
	char		*auditset_fmri;
	char		*mask_cfg;
	uint32_t	policy;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* allow execution only inside the SMF facility */
	if ((auditset_fmri = getenv("SMF_FMRI")) == NULL ||
	    strcmp(auditset_fmri, AUDITSET_FMRI) != 0) {
		(void) printf(gettext("svc-auditset can be executed only "
		    "inside the SMF facility.\n"));
		return (SMF_EXIT_ERR_NOSMF);
	}

	/* check the c2audit module state */
	if (adt_audit_state(AUC_DISABLED)) {
#ifdef	DEBUG
		if (errno == ENOTSUP) {
			(void) printf("c2audit module is excluded from "
			    "the system(4); kernel won't be updated.\n");
		} else {
			(void) printf("%s\n", strerror(errno));
		}
#endif
		return (SMF_EXIT_OK);
	}

	/* check the audit policy */
	if (auditon(A_GETPOLICY, (caddr_t)&policy, 0) == -1) {
		(void) printf("Could not read audit policy: %s\n",
		    strerror(errno));
		return (SMF_EXIT_ERR_OTHER);
	}

	if (!(policy & AUDIT_PERZONE) && (getzoneid() != GLOBAL_ZONEID))
		return (SMF_EXIT_OK);

	/* update attributable mask */
	if (!do_getflags_scf(&mask_cfg) || mask_cfg == NULL) {
		(void) printf("Could not get configured attributable audit "
		    "flags.\n");
		return (SMF_EXIT_ERR_OTHER);
	}
	if (!update_kcontext(A_SETAMASK, mask_cfg)) {
		free(mask_cfg);
		return (SMF_EXIT_ERR_OTHER);
	}
	free(mask_cfg);

	/* update non-attributable mask */
	if (!do_getnaflags_scf(&mask_cfg) || mask_cfg == NULL) {
		(void) printf("Could not get configured non-attributable "
		    "audit flags.\n");
		return (SMF_EXIT_ERR_OTHER);
	}
	if (!update_kcontext(A_SETKMASK, mask_cfg)) {
		free(mask_cfg);
		return (SMF_EXIT_ERR_OTHER);
	}
	free(mask_cfg);

	return (SMF_EXIT_OK);
}
