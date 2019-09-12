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

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <string.h>
#include <stdlib.h>
#include <alloca.h>
#include <libuutil.h>

#include "idtab.h"
#include "psexp.h"

void
psexp_create(psexp_t *psexp)
{
	idtab_create(&psexp->ps_euids);
	idtab_create(&psexp->ps_ruids);
	idtab_create(&psexp->ps_rgids);
	idtab_create(&psexp->ps_ppids);
	idtab_create(&psexp->ps_pgids);
	idtab_create(&psexp->ps_sids);
	idtab_create(&psexp->ps_ttys);
	idtab_create(&psexp->ps_projids);
	idtab_create(&psexp->ps_taskids);
	idtab_create(&psexp->ps_zoneids);
	idtab_create(&psexp->ps_ctids);

	psexp->ps_pat = NULL;
}

void
psexp_destroy(psexp_t *psexp)
{
	idtab_destroy(&psexp->ps_euids);
	idtab_destroy(&psexp->ps_ruids);
	idtab_destroy(&psexp->ps_rgids);
	idtab_destroy(&psexp->ps_ppids);
	idtab_destroy(&psexp->ps_pgids);
	idtab_destroy(&psexp->ps_sids);
	idtab_destroy(&psexp->ps_ttys);
	idtab_destroy(&psexp->ps_projids);
	idtab_destroy(&psexp->ps_taskids);
	idtab_destroy(&psexp->ps_zoneids);
	idtab_destroy(&psexp->ps_ctids);

	if (psexp->ps_pat)
		regfree(&psexp->ps_reg);
}

int
psexp_compile(psexp_t *psexp)
{
	size_t nbytes;
	char *buf;
	int err;

	idtab_sort(&psexp->ps_euids);
	idtab_sort(&psexp->ps_ruids);
	idtab_sort(&psexp->ps_rgids);
	idtab_sort(&psexp->ps_ppids);
	idtab_sort(&psexp->ps_pgids);
	idtab_sort(&psexp->ps_sids);
	idtab_sort(&psexp->ps_ttys);
	idtab_sort(&psexp->ps_projids);
	idtab_sort(&psexp->ps_taskids);
	idtab_sort(&psexp->ps_zoneids);
	idtab_sort(&psexp->ps_ctids);

	if (psexp->ps_pat != NULL) {
		if ((err = regcomp(&psexp->ps_reg, psexp->ps_pat,
		    REG_EXTENDED)) != 0) {

			nbytes = regerror(err, &psexp->ps_reg, NULL, 0);
			buf = alloca(nbytes + 1);
			(void) regerror(err, &psexp->ps_reg, buf, nbytes);
			(void) strcat(buf, "\n");
			uu_warn(buf);
			return (-1);
		}
	}

	return (0);
}

#define	NOMATCH(__f1, __f2) \
	psexp->__f1.id_data && !idtab_search(&psexp->__f1, psinfo->__f2)

int
psexp_match(psexp_t *psexp, psinfo_t *psinfo, const char *argv, int flags)
{
	regmatch_t pmatch;

	if (NOMATCH(ps_euids, pr_euid))
		return (0);
	if (NOMATCH(ps_ruids, pr_uid))
		return (0);
	if (NOMATCH(ps_rgids, pr_gid))
		return (0);
	if (NOMATCH(ps_ppids, pr_ppid))
		return (0);
	if (NOMATCH(ps_pgids, pr_pgid))
		return (0);
	if (NOMATCH(ps_sids, pr_sid))
		return (0);
	if (NOMATCH(ps_ttys, pr_ttydev))
		return (0);
	if (NOMATCH(ps_projids, pr_projid))
		return (0);
	if (NOMATCH(ps_taskids, pr_taskid))
		return (0);
	if (NOMATCH(ps_zoneids, pr_zoneid))
		return (0);
	if (NOMATCH(ps_ctids, pr_contract))
		return (0);

	if (psexp->ps_pat != NULL) {
		if (regexec(&psexp->ps_reg, argv, 1, &pmatch, 0) != 0)
			return (0);

		if ((flags & PSEXP_EXACT) &&
		    (pmatch.rm_so != 0 || argv[pmatch.rm_eo] != '\0'))
			return (0);
	}

	return (1);
}
