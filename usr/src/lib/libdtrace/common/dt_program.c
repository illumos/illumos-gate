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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <dt_impl.h>
#include <dt_program.h>
#include <dt_printf.h>

dtrace_prog_t *
dt_program_create(dtrace_hdl_t *dtp)
{
	dtrace_prog_t *pgp = dt_zalloc(dtp, sizeof (dtrace_prog_t));

	if (pgp != NULL)
		dt_list_append(&dtp->dt_programs, pgp);
	else
		(void) dt_set_errno(dtp, EDT_NOMEM);

	return (pgp);
}

void
dt_program_destroy(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dt_stmt_t *stp, *next;
	uint_t i;

	for (stp = dt_list_next(&pgp->dp_stmts); stp != NULL; stp = next) {
		next = dt_list_next(stp);
		dtrace_stmt_destroy(dtp, stp->ds_desc);
		dt_free(dtp, stp);
	}

	for (i = 0; i < pgp->dp_xrefslen; i++)
		dt_free(dtp, pgp->dp_xrefs[i]);

	dt_free(dtp, pgp->dp_xrefs);
	dt_list_delete(&dtp->dt_programs, pgp);
	dt_free(dtp, pgp);
}

/*ARGSUSED*/
void
dtrace_program_info(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_proginfo_t *pip)
{
	dt_stmt_t *stp;
	dtrace_actdesc_t *ap;
	dtrace_ecbdesc_t *last = NULL;

	if (pip == NULL)
		return;

	bzero(pip, sizeof (dtrace_proginfo_t));

	if (dt_list_next(&pgp->dp_stmts) != NULL) {
		pip->dpi_descattr = _dtrace_maxattr;
		pip->dpi_stmtattr = _dtrace_maxattr;
	} else {
		pip->dpi_descattr = _dtrace_defattr;
		pip->dpi_stmtattr = _dtrace_defattr;
	}

	for (stp = dt_list_next(&pgp->dp_stmts); stp; stp = dt_list_next(stp)) {
		dtrace_ecbdesc_t *edp = stp->ds_desc->dtsd_ecbdesc;

		if (edp == last)
			continue;
		last = edp;

		pip->dpi_descattr =
		    dt_attr_min(stp->ds_desc->dtsd_descattr, pip->dpi_descattr);

		pip->dpi_stmtattr =
		    dt_attr_min(stp->ds_desc->dtsd_stmtattr, pip->dpi_stmtattr);

		/*
		 * If there aren't any actions, account for the fact that
		 * recording the epid will generate a record.
		 */
		if (edp->dted_action == NULL)
			pip->dpi_recgens++;

		for (ap = edp->dted_action; ap != NULL; ap = ap->dtad_next) {
			if (ap->dtad_kind == DTRACEACT_SPECULATE) {
				pip->dpi_speculations++;
				continue;
			}

			if (DTRACEACT_ISAGG(ap->dtad_kind)) {
				pip->dpi_recgens -= ap->dtad_arg;
				pip->dpi_aggregates++;
				continue;
			}

			if (DTRACEACT_ISDESTRUCTIVE(ap->dtad_kind))
				continue;

			if (ap->dtad_kind == DTRACEACT_DIFEXPR &&
			    ap->dtad_difo->dtdo_rtype.dtdt_kind ==
			    DIF_TYPE_CTF &&
			    ap->dtad_difo->dtdo_rtype.dtdt_size == 0)
				continue;

			pip->dpi_recgens++;
		}
	}
}

int
dtrace_program_exec(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_proginfo_t *pip)
{
	void *dof;
	int n, err;

	dtrace_program_info(dtp, pgp, pip);

	if ((dof = dtrace_dof_create(dtp, pgp, DTRACE_D_STRIP)) == NULL)
		return (-1);

	n = dt_ioctl(dtp, DTRACEIOC_ENABLE, dof);
	dtrace_dof_destroy(dtp, dof);

	if (n == -1) {
		switch (errno) {
		case EINVAL:
			err = EDT_DIFINVAL;
			break;
		case EFAULT:
			err = EDT_DIFFAULT;
			break;
		case E2BIG:
			err = EDT_DIFSIZE;
			break;
		default:
			err = errno;
		}

		return (dt_set_errno(dtp, err));
	}

	if (pip != NULL)
		pip->dpi_matches += n;

	return (0);
}

static void
dt_ecbdesc_hold(dtrace_ecbdesc_t *edp)
{
	edp->dted_refcnt++;
}

void
dt_ecbdesc_release(dtrace_hdl_t *dtp, dtrace_ecbdesc_t *edp)
{
	if (--edp->dted_refcnt > 0)
		return;

	dt_difo_free(dtp, edp->dted_pred.dtpdd_difo);
	assert(edp->dted_action == NULL);
	dt_free(dtp, edp);
}

dtrace_ecbdesc_t *
dt_ecbdesc_create(dtrace_hdl_t *dtp, const dtrace_probedesc_t *pdp)
{
	dtrace_ecbdesc_t *edp;

	if ((edp = dt_zalloc(dtp, sizeof (dtrace_ecbdesc_t))) == NULL) {
		(void) dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	edp->dted_probe = *pdp;
	dt_ecbdesc_hold(edp);
	return (edp);
}

dtrace_stmtdesc_t *
dtrace_stmt_create(dtrace_hdl_t *dtp, dtrace_ecbdesc_t *edp)
{
	dtrace_stmtdesc_t *sdp;

	if ((sdp = dt_zalloc(dtp, sizeof (dtrace_stmtdesc_t))) == NULL)
		return (NULL);

	dt_ecbdesc_hold(edp);
	sdp->dtsd_ecbdesc = edp;
	sdp->dtsd_descattr = _dtrace_defattr;
	sdp->dtsd_stmtattr = _dtrace_defattr;

	return (sdp);
}

dtrace_actdesc_t *
dtrace_stmt_action(dtrace_hdl_t *dtp, dtrace_stmtdesc_t *sdp)
{
	dtrace_actdesc_t *new;
	dtrace_ecbdesc_t *edp = sdp->dtsd_ecbdesc;

	if ((new = dt_alloc(dtp, sizeof (dtrace_actdesc_t))) == NULL)
		return (NULL);

	if (sdp->dtsd_action_last != NULL) {
		assert(sdp->dtsd_action != NULL);
		assert(sdp->dtsd_action_last->dtad_next == NULL);
		sdp->dtsd_action_last->dtad_next = new;
	} else {
		dtrace_actdesc_t *ap = edp->dted_action;

		assert(sdp->dtsd_action == NULL);
		sdp->dtsd_action = new;

		while (ap != NULL && ap->dtad_next != NULL)
			ap = ap->dtad_next;

		if (ap == NULL)
			edp->dted_action = new;
		else
			ap->dtad_next = new;
	}

	sdp->dtsd_action_last = new;
	bzero(new, sizeof (dtrace_actdesc_t));
	new->dtad_uarg = (uintptr_t)sdp;

	return (new);
}

int
dtrace_stmt_add(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_stmtdesc_t *sdp)
{
	dt_stmt_t *stp = dt_alloc(dtp, sizeof (dt_stmt_t));

	if (stp == NULL)
		return (-1); /* errno is set for us */

	dt_list_append(&pgp->dp_stmts, stp);
	stp->ds_desc = sdp;

	return (0);
}

int
dtrace_stmt_iter(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_stmt_f *func, void *data)
{
	dt_stmt_t *stp, *next;
	int status = 0;

	for (stp = dt_list_next(&pgp->dp_stmts); stp != NULL; stp = next) {
		next = dt_list_next(stp);
		if ((status = func(dtp, pgp, stp->ds_desc, data)) != 0)
			break;
	}

	return (status);
}

void
dtrace_stmt_destroy(dtrace_hdl_t *dtp, dtrace_stmtdesc_t *sdp)
{
	dtrace_ecbdesc_t *edp = sdp->dtsd_ecbdesc;

	/*
	 * We need to remove any actions that we have on this ECB, and
	 * remove our hold on the ECB itself.
	 */
	if (sdp->dtsd_action != NULL) {
		dtrace_actdesc_t *last = sdp->dtsd_action_last;
		dtrace_actdesc_t *ap, *next;

		assert(last != NULL);

		for (ap = edp->dted_action; ap != NULL; ap = ap->dtad_next) {
			if (ap == sdp->dtsd_action)
				break;

			if (ap->dtad_next == sdp->dtsd_action)
				break;
		}

		assert(ap != NULL);

		if (ap == edp->dted_action)
			edp->dted_action = last->dtad_next;
		else
			ap->dtad_next = last->dtad_next;

		/*
		 * We have now removed our action list from its ECB; we can
		 * safely destroy the list.
		 */
		last->dtad_next = NULL;

		for (ap = sdp->dtsd_action; ap != NULL; ap = next) {
			assert(ap->dtad_uarg == (uintptr_t)sdp);
			dt_difo_free(dtp, ap->dtad_difo);
			next = ap->dtad_next;
			dt_free(dtp, ap);
		}
	}

	if (sdp->dtsd_fmtdata != NULL)
		dt_printf_destroy(sdp->dtsd_fmtdata);

	dt_ecbdesc_release(dtp, sdp->dtsd_ecbdesc);
	dt_free(dtp, sdp);
}
