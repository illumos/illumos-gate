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
/* Copyright (c) 1990 Mentat Inc. */

#include <sys/types.h>
#include <sys/systm.h>
#include <inet/common.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <inet/mi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/policy.h>
#include <inet/nd.h>

/* Free the table pointed to by 'ndp' */
void
nd_free(caddr_t	*nd_pparam)
{
	ND	*nd;

	if ((nd = (ND *)(*nd_pparam)) != NULL) {
		if (nd->nd_tbl)
			mi_free((char *)nd->nd_tbl);
		mi_free((char *)nd);
		*nd_pparam = NULL;
	}
}

int
nd_getset(queue_t *q, caddr_t nd_param, MBLKP mp)
{
	int	err;
	IOCP	iocp;
	MBLKP	mp1;
	ND	*nd;
	NDE	*nde;
	char	*valp;
	long	avail;

	if (!nd_param)
		return (B_FALSE);
	nd = (ND *)nd_param;
	iocp = (IOCP)mp->b_rptr;
	if (iocp->ioc_count == 0 || !(mp1 = mp->b_cont)) {
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_count = 0;
		iocp->ioc_error = EINVAL;
		return (B_TRUE);
	}
	/*
	 * NOTE - logic throughout nd_xxx assumes single data block for ioctl.
	 *	However, existing code sends in some big buffers.
	 */
	avail = iocp->ioc_count;
	if (mp1->b_cont) {
		freemsg(mp1->b_cont);
		mp1->b_cont = NULL;
	}

	mp1->b_datap->db_lim[-1] = '\0';	/* Force null termination */
	valp = (char *)mp1->b_rptr;
	for (nde = nd->nd_tbl; ; nde++) {
		if (!nde->nde_name)
			return (B_FALSE);
		if (mi_strcmp(nde->nde_name, valp) == 0)
			break;
	}
	err = EINVAL;
	while (*valp++)
		noop;
	if (!*valp || valp >= (char *)mp1->b_wptr)
		valp = NULL;
	switch (iocp->ioc_cmd) {
	case ND_GET:
		/* We overwrite the name/value with the reply data */
		mp1->b_wptr = mp1->b_rptr;
		err = (*nde->nde_get_pfi)(q, mp1, nde->nde_data, iocp->ioc_cr);
		if (!err) {
			int	size_out;
			int	excess;

			iocp->ioc_rval = 0;

			/* Tack on the null */
			(void) mi_mpprintf_putc((char *)mp1, '\0');
			size_out = msgdsize(mp1);
			excess = size_out - avail;
			if (excess > 0) {
				iocp->ioc_rval = size_out;
				size_out -= excess;
				(void) adjmsg(mp1, -(excess + 1));
				(void) mi_mpprintf_putc((char *)mp1, '\0');
			}
			iocp->ioc_count = size_out;
		}
		break;

	case ND_SET:
		if (valp) {
			if ((iocp->ioc_cr != NULL) &&
			    ((err = secpolicy_ip_config(iocp->ioc_cr, B_FALSE))
			    == 0)) {
				err = (*nde->nde_set_pfi)(q, mp1, valp,
				    nde->nde_data, iocp->ioc_cr);
			}
			iocp->ioc_count = 0;
			freemsg(mp1);
			mp->b_cont = NULL;
		}
		break;

	default:
		break;
	}
	iocp->ioc_error = err;
	mp->b_datap->db_type = M_IOCACK;
	return (B_TRUE);
}

/* ARGSUSED */
int
nd_get_default(queue_t *q, MBLKP mp, caddr_t data, cred_t *ioc_cr)
{
	return (EACCES);
}

/*
 * This routine may be used as the get dispatch routine in nd tables
 * for long variables.  To use this routine instead of a module
 * specific routine, call nd_load as
 *	nd_load(&nd_ptr, "name", nd_get_long, set_pfi, &long_variable)
 * The name of the variable followed by a space and the value of the
 * variable will be printed in response to a get_status call.
 */
/* ARGSUSED */
int
nd_get_long(queue_t *q, MBLKP mp, caddr_t data, cred_t *ioc_cr)
{
	ulong_t	*lp;

	lp = (ulong_t *)data;
	(void) mi_mpprintf(mp, "%ld", *lp);
	return (0);
}

/* ARGSUSED */
int
nd_get_names(queue_t *q, MBLKP mp, caddr_t nd_param, cred_t *ioc_cr)
{
	ND	*nd;
	NDE	*nde;
	char	*rwtag;
	boolean_t	get_ok, set_ok;

	nd = (ND *)nd_param;
	if (!nd)
		return (ENOENT);
	for (nde = nd->nd_tbl; nde->nde_name; nde++) {
		get_ok = nde->nde_get_pfi != nd_get_default;
		set_ok = nde->nde_set_pfi != nd_set_default;
		if (get_ok) {
			if (set_ok)
				rwtag = "read and write";
			else
				rwtag = "read only";
		} else if (set_ok)
			rwtag = "write only";
		else
			rwtag = "no read or write";
		(void) mi_mpprintf(mp, "%s (%s)", nde->nde_name, rwtag);
	}
	return (0);
}

/*
 * Load 'name' into the named dispatch table pointed to by 'ndp'.
 * 'ndp' should be the address of a char pointer cell.  If the table
 * does not exist (*ndp == 0), a new table is allocated and 'ndp'
 * is stuffed.  If there is not enough space in the table for a new
 * entry, more space is allocated.
 * Never fails due to memory allocation failures.
 */
boolean_t
nd_load(caddr_t *nd_pparam, char *name, ndgetf_t get_pfi, ndsetf_t set_pfi,
    caddr_t data)
{
	ND	*nd;
	NDE	*nde;

	if (!nd_pparam)
		return (B_FALSE);
	if ((nd = (ND *)(*nd_pparam)) == NULL) {
		nd = (ND *)mi_alloc_sleep(sizeof (ND), BPRI_MED);
		bzero((caddr_t)nd, sizeof (ND));
		*nd_pparam = (caddr_t)nd;
	}
	if (nd->nd_tbl) {
		for (nde = nd->nd_tbl; nde->nde_name; nde++) {
			if (mi_strcmp(name, nde->nde_name) == 0)
				goto fill_it;
		}
	}
	if (nd->nd_free_count <= 1) {
		nde = (NDE *)mi_alloc_sleep(nd->nd_size +
		    NDE_ALLOC_SIZE, BPRI_MED);
		bzero((char *)nde, nd->nd_size + NDE_ALLOC_SIZE);
		nd->nd_free_count += NDE_ALLOC_COUNT;
		if (nd->nd_tbl) {
			bcopy((char *)nd->nd_tbl, (char *)nde, nd->nd_size);
			mi_free((char *)nd->nd_tbl);
		} else {
			nd->nd_free_count--;
			nde->nde_name = "?";
			nde->nde_get_pfi = nd_get_names;
			nde->nde_set_pfi = nd_set_default;
		}
		nde->nde_data = (caddr_t)nd;
		nd->nd_tbl = nde;
		nd->nd_size += NDE_ALLOC_SIZE;
	}
	for (nde = nd->nd_tbl; nde->nde_name; nde++)
		noop;
	nd->nd_free_count--;
fill_it:
	nde->nde_name = name;
	nde->nde_get_pfi = get_pfi ? get_pfi : nd_get_default;
	nde->nde_set_pfi = set_pfi ? set_pfi : nd_set_default;
	nde->nde_data = data;
	return (B_TRUE);
}

/*
 * Unload 'name' from the named dispatch table.  If the table does not
 * exist, I return.  I do not free up space, but I do raise the
 * free count so future nd_load()s don't take as much memory.
 */

void
nd_unload(caddr_t *nd_pparam, char *name)
{
	ND *nd;
	NDE *nde;
	boolean_t foundit = B_FALSE;

	/* My apologies for the in-boolean assignment. */
	if (nd_pparam == NULL || (nd = (ND *)(*nd_pparam)) == NULL ||
	    nd->nd_tbl == NULL)
		return;

	for (nde = nd->nd_tbl; nde->nde_name != NULL; nde++) {
		if (foundit)
			*(nde - 1) = *nde;
		if (mi_strcmp(name, nde->nde_name) == 0)
			foundit = B_TRUE;
	}
	if (foundit)
		bzero(nde - 1, sizeof (NDE));
}

/* ARGSUSED */
int
nd_set_default(queue_t *q, MBLKP mp, char *value, caddr_t data, cred_t *ioc_cr)
{
	return (EACCES);
}

/* ARGSUSED */
int
nd_set_long(queue_t *q, MBLKP mp, char *value, caddr_t data, cred_t *ioc_cr)
{
	ulong_t	*lp;
	long	new_value;

	if (ddi_strtol(value, NULL, 10, &new_value) != 0)
		return (EINVAL);
	lp = (ulong_t *)data;
	*lp = new_value;
	return (0);
}
