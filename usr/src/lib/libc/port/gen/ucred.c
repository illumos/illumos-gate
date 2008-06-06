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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _ucred_free = ucred_free
#pragma weak _ucred_get = ucred_get
#pragma weak _ucred_getegid = ucred_getegid
#pragma weak _ucred_geteuid = ucred_geteuid
#pragma weak _ucred_getgroups = ucred_getgroups
#pragma weak _ucred_getpflags = ucred_getpflags
#pragma weak _ucred_getpid = ucred_getpid
#pragma weak _ucred_getzoneid = ucred_getzoneid
#pragma weak _ucred_getprojid = ucred_getprojid
#pragma weak _ucred_getprivset = ucred_getprivset
#pragma weak _ucred_getrgid = ucred_getrgid
#pragma weak _ucred_getruid = ucred_getruid
#pragma weak _ucred_getsgid = ucred_getsgid
#pragma weak _ucred_getsuid = ucred_getsuid
#pragma weak _ucred_getauid = ucred_getauid
#pragma weak _ucred_getasid = ucred_getasid
#pragma weak _ucred_getatid = ucred_getatid
#pragma weak _ucred_getlabel = ucred_getlabel
#pragma weak _ucred_getamask = ucred_getamask
#pragma weak _ucred_size = ucred_size

#include "lint.h"

#define	_STRUCTURED_PROC	1

#include "priv_private.h"
#include <errno.h>
#include <priv.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ucred.h>
#include <limits.h>
#include <fcntl.h>
#include <door.h>
#include <alloca.h>
#include <sys/ucred.h>
#include <sys/procfs.h>
#include <sys/sysmacros.h>
#include <sys/zone.h>
#include <tsol/label.h>

ucred_t *
_ucred_alloc(void)
{
	ucred_t *r;
	size_t sz = ucred_size();

	r = malloc(sz);

	if (r != NULL)
		r->uc_size = (uint32_t)sz;

	return (r);
}

void
ucred_free(ucred_t *uc)
{
	free(uc);
}


ucred_t *
ucred_get(pid_t pid)
{
	ucred_t *uc;

	uc = _ucred_alloc();

	if (uc == NULL)
		return (NULL);

	if (syscall(SYS_ucredsys, UCREDSYS_UCREDGET, pid, uc) != 0) {
		ucred_free(uc);
		return (NULL);
	}

	return (uc);
}

uid_t
ucred_geteuid(const ucred_t *uc)
{
	/* LINTED: alignment */
	const prcred_t *cr = UCCRED(uc);

	if (cr == NULL) {
		errno = EINVAL;
		return ((uid_t)-1);
	}

	return (cr->pr_euid);
}

uid_t
ucred_getruid(const ucred_t *uc)
{
	/* LINTED: alignment */
	const prcred_t *cr = UCCRED(uc);

	if (cr == NULL) {
		errno = EINVAL;
		return ((uid_t)-1);
	}

	return (cr->pr_ruid);
}

uid_t
ucred_getsuid(const ucred_t *uc)
{
	/* LINTED: alignment */
	const prcred_t *cr = UCCRED(uc);

	if (cr == NULL) {
		errno = EINVAL;
		return ((uid_t)-1);
	}

	return (cr->pr_suid);
}

gid_t
ucred_getegid(const ucred_t *uc)
{
	/* LINTED: alignment */
	const prcred_t *cr = UCCRED(uc);

	if (cr == NULL) {
		errno = EINVAL;
		return ((gid_t)-1);
	}

	return (cr->pr_egid);
}

gid_t
ucred_getrgid(const ucred_t *uc)
{
	/* LINTED: alignment */
	const prcred_t *cr = UCCRED(uc);

	if (cr == NULL) {
		errno = EINVAL;
		return ((gid_t)-1);
	}

	return (cr->pr_rgid);
}

gid_t
ucred_getsgid(const ucred_t *uc)
{
	/* LINTED: alignment */
	const prcred_t *cr = UCCRED(uc);

	if (cr == NULL) {
		errno = EINVAL;
		return ((gid_t)-1);
	}

	return (cr->pr_sgid);
}

int
ucred_getgroups(const ucred_t *uc, const gid_t **grps)
{
	/* LINTED: alignment */
	const prcred_t *cr = UCCRED(uc);

	if (cr == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (cr->pr_ngroups > 0)
		*grps = &cr->pr_groups[0];
	else
		*grps = NULL;

	return (cr->pr_ngroups);
}

const priv_set_t *
ucred_getprivset(const ucred_t *uc, priv_ptype_t set)
{
	/* LINTED: alignment */
	const prpriv_t *pr = UCPRIV(uc);
	int pset = priv_getsetbyname(set);
	priv_data_t *d;

	if (pr == NULL || pset == -1) {
		errno = EINVAL;
		return (NULL);
	}

	LOADPRIVDATA(d);

	return ((const priv_set_t *)
	    &pr->pr_sets[d->pd_pinfo->priv_setsize * pset]);
}

pid_t
ucred_getpid(const ucred_t *uc)
{

	if (uc->uc_pid == -1)
		errno = EINVAL;

	return (uc->uc_pid);
}

projid_t
ucred_getprojid(const ucred_t *uc)
{

	if (uc->uc_projid == -1)
		errno = EINVAL;

	return (uc->uc_projid);
}

zoneid_t
ucred_getzoneid(const ucred_t *uc)
{

	if (uc->uc_zoneid < MIN_ZONEID || uc->uc_zoneid > MAX_ZONEID) {
		errno = EINVAL;
		return (-1);
	}

	return (uc->uc_zoneid);
}

bslabel_t *
ucred_getlabel(const ucred_t *uc)
{
	/* LINTED: alignment */
	bslabel_t *slabel = UCLABEL(uc);

	if (!is_system_labeled() || slabel == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	return (slabel);
}

/*
 * For now, assume single bit flags.
 */
uint_t
ucred_getpflags(const ucred_t *uc, uint_t flag)
{
	/* LINTED: alignment */
	prpriv_t *pr = UCPRIV(uc);
	char *x, *end;

	if (pr == NULL) {
		errno = EINVAL;
		return ((uint_t)-1);
	}

	end = (char *)pr + PRIV_PRPRIV_SIZE(pr);
	x = end - pr->pr_infosize;

	while (x < end) {
		/* LINTED: alignment */
		priv_info_t *pi = (priv_info_t *)x;
		priv_info_uint_t *pii;

		switch (pi->priv_info_type) {
		case PRIV_INFO_FLAGS:
			/* LINTED: alignment */
			pii = (priv_info_uint_t *)x;
			return ((pii->val & flag) ? 1 : 0);
		}
		/* Forward progress */
		if (pi->priv_info_size < sizeof (priv_info_t))
			break;
		x += pi->priv_info_size;
	}

	errno = EINVAL;
	return ((uint_t)-1);
}

au_id_t
ucred_getauid(const ucred_t *uc)
{
	/* LINTED: alignment */
	const auditinfo64_addr_t *ainfo = UCAUD(uc);

	if (ainfo == NULL)
		return (AU_NOAUDITID);

	return (ainfo->ai_auid);
}

au_asid_t
ucred_getasid(const ucred_t *uc)
{
	/* LINTED: alignment */
	const auditinfo64_addr_t *ainfo = UCAUD(uc);

	if (ainfo == NULL)
		return (-1);

	return (ainfo->ai_asid);
}

const au_tid64_addr_t *
ucred_getatid(const ucred_t *uc)
{
	/* LINTED: alignment */
	const auditinfo64_addr_t *ainfo = UCAUD(uc);

	if (ainfo == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	return (&ainfo->ai_termid);
}

const au_mask_t *
ucred_getamask(const ucred_t *uc)
{
	/* LINTED: alignment */
	const auditinfo64_addr_t *ainfo = UCAUD(uc);

	if (ainfo == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	return (&ainfo->ai_mask);
}

size_t
ucred_size(void)
{
	priv_data_t *d;

	LOADPRIVDATA(d);

	return (d->pd_ucredsize);
}
