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

/*
 * SID system call.
 */

#include <sys/sid.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/policy.h>
#include <sys/door.h>
#include <sys/kidmap.h>
#include <sys/proc.h>

static uint64_t
allocids(int flag, int nuids, int ngids)
{
	rval_t r;
	uid_t su = 0;
	gid_t sg = 0;
	struct door_info di;
	door_handle_t dh;
	int err;
	zone_t *zone = crgetzone(CRED());

	dh = idmap_get_door(zone);

	if (dh == NULL)
		return (set_errno(EPERM));

	if ((err = door_ki_info(dh, &di)) != 0) {
		door_ki_rele(dh);
		return (set_errno(err));
	}

	door_ki_rele(dh);

	if (curproc->p_pid != di.di_target)
		return (set_errno(EPERM));

	if (flag)
		idmap_purge_cache(zone);

	if (nuids < 0 || ngids < 0)
		return (set_errno(EINVAL));

	if (flag != 0 || nuids > 0)
		err = eph_uid_alloc(zone, flag, &su, nuids);
	if (err == 0 && (flag != 0 || ngids > 0))
		err = eph_gid_alloc(zone, flag, &sg, ngids);

	if (err != 0)
		return (set_errno(EOVERFLOW));

	r.r_val1 = su;
	r.r_val2 = sg;
	return (r.r_vals);
}

static int
idmap_reg(int did)
{
	door_handle_t dh;
	int err;
	cred_t *cr = CRED();

	if ((err = secpolicy_idmap(cr)) != 0)
		return (set_errno(err));

	dh = door_ki_lookup(did);

	if (dh == NULL)
		return (set_errno(EBADF));

	if ((err = idmap_reg_dh(crgetzone(cr), dh)) != 0)
		return (set_errno(err));

	return (0);
}

static int
idmap_unreg(int did)
{
	door_handle_t dh = door_ki_lookup(did);
	int res;
	zone_t *zone;

	if (dh == NULL)
		return (set_errno(EINVAL));

	zone = crgetzone(CRED());
	res = idmap_unreg_dh(zone, dh);
	door_ki_rele(dh);

	if (res != 0)
		return (set_errno(res));
	return (0);
}

static uint64_t
idmap_flush_kcache(void)
{
	struct door_info di;
	door_handle_t dh;
	int err;
	zone_t *zone = crgetzone(CRED());

	dh = idmap_get_door(zone);

	if (dh == NULL)
		return (set_errno(EPERM));

	if ((err = door_ki_info(dh, &di)) != 0) {
		door_ki_rele(dh);
		return (set_errno(err));
	}

	door_ki_rele(dh);

	if (curproc->p_pid != di.di_target)
		return (set_errno(EPERM));

	idmap_purge_cache(zone);

	return (0);
}

uint64_t
sidsys(int op, int flag, int nuids, int ngids)
{
	switch (op) {
	case SIDSYS_ALLOC_IDS:
		return (allocids(flag, nuids, ngids));
	case SIDSYS_IDMAP_REG:
		return (idmap_reg(flag));
	case SIDSYS_IDMAP_UNREG:
		return (idmap_unreg(flag));
	case SIDSYS_IDMAP_FLUSH_KCACHE:
		return (idmap_flush_kcache());
	default:
		return (set_errno(EINVAL));
	}
}
