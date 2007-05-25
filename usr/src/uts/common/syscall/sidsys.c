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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SID system call.
 */

#include <sys/sid.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/policy.h>
#include <sys/door.h>

static kmutex_t idmap_mutex;

typedef struct idmap_reg {
	door_handle_t 	idmap_door;
	int		idmap_flags;
	int		idmap_ref;
} idmap_reg_t;

static idmap_reg_t *idmap_ptr;

static int idmap_unreg_dh(door_handle_t);

static void
idmap_freeone(idmap_reg_t *p)
{
	ASSERT(p->idmap_ref == 0);
	ASSERT(MUTEX_HELD(&idmap_mutex));

	door_ki_rele(p->idmap_door);
	if (idmap_ptr == p)
		idmap_ptr = NULL;

	kmem_free(p, sizeof (*p));
}

static int
idmap_do_call(sidmap_call_t *callp, size_t callsz, void **resp, size_t *respsz)
{
	door_arg_t da;
	idmap_reg_t *p;
	int ret;
	int dres;

	mutex_enter(&idmap_mutex);
	p = idmap_ptr;
	if (p != NULL) {
		p->idmap_ref++;
	} else {
		mutex_exit(&idmap_mutex);
		return (-1);
	}
	mutex_exit(&idmap_mutex);

	da.data_ptr = (char *)callp;
	da.data_size = callsz;
	da.desc_ptr = NULL;
	da.desc_num = 0;
	da.rbuf = *resp;
	da.rsize = *respsz;

	while ((dres = door_ki_upcall(p->idmap_door, &da)) != 0) {
		switch (dres) {
		case EINTR:
		case EAGAIN:
			delay(1);
			continue;
		case EINVAL:
		case EBADF:
			(void) idmap_unreg_dh(p->idmap_door);
			/* FALLTHROUGH */
		default:
			ret = -1;
			goto out;
		}
	}
	*resp = da.rbuf;
	*respsz = da.rsize;
	ret = 0;
out:
	mutex_enter(&idmap_mutex);
	if (--p->idmap_ref == 0)
		idmap_freeone(p);
	mutex_exit(&idmap_mutex);
	return (ret);
}

/*
 * Current code only attempts to map ids to sids.
 */
int
idmap_call_byid(uid_t id, ksid_t *ksid)
{
	sidmap_call_t call;
	domsid_t res, *resp = &res;
	size_t respsz = sizeof (res);

	call.sc_type = SIDSYS_ID2SID;
	call.sc_val.sc_id = id;

	if (idmap_do_call(&call, sizeof (call), (void **)&resp, &respsz) != 0)
		return (-1);

	ksid->ks_domain = ksid_lookupdomain(resp->ds_dom);
	ksid->ks_rid = resp->ds_rid;

	/* Larger SID return value; this usually happens */
	if (resp != &res)
		kmem_free(resp, respsz);

	return (0);
}

uid_t
idmap_call_bysid(ksid_t *ksid)
{
	ksiddomain_t *domp = ksid->ks_domain;
	sidmap_call_t *callp;
	uid_t res = (uid_t)-1;
	uid_t *resp = &res;
	size_t callsz;
	size_t respsz = sizeof (res);

	callsz = sizeof (sidmap_call_t) + domp->kd_len;

	callp = kmem_alloc(callsz, KM_SLEEP);
	callp->sc_type = SIDSYS_SID2ID;
	bcopy(domp->kd_name, callp->sc_val.sc_sid.ds_dom, domp->kd_len);
	callp->sc_val.sc_sid.ds_rid = ksid->ks_rid;

	if (idmap_do_call(callp, callsz, (void **)&resp, &respsz) != 0)
		goto out;

	/* Should never happen; the original buffer should be large enough */
	if (resp != &res) {
		kmem_free(resp, respsz);
		goto out;
	}

	if (respsz != sizeof (uid_t))
		res = (uid_t)-1;

out:
	kmem_free(callp, callsz);
	return (res);
}

static int
idmap_reg(int did)
{
	door_handle_t dh;
	idmap_reg_t *idmp;
	int err;

	if ((err = secpolicy_idmap(CRED())) != 0)
		return (set_errno(err));

	dh = door_ki_lookup(did);

	if (dh == NULL)
		return (set_errno(EBADF));

	idmp = kmem_alloc(sizeof (*idmp), KM_SLEEP);

	idmp->idmap_door = dh;
	mutex_enter(&idmap_mutex);
	if (idmap_ptr != NULL) {
		if (--idmap_ptr->idmap_ref == 0)
			idmap_freeone(idmap_ptr);
	}
	idmp->idmap_flags = 0;
	idmp->idmap_ref = 1;
	idmap_ptr = idmp;
	mutex_exit(&idmap_mutex);
	return (0);
}

static int
idmap_unreg_dh(door_handle_t dh)
{
	mutex_enter(&idmap_mutex);
	if (idmap_ptr == NULL || idmap_ptr->idmap_door != dh) {
		mutex_exit(&idmap_mutex);
		return (EINVAL);
	}

	if (idmap_ptr->idmap_flags != 0) {
		mutex_exit(&idmap_mutex);
		return (EAGAIN);
	}
	idmap_ptr->idmap_flags = 1;
	if (--idmap_ptr->idmap_ref == 0)
		idmap_freeone(idmap_ptr);
	mutex_exit(&idmap_mutex);
	return (0);
}

static int
idmap_unreg(int did)
{
	door_handle_t dh = door_ki_lookup(did);
	int res;

	if (dh == NULL)
		return (set_errno(EINVAL));

	res = idmap_unreg_dh(dh);
	door_ki_rele(dh);

	if (res != 0)
		return (set_errno(res));
	return (0);
}

static boolean_t
its_my_door(void)
{
	mutex_enter(&idmap_mutex);
	if (idmap_ptr != NULL) {
		struct door_info info;
		int err = door_ki_info(idmap_ptr->idmap_door, &info);
		if (err == 0 && info.di_target == curproc->p_pid) {
			mutex_exit(&idmap_mutex);
			return (B_TRUE);
		}
	}
	mutex_exit(&idmap_mutex);
	return (B_FALSE);
}

static uint64_t
allocids(int flag, int nuids, int ngids)
{
	rval_t r;
	uid_t su = 0;
	gid_t sg = 0;
	int err;

	if (!its_my_door())
		return (set_errno(EPERM));

	if (nuids < 0 || ngids < 0)
		return (set_errno(EINVAL));

	if (flag != 0 || nuids > 0)
		err = eph_uid_alloc(flag, &su, nuids);
	if (err == 0 && (flag != 0 || ngids > 0))
		err = eph_gid_alloc(flag, &sg, ngids);

	if (err != 0)
		return (set_errno(EOVERFLOW));

	r.r_val1 = su;
	r.r_val2 = sg;
	return (r.r_vals);
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
	default:
		return (set_errno(EINVAL));
	}
}
