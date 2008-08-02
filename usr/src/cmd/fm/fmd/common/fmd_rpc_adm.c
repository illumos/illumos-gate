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

#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>

#include <fmd_rpc_adm.h>
#include <fmd_rpc.h>
#include <fmd_module.h>
#include <fmd_ustat.h>
#include <fmd_error.h>
#include <fmd_asru.h>
#include <fmd_ckpt.h>
#include <fmd_case.h>
#include <fmd_fmri.h>
#include <fmd_idspace.h>
#include <fmd_xprt.h>

#include <fmd.h>

bool_t
fmd_adm_modinfo_1_svc(struct fmd_rpc_modlist *rvp, struct svc_req *req)
{
	struct fmd_rpc_modinfo *rmi;
	fmd_module_t *mp;

	rvp->rml_list = NULL;
	rvp->rml_err = 0;
	rvp->rml_len = 0;

	if (fmd_rpc_deny(req)) {
		rvp->rml_err = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	(void) pthread_mutex_lock(&fmd.d_mod_lock);

	for (mp = fmd_list_next(&fmd.d_mod_list);
	    mp != NULL; mp = fmd_list_next(mp)) {

		if ((rmi = malloc(sizeof (struct fmd_rpc_modinfo))) == NULL) {
			rvp->rml_err = FMD_ADM_ERR_NOMEM;
			break;
		}

		fmd_module_lock(mp);

		/*
		 * If mod_info is NULL, the module is in the middle of loading:
		 * do not report its presence to observability tools yet.
		 */
		if (mp->mod_info == NULL) {
			fmd_module_unlock(mp);
			free(rmi);
			continue;
		}

		rmi->rmi_name = strdup(mp->mod_name);
		rmi->rmi_desc = strdup(mp->mod_info->fmdi_desc);
		rmi->rmi_vers = strdup(mp->mod_info->fmdi_vers);
		rmi->rmi_faulty = mp->mod_error != 0;
		rmi->rmi_next = rvp->rml_list;

		fmd_module_unlock(mp);
		rvp->rml_list = rmi;
		rvp->rml_len++;

		if (rmi->rmi_desc == NULL || rmi->rmi_vers == NULL) {
			rvp->rml_err = FMD_ADM_ERR_NOMEM;
			break;
		}
	}

	(void) pthread_mutex_unlock(&fmd.d_mod_lock);
	return (TRUE);
}

bool_t
fmd_adm_modcstat_1_svc(char *name,
    struct fmd_rpc_modstat *rms, struct svc_req *req)
{
	fmd_ustat_snap_t snap;
	fmd_module_t *mp;

	rms->rms_buf.rms_buf_val = NULL;
	rms->rms_buf.rms_buf_len = 0;
	rms->rms_err = 0;

	if (fmd_rpc_deny(req)) {
		rms->rms_err = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, name)) == NULL) {
		rms->rms_err = FMD_ADM_ERR_MODSRCH;
		return (TRUE);
	}

	if (fmd_modstat_snapshot(mp, &snap) == 0) {
		rms->rms_buf.rms_buf_val = snap.uss_buf;
		rms->rms_buf.rms_buf_len = snap.uss_len;
	} else if (errno == EFMD_HDL_ABORT) {
		rms->rms_err = FMD_ADM_ERR_MODFAIL;
	} else
		rms->rms_err = FMD_ADM_ERR_NOMEM;

	fmd_module_rele(mp);
	return (TRUE);
}

bool_t
fmd_adm_moddstat_1_svc(char *name,
    struct fmd_rpc_modstat *rms, struct svc_req *req)
{
	fmd_module_t *mp;

	rms->rms_buf.rms_buf_val = NULL;
	rms->rms_buf.rms_buf_len = 0;
	rms->rms_err = 0;

	if (fmd_rpc_deny(req)) {
		rms->rms_err = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, name)) == NULL) {
		rms->rms_err = FMD_ADM_ERR_MODSRCH;
		return (TRUE);
	}

	rms->rms_buf.rms_buf_val = malloc(sizeof (fmd_modstat_t));
	rms->rms_buf.rms_buf_len = sizeof (fmd_modstat_t) / sizeof (fmd_stat_t);

	if (rms->rms_buf.rms_buf_val == NULL) {
		rms->rms_err = FMD_ADM_ERR_NOMEM;
		rms->rms_buf.rms_buf_len = 0;
		fmd_module_rele(mp);
		return (TRUE);
	}

	/*
	 * Note: the bcopy() here is valid only if no FMD_TYPE_STRING stats
	 * are present in mp->mod_stats.  We don't use any for the daemon-
	 * maintained stats and provide this function in order to reduce the
	 * overhead of the fmstat(1M) default view, where these minimal stats
	 * must be retrieved for all of the active modules.
	 */
	(void) pthread_mutex_lock(&mp->mod_stats_lock);

	if (mp->mod_stats != NULL) {
		mp->mod_stats->ms_snaptime.fmds_value.ui64 = gethrtime();
		bcopy(mp->mod_stats, rms->rms_buf.rms_buf_val,
		    sizeof (fmd_modstat_t));
	} else {
		free(rms->rms_buf.rms_buf_val);
		rms->rms_buf.rms_buf_val = NULL;
		rms->rms_buf.rms_buf_len = 0;
		rms->rms_err = FMD_ADM_ERR_MODFAIL;
	}

	(void) pthread_mutex_unlock(&mp->mod_stats_lock);
	fmd_module_rele(mp);
	return (TRUE);
}

bool_t
fmd_adm_modgstat_1_svc(struct fmd_rpc_modstat *rms, struct svc_req *req)
{
	const size_t size = sizeof (fmd_statistics_t);

	if (fmd_rpc_deny(req)) {
		rms->rms_buf.rms_buf_val = NULL;
		rms->rms_buf.rms_buf_len = 0;
		rms->rms_err = FMD_ADM_ERR_PERM;
	} else if ((rms->rms_buf.rms_buf_val = malloc(size)) != NULL) {
		/*
		 * Note: the bcopy() here is valid only if no FMD_TYPE_STRING
		 * stats are present in fmd.d_stats (see definition in fmd.c).
		 */
		(void) pthread_mutex_lock(&fmd.d_stats_lock);
		bcopy(fmd.d_stats, rms->rms_buf.rms_buf_val, size);
		(void) pthread_mutex_unlock(&fmd.d_stats_lock);
		rms->rms_buf.rms_buf_len = size / sizeof (fmd_stat_t);
		rms->rms_err = 0;
	} else {
		rms->rms_buf.rms_buf_len = 0;
		rms->rms_err = FMD_ADM_ERR_NOMEM;
	}

	return (TRUE);
}

bool_t
fmd_adm_modload_1_svc(char *path, int *rvp, struct svc_req *req)
{
	fmd_module_t *mp;
	const char *p;
	int err = 0;

	if (fmd_rpc_deny(req)) {
		*rvp = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	/*
	 * Before we endure the expense of constructing a module and attempting
	 * to load it, do a quick check to see if the pathname is valid.
	 */
	if (access(path, F_OK) != 0) {
		*rvp = FMD_ADM_ERR_MODNOENT;
		return (TRUE);
	}

	if ((p = strrchr(path, '.')) != NULL && strcmp(p, ".so") == 0)
		mp = fmd_modhash_load(fmd.d_mod_hash, path, &fmd_rtld_ops);
	else
		mp = fmd_modhash_load(fmd.d_mod_hash, path, &fmd_proc_ops);

	if (mp == NULL) {
		switch (errno) {
		case EFMD_MOD_LOADED:
			err = FMD_ADM_ERR_MODEXIST;
			break;
		case EFMD_MOD_INIT:
			err = FMD_ADM_ERR_MODINIT;
			break;
		default:
			err = FMD_ADM_ERR_MODLOAD;
			break;
		}
	}

	*rvp = err;
	return (TRUE);
}

bool_t
fmd_adm_modunload_1_svc(char *name, int *rvp, struct svc_req *req)
{
	fmd_module_t *mp = NULL;
	int err = 0;

	if (fmd_rpc_deny(req))
		err = FMD_ADM_ERR_PERM;
	else if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, name)) == NULL)
		err = FMD_ADM_ERR_MODSRCH;
	else if (mp == fmd.d_self)
		err = FMD_ADM_ERR_MODBUSY;
	else if (fmd_modhash_unload(fmd.d_mod_hash, name) != 0)
		err = FMD_ADM_ERR_MODSRCH;

	if (mp != NULL)
		fmd_module_rele(mp);

	*rvp = err;
	return (TRUE);
}

bool_t
fmd_adm_modreset_1_svc(char *name, int *rvp, struct svc_req *req)
{
	fmd_module_t *mp = NULL;
	int err = 0;

	if (fmd_rpc_deny(req))
		err = FMD_ADM_ERR_PERM;
	else if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, name)) == NULL)
		err = FMD_ADM_ERR_MODSRCH;
	else if (mp == fmd.d_self)
		err = FMD_ADM_ERR_MODBUSY;
	else if (fmd_modhash_unload(fmd.d_mod_hash, name) != 0)
		err = FMD_ADM_ERR_MODSRCH;

	if (err == 0)
		fmd_ckpt_delete(mp); /* erase any saved checkpoints */

	if (err == 0 && fmd_modhash_load(fmd.d_mod_hash,
	    mp->mod_path, mp->mod_ops) == NULL) {
		if (errno == EFMD_MOD_INIT)
			err = FMD_ADM_ERR_MODINIT;
		else
			err = FMD_ADM_ERR_MODLOAD;
	}

	if (mp != NULL)
		fmd_module_rele(mp);

	*rvp = err;
	return (TRUE);
}

bool_t
fmd_adm_modgc_1_svc(char *name, int *rvp, struct svc_req *req)
{
	fmd_module_t *mp;
	int err = 0;

	if (fmd_rpc_deny(req))
		err = FMD_ADM_ERR_PERM;
	else if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, name)) == NULL)
		err = FMD_ADM_ERR_MODSRCH;
	else {
		fmd_module_gc(mp);
		fmd_module_rele(mp);
	}

	*rvp = err;
	return (TRUE);
}

/*
 * Unlike our other RPC callbacks, fmd_adm_rsrclist_1 can return large amounts
 * of data that may exceed the underlying RPC transport buffer size if the
 * resource cache is heavily populated and/or all resources are requested.
 * To minimize the likelihood of running out of RPC buffer space and having to
 * fail the client request, fmd_adm_rsrclist_1 returns a snapshot of the
 * relevant FMRI strings only: the client can use fmd_adm_rsrcinfo_1 on an
 * individual FMRI if more information is needed.  To further reduce the XDR
 * overhead, the string list is represented as XDR-opaque data where the
 * entire list is returned as a string table (e.g. "fmriA\0fmriB\0...").
 */
static void
fmd_adm_rsrclist_asru(fmd_asru_t *ap, void *arg)
{
	struct fmd_rpc_rsrclist *rrl = arg;
	size_t name_len, buf_len;
	void *p;

	/*
	 * Skip the ASRU if this fault is marked as invisible.
	 * If rrl_all is false, we take a quick look at asru_flags with no lock
	 * held to see if the ASRU is not faulty.  If so,
	 * we don't want to report it by default and can just skip this ASRU.
	 * This helps keep overhead low in the common case, as the call to
	 * fmd_asru_getstate() can be expensive depending on the scheme.
	 */

	if (ap->asru_flags & FMD_ASRU_INVISIBLE)
		return;
	if (rrl->rrl_all == B_FALSE && !(ap->asru_flags & FMD_ASRU_FAULTY))
		return;

	if (rrl->rrl_err != 0 || fmd_asru_getstate(ap) == 0)
		return; /* error has occurred or resource is in 'ok' state */

	/*
	 * Lock the ASRU and reallocate rrl_buf[] to be large enough to hold
	 * another string, doubling it as needed.  Then copy the new string
	 * on to the end, and increment rrl_len to indicate the used space.
	 */
	(void) pthread_mutex_lock(&ap->asru_lock);
	name_len = strlen(ap->asru_name) + 1;

	while (rrl->rrl_len + name_len > rrl->rrl_buf.rrl_buf_len) {
		if (rrl->rrl_buf.rrl_buf_len != 0)
			buf_len = rrl->rrl_buf.rrl_buf_len * 2;
		else
			buf_len = 1024; /* default buffer size */

		if ((p = realloc(rrl->rrl_buf.rrl_buf_val, buf_len)) != NULL) {
			bzero((char *)p + rrl->rrl_buf.rrl_buf_len,
			    buf_len - rrl->rrl_buf.rrl_buf_len);
			rrl->rrl_buf.rrl_buf_val = p;
			rrl->rrl_buf.rrl_buf_len = buf_len;
		} else {
			rrl->rrl_err = FMD_ADM_ERR_NOMEM;
			break;
		}
	}

	if (rrl->rrl_err == 0) {
		bcopy(ap->asru_name, (char *)rrl->rrl_buf.rrl_buf_val +
		    rrl->rrl_len, name_len);
		rrl->rrl_len += name_len;
		rrl->rrl_cnt++;
	}

	(void) pthread_mutex_unlock(&ap->asru_lock);
}

bool_t
fmd_adm_rsrclist_1_svc(bool_t all,
    struct fmd_rpc_rsrclist *rvp, struct svc_req *req)
{
	rvp->rrl_buf.rrl_buf_len = 0;
	rvp->rrl_buf.rrl_buf_val = NULL;
	rvp->rrl_len = 0;
	rvp->rrl_cnt = 0;
	rvp->rrl_err = 0;
	rvp->rrl_all = all;

	if (fmd_rpc_deny(req))
		rvp->rrl_err = FMD_ADM_ERR_PERM;
	else
		fmd_asru_hash_apply(fmd.d_asrus, fmd_adm_rsrclist_asru, rvp);

	return (TRUE);
}

bool_t
fmd_adm_rsrcinfo_1_svc(char *fmri,
    struct fmd_rpc_rsrcinfo *rvp, struct svc_req *req)
{
	fmd_asru_t *ap;
	fmd_case_impl_t *cip;
	int state;

	bzero(rvp, sizeof (struct fmd_rpc_rsrcinfo));

	if (fmd_rpc_deny(req)) {
		rvp->rri_err = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	if ((ap = fmd_asru_hash_lookup_name(fmd.d_asrus, fmri)) == NULL) {
		rvp->rri_err = FMD_ADM_ERR_RSRCSRCH;
		return (TRUE);
	}

	state = fmd_asru_getstate(ap);
	(void) pthread_mutex_lock(&ap->asru_lock);
	cip = (fmd_case_impl_t *)ap->asru_case;

	rvp->rri_fmri = strdup(ap->asru_name);
	rvp->rri_uuid = strdup(ap->asru_uuid);
	rvp->rri_case = cip ? strdup(cip->ci_uuid) : NULL;
	rvp->rri_faulty = (state & FMD_ASRU_FAULTY) != 0;
	rvp->rri_unusable = (state & FMD_ASRU_UNUSABLE) != 0;
	rvp->rri_invisible = (ap->asru_flags & FMD_ASRU_INVISIBLE) != 0;

	(void) pthread_mutex_unlock(&ap->asru_lock);
	fmd_asru_hash_release(fmd.d_asrus, ap);

	if (rvp->rri_fmri == NULL || rvp->rri_uuid == NULL)
		rvp->rri_err = FMD_ADM_ERR_NOMEM;

	return (TRUE);
}

bool_t
fmd_adm_rsrcflush_1_svc(char *name, int *rvp, struct svc_req *req)
{
	return (fmd_adm_rsrcrepaired_1_svc(name, rvp, req));
}

bool_t
fmd_adm_rsrcrepaired_1_svc(char *name, int *rvp, struct svc_req *req)
{
	int err = FMD_ADM_ERR_RSRCNOTF;

	if (fmd_rpc_deny(req))
		err = FMD_ADM_ERR_PERM;
	else {
		fmd_asru_hash_apply_by_asru(fmd.d_asrus, name,
		    fmd_asru_repaired, &err);
		fmd_asru_hash_apply_by_label(fmd.d_asrus, name,
		    fmd_asru_repaired, &err);
		fmd_asru_hash_apply_by_fru(fmd.d_asrus, name,
		    fmd_asru_repaired, &err);
		fmd_asru_hash_apply_by_rsrc(fmd.d_asrus, name,
		    fmd_asru_repaired, &err);
	}
	*rvp = err;
	return (TRUE);
}

bool_t
fmd_adm_rsrcreplaced_1_svc(char *name, int *rvp, struct svc_req *req)
{
	int err = FMD_ADM_ERR_RSRCNOTF;

	if (fmd_rpc_deny(req))
		err = FMD_ADM_ERR_PERM;
	else {
		fmd_asru_hash_apply_by_asru(fmd.d_asrus, name,
		    fmd_asru_replaced, &err);
		fmd_asru_hash_apply_by_label(fmd.d_asrus, name,
		    fmd_asru_replaced, &err);
		fmd_asru_hash_apply_by_fru(fmd.d_asrus, name,
		    fmd_asru_replaced, &err);
		fmd_asru_hash_apply_by_rsrc(fmd.d_asrus, name,
		    fmd_asru_replaced, &err);
	}
	*rvp = err;
	return (TRUE);
}

typedef struct {
	int *errp;
	char *uuid;
} fmd_adm_ra_t;

void
fmd_asru_ra_cb(fmd_asru_link_t *alp, void *arg)
{
	fmd_adm_ra_t *farap = (fmd_adm_ra_t *)arg;

	if (strcmp(farap->uuid, "") == 0 ||
	    strcmp(farap->uuid, alp->al_case_uuid) == 0)
		fmd_asru_acquit(alp, farap->errp);
}

bool_t
fmd_adm_rsrcacquit_1_svc(char *name, char *uuid, int *rvp, struct svc_req *req)
{
	int err = FMD_ADM_ERR_RSRCNOTF;
	fmd_adm_ra_t fara;

	if (fmd_rpc_deny(req))
		err = FMD_ADM_ERR_PERM;
	else {
		fara.errp = &err;
		fara.uuid = uuid;
		fmd_asru_hash_apply_by_asru(fmd.d_asrus, name,
		    fmd_asru_ra_cb, &fara);
		fmd_asru_hash_apply_by_label(fmd.d_asrus, name,
		    fmd_asru_ra_cb, &fara);
		fmd_asru_hash_apply_by_fru(fmd.d_asrus, name,
		    fmd_asru_ra_cb, &fara);
		fmd_asru_hash_apply_by_rsrc(fmd.d_asrus, name,
		    fmd_asru_ra_cb, &fara);
	}
	*rvp = err;
	return (TRUE);
}

static void
fmd_adm_serdinfo_eng(fmd_serd_eng_t *sgp, void *arg)
{
	struct fmd_rpc_serdlist *rsl = arg;
	struct fmd_rpc_serdinfo *rsi = malloc(sizeof (struct fmd_rpc_serdinfo));

	uint64_t old, now = fmd_time_gethrtime();
	const fmd_serd_elem_t *oep;

	if (rsi == NULL || (rsi->rsi_name = strdup(sgp->sg_name)) == NULL) {
		rsl->rsl_err = FMD_ADM_ERR_NOMEM;
		free(rsi);
		return;
	}

	if ((oep = fmd_list_next(&sgp->sg_list)) != NULL)
		old = fmd_event_hrtime(oep->se_event);
	else
		old = now;

	rsi->rsi_delta = now >= old ? now - old : (UINT64_MAX - old) + now + 1;
	rsi->rsi_count = sgp->sg_count;
	rsi->rsi_fired = fmd_serd_eng_fired(sgp) != 0;
	rsi->rsi_n = sgp->sg_n;
	rsi->rsi_t = sgp->sg_t;
	rsi->rsi_next = rsl->rsl_list;

	rsl->rsl_list = rsi;
	rsl->rsl_len++;
}

bool_t
fmd_adm_serdinfo_1_svc(char *name,
    struct fmd_rpc_serdlist *rvp, struct svc_req *req)
{
	fmd_module_t *mp;

	rvp->rsl_list = NULL;
	rvp->rsl_err = 0;
	rvp->rsl_len = 0;

	if (fmd_rpc_deny(req)) {
		rvp->rsl_err = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, name)) == NULL) {
		rvp->rsl_err = FMD_ADM_ERR_MODSRCH;
		return (TRUE);
	}

	fmd_module_lock(mp);
	fmd_serd_hash_apply(&mp->mod_serds, fmd_adm_serdinfo_eng, rvp);
	fmd_module_unlock(mp);

	fmd_module_rele(mp);
	return (TRUE);
}

bool_t
fmd_adm_serdreset_1_svc(char *mname, char *sname, int *rvp, struct svc_req *req)
{
	fmd_module_t *mp;
	fmd_serd_eng_t *sgp;
	int err = 0;

	if (fmd_rpc_deny(req)) {
		*rvp = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	if ((mp = fmd_modhash_lookup(fmd.d_mod_hash, mname)) == NULL) {
		*rvp = FMD_ADM_ERR_MODSRCH;
		return (TRUE);
	}

	fmd_module_lock(mp);

	if ((sgp = fmd_serd_eng_lookup(&mp->mod_serds, sname)) != NULL) {
		if (fmd_serd_eng_fired(sgp)) {
			err = FMD_ADM_ERR_SERDFIRED;
		} else {
			fmd_serd_eng_reset(sgp);
			fmd_module_setdirty(mp);
		}
	} else
		err = FMD_ADM_ERR_SERDSRCH;

	fmd_module_unlock(mp);
	fmd_module_rele(mp);

	*rvp = err;
	return (TRUE);
}

bool_t
fmd_adm_logrotate_1_svc(char *name, int *rvp, struct svc_req *req)
{
	fmd_log_t **lpp, *old, *new;
	int try = 1, trylimit = 1;

	hrtime_t nsec = 0;
	timespec_t tv;

	if (fmd_rpc_deny(req)) {
		*rvp = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	if (strcmp(name, "errlog") == 0)
		lpp = &fmd.d_errlog;
	else if (strcmp(name, "fltlog") == 0)
		lpp = &fmd.d_fltlog;
	else {
		*rvp = FMD_ADM_ERR_ROTSRCH;
		return (TRUE);
	}

	(void) fmd_conf_getprop(fmd.d_conf, "log.tryrotate", &trylimit);
	(void) fmd_conf_getprop(fmd.d_conf, "log.waitrotate", &nsec);

	tv.tv_sec = nsec / NANOSEC;
	tv.tv_nsec = nsec % NANOSEC;

	/*
	 * To rotate a log file, grab d_log_lock as writer to make sure no
	 * one else can discover the current log pointer.  Then try to rotate
	 * the log.  If we're successful, release the old log pointer.
	 */
	do {
		if (try > 1)
			(void) nanosleep(&tv, NULL); /* wait for checkpoints */

		(void) pthread_rwlock_wrlock(&fmd.d_log_lock);
		old = *lpp;

		if ((new = fmd_log_rotate(old)) != NULL) {
			fmd_log_rele(old);
			*lpp = new;
		}

		(void) pthread_rwlock_unlock(&fmd.d_log_lock);

	} while (new == NULL && errno == EFMD_LOG_ROTBUSY && try++ < trylimit);

	if (new != NULL)
		*rvp = 0;
	else if (errno == EFMD_LOG_ROTBUSY)
		*rvp = FMD_ADM_ERR_ROTBUSY;
	else
		*rvp = FMD_ADM_ERR_ROTFAIL;

	return (TRUE);
}

bool_t
fmd_adm_caserepair_1_svc(char *uuid, int *rvp, struct svc_req *req)
{
	fmd_case_t *cp = NULL;
	int err = 0;

	if (fmd_rpc_deny(req))
		err = FMD_ADM_ERR_PERM;
	else if ((cp = fmd_case_hash_lookup(fmd.d_cases, uuid)) == NULL)
		err = FMD_ADM_ERR_CASESRCH;
	else if (fmd_case_repair(cp) != 0) {
		err = errno == EFMD_CASE_OWNER ?
		    FMD_ADM_ERR_CASEXPRT : FMD_ADM_ERR_CASEOPEN;
	}

	if (cp != NULL)
		fmd_case_rele(cp);

	*rvp = err;
	return (TRUE);
}

bool_t
fmd_adm_caseacquit_1_svc(char *uuid, int *rvp, struct svc_req *req)
{
	fmd_case_t *cp = NULL;
	int err = 0;

	if (fmd_rpc_deny(req))
		err = FMD_ADM_ERR_PERM;
	else if ((cp = fmd_case_hash_lookup(fmd.d_cases, uuid)) == NULL)
		err = FMD_ADM_ERR_CASESRCH;
	else if (fmd_case_acquit(cp) != 0) {
		err = errno == EFMD_CASE_OWNER ?
		    FMD_ADM_ERR_CASEXPRT : FMD_ADM_ERR_CASEOPEN;
	}

	if (cp != NULL)
		fmd_case_rele(cp);

	*rvp = err;
	return (TRUE);
}

void
fmd_adm_caselist_case(fmd_case_t *cp, void *arg)
{
	fmd_case_impl_t *cip = (fmd_case_impl_t *)cp;
	struct fmd_rpc_caselist *rcl = arg;
	size_t uuid_len, buf_len;
	void *p;

	if (rcl->rcl_err != 0)
		return;

	/*
	 * skip invisible cases
	 */
	if (cip->ci_flags & FMD_CF_INVISIBLE)
		return;

	/*
	 * Lock the case and reallocate rcl_buf[] to be large enough to hold
	 * another string, doubling it as needed.  Then copy the new string
	 * on to the end, and increment rcl_len to indicate the used space.
	 */
	if (!(cip->ci_flags & FMD_CF_SOLVED))
		return;

	(void) pthread_mutex_lock(&cip->ci_lock);

	uuid_len = cip->ci_uuidlen + 1;

	while (rcl->rcl_len + uuid_len > rcl->rcl_buf.rcl_buf_len) {
		if (rcl->rcl_buf.rcl_buf_len != 0)
			buf_len = rcl->rcl_buf.rcl_buf_len * 2;
		else
			buf_len = 1024; /* default buffer size */

		if ((p = realloc(rcl->rcl_buf.rcl_buf_val, buf_len)) != NULL) {
			bzero((char *)p + rcl->rcl_buf.rcl_buf_len,
			    buf_len - rcl->rcl_buf.rcl_buf_len);
			rcl->rcl_buf.rcl_buf_val = p;
			rcl->rcl_buf.rcl_buf_len = buf_len;
		} else {
			rcl->rcl_err = FMD_ADM_ERR_NOMEM;
			break;
		}
	}

	if (rcl->rcl_err == 0) {
		bcopy(cip->ci_uuid, (char *)rcl->rcl_buf.rcl_buf_val +
		    rcl->rcl_len, uuid_len);
		rcl->rcl_len += uuid_len;
		rcl->rcl_cnt++;
	}

	(void) pthread_mutex_unlock(&cip->ci_lock);
}

bool_t
fmd_adm_caselist_1_svc(struct fmd_rpc_caselist *rvp, struct svc_req *req)
{
	rvp->rcl_buf.rcl_buf_len = 0;
	rvp->rcl_buf.rcl_buf_val = NULL;
	rvp->rcl_len = 0;
	rvp->rcl_cnt = 0;
	rvp->rcl_err = 0;

	if (fmd_rpc_deny(req))
		rvp->rcl_err = FMD_ADM_ERR_PERM;
	else
		fmd_case_hash_apply(fmd.d_cases, fmd_adm_caselist_case, rvp);

	return (TRUE);
}

bool_t
fmd_adm_caseinfo_1_svc(char *uuid, struct fmd_rpc_caseinfo *rvp,
    struct svc_req *req)
{
	fmd_case_t *cp;
	nvlist_t *nvl;
	int err = 0;

	bzero(rvp, sizeof (struct fmd_rpc_caseinfo));

	if (fmd_rpc_deny(req)) {
		rvp->rci_err = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	if ((cp = fmd_case_hash_lookup(fmd.d_cases, uuid)) == NULL) {
		rvp->rci_err = FMD_ADM_ERR_CASESRCH;
		return (TRUE);
	}

	if (!(((fmd_case_impl_t *)cp)->ci_flags & FMD_CF_SOLVED)) {
		fmd_case_rele(cp);
		rvp->rci_err = FMD_ADM_ERR_CASESRCH;
		return (TRUE);
	}

	nvl = fmd_case_mkevent(cp, FM_LIST_SUSPECT_CLASS);

	err = nvlist_pack(nvl, &rvp->rci_evbuf.rci_evbuf_val,
	    &rvp->rci_evbuf.rci_evbuf_len, NV_ENCODE_XDR, 0);

	nvlist_free(nvl);

	if (err != 0)
		rvp->rci_err = FMD_ADM_ERR_NOMEM;

	fmd_case_rele(cp);

	return (TRUE);
}

/*ARGSUSED*/
static void
fmd_adm_xprtlist_one(fmd_idspace_t *ids, id_t id, void *arg)
{
	struct fmd_rpc_xprtlist *rvp = arg;

	if (rvp->rxl_len < rvp->rxl_buf.rxl_buf_len)
		rvp->rxl_buf.rxl_buf_val[rvp->rxl_len++] = id;
}

bool_t
fmd_adm_xprtlist_1_svc(struct fmd_rpc_xprtlist *rvp, struct svc_req *req)
{
	if (fmd_rpc_deny(req)) {
		rvp->rxl_buf.rxl_buf_len = 0;
		rvp->rxl_buf.rxl_buf_val = NULL;
		rvp->rxl_len = 0;
		rvp->rxl_err = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	/*
	 * Since we're taking a snapshot of the transports, and these could
	 * change after we return our result, there's no need to hold any kind
	 * of lock between retrieving ids_count and taking the snapshot.  We'll
	 * just capture up to a maximum of whatever ids_count value we sampled.
	 */
	rvp->rxl_buf.rxl_buf_len = fmd.d_xprt_ids->ids_count;
	rvp->rxl_buf.rxl_buf_val = malloc(sizeof (int32_t) *
	    rvp->rxl_buf.rxl_buf_len);
	rvp->rxl_len = 0;
	rvp->rxl_err = 0;

	if (rvp->rxl_buf.rxl_buf_val == NULL) {
		rvp->rxl_err = FMD_ADM_ERR_NOMEM;
		return (TRUE);
	}

	fmd_idspace_apply(fmd.d_xprt_ids, fmd_adm_xprtlist_one, rvp);
	return (TRUE);
}

bool_t
fmd_adm_xprtstat_1_svc(int32_t id,
    struct fmd_rpc_modstat *rms, struct svc_req *req)
{
	fmd_xprt_impl_t *xip;
	fmd_stat_t *sp, *ep, *cp;

	if (fmd_rpc_deny(req)) {
		rms->rms_buf.rms_buf_val = NULL;
		rms->rms_buf.rms_buf_len = 0;
		rms->rms_err = FMD_ADM_ERR_PERM;
		return (TRUE);
	}

	rms->rms_buf.rms_buf_val = malloc(sizeof (fmd_xprt_stat_t));
	rms->rms_buf.rms_buf_len = sizeof (fmd_xprt_stat_t) /
	    sizeof (fmd_stat_t);
	rms->rms_err = 0;

	if (rms->rms_buf.rms_buf_val == NULL) {
		rms->rms_err = FMD_ADM_ERR_NOMEM;
		rms->rms_buf.rms_buf_len = 0;
		return (TRUE);
	}

	if ((xip = fmd_idspace_hold(fmd.d_xprt_ids, id)) == NULL) {
		rms->rms_err = FMD_ADM_ERR_XPRTSRCH;
		return (TRUE);
	}

	/*
	 * Grab the stats lock and bcopy the entire transport stats array in
	 * one shot. Then go back through and duplicate any string values.
	 */
	(void) pthread_mutex_lock(&xip->xi_stats_lock);

	sp = (fmd_stat_t *)xip->xi_stats;
	ep = sp + rms->rms_buf.rms_buf_len;
	cp = rms->rms_buf.rms_buf_val;

	bcopy(sp, cp, sizeof (fmd_xprt_stat_t));

	for (; sp < ep; sp++, cp++) {
		if (sp->fmds_type == FMD_TYPE_STRING &&
		    sp->fmds_value.str != NULL)
			cp->fmds_value.str = strdup(sp->fmds_value.str);
	}

	(void) pthread_mutex_unlock(&xip->xi_stats_lock);
	fmd_idspace_rele(fmd.d_xprt_ids, id);

	return (TRUE);
}

int
fmd_adm_1_freeresult(SVCXPRT *xprt, xdrproc_t proc, caddr_t data)
{
	xdr_free(proc, data);
	svc_done(xprt);
	return (TRUE);
}

/*
 * Custom XDR routine for our API structure fmd_stat_t.  This function must
 * match the definition of fmd_stat_t in <fmd_api.h> and must also match
 * the corresponding routine in usr/src/lib/fm/libfmd_adm/common/fmd_adm.c.
 */
bool_t
xdr_fmd_stat(XDR *xp, fmd_stat_t *sp)
{
	bool_t rv = TRUE;

	rv &= xdr_opaque(xp, sp->fmds_name, sizeof (sp->fmds_name));
	rv &= xdr_u_int(xp, &sp->fmds_type);
	rv &= xdr_opaque(xp, sp->fmds_desc, sizeof (sp->fmds_desc));

	switch (sp->fmds_type) {
	case FMD_TYPE_BOOL:
		rv &= xdr_int(xp, &sp->fmds_value.bool);
		break;
	case FMD_TYPE_INT32:
		rv &= xdr_int32_t(xp, &sp->fmds_value.i32);
		break;
	case FMD_TYPE_UINT32:
		rv &= xdr_uint32_t(xp, &sp->fmds_value.ui32);
		break;
	case FMD_TYPE_INT64:
		rv &= xdr_int64_t(xp, &sp->fmds_value.i64);
		break;
	case FMD_TYPE_UINT64:
	case FMD_TYPE_TIME:
	case FMD_TYPE_SIZE:
		rv &= xdr_uint64_t(xp, &sp->fmds_value.ui64);
		break;
	case FMD_TYPE_STRING:
		rv &= xdr_string(xp, &sp->fmds_value.str, ~0);
		break;
	}

	return (rv);
}
