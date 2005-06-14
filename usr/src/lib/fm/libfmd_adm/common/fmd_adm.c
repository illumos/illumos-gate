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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <stdlib.h>
#include <netdir.h>
#include <errno.h>

#include <fmd_adm_impl.h>
#include <fmd_rpc_adm.h>

static const uint_t _fmd_adm_bufsize = 128 * 1024;

fmd_adm_t *
fmd_adm_open(const char *host, uint32_t prog, int version)
{
	fmd_adm_t *ap;
	CLIENT *c;
	int err;
	rpcvers_t v;

	if (version != FMD_ADM_VERSION) {
		errno = ENOTSUP;
		return (NULL);
	}

	if (host == NULL)
		host = HOST_SELF;

	if (prog == FMD_ADM_PROGRAM)
		prog = FMD_ADM;

	/*
	 * If we are connecting to the local host, attempt a door connection
	 * first.  If that fails or we need another host, fall through to
	 * using the standard clnt_create that iterates over all transports.
	 */
	if (strcmp(host, HOST_SELF) == 0)
		c = clnt_door_create(prog, FMD_ADM_VERSION_1, _fmd_adm_bufsize);
	else
		c = NULL;

	if (c == NULL) {
		c = clnt_create_vers(host, prog, &v,
		    FMD_ADM_VERSION_1, FMD_ADM_VERSION_1, NULL);
	}

	if (c == NULL) {
		errno = EPROTO;
		return (NULL);
	}

	if ((ap = malloc(sizeof (fmd_adm_t))) == NULL) {
		err = errno;
		clnt_destroy(c);
		errno = err;
		return (NULL);
	}

	ap->adm_clnt = c;
	ap->adm_version = version;
	ap->adm_svcerr = 0;
	ap->adm_errno = 0;

	return (ap);
}

void
fmd_adm_close(fmd_adm_t *ap)
{
	if (ap == NULL)
		return; /* permit NULL to simply caller code */

	clnt_destroy(ap->adm_clnt);
	free(ap);
}

static const char *
fmd_adm_svc_errmsg(enum fmd_adm_error err)
{
	switch (err) {
	case FMD_ADM_ERR_NOMEM:
		return ("unable to perform request due to allocation failure");
	case FMD_ADM_ERR_PERM:
		return ("operation requires additional privilege");
	case FMD_ADM_ERR_MODSRCH:
		return ("specified module is not loaded in fault manager");
	case FMD_ADM_ERR_MODBUSY:
		return ("module is in use and cannot be unloaded");
	case FMD_ADM_ERR_MODFAIL:
		return ("module failed and can no longer export statistics");
	case FMD_ADM_ERR_MODNOENT:
		return ("file missing or cannot be accessed by fault manager");
	case FMD_ADM_ERR_MODEXIST:
		return ("module using same name is already loaded");
	case FMD_ADM_ERR_MODINIT:
		return ("module failed to initialize (consult fmd(1M) log)");
	case FMD_ADM_ERR_MODLOAD:
		return ("module failed to load (consult fmd(1M) log)");
	case FMD_ADM_ERR_RSRCSRCH:
		return ("specified resource is not cached by fault manager");
	case FMD_ADM_ERR_RSRCNOTF:
		return ("specified resource is not known to be faulty");
	case FMD_ADM_ERR_SERDSRCH:
		return ("specified serd engine not present in module");
	case FMD_ADM_ERR_SERDFIRED:
		return ("specified serd engine has already fired");
	case FMD_ADM_ERR_ROTSRCH:
		return ("invalid log file name");
	case FMD_ADM_ERR_ROTFAIL:
		return ("failed to rotate log file (consult fmd(1M) log)");
	case FMD_ADM_ERR_ROTBUSY:
		return ("log file is too busy to rotate (try again later)");
	case FMD_ADM_ERR_CASESRCH:
		return ("specified UUID is invalid or has been repaired");
	case FMD_ADM_ERR_CASEOPEN:
		return ("specified UUID is still being diagnosed");
	default:
		return ("unknown fault manager error");
	}
}

const char *
fmd_adm_errmsg(fmd_adm_t *ap)
{
	if (ap == NULL) {
		switch (errno) {
		case ENOTSUP:
			return ("client requires newer libfmd_adm version");
		case EPROTO:
			return (clnt_spcreateerror("failed to connect to fmd"));
		}
	}

	switch (ap ? ap->adm_errno : errno) {
	case EPROTO:
		return (clnt_sperror(ap->adm_clnt, "rpc call failed"));
	case EREMOTE:
		return (fmd_adm_svc_errmsg(ap->adm_svcerr));
	default:
		return (strerror(ap->adm_errno));
	}
}

static int
fmd_adm_set_svcerr(fmd_adm_t *ap, enum fmd_adm_error err)
{
	if (err != 0) {
		ap->adm_svcerr = err;
		ap->adm_errno = EREMOTE;
		return (-1);
	} else {
		ap->adm_svcerr = err;
		ap->adm_errno = 0;
		return (0);
	}
}

static int
fmd_adm_set_errno(fmd_adm_t *ap, int err)
{
	ap->adm_errno = err;
	errno = err;
	return (-1);
}

static int
fmd_adm_stats_cmp(const void *lp, const void *rp)
{
	return (strcmp(((fmd_stat_t *)lp)->fmds_name,
	    ((fmd_stat_t *)rp)->fmds_name));
}

int
fmd_adm_stats_read(fmd_adm_t *ap, const char *name, fmd_adm_stats_t *sp)
{
	struct fmd_rpc_modstat rms;
	enum clnt_stat cs;

	if (sp == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	bzero(&rms, sizeof (rms)); /* tell xdr to allocate memory for us */

	if (name != NULL)
		cs = fmd_adm_modcstat_1((char *)name, &rms, ap->adm_clnt);
	else
		cs = fmd_adm_modgstat_1(&rms, ap->adm_clnt);

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rms.rms_err != 0) {
		xdr_free(xdr_fmd_rpc_modstat, (char *)&rms);
		return (fmd_adm_set_svcerr(ap, rms.rms_err));
	}

	sp->ams_buf = rms.rms_buf.rms_buf_val;
	sp->ams_len = rms.rms_buf.rms_buf_len;

	if (sp->ams_len != 0) {
		qsort(sp->ams_buf, sp->ams_len,
		    sizeof (fmd_stat_t), fmd_adm_stats_cmp);
	}

	return (0);
}

int
fmd_adm_stats_free(fmd_adm_t *ap, fmd_adm_stats_t *sp)
{
	struct fmd_rpc_modstat rms;

	if (sp == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	rms.rms_buf.rms_buf_val = sp->ams_buf;
	rms.rms_buf.rms_buf_len = sp->ams_len;
	rms.rms_err = 0;

	xdr_free(xdr_fmd_rpc_modstat, (char *)&rms);
	bzero(sp, sizeof (fmd_adm_stats_t));

	return (0);
}

static int
fmd_adm_module_cmp(const void *lp, const void *rp)
{
	return (strcmp((*(struct fmd_rpc_modinfo **)lp)->rmi_name,
	    (*(struct fmd_rpc_modinfo **)rp)->rmi_name));
}

int
fmd_adm_module_iter(fmd_adm_t *ap, fmd_adm_module_f *func, void *arg)
{
	struct fmd_rpc_modinfo *rmi, **rms, **rmp;
	struct fmd_rpc_modlist rml;
	fmd_adm_modinfo_t ami;

	bzero(&rml, sizeof (rml)); /* tell xdr to allocate memory for us */

	if (fmd_adm_modinfo_1(&rml, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rml.rml_err != 0 || rml.rml_len == 0) {
		xdr_free(xdr_fmd_rpc_modlist, (char *)&rml);
		return (fmd_adm_set_svcerr(ap, rml.rml_err));
	}

	if ((rms = rmp = malloc(sizeof (void *) * rml.rml_len)) == NULL) {
		xdr_free(xdr_fmd_rpc_modlist, (char *)&rml);
		return (fmd_adm_set_errno(ap, EAGAIN));
	}

	for (rmi = rml.rml_list; rmi != NULL; rmi = rmi->rmi_next)
		*rmp++ = rmi; /* store copy of pointer in array for sorting */

	qsort(rms, rml.rml_len, sizeof (void *), fmd_adm_module_cmp);

	for (rmp = rms; rmp < rms + rml.rml_len; rmp++) {
		rmi = *rmp;

		ami.ami_name = rmi->rmi_name;
		ami.ami_desc = rmi->rmi_desc;
		ami.ami_vers = rmi->rmi_vers;
		ami.ami_flags = 0;

		if (rmi->rmi_faulty)
			ami.ami_flags |= FMD_ADM_MOD_FAILED;

		if (func(&ami, arg) != 0)
			break;
	}

	free(rms);
	xdr_free(xdr_fmd_rpc_modlist, (char *)&rml);
	return (0);
}

int
fmd_adm_module_load(fmd_adm_t *ap, const char *path)
{
	char *str = (char *)path;
	int err;

	if (path == NULL || path[0] != '/')
		return (fmd_adm_set_errno(ap, EINVAL));

	if (fmd_adm_modload_1(str, &err, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_module_unload(fmd_adm_t *ap, const char *name)
{
	char *str = (char *)name;
	int err;

	if (name == NULL || strchr(name, '/') != NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	if (fmd_adm_modunload_1(str, &err, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_module_reset(fmd_adm_t *ap, const char *name)
{
	char *str = (char *)name;
	int err;

	if (name == NULL || strchr(name, '/') != NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	if (fmd_adm_modreset_1(str, &err, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_module_gc(fmd_adm_t *ap, const char *name)
{
	char *str = (char *)name;
	int err;

	if (name == NULL || strchr(name, '/') != NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	if (fmd_adm_modgc_1(str, &err, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_module_stats(fmd_adm_t *ap, const char *name, fmd_adm_stats_t *sp)
{
	struct fmd_rpc_modstat rms;

	if (name == NULL || sp == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	bzero(&rms, sizeof (rms)); /* tell xdr to allocate memory for us */

	if (fmd_adm_moddstat_1((char *)name, &rms, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rms.rms_err != 0) {
		xdr_free(xdr_fmd_rpc_modstat, (char *)&rms);
		return (fmd_adm_set_svcerr(ap, rms.rms_err));
	}

	sp->ams_buf = rms.rms_buf.rms_buf_val;
	sp->ams_len = rms.rms_buf.rms_buf_len;

	return (0);
}

static int
fmd_adm_rsrc_cmp(const void *lp, const void *rp)
{
	return (strcmp(*(char **)lp, *(char **)rp));
}

int
fmd_adm_rsrc_iter(fmd_adm_t *ap, int all, fmd_adm_rsrc_f *func, void *arg)
{
	struct fmd_rpc_rsrclist rrl;
	struct fmd_rpc_rsrcinfo rri;
	fmd_adm_rsrcinfo_t ari;
	char **fmris, *p;
	int i, rv;

	bzero(&rrl, sizeof (rrl)); /* tell xdr to allocate memory for us */

	if (fmd_adm_rsrclist_1(all, &rrl, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rrl.rrl_err != 0) {
		xdr_free(xdr_fmd_rpc_rsrclist, (char *)&rrl);
		return (fmd_adm_set_svcerr(ap, rrl.rrl_err));
	}

	if ((fmris = malloc(sizeof (char *) * rrl.rrl_cnt)) == NULL) {
		xdr_free(xdr_fmd_rpc_rsrclist, (char *)&rrl);
		return (fmd_adm_set_errno(ap, EAGAIN));
	}

	/*
	 * The fmd_adm_rsrclist_1 request returns an opaque XDR buffer that is
	 * a string table of FMRIs (e.g. "fmriA\0fmriB\0...") where rrl_cnt is
	 * the number of strings in the table and rrl_buf_val is its address.
	 * We construct an array of pointers into the string table and sort it.
	 */
	p = rrl.rrl_buf.rrl_buf_val;

	for (i = 0; i < rrl.rrl_cnt; i++, p += strlen(p) + 1)
		fmris[i] = p; /* store fmri pointer in array for sorting */

	qsort(fmris, rrl.rrl_cnt, sizeof (char *), fmd_adm_rsrc_cmp);

	/*
	 * For each FMRI in the resource cache snapshot, use fmd_adm_rsrcinfo_1
	 * to get more information and the invoke the callback function.  If
	 * FMD_ADM_ERR_RSRCSRCH is returned, the FMRI has been purged from the
	 * cache since our snapshot: this error is therefore silently ignored.
	 */
	for (i = 0; i < rrl.rrl_cnt; i++) {
		bzero(&rri, sizeof (rri));

		if (fmd_adm_rsrcinfo_1(fmris[i], &rri,
		    ap->adm_clnt) != RPC_SUCCESS) {
			free(fmris);
			xdr_free(xdr_fmd_rpc_rsrclist, (char *)&rrl);
			return (fmd_adm_set_errno(ap, EPROTO));
		}

		if (rri.rri_err != 0 && rri.rri_err != FMD_ADM_ERR_RSRCSRCH) {
			xdr_free(xdr_fmd_rpc_rsrcinfo, (char *)&rri);
			free(fmris);
			xdr_free(xdr_fmd_rpc_rsrclist, (char *)&rrl);
			return (fmd_adm_set_svcerr(ap, rri.rri_err));
		}

		if (rri.rri_err == FMD_ADM_ERR_RSRCSRCH) {
			xdr_free(xdr_fmd_rpc_rsrcinfo, (char *)&rri);
			continue;
		}

		ari.ari_fmri = rri.rri_fmri;
		ari.ari_uuid = rri.rri_uuid;
		ari.ari_case = rri.rri_case;
		ari.ari_flags = 0;

		if (rri.rri_faulty)
			ari.ari_flags |= FMD_ADM_RSRC_FAULTY;
		if (rri.rri_unusable)
			ari.ari_flags |= FMD_ADM_RSRC_UNUSABLE;
		if (rri.rri_invisible)
			ari.ari_flags |= FMD_ADM_RSRC_INVISIBLE;

		rv = func(&ari, arg);
		xdr_free(xdr_fmd_rpc_rsrcinfo, (char *)&rri);

		if (rv != 0)
			break;
	}

	free(fmris);
	xdr_free(xdr_fmd_rpc_rsrclist, (char *)&rrl);
	return (0);
}

int
fmd_adm_rsrc_flush(fmd_adm_t *ap, const char *fmri)
{
	char *str = (char *)fmri;
	int err;

	if (fmri == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	if (fmd_adm_rsrcflush_1(str, &err, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_rsrc_repair(fmd_adm_t *ap, const char *fmri)
{
	char *str = (char *)fmri;
	int err;

	if (fmri == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	if (fmd_adm_rsrcrepair_1(str, &err, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_case_repair(fmd_adm_t *ap, const char *uuid)
{
	char *str = (char *)uuid;
	int err;

	if (uuid == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	if (fmd_adm_caserepair_1(str, &err, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

static int
fmd_adm_serd_cmp(const void *lp, const void *rp)
{
	return (strcmp((*(struct fmd_rpc_serdinfo **)lp)->rsi_name,
	    (*(struct fmd_rpc_serdinfo **)rp)->rsi_name));
}

int
fmd_adm_serd_iter(fmd_adm_t *ap, const char *name,
    fmd_adm_serd_f *func, void *arg)
{
	struct fmd_rpc_serdinfo *rsi, **ris, **rip;
	struct fmd_rpc_serdlist rsl;
	fmd_adm_serdinfo_t asi;

	bzero(&rsl, sizeof (rsl)); /* tell xdr to allocate memory for us */

	if (fmd_adm_serdinfo_1((char *)name, &rsl, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rsl.rsl_err != 0 || rsl.rsl_len == 0) {
		xdr_free(xdr_fmd_rpc_serdlist, (char *)&rsl);
		return (fmd_adm_set_svcerr(ap, rsl.rsl_err));
	}

	if ((ris = rip = malloc(sizeof (void *) * rsl.rsl_len)) == NULL) {
		xdr_free(xdr_fmd_rpc_serdlist, (char *)&rsl);
		return (fmd_adm_set_errno(ap, EAGAIN));
	}

	for (rsi = rsl.rsl_list; rsi != NULL; rsi = rsi->rsi_next)
		*rip++ = rsi; /* store copy of pointer in array for sorting */

	qsort(ris, rsl.rsl_len, sizeof (void *), fmd_adm_serd_cmp);

	for (rip = ris; rip < ris + rsl.rsl_len; rip++) {
		rsi = *rip;

		asi.asi_name = rsi->rsi_name;
		asi.asi_delta = rsi->rsi_delta;
		asi.asi_n = rsi->rsi_n;
		asi.asi_t = rsi->rsi_t;
		asi.asi_count = rsi->rsi_count;
		asi.asi_flags = 0;

		if (rsi->rsi_fired)
			asi.asi_flags |= FMD_ADM_SERD_FIRED;

		if (func(&asi, arg) != 0)
			break;
	}

	free(ris);
	xdr_free(xdr_fmd_rpc_serdlist, (char *)&rsl);
	return (0);
}

int
fmd_adm_serd_reset(fmd_adm_t *ap, const char *mod, const char *name)
{
	char *s1 = (char *)mod, *s2 = (char *)name;
	int err;

	if (mod == NULL || name == NULL || strchr(mod, '/') != NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	if (fmd_adm_serdreset_1(s1, s2, &err, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_log_rotate(fmd_adm_t *ap, const char *log)
{
	int err;

	if (log == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	if (fmd_adm_logrotate_1((char *)log, &err, ap->adm_clnt) != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

/*
 * Custom XDR routine for our API structure fmd_stat_t.  This function must
 * match the definition of fmd_stat_t in <fm/fmd_api.h> and must also match
 * the corresponding routine in usr/src/cmd/fm/fmd/common/fmd_rpc_adm.c.
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
