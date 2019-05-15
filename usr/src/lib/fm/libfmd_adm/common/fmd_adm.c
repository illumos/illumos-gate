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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <strings.h>
#include <stdlib.h>
#include <netdir.h>
#include <errno.h>
#include <alloca.h>
#include <locale.h>
#include <uuid/uuid.h>

#include <sys/fm/protocol.h>
#include <fmd_adm_impl.h>
#include <fmd_rpc_adm.h>

static const uint_t _fmd_adm_bufsize = 128 * 1024;
static const char _url_fallback[] = "http://illumos.org/msg/";

fmd_adm_t *
fmd_adm_open(const char *host, uint32_t prog, int version)
{
	fmd_adm_t *ap;
	CLIENT *c;
	rpcvers_t v;

	if (version != FMD_ADM_VERSION) {
		errno = ENOTSUP;
		return (NULL);
	}

	if (host == NULL)
		host = HOST_SELF;

	if (prog == FMD_ADM_PROGRAM)
		prog = FMD_ADM;

	if ((ap = malloc(sizeof (fmd_adm_t))) == NULL)
		return (NULL);

	if (strcmp(host, HOST_SELF) == 0) {
		c = clnt_door_create(prog, FMD_ADM_VERSION_1, _fmd_adm_bufsize);
		ap->adm_maxretries = 1;
	} else {
		c = clnt_create_vers(host, prog, &v,
		    FMD_ADM_VERSION_1, FMD_ADM_VERSION_1, NULL);
		ap->adm_maxretries = 0;
	}

	if (c == NULL) {
		errno = EPROTO;
		free(ap);
		return (NULL);
	}

	ap->adm_prog = prog;
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
	case FMD_ADM_ERR_XPRTSRCH:
		return ("specified transport ID is invalid or has been closed");
	case FMD_ADM_ERR_CASEXPRT:
		return ("specified UUID is owned by a different fault manager");
	case FMD_ADM_ERR_RSRCNOTR:
		return ("specified resource has not been replaced");
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

/*
 * If the server (fmd) is restarted, this will cause all future door calls to
 * fail.  Unfortunately, once the server comes back up, we have no way of
 * reestablishing the connection.  To get around this, if the error indicates
 * that the RPC call failed, we reopen the client handle and try again.  For
 * simplicity we only deal with the door case, as it's unclear whether the
 * remote case suffers from the same pathology.
 */
boolean_t
fmd_adm_retry(fmd_adm_t *ap, enum clnt_stat cs, uint_t *retries)
{
	CLIENT *c;
	struct rpc_err err;

	if (cs == RPC_SUCCESS || *retries == ap->adm_maxretries)
		return (B_FALSE);

	clnt_geterr(ap->adm_clnt, &err);
	if (err.re_status != RPC_CANTSEND)
		return (B_FALSE);

	if ((c = clnt_door_create(ap->adm_prog, FMD_ADM_VERSION_1,
	    _fmd_adm_bufsize)) == NULL)
		return (B_FALSE);

	(*retries)++;

	clnt_destroy(ap->adm_clnt);
	ap->adm_clnt = c;

	return (B_TRUE);
}

int
fmd_adm_stats_read(fmd_adm_t *ap, const char *name, fmd_adm_stats_t *sp)
{
	struct fmd_rpc_modstat rms;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (sp == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	bzero(&rms, sizeof (rms)); /* tell xdr to allocate memory for us */

	do {
		if (name != NULL)
			cs = fmd_adm_modcstat_1((char *)name, &rms,
			    ap->adm_clnt);
		else
			cs = fmd_adm_modgstat_1(&rms, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

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
	enum clnt_stat cs;
	uint_t retries = 0;

	bzero(&rml, sizeof (rml)); /* tell xdr to allocate memory for us */

	do {
		cs = fmd_adm_modinfo_1(&rml, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
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
	enum clnt_stat cs;
	uint_t retries = 0;

	if (path == NULL || path[0] != '/')
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_modload_1(str, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_module_unload(fmd_adm_t *ap, const char *name)
{
	char *str = (char *)name;
	int err;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (name == NULL || strchr(name, '/') != NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_modunload_1(str, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_module_reset(fmd_adm_t *ap, const char *name)
{
	char *str = (char *)name;
	int err;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (name == NULL || strchr(name, '/') != NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_modreset_1(str, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_module_gc(fmd_adm_t *ap, const char *name)
{
	char *str = (char *)name;
	int err;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (name == NULL || strchr(name, '/') != NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_modgc_1(str, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_module_stats(fmd_adm_t *ap, const char *name, fmd_adm_stats_t *sp)
{
	struct fmd_rpc_modstat rms;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (name == NULL || sp == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	bzero(&rms, sizeof (rms)); /* tell xdr to allocate memory for us */

	do {
		cs = fmd_adm_moddstat_1((char *)name, &rms, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rms.rms_err != 0) {
		xdr_free(xdr_fmd_rpc_modstat, (char *)&rms);
		return (fmd_adm_set_svcerr(ap, rms.rms_err));
	}

	sp->ams_buf = rms.rms_buf.rms_buf_val;
	sp->ams_len = rms.rms_buf.rms_buf_len;

	return (0);
}

int
fmd_adm_rsrc_count(fmd_adm_t *ap, int all, uint32_t *rcp)
{
	struct fmd_rpc_rsrclist rrl;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (rcp == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	bzero(&rrl, sizeof (rrl)); /* tell xdr to allocate memory for us */

	do {
		cs = fmd_adm_rsrclist_1(all, &rrl, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rrl.rrl_err != 0) {
		xdr_free(xdr_fmd_rpc_rsrclist, (char *)&rrl);
		return (fmd_adm_set_svcerr(ap, rrl.rrl_err));
	}

	*rcp = rrl.rrl_cnt;
	xdr_free(xdr_fmd_rpc_rsrclist, (char *)&rrl);
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
	enum clnt_stat cs;
	uint_t retries = 0;

	bzero(&rrl, sizeof (rrl)); /* tell xdr to allocate memory for us */

	do {
		cs = fmd_adm_rsrclist_1(all, &rrl, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
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

		retries = 0;
		do {
			cs = fmd_adm_rsrcinfo_1(fmris[i], &rri, ap->adm_clnt);
		} while (fmd_adm_retry(ap, cs, &retries));

		if (cs != RPC_SUCCESS) {
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
	enum clnt_stat cs;
	uint_t retries = 0;

	if (fmri == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_rsrcflush_1(str, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_rsrc_repaired(fmd_adm_t *ap, const char *fmri)
{
	char *str = (char *)fmri;
	int err;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (fmri == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_rsrcrepaired_1(str, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_rsrc_replaced(fmd_adm_t *ap, const char *fmri)
{
	char *str = (char *)fmri;
	int err;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (fmri == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_rsrcreplaced_1(str, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_rsrc_acquit(fmd_adm_t *ap, const char *fmri, const char *uuid)
{
	char *str = (char *)fmri;
	char *str2 = (char *)uuid;
	int err;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (fmri == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_rsrcacquit_1(str, str2, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_case_repair(fmd_adm_t *ap, const char *uuid)
{
	char *str = (char *)uuid;
	int err;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (uuid == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_caserepair_1(str, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_case_acquit(fmd_adm_t *ap, const char *uuid)
{
	char *str = (char *)uuid;
	int err;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (uuid == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_caseacquit_1(str, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

static int
fmd_adm_case_cmp(const void *lp, const void *rp)
{
	return (strcmp(*(char **)lp, *(char **)rp));
}

static int
fmd_adm_case_one(fmd_adm_caseinfo_t *acp, const char *url_token,
    fmd_adm_case_f *func, void *arg)
{
	char *p, *urlcode, *dict, *olang;
	const char *url;
	size_t	len;

	if ((p = strchr(acp->aci_code, '-')) == NULL ||
	    p == acp->aci_code) {
		acp->aci_url = NULL;
	} else {
		dict = alloca((size_t)(p - acp->aci_code) + 1);
		(void) strncpy(dict, acp->aci_code,
		    (size_t)(p - acp->aci_code));
		dict[(size_t)(p - acp->aci_code)] = '\0';

		/*
		 * If we're given a token to use in looking up the URL, try
		 * to use it.  Otherwise, or if we don't find it that way,
		 * use the fallback.
		 */
		if (url_token == NULL) {
			url = _url_fallback;
		} else if ((url = dgettext(dict, url_token)) == url_token) {
			/*
			 * We didn't find a translation in the
			 * dictionary for the current language.  Fall
			 * back to C and try again.
			 */
			olang = setlocale(LC_MESSAGES, NULL);
			(void) setlocale(LC_MESSAGES, "C");
			if ((url = dgettext(dict, url_token)) == url_token)
				url = _url_fallback;
			(void) setlocale(LC_MESSAGES, olang);
		}
		len = strlen(url);
		if (url[len - 1] == '/') {
			len += strlen(acp->aci_code) + 1;
			urlcode = alloca(len);
			(void) snprintf(urlcode, len, "%s%s", url,
			    acp->aci_code);
		} else {
			urlcode = (char *)url;
		}
		acp->aci_url = urlcode;
	}

	return (func(acp, arg));
}

/*
 * Our approach to cases is the same as for resources: we first obtain a
 * list of UUIDs, sort them, then obtain the case information for each.
 */
int
fmd_adm_case_iter(fmd_adm_t *ap, const char *url_token, fmd_adm_case_f *func,
    void *arg)
{
	struct fmd_rpc_caselist rcl;
	struct fmd_rpc_caseinfo rci;
	fmd_adm_caseinfo_t aci;
	char **uuids, *p;
	int i, rv;
	enum clnt_stat cs;
	uint_t retries = 0;

	bzero(&rcl, sizeof (rcl)); /* tell xdr to allocate memory for us */

	do {
		cs = fmd_adm_caselist_1(&rcl, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rcl.rcl_err != 0) {
		xdr_free(xdr_fmd_rpc_caselist, (char *)&rcl);
		return (fmd_adm_set_svcerr(ap, rcl.rcl_err));
	}

	if ((uuids = malloc(sizeof (char *) * rcl.rcl_cnt)) == NULL) {
		xdr_free(xdr_fmd_rpc_caselist, (char *)&rcl);
		return (fmd_adm_set_errno(ap, EAGAIN));
	}

	p = rcl.rcl_buf.rcl_buf_val;

	for (i = 0; i < rcl.rcl_cnt; i++, p += strlen(p) + 1)
		uuids[i] = p;

	qsort(uuids, rcl.rcl_cnt, sizeof (char *), fmd_adm_case_cmp);

	for (i = 0; i < rcl.rcl_cnt; i++) {
		bzero(&rci, sizeof (rci));

		retries = 0;
		do {
			cs = fmd_adm_caseinfo_1(uuids[i], &rci, ap->adm_clnt);
		} while (fmd_adm_retry(ap, cs, &retries));

		if (cs != RPC_SUCCESS) {
			free(uuids);
			xdr_free(xdr_fmd_rpc_caselist, (char *)&rcl);
			return (fmd_adm_set_errno(ap, EPROTO));
		}

		if (rci.rci_err != 0 && rci.rci_err != FMD_ADM_ERR_CASESRCH) {
			xdr_free(xdr_fmd_rpc_caseinfo, (char *)&rci);
			free(uuids);
			xdr_free(xdr_fmd_rpc_caselist, (char *)&rcl);
			return (fmd_adm_set_svcerr(ap, rci.rci_err));
		}

		if (rci.rci_err == FMD_ADM_ERR_CASESRCH) {
			xdr_free(xdr_fmd_rpc_caseinfo, (char *)&rci);
			continue;
		}

		bzero(&aci, sizeof (aci));

		if ((rv = nvlist_unpack(rci.rci_evbuf.rci_evbuf_val,
		    rci.rci_evbuf.rci_evbuf_len, &aci.aci_event, 0)) != 0) {
			xdr_free(xdr_fmd_rpc_caseinfo, (char *)&rci);
			free(uuids);
			xdr_free(xdr_fmd_rpc_caselist, (char *)&rcl);
			return (fmd_adm_set_errno(ap, rv));
		}

		if ((rv = nvlist_lookup_string(aci.aci_event, FM_SUSPECT_UUID,
		    (char **)&aci.aci_uuid)) != 0) {
			xdr_free(xdr_fmd_rpc_caseinfo, (char *)&rci);
			free(uuids);
			xdr_free(xdr_fmd_rpc_caselist, (char *)&rcl);
			nvlist_free(aci.aci_event);
			return (fmd_adm_set_errno(ap, rv));
		}
		if ((rv = nvlist_lookup_string(aci.aci_event,
		    FM_SUSPECT_DIAG_CODE, (char **)&aci.aci_code)) != 0) {
			xdr_free(xdr_fmd_rpc_caseinfo, (char *)&rci);
			free(uuids);
			xdr_free(xdr_fmd_rpc_caselist, (char *)&rcl);
			nvlist_free(aci.aci_event);
			return (fmd_adm_set_errno(ap, rv));
		}

		rv = fmd_adm_case_one(&aci, url_token, func, arg);

		xdr_free(xdr_fmd_rpc_caseinfo, (char *)&rci);
		nvlist_free(aci.aci_event);

		if (rv != 0)
			break;
	}

	free(uuids);
	xdr_free(xdr_fmd_rpc_caselist, (char *)&rcl);
	return (0);
}

static int
fmd_adm_serd_cmp(const void *lp, const void *rp)
{
	return (strcmp(*(char **)lp, *(char **)rp));
}

int
fmd_adm_serd_iter(fmd_adm_t *ap, const char *name,
    fmd_adm_serd_f *func, void *arg)
{
	struct fmd_rpc_serdlist rsl;
	struct fmd_rpc_serdinfo rsi;
	char **serds, *p;
	fmd_adm_serdinfo_t asi;
	enum clnt_stat cs;
	uint_t retries = 0;
	int i, rv;

	bzero(&rsl, sizeof (rsl)); /* tell xdr to allocate memory for us */

	do {
		cs = fmd_adm_serdlist_1((char *)name, &rsl, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rsl.rsl_err != 0 || rsl.rsl_len == 0) {
		xdr_free(xdr_fmd_rpc_serdlist, (char *)&rsl);
		return (fmd_adm_set_svcerr(ap, rsl.rsl_err));
	}

	if ((serds = malloc(sizeof (char *) * rsl.rsl_cnt)) == NULL) {
		xdr_free(xdr_fmd_rpc_serdlist, (char *)&rsl);
		return (fmd_adm_set_errno(ap, EAGAIN));
	}

	p = rsl.rsl_buf.rsl_buf_val;

	for (i = 0; i < rsl.rsl_cnt; i++, p += strlen(p) + 1)
		serds[i] = p;

	qsort(serds, rsl.rsl_cnt, sizeof (char *), fmd_adm_serd_cmp);

	for (i = 0; i < rsl.rsl_cnt; i++) {
		bzero(&rsi, sizeof (rsi));

		retries = 0;
		do {
			cs = fmd_adm_serdinfo_1((char *)name, serds[i], &rsi,
			    ap->adm_clnt);
		} while (fmd_adm_retry(ap, cs, &retries));

		if (cs != RPC_SUCCESS) {
			free(serds);
			xdr_free(xdr_fmd_rpc_serdlist, (char *)&rsl);
			return (fmd_adm_set_errno(ap, EPROTO));
		}

		if (rsi.rsi_err != 0 && rsi.rsi_err != FMD_ADM_ERR_SERDSRCH) {
			free(serds);
			xdr_free(xdr_fmd_rpc_serdinfo, (char *)&rsi);
			xdr_free(xdr_fmd_rpc_serdlist, (char *)&rsl);
			return (fmd_adm_set_svcerr(ap, rsi.rsi_err));
		}

		if (rsi.rsi_err == FMD_ADM_ERR_SERDSRCH) {
			xdr_free(xdr_fmd_rpc_serdinfo, (char *)&rsi);
			continue;
		}

		bzero(&asi, sizeof (asi));

		asi.asi_name = rsi.rsi_name;
		asi.asi_delta = rsi.rsi_delta;
		asi.asi_n = rsi.rsi_n;
		asi.asi_t = rsi.rsi_t;
		asi.asi_count = rsi.rsi_count;
		asi.asi_flags = 0;

		if (rsi.rsi_fired)
			asi.asi_flags |= FMD_ADM_SERD_FIRED;

		rv = func(&asi, arg);

		xdr_free(xdr_fmd_rpc_serdinfo, (char *)&rsi);

		if (rv != 0)
			break;
	}

	free(serds);
	xdr_free(xdr_fmd_rpc_serdlist, (char *)&rsl);
	return (0);
}

int
fmd_adm_serd_reset(fmd_adm_t *ap, const char *mod, const char *name)
{
	char *s1 = (char *)mod, *s2 = (char *)name;
	int err;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (mod == NULL || name == NULL || strchr(mod, '/') != NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_serdreset_1(s1, s2, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	return (fmd_adm_set_svcerr(ap, err));
}

int
fmd_adm_xprt_iter(fmd_adm_t *ap, fmd_adm_xprt_f *func, void *arg)
{
	struct fmd_rpc_xprtlist rxl;
	uint_t i;
	enum clnt_stat cs;
	uint_t retries = 0;

	bzero(&rxl, sizeof (rxl)); /* tell xdr to allocate memory for us */

	do {
		cs = fmd_adm_xprtlist_1(&rxl, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rxl.rxl_err != 0) {
		xdr_free(xdr_fmd_rpc_xprtlist, (char *)&rxl);
		return (fmd_adm_set_svcerr(ap, rxl.rxl_err));
	}

	for (i = 0; i < rxl.rxl_len; i++)
		(void) func(rxl.rxl_buf.rxl_buf_val[i], arg);

	xdr_free(xdr_fmd_rpc_xprtlist, (char *)&rxl);
	return (0);
}

int
fmd_adm_xprt_stats(fmd_adm_t *ap, id_t id, fmd_adm_stats_t *sp)
{
	struct fmd_rpc_modstat rms;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (sp == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	bzero(&rms, sizeof (rms)); /* tell xdr to allocate memory for us */

	do {
		cs = fmd_adm_xprtstat_1(id, &rms, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
		return (fmd_adm_set_errno(ap, EPROTO));

	if (rms.rms_err != 0) {
		xdr_free(xdr_fmd_rpc_modstat, (char *)&rms);
		return (fmd_adm_set_svcerr(ap, rms.rms_err));
	}

	sp->ams_buf = rms.rms_buf.rms_buf_val;
	sp->ams_len = rms.rms_buf.rms_buf_len;

	return (0);
}

int
fmd_adm_log_rotate(fmd_adm_t *ap, const char *log)
{
	int err;
	enum clnt_stat cs;
	uint_t retries = 0;

	if (log == NULL)
		return (fmd_adm_set_errno(ap, EINVAL));

	do {
		cs = fmd_adm_logrotate_1((char *)log, &err, ap->adm_clnt);
	} while (fmd_adm_retry(ap, cs, &retries));

	if (cs != RPC_SUCCESS)
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
