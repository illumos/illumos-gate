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
 * NFS Version 4 client side SECINFO code.
 */

#include <nfs/nfs4_clnt.h>
#include <nfs/nfs4.h>
#include <nfs/nfs_clnt.h>
#include <nfs/rnode4.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/systm.h>

/*
 * Set up the security flavors supported in this release.
 * In the order of potential usage.
 */
#define	SECINFO_SUPPORT_COUNT 6	/* sys, krb5, krb5i, krb5p, none, dh */
static char krb5_val[] = {'\x2A', '\x86', '\x48', '\x86', '\xF7', \
			'\x12', '\x01', '\x02', '\x02'};
static sec_oid4 krb5_oid = {9, krb5_val};
static SECINFO4res *secinfo_support;

/* XXX should come from auth.h, do the cleanup someday */
extern void sec_clnt_freeinfo(struct sec_data *);

/*
 * "nfsstat -m" needs to print out what flavor is used for a mount
 * point. V3 kernel gets the nfs pseudo flavor from the userland and provides
 * nfsstat with such information. However, in V4, we do not have nfs pseudo
 * flavors mapping in the kernel for the rpcsec_gss data negotiated from
 * the nfs server.
 *
 * XXX
 * Hard coded the mapping in V4 for now. We should look into a possibility
 * to return the rpcsec_gss mechanism and service information to nfsstat and
 * perhaps have nfsstat print out the mech and service seperately...
 *
 * We should avoid referring to nfssec.conf file in V4. The original reason
 * for having /etc/nfssec.conf file is because V3 MOUNT protocol can only
 * return an integer for a flavor, thus the term "nfs pseudo flavor" is
 * defined and the nfssec.conf file is used to map the nfs pseudo flavor
 * to rpcsec_gss data (mech, service, default-qop). Now, V4 can return the
 * rpcsec_gss data instead of an integer, so in theory, V4 should not need
 * to depend on the nfssec.conf file anymore.
 */
#define	NFS_FLAVOR_KRB5		390003
#define	NFS_FLAVOR_KRB5I	390004
#define	NFS_FLAVOR_KRB5P	390005

/*
 * Currently, 6 flavors are supported: sys, krb5, krb5i, krb5p, dh, none.
 * Without proper keys, krb5* or dh will fail.
 *
 * XXX kgss_indicate_mechs() should be able to tell us what gss mechanisms
 * are supported on this host (/etc/gss/mech), thus nfs should be able to
 * use them. However, the dh640 and dh1024 implementation are not nfs tested.
 * Should look into using kgss_indicate_mechs when new gss mechanism is added.
 */
void
nfs4_secinfo_init(void)
{
	secinfo4 *val;
	int i;

	secinfo_support = kmem_alloc(sizeof (SECINFO4res), KM_SLEEP);
	secinfo_support->SECINFO4resok_len = SECINFO_SUPPORT_COUNT;
	val = kmem_alloc(
	    secinfo_support->SECINFO4resok_len * sizeof (secinfo4),
	    KM_SLEEP);

	val[0].flavor = AUTH_SYS;
	val[0].flavor_info.oid.sec_oid4_len = 0;
	val[0].flavor_info.oid.sec_oid4_val = NULL;
	val[0].flavor_info.service = 0;
	val[0].flavor_info.qop = 0;

	/* add krb5, krb5i, krb5p */
	for (i = 1; i <= 3; i++) {
		val[i].flavor = RPCSEC_GSS;
		val[i].flavor_info.oid = krb5_oid;	/* struct copy */
		val[i].flavor_info.service = i;
		val[i].flavor_info.qop = 0;
	}

	val[4].flavor = AUTH_DH;
	val[4].flavor_info.oid.sec_oid4_len = 0;
	val[4].flavor_info.oid.sec_oid4_val = NULL;
	val[4].flavor_info.service = 0;
	val[4].flavor_info.qop = 0;

	val[5].flavor = AUTH_NONE;
	val[5].flavor_info.oid.sec_oid4_len = 0;
	val[5].flavor_info.oid.sec_oid4_val = NULL;
	val[5].flavor_info.service = 0;
	val[5].flavor_info.qop = 0;

#if !defined(lint)
	ASSERT(SECINFO_SUPPORT_COUNT == 6);
#endif

	secinfo_support->SECINFO4resok_val = val;
}

/*
 * clean up secinfo_support
 */
void
nfs4_secinfo_fini(void)
{

	kmem_free(secinfo_support->SECINFO4resok_val,
	    secinfo_support->SECINFO4resok_len * sizeof (secinfo4));
	kmem_free(secinfo_support, sizeof (SECINFO4res));
}

/*
 * Map RPCSEC_GSS data to a nfs pseudo flavor number defined
 * in the nfssec.conf file.
 *
 * mechanism    service    qop       nfs-pseudo-flavor
 * ----------------------------------------------------
 * kerberos_v5  none       default   390003/krb5
 * kerberos_v5  integrity  default   390004/krb5i
 * kerberos_v5  privacy    default   390005/krb5p
 *
 * XXX need to re-visit the mapping semantics when a new
 * security mechanism is to be added.
 */
int
secinfo2nfsflavor(sec_oid4 *mech_oid, rpc_gss_svc_t service)
{
	/* Is this kerberos_v5? */
	if (bcmp(mech_oid->sec_oid4_val, krb5_oid.sec_oid4_val,
	    krb5_oid.sec_oid4_len) != 0) {
		return (0);
	}

	/* for krb5, krb5i, krb5p mapping */
	switch (service) {
	case RPC_GSS_SVC_NONE:
		return (NFS_FLAVOR_KRB5);
	case RPC_GSS_SVC_INTEGRITY:
		return (NFS_FLAVOR_KRB5I);
	case RPC_GSS_SVC_PRIVACY:
		return (NFS_FLAVOR_KRB5P);
	default:
		break;
	}

	/* no mapping */
	return (0);
}

/*
 * secinfo_create() maps the secinfo4 data coming over the wire
 * to sv_secinfo data structure in servinfo4_t
 */
static sv_secinfo_t *
secinfo_create(servinfo4_t *svp, SECINFO4res *sec_info, char *servname)
{
	uint_t i, seccnt, scnt;
	sec_data_t *sdata;
	sv_secinfo_t *sinfo;
	uint_t len = sec_info->SECINFO4resok_len;
	secinfo4 *value = sec_info->SECINFO4resok_val;

	if (len == 0)
		return (NULL);

	seccnt = len;

	/*
	 * If there is no valid sv_dhsec data available but an AUTH_DH
	 * is in the list, skip AUTH_DH flavor.
	 */
	if (!svp->sv_dhsec) {
		for (i = 0; i < len; i++) {
			if (value[i].flavor == AUTH_DH)
				seccnt--;
		}
	}

	if (seccnt == 0)
		return (NULL);

	sdata = kmem_alloc(sizeof (sec_data_t) * seccnt, KM_SLEEP);
	scnt = 0;
	for (i = 0; i < len; i++) {
		secinfo4 *val = &value[i];
		gss_clntdata_t *data;
		rpcsec_gss_info *info;

		sdata[scnt].flags = 0;
		sdata[scnt].rpcflavor = val->flavor;

		switch (val->flavor) {
		case RPCSEC_GSS:
			data = kmem_alloc(sizeof (gss_clntdata_t), KM_SLEEP);
			data->realm[0] = '\0';
			info = &val->flavor_info;
			data->service = (rpc_gss_service_t)info->service;
			data->qop = (uint_t)info->qop;
			data->mechanism.length = info->oid.sec_oid4_len;
			data->mechanism.elements =
			    kmem_alloc(info->oid.sec_oid4_len, KM_SLEEP);
			bcopy(info->oid.sec_oid4_val,
			    data->mechanism.elements, info->oid.sec_oid4_len);
			data->uname[0] = 'n'; data->uname[1] = 'f';
			data->uname[2] = 's'; data->uname[3] = '\0';
			(void) strcpy(data->inst, servname);

			sdata[scnt].data = (caddr_t)data;
			sdata[scnt].secmod =
			    secinfo2nfsflavor(&info->oid, info->service);
			scnt++;
			break;
		case AUTH_DH:
			if (svp->sv_dhsec) {
				sdata[scnt] = *svp->sv_dhsec;
				scnt++;
				break;
			}
			/* no auth_dh data on the client, skip auth_dh */
			continue;
		default:
			sdata[scnt].secmod = val->flavor;
			sdata[scnt].data = NULL;
			scnt++;
			break;
		}
	}

	ASSERT(seccnt == scnt);
	sinfo = kmem_alloc(sizeof (sv_secinfo_t), KM_SLEEP);
	sinfo->count = seccnt;
	sinfo->sdata = sdata;

	return (sinfo);
}

/*
 * secinfo_free() frees the malloc'd portion of a sv_secinfo_t in servinfo4_t.
 *
 * This is similar to sec_clnt_freeinfo() offered from rpcsec module,
 * except that sec_clnt_freeinfo() frees up an individual secdata.
 */
void
secinfo_free(sv_secinfo_t *secinfo)
{
	int i;

	if (secinfo == NULL)
		return;

	for (i = 0; i < secinfo->count; i++) {
		if (secinfo->sdata[i].rpcflavor == RPCSEC_GSS) {
			gss_clntdata_t *data = (gss_clntdata_t *)
			    secinfo->sdata[i].data;

			/*
			 * An auth handle may already cached in rpcsec_gss
			 * module per this secdata. Purge the cache entry
			 * before freeing up this secdata. Can't use
			 * sec_clnt_freeinfo since the allocation of secinfo
			 * is different from sec_data.
			 */
			(void) rpc_gss_secpurge((void *)&secinfo->sdata[i]);

			kmem_free(data->mechanism.elements,
			    data->mechanism.length);
			kmem_free(data, sizeof (gss_clntdata_t));
		}

		if (secinfo->sdata[i].rpcflavor == AUTH_DH) {

			/* release ref to sv_dhsec */
			secinfo->sdata[i].data = NULL;

			/*
			 * No need to purge the auth_dh cache entry (e.g. call
			 * purge_authtab()) since the AUTH_DH data used here
			 * are always the same.
			 */
		}
	}
	kmem_free(secinfo->sdata, sizeof (sec_data_t) * secinfo->count);
	kmem_free(secinfo, sizeof (sv_secinfo_t));
}

/*
 * Check if there is more secinfo to try.
 * If TRUE, try again.
 */
static bool_t
secinfo_check(servinfo4_t *svp)
{

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
	if (svp->sv_secinfo == NULL) {
		nfs_rw_exit(&svp->sv_lock);
		return (FALSE);
	}

	svp->sv_secinfo->index++;
	if (svp->sv_secinfo->index < svp->sv_secinfo->count) {
		svp->sv_flags |= SV4_TRYSECINFO;
		svp->sv_currsec =
		    &svp->sv_secinfo->sdata[svp->sv_secinfo->index];
		nfs_rw_exit(&svp->sv_lock);
		return (TRUE);
	} else {
		svp->sv_secinfo->index = 0;
		svp->sv_flags &= ~SV4_TRYSECINFO;
		svp->sv_currsec = NULL;
		nfs_rw_exit(&svp->sv_lock);
		return (FALSE);
	}
}

/*
 * Update the secinfo related fields in svp.
 *
 * secinfo_update will free the previous sv_secinfo and update with
 * the new secinfo. However, if the sv_secinfo is saved into sv_save_secinfo
 * before the recovery starts via save_mnt_secinfo(), sv_secinfo will not
 * be freed until the recovery is done.
 */
static void
secinfo_update(servinfo4_t *svp, SECINFO4res *sec_info)
{

	sv_secinfo_t *newsecinfo;

	/*
	 * Create secinfo before freeing the old one to make sure
	 * they are not using the same address.
	 */
	newsecinfo = secinfo_create(svp, sec_info, svp->sv_hostname);

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
	if (svp->sv_secinfo && svp->sv_secinfo != svp->sv_save_secinfo) {
		secinfo_free(svp->sv_secinfo);
	}

	svp->sv_secinfo = newsecinfo;
	if (svp->sv_secinfo) {
		svp->sv_secinfo->index = 0;
		svp->sv_flags |= SV4_TRYSECINFO;
		svp->sv_currsec =
		    &svp->sv_secinfo->sdata[svp->sv_secinfo->index];
	} else {
		svp->sv_flags &= ~SV4_TRYSECINFO;
		svp->sv_currsec = NULL;
	}
	nfs_rw_exit(&svp->sv_lock);
}

/*
 * Save the original mount point security information.
 *
 * sv_savesec saves the pointer of sv_currsec which points to one of the
 * secinfo data in the sv_secinfo list. i.e. sv_currsec == &sv_secinfo[index].
 *
 * sv_save_secinfo saves the pointer of sv_secinfo which is the list of
 * secinfo data returned by the server.
 */
void
save_mnt_secinfo(servinfo4_t *svp)
{
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
	if (svp->sv_currsec) {
		svp->sv_savesec = svp->sv_currsec;
		svp->sv_save_secinfo = svp->sv_secinfo;
	} else {
		ASSERT(svp->sv_save_secinfo == NULL);
		svp->sv_savesec = svp->sv_secdata;
	}
	nfs_rw_exit(&svp->sv_lock);
}

/*
 * Check if we need to restore what is saved in sv_savesec and sv_save_secinfo
 * to be the current secinfo information - sv_currsec and sv_secinfo.
 *
 * If op a node that is a stub for a crossed mount point,
 * keep the original secinfo flavor for the current file system,
 * not the crossed one.
 */
void
check_mnt_secinfo(servinfo4_t *svp, vnode_t *vp)
{
	bool_t is_restore;

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);

	is_restore = (vp == NULL || (RP_ISSTUB(VTOR4(vp)))) &&
	    svp->sv_save_secinfo &&
	    (svp->sv_secinfo != svp->sv_save_secinfo);

	if (is_restore) {
		secinfo_free(svp->sv_secinfo);
		if (svp->sv_savesec == svp->sv_secdata) {
			ASSERT(svp->sv_save_secinfo == NULL);
			svp->sv_secinfo = NULL;
			svp->sv_currsec = NULL;
		} else {
			ASSERT(svp->sv_save_secinfo != NULL);
			svp->sv_secinfo = svp->sv_save_secinfo;
			svp->sv_currsec = svp->sv_savesec;
		}
	} else {
		if (svp->sv_save_secinfo &&
		    svp->sv_save_secinfo != svp->sv_secinfo)
			secinfo_free(svp->sv_save_secinfo);
	}

	svp->sv_save_secinfo = NULL;
	svp->sv_savesec = NULL;

	nfs_rw_exit(&svp->sv_lock);
}

/*
 * Use the security flavors supported on the client to try
 * PUTROOTFH until a flavor is found.
 *
 * PUTROOTFH could return NFS4ERR_RESOURCE and NFS4ERR_WRONGSEC that
 * may need a recovery action. This routine only handles NFS4ERR_WRONGSEC.
 * For other recovery action, it returns ok to the caller for retry.
 */
static int
secinfo_tryroot_otw(mntinfo4_t *mi, cred_t *cr)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop;
	int doqueue = 1;
	bool_t needrecov = FALSE;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };

	/* use the flavors supported on the client */
	secinfo_update(mi->mi_curr_serv, secinfo_support);

	/* Compound {Putroofh} */
	args.ctag = TAG_PUTROOTFH;

	args.array_len = 1;
	args.array = &argop;

	argop.argop = OP_PUTROOTFH;
retry:
	NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
	    "secinfo_tryroot_otw: %s call, mi 0x%p",
	    needrecov ? "recov" : "first", (void*)mi));

	rfs4call(mi, &args, &res, cr, &doqueue, RFSCALL_SOFT, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
	if (e.error && !needrecov) {
		return (e.error);
	}

	if (res.status == NFS4ERR_WRONGSEC) {
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		if (secinfo_check(mi->mi_curr_serv))
			goto retry;
		/*
		 * Have tried all flavors supported on the client,
		 * but still get NFS4ERR_WRONGSEC. Nothing more can
		 * be done.
		 */
		return (geterrno4(res.status));
	}

	if (needrecov) {
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "secinfo_tryroot_otw: let the caller retry\n"));

		if (!e.error)
			xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return (0);
	}

	if (res.status) {
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return (geterrno4(res.status));
	}

	/*
	 * Done.
	 *
	 * Now, mi->sv_curr_server->sv_currsec points to the flavor found.
	 * SV4_TRYSECINFO has been cleared in rfs4call.
	 * sv_currsec will be used.
	 */
	xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	return (e.error);
}

/*
 * Caculate the total number of components within a given pathname.
 * Assuming the given pathname is not null.
 * e.g. returns 5 for "/a/b/c/d/e" or "a/b/c/d/e"
 *	returns 0 for "/"
 */
static int
comp_total(char *inpath)
{
	int tnum = 0;
	char *slash;

	while (*inpath != '\0') {

		if (*inpath == '/') {
			inpath++;
			continue;
		}
		if ((slash = (char *)strchr(inpath, '/')) == NULL) {
			tnum++;
			break;
		} else {
			tnum++;
			inpath = slash + 1;
		}
	}

	return (tnum);
}

/*
 * Get the pointer of the n-th component in the given path.
 * Mark the preceeding '/' of the component to be '\0' when done.
 * Assuming nth is > 0.
 */
static void
comp_getn(char *inpath, int nth, component4 *comp)
{
	char *path = inpath, *comp_start, *slash = NULL;
	int count = 0;

	while ((count != nth) && (*path != '\0')) {

		comp_start = path;

		/* ignore slashes prior to the component name */
		while (*path == '/')
			path++;

		if (*path != '\0') {
			comp_start = path;
			count++;
		}

		if ((slash = strchr(path, '/')) == NULL)
			break;
		else
			path = slash + 1;
	}

	if (count == nth) {
		if (slash)
			*slash = '\0';
		comp->utf8string_len = strlen(comp_start);
		comp->utf8string_val = comp_start;

		if (comp_start != inpath) {
			comp_start--;
			*comp_start = '\0';
		}
	} else {
		comp->utf8string_len = 0;
		comp->utf8string_val = NULL;
	}
}

/*
 * SECINFO over the wire compound operation
 *
 *	compound {PUTROOTFH, {LOOKUP parent-path}, SECINFO component}
 *
 * This routine assumes there is a component to work on, thus the
 * given pathname (svp->sv_path) has to have at least 1 component.
 *
 * isrecov - TRUE if this routine is called from a recovery thread.
 *
 * nfs4secinfo_otw() only deals with NFS4ERR_WRONGSEC recovery. If this
 * is already in a recovery thread, then setup the non-wrongsec recovery
 * action thru nfs4_start_recovery and return to the outer loop in
 * nfs4_recov_thread() for recovery. If this is not called from a recovery
 * thread, then error out and let the caller decide what to do.
 */
static int
nfs4secinfo_otw(mntinfo4_t *mi, cred_t *cr, servinfo4_t *svp, int isrecov)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 *argop;
	nfs_resop4 *resop;
	lookup4_param_t lookuparg;
	uint_t path_len;
	int doqueue;
	int numops, num_argops;
	char *tmp_path;
	component4 comp;
	uint_t ncomp, tcomp;
	bool_t needrecov = FALSE;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	ncomp = tcomp = comp_total(svp->sv_path);
	path_len = strlen(svp->sv_path);
	nfs_rw_exit(&svp->sv_lock);
	ASSERT(ncomp > 0);

retry:
	tmp_path = kmem_alloc(path_len + 1, KM_SLEEP);
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	bcopy(svp->sv_path, tmp_path, path_len + 1);
	nfs_rw_exit(&svp->sv_lock);
	comp_getn(tmp_path, ncomp, &comp);

	args.ctag = TAG_SECINFO;

	lookuparg.l4_getattrs = LKP4_NO_ATTRIBUTES;
	lookuparg.argsp = &args;
	lookuparg.resp = &res;
	lookuparg.header_len = 1;	/* Putrootfh */
	lookuparg.trailer_len = 1;	/* Secinfo */
	lookuparg.ga_bits = NULL;
	lookuparg.mi = mi;

	/* setup LOOKUPs for parent path */
	(void) nfs4lookup_setup(tmp_path, &lookuparg, 0);

	argop = args.array;

	/* put root fh */
	argop[0].argop = OP_PUTROOTFH;

	/* setup SECINFO op */
	num_argops = args.array_len;
	argop[num_argops - 1].argop = OP_SECINFO;
	argop[num_argops - 1].nfs_argop4_u.opsecinfo.name.utf8string_len =
	    comp.utf8string_len;
	argop[num_argops - 1].nfs_argop4_u.opsecinfo.name.utf8string_val =
	    comp.utf8string_val;

	doqueue = 1;

	NFS4_DEBUG(nfs4_client_call_debug, (CE_NOTE,
	    "nfs4secinfo_otw: %s call, mi 0x%p",
	    needrecov ? "recov" : "first", (void*)mi));

	rfs4call(mi, &args, &res, cr, &doqueue, RFSCALL_SOFT, &e);

	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);
	if (e.error && !needrecov) {
		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		kmem_free(tmp_path, path_len + 1);
		return (e.error);
	}

	/*
	 * Secinfo compound op may fail with NFS4ERR_WRONGSEC from
	 * PUTROOTFH or LOOKUP. Special handling here to recover it.
	 */
	if (res.status == NFS4ERR_WRONGSEC) {

		if (res.array_len == 1) {
			/*
			 * If a flavor can not be found via trying
			 * all supported flavors on the client, no
			 * more operations.
			 */
			ncomp = tcomp;
			nfs4args_lookup_free(argop, num_argops);
			kmem_free(argop,
			    lookuparg.arglen * sizeof (nfs_argop4));
			xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			kmem_free(tmp_path, path_len + 1);

			if (e.error = secinfo_tryroot_otw(mi, cr)) {
				return (e.error);
			}
			goto retry;
		}
		ncomp = res.array_len - 1;
		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		kmem_free(tmp_path, path_len + 1);
		goto retry;
	}

	/*
	 * This routine does not do recovery for non NFS4ERR_WRONGSEC error.
	 * However, if this is already in a recovery thread, then
	 * set up the recovery action thru nfs4_start_recovery and
	 * return ok back to the outer loop in nfs4_recov_thread for
	 * recovery.
	 */
	if (needrecov) {
		bool_t abort;

		/* If not in a recovery thread, bail out */
		if (!isrecov) {
			if (!e.error) {
				e.error = geterrno4(res.status);
				xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
			}

			nfs4args_lookup_free(argop, num_argops);
			kmem_free(argop,
			    lookuparg.arglen * sizeof (nfs_argop4));
			kmem_free(tmp_path, path_len + 1);
			return (e.error);
		}

		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "nfs4secinfo_otw: recovery in a recovery thread\n"));

		abort = nfs4_start_recovery(&e, mi, NULL,
		    NULL, NULL, NULL, OP_SECINFO, NULL, NULL, NULL);
		if (!e.error) {
			e.error = geterrno4(res.status);
			xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		}
		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		kmem_free(tmp_path, path_len + 1);
		if (abort == FALSE) {
			/*
			 * Return ok to let the outer loop in
			 * nfs4_recov_thread continue with the recovery action.
			 */
			return (0);
		}
		return (e.error);
	}

	if (res.status) {
		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		kmem_free(tmp_path, path_len + 1);
		return (geterrno4(res.status));
	}

	/*
	 * Success! Now get the SECINFO result.
	 */
	numops = res.array_len;
	resop = &res.array[numops-1];	/* secinfo res */
	ASSERT(resop->resop == OP_SECINFO);

	if (resop->nfs_resop4_u.opsecinfo.SECINFO4resok_len == 0) {
		/*
		 * Server does not return any flavor for this export point.
		 * Return EACCES.
		 */
		nfs4args_lookup_free(argop, num_argops);
		kmem_free(tmp_path, path_len + 1);
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		kmem_free(argop, num_argops * sizeof (nfs_argop4));
		return (EACCES);
	}

	secinfo_update(mi->mi_curr_serv, &resop->nfs_resop4_u.opsecinfo);

	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	if (svp->sv_secinfo == NULL) {
		nfs_rw_exit(&svp->sv_lock);
		/*
		 * This could be because the server requires AUTH_DH, but
		 * the client does not have netname/syncaddr data
		 * from sv_dhsec.
		 */
		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		kmem_free(tmp_path, path_len + 1);
		return (EACCES);
	}
	nfs_rw_exit(&svp->sv_lock);

	/*
	 * If this is not the original request, try again using the
	 * new secinfo data in mi.
	 */
	if (ncomp != tcomp) {

		ncomp = tcomp;
		nfs4args_lookup_free(argop, num_argops);
		kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		kmem_free(tmp_path, path_len + 1);
		goto retry;
	}

	/* Done! */
	nfs4args_lookup_free(argop, num_argops);
	kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));
	xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	kmem_free(tmp_path, path_len + 1);

	return (0); /* got the secinfo */
}

/*
 * Get the security information per mount point.
 * Use the server pathname to get the secinfo.
 */
int
nfs4_secinfo_path(mntinfo4_t *mi, cred_t *cr, int isrecov)
{
	int error = 0;
	int ncomp;
	servinfo4_t *svp = mi->mi_curr_serv;

	/*
	 * Get the server pathname that is being mounted on.
	 */
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	ASSERT(svp->sv_path != NULL);

	/* returns 0 for root, no matter how many leading /'s */
	ncomp = comp_total(svp->sv_path);

	/*
	 * If mounting server rootdir, use available secinfo list
	 * on the client. No SECINFO call here since SECINFO op
	 * expects a component name.
	 */
	if (ncomp == 0) {
		if (svp->sv_secinfo == NULL) {
			nfs_rw_exit(&svp->sv_lock);
			secinfo_update(svp, secinfo_support);
			return (0);
		}
		nfs_rw_exit(&svp->sv_lock);

		if (secinfo_check(svp))
			return (0); /* try again */

		/* no flavors in sv_secinfo work */
		return (EACCES);
	}
	nfs_rw_exit(&svp->sv_lock);

	/*
	 * Get the secinfo from the server.
	 */
	error = nfs4secinfo_otw(mi, cr, svp, isrecov);

	if (error) {

		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
		if (svp->sv_secinfo) {
			if (svp->sv_save_secinfo == svp->sv_secinfo) {
				svp->sv_save_secinfo = NULL;
				svp->sv_savesec = NULL;
			}
			secinfo_free(svp->sv_secinfo);
			svp->sv_secinfo = NULL;
			svp->sv_currsec = NULL;
			svp->sv_flags &= ~SV4_TRYSECINFO;
		}

		if (svp->sv_save_secinfo) {
			secinfo_free(svp->sv_save_secinfo);
			svp->sv_save_secinfo = NULL;
			svp->sv_savesec = NULL;
		}
		nfs_rw_exit(&svp->sv_lock);
	}

	return (error);
}

/*
 * (secinfo) compound based on a given filehandle and component name.
 *
 * i.e. (secinfo) PUTFH (fh), SECINFO nm
 */
int
nfs4_secinfo_fh_otw(mntinfo4_t *mi, nfs4_sharedfh_t *fh, char *nm, cred_t *cr)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop[2];
	nfs_resop4 *resop;
	int num_argops, doqueue;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	servinfo4_t *svp;

	ASSERT(strlen(nm) > 0);

	num_argops = 2; /* Putfh, Secinfo nm */
	args.ctag = TAG_SECINFO;
	args.array_len = num_argops;
	args.array = argop;

	/* putfh fh */
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = fh;

	/* setup SECINFO op */
	argop[1].argop = OP_CSECINFO;
	argop[1].nfs_argop4_u.opcsecinfo.cname = nm;

	doqueue = 1;

	rfs4call(mi, &args, &res, cr, &doqueue, RFSCALL_SOFT, &e);

	if (e.error)
		return (e.error);

	if (res.status) {
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return (geterrno4(res.status));
	}

	/*
	 * Success! Now get the SECINFO result.
	 */
	resop = &res.array[1];	/* secinfo res */
	ASSERT(resop->resop == OP_SECINFO);

	if (resop->nfs_resop4_u.opsecinfo.SECINFO4resok_len == 0) {
		/*
		 * Server does not return any flavor for this export point.
		 * Return EACCES.
		 */
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return (EACCES);
	}

	secinfo_update(mi->mi_curr_serv, &resop->nfs_resop4_u.opsecinfo);

	svp = mi->mi_curr_serv;
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	if (mi->mi_curr_serv->sv_secinfo == NULL) {
		nfs_rw_exit(&svp->sv_lock);
		/*
		 * This could be because the server requires AUTH_DH, but
		 * the client does not have netname/syncaddr data
		 * from sv_dhsec.
		 */
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		return (EACCES);
	}
	nfs_rw_exit(&svp->sv_lock);

	/* Done! */
	xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	return (0); /* got the secinfo */
}

/*
 * Making secinfo operation with a given vnode.
 *
 * This routine is not used by the recovery thread.
 * Mainly used in response to NFS4ERR_WRONGSEC from lookup.
 */
int
nfs4_secinfo_vnode_otw(vnode_t *dvp, char *nm, cred_t *cr)
{
	ASSERT(strlen(nm) > 0);

	return (nfs4_secinfo_fh_otw(VTOMI4(dvp), VTOR4(dvp)->r_fh, nm, cr));
}

/*
 * Making secinfo operation with a given vnode if this vnode
 * has a parent node. If the given vnode is a root node, use
 * the pathname from the mntinfor4_t to do the secinfo call.
 *
 * This routine is mainly used by the recovery thread.
 */
int
nfs4_secinfo_vnode(vnode_t *vp, cred_t *cr, int isrecov)
{
	svnode_t *svp = VTOSV(vp);
	char *nm;
	int error = 0;

	/*
	 * If there is a parent filehandle, use it to get the secinfo,
	 * otherwise, use mntinfo4_t pathname to get the secinfo.
	 */
	if (svp->sv_dfh) {
		nm = fn_name(svp->sv_name); /* get the actual component name */
		error = nfs4_secinfo_fh_otw(VTOMI4(vp), svp->sv_dfh, nm, cr);
		kmem_free(nm, MAXNAMELEN);
	} else {
		error = nfs4_secinfo_path(VTOMI4(vp), cr, isrecov);
	}

	return (error);
}

/*
 * We are here because the client gets NFS4ERR_WRONGSEC.
 *
 * Get the security information from the server and indicate
 * a set of new security information is here to try.
 * Start with the server path that's mounted.
 */
int
nfs4_secinfo_recov(mntinfo4_t *mi, vnode_t *vp1, vnode_t *vp2)
{
	int error = 0;
	cred_t *cr, *lcr = NULL;
	servinfo4_t *svp = mi->mi_curr_serv;

	/*
	 * If the client explicitly specifies a preferred flavor to use
	 * and gets NFS4ERR_WRONGSEC back, there is no need to negotiate
	 * the flavor.
	 */
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	if (! (svp->sv_flags & SV4_TRYSECDEFAULT)) {
		error = geterrno4(NFS4ERR_WRONGSEC);
		nfs_rw_exit(&svp->sv_lock);
	} else {
		cr = crgetcred();

		if (svp->sv_secdata->uid != 0) {
			lcr = crdup(cr);
			(void) crsetugid(lcr, svp->sv_secdata->uid,
			    crgetgid(cr));
		}
		nfs_rw_exit(&svp->sv_lock);

		if (vp1 == NULL && vp2 == NULL) {
			error = nfs4_secinfo_path(mi, cr, TRUE);

			if (lcr && error == EACCES)
				error = nfs4_secinfo_path(mi, lcr, TRUE);
		} else if (vp1) {
			error = nfs4_secinfo_vnode(vp1, cr, TRUE);

			if (lcr && error == EACCES)
				error = nfs4_secinfo_vnode(vp1, lcr, TRUE);
		} /* else */
			/* ??? */

		crfree(cr);
		if (lcr != NULL)
			crfree(lcr);
	}

	mutex_enter(&mi->mi_lock);
	mi->mi_recovflags &= ~MI4R_NEED_SECINFO;
	mutex_exit(&mi->mi_lock);

	return (error);
}
