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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <smbsrv/smb_door.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_ktypes.h>

typedef struct smb_unshare {
	list_node_t	us_lnd;
	char		us_sharename[MAXNAMELEN];
} smb_unshare_t;

static kmem_cache_t	*smb_kshare_cache_share;
static kmem_cache_t	*smb_kshare_cache_unexport;
kmem_cache_t	*smb_kshare_cache_vfs;

static int smb_kshare_cmp(const void *, const void *);
static void smb_kshare_hold(const void *);
static boolean_t smb_kshare_rele(const void *);
static void smb_kshare_destroy(void *);
static char *smb_kshare_oemname(const char *);
static int smb_kshare_is_special(const char *);
static boolean_t smb_kshare_is_admin(const char *);
static smb_kshare_t *smb_kshare_decode(nvlist_t *);
static uint32_t smb_kshare_decode_bool(nvlist_t *, const char *, uint32_t);
static void smb_kshare_unexport_thread(smb_thread_t *, void *);
static int smb_kshare_export(smb_server_t *, smb_kshare_t *);
static int smb_kshare_unexport(smb_server_t *, const char *);
static int smb_kshare_export_trans(smb_server_t *, char *, char *, char *);
static void smb_kshare_csc_flags(smb_kshare_t *, const char *);

static boolean_t smb_export_isready(smb_server_t *);

#ifdef	_KERNEL
static int smb_kshare_chk_dsrv_status(int, smb_dr_ctx_t *);
#endif	/* _KERNEL */

static const smb_avl_nops_t smb_kshare_avlops = {
	smb_kshare_cmp,
	smb_kshare_hold,
	smb_kshare_rele,
	smb_kshare_destroy
};

#ifdef	_KERNEL
/*
 * This function is not MultiThread safe. The caller has to make sure only one
 * thread calls this function.
 */
door_handle_t
smb_kshare_door_init(int door_id)
{
	return (door_ki_lookup(door_id));
}

/*
 * This function is not MultiThread safe. The caller has to make sure only one
 * thread calls this function.
 */
void
smb_kshare_door_fini(door_handle_t dhdl)
{
	if (dhdl)
		door_ki_rele(dhdl);
}

/*
 * This is a special interface that will be utilized by ZFS to cause
 * a share to be added/removed
 *
 * arg is either a smb_share_t or share_name from userspace.
 * It will need to be copied into the kernel.   It is smb_share_t
 * for add operations and share_name for delete operations.
 */
int
smb_kshare_upcall(door_handle_t dhdl, void *arg, boolean_t add_share)
{
	door_arg_t	doorarg = { 0 };
	char		*buf = NULL;
	char		*str = NULL;
	int		error;
	int		rc;
	unsigned int	used;
	smb_dr_ctx_t	*dec_ctx;
	smb_dr_ctx_t	*enc_ctx;
	smb_share_t	*lmshare = NULL;
	int		opcode;

	opcode = (add_share) ? SMB_SHROP_ADD : SMB_SHROP_DELETE;

	buf = kmem_alloc(SMB_SHARE_DSIZE, KM_SLEEP);
	enc_ctx = smb_dr_encode_start(buf, SMB_SHARE_DSIZE);
	smb_dr_put_uint32(enc_ctx, opcode);

	switch (opcode) {
	case SMB_SHROP_ADD:
		lmshare = kmem_alloc(sizeof (smb_share_t), KM_SLEEP);
		error = xcopyin(arg, lmshare, sizeof (smb_share_t));
		if (error != 0) {
			kmem_free(lmshare, sizeof (smb_share_t));
			kmem_free(buf, SMB_SHARE_DSIZE);
			return (error);
		}
		smb_dr_put_share(enc_ctx, lmshare);
		break;

	case SMB_SHROP_DELETE:
		str = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		error = copyinstr(arg, str, MAXPATHLEN, NULL);
		if (error != 0) {
			kmem_free(str, MAXPATHLEN);
			kmem_free(buf, SMB_SHARE_DSIZE);
			return (error);
		}
		smb_dr_put_string(enc_ctx, str);
		kmem_free(str, MAXPATHLEN);
		break;
	}

	if ((error = smb_dr_encode_finish(enc_ctx, &used)) != 0) {
		kmem_free(buf, SMB_SHARE_DSIZE);
		if (lmshare)
			kmem_free(lmshare, sizeof (smb_share_t));
		return (NERR_InternalError);
	}

	doorarg.data_ptr = buf;
	doorarg.data_size = used;
	doorarg.rbuf = buf;
	doorarg.rsize = SMB_SHARE_DSIZE;

	error = door_ki_upcall_limited(dhdl, &doorarg, NULL, SIZE_MAX, 0);

	if (error) {
		kmem_free(buf, SMB_SHARE_DSIZE);
		if (lmshare)
			kmem_free(lmshare, sizeof (smb_share_t));
		return (error);
	}

	dec_ctx = smb_dr_decode_start(doorarg.data_ptr, doorarg.data_size);
	if (smb_kshare_chk_dsrv_status(opcode, dec_ctx) != 0) {
		kmem_free(buf, SMB_SHARE_DSIZE);
		if (lmshare)
			kmem_free(lmshare, sizeof (smb_share_t));
		return (NERR_InternalError);
	}

	rc = smb_dr_get_uint32(dec_ctx);
	if (opcode == SMB_SHROP_ADD)
		smb_dr_get_share(dec_ctx, lmshare);

	if (smb_dr_decode_finish(dec_ctx))
		rc = NERR_InternalError;

	kmem_free(buf, SMB_SHARE_DSIZE);
	if (lmshare)
		kmem_free(lmshare, sizeof (smb_share_t));

	return ((rc == NERR_DuplicateShare && add_share) ? 0 : rc);
}
#endif	/* _KERNEL */

/*
 * Executes map and unmap command for shares.
 */
int
smb_kshare_exec(smb_server_t *sv, smb_shr_execinfo_t *execinfo)
{
	int exec_rc = 0;

	(void) smb_kdoor_upcall(sv, SMB_DR_SHR_EXEC,
	    execinfo, smb_shr_execinfo_xdr, &exec_rc, xdr_int);

	return (exec_rc);
}

/*
 * Obtains any host access restriction on the specified
 * share for the given host (ipaddr) by calling smbd
 */
uint32_t
smb_kshare_hostaccess(smb_kshare_t *shr, smb_session_t *session)
{
	smb_shr_hostaccess_query_t req;
	smb_inaddr_t *ipaddr = &session->ipaddr;
	uint32_t host_access = SMB_SHRF_ACC_OPEN;
	uint32_t flag = SMB_SHRF_ACC_OPEN;
	uint32_t access;

	if (smb_inet_iszero(ipaddr))
		return (ACE_ALL_PERMS);

	if ((shr->shr_access_none == NULL || *shr->shr_access_none == '\0') &&
	    (shr->shr_access_ro == NULL || *shr->shr_access_ro == '\0') &&
	    (shr->shr_access_rw == NULL || *shr->shr_access_rw == '\0'))
		return (ACE_ALL_PERMS);

	if (shr->shr_access_none != NULL)
		flag |= SMB_SHRF_ACC_NONE;
	if (shr->shr_access_ro != NULL)
		flag |= SMB_SHRF_ACC_RO;
	if (shr->shr_access_rw != NULL)
		flag |= SMB_SHRF_ACC_RW;

	req.shq_none = shr->shr_access_none;
	req.shq_ro = shr->shr_access_ro;
	req.shq_rw = shr->shr_access_rw;
	req.shq_flag = flag;
	req.shq_ipaddr = *ipaddr;

	(void) smb_kdoor_upcall(session->s_server, SMB_DR_SHR_HOSTACCESS,
	    &req, smb_shr_hostaccess_query_xdr, &host_access, xdr_uint32_t);

	switch (host_access) {
	case SMB_SHRF_ACC_RO:
		access = ACE_ALL_PERMS & ~ACE_ALL_WRITE_PERMS;
		break;
	case SMB_SHRF_ACC_OPEN:
	case SMB_SHRF_ACC_RW:
		access = ACE_ALL_PERMS;
		break;
	case SMB_SHRF_ACC_NONE:
	default:
		access = 0;
	}

	return (access);
}

/*
 * This function is called when smb_server_t is
 * created which means smb/service is ready for
 * exporting SMB shares
 */
void
smb_export_start(smb_server_t *sv)
{
	mutex_enter(&sv->sv_export.e_mutex);
	if (sv->sv_export.e_ready) {
		mutex_exit(&sv->sv_export.e_mutex);
		return;
	}

	sv->sv_export.e_ready = B_TRUE;
	mutex_exit(&sv->sv_export.e_mutex);

	smb_avl_create(&sv->sv_export.e_share_avl, sizeof (smb_kshare_t),
	    offsetof(smb_kshare_t, shr_link), &smb_kshare_avlops);

	(void) smb_kshare_export_trans(sv, "IPC$", "IPC$", "Remote IPC");
	(void) smb_kshare_export_trans(sv, "c$", SMB_CVOL, "Default Share");
	(void) smb_kshare_export_trans(sv, "vss$", SMB_VSS, "VSS");
}

/*
 * This function is called when smb_server_t goes
 * away which means SMB shares should not be made
 * available to clients
 */
void
smb_export_stop(smb_server_t *sv)
{
	mutex_enter(&sv->sv_export.e_mutex);
	if (!sv->sv_export.e_ready) {
		mutex_exit(&sv->sv_export.e_mutex);
		return;
	}
	sv->sv_export.e_ready = B_FALSE;
	mutex_exit(&sv->sv_export.e_mutex);

	smb_avl_destroy(&sv->sv_export.e_share_avl);
	smb_vfs_rele_all(&sv->sv_export);
}

void
smb_kshare_g_init(void)
{
	smb_kshare_cache_share = kmem_cache_create("smb_share_cache",
	    sizeof (smb_kshare_t), 8, NULL, NULL, NULL, NULL, NULL, 0);

	smb_kshare_cache_unexport = kmem_cache_create("smb_unexport_cache",
	    sizeof (smb_unshare_t), 8, NULL, NULL, NULL, NULL, NULL, 0);

	smb_kshare_cache_vfs = kmem_cache_create("smb_vfs_cache",
	    sizeof (smb_vfs_t), 8, NULL, NULL, NULL, NULL, NULL, 0);
}

void
smb_kshare_init(smb_server_t *sv)
{

	smb_llist_constructor(&sv->sv_export.e_vfs_list, sizeof (smb_vfs_t),
	    offsetof(smb_vfs_t, sv_lnd));

	smb_slist_constructor(&sv->sv_export.e_unexport_list,
	    sizeof (smb_unshare_t), offsetof(smb_unshare_t, us_lnd));
}

int
smb_kshare_start(smb_server_t *sv)
{
	smb_thread_init(&sv->sv_export.e_unexport_thread, "smb_kshare_unexport",
	    smb_kshare_unexport_thread, sv, smbsrv_base_pri);

	return (smb_thread_start(&sv->sv_export.e_unexport_thread));
}

void
smb_kshare_stop(smb_server_t *sv)
{
	smb_thread_stop(&sv->sv_export.e_unexport_thread);
	smb_thread_destroy(&sv->sv_export.e_unexport_thread);
}

void
smb_kshare_fini(smb_server_t *sv)
{
	smb_unshare_t *ux;

	while ((ux = list_head(&sv->sv_export.e_unexport_list.sl_list))
	    != NULL) {
		smb_slist_remove(&sv->sv_export.e_unexport_list, ux);
		kmem_cache_free(smb_kshare_cache_unexport, ux);
	}
	smb_slist_destructor(&sv->sv_export.e_unexport_list);

	smb_vfs_rele_all(&sv->sv_export);

	smb_llist_destructor(&sv->sv_export.e_vfs_list);
}

void
smb_kshare_g_fini(void)
{
	kmem_cache_destroy(smb_kshare_cache_unexport);
	kmem_cache_destroy(smb_kshare_cache_share);
	kmem_cache_destroy(smb_kshare_cache_vfs);
}

/*
 * A list of shares in nvlist format can be sent down
 * from userspace thourgh the IOCTL interface. The nvlist
 * is unpacked here and all the shares in the list will
 * be exported.
 */
int
smb_kshare_export_list(smb_ioc_share_t *ioc)
{
	smb_server_t	*sv = NULL;
	nvlist_t	*shrlist = NULL;
	nvlist_t	 *share;
	nvpair_t	 *nvp;
	smb_kshare_t	 *shr;
	char		*shrname;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	if (!smb_export_isready(sv)) {
		rc = ENOTACTIVE;
		goto out;
	}

	rc = nvlist_unpack(ioc->shr, ioc->shrlen, &shrlist, KM_SLEEP);
	if (rc != 0)
		goto out;

	for (nvp = nvlist_next_nvpair(shrlist, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(shrlist, nvp)) {

		/*
		 * Since this loop can run for a while we want to exit
		 * as soon as the server state is anything but RUNNING
		 * to allow shutdown to proceed.
		 */
		if (sv->sv_state != SMB_SERVER_STATE_RUNNING)
			goto out;

		if (nvpair_type(nvp) != DATA_TYPE_NVLIST)
			continue;

		shrname = nvpair_name(nvp);
		ASSERT(shrname);

		if ((rc = nvpair_value_nvlist(nvp, &share)) != 0) {
			cmn_err(CE_WARN, "export[%s]: failed accessing",
			    shrname);
			continue;
		}

		if ((shr = smb_kshare_decode(share)) == NULL) {
			cmn_err(CE_WARN, "export[%s]: failed decoding",
			    shrname);
			continue;
		}

		/* smb_kshare_export consumes shr so it's not leaked */
		if ((rc = smb_kshare_export(sv, shr)) != 0) {
			smb_kshare_destroy(shr);
			continue;
		}
	}
	rc = 0;

out:
	nvlist_free(shrlist);
	smb_server_release(sv);
	return (rc);
}

/*
 * This function is invoked when a share is disabled to disconnect trees
 * and close files.  Cleaning up may involve VOP and/or VFS calls, which
 * may conflict/deadlock with stuck threads if something is amiss with the
 * file system.  Queueing the request for asynchronous processing allows the
 * call to return immediately so that, if the unshare is being done in the
 * context of a forced unmount, the forced unmount will always be able to
 * proceed (unblocking stuck I/O and eventually allowing all blocked unshare
 * processes to complete).
 *
 * The path lookup to find the root vnode of the VFS in question and the
 * release of this vnode are done synchronously prior to any associated
 * unmount.  Doing these asynchronous to an associated unmount could run
 * the risk of a spurious EBUSY for a standard unmount or an EIO during
 * the path lookup due to a forced unmount finishing first.
 */
int
smb_kshare_unexport_list(smb_ioc_share_t *ioc)
{
	smb_server_t	*sv = NULL;
	smb_unshare_t	*ux;
	nvlist_t	*shrlist = NULL;
	nvpair_t	*nvp;
	boolean_t	unexport = B_FALSE;
	char		*shrname;
	int		rc;

	if ((rc = smb_server_lookup(&sv)) != 0)
		return (rc);

	if ((rc = nvlist_unpack(ioc->shr, ioc->shrlen, &shrlist, 0)) != 0)
		goto out;

	for (nvp = nvlist_next_nvpair(shrlist, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(shrlist, nvp)) {
		if (nvpair_type(nvp) != DATA_TYPE_NVLIST)
			continue;

		shrname = nvpair_name(nvp);
		ASSERT(shrname);

		if ((rc = smb_kshare_unexport(sv, shrname)) != 0)
			continue;

		ux = kmem_cache_alloc(smb_kshare_cache_unexport, KM_SLEEP);
		(void) strlcpy(ux->us_sharename, shrname, MAXNAMELEN);

		smb_slist_insert_tail(&sv->sv_export.e_unexport_list, ux);
		unexport = B_TRUE;
	}

	if (unexport)
		smb_thread_signal(&sv->sv_export.e_unexport_thread);
	rc = 0;

out:
	nvlist_free(shrlist);
	smb_server_release(sv);
	return (rc);
}

/*
 * Get properties (currently only shortname enablement)
 * of specified share.
 */
int
smb_kshare_info(smb_ioc_shareinfo_t *ioc)
{
	ioc->shortnames = smb_shortnames;
	return (0);
}

/*
 * This function builds a response for a NetShareEnum RAP request.
 * List of shares is scanned twice. In the first round the total number
 * of shares which their OEM name is shorter than 13 chars (esi->es_ntotal)
 * and also the number of shares that fit in the given buffer are calculated.
 * In the second round the shares data are encoded in the buffer.
 *
 * The data associated with each share has two parts, a fixed size part and
 * a variable size part which is share's comment. The outline of the response
 * buffer is so that fixed part for all the shares will appear first and follows
 * with the comments for all those shares and that's why the data cannot be
 * encoded in one round without unnecessarily complicating the code.
 */
void
smb_kshare_enum(smb_server_t *sv, smb_enumshare_info_t *esi)
{
	smb_avl_t *share_avl;
	smb_avl_cursor_t cursor;
	smb_kshare_t *shr;
	int remained;
	uint16_t infolen = 0;
	uint16_t cmntlen = 0;
	uint16_t sharelen;
	uint16_t clen;
	uint32_t cmnt_offs;
	smb_msgbuf_t info_mb;
	smb_msgbuf_t cmnt_mb;
	boolean_t autohome_added = B_FALSE;

	if (!smb_export_isready(sv)) {
		esi->es_ntotal = esi->es_nsent = 0;
		esi->es_datasize = 0;
		return;
	}

	esi->es_ntotal = esi->es_nsent = 0;
	remained = esi->es_bufsize;
	share_avl = &sv->sv_export.e_share_avl;

	/* Do the necessary calculations in the first round */
	smb_avl_iterinit(share_avl, &cursor);

	while ((shr = smb_avl_iterate(share_avl, &cursor)) != NULL) {
		if (shr->shr_oemname == NULL) {
			smb_avl_release(share_avl, shr);
			continue;
		}

		if ((shr->shr_flags & SMB_SHRF_AUTOHOME) && !autohome_added) {
			if (esi->es_posix_uid == shr->shr_uid) {
				autohome_added = B_TRUE;
			} else {
				smb_avl_release(share_avl, shr);
				continue;
			}
		}

		esi->es_ntotal++;

		if (remained <= 0) {
			smb_avl_release(share_avl, shr);
			continue;
		}

		clen = strlen(shr->shr_cmnt) + 1;
		sharelen = SHARE_INFO_1_SIZE + clen;

		if (sharelen <= remained) {
			infolen += SHARE_INFO_1_SIZE;
			cmntlen += clen;
		}

		remained -= sharelen;
		smb_avl_release(share_avl, shr);
	}

	esi->es_datasize = infolen + cmntlen;

	smb_msgbuf_init(&info_mb, (uint8_t *)esi->es_buf, infolen, 0);
	smb_msgbuf_init(&cmnt_mb, (uint8_t *)esi->es_buf + infolen, cmntlen, 0);
	cmnt_offs = infolen;

	/* Encode the data in the second round */
	smb_avl_iterinit(share_avl, &cursor);
	autohome_added = B_FALSE;

	while ((shr = smb_avl_iterate(share_avl, &cursor)) != NULL) {
		if (shr->shr_oemname == NULL) {
			smb_avl_release(share_avl, shr);
			continue;
		}

		if ((shr->shr_flags & SMB_SHRF_AUTOHOME) && !autohome_added) {
			if (esi->es_posix_uid == shr->shr_uid) {
				autohome_added = B_TRUE;
			} else {
				smb_avl_release(share_avl, shr);
				continue;
			}
		}

		if (smb_msgbuf_encode(&info_mb, "13c.wl",
		    shr->shr_oemname, shr->shr_type, cmnt_offs) < 0) {
			smb_avl_release(share_avl, shr);
			break;
		}

		if (smb_msgbuf_encode(&cmnt_mb, "s", shr->shr_cmnt) < 0) {
			smb_avl_release(share_avl, shr);
			break;
		}

		cmnt_offs += strlen(shr->shr_cmnt) + 1;
		esi->es_nsent++;

		smb_avl_release(share_avl, shr);
	}

	smb_msgbuf_term(&info_mb);
	smb_msgbuf_term(&cmnt_mb);
}

/*
 * Looks up the given share and returns a pointer
 * to its definition if it's found. A hold on the
 * object is taken before the pointer is returned
 * in which case the caller MUST always call
 * smb_kshare_release().
 */
smb_kshare_t *
smb_kshare_lookup(smb_server_t *sv, const char *shrname)
{
	smb_kshare_t key;
	smb_kshare_t *shr;

	ASSERT(shrname);

	if (!smb_export_isready(sv))
		return (NULL);

	key.shr_name = (char *)shrname;
	shr = smb_avl_lookup(&sv->sv_export.e_share_avl, &key);
	return (shr);
}

/*
 * Releases the hold taken on the specified share object
 */
void
smb_kshare_release(smb_server_t *sv, smb_kshare_t *shr)
{
	ASSERT(shr);
	ASSERT(shr->shr_magic == SMB_SHARE_MAGIC);

	smb_avl_release(&sv->sv_export.e_share_avl, shr);
}

/*
 * Add the given share in the specified server.
 * If the share is a disk share, smb_vfs_hold() is
 * invoked to ensure that there is a hold on the
 * corresponding file system before the share is
 * added to shares AVL.
 *
 * If the share is an Autohome share and it is
 * already in the AVL only a reference count for
 * that share is incremented.
 */
static int
smb_kshare_export(smb_server_t *sv, smb_kshare_t *shr)
{
	smb_avl_t	*share_avl;
	smb_kshare_t	*auto_shr;
	vnode_t		*vp;
	int		rc = 0;

	share_avl = &sv->sv_export.e_share_avl;

	if (!STYPE_ISDSK(shr->shr_type)) {
		if ((rc = smb_avl_add(share_avl, shr)) != 0) {
			cmn_err(CE_WARN, "export[%s]: failed caching (%d)",
			    shr->shr_name, rc);
		}

		return (rc);
	}

	if ((auto_shr = smb_avl_lookup(share_avl, shr)) != NULL) {
		if ((auto_shr->shr_flags & SMB_SHRF_AUTOHOME) == 0) {
			smb_avl_release(share_avl, auto_shr);
			return (EEXIST);
		}

		mutex_enter(&auto_shr->shr_mutex);
		auto_shr->shr_autocnt++;
		mutex_exit(&auto_shr->shr_mutex);
		smb_avl_release(share_avl, auto_shr);
		return (0);
	}

	if ((rc = smb_server_sharevp(sv, shr->shr_path, &vp)) != 0) {
		cmn_err(CE_WARN, "export[%s(%s)]: failed obtaining vnode (%d)",
		    shr->shr_name, shr->shr_path, rc);
		return (rc);
	}

	if ((rc = smb_vfs_hold(&sv->sv_export, vp->v_vfsp)) == 0) {
		if ((rc = smb_avl_add(share_avl, shr)) != 0) {
			cmn_err(CE_WARN, "export[%s]: failed caching (%d)",
			    shr->shr_name, rc);
			smb_vfs_rele(&sv->sv_export, vp->v_vfsp);
		}
	} else {
		cmn_err(CE_WARN, "export[%s(%s)]: failed holding VFS (%d)",
		    shr->shr_name, shr->shr_path, rc);
	}

	VN_RELE(vp);
	return (rc);
}

/*
 * Removes the share specified by 'shrname' from the AVL
 * tree of the given server if it's there.
 *
 * If the share is an Autohome share, the autohome count
 * is decremented and the share is only removed if the
 * count goes to zero.
 *
 * If the share is a disk share, the hold on the corresponding
 * file system is released before removing the share from
 * the AVL tree.
 */
static int
smb_kshare_unexport(smb_server_t *sv, const char *shrname)
{
	smb_avl_t	*share_avl;
	smb_kshare_t	key;
	smb_kshare_t	*shr;
	vnode_t		*vp;
	int		rc;
	boolean_t	auto_unexport;

	share_avl = &sv->sv_export.e_share_avl;

	key.shr_name = (char *)shrname;
	if ((shr = smb_avl_lookup(share_avl, &key)) == NULL)
		return (ENOENT);

	if ((shr->shr_flags & SMB_SHRF_AUTOHOME) != 0) {
		mutex_enter(&shr->shr_mutex);
		shr->shr_autocnt--;
		auto_unexport = (shr->shr_autocnt == 0);
		mutex_exit(&shr->shr_mutex);
		if (!auto_unexport) {
			smb_avl_release(share_avl, shr);
			return (0);
		}
	}

	if (STYPE_ISDSK(shr->shr_type)) {
		if ((rc = smb_server_sharevp(sv, shr->shr_path, &vp)) != 0) {
			smb_avl_release(share_avl, shr);
			cmn_err(CE_WARN, "unexport[%s]: failed obtaining vnode"
			    " (%d)", shrname, rc);
			return (rc);
		}

		smb_vfs_rele(&sv->sv_export, vp->v_vfsp);
		VN_RELE(vp);
	}

	smb_avl_remove(share_avl, shr);
	smb_avl_release(share_avl, shr);

	return (0);
}

/*
 * Exports IPC$ or Admin shares
 */
static int
smb_kshare_export_trans(smb_server_t *sv, char *name, char *path, char *cmnt)
{
	smb_kshare_t *shr;

	ASSERT(name);
	ASSERT(path);

	shr = kmem_cache_alloc(smb_kshare_cache_share, KM_SLEEP);
	bzero(shr, sizeof (smb_kshare_t));

	shr->shr_magic = SMB_SHARE_MAGIC;
	shr->shr_refcnt = 1;
	shr->shr_flags = SMB_SHRF_TRANS | smb_kshare_is_admin(shr->shr_name);
	if (strcasecmp(name, "IPC$") == 0)
		shr->shr_type = STYPE_IPC;
	else
		shr->shr_type = STYPE_DISKTREE;

	shr->shr_type |= smb_kshare_is_special(shr->shr_name);

	shr->shr_name = smb_mem_strdup(name);
	if (path)
		shr->shr_path = smb_mem_strdup(path);
	if (cmnt)
		shr->shr_cmnt = smb_mem_strdup(cmnt);
	shr->shr_oemname = smb_kshare_oemname(name);

	return (smb_kshare_export(sv, shr));
}

/*
 * Decodes share information in an nvlist format into a smb_kshare_t
 * structure.
 *
 * This is a temporary function and will be replaced by functions
 * provided by libsharev2 code after it's available.
 */
static smb_kshare_t *
smb_kshare_decode(nvlist_t *share)
{
	smb_kshare_t tmp;
	smb_kshare_t *shr;
	nvlist_t *smb;
	char *csc_name = NULL;
	int rc;

	ASSERT(share);

	bzero(&tmp, sizeof (smb_kshare_t));

	rc = nvlist_lookup_string(share, "name", &tmp.shr_name);
	rc |= nvlist_lookup_string(share, "path", &tmp.shr_path);
	(void) nvlist_lookup_string(share, "desc", &tmp.shr_cmnt);

	ASSERT(tmp.shr_name && tmp.shr_path);

	rc |= nvlist_lookup_nvlist(share, "smb", &smb);
	if (rc != 0) {
		cmn_err(CE_WARN, "kshare: failed looking up SMB properties"
		    " (%d)", rc);
		return (NULL);
	}

	rc = nvlist_lookup_uint32(smb, "type", &tmp.shr_type);
	if (rc != 0) {
		cmn_err(CE_WARN, "kshare[%s]: failed getting the share type"
		    " (%d)", tmp.shr_name, rc);
		return (NULL);
	}

	(void) nvlist_lookup_string(smb, SHOPT_AD_CONTAINER,
	    &tmp.shr_container);
	(void) nvlist_lookup_string(smb, SHOPT_NONE, &tmp.shr_access_none);
	(void) nvlist_lookup_string(smb, SHOPT_RO, &tmp.shr_access_ro);
	(void) nvlist_lookup_string(smb, SHOPT_RW, &tmp.shr_access_rw);

	tmp.shr_flags |= smb_kshare_decode_bool(smb, SHOPT_ABE, SMB_SHRF_ABE);
	tmp.shr_flags |= smb_kshare_decode_bool(smb, SHOPT_CATIA,
	    SMB_SHRF_CATIA);
	tmp.shr_flags |= smb_kshare_decode_bool(smb, SHOPT_GUEST,
	    SMB_SHRF_GUEST_OK);
	tmp.shr_flags |= smb_kshare_decode_bool(smb, SHOPT_DFSROOT,
	    SMB_SHRF_DFSROOT);
	tmp.shr_flags |= smb_kshare_decode_bool(smb, "Autohome",
	    SMB_SHRF_AUTOHOME);

	if ((tmp.shr_flags & SMB_SHRF_AUTOHOME) == SMB_SHRF_AUTOHOME) {
		rc = nvlist_lookup_uint32(smb, "uid", &tmp.shr_uid);
		rc |= nvlist_lookup_uint32(smb, "gid", &tmp.shr_gid);
		if (rc != 0) {
			cmn_err(CE_WARN, "kshare: failed looking up uid/gid"
			    " (%d)", rc);
			return (NULL);
		}
	}

	(void) nvlist_lookup_string(smb, SHOPT_CSC, &csc_name);
	smb_kshare_csc_flags(&tmp, csc_name);

	shr = kmem_cache_alloc(smb_kshare_cache_share, KM_SLEEP);
	bzero(shr, sizeof (smb_kshare_t));

	shr->shr_magic = SMB_SHARE_MAGIC;
	shr->shr_refcnt = 1;

	shr->shr_name = smb_mem_strdup(tmp.shr_name);
	shr->shr_path = smb_mem_strdup(tmp.shr_path);
	if (tmp.shr_cmnt)
		shr->shr_cmnt = smb_mem_strdup(tmp.shr_cmnt);
	if (tmp.shr_container)
		shr->shr_container = smb_mem_strdup(tmp.shr_container);
	if (tmp.shr_access_none)
		shr->shr_access_none = smb_mem_strdup(tmp.shr_access_none);
	if (tmp.shr_access_ro)
		shr->shr_access_ro = smb_mem_strdup(tmp.shr_access_ro);
	if (tmp.shr_access_rw)
		shr->shr_access_rw = smb_mem_strdup(tmp.shr_access_rw);

	shr->shr_oemname = smb_kshare_oemname(shr->shr_name);
	shr->shr_flags = tmp.shr_flags | smb_kshare_is_admin(shr->shr_name);
	shr->shr_type = tmp.shr_type | smb_kshare_is_special(shr->shr_name);

	shr->shr_uid = tmp.shr_uid;
	shr->shr_gid = tmp.shr_gid;

	if ((shr->shr_flags & SMB_SHRF_AUTOHOME) == SMB_SHRF_AUTOHOME)
		shr->shr_autocnt = 1;

	return (shr);
}

#if 0
static void
smb_kshare_log(smb_kshare_t *shr)
{
	cmn_err(CE_NOTE, "Share info:");
	cmn_err(CE_NOTE, "\tname: %s", (shr->shr_name) ? shr->shr_name : "");
	cmn_err(CE_NOTE, "\tpath: %s", (shr->shr_path) ? shr->shr_path : "");
	cmn_err(CE_NOTE, "\tcmnt: (%s)",
	    (shr->shr_cmnt) ? shr->shr_cmnt : "NULL");
	cmn_err(CE_NOTE, "\toemname: (%s)",
	    (shr->shr_oemname) ? shr->shr_oemname : "NULL");
	cmn_err(CE_NOTE, "\tflags: %X", shr->shr_flags);
	cmn_err(CE_NOTE, "\ttype: %d", shr->shr_type);
}
#endif

/*
 * Compare function used by shares AVL
 */
static int
smb_kshare_cmp(const void *p1, const void *p2)
{
	smb_kshare_t *shr1 = (smb_kshare_t *)p1;
	smb_kshare_t *shr2 = (smb_kshare_t *)p2;
	int rc;

	ASSERT(shr1);
	ASSERT(shr1->shr_name);

	ASSERT(shr2);
	ASSERT(shr2->shr_name);

	rc = smb_strcasecmp(shr1->shr_name, shr2->shr_name, 0);

	if (rc < 0)
		return (-1);

	if (rc > 0)
		return (1);

	return (0);
}

/*
 * This function is called by smb_avl routines whenever
 * there is a need to take a hold on a share structure
 * inside AVL
 */
static void
smb_kshare_hold(const void *p)
{
	smb_kshare_t *shr = (smb_kshare_t *)p;

	ASSERT(shr);
	ASSERT(shr->shr_magic == SMB_SHARE_MAGIC);

	mutex_enter(&shr->shr_mutex);
	shr->shr_refcnt++;
	mutex_exit(&shr->shr_mutex);
}

/*
 * This function must be called by smb_avl routines whenever
 * smb_kshare_hold is called and the hold needs to be released.
 */
static boolean_t
smb_kshare_rele(const void *p)
{
	smb_kshare_t *shr = (smb_kshare_t *)p;
	boolean_t destroy;

	ASSERT(shr);
	ASSERT(shr->shr_magic == SMB_SHARE_MAGIC);

	mutex_enter(&shr->shr_mutex);
	ASSERT(shr->shr_refcnt > 0);
	shr->shr_refcnt--;
	destroy = (shr->shr_refcnt == 0);
	mutex_exit(&shr->shr_mutex);

	return (destroy);
}

/*
 * Frees all the memory allocated for the given
 * share structure. It also removes the structure
 * from the share cache.
 */
static void
smb_kshare_destroy(void *p)
{
	smb_kshare_t *shr = (smb_kshare_t *)p;

	ASSERT(shr);
	ASSERT(shr->shr_magic == SMB_SHARE_MAGIC);

	smb_mem_free(shr->shr_name);
	smb_mem_free(shr->shr_path);
	smb_mem_free(shr->shr_cmnt);
	smb_mem_free(shr->shr_container);
	smb_mem_free(shr->shr_oemname);
	smb_mem_free(shr->shr_access_none);
	smb_mem_free(shr->shr_access_ro);
	smb_mem_free(shr->shr_access_rw);

	kmem_cache_free(smb_kshare_cache_share, shr);
}


/*
 * Generate an OEM name for the given share name.  If the name is
 * shorter than 13 bytes the oemname will be returned; otherwise NULL
 * is returned.
 */
static char *
smb_kshare_oemname(const char *shrname)
{
	smb_wchar_t *unibuf;
	char *oem_name;
	int length;

	length = strlen(shrname) + 1;

	oem_name = smb_mem_alloc(length);
	unibuf = smb_mem_alloc(length * sizeof (smb_wchar_t));

	(void) smb_mbstowcs(unibuf, shrname, length);

	if (ucstooem(oem_name, unibuf, length, OEM_CPG_850) == 0)
		(void) strcpy(oem_name, shrname);

	smb_mem_free(unibuf);

	if (strlen(oem_name) + 1 > SMB_SHARE_OEMNAME_MAX) {
		smb_mem_free(oem_name);
		return (NULL);
	}

	return (oem_name);
}

/*
 * Special share reserved for interprocess communication (IPC$) or
 * remote administration of the server (ADMIN$). Can also refer to
 * administrative shares such as C$, D$, E$, and so forth.
 */
static int
smb_kshare_is_special(const char *sharename)
{
	int len;

	if (sharename == NULL)
		return (0);

	if ((len = strlen(sharename)) == 0)
		return (0);

	if (sharename[len - 1] == '$')
		return (STYPE_SPECIAL);

	return (0);
}

/*
 * Check whether or not this is a default admin share: C$, D$ etc.
 */
static boolean_t
smb_kshare_is_admin(const char *sharename)
{
	if (sharename == NULL)
		return (B_FALSE);

	if (strlen(sharename) == 2 &&
	    smb_isalpha(sharename[0]) && sharename[1] == '$') {
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Decodes the given boolean share option.
 * If the option is present in the nvlist and it's value is true
 * returns the corresponding flag value, otherwise returns 0.
 */
static uint32_t
smb_kshare_decode_bool(nvlist_t *nvl, const char *propname, uint32_t flag)
{
	char *boolp;

	if (nvlist_lookup_string(nvl, propname, &boolp) == 0)
		if (strcasecmp(boolp, "true") == 0)
			return (flag);

	return (0);
}

/*
 * Map a client-side caching (CSC) option to the appropriate share
 * flag.  Only one option is allowed; an error will be logged if
 * multiple options have been specified.  We don't need to do anything
 * about multiple values here because the SRVSVC will not recognize
 * a value containing multiple flags and will return the default value.
 *
 * If the option value is not recognized, it will be ignored: invalid
 * values will typically be caught and rejected by sharemgr.
 */
static void
smb_kshare_csc_flags(smb_kshare_t *shr, const char *value)
{
	int i;
	static struct {
		char *value;
		uint32_t flag;
	} cscopt[] = {
		{ "disabled",	SMB_SHRF_CSC_DISABLED },
		{ "manual",	SMB_SHRF_CSC_MANUAL },
		{ "auto",	SMB_SHRF_CSC_AUTO },
		{ "vdo",	SMB_SHRF_CSC_VDO }
	};

	if (value == NULL)
		return;

	for (i = 0; i < (sizeof (cscopt) / sizeof (cscopt[0])); ++i) {
		if (strcasecmp(value, cscopt[i].value) == 0) {
			shr->shr_flags |= cscopt[i].flag;
			break;
		}
	}

	switch (shr->shr_flags & SMB_SHRF_CSC_MASK) {
	case 0:
	case SMB_SHRF_CSC_DISABLED:
	case SMB_SHRF_CSC_MANUAL:
	case SMB_SHRF_CSC_AUTO:
	case SMB_SHRF_CSC_VDO:
		break;

	default:
		cmn_err(CE_NOTE, "csc option conflict: 0x%08x",
		    shr->shr_flags & SMB_SHRF_CSC_MASK);
		break;
	}
}

/*
 * This function processes the unexport event list and disconnects shares
 * asynchronously.  The function executes as a zone-specific thread.
 *
 * The server arg passed in is safe to use without a reference count, because
 * the server cannot be deleted until smb_thread_stop()/destroy() return,
 * which is also when the thread exits.
 */
/*ARGSUSED*/
static void
smb_kshare_unexport_thread(smb_thread_t *thread, void *arg)
{
	smb_server_t	*sv = arg;
	smb_unshare_t	*ux;

	while (smb_thread_continue(thread)) {
		while ((ux = list_head(&sv->sv_export.e_unexport_list.sl_list))
		    != NULL) {
			smb_slist_remove(&sv->sv_export.e_unexport_list, ux);
			(void) smb_server_unshare(ux->us_sharename);
			kmem_cache_free(smb_kshare_cache_unexport, ux);
		}
	}
}

static boolean_t
smb_export_isready(smb_server_t *sv)
{
	boolean_t ready;

	mutex_enter(&sv->sv_export.e_mutex);
	ready = sv->sv_export.e_ready;
	mutex_exit(&sv->sv_export.e_mutex);

	return (ready);
}

#ifdef	_KERNEL
/*
 * Return 0 upon success. Otherwise > 0
 */
static int
smb_kshare_chk_dsrv_status(int opcode, smb_dr_ctx_t *dec_ctx)
{
	int status = smb_dr_get_int32(dec_ctx);
	int err;

	switch (status) {
	case SMB_SHARE_DSUCCESS:
		return (0);

	case SMB_SHARE_DERROR:
		err = smb_dr_get_uint32(dec_ctx);
		cmn_err(CE_WARN, "%d: Encountered door server error %d",
		    opcode, err);
		(void) smb_dr_decode_finish(dec_ctx);
		return (err);
	}

	ASSERT(0);
	return (EINVAL);
}
#endif	/* _KERNEL */
