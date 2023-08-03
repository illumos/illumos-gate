/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017-2022 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2021-2023 RackTop Systems, Inc.
 */

/*
 * SMB2 Durable Handle support
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/fcntl.h>
#include <sys/nbmlock.h>
#include <sys/sid.h>
#include <smbsrv/string.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb2_kproto.h>

/* Windows default values from [MS-SMB2] */
/*
 * (times in seconds)
 * resilient:
 * MaxTimeout = 300 (win7+)
 * if timeout > MaxTimeout, ERROR
 * if timeout != 0, timeout = req.timeout
 * if timeout == 0, timeout = (infinity) (Win7/w2k8r2)
 * if timeout == 0, timeout = 120 (Win8+)
 * v2:
 * if timeout != 0, timeout = MIN(timeout, 300) (spec)
 * if timeout != 0, timeout = timeout (win8/2k12)
 * if timeout == 0, timeout = Share.CATimeout. \
 *	if Share.CATimeout == 0, timeout = 60 (win8/w2k12)
 * if timeout == 0, timeout = 180 (win8.1/w2k12r2)
 * open.timeout = 60 (win8/w2k12r2) (i.e. we ignore the request)
 * v1:
 * open.timeout = 16 minutes
 */

uint32_t smb2_dh_def_timeout = 60 * MILLISEC;	/* mSec. */
uint32_t smb2_dh_max_timeout = 300 * MILLISEC;	/* mSec. */

uint32_t smb2_res_def_timeout = 120 * MILLISEC;	/* mSec. */
uint32_t smb2_res_max_timeout = 300 * MILLISEC;	/* mSec. */

uint32_t smb2_persist_timeout = 300 * MILLISEC;	/* mSec. */

/*
 * Max. size of the file used to store a CA handle.
 * Don't adjust this while the server is running.
 */
static uint32_t smb2_dh_max_cah_size = 64 * 1024;
static uint32_t smb2_ca_info_version = 1;

/*
 * Want this to have invariant layout on disk, where the
 * last two uint32_t values are stored as a uint64_t
 */
struct nvlk {
	uint64_t lk_start;
	uint64_t lk_len;
	/* (lk_pid << 32) | lk_type */
#ifdef	_BIG_ENDIAN
	uint32_t lk_pid, lk_type;
#else
	uint32_t lk_type, lk_pid;
#endif
};

static void smb2_dh_import_share(void *);
static smb_ofile_t *smb2_dh_import_handle(smb_request_t *, smb_node_t *,
    char *, uint64_t);
static int smb2_dh_read_nvlist(smb_request_t *, smb_node_t *,
    char *, struct nvlist **);
static int smb2_dh_import_cred(smb_ofile_t *, char *);

#define	DH_SN_SIZE 24	/* size of DH stream name buffers */
/*
 * Build the stream name used to store a CA handle.
 * i.e. ":0123456789abcdef:$CA"
 * Note: smb_fsop_create adds the SUNWsmb prefix,
 * so we compose the name without the prefix.
 */
static inline void
smb2_dh_make_stream_name(char *buf, size_t buflen, uint64_t id)
{
	ASSERT(buflen >= DH_SN_SIZE);
	(void) snprintf(buf, buflen,
	    ":%016" PRIx64 ":$CA", id);
}

/*
 * smb_dh_should_save
 *
 * During session tear-down, decide whether to keep a durable handle.
 *
 * There are two cases where we save durable handles:
 * 1. An SMB2 LOGOFF request was received
 * 2. An unexpected disconnect from the client
 *    Note: Specifying a PrevSessionID in session setup
 *    is considered a disconnect (we just haven't learned about it yet)
 * In every other case, we close durable handles.
 *
 * [MS-SMB2] 3.3.5.6 SMB2_LOGOFF
 * [MS-SMB2] 3.3.7.1 Handling Loss of a Connection
 *
 * If any of the following are true, preserve for reconnect:
 *
 * - Open.IsResilient is TRUE.
 *
 * - Open.OplockLevel == SMB2_OPLOCK_LEVEL_BATCH and
 *   Open.OplockState == Held, and Open.IsDurable is TRUE.
 *
 * - Open.OplockLevel == SMB2_OPLOCK_LEVEL_LEASE,
 *   Lease.LeaseState SMB2_LEASE_HANDLE_CACHING,
 *   Open.OplockState == Held, and Open.IsDurable is TRUE.
 *
 * - Open.IsPersistent is TRUE.
 *
 * We also deal with some special cases for shutdown of the
 * server, session, user, tree (in that order). Other than
 * the cases above, shutdown (or forced termination) should
 * destroy durable handles.
 */
boolean_t
smb_dh_should_save(smb_ofile_t *of)
{
	ASSERT(MUTEX_HELD(&of->f_mutex));
	ASSERT(of->dh_vers != SMB2_NOT_DURABLE);

	/* SMB service shutting down, destroy DH */
	if (of->f_server->sv_state == SMB_SERVER_STATE_STOPPING)
		return (B_FALSE);

	/*
	 * SMB Session (connection) going away (server up).
	 * If server initiated disconnect, destroy DH
	 * If client initiated disconnect, save all DH.
	 */
	if (of->f_session->s_state == SMB_SESSION_STATE_TERMINATED)
		return (B_FALSE);
	if (of->f_session->s_state == SMB_SESSION_STATE_DISCONNECTED)
		return (B_TRUE);

	/*
	 * SMB User logoff, session still "up".
	 * Action depends on why/how this logoff happened,
	 * determined based on user->preserve_opens
	 */
	if (of->f_user->u_state == SMB_USER_STATE_LOGGING_OFF) {
		switch (of->f_user->preserve_opens) {
		case SMB2_DH_PRESERVE_NONE:
			/* Server-initiated */
			return (B_FALSE);
		case SMB2_DH_PRESERVE_SOME:
			/* Previous session logoff. */
			goto preserve_some;
		case SMB2_DH_PRESERVE_ALL:
			/* Protocol logoff request */
			return (B_TRUE);
		}
	}

	/*
	 * SMB tree disconnecting (user still logged on)
	 * i.e. when kshare export forces disconnection.
	 */
	if (of->f_tree->t_state == SMB_TREE_STATE_DISCONNECTING)
		return (B_FALSE);

preserve_some:
	/* preserve_opens == SMB2_DH_PRESERVE_SOME */

	switch (of->dh_vers) {
		uint32_t ol_state;

	case SMB2_RESILIENT:
		return (B_TRUE);

	case SMB2_DURABLE_V2:
		if (of->dh_persist)
			return (B_TRUE);
		/* FALLTHROUGH */
	case SMB2_DURABLE_V1:
		/* IS durable (v1 or v2) */
		if (of->f_lease != NULL)
			ol_state = of->f_lease->ls_state;
		else
			ol_state = of->f_oplock.og_state;
		if ((ol_state & (OPLOCK_LEVEL_BATCH |
		    OPLOCK_LEVEL_CACHE_HANDLE)) != 0)
			return (B_TRUE);
		/* FALLTHROUGH */
	case SMB2_NOT_DURABLE:
	default:
		break;
	}

	return (B_FALSE);
}

/*
 * Is this stream name a CA handle? i.e.
 * ":0123456789abcdef:$CA"
 */
static boolean_t
smb2_dh_match_ca_name(const char *name, uint64_t *idp)
{
	static const char suffix[] = ":$CA";
	u_longlong_t ull;
	const char *p = name;
	char *p2 = NULL;
	int len, rc;

	if (*p++ != ':')
		return (B_FALSE);

	rc = ddi_strtoull(p, &p2, 16, &ull);
	if (rc != 0 || p2 != (p + 16))
		return (B_FALSE);
	p += 16;

	len = sizeof (suffix) - 1;
	if (strncmp(p, suffix, len) != 0)
		return (B_FALSE);
	p += len;

	if (*p != '\0')
		return (B_FALSE);

	*idp = (uint64_t)ull;
	return (B_TRUE);
}

/*
 * smb2_dh_new_ca_share
 *
 * Called when a new share has ca=true.  Find or create the CA dir,
 * and start a thread to import persistent handles.
 */
int
smb2_dh_new_ca_share(smb_server_t *sv, smb_kshare_t *shr)
{
	smb_kshare_t	*shr2;
	smb_request_t	*sr;
	taskqid_t	tqid;

	ASSERT(STYPE_ISDSK(shr->shr_type));

	/*
	 * Need to lookup the kshare again, to get a hold.
	 * Add a function to just get the hold?
	 */
	shr2 = smb_kshare_lookup(sv, shr->shr_name);
	if (shr2 != shr)
		return (EINVAL);

	sr = smb_request_alloc(sv->sv_session, 0);
	if (sr == NULL) {
		/* shutting down? */
		smb_kshare_release(sv, shr);
		return (EINTR);
	}
	sr->sr_state = SMB_REQ_STATE_SUBMITTED;

	/*
	 * Mark this share as "busy importing persistent handles"
	 * so we can hold off tree connect until that's done.
	 * Will clear and wakeup below.
	 */
	mutex_enter(&shr->shr_mutex);
	shr->shr_import_busy = sr;
	mutex_exit(&shr->shr_mutex);

	/*
	 * Start a taskq job to import any CA handles.
	 * The hold on the kshare is given to this job,
	 * which releases it when it's done.
	 */
	sr->arg.tcon.si = shr;	/* hold from above */
	tqid = taskq_dispatch(sv->sv_worker_pool,
	    smb2_dh_import_share, sr, TQ_SLEEP);
	VERIFY(tqid != TASKQID_INVALID);

	return (0);
}

int smb2_dh_import_delay = 0;

static void
smb2_dh_import_share(void *arg)
{
	smb_request_t	*sr = arg;
	smb_kshare_t	*shr = sr->arg.tcon.si;
	smb_node_t	*snode;
	cred_t		*kcr = zone_kcred();
	smb_streaminfo_t *str_info = NULL;
	char		*nvl_buf = NULL;
	uint64_t	id;
	smb_node_t	*str_node;
	smb_odir_t	*od = NULL;
	smb_ofile_t	*of;
	int		rc;
	boolean_t	eof;

	sr->sr_state = SMB_REQ_STATE_ACTIVE;

	if (smb2_dh_import_delay > 0)
		delay(SEC_TO_TICK(smb2_dh_import_delay));

	/*
	 * Borrow the server's "root" user.
	 *
	 * This takes the place of smb_session_lookup_ssnid()
	 * that would happen in smb2_dispatch for a normal SR.
	 * As usual, this hold is released in smb_request_free.
	 */
	sr->uid_user = sr->sr_server->sv_rootuser;
	smb_user_hold_internal(sr->uid_user);
	sr->user_cr = sr->uid_user->u_cred;

	/*
	 * Create a temporary tree connect
	 */
	sr->tid_tree = smb_tree_alloc(sr, shr, shr->shr_root_node,
	    ACE_ALL_PERMS, 0);
	if (sr->tid_tree == NULL) {
		cmn_err(CE_NOTE, "smb2_dh_import_share: "
		    "failed connect share <%s>", shr->shr_name);
		goto out;
	}
	snode = sr->tid_tree->t_snode;

	/*
	 * Get the buffers we'll use to read CA handle data.
	 * Also get a buffer for the stream name info.
	 */
	nvl_buf = kmem_alloc(smb2_dh_max_cah_size, KM_SLEEP);
	str_info = kmem_alloc(sizeof (smb_streaminfo_t), KM_SLEEP);

	/*
	 * Open the ext. attr dir under the share root and
	 * import CA handles for this share.
	 */
	if (smb_odir_openat(sr, snode, &od, B_FALSE) != 0) {
		cmn_err(CE_NOTE, "!Share [%s] CA import, no xattr dir?",
		    shr->shr_name);
		goto out;
	}

	eof = B_FALSE;
	do {
		/*
		 * If the kshare gets unshared before we finish,
		 * bail out so we don't hold things up.
		 */
		if (shr->shr_flags & SMB_SHRF_REMOVED)
			break;

		/*
		 * If the server's stopping, no point importing.
		 */
		if (smb_server_is_stopping(sr->sr_server))
			break;

		/*
		 * Read a stream name and info
		 */
		rc = smb_odir_read_streaminfo(sr, od, str_info, &eof);
		if ((rc != 0) || (eof))
			break;

		/*
		 * Skip anything not a CA handle.
		 */
		if (!smb2_dh_match_ca_name(str_info->si_name, &id)) {
			continue;
		}

		/*
		 * Lookup stream node and import
		 */
		str_node = NULL;
		rc = smb_fsop_lookup_name(sr, kcr, SMB_CASE_SENSITIVE,
		    snode, snode, str_info->si_name, &str_node);
		if (rc != 0) {
			cmn_err(CE_NOTE, "Share [%s] CA import, "
			    "lookup <%s> failed rc=%d",
			    shr->shr_name, str_info->si_name, rc);
			continue;
		}
		of = smb2_dh_import_handle(sr, str_node, nvl_buf, id);
		smb_node_release(str_node);
		if (of != NULL) {
			smb_ofile_release(of);
			of = NULL;
		}
		sr->fid_ofile = NULL;
		smb_lavl_flush(&sr->tid_tree->t_ofile_list);

	} while (!eof);

out:
	if (od != NULL) {
		smb_odir_close(od);
		smb_odir_release(od);
	}

	if (str_info != NULL)
		kmem_free(str_info, sizeof (smb_streaminfo_t));
	if (nvl_buf != NULL)
		kmem_free(nvl_buf, smb2_dh_max_cah_size);

	/*
	 * We did a (temporary, internal) tree connect above,
	 * which we need to undo before we return.  Note that
	 * smb_request_free will do the final release of
	 * sr->tid_tree, sr->uid_user
	 */
	if (sr->tid_tree != NULL)
		smb_tree_disconnect(sr->tid_tree, B_FALSE);

	/*
	 * Wake up any waiting tree connect(s).
	 * See smb_tree_connect_disk().
	 */
	mutex_enter(&shr->shr_mutex);
	shr->shr_import_busy = NULL;
	cv_broadcast(&shr->shr_cv);
	mutex_exit(&shr->shr_mutex);

	smb_kshare_release(sr->sr_server, shr);
	smb_request_free(sr);
}

/*
 * This returns the new ofile mostly for dtrace.
 */
static smb_ofile_t *
smb2_dh_import_handle(smb_request_t *sr, smb_node_t *str_node,
    char *nvl_buf, uint64_t persist_id)
{
	uint8_t		client_uuid[UUID_LEN];
	smb_tree_t	*tree = sr->tid_tree;
	smb_arg_open_t	*op = &sr->arg.open;
	smb_pathname_t	*pn = &op->fqi.fq_path;
	cred_t		*kcr = zone_kcred();
	struct nvlist	*nvl = NULL;
	char		*sidstr = NULL;
	smb_ofile_t	*of = NULL;
	smb_attr_t	*pa;
	boolean_t	did_open = B_FALSE;
	boolean_t	have_lease = B_FALSE;
	hrtime_t	hrt;
	uint64_t	*u64p;
	uint64_t	u64;
	uint32_t	u32;
	uint32_t	status;
	char		*s;
	uint8_t		*u8p;
	uint_t		alen;
	int		rc;

	/*
	 * While we're called with arg.tcon, we now want to use
	 * smb_arg_open for the rest of import, so clear it.
	 */
	bzero(op, sizeof (*op));
	op->create_disposition = FILE_OPEN;

	/*
	 * Read and unpack the NVL
	 */
	rc = smb2_dh_read_nvlist(sr, str_node, nvl_buf, &nvl);
	if (rc != 0)
		return (NULL);

	/*
	 * Known CA info version?
	 */
	u32 = 0;
	rc = nvlist_lookup_uint32(nvl, "info_version", &u32);
	if (rc != 0 || u32 != smb2_ca_info_version) {
		cmn_err(CE_NOTE, "CA import (%s/%s) bad vers=%d",
		    tree->t_resource, str_node->od_name, u32);
		goto errout;
	}

	/*
	 * The persist ID in the nvlist should match the one
	 * encoded in the file name. (not enforced)
	 */
	u64 = 0;
	rc = nvlist_lookup_uint64(nvl, "file_persistid", &u64);
	if (rc != 0 || u64 != persist_id) {
		cmn_err(CE_WARN, "CA import (%s/%s) bad id=%016" PRIx64,
		    tree->t_resource, str_node->od_name, u64);
		/* goto errout? (allow) */
	}

	/*
	 * Does it belong in the share being imported?
	 */
	s = NULL;
	rc = nvlist_lookup_string(nvl, "share_name", &s);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) no share_name",
		    tree->t_resource, str_node->od_name);
		goto errout;
	}
	if (smb_strcasecmp(s, tree->t_sharename, 0) != 0) {
		/* Normal (not an error) */
#ifdef DEBUG
		cmn_err(CE_NOTE, "CA import (%s/%s) other share",
		    tree->t_resource, str_node->od_name);
#endif
		goto errout;
	}

	/*
	 * Get the path name (for lookup)
	 */
	rc = nvlist_lookup_string(nvl, "path_name", &pn->pn_path);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) no path_name",
		    tree->t_resource, str_node->od_name);
		goto errout;
	}

	/*
	 * owner sid
	 */
	rc = nvlist_lookup_string(nvl, "owner_sid", &sidstr);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) no owner_sid",
		    tree->t_resource, str_node->od_name);
		goto errout;
	}

	/*
	 * granted access
	 */
	rc = nvlist_lookup_uint32(nvl,
	    "granted_access", &op->desired_access);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) no granted_access",
		    tree->t_resource, str_node->od_name);
		goto errout;
	}

	/*
	 * share access
	 */
	rc = nvlist_lookup_uint32(nvl,
	    "share_access", &op->share_access);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) no share_access",
		    tree->t_resource, str_node->od_name);
		goto errout;
	}

	/*
	 * create options
	 */
	rc = nvlist_lookup_uint32(nvl,
	    "create_options", &op->create_options);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) no create_options",
		    tree->t_resource, str_node->od_name);
		goto errout;
	}

	/*
	 * create guid (client-assigned)
	 */
	alen = UUID_LEN;
	u8p = NULL;
	rc = nvlist_lookup_uint8_array(nvl, "file_guid", &u8p, &alen);
	if (rc != 0 || alen != UUID_LEN) {
		cmn_err(CE_NOTE, "CA import (%s/%s) bad file_guid",
		    tree->t_resource, str_node->od_name);
		goto errout;
	}
	bcopy(u8p, op->create_guid, UUID_LEN);

	/*
	 * client uuid (identifies the client)
	 */
	alen = UUID_LEN;
	u8p = NULL;
	rc = nvlist_lookup_uint8_array(nvl, "client_uuid", &u8p, &alen);
	if (rc != 0 || alen != UUID_LEN) {
		cmn_err(CE_NOTE, "CA import (%s/%s) no client_uuid",
		    tree->t_resource, str_node->od_name);
		goto errout;
	}
	bcopy(u8p, client_uuid, UUID_LEN);

	/*
	 * Lease key (optional)
	 */
	alen = SMB_LEASE_KEY_SZ;
	u8p = NULL;
	rc = nvlist_lookup_uint8_array(nvl, "lease_uuid", &u8p, &alen);
	if (rc == 0) {
		bcopy(u8p, op->lease_key, UUID_LEN);
		(void) nvlist_lookup_uint32(nvl,
		    "lease_state", &op->lease_state);
		(void) nvlist_lookup_uint16(nvl,
		    "lease_epoch", &op->lease_epoch);
		(void) nvlist_lookup_uint16(nvl,
		    "lease_version", &op->lease_version);
		have_lease = B_TRUE;
	} else {
		(void) nvlist_lookup_uint32(nvl,
		    "oplock_state", &op->op_oplock_state);
	}

	/*
	 * Done getting what we need from the NV list.
	 * (re)open the file
	 */
	status = smb_common_open(sr);
	if (status != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) open failed 0x%x",
		    tree->t_resource, str_node->od_name, status);
		(void) smb_node_set_delete_on_close(str_node, kcr, 0);
		goto errout;
	}
	of = sr->fid_ofile;
	did_open = B_TRUE;

	/*
	 * Now restore the rest of the SMB2 level state.
	 * See smb2_create after smb_common_open
	 */

	/*
	 * Setup of->f_cr with owner SID
	 */
	rc = smb2_dh_import_cred(of, sidstr);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) import cred failed",
		    tree->t_resource, str_node->od_name);
		goto errout;
	}

	/*
	 * Use the persist ID we previously assigned.
	 * Like smb_ofile_set_persistid_ph()
	 */
	rc = smb_ofile_insert_persistid(of, persist_id);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) "
		    "insert_persistid rc=%d",
		    tree->t_resource, str_node->od_name, rc);
		goto errout;
	}

	/*
	 * Like smb2_lease_create()
	 *
	 * Lease state is stored in each persistent handle, but
	 * only one handle has the state we want.  As we import
	 * each handle, "upgrade" the lease if the handle we're
	 * importing has a "better" lease state (higher epoch or
	 * more cache rights).  After all handles are imported,
	 * that will get the lease to the right state.
	 */
	if (have_lease) {
		smb_lease_t *ls;
		status = smb2_lease_create(sr, client_uuid);
		if (status != 0) {
			cmn_err(CE_NOTE, "CA import (%s/%s) get lease 0x%x",
			    tree->t_resource, str_node->od_name, status);
			goto errout;
		}
		ls = of->f_lease;

		/* Use most current "epoch". */
		mutex_enter(&ls->ls_mutex);
		if (ls->ls_epoch < op->lease_epoch)
			ls->ls_epoch = op->lease_epoch;
		mutex_exit(&ls->ls_mutex);

		/*
		 * Get the lease (and oplock)
		 * uses op->lease_state
		 */
		op->op_oplock_level = SMB2_OPLOCK_LEVEL_LEASE;
		smb2_lease_acquire(sr);

	} else {
		/*
		 * No lease; maybe get an oplock
		 * uses: op->op_oplock_level
		 */
		if (op->op_oplock_state & OPLOCK_LEVEL_BATCH) {
			op->op_oplock_level = SMB2_OPLOCK_LEVEL_BATCH;
		} else if (op->op_oplock_state & OPLOCK_LEVEL_ONE) {
			op->op_oplock_level = SMB2_OPLOCK_LEVEL_EXCLUSIVE;
		} else if (op->op_oplock_state & OPLOCK_LEVEL_TWO) {
			op->op_oplock_level = SMB2_OPLOCK_LEVEL_II;
		} else {
			op->op_oplock_level = SMB2_OPLOCK_LEVEL_NONE;
		}
		smb2_oplock_acquire(sr);
	}

	/*
	 * Byte range locks
	 */
	alen = 0;
	u64p = NULL;
	if (nvlist_lookup_uint64_array(nvl, "locks", &u64p, &alen) == 0) {
		uint_t	i;
		uint_t nlocks = alen / 3;
		struct nvlk	*nlp;

		nlp = (struct nvlk *)u64p;
		for (i = 0; i < nlocks; i++) {
			status = smb_lock_range(
			    sr,
			    nlp->lk_start,
			    nlp->lk_len,
			    nlp->lk_pid,
			    nlp->lk_type,
			    0);
			if (status != 0) {
				cmn_err(CE_NOTE, "CA import (%s/%s) "
				    "get lock %d failed 0x%x",
				    tree->t_resource,
				    str_node->od_name,
				    i, status);
			}
			nlp++;
		}
	}
	alen = SMB_OFILE_LSEQ_MAX;
	u8p = NULL;
	if (nvlist_lookup_uint8_array(nvl, "lockseq", &u8p, &alen) == 0) {
		if (alen != SMB_OFILE_LSEQ_MAX) {
			cmn_err(CE_NOTE, "CA import (%s/%s) "
			    "get lockseq bad len=%d",
			    tree->t_resource,
			    str_node->od_name,
			    alen);
		} else {
			mutex_enter(&of->f_mutex);
			bcopy(u8p, of->f_lock_seq, alen);
			mutex_exit(&of->f_mutex);
		}
	}

	/*
	 * Optional "sticky" times (set pending attributes)
	 */
	mutex_enter(&of->f_mutex);
	pa = &of->f_pending_attr;
	if (nvlist_lookup_hrtime(nvl, "atime", &hrt) == 0) {
		hrt2ts(hrt, &pa->sa_vattr.va_atime);
		pa->sa_mask |= SMB_AT_ATIME;
	}
	if (nvlist_lookup_hrtime(nvl, "mtime", &hrt) == 0) {
		hrt2ts(hrt, &pa->sa_vattr.va_mtime);
		pa->sa_mask |= SMB_AT_MTIME;
	}
	if (nvlist_lookup_hrtime(nvl, "ctime", &hrt) == 0) {
		hrt2ts(hrt, &pa->sa_vattr.va_ctime);
		pa->sa_mask |= SMB_AT_CTIME;
	}
	mutex_exit(&of->f_mutex);

	/*
	 * Make durable and persistent.
	 * See smb2_dh_make_persistent()
	 */
	of->dh_vers = SMB2_DURABLE_V2;
	bcopy(op->create_guid, of->dh_create_guid, UUID_LEN);
	of->dh_persist = B_TRUE;
	of->dh_nvfile = str_node;
	smb_node_ref(str_node);
	of->dh_nvlist = nvl;
	nvl = NULL;

	/*
	 * Now make it state orphaned...
	 * See smb_ofile_drop(), then
	 * smb_ofile_save_dh()
	 */
	mutex_enter(&of->f_mutex);
	of->f_state = SMB_OFILE_STATE_SAVE_DH;
	of->dh_timeout_offset = MSEC2NSEC(smb2_persist_timeout);
	mutex_exit(&of->f_mutex);

	/*
	 * Finished!
	 */
	return (of);

errout:
	if (did_open) {
		smb_ofile_close(of, 0);
		smb_ofile_release(of);
	} else {
		ASSERT(of == NULL);
	}

	if (nvl != NULL)
		nvlist_free(nvl);

	return (NULL);
}

static int
smb2_dh_read_nvlist(smb_request_t *sr, smb_node_t *node,
    char *fbuf, struct nvlist **nvlpp)
{
	smb_attr_t	attr;
	iovec_t		iov;
	uio_t		uio;
	smb_tree_t	*tree = sr->tid_tree;
	cred_t		*kcr = zone_kcred();
	size_t		flen;
	int		rc;

	bzero(&attr, sizeof (attr));
	attr.sa_mask = SMB_AT_SIZE;
	rc = smb_node_getattr(NULL, node, kcr, NULL, &attr);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) getattr rc=%d",
		    tree->t_resource, node->od_name, rc);
		return (rc);
	}

	if (attr.sa_vattr.va_size < 4 ||
	    attr.sa_vattr.va_size > smb2_dh_max_cah_size) {
		cmn_err(CE_NOTE, "CA import (%s/%s) bad size=%" PRIu64,
		    tree->t_resource, node->od_name,
		    (uint64_t)attr.sa_vattr.va_size);
		return (EINVAL);
	}
	flen = (size_t)attr.sa_vattr.va_size;

	bzero(&uio, sizeof (uio));
	iov.iov_base = fbuf;
	iov.iov_len = flen;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = flen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_extflg = UIO_COPY_DEFAULT;
	rc = smb_fsop_read(sr, kcr, node, NULL, &uio, 0);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) read, rc=%d",
		    tree->t_resource, node->od_name, rc);
		return (rc);
	}
	if (uio.uio_resid != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) short read",
		    tree->t_resource, node->od_name);
		return (EIO);
	}

	rc = nvlist_unpack(fbuf, flen, nvlpp, KM_SLEEP);
	if (rc != 0) {
		cmn_err(CE_NOTE, "CA import (%s/%s) unpack, rc=%d",
		    tree->t_resource, node->od_name, rc);
		return (rc);
	}

	return (0);
}

/*
 * Setup a vestigial credential in of->f_cr just good enough for
 * smb_is_same_user to determine if the caller owned this ofile.
 * At reconnect, of->f_cr will be replaced with the caller's.
 */
static int
smb2_dh_import_cred(smb_ofile_t *of, char *sidstr)
{
#ifdef	_FAKE_KERNEL
	_NOTE(ARGUNUSED(sidstr))
	/* fksmbd doesn't have real credentials. */
	of->f_cr = CRED();
	crhold(of->f_cr);
#else
	char tmpstr[SMB_SID_STRSZ];
	ksid_t		ksid;
	cred_t		*cr, *oldcr;
	int		rc;

	(void) strlcpy(tmpstr, sidstr, sizeof (tmpstr));
	bzero(&ksid, sizeof (ksid));

	rc = smb_sid_splitstr(tmpstr, &ksid.ks_rid);
	if (rc != 0)
		return (rc);
	cr = crget();

	ksid.ks_domain = ksid_lookupdomain(tmpstr);
	crsetsid(cr, &ksid, KSID_USER);
	ksiddomain_hold(ksid.ks_domain);
	crsetsid(cr, &ksid, KSID_OWNER);

	/*
	 * Just to avoid leaving the KSID_GROUP slot NULL,
	 * put the "everyone" SID there (S-1-1-0).
	 */
	ksid.ks_domain = ksid_lookupdomain("S-1-1");
	ksid.ks_rid = 0;
	crsetsid(cr, &ksid, KSID_GROUP);

	oldcr = of->f_cr;
	of->f_cr = cr;
	if (oldcr != NULL)
		crfree(oldcr);
#endif

	return (0);
}

/*
 * Set Delete-on-Close (DoC) on the persistent state file so it will be
 * removed when the last ref. goes away (in smb2_dh_close_persistent).
 *
 * This is called in just two places:
 * (1) SMB2_close request -- client tells us to destroy the handle.
 * (2) smb2_dh_expire -- client has forgotten about this handle.
 * All other (server-initiated) close calls should leave these
 * persistent state files in the file system.
 */
void
smb2_dh_setdoc_persistent(smb_ofile_t *of)
{
	smb_node_t *strnode;
	uint32_t status;

	mutex_enter(&of->dh_nvlock);
	if ((strnode = of->dh_nvfile) != NULL)
		smb_node_ref(strnode);
	mutex_exit(&of->dh_nvlock);

	if (strnode != NULL) {
		status = smb_node_set_delete_on_close(strnode,
		    zone_kcred(), SMB_CASE_SENSITIVE);
		if (status != 0) {
			cmn_err(CE_WARN, "Can't set DoC on CA file: %s",
			    strnode->od_name);
			DTRACE_PROBE1(rm__ca__err, smb_ofile_t *, of);
		}
		smb_node_release(strnode);
	}
}

/*
 * During ofile close, free the persistent handle state nvlist and
 * drop our reference to the state file node (which may unlink it
 * if smb2_dh_setdoc_persistent was called).
 */
void
smb2_dh_close_persistent(smb_ofile_t *of)
{
	smb_node_t	*strnode;
	struct nvlist	*nvl;

	/*
	 * Clear out nvlist and stream linkage
	 */
	mutex_enter(&of->dh_nvlock);
	strnode = of->dh_nvfile;
	of->dh_nvfile = NULL;
	nvl = of->dh_nvlist;
	of->dh_nvlist = NULL;
	mutex_exit(&of->dh_nvlock);

	if (nvl != NULL)
		nvlist_free(nvl);

	if (strnode != NULL)
		smb_node_release(strnode);
}

/*
 * Make this durable handle persistent.
 * If we succeed, set of->dh_persist = TRUE.
 */
int
smb2_dh_make_persistent(smb_request_t *sr, smb_ofile_t *of)
{
	char		fname[DH_SN_SIZE];
	char		sidstr[SMB_SID_STRSZ];
	smb_attr_t	attr;
	smb_arg_open_t	*op = &sr->arg.open;
	cred_t		*kcr = zone_kcred();
	smb_node_t	*dnode = of->f_tree->t_snode;
	smb_node_t	*fnode = NULL;
	ksid_t		*ksid;
	int		rc;

	ASSERT(of->dh_nvfile == NULL);

	/*
	 * Create the persistent handle nvlist file.
	 * It's a named stream in the share root.
	 */
	smb2_dh_make_stream_name(fname, sizeof (fname), of->f_persistid);

	bzero(&attr, sizeof (attr));
	attr.sa_mask = SMB_AT_TYPE | SMB_AT_MODE | SMB_AT_SIZE;
	attr.sa_vattr.va_type = VREG;
	attr.sa_vattr.va_mode = 0640;
	attr.sa_vattr.va_size = 4;
	rc = smb_fsop_create(sr, kcr, dnode, fname, &attr, &fnode);
	if (rc != 0)
		return (rc);

	mutex_enter(&of->dh_nvlock);

	/* fnode is held. rele in smb2_dh_close_persistent */
	of->dh_nvfile = fnode;
	(void) nvlist_alloc(&of->dh_nvlist, NV_UNIQUE_NAME, KM_SLEEP);

	/*
	 * Want the ksid as a string
	 */
	ksid = crgetsid(of->f_user->u_cred, KSID_USER);
	(void) snprintf(sidstr, sizeof (sidstr), "%s-%u",
	    ksid->ks_domain->kd_name, ksid->ks_rid);

	/*
	 * Fill in the fixed parts of the nvlist
	 */
	(void) nvlist_add_uint32(of->dh_nvlist,
	    "info_version", smb2_ca_info_version);
	(void) nvlist_add_string(of->dh_nvlist,
	    "owner_sid", sidstr);
	(void) nvlist_add_string(of->dh_nvlist,
	    "share_name", of->f_tree->t_sharename);
	(void) nvlist_add_uint64(of->dh_nvlist,
	    "file_persistid", of->f_persistid);
	(void) nvlist_add_uint8_array(of->dh_nvlist,
	    "file_guid", of->dh_create_guid, UUID_LEN);
	(void) nvlist_add_string(of->dh_nvlist,
	    "client_ipaddr", sr->session->ip_addr_str);
	(void) nvlist_add_uint8_array(of->dh_nvlist,
	    "client_uuid", sr->session->clnt_uuid, UUID_LEN);
	(void) nvlist_add_string(of->dh_nvlist,
	    "path_name", op->fqi.fq_path.pn_path);
	(void) nvlist_add_uint32(of->dh_nvlist,
	    "granted_access", of->f_granted_access);
	(void) nvlist_add_uint32(of->dh_nvlist,
	    "share_access", of->f_share_access);
	(void) nvlist_add_uint32(of->dh_nvlist,
	    "create_options", of->f_create_options);
	if (of->f_lease != NULL) {
		smb_lease_t *ls = of->f_lease;
		(void) nvlist_add_uint8_array(of->dh_nvlist,
		    "lease_uuid", ls->ls_key, 16);
		(void) nvlist_add_uint32(of->dh_nvlist,
		    "lease_state", ls->ls_state);
		(void) nvlist_add_uint16(of->dh_nvlist,
		    "lease_epoch", ls->ls_epoch);
		(void) nvlist_add_uint16(of->dh_nvlist,
		    "lease_version", ls->ls_version);
	} else {
		(void) nvlist_add_uint32(of->dh_nvlist,
		    "oplock_state", of->f_oplock.og_state);
	}
	mutex_exit(&of->dh_nvlock);

	smb2_dh_update_locks(sr, of);

	/* Tell sr update nvlist file */
	sr->dh_nvl_dirty = B_TRUE;

	return (0);
}

void
smb2_dh_update_nvfile(smb_request_t *sr)
{
	smb_attr_t	attr;
	iovec_t		iov;
	uio_t		uio;
	smb_ofile_t	*of = sr->fid_ofile;
	cred_t		*kcr = zone_kcred();
	char		*buf = NULL;
	size_t		buflen = 0;
	uint32_t	wcnt;
	int		rc;

	if (of == NULL || of->dh_persist == B_FALSE)
		return;

	mutex_enter(&of->dh_nvlock);
	if (of->dh_nvlist == NULL || of->dh_nvfile == NULL) {
		mutex_exit(&of->dh_nvlock);
		return;
	}

	rc = nvlist_size(of->dh_nvlist, &buflen, NV_ENCODE_XDR);
	if (rc != 0)
		goto out;
	buf = kmem_zalloc(buflen, KM_SLEEP);

	rc = nvlist_pack(of->dh_nvlist, &buf, &buflen,
	    NV_ENCODE_XDR, KM_SLEEP);
	if (rc != 0)
		goto out;

	bzero(&attr, sizeof (attr));
	attr.sa_mask = SMB_AT_SIZE;
	attr.sa_vattr.va_size = buflen;
	rc = smb_node_setattr(sr, of->dh_nvfile, kcr, NULL, &attr);
	if (rc != 0)
		goto out;

	bzero(&uio, sizeof (uio));
	iov.iov_base = (void *) buf;
	iov.iov_len = buflen;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_resid = buflen;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_extflg = UIO_COPY_DEFAULT;
	rc = smb_fsop_write(sr, kcr, of->dh_nvfile,
	    NULL, &uio, &wcnt, 0);
	if (rc == 0 && wcnt != buflen)
		rc = EIO;

out:
	mutex_exit(&of->dh_nvlock);

	if (rc != 0) {
		cmn_err(CE_WARN,
		    "clnt(%s) failed to update persistent handle, rc=%d",
		    sr->session->ip_addr_str, rc);
	}

	if (buf != NULL) {
		kmem_free(buf, buflen);
	}
}

/*
 * Called after f_oplock (and lease) changes
 * If lease, update: lease_state, lease_epoch
 * else (oplock) update: oplock_state
 */
void
smb2_dh_update_oplock(smb_request_t *sr, smb_ofile_t *of)
{
	smb_lease_t *ls;

	mutex_enter(&of->dh_nvlock);
	if (of->dh_nvlist == NULL) {
		mutex_exit(&of->dh_nvlock);
		return;
	}

	if (of->f_lease != NULL) {
		ls = of->f_lease;
		(void) nvlist_add_uint32(of->dh_nvlist,
		    "lease_state", ls->ls_state);
		(void) nvlist_add_uint16(of->dh_nvlist,
		    "lease_epoch", ls->ls_epoch);
	} else {
		(void) nvlist_add_uint32(of->dh_nvlist,
		    "oplock_state", of->f_oplock.og_state);
	}
	mutex_exit(&of->dh_nvlock);

	sr->dh_nvl_dirty = B_TRUE;
}

/*
 * Save locks from this ofile as an array of uint64_t, where the
 * elements are triplets: (start, length, (pid << 32) | type)
 * Note pid should always be zero for SMB2, so we could use
 * that 32-bit spot for something else if needed.
 */
void
smb2_dh_update_locks(smb_request_t *sr, smb_ofile_t *of)
{
	uint8_t		lseq[SMB_OFILE_LSEQ_MAX];
	smb_node_t	*node = of->f_node;
	smb_llist_t	*llist = &node->n_lock_list;
	size_t		vec_sz;	// storage size
	uint_t		my_cnt = 0;
	uint64_t	*vec = NULL;
	struct nvlk	*nlp;
	smb_lock_t	*lock;

	smb_llist_enter(llist, RW_READER);
	vec_sz = (llist->ll_count + 1) * sizeof (struct nvlk);
	vec = kmem_alloc(vec_sz, KM_SLEEP);
	nlp = (struct nvlk *)vec;
	for (lock = smb_llist_head(llist);
	    lock != NULL;
	    lock = smb_llist_next(llist, lock)) {
		if (lock->l_file != of)
			continue;
		nlp->lk_start = lock->l_start;
		nlp->lk_len = lock->l_length;
		nlp->lk_pid = lock->l_pid;
		nlp->lk_type = lock->l_type;
		nlp++;
		my_cnt++;
	}
	smb_llist_exit(llist);

	mutex_enter(&of->f_mutex);
	bcopy(of->f_lock_seq, lseq, sizeof (lseq));
	mutex_exit(&of->f_mutex);

	mutex_enter(&of->dh_nvlock);
	if (of->dh_nvlist != NULL) {

		(void) nvlist_add_uint64_array(of->dh_nvlist,
		    "locks", vec, my_cnt * 3);

		(void) nvlist_add_uint8_array(of->dh_nvlist,
		    "lockseq", lseq, sizeof (lseq));
	}
	mutex_exit(&of->dh_nvlock);

	kmem_free(vec, vec_sz);

	sr->dh_nvl_dirty = B_TRUE;
}

/*
 * Save "sticky" times
 */
void
smb2_dh_update_times(smb_request_t *sr, smb_ofile_t *of, smb_attr_t *attr)
{
	hrtime_t t;

	mutex_enter(&of->dh_nvlock);
	if (of->dh_nvlist == NULL) {
		mutex_exit(&of->dh_nvlock);
		return;
	}

	if (attr->sa_mask & SMB_AT_ATIME) {
		t = ts2hrt(&attr->sa_vattr.va_atime);
		(void) nvlist_add_hrtime(of->dh_nvlist, "atime", t);
	}
	if (attr->sa_mask & SMB_AT_MTIME) {
		t = ts2hrt(&attr->sa_vattr.va_mtime);
		(void) nvlist_add_hrtime(of->dh_nvlist, "mtime", t);
	}
	if (attr->sa_mask & SMB_AT_CTIME) {
		t = ts2hrt(&attr->sa_vattr.va_ctime);
		(void) nvlist_add_hrtime(of->dh_nvlist, "ctime", t);
	}
	mutex_exit(&of->dh_nvlock);

	sr->dh_nvl_dirty = B_TRUE;
}


/*
 * Requirements for ofile found during reconnect (MS-SMB2 3.3.5.9.7):
 * - security descriptor must match provided descriptor
 *
 * If file is leased:
 * - lease must be requested
 * - client guid must match session guid
 * - file name must match given name
 * - lease key must match provided lease key
 * If file is not leased:
 * - Lease must not be requested
 *
 * dh_v2 only:
 * - SMB2_DHANDLE_FLAG_PERSISTENT must be set if dh_persist is true
 * - SMB2_DHANDLE_FLAG_PERSISTENT must not be set if dh_persist is false
 * - desired access, share access, and create_options must be ignored
 * - createguid must match
 */
static uint32_t
smb2_dh_reconnect_checks(smb_request_t *sr, smb_ofile_t *of)
{
	smb_arg_open_t	*op = &sr->sr_open;
	char *fname;

	if (of->f_lease != NULL) {
		if (bcmp(sr->session->clnt_uuid,
		    of->f_lease->ls_clnt, 16) != 0)
			return (NT_STATUS_OBJECT_NAME_NOT_FOUND);

		if (op->op_oplock_level != SMB2_OPLOCK_LEVEL_LEASE)
			return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
		if (bcmp(op->lease_key, of->f_lease->ls_key,
		    SMB_LEASE_KEY_SZ) != 0)
			return (NT_STATUS_OBJECT_NAME_NOT_FOUND);

		/*
		 * We're supposed to check the name is the same.
		 * Not really necessary to do this, so just do
		 * minimal effort (check last component)
		 */
		fname = strrchr(op->fqi.fq_path.pn_path, '\\');
		if (fname != NULL)
			fname++;
		else
			fname = op->fqi.fq_path.pn_path;
		if (smb_strcasecmp(fname, of->f_node->od_name, 0) != 0) {
#ifdef	DEBUG
			cmn_err(CE_NOTE, "reconnect name <%s> of name <%s>",
			    fname, of->f_node->od_name);
#endif
			return (NT_STATUS_INVALID_PARAMETER);
		}
	} else {
		if (op->op_oplock_level == SMB2_OPLOCK_LEVEL_LEASE)
			return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	if (op->dh_vers == SMB2_DURABLE_V2) {
		boolean_t op_persist =
		    ((op->dh_v2_flags & SMB2_DHANDLE_FLAG_PERSISTENT) != 0);
		if (of->dh_persist != op_persist)
			return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
		if (memcmp(op->create_guid, of->dh_create_guid, UUID_LEN))
			return (NT_STATUS_OBJECT_NAME_NOT_FOUND);
	}

	if (!smb_is_same_user(sr->user_cr, of->f_cr))
		return (NT_STATUS_ACCESS_DENIED);

	return (NT_STATUS_SUCCESS);
}

/*
 * [MS-SMB2] 3.3.5.9.7 and 3.3.5.9.12 (durable reconnect v1/v2)
 *
 * Looks up an ofile on the server's sv_dh_list by the persistid.
 * If found, it validates the request.
 * (see smb2_dh_reconnect_checks() for details)
 * If the checks are passed, add it onto the new tree's list.
 *
 * Note that the oplock break code path can get to an ofile via the node
 * ofile list.  It starts with a ref taken in smb_ofile_hold_olbrk, which
 * waits if the ofile is found in state RECONNECT.  That wait happens with
 * the node ofile list lock held as reader, and the oplock mutex held.
 * Implications of that are: While we're in state RECONNECT, we shoud NOT
 * block (at least, not for long) and must not try to enter any of the
 * node ofile list lock or oplock mutex.  Thankfully, we don't need to
 * enter those while reclaiming an orphaned ofile.
 */
uint32_t
smb2_dh_reconnect(smb_request_t *sr)
{
	smb_arg_open_t	*op = &sr->sr_open;
	smb_tree_t *tree = sr->tid_tree;
	smb_ofile_t *of;
	cred_t *old_cr;
	uint32_t status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	uint16_t fid = 0;

	if (smb_idpool_alloc(&tree->t_fid_pool, &fid))
		return (NT_STATUS_TOO_MANY_OPENED_FILES);

	/* Find orphaned handle. */
	of = smb_ofile_lookup_by_persistid(sr, op->dh_fileid.persistent);
	if (of == NULL)
		goto errout;

	mutex_enter(&of->f_mutex);
	if (of->f_state != SMB_OFILE_STATE_ORPHANED) {
		mutex_exit(&of->f_mutex);
		goto errout;
	}

	status = smb2_dh_reconnect_checks(sr, of);
	if (status != NT_STATUS_SUCCESS) {
		mutex_exit(&of->f_mutex);
		goto errout;
	}

	/*
	 * Note: cv_broadcast(&of->f_cv) when we're
	 * done messing around in this state.
	 * See: smb_ofile_hold_olbrk()
	 */
	of->f_state = SMB_OFILE_STATE_RECONNECT;
	mutex_exit(&of->f_mutex);

	/*
	 * At this point, we should be the only thread with a ref on the
	 * ofile, and the RECONNECT state should prevent new refs from
	 * being granted, or other durable threads from observing or
	 * reclaiming it. Put this ofile in the new tree, similar to
	 * the last part of smb_ofile_open.
	 */

	old_cr = of->f_cr;
	of->f_cr = sr->user_cr;
	crhold(of->f_cr);
	crfree(old_cr);

	of->f_session = sr->session; /* hold is via user and tree */
	smb_user_hold_internal(sr->uid_user);
	of->f_user = sr->uid_user;
	smb_tree_hold_internal(tree);
	of->f_tree = tree;
	of->f_fid = fid;

	smb_lavl_enter(&tree->t_ofile_list, RW_WRITER);
	smb_lavl_insert(&tree->t_ofile_list, of);
	smb_lavl_exit(&tree->t_ofile_list);
	atomic_inc_32(&tree->t_open_files);
	atomic_inc_32(&sr->session->s_file_cnt);

	/*
	 * The ofile is now in the caller's session & tree.
	 *
	 * In case smb_ofile_hold or smb_oplock_send_break() are
	 * waiting for state RECONNECT to complete, wakeup.
	 */
	mutex_enter(&of->f_mutex);
	of->dh_expire_time = 0;
	of->f_state = SMB_OFILE_STATE_OPEN;
	cv_broadcast(&of->f_cv);
	mutex_exit(&of->f_mutex);

	/*
	 * The ofile is now visible in the new session.
	 * From here, this is similar to the last part of
	 * smb_common_open().
	 */
	op->fqi.fq_fattr.sa_mask = SMB_AT_ALL;
	(void) smb_node_getattr(sr, of->f_node, zone_kcred(), of,
	    &op->fqi.fq_fattr);

	/*
	 * Set up the fileid and dosattr in open_param for response
	 */
	op->fileid = op->fqi.fq_fattr.sa_vattr.va_nodeid;
	op->dattr = op->fqi.fq_fattr.sa_dosattr;

	/*
	 * Set up the file type in open_param for the response
	 * The ref. from ofile lookup is "given" to fid_ofile.
	 */
	op->ftype = SMB_FTYPE_DISK;
	sr->smb_fid = of->f_fid;
	sr->fid_ofile = of;

	if (smb_node_is_file(of->f_node)) {
		op->dsize = op->fqi.fq_fattr.sa_vattr.va_size;
	} else {
		/* directory or symlink */
		op->dsize = 0;
	}

	op->create_options = 0; /* no more modifications wanted */
	op->action_taken = SMB_OACT_OPENED;
	return (NT_STATUS_SUCCESS);

errout:
	if (of != NULL)
		smb_ofile_release(of);
	if (fid != 0)
		smb_idpool_free(&tree->t_fid_pool, fid);

	return (status);
}

/*
 * Durable handle expiration
 * ofile state is _EXPIRED
 */
static void
smb2_dh_expire(void *arg)
{
	smb_ofile_t *of = (smb_ofile_t *)arg;

	if (of->dh_persist)
		smb2_dh_setdoc_persistent(of);
	smb_ofile_close(of, 0);
	smb_ofile_release(of);
}

/*
 * Called once a minute to do expiration of durable handles.
 *
 * Normally expired durable handles should be in state "orphaned",
 * having transitioned from state SAVE_DH through SAVING to state
 * ORPHANED after all ofile references go away.  If an ofile has
 * leaked references and the client disconnects, it will be found
 * here still in state SAVE_DH and past it's expiration time.
 * Call smb2_dh_expire for these as well, which will move them
 * from state SAVE_DH to state CLOSING, so they can no longer
 * cause sharing violations for new opens.
 */
void
smb2_durable_timers(smb_server_t *sv)
{
	smb_hash_t *hash;
	smb_llist_t *bucket;
	smb_ofile_t *of;
	hrtime_t now;
	int i;

	hash = sv->sv_persistid_ht;
	now = gethrtime();

	for (i = 0; i < hash->num_buckets; i++) {
		bucket = &hash->buckets[i].b_list;
		smb_llist_enter(bucket, RW_READER);
		for (of = smb_llist_head(bucket);
		    of != NULL;
		    of = smb_llist_next(bucket, of)) {
			SMB_OFILE_VALID(of);

			/*
			 * Check outside the mutex first to avoid some
			 * mutex_enter work in this loop.  If the state
			 * changes under foot, the worst that happens
			 * is we either enter the mutex when we might
			 * not have needed to, or we miss some DH in
			 * this pass and get it on the next.
			 */
			if (of->f_state != SMB_OFILE_STATE_ORPHANED &&
			    of->f_state != SMB_OFILE_STATE_SAVE_DH)
				continue;

			mutex_enter(&of->f_mutex);
			if ((of->f_state == SMB_OFILE_STATE_ORPHANED ||
			    of->f_state == SMB_OFILE_STATE_SAVE_DH) &&
			    of->dh_expire_time != 0 &&
			    of->dh_expire_time <= now) {

				of->f_state = SMB_OFILE_STATE_EXPIRED;
				/* inline smb_ofile_hold_internal() */
				of->f_refcnt++;
				smb_llist_post(bucket, of, smb2_dh_expire);
			}
			mutex_exit(&of->f_mutex);
		}
		smb_llist_exit(bucket);
	}
}

/*
 * This is called when we're about to add a new open to some node.
 * If we still have orphaned durable handles on this node, let's
 * assume the client has lost interest in those and close them,
 * otherwise we might conflict with our own orphaned handles.
 *
 * We need this because we import persistent handles "speculatively"
 * during share import (before the client ever asks for reconnect).
 * That allows us to avoid any need for a "create blackout" (or
 * "grace period") because the imported handles prevent unwanted
 * conflicting opens from other clients.  However, if some client
 * "forgets" about a persistent handle (*cough* Hyper-V) and tries
 * a new (conflicting) open instead of a reconnect, that might
 * fail unless we expire our orphaned durables handle first.
 *
 * Logic similar to smb_node_open_check()
 */
void
smb2_dh_close_my_orphans(smb_request_t *sr, smb_ofile_t *new_of)
{
	smb_node_t *node = new_of->f_node;
	smb_ofile_t *of;

	SMB_NODE_VALID(node);

	smb_llist_enter(&node->n_ofile_list, RW_READER);
	for (of = smb_llist_head(&node->n_ofile_list);
	    of != NULL;
	    of = smb_llist_next(&node->n_ofile_list, of)) {

		/* Same client? */
		if (of->f_lease != NULL &&
		    bcmp(sr->session->clnt_uuid,
		    of->f_lease->ls_clnt, 16) != 0)
			continue;

		if (!smb_is_same_user(sr->user_cr, of->f_cr))
			continue;

		mutex_enter(&of->f_mutex);
		if (of->f_state == SMB_OFILE_STATE_ORPHANED ||
		    of->f_state == SMB_OFILE_STATE_SAVE_DH) {
			of->f_state = SMB_OFILE_STATE_EXPIRED;
			/* inline smb_ofile_hold_internal() */
			of->f_refcnt++;
			smb_llist_post(&node->n_ofile_list,
			    of, smb2_dh_expire);
		}
		mutex_exit(&of->f_mutex);
	}

	smb_llist_exit(&node->n_ofile_list);
}

/*
 * Called for each orphaned DH during shutdown.
 * Clean out any in-memory state, but leave any
 * on-disk persistent handle state in place.
 */
static void
smb2_dh_cleanup(void *arg)
{
	smb_ofile_t *of = (smb_ofile_t *)arg;
	smb_node_t *strnode;
	struct nvlist *nvl;

	/*
	 * Intentionally skip smb2_dh_close_persistent by
	 * clearing dh_nvfile before smb_ofile_close().
	 */
	mutex_enter(&of->dh_nvlock);
	strnode = of->dh_nvfile;
	of->dh_nvfile = NULL;
	nvl = of->dh_nvlist;
	of->dh_nvlist = NULL;
	mutex_exit(&of->dh_nvlock);

	if (nvl != NULL)
		nvlist_free(nvl);

	if (strnode != NULL)
		smb_node_release(strnode);

	smb_ofile_close(of, 0);
	smb_ofile_release(of);
}

/*
 * Clean out durable handles during shutdown.
 *
 * Like, smb2_durable_timers but cleanup only in-memory state,
 * and leave any persistent state there for later reconnect.
 */
void
smb2_dh_shutdown(smb_server_t *sv)
{
	static const smb_oplock_grant_t og0 = { 0 };
	smb_hash_t *hash;
	smb_llist_t *bucket;
	smb_ofile_t *of;
	int i;

	hash = sv->sv_persistid_ht;

	for (i = 0; i < hash->num_buckets; i++) {
		bucket = &hash->buckets[i].b_list;
		smb_llist_enter(bucket, RW_READER);
		of = smb_llist_head(bucket);
		while (of != NULL) {
			SMB_OFILE_VALID(of);
			mutex_enter(&of->f_mutex);

			switch (of->f_state) {
			case SMB_OFILE_STATE_ORPHANED:
			case SMB_OFILE_STATE_SAVE_DH:
				of->f_state = SMB_OFILE_STATE_EXPIRED;
				/* inline smb_ofile_hold_internal() */
				of->f_refcnt++;
				smb_llist_post(bucket, of, smb2_dh_cleanup);
				break;

			default:
				/*
				 * Should not be possible, but try to
				 * make this zombie ofile harmless.
				 */
				cmn_err(CE_NOTE, "!dh_shutdown found "
				    "of = %p with invalid state = %d",
				    (void *)of, of->f_state);
				DTRACE_PROBE1(bad_ofile, smb_ofile_t *, of);
				ASSERT(0);
				of->f_oplock = og0;
				break;
			}
			mutex_exit(&of->f_mutex);
			of = smb_llist_next(bucket, of);
		}
		smb_llist_exit(bucket);
	}

#ifdef	DEBUG
	for (i = 0; i < hash->num_buckets; i++) {
		bucket = &hash->buckets[i].b_list;
		smb_llist_enter(bucket, RW_READER);
		of = smb_llist_head(bucket);
		while (of != NULL) {
			SMB_OFILE_VALID(of);
			cmn_err(CE_NOTE, "dh_shutdown leaked of=%p",
			    (void *)of);
			of = smb_llist_next(bucket, of);
		}
		smb_llist_exit(bucket);
	}
#endif	// DEBUG
}

uint32_t
smb2_fsctl_set_resilient(smb_request_t *sr, smb_fsctl_t *fsctl)
{
	uint32_t timeout;
	smb_ofile_t *of = sr->fid_ofile;

	/*
	 * Note: The spec does not explicitly prohibit resilient directories
	 * the same way it prohibits durable directories. We prohibit them
	 * anyway as a simplifying assumption, as there doesn't seem to be
	 * much use for it. (HYPER-V only seems to use it on files anyway)
	 */
	if (fsctl->InputCount < 8 || !smb_node_is_file(of->f_node))
		return (NT_STATUS_INVALID_PARAMETER);

	(void) smb_mbc_decodef(fsctl->in_mbc, "l4.",
	    &timeout); /* milliseconds */

	if (smb2_enable_dh == 0)
		return (NT_STATUS_NOT_SUPPORTED);

	/*
	 * The spec wants us to return INVALID_PARAMETER if the timeout
	 * is too large, but we have no way of informing the client
	 * what an appropriate timeout is, so just set the timeout to
	 * our max and return SUCCESS.
	 */
	if (timeout == 0)
		timeout = smb2_res_def_timeout;
	if (timeout > smb2_res_max_timeout)
		timeout = smb2_res_max_timeout;

	mutex_enter(&of->f_mutex);
	of->dh_vers = SMB2_RESILIENT;
	of->dh_timeout_offset = MSEC2NSEC(timeout);
	mutex_exit(&of->f_mutex);

	return (NT_STATUS_SUCCESS);
}
