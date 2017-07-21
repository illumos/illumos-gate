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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * SMB2 Durable Handle support
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/fcntl.h>
#include <sys/nbmlock.h>
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
 */
boolean_t
smb_dh_should_save(smb_ofile_t *of)
{
	ASSERT(MUTEX_HELD(&of->f_mutex));
	ASSERT(of->dh_vers != SMB2_NOT_DURABLE);

	if (of->f_user->preserve_opens == SMB2_DH_PRESERVE_NONE)
		return (B_FALSE);

	if (of->f_user->preserve_opens == SMB2_DH_PRESERVE_ALL)
		return (B_TRUE);

	switch (of->dh_vers) {
	case SMB2_RESILIENT:
		return (B_TRUE);

	case SMB2_DURABLE_V2:
		if (of->dh_persist)
			return (B_TRUE);
		/* FALLTHROUGH */
	case SMB2_DURABLE_V1:
		/* IS durable (v1 or v2) */
		if ((of->f_oplock.og_state & (OPLOCK_LEVEL_BATCH |
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

	smb_llist_enter(&tree->t_ofile_list, RW_WRITER);
	smb_llist_insert_tail(&tree->t_ofile_list, of);
	smb_llist_exit(&tree->t_ofile_list);
	atomic_inc_32(&tree->t_open_files);
	atomic_inc_32(&sr->session->s_file_cnt);

	/*
	 * The ofile is now in the caller's session & tree.
	 *
	 * In case smb_ofile_hold or smb_oplock_send_brk() are
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

	smb_ofile_close(of, 0);
	smb_ofile_release(of);
}

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
			if (of->f_state != SMB_OFILE_STATE_ORPHANED)
				continue;

			mutex_enter(&of->f_mutex);
			/* STATE_ORPHANED implies dh_expire_time != 0 */
			if (of->f_state == SMB_OFILE_STATE_ORPHANED &&
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
 * Clean out durable handles during shutdown.
 * Like, smb2_durable_timers but expire all,
 * and make sure the hash buckets are empty.
 */
void
smb2_dh_shutdown(smb_server_t *sv)
{
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
				of->f_state = SMB_OFILE_STATE_EXPIRED;
				/* inline smb_ofile_hold_internal() */
				of->f_refcnt++;
				smb_llist_post(bucket, of, smb2_dh_expire);
				break;
			default:
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
smb2_fsctl_resiliency(smb_request_t *sr, smb_fsctl_t *fsctl)
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
