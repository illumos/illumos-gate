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

/*
 * Common code for tree connections.
 */

#include <sys/errno.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_door_svc.h>


#define	SMB_TREE_EMSZ		64

#define	ADMINISTRATORS_SID	"S-1-5-32-544"

int smb_tcon_mute = 0;


int smbsr_setup_share(struct smb_request *, char *, int32_t, char *);
void smbsr_share_report(struct smb_request *, char *, char *, char *);
int smb_get_stype(const char *, const char *, int32_t *);


/*
 * smbsr_connect_tree
 *
 * Set up a share. A Uniform Naming Convention (UNC) string is suppose to
 * be in the form: \\HOST\SHARENAME. A sharename alone is also acceptable.
 * We don't actually audit the host, we just ensure that the \ are present
 * and extract the share name. Share names are case insensitive so we map
 * the share name to lower-case. So it is important that all internal
 * mechanisms (user interface, etc. use lower-case names.
 */
int
smbsr_connect_tree(struct smb_request *sr)
{
	char errmsg[SMB_TREE_EMSZ];
	char *sharename;
	char *access_msg;
	int32_t stype;
	DWORD status;
	int rc;

	errmsg[0] = '\0';
	(void) utf8_strlwr(sr->arg.tcon.path);
	sharename = sr->arg.tcon.path;

	if (sharename[0] == '\\') {
		/*
		 * Looks like a UNC path, make sure the format is correct.
		 */
		if (sharename[1] != '\\') {
			smbsr_error(sr, 0, ERRSRV, ERRinvnetname);
			/* NOTREACHED */
		}

		if ((sharename = strchr(sharename+2, '\\')) == 0) {
			smbsr_error(sr, 0, ERRSRV, ERRinvnetname);
			/* NOTREACHED */
		}

		++sharename;
	} else if (strchr(sharename, '\\')) {
		/*
		 * This should be a sharename: no embedded '\' allowed.
		 */
		smbsr_error(sr, 0, ERRSRV, ERRinvnetname);
		/* NOTREACHED */
	}

	if (smb_get_stype(sharename, sr->arg.tcon.service, &stype) != 0) {
		smbsr_error(sr, NT_STATUS_BAD_DEVICE_TYPE,
		    ERRDOS, ERROR_BAD_DEV_TYPE);
		/* NOTREACHED */
	}

	if ((rc = smbsr_setup_share(sr, sharename, stype, errmsg)) != 0) {
		access_msg = "access denied";
		smbsr_share_report(sr, sharename, access_msg, errmsg);

		/*
		 * Windows 2000 may try to connect to user shares using
		 * an anonymous IPC connection.  NT returns access denied.
		 */
		status = (rc == ERRaccess) ? NT_STATUS_ACCESS_DENIED : 0;
		smbsr_error(sr, status, ERRSRV, rc);
		/* NOTREACHED */
	}

	if (STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		if (SMB_TREE_IS_READ_ONLY(sr))
			access_msg = "ro access granted";
		else
			access_msg = "rw access granted";

		smbsr_share_report(sr, sharename, access_msg, errmsg);
	}

	return (rc);
}


/*
 * smbsr_share_report
 *
 * Report share access result to syslog.
 */
/*ARGSUSED*/
void
smbsr_share_report(struct smb_request *sr, char *sharename,
    char *access_msg, char *errmsg)
{
	smb_user_t *user;

	user = sr->uid_user;
	ASSERT(user);

	if (smb_tcon_mute)
		return;

	if (user->u_name) {
		/*
		 * Only report normal users, i.e. ignore W2K misuse
		 * of the IPC connection by filtering out internal
		 * names such as nobody and root.
		 */
		if ((strcmp(user->u_name, "root") == 0) ||
		    (strcmp(user->u_name, "nobody") == 0)) {
			return;
		}
	}

	cmn_err(CE_NOTE, "smbd[%s\\%s]: %s %s",
	    user->u_domain, user->u_name, sharename, access_msg);
}

/*
 * smbsr_setup_share
 *
 * This is where the real of setting up share is done.
 * Note that ambiguities are resolved by assuming that a directory
 * is being requested.
 *
 * Returns 0 on success or a non-zero error code on failure.
 */
int
smbsr_setup_share(struct smb_request *sr, char *sharename, int32_t stype,
    char *errmsg)
{
	smb_node_t		*dir_snode = NULL;
	smb_node_t		*snode = NULL;
	char			last_component[MAXNAMELEN];
	smb_tree_t		*tree;
	char			*resource;
	uint16_t		access = SMB_TREE_READ_WRITE;
	int			rc;
	lmshare_info_t 		si;
	nt_sid_t		*sid;
	fsvol_attr_t		vol_attr;
	smb_attr_t		attr;
	int			is_admin;
	smb_user_t		*user = sr->uid_user;
	cred_t			*u_cred;

	ASSERT(user);
	u_cred = user->u_cred;
	ASSERT(u_cred);

	bzero(&si, sizeof (lmshare_info_t));

	/*
	 * XXX Host based access control check to go here.
	 */

	if (STYPE_ISIPC(stype)) {
		if ((user->u_flags & SMB_USER_FLAG_IPC) &&
		    smb_info.si.skc_restrict_anon) {
			(void) strlcpy(errmsg, "anonymous access restricted",
			    SMB_TREE_EMSZ);
			return (ERRaccess);
		}

		bzero(&vol_attr, sizeof (fsvol_attr_t));
		resource = sharename;
		sr->arg.tcon.service = "IPC";

		tree = smb_tree_connect(sr->uid_user, access,
		    sharename, resource, stype, 0, &vol_attr);

		if (tree == NULL)
			return (ERRaccess);

		sr->smb_tid = tree->t_tid;
		sr->tid_tree = tree;
		return (0);
	}

	/*
	 * From here on we can assume that this is a disk share.
	 */
	ASSERT(STYPE_ISDSK(stype));

	if (user->u_flags & SMB_USER_FLAG_IPC) {
		(void) strlcpy(errmsg, "IPC only", SMB_TREE_EMSZ);
		return (ERRaccess);
	}

	/*
	 * Handle the default administration shares: C$, D$ etc.
	 * Only a user with admin rights is allowed to map these
	 * shares.
	 */
	if ((is_admin = lmshrd_is_admin(sharename)) == NERR_InternalError) {
		(void) strlcpy(errmsg, "internal error", SMB_TREE_EMSZ);
		return (ERRaccess);
	}

	if (is_admin) {
		sid = nt_sid_strtosid(ADMINISTRATORS_SID);
		if (sid) {
			rc = smb_cred_is_member(u_cred, sid);
			MEM_FREE("smbsrv", sid);
			if (rc == 0) {
				(void) strlcpy(errmsg,
				    "not administrator", SMB_TREE_EMSZ);
				return (ERRaccess);
			}
		}
	}

	if (lmshrd_getinfo(sharename, &si) != NERR_Success) {
		(void) strlcpy(errmsg, "share not found", SMB_TREE_EMSZ);
		return (ERRinvnetname);
	}

	resource = si.directory;
	sr->arg.tcon.service = "A:";

#ifdef HOST_ACCESS
	/*
	 * XXX This needs some sharemgr work
	 */
	if (hostaccess == APRV_ACC_RO)
		access = SMB_TREE_READ_ONLY;
#endif /* HOST_ACCESS */

	/*
	 * No password or password OK. Now check that the directory
	 * actually exists.
	 *
	 * The snode reference from smb_pathname_reduce() will not be
	 * released in this routine (except in an error path) because
	 * trees need a reference to their root node.  The reference
	 * will be released upon tree deallocation.
	 */

	rc = smb_pathname_reduce(sr, u_cred, resource, 0, 0, &dir_snode,
	    last_component);

	if (rc) {
		(void) strlcpy(errmsg, "smb_pathname_reduce", SMB_TREE_EMSZ);
		return (ERRinvnetname);
	}

	rc = smb_fsop_lookup(sr, u_cred, SMB_FOLLOW_LINKS, 0, dir_snode,
	    last_component, &snode, &attr, 0, 0);

	smb_node_release(dir_snode);

	if (rc) {
		(void) strlcpy(errmsg, "smb_fsop_lookup", SMB_TREE_EMSZ);
		rc = ERRinvnetname;
		goto error_out;
	}

	if ((rc = fsd_getattr(&snode->tree_fsd, &vol_attr)) != 0) {
		(void) strlcpy(errmsg, "fsd_getattr", SMB_TREE_EMSZ);
		rc = ERRinvnetname;
		goto error_out;
	}

	tree = smb_tree_connect(sr->uid_user, access,
	    sharename, resource, stype, snode, &vol_attr);

	if (tree == NULL) {
		rc = ERRaccess;
		goto error_out;
	}

	sr->smb_tid = tree->t_tid;
	sr->tid_tree = tree;
	return (0);

error_out:
	if (snode)
		smb_node_release(snode);

	return (rc);
}

/*
 * smb_get_stype
 *
 * Map the service to a resource type.  Valid values for service
 * (CIFS/1.0 section 4.1.4) are:
 *
 *	A:      Disk share
 *	LPT1:   Printer
 *	IPC     Named pipe
 *	COMM    Communications device
 *	?????   Any type of device (wildcard)
 *
 * We support IPC and disk shares; anything else is currently treated
 * as an error.  IPC$ is reserved as the named pipe share.
 */
int
smb_get_stype(const char *sharename, const char *service, int32_t *stype_ret)
{
	const char *any = "?????";

	if ((strcmp(service, any) == 0) || (strcasecmp(service, "IPC") == 0)) {
		if (strcasecmp(sharename, "IPC$") == 0) {
			*stype_ret = STYPE_IPC;
			return (0);
		}
	}

	if ((strcmp(service, any) == 0) || (strcasecmp(service, "A:") == 0)) {
		if (strcasecmp(sharename, "IPC$") == 0)
			return (-1);

		*stype_ret = STYPE_DISKTREE;
		return (0);
	}

	return (-1);
}

/*
 * smbsr_rq_notify
 *
 * Notify all requests, except sr, associated with the specified tree
 * that it's time to complete.
 * It's assumed that the tree has already been clipped from the session
 * list so that no new requests can be added to the list while we're in
 * here.
 *
 * Note that sr may be null.
 *
 * Returns:
 */
void
smbsr_rq_notify(smb_request_t *sr, smb_session_t *session, smb_tree_t *tree)
{
	struct smb_request	*asr;

	smb_slist_enter(&session->s_req_list);
	asr = smb_slist_head(&session->s_req_list);
	while (asr) {
		ASSERT(asr->sr_magic == SMB_REQ_MAGIC);
		if ((asr != sr) && (asr->tid_tree == tree)) {
			smb_request_cancel(asr);
		}
		asr = smb_slist_next(&session->s_req_list, asr);
	}
	smb_slist_exit(&session->s_req_list);
}
