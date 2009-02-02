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
 * General Structures Layout
 * -------------------------
 *
 * This is a simplified diagram showing the relationship between most of the
 * main structures.
 *
 * +-------------------+
 * |     SMB_INFO      |
 * +-------------------+
 *          |
 *          |
 *          v
 * +-------------------+       +-------------------+      +-------------------+
 * |     SESSION       |<----->|     SESSION       |......|      SESSION      |
 * +-------------------+       +-------------------+      +-------------------+
 *          |
 *          |
 *          v
 * +-------------------+       +-------------------+      +-------------------+
 * |       USER        |<----->|       USER        |......|       USER        |
 * +-------------------+       +-------------------+      +-------------------+
 *          |
 *          |
 *          v
 * +-------------------+       +-------------------+      +-------------------+
 * |       TREE        |<----->|       TREE        |......|       TREE        |
 * +-------------------+       +-------------------+      +-------------------+
 *      |         |
 *      |         |
 *      |         v
 *      |     +-------+       +-------+      +-------+
 *      |     | OFILE |<----->| OFILE |......| OFILE |
 *      |     +-------+       +-------+      +-------+
 *      |
 *      |
 *      v
 *  +-------+       +------+      +------+
 *  | ODIR  |<----->| ODIR |......| ODIR |
 *  +-------+       +------+      +------+
 *
 *
 * Odir State Machine
 * ------------------
 *
 *    +-------------------------+
 *    |  SMB_ODIR_STATE_OPEN    |<----------- open / creation
 *    +-------------------------+
 *		    |
 *		    | close
 *		    |
 *		    v
 *    +-------------------------+
 *    | SMB_ODIR_STATE_CLOSING  |
 *    +-------------------------+
 *		    |
 *		    | last release
 *		    |
 *		    v
 *    +-------------------------+
 *    | SMB_ODIR_STATE_CLOSED   |----------> deletion
 *    +-------------------------+
 *
 *
 * SMB_ODIR_STATE_OPEN
 * - the odir exists in the list of odirs of its tree.
 * - references will be given out if the odir is looked up
 * - if a close is received the odir will transition to
 *   SMB_ODIR_STATE_CLOSING.
 *
 * SMB_ODIR_STATE_CLOSING
 * - the odir exists in the list of odirs of its tree.
 * - references will NOT be given out if the odir is looked up.
 * - when the last reference is released (refcnt == 0) the
 *   odir will transition to SMB_ODIR_STATE_CLOSED.
 *
 * SMB_ODIR_STATE_CLOSED
 * - the odir exists in the list of odirs of its tree.
 * - there are no users of the odir (refcnt == 0)
 * - references will NOT be given out if the odir is looked up.
 * - the odir is being removed from the tree's list and deleted.
 *
 * Comments
 * --------
 *    The state machine of the odir structures is controlled by 3 elements:
 *      - The list of odirs of the tree it belongs to.
 *      - The mutex embedded in the structure itself.
 *      - The reference count.
 *
 *    There's a mutex embedded in the odir structure used to protect its fields
 *    and there's a lock embedded in the list of odirs of a tree. To
 *    increment or to decrement the reference count the mutex must be entered.
 *    To insert the odir into the list of odirs of the tree and to remove
 *    the odir from it, the lock must be entered in RW_WRITER mode.
 *
 *    In order to avoid deadlocks, when both (mutex and lock of the odir
 *    list) have to be entered, the lock must be entered first.
 *
 *
 * Odir Interface
 * ---------------
 * odid = smb_odir_open(pathname)
 *	Create an odir representing the directory specified in pathname and
 *	add it into the tree's list of odirs.
 *	Return an identifier (odid) uniquely identifying the created odir.
 *
 * smb_odir_openat(smb_node_t *unode)
 *	Create an odir representing the extended attribute directory
 *	associated with the file (or directory) represented by unode
 *	and add it into the tree's list of odirs.
 *	Return an identifier (odid) uniquely identifying the created odir.
 *
 * smb_odir_t *odir = smb_tree_lookup_odir(odid)
 *	Find the odir corresponding to the specified odid in the tree's
 *	list of odirs.
 *
 * smb_odir_read(..., smb_odirent_t *odirent)
 *	Find the next directory entry in the odir and return it in odirent.
 *
 * smb_odir_read_fileinfo(..., smb_fileinfo_t *)
 *	Find the next directory entry in the odir. Return the details of
 *	the directory entry in smb_fileinfo_t. (See odir internals below)
 *
 * smb_odir_read_stream_info(..., smb_streaminfo_t *)
 *	Find the next named stream entry in the odir. Return the details of
 *	the named stream in smb_streaminfo_t.
 *
 * smb_odir_release(smb_odir_t *odir)
 *	Release the hold on the odir, obtained by lookup.
 *
 * smb_odir_close(smb_odir_t *odir)
 *	Close the odir and remove it from the tree's list of odirs.
 *
 *
 * Odir Internals
 * --------------
 * The odir object represent an open directory search. Each read operation
 * provides the caller with a structure containing information  pertaining
 * to the next directory entry that matches the search criteria, namely
 * the filename or match pattern and, in the case of smb_odir_read_fileinfo(),
 * the search attributes.
 *
 * The odir maintains a buffer (d_buf) of directory entries read from
 * the filesystem via a vop_readdir. The buffer is populated when a read
 * request (smb_odir_next_odirent) finds that the buffer is empty or that
 * the end of the buffer has been reached, and also when a new client request
 * (find next) begins.
 *
 * The data in d_buf (that which is returned from the file system) can
 * be in one of two formats. If the file system supports extended directory
 * entries we request that the data be returned as edirent_t structures. If
 * it does not the data will be returned as dirent64_t structures. For
 * convenience, when the next directory entry is read from d_buf by
 * smb_odir_next_odirent it is translated into an smb_odirent_t.
 *
 * smb_odir_read_fileinfo
 * The processing required to obtain the information to populate the caller's
 * smb_fileinfo_t differs depending upon whether the directory search is for a
 * single specified filename or for multiple files matching a search pattern.
 * Thus smb_odir_read_fileinfo uses two static functions:
 * smb_odir_single_fileinfo - obtains the smb_fileinfo_t info for the single
 * filename as specified in smb_odir_open request.
 * smb_odir_wildcard_fileinfo - obtains the smb_fileinfo_t info for the filename
 * returned from the smb_odir_next_odirent. This is called in a loop until
 * an entry matching the search criteria is found or no more entries exist.
 *
 * If a directory entry is a VLNK, the name returned in the smb_fileinfo_t
 * is the name of the directory entry but the attributes are the attribites
 * of the file that is the target of the link. If the link target cannot
 * be found the attributes returned are the attributes of the link itself.
 *
 * smb_odir_read_stream_info
 * In order for an odir to provide information about stream files it
 * must be opened with smb_odir_openat(). smb_odir_read_streaminfo() can
 * then be used to obtain the name and size of named stream files.
 *
 * Resuming a Search
 * -----------------
 * A directory search often consists of multiple client requests: an initial
 * find_first request followed by zero or more find_next requests and a
 * find_close request.
 * The find_first request will open and lookup the odir, read its desired
 * number of entries from the odir, then release the odir and return.
 * A find_next request will lookup the odir and read its desired number of
 * entries from the odir, then release the odir and return.
 * At the end of the search the find_close request will close the odir.
 *
 * In order to be able to resume a directory search (find_next) the odir
 * provides the capability for the caller to save one or more resume points
 * (cookies) at the end of a request, and to specify which resume point
 * (cookie) to restart from at the beginning of the next search.
 *	smb_odir_save_cookie(..., cookie)
 *	smb_odir_resume_at(smb_odir_resume_t *resume)
 * A search can be resumed at a specified resume point (cookie), the resume
 * point (cookie) stored at a specified index in the d_cookies array, or
 * a specified filename. The latter (specified filename) is not yet supported.
 *
 * See smb_search, smb_find, smb_find_unique, and smb_trans2_find for details
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <sys/extdirent.h>

/* static functions */
static smb_odir_t *smb_odir_create(smb_request_t *, smb_node_t *,
    char *, uint16_t);
static void smb_odir_delete(smb_odir_t *);
static int smb_odir_single_fileinfo(smb_request_t *, smb_odir_t *,
    smb_fileinfo_t *);
static int smb_odir_wildcard_fileinfo(smb_request_t *, smb_odir_t *,
    smb_odirent_t *, smb_fileinfo_t *);
static int smb_odir_next_odirent(smb_odir_t *, smb_odirent_t *);
static boolean_t smb_odir_lookup_link(smb_request_t *, smb_odir_t *, char *,
    smb_node_t **, smb_attr_t *);


/*
 * smb_odir_open
 *
 * Create an odir representing the directory specified in pathname.
 *
 * Returns:
 * odid - Unique identifier of newly created odir.
 *    0 - error, error details set in sr.
 */
uint16_t
smb_odir_open(smb_request_t *sr, char *path, uint16_t sattr)
{
	int		rc;
	smb_tree_t	*tree;
	smb_node_t	*dnode;
	char		pattern[MAXNAMELEN];
	smb_odir_t 	*od;

	ASSERT(sr);
	ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
	ASSERT(sr->tid_tree);
	ASSERT(sr->tid_tree->t_magic == SMB_TREE_MAGIC);

	tree = sr->tid_tree;

	rc = smb_pathname_reduce(sr, sr->user_cr, path,
	    tree->t_snode, tree->t_snode, &dnode, pattern);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (0);
	}

	if (dnode->vp->v_type != VDIR) {
		smbsr_error(sr, NT_STATUS_OBJECT_PATH_NOT_FOUND,
		    ERRDOS, ERROR_PATH_NOT_FOUND);
		smb_node_release(dnode);
		return (0);
	}

	if (smb_fsop_access(sr, sr->user_cr, dnode, FILE_LIST_DIRECTORY) != 0) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		smb_node_release(dnode);
		return (0);
	}

	od = smb_odir_create(sr, dnode, pattern, sattr);
	smb_node_release(dnode);
	return (od ? od->d_odid : 0);
}

/*
 * smb_odir_openat
 *
 * Create an odir representing the extended attribute directory
 * associated with the file (or directory) represented by unode.
 *
 * Returns:
 * odid - Unique identifier of newly created odir.
 *    0 - error, error details set in sr.
 */
uint16_t
smb_odir_openat(smb_request_t *sr, smb_node_t *unode)
{
	int		rc;
	vnode_t		*xattr_dvp;
	smb_odir_t	*od;
	cred_t		*cr;
	char		pattern[SMB_STREAM_PREFIX_LEN + 2];

	smb_node_t	*xattr_dnode;
	smb_attr_t	tmp_attr;

	ASSERT(sr);
	ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
	ASSERT(unode);
	ASSERT(unode->n_magic == SMB_NODE_MAGIC);

	if (SMB_TREE_CONTAINS_NODE(sr, unode) == 0) {
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
		    ERRDOS, ERROR_ACCESS_DENIED);
		return (0);
	}
	cr = sr->user_cr;

	/* find the xattrdir vnode */
	rc = smb_vop_lookup_xattrdir(unode->vp, &xattr_dvp, LOOKUP_XATTR, cr);
	if (rc != 0) {
		smbsr_errno(sr, rc);
		return (0);
	}

	/* lookup the xattrdir's smb_node */
	xattr_dnode = smb_node_lookup(sr, NULL, cr, xattr_dvp, XATTR_DIR,
	    unode, NULL, &tmp_attr);
	VN_RELE(xattr_dvp);
	if (xattr_dnode == NULL) {
		smbsr_error(sr, NT_STATUS_NO_MEMORY,
		    ERRDOS, ERROR_NOT_ENOUGH_MEMORY);
		return (0);
	}

	(void) snprintf(pattern, sizeof (pattern), "%s*", SMB_STREAM_PREFIX);
	od = smb_odir_create(sr, xattr_dnode, pattern, SMB_SEARCH_ATTRIBUTES);
	smb_node_release(xattr_dnode);
	if (od == NULL)
		return (0);

	od->d_xat = B_TRUE;
	return (od->d_odid);
}

/*
 * smb_odir_hold
 */
boolean_t
smb_odir_hold(smb_odir_t *od)
{
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);

	mutex_enter(&od->d_mutex);
	if (od->d_state != SMB_ODIR_STATE_OPEN) {
		mutex_exit(&od->d_mutex);
		return (B_FALSE);
	}

	od->d_refcnt++;
	mutex_exit(&od->d_mutex);
	return (B_TRUE);
}

/*
 * smb_odir_release
 *
 * If the odir is in SMB_ODIR_STATE_CLOSING and this release
 * results in a refcnt of 0, the odir may be removed from
 * the tree's list of odirs and deleted.  The odir's state is
 * set to SMB_ODIR_STATE_CLOSED prior to exiting the mutex and
 * deleting it. This ensure that nobody else can ontain a reference
 * to it while we are deleting it.
 */
void
smb_odir_release(smb_odir_t *od)
{
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);

	mutex_enter(&od->d_mutex);
	ASSERT(od->d_refcnt);

	switch (od->d_state) {
	case SMB_ODIR_STATE_OPEN:
		od->d_refcnt--;
		break;
	case SMB_ODIR_STATE_CLOSING:
		od->d_refcnt--;
		if (od->d_refcnt == 0) {
			od->d_state = SMB_ODIR_STATE_CLOSED;
			mutex_exit(&od->d_mutex);
			smb_odir_delete(od);
			return;
		}
		break;
	case SMB_ODIR_STATE_CLOSED:
		break;
	default:
		ASSERT(0);
		break;
	}

	mutex_exit(&od->d_mutex);
}

/*
 * smb_odir_close
 */
void
smb_odir_close(smb_odir_t *od)
{
	ASSERT(od);
	ASSERT(od->d_refcnt);

	mutex_enter(&od->d_mutex);
	if (od->d_state != SMB_ODIR_STATE_OPEN) {
		mutex_exit(&od->d_mutex);
		return;
	}
	od->d_state = SMB_ODIR_STATE_CLOSING;
	mutex_exit(&od->d_mutex);

	smb_odir_release(od);
}

/*
 * smb_odir_read
 *
 * Find the next directory entry matching the search pattern.
 * No search attribute matching is performed.
 *
 * Returns:
 *  0 - success.
 *      - If a matching entry was found eof will be B_FALSE and
 *        odirent will be populated.
 *      - If there are no matching entries eof will be B_TRUE.
 * -1 - error, error details set in sr.
 */
int
smb_odir_read(smb_request_t *sr, smb_odir_t *od,
    smb_odirent_t *odirent, boolean_t *eof)
{
	int rc;

	ASSERT(sr);
	ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);
	ASSERT(odirent);

	mutex_enter(&od->d_mutex);

	ASSERT(od->d_state == SMB_ODIR_STATE_OPEN);
	if (od->d_state != SMB_ODIR_STATE_OPEN) {
		mutex_exit(&od->d_mutex);
		return (-1);
	}

	for (;;) {
		if ((rc = smb_odir_next_odirent(od, odirent)) != 0)
			break;
		if (smb_match_name(odirent->od_ino, odirent->od_name,
		    od->d_pattern, od->d_ignore_case))
			break;
	}

	mutex_exit(&od->d_mutex);

	switch (rc) {
	case 0:
		*eof = B_FALSE;
		return (0);
	case ENOENT:
		*eof = B_TRUE;
		return (0);
	default:
		smbsr_errno(sr, rc);
		return (-1);
	}
}

/*
 * smb_odir_read_fileinfo
 *
 * Find the next directory entry matching the search pattern
 * and attributes: od->d_pattern and od->d_sattr.
 *
 * If the search pattern specifies a single filename call
 * smb_odir_single_fileinfo to get the file attributes and
 * populate the caller's smb_fileinfo_t.
 *
 * If the search pattern contains wildcards call smb_odir_next_odirent
 * to get the next directory entry then. Repeat until a matching
 * filename is found. Call smb_odir_wildcard_fileinfo to get the
 * file attributes and populate the caller's smb_fileinfo_t.
 * This is repeated until a file matching the search criteria is found.
 *
 * Returns:
 *  0 - success.
 *      - If a matching entry was found eof will be B_FALSE and
 *        fileinfo will be populated.
 *      - If there are no matching entries eof will be B_TRUE.
 * -1 - error, error details set in sr.
 */
int
smb_odir_read_fileinfo(smb_request_t *sr, smb_odir_t *od,
    smb_fileinfo_t *fileinfo, boolean_t *eof)
{
	int		rc;
	smb_odirent_t	*odirent;

	ASSERT(sr);
	ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);
	ASSERT(fileinfo);

	mutex_enter(&od->d_mutex);

	ASSERT(od->d_state == SMB_ODIR_STATE_OPEN);
	if (od->d_state != SMB_ODIR_STATE_OPEN) {
		mutex_exit(&od->d_mutex);
		return (-1);
	}

	if (!od->d_wildcards) {
		if (od->d_eof)
			rc = ENOENT;
		else
			rc = smb_odir_single_fileinfo(sr, od, fileinfo);
		od->d_eof = B_TRUE;
	} else {
		odirent = kmem_alloc(sizeof (smb_odirent_t), KM_SLEEP);
		for (;;) {
			bzero(fileinfo, sizeof (smb_fileinfo_t));
			if ((rc = smb_odir_next_odirent(od, odirent)) != 0)
				break;

			if (!smb_match_name(odirent->od_ino, odirent->od_name,
			    od->d_pattern, od->d_ignore_case))
				continue;

			rc = smb_odir_wildcard_fileinfo(sr, od, odirent,
			    fileinfo);
			if (rc == 0)
				break;
		}
		kmem_free(odirent, sizeof (smb_odirent_t));
	}
	mutex_exit(&od->d_mutex);

	switch (rc) {
	case 0:
		*eof = B_FALSE;
		return (0);
	case ENOENT:
		*eof = B_TRUE;
		return (0);
	default:
		smbsr_errno(sr, rc);
		return (-1);
	}
}


/*
 * smb_odir_read_streaminfo
 *
 * Find the next directory entry whose name begins with SMB_STREAM_PREFIX,
 * and thus represents an NTFS named stream.
 * No search attribute matching is performed.
 *
 * Returns:
 *  0 - success.
 *      - If a matching entry was found eof will be B_FALSE and
 *        sinfo will be populated.
 *      - If there are no matching entries eof will be B_TRUE.
 * -1 - error, error details set in sr.
 */
int
smb_odir_read_streaminfo(smb_request_t *sr, smb_odir_t *od,
    smb_streaminfo_t *sinfo, boolean_t *eof)
{
	int		rc;
	smb_odirent_t	*odirent;
	vnode_t		*vp;
	smb_attr_t	attr;

	ASSERT(sr);
	ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);
	ASSERT(sinfo);

	mutex_enter(&od->d_mutex);

	ASSERT(od->d_state == SMB_ODIR_STATE_OPEN);
	if (od->d_state != SMB_ODIR_STATE_OPEN) {
		mutex_exit(&od->d_mutex);
		return (-1);
	}

	/* Check that odir represents an xattr directory */
	if (!od->d_xat) {
		*eof = B_TRUE;
		mutex_exit(&od->d_mutex);
		return (0);
	}

	odirent = kmem_alloc(sizeof (smb_odirent_t), KM_SLEEP);

	for (;;) {
		bzero(sinfo, sizeof (smb_streaminfo_t));
		if ((rc = smb_odir_next_odirent(od, odirent)) != 0)
			break;

		if (strncmp(odirent->od_name, SMB_STREAM_PREFIX,
		    SMB_STREAM_PREFIX_LEN)) {
			continue;
		}

		/*
		 * since we only care about the size attribute we don't need to
		 * pass the vp of the unnamed stream file to smb_vop_getattr
		 */
		rc = smb_vop_lookup(od->d_dnode->vp, odirent->od_name, &vp,
		    NULL, 0, od->d_tree->t_snode->vp, od->d_user->u_cred);
		if (rc == 0) {
			rc = smb_vop_getattr(vp, NULL, &attr, 0,
			    od->d_user->u_cred);
			VN_RELE(vp);
		}

		if (rc == 0) {
			(void) strlcpy(sinfo->si_name,
			    odirent->od_name + SMB_STREAM_PREFIX_LEN,
			    sizeof (sinfo->si_name));
			sinfo->si_size = attr.sa_vattr.va_size;
			break;
		}
	}
	mutex_exit(&od->d_mutex);

	kmem_free(odirent, sizeof (smb_odirent_t));

	switch (rc) {
	case 0:
		*eof = B_FALSE;
		return (0);
	case ENOENT:
		*eof = B_TRUE;
		return (0);
	default:
		smbsr_errno(sr, rc);
		return (-1);
	}
}

/*
 * smb_odir_save_cookie
 *
 * Callers can save up to SMB_MAX_SEARCH cookies in the odir
 * to be used as resume points for a 'find next' request.
 */
void
smb_odir_save_cookie(smb_odir_t *od, int idx, uint32_t cookie)
{
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);
	ASSERT(idx >= 0 && idx < SMB_MAX_SEARCH);

	mutex_enter(&od->d_mutex);
	od->d_cookies[idx] = cookie;
	mutex_exit(&od->d_mutex);
}

/*
 * smb_odir_resume_at
 *
 * Searching can be resumed from:
 * - the cookie saved at a specified index (SMBsearch, SMBfind).
 * - a specified cookie (SMB_trans2_find)
 * - a specified filename (SMB_trans2_find) - NOT SUPPORTED.
 *   Defaults to continuing from where the last search ended.
 *
 * Continuation from where the last search ended (SMB_trans2_find)
 * is implemented by saving the last cookie at a specific index (0)
 * smb_odir_resume_at indicates a new request, so reset od->d_bufptr
 * and d_eof to force a vop_readdir.
 */
void
smb_odir_resume_at(smb_odir_t *od, smb_odir_resume_t *resume)
{
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);
	ASSERT(resume);

	mutex_enter(&od->d_mutex);

	switch (resume->or_type) {
		case SMB_ODIR_RESUME_IDX:
			ASSERT(resume->or_idx >= 0);
			ASSERT(resume->or_idx < SMB_MAX_SEARCH);

			if ((resume->or_idx < 0) ||
			    (resume->or_idx >= SMB_MAX_SEARCH)) {
				resume->or_idx = 0;
			}
			od->d_offset = od->d_cookies[resume->or_idx];
			break;
		case SMB_ODIR_RESUME_COOKIE:
			od->d_offset = resume->or_cookie;
			break;
		case SMB_ODIR_RESUME_FNAME:
		default:
			od->d_offset = od->d_cookies[0];
			break;
	}

	/* Force a vop_readdir to refresh d_buf */
	od->d_bufptr = NULL;
	od->d_eof = B_FALSE;

	mutex_exit(&od->d_mutex);
}


/* *** static functions *** */

/*
 * smb_odir_create
 * Allocate and populate an odir obect and add it to the tree's list.
 */
static smb_odir_t *
smb_odir_create(smb_request_t *sr, smb_node_t *dnode,
    char *pattern, uint16_t sattr)
{
	smb_odir_t	*od;
	smb_tree_t	*tree;
	uint16_t	odid;

	ASSERT(sr);
	ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
	ASSERT(sr->tid_tree);
	ASSERT(sr->tid_tree->t_magic == SMB_TREE_MAGIC);
	ASSERT(dnode);
	ASSERT(dnode->n_magic == SMB_NODE_MAGIC);

	tree = sr->tid_tree;

	if (smb_idpool_alloc(&tree->t_odid_pool, &odid)) {
		smbsr_error(sr, NT_STATUS_TOO_MANY_OPENED_FILES,
		    ERRDOS, ERROR_TOO_MANY_OPEN_FILES);
		return (NULL);
	}

	od = kmem_cache_alloc(tree->t_server->si_cache_odir, KM_SLEEP);
	bzero(od, sizeof (smb_odir_t));

	mutex_init(&od->d_mutex, NULL, MUTEX_DEFAULT, NULL);
	od->d_refcnt = 1;
	od->d_state = SMB_ODIR_STATE_OPEN;
	od->d_magic = SMB_ODIR_MAGIC;
	od->d_opened_by_pid = sr->smb_pid;
	od->d_session = tree->t_session;
	od->d_user = tree->t_user;
	od->d_tree = tree;
	od->d_dnode = dnode;
	smb_node_ref(dnode);
	od->d_odid = odid;
	od->d_sattr = sattr;
	(void) strlcpy(od->d_pattern, pattern, sizeof (od->d_pattern));
	od->d_wildcards = (smb_convert_unicode_wildcards(od->d_pattern) != 0);
	od->d_is_edp = vfs_has_feature(dnode->vp->v_vfsp, VFSFT_DIRENTFLAGS);
	od->d_ignore_case =
	    smb_tree_has_feature(tree, SMB_TREE_CASEINSENSITIVE);
	od->d_eof = B_FALSE;

	smb_llist_enter(&tree->t_odir_list, RW_WRITER);
	smb_llist_insert_tail(&tree->t_odir_list, od);
	smb_llist_exit(&tree->t_odir_list);

	atomic_inc_32(&tree->t_session->s_dir_cnt);
	return (od);
}

/*
 * smb_odir_delete
 *
 * Removal of the odir from the tree's list of odirs must be
 * done before any resources associated with the odir are
 * released.
 */
static void
smb_odir_delete(smb_odir_t *od)
{
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);
	ASSERT(od->d_state == SMB_ODIR_STATE_CLOSED);
	ASSERT(od->d_refcnt == 0);

	smb_llist_enter(&od->d_tree->t_odir_list, RW_WRITER);
	smb_llist_remove(&od->d_tree->t_odir_list, od);
	smb_llist_exit(&od->d_tree->t_odir_list);

	od->d_magic = 0;
	atomic_dec_32(&od->d_tree->t_session->s_dir_cnt);
	smb_node_release(od->d_dnode);
	smb_idpool_free(&od->d_tree->t_odid_pool, od->d_odid);
	mutex_destroy(&od->d_mutex);
	kmem_cache_free(od->d_tree->t_server->si_cache_odir, od);
}

/*
 * smb_odir_next_odirent
 *
 * Find the next directory entry in d_buf. If d_bufptr is NULL (buffer
 * is empty or we've reached the end of it), read the next set of
 * entries from the file system (vop_readdir).
 *
 * File systems which support VFSFT_EDIRENT_FLAGS will return the
 * directory entries as a buffer of edirent_t structure. Others will
 * return a buffer of dirent64_t structures.  For simplicity translate
 * the data into an smb_odirent_t structure.
 * The ed_name/d_name in d_buf is NULL terminated by the file system.
 *
 * Some file systems can have directories larger than SMB_MAXDIRSIZE.
 * If the odirent offset >= SMB_MAXDIRSIZE return ENOENT.
 *
 * Returns:
 *      0 - success. odirent is populated with the next directory entry
 * ENOENT - no more directory entries
 *  errno - error
 */
static int
smb_odir_next_odirent(smb_odir_t *od, smb_odirent_t *odirent)
{
	int		rc;
	int		reclen;
	int		eof;
	dirent64_t	*dp;
	edirent_t	*edp;

	ASSERT(MUTEX_HELD(&od->d_mutex));

	if (od->d_bufptr != NULL) {
		reclen = od->d_is_edp ?
		    od->d_edp->ed_reclen : od->d_dp->d_reclen;

		if (reclen == 0) {
			od->d_bufptr = NULL;
		} else {
			od->d_bufptr += reclen;
			if (od->d_bufptr >= od->d_buf + od->d_bufsize)
				od->d_bufptr = NULL;
		}
	}

	if (od->d_bufptr == NULL) {
		if (od->d_eof)
			return (ENOENT);

		od->d_bufsize = sizeof (od->d_buf);

		rc = smb_vop_readdir(od->d_dnode->vp, od->d_offset,
		    od->d_buf, &od->d_bufsize, &eof, od->d_user->u_cred);

		if ((rc == 0) && (od->d_bufsize == 0))
			rc = ENOENT;

		if (rc != 0) {
			od->d_bufptr = NULL;
			od->d_bufsize = 0;
			return (rc);
		}

		od->d_eof = (eof != 0);
		od->d_bufptr = od->d_buf;
	}

	od->d_offset = (od->d_is_edp) ? od->d_edp->ed_off : od->d_dp->d_off;
	if (od->d_offset >= SMB_MAXDIRSIZE) {
		od->d_bufptr = NULL;
		od->d_bufsize = 0;
		return (ENOENT);
	}

	if (od->d_is_edp) {
		edp = od->d_edp;
		odirent->od_ino = edp->ed_ino;
		odirent->od_eflags = edp->ed_eflags;
		(void) strlcpy(odirent->od_name, edp->ed_name,
		    sizeof (odirent->od_name));
	} else {
		dp = od->d_dp;
		odirent->od_ino = dp->d_ino;
		odirent->od_eflags = 0;
		(void) strlcpy(odirent->od_name, dp->d_name,
		    sizeof (odirent->od_name));
	}

	return (0);
}

/*
 * smb_odir_single_fileinfo
 *
 * Lookup the file identified by od->d_pattern.
 *
 * If the looked up file is a link, we attempt to lookup the link target
 * to use its attributes in place of those of the files's.
 * If we fail to lookup the target of the link we use the original
 * file's attributes.
 * Check if the attributes match the search attributes.
 *
 * Returns: 0 - success
 *     ENOENT - no match
 *      errno - error
 */
static int
smb_odir_single_fileinfo(smb_request_t *sr, smb_odir_t *od,
    smb_fileinfo_t *fileinfo)
{
	int		rc;
	smb_node_t	*fnode, *tgt_node;
	smb_attr_t	attr, tgt_attr, *fattr;
	ino64_t		ino;
	char		*name;
	uint32_t	dosattr;

	ASSERT(sr);
	ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);

	ASSERT(MUTEX_HELD(&od->d_mutex));
	bzero(fileinfo, sizeof (smb_fileinfo_t));

	rc = smb_fsop_lookup(sr, od->d_user->u_cred, 0, od->d_tree->t_snode,
	    od->d_dnode, od->d_pattern, &fnode, &attr, 0, 0);
	if (rc != 0)
		return (rc);

	name = fnode->od_name;

	(void) strlcpy(fileinfo->fi_name, name, sizeof (fileinfo->fi_name));
	ino = attr.sa_vattr.va_nodeid;
	(void) smb_mangle_name(ino, name,
	    fileinfo->fi_shortname, fileinfo->fi_name83, 0);

	/* follow link to get target node & attr */
	if ((fnode->vp->v_type == VLNK) &&
	    (smb_odir_lookup_link(sr, od, name, &tgt_node, &tgt_attr))) {
		smb_node_release(fnode);
		fnode = tgt_node;
		fattr = &tgt_attr;
	} else {
		fattr = &attr;
	}

	/* check search attributes */
	dosattr = smb_node_get_dosattr(fnode);
	if (!smb_sattr_check(dosattr, od->d_sattr, fileinfo->fi_name)) {
		smb_node_release(fnode);
		return (ENOENT);
	}

	fileinfo->fi_dosattr = dosattr;
	fileinfo->fi_nodeid = fattr->sa_vattr.va_nodeid;
	fileinfo->fi_size = smb_node_get_size(fnode, fattr);
	fileinfo->fi_alloc_size = fattr->sa_vattr.va_nblocks * DEV_BSIZE;
	fileinfo->fi_atime = fattr->sa_vattr.va_atime;
	fileinfo->fi_mtime = fattr->sa_vattr.va_mtime;
	fileinfo->fi_ctime = fattr->sa_vattr.va_ctime;
	if (fattr->sa_crtime.tv_sec)
		fileinfo->fi_crtime = fattr->sa_crtime;
	else
		fileinfo->fi_crtime = fattr->sa_vattr.va_mtime;

	smb_node_release(fnode);
	return (0);
}

/*
 * smb_odir_wildcard_fileinfo
 *
 * odirent contains a directory entry, obtained from a vop_readdir.
 * If a case conflict is identified the filename is mangled and the
 * shortname is used as 'name', in place of odirent->od_name. This
 * name will be used in the smb_fsop_lookup because smb_fsop_lookup
 * performs a case insensitive lookup if the tree is case insesitive,
 * so the mangled name is required in the case conflict scenario to
 * ensure the correct match.
 *
 * If the looked up file is a link, we attempt to lookup the link target
 * to use its attributes in place of those of the files's.
 * If we fail to lookup the target of the link we use the original
 * file's attributes.
 * Check if the attributes match the search attributes.
 *
 * Although some file systems can have directories larger than
 * SMB_MAXDIRSIZE smb_odir_next_odirent ensures that no offset larger
 * than SMB_MAXDIRSIZE is returned.  It is therefore safe to use the
 * offset as the cookie (uint32_t).
 *
 * Returns: 0 - success
 *     ENOENT - no match, proceed to next entry
 *      errno - error
 */
static int
smb_odir_wildcard_fileinfo(smb_request_t *sr, smb_odir_t *od,
    smb_odirent_t *odirent, smb_fileinfo_t *fileinfo)
{
	int		rc;
	smb_node_t	*fnode, *tgt_node;
	smb_attr_t	attr, tgt_attr, *fattr;
	char		*name;
	uint32_t	dosattr;
	boolean_t	case_conflict;

	ASSERT(sr);
	ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
	ASSERT(od);
	ASSERT(od->d_magic == SMB_ODIR_MAGIC);

	ASSERT(MUTEX_HELD(&od->d_mutex));
	bzero(fileinfo, sizeof (smb_fileinfo_t));

	case_conflict = ((od->d_ignore_case) &&
	    (odirent->od_eflags & ED_CASE_CONFLICT));
	(void) smb_mangle_name(odirent->od_ino, odirent->od_name,
	    fileinfo->fi_shortname, fileinfo->fi_name83, case_conflict);
	name = (case_conflict) ? fileinfo->fi_shortname : odirent->od_name;
	(void) strlcpy(fileinfo->fi_name, name, sizeof (fileinfo->fi_name));

	rc = smb_fsop_lookup(sr, od->d_user->u_cred, 0, od->d_tree->t_snode,
	    od->d_dnode, name, &fnode, &attr, 0, 0);
	if (rc != 0)
		return (rc);

	/* follow link to get target node & attr */
	if ((fnode->vp->v_type == VLNK) &&
	    (smb_odir_lookup_link(sr, od, name, &tgt_node, &tgt_attr))) {
		smb_node_release(fnode);
		fnode = tgt_node;
		fattr = &tgt_attr;
	} else {
		fattr = &attr;
	}

	/* check search attributes */
	dosattr = smb_node_get_dosattr(fnode);
	if (!smb_sattr_check(dosattr, od->d_sattr, fileinfo->fi_name)) {
		smb_node_release(fnode);
		return (ENOENT);
	}

	fileinfo->fi_cookie = (uint32_t)od->d_offset;
	fileinfo->fi_dosattr = dosattr;
	fileinfo->fi_nodeid = fattr->sa_vattr.va_nodeid;
	fileinfo->fi_size = smb_node_get_size(fnode, fattr);
	fileinfo->fi_alloc_size = fattr->sa_vattr.va_nblocks * DEV_BSIZE;
	fileinfo->fi_atime = fattr->sa_vattr.va_atime;
	fileinfo->fi_mtime = fattr->sa_vattr.va_mtime;
	fileinfo->fi_ctime = fattr->sa_vattr.va_ctime;
	if (fattr->sa_crtime.tv_sec)
		fileinfo->fi_crtime = fattr->sa_crtime;
	else
		fileinfo->fi_crtime = fattr->sa_vattr.va_mtime;

	smb_node_release(fnode);
	return (0);
}

/*
 * smb_odir_lookup_link
 *
 * If the file is a symlink we lookup the object to which the
 * symlink refers so that we can return its attributes.
 * This can cause a problem if a symlink in a sub-directory
 * points to a parent directory (some UNIX GUI's create a symlink
 * in $HOME/.desktop that points to the user's home directory).
 * Some Windows applications (e.g. virus scanning) loop/hang
 * trying to follow this recursive path and there is little
 * we can do because the path is constructed on the client.
 * smb_dirsymlink_enable allows an end-user to disable
 * symlinks to directories. Symlinks to other object types
 * should be unaffected.
 *
 * Returns:  B_TRUE - followed link. tgt_node and tgt_attr set
 *          B_FALSE - link not followed
 */
static boolean_t
smb_odir_lookup_link(smb_request_t *sr, smb_odir_t *od,
    char *fname, smb_node_t **tgt_node, smb_attr_t *tgt_attr)
{
	int rc;

	rc = smb_fsop_lookup(sr, od->d_user->u_cred, SMB_FOLLOW_LINKS,
	    od->d_tree->t_snode, od->d_dnode, fname, tgt_node, tgt_attr, 0, 0);
	if (rc != 0) {
		*tgt_node = NULL;
		return (B_FALSE);
	}

	if ((tgt_attr->sa_vattr.va_type == VDIR) && (!smb_dirsymlink_enable)) {
		smb_node_release(*tgt_node);
		*tgt_node = NULL;
		return (B_FALSE);
	}

	return (B_TRUE);
}
