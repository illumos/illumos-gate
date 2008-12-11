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
 * Tree State Machine
 * ------------------
 *
 *    +-----------------------------+	 T0
 *    |  SMB_TREE_STATE_CONNECTED   |<----------- Creation/Allocation
 *    +-----------------------------+
 *		    |
 *		    | T1
 *		    |
 *		    v
 *    +------------------------------+
 *    | SMB_TREE_STATE_DISCONNECTING |
 *    +------------------------------+
 *		    |
 *		    | T2
 *		    |
 *		    v
 *    +-----------------------------+    T3
 *    | SMB_TREE_STATE_DISCONNECTED |----------> Deletion/Free
 *    +-----------------------------+
 *
 * SMB_TREE_STATE_CONNECTED
 *
 *    While in this state:
 *      - The tree is queued in the list of trees of its user.
 *      - References will be given out if the tree is looked up.
 *      - Files under that tree can be accessed.
 *
 * SMB_TREE_STATE_DISCONNECTING
 *
 *    While in this state:
 *      - The tree is queued in the list of trees of its user.
 *      - References will not be given out if the tree is looked up.
 *      - The files and directories open under the tree are being closed.
 *      - The resources associated with the tree remain.
 *
 * SMB_TREE_STATE_DISCONNECTED
 *
 *    While in this state:
 *      - The tree is queued in the list of trees of its user.
 *      - References will not be given out if the tree is looked up.
 *      - The tree has no more files and directories opened.
 *      - The resources associated with the tree remain.
 *
 * Transition T0
 *
 *    This transition occurs in smb_tree_connect(). A new tree is created and
 *    added to the list of trees of a user.
 *
 * Transition T1
 *
 *    This transition occurs in smb_tree_disconnect().
 *
 * Transition T2
 *
 *    This transition occurs in smb_tree_release(). The resources associated
 *    with the tree are freed as well as the tree structure. For the transition
 *    to occur, the tree must be in the SMB_TREE_STATE_DISCONNECTED state and
 *    the reference count be zero.
 *
 * Comments
 * --------
 *
 *    The state machine of the tree structures is controlled by 3 elements:
 *      - The list of trees of the user it belongs to.
 *      - The mutex embedded in the structure itself.
 *      - The reference count.
 *
 *    There's a mutex embedded in the tree structure used to protect its fields
 *    and there's a lock embedded in the list of trees of a user. To
 *    increment or to decrement the reference count the mutex must be entered.
 *    To insert the tree into the list of trees of the user and to remove
 *    the tree from it, the lock must be entered in RW_WRITER mode.
 *
 *    Rules of access to a tree structure:
 *
 *    1) In order to avoid deadlocks, when both (mutex and lock of the user
 *       list) have to be entered, the lock must be entered first.
 *
 *    2) All actions applied to a tree require a reference count.
 *
 *    3) There are 2 ways of getting a reference count: when a tree is
 *       connected and when a tree is looked up.
 *
 *    It should be noted that the reference count of a tree registers the
 *    number of references to the tree in other structures (such as an smb
 *    request). The reference count is not incremented in these 2 instances:
 *
 *    1) The tree is connected. An tree is anchored by his state. If there's
 *       no activity involving a tree currently connected, the reference
 *       count of that tree is zero.
 *
 *    2) The tree is queued in the list of trees of the user. The fact of
 *       being queued in that list is NOT registered by incrementing the
 *       reference count.
 */
#include <sys/types.h>
#include <sys/refstr_impl.h>
#include <sys/feature_tests.h>
#include <sys/sunddi.h>
#include <sys/fsid.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/varargs.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_share.h>

int smb_tcon_mute = 0;

static smb_tree_t *smb_tree_connect_disk(smb_request_t *, const char *);
static smb_tree_t *smb_tree_connect_ipc(smb_request_t *, const char *);
static smb_tree_t *smb_tree_alloc(smb_user_t *, const char *, const char *,
    int32_t, smb_node_t *);
static void smb_tree_dealloc(smb_tree_t *);
static boolean_t smb_tree_is_connected(smb_tree_t *);
static boolean_t smb_tree_is_disconnected(smb_tree_t *);
static const char *smb_tree_get_sharename(const char *);
static int smb_tree_get_stype(const char *, const char *, int32_t *);
static int smb_tree_getattr(smb_node_t *, smb_tree_t *);
static void smb_tree_get_volname(vfs_t *, smb_tree_t *);
static void smb_tree_get_flags(vfs_t *, smb_tree_t *);
static void smb_tree_log(smb_request_t *, const char *, const char *, ...);

/*
 * Extract the share name and share type and connect as appropriate.
 * Share names are case insensitive so we map the share name to
 * lower-case as a convenience for internal processing.
 */
smb_tree_t *
smb_tree_connect(smb_request_t *sr)
{
	char *unc_path = sr->arg.tcon.path;
	char *service = sr->arg.tcon.service;
	smb_tree_t *tree = NULL;
	const char *name;
	int32_t stype;

	(void) utf8_strlwr(unc_path);

	if ((name = smb_tree_get_sharename(unc_path)) == NULL) {
		smbsr_error(sr, 0, ERRSRV, ERRinvnetname);
		return (NULL);
	}

	if (smb_tree_get_stype(name, service, &stype) != 0) {
		smbsr_error(sr, NT_STATUS_BAD_DEVICE_TYPE,
		    ERRDOS, ERROR_BAD_DEV_TYPE);
		return (NULL);
	}

	switch (stype & STYPE_MASK) {
	case STYPE_DISKTREE:
		tree = smb_tree_connect_disk(sr, name);
		break;

	case STYPE_IPC:
		tree = smb_tree_connect_ipc(sr, name);
		break;

	default:
		smbsr_error(sr, NT_STATUS_BAD_DEVICE_TYPE,
		    ERRDOS, ERROR_BAD_DEV_TYPE);
		break;
	}

	return (tree);
}

/*
 * Disconnect a tree.
 */
void
smb_tree_disconnect(
    smb_tree_t	*tree)
{
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	mutex_enter(&tree->t_mutex);
	ASSERT(tree->t_refcnt);

	if (smb_tree_is_connected(tree)) {
		/*
		 * Indicate that the disconnect process has started.
		 */
		tree->t_state = SMB_TREE_STATE_DISCONNECTING;
		mutex_exit(&tree->t_mutex);
		atomic_dec_32(&tree->t_server->sv_open_trees);

		/*
		 * The files opened under this tree are closed.
		 */
		smb_ofile_close_all(tree);
		/*
		 * The directories opened under this tree are closed.
		 */
		smb_odir_close_all(tree);
		mutex_enter(&tree->t_mutex);
		tree->t_state = SMB_TREE_STATE_DISCONNECTED;
	}

	mutex_exit(&tree->t_mutex);
}

/*
 * Take a reference on a tree.
 */
boolean_t
smb_tree_hold(
    smb_tree_t		*tree)
{
	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	mutex_enter(&tree->t_mutex);

	if (smb_tree_is_connected(tree)) {
		tree->t_refcnt++;
		mutex_exit(&tree->t_mutex);
		return (B_TRUE);
	}

	mutex_exit(&tree->t_mutex);
	return (B_FALSE);
}

/*
 * Release a reference on a tree.  If the tree is disconnected and the
 * reference count falls to zero, the tree will be deallocated.
 */
void
smb_tree_release(
    smb_tree_t		*tree)
{
	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	mutex_enter(&tree->t_mutex);
	ASSERT(tree->t_refcnt);
	tree->t_refcnt--;

	if (smb_tree_is_disconnected(tree) && (tree->t_refcnt == 0)) {
		mutex_exit(&tree->t_mutex);
		smb_tree_dealloc(tree);
		return;
	}

	mutex_exit(&tree->t_mutex);
}

/*
 * Close ofiles and odirs that match pid.
 */
void
smb_tree_close_pid(
    smb_tree_t		*tree,
    uint16_t		pid)
{
	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	smb_ofile_close_all_by_pid(tree, pid);
	smb_odir_close_all_by_pid(tree, pid);
}

/*
 * Check whether or not a tree supports the features identified by flags.
 */
boolean_t
smb_tree_has_feature(smb_tree_t *tree, uint32_t flags)
{
	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);

	return ((tree->t_flags & flags) == flags);
}

/* *************************** Static Functions ***************************** */

/*
 * Connect a share for use with files and directories.
 */
static smb_tree_t *
smb_tree_connect_disk(smb_request_t *sr, const char *sharename)
{
	smb_user_t		*user = sr->uid_user;
	smb_node_t		*dir_snode = NULL;
	smb_node_t		*snode = NULL;
	char			last_component[MAXNAMELEN];
	smb_tree_t		*tree;
	smb_share_t 		*si;
	smb_attr_t		attr;
	cred_t			*u_cred;
	int			rc;
	uint32_t		access = 0; /* read/write is assumed */
	uint32_t		hostaccess;

	ASSERT(user);
	u_cred = user->u_cred;
	ASSERT(u_cred);

	if (user->u_flags & SMB_USER_FLAG_IPC) {
		smb_tree_log(sr, sharename, "access denied: IPC only");
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRSRV, ERRaccess);
		return (NULL);
	}

	si = kmem_zalloc(sizeof (smb_share_t), KM_SLEEP);

	if (smb_kshare_getinfo(sr->sr_server->sv_lmshrd, (char *)sharename, si,
	    sr->session->ipaddr) != NERR_Success) {
		smb_tree_log(sr, sharename, "share not found");
		smbsr_error(sr, 0, ERRSRV, ERRinvnetname);
		kmem_free(si, sizeof (smb_share_t));
		return (NULL);
	}

	/*
	 * Handle the default administration shares: C$, D$ etc.
	 * Only a user with admin rights is allowed to map these
	 * shares.
	 */
	if (si->shr_flags & SMB_SHRF_ADMIN) {
		if (!smb_user_is_admin(user)) {
			smb_tree_log(sr, sharename, "access denied: not admin");
			smbsr_error(sr, NT_STATUS_ACCESS_DENIED,
			    ERRSRV, ERRaccess);
			kmem_free(si, sizeof (smb_share_t));
			return (NULL);
		}
	}

	/*
	 * Set up the OptionalSupport for this share.
	 */
	sr->arg.tcon.optional_support = SMB_SUPPORT_SEARCH_BITS;

	switch (si->shr_flags & SMB_SHRF_CSC_MASK) {
	case SMB_SHRF_CSC_DISABLED:
		sr->arg.tcon.optional_support |= SMB_CSC_CACHE_NONE;
		break;
	case SMB_SHRF_CSC_AUTO:
		sr->arg.tcon.optional_support |= SMB_CSC_CACHE_AUTO_REINT;
		break;
	case SMB_SHRF_CSC_VDO:
		sr->arg.tcon.optional_support |= SMB_CSC_CACHE_VDO;
		break;
	case SMB_SHRF_CSC_MANUAL:
	default:
		/*
		 * Default to SMB_CSC_CACHE_MANUAL_REINT.
		 */
		break;
	}

	hostaccess = si->shr_access_value & SMB_SHRF_ACC_ALL;

	if (hostaccess == SMB_SHRF_ACC_RO) {
		access = SMB_TREE_READONLY;
	} else if (hostaccess == SMB_SHRF_ACC_NONE) {
		kmem_free(si, sizeof (smb_share_t));
		smb_tree_log(sr, sharename, "access denied: host access");
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRSRV, ERRaccess);
		return (NULL);
	}

	/*
	 * Check that the shared directory exists.
	 */
	rc = smb_pathname_reduce(sr, u_cred, si->shr_path, 0, 0, &dir_snode,
	    last_component);

	if (rc == 0) {
		rc = smb_fsop_lookup(sr, u_cred, SMB_FOLLOW_LINKS, 0,
		    dir_snode, last_component, &snode, &attr, 0, 0);

		smb_node_release(dir_snode);
	}

	if (rc) {
		if (snode)
			smb_node_release(snode);

		smb_tree_log(sr, sharename, "bad path: %s", si->shr_path);
		smbsr_error(sr, 0, ERRSRV, ERRinvnetname);
		kmem_free(si, sizeof (smb_share_t));
		return (NULL);
	}

	tree = smb_tree_alloc(user, sharename, si->shr_path, STYPE_DISKTREE,
	    snode);

	if (tree == NULL)
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRSRV, ERRaccess);
	else
		tree->t_flags |= access;

	smb_node_release(snode);
	kmem_free(si, sizeof (smb_share_t));
	return (tree);
}

/*
 * Connect an IPC share for use with named pipes.
 */
static smb_tree_t *
smb_tree_connect_ipc(smb_request_t *sr, const char *name)
{
	smb_user_t *user = sr->uid_user;
	smb_tree_t *tree;

	ASSERT(user);

	if ((user->u_flags & SMB_USER_FLAG_IPC) &&
	    sr->sr_cfg->skc_restrict_anon) {
		smb_tree_log(sr, name, "access denied: restrict anonymous");
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRSRV, ERRaccess);
		return (NULL);
	}

	sr->arg.tcon.optional_support = SMB_SUPPORT_SEARCH_BITS;

	tree = smb_tree_alloc(user, name, name, STYPE_IPC, NULL);
	if (tree == NULL) {
		smb_tree_log(sr, name, "access denied");
		smbsr_error(sr, NT_STATUS_ACCESS_DENIED, ERRSRV, ERRaccess);
	}

	return (tree);
}

/*
 * Allocate a tree.
 */
static smb_tree_t *
smb_tree_alloc(
    smb_user_t		*user,
    const char		*sharename,
    const char		*resource,
    int32_t		stype,
    smb_node_t		*snode)
{
	smb_tree_t	*tree;
	uint16_t	tid;

	if (smb_idpool_alloc(&user->u_tid_pool, &tid))
		return (NULL);

	tree = kmem_cache_alloc(user->u_server->si_cache_tree, KM_SLEEP);
	bzero(tree, sizeof (smb_tree_t));

	if (STYPE_ISDSK(stype)) {
		if (smb_tree_getattr(snode, tree) != 0) {
			smb_idpool_free(&user->u_tid_pool, tid);
			kmem_cache_free(user->u_server->si_cache_tree, tree);
			return (NULL);
		}
	}

	if (smb_idpool_constructor(&tree->t_fid_pool)) {
		smb_idpool_free(&user->u_tid_pool, tid);
		kmem_cache_free(user->u_server->si_cache_tree, tree);
		return (NULL);
	}

	if (smb_idpool_constructor(&tree->t_sid_pool)) {
		smb_idpool_destructor(&tree->t_fid_pool);
		smb_idpool_free(&user->u_tid_pool, tid);
		kmem_cache_free(user->u_server->si_cache_tree, tree);
		return (NULL);
	}

	smb_llist_constructor(&tree->t_ofile_list, sizeof (smb_ofile_t),
	    offsetof(smb_ofile_t, f_lnd));

	smb_llist_constructor(&tree->t_odir_list, sizeof (smb_odir_t),
	    offsetof(smb_odir_t, d_lnd));

	(void) strlcpy(tree->t_sharename, sharename,
	    sizeof (tree->t_sharename));
	(void) strlcpy(tree->t_resource, resource, sizeof (tree->t_resource));

	mutex_init(&tree->t_mutex, NULL, MUTEX_DEFAULT, NULL);

	tree->t_user = user;
	tree->t_session = user->u_session;
	tree->t_server = user->u_server;
	tree->t_refcnt = 1;
	tree->t_tid = tid;
	tree->t_res_type = stype;
	tree->t_state = SMB_TREE_STATE_CONNECTED;
	tree->t_magic = SMB_TREE_MAGIC;

	if (STYPE_ISDSK(stype)) {
		smb_node_ref(snode);
		tree->t_snode = snode;
		tree->t_acltype = smb_fsop_acltype(snode);
	}

	smb_llist_enter(&user->u_tree_list, RW_WRITER);
	smb_llist_insert_head(&user->u_tree_list, tree);
	smb_llist_exit(&user->u_tree_list);
	atomic_inc_32(&user->u_session->s_tree_cnt);
	atomic_inc_32(&user->u_server->sv_open_trees);

	return (tree);
}

/*
 * Deallocate a tree: release all resources associated with a tree and
 * remove the tree from the user's tree list.
 *
 * The tree being destroyed must be in the "destroying" state and the
 * reference count must be zero. This function assumes it's single threaded
 * i.e. only one thread will attempt to destroy a specific tree, which
 * should be the case if the tree is in disconnected and has a reference
 * count of zero.
 */
static void
smb_tree_dealloc(smb_tree_t *tree)
{
	ASSERT(tree);
	ASSERT(tree->t_magic == SMB_TREE_MAGIC);
	ASSERT(tree->t_state == SMB_TREE_STATE_DISCONNECTED);
	ASSERT(tree->t_refcnt == 0);

	/*
	 * Remove the tree from the user's tree list.  This must be done
	 * before any resources associated with the tree are released.
	 */
	smb_llist_enter(&tree->t_user->u_tree_list, RW_WRITER);
	smb_llist_remove(&tree->t_user->u_tree_list, tree);
	smb_llist_exit(&tree->t_user->u_tree_list);

	tree->t_magic = (uint32_t)~SMB_TREE_MAGIC;
	smb_idpool_free(&tree->t_user->u_tid_pool, tree->t_tid);
	atomic_dec_32(&tree->t_session->s_tree_cnt);

	if (tree->t_snode)
		smb_node_release(tree->t_snode);

	mutex_destroy(&tree->t_mutex);

	/*
	 * The list of open files and open directories should be empty.
	 */
	smb_llist_destructor(&tree->t_ofile_list);
	smb_llist_destructor(&tree->t_odir_list);
	smb_idpool_destructor(&tree->t_fid_pool);
	smb_idpool_destructor(&tree->t_sid_pool);
	kmem_cache_free(tree->t_server->si_cache_tree, tree);
}

/*
 * Determine whether or not a tree is connected.
 * This function must be called with the tree mutex held.
 */
static boolean_t
smb_tree_is_connected(smb_tree_t *tree)
{
	switch (tree->t_state) {
	case SMB_TREE_STATE_CONNECTED:
		return (B_TRUE);

	case SMB_TREE_STATE_DISCONNECTING:
	case SMB_TREE_STATE_DISCONNECTED:
		/*
		 * The tree exists but being diconnected or destroyed.
		 */
		return (B_FALSE);

	default:
		ASSERT(0);
		return (B_FALSE);
	}
}

/*
 * Determine whether or not a tree is disconnected.
 * This function must be called with the tree mutex held.
 */
static boolean_t
smb_tree_is_disconnected(smb_tree_t *tree)
{
	switch (tree->t_state) {
	case SMB_TREE_STATE_DISCONNECTED:
		return (B_TRUE);

	case SMB_TREE_STATE_CONNECTED:
	case SMB_TREE_STATE_DISCONNECTING:
		return (B_FALSE);

	default:
		ASSERT(0);
		return (B_FALSE);
	}
}

/*
 * Return a pointer to the share name within a share resource path.
 *
 * The share path may be a Uniform Naming Convention (UNC) string
 * (\\server\share) or simply the share name.  We validate the UNC
 * format but we don't look at the server name.
 */
static const char *
smb_tree_get_sharename(const char *unc_path)
{
	const char *sharename = unc_path;

	if (sharename[0] == '\\') {
		/*
		 * Looks like a UNC path, validate the format.
		 */
		if (sharename[1] != '\\')
			return (NULL);

		if ((sharename = strchr(sharename+2, '\\')) == NULL)
			return (NULL);

		++sharename;
	} else if (strchr(sharename, '\\') != NULL) {
		/*
		 * This should be a share name (no embedded \'s).
		 */
		return (NULL);
	}

	return (sharename);
}

/*
 * Map the service to a resource type.  Valid values for service are:
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
static int
smb_tree_get_stype(const char *sharename, const char *service,
    int32_t *stype_ret)
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
 * Obtain the tree attributes: volume name, typename and flags.
 */
static int
smb_tree_getattr(smb_node_t *node, smb_tree_t *tree)
{
	vfs_t *vfsp = SMB_NODE_VFS(node);

	ASSERT(vfsp);

	if (getvfs(&vfsp->vfs_fsid) != vfsp)
		return (ESTALE);

	smb_tree_get_volname(vfsp, tree);
	smb_tree_get_flags(vfsp, tree);

	VFS_RELE(vfsp);
	return (0);
}

/*
 * Extract the volume name.
 */
static void
smb_tree_get_volname(vfs_t *vfsp, smb_tree_t *tree)
{
	refstr_t *vfs_mntpoint;
	const char *s;
	char *name;

	vfs_mntpoint = vfs_getmntpoint(vfsp);

	s = vfs_mntpoint->rs_string;
	s += strspn(s, "/");
	(void) strlcpy(tree->t_volume, s, SMB_VOLNAMELEN);

	refstr_rele(vfs_mntpoint);

	name = tree->t_volume;
	(void) strsep((char **)&name, "/");
}

/*
 * Always set ACL support because the VFS will fake ACLs for file systems
 * that don't support them.
 *
 * Some flags are dependent on the typename, which is also set up here.
 * File system types are hardcoded in uts/common/os/vfs_conf.c.
 */
static void
smb_tree_get_flags(vfs_t *vfsp, smb_tree_t *tree)
{
	uint32_t flags = SMB_TREE_SUPPORTS_ACLS;
	char *name;

	if (vfsp->vfs_flag & VFS_RDONLY)
		flags |= SMB_TREE_READONLY;

	if (vfsp->vfs_flag & VFS_XATTR)
		flags |= SMB_TREE_STREAMS;

	if (vfs_optionisset(vfsp, MNTOPT_NOATIME, NULL))
		flags |= SMB_TREE_NO_ATIME;

	name = vfssw[vfsp->vfs_fstype].vsw_name;

	if (strcmp(name, "tmpfs") == 0)
		flags |= SMB_TREE_NO_EXPORT;

	if (strncasecmp(name, NFS, sizeof (NFS)) == 0)
		flags |= SMB_TREE_NFS_MOUNTED;

	(void) strlcpy(tree->t_typename, name, SMB_TYPENAMELEN);
	(void) utf8_strupr((char *)tree->t_typename);

	if (vfs_has_feature(vfsp, VFSFT_XVATTR))
		flags |= SMB_TREE_XVATTR;

	if (vfs_has_feature(vfsp, VFSFT_CASEINSENSITIVE))
		flags |= SMB_TREE_CASEINSENSITIVE;

	if (vfs_has_feature(vfsp, VFSFT_NOCASESENSITIVE))
		flags |= SMB_TREE_NO_CASESENSITIVE;

	if (vfs_has_feature(vfsp, VFSFT_DIRENTFLAGS))
		flags |= SMB_TREE_DIRENTFLAGS;

	if (vfs_has_feature(vfsp, VFSFT_ACLONCREATE))
		flags |= SMB_TREE_ACLONCREATE;

	if (vfs_has_feature(vfsp, VFSFT_ACEMASKONACCESS))
		flags |= SMB_TREE_ACEMASKONACCESS;

	DTRACE_PROBE1(smb__tree__flags, uint32_t, flags);

	tree->t_flags = flags;
}

/*
 * Report share access result to syslog.
 */
static void
smb_tree_log(smb_request_t *sr, const char *sharename, const char *fmt, ...)
{
	va_list ap;
	char buf[128];
	smb_user_t *user = sr->uid_user;

	ASSERT(user);

	if (smb_tcon_mute)
		return;

	if ((user->u_name) && (strcasecmp(sharename, "IPC$") == 0)) {
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

	va_start(ap, fmt);
	(void) vsnprintf(buf, 128, fmt, ap);
	va_end(ap);

	cmn_err(CE_NOTE, "smbd[%s\\%s]: %s %s",
	    user->u_domain, user->u_name, sharename, buf);
}
