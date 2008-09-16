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
 * User State Machine
 * ------------------
 *
 *    +-----------------------------+	 T0
 *    |  SMB_USER_STATE_LOGGED_IN   |<----------- Creation/Allocation
 *    +-----------------------------+
 *		    |
 *		    | T1
 *		    |
 *		    v
 *    +-----------------------------+
 *    |  SMB_USER_STATE_LOGGING_OFF |
 *    +-----------------------------+
 *		    |
 *		    | T2
 *		    |
 *		    v
 *    +-----------------------------+    T3
 *    |  SMB_USER_STATE_LOGGED_OFF  |----------> Deletion/Free
 *    +-----------------------------+
 *
 * SMB_USER_STATE_LOGGED_IN
 *
 *    While in this state:
 *      - The user is queued in the list of users of his session.
 *      - References will be given out if the user is looked up.
 *      - The user can access files and pipes.
 *
 * SMB_USER_STATE_LOGGING_OFF
 *
 *    While in this state:
 *      - The user is queued in the list of users of his session.
 *      - References will not be given out if the user is looked up.
 *      - The trees the user connected are being disconnected.
 *      - The resources associated with the user remain.
 *
 * SMB_USER_STATE_LOGGING_OFF
 *
 *    While in this state:
 *      - The user is queued in the list of users of his session.
 *      - References will not be given out if the user is looked up.
 *      - The user has no more trees connected.
 *      - The resources associated with the user remain.
 *
 * Transition T0
 *
 *    This transition occurs in smb_user_login(). A new user is created and
 *    added to the list of users of a session.
 *
 * Transition T1
 *
 *    This transition occurs in smb_user_logoff().
 *
 * Transition T2
 *
 *    This transition occurs in smb_user_release(). The resources associated
 *    with the user are deleted as well as the user. For the transition to
 *    occur, the user must be in the SMB_USER_STATE_LOGGED_OFF state and the
 *    reference count be zero.
 *
 * Comments
 * --------
 *
 *    The state machine of the user structures is controlled by 3 elements:
 *      - The list of users of the session he belongs to.
 *      - The mutex embedded in the structure itself.
 *      - The reference count.
 *
 *    There's a mutex embedded in the user structure used to protect its fields
 *    and there's a lock embedded in the list of users of a session. To
 *    increment or to decrement the reference count the mutex must be entered.
 *    To insert the user into the list of users of the session and to remove
 *    the user from it, the lock must be entered in RW_WRITER mode.
 *
 *    Rules of access to a user structure:
 *
 *    1) In order to avoid deadlocks, when both (mutex and lock of the session
 *       list) have to be entered, the lock must be entered first.
 *
 *    2) All actions applied to a user require a reference count.
 *
 *    3) There are 2 ways of getting a reference count. One is when the user
 *       logs in. The other when the user is looked up. This translates into
 *       3 functions: smb_user_login(), smb_user_lookup_by_uid() and
 *       smb_user_lookup_by_credentials.
 *
 *    It should be noted that the reference count of a user registers the
 *    number of references to the user in other structures (such as an smb
 *    request). The reference count is not incremented in these 2 instances:
 *
 *    1) The user is logged in. An user is anchored by his state. If there's
 *       no activity involving a user currently logged in, the reference
 *       count of that user is zero.
 *
 *    2) The user is queued in the list of users of the session. The fact of
 *       being queued in that list is NOT registered by incrementing the
 *       reference count.
 */
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_door_svc.h>


#define	ADMINISTRATORS_SID	"S-1-5-32-544"

static smb_sid_t *smb_admins_sid = NULL;

static void smb_user_delete(smb_user_t *user);
static smb_tree_t *smb_user_get_tree(smb_llist_t *, smb_tree_t *);

int
smb_user_init(void)
{
	if (smb_admins_sid != NULL)
		return (0);

	if ((smb_admins_sid = smb_sid_fromstr(ADMINISTRATORS_SID)) == NULL)
		return (-1);

	return (0);
}

void
smb_user_fini(void)
{
	if (smb_admins_sid != NULL) {
		smb_sid_free(smb_admins_sid);
		smb_admins_sid = NULL;
	}
}

/*
 * smb_user_login
 *
 *
 */
smb_user_t *
smb_user_login(
    smb_session_t	*session,
    cred_t		*cr,
    char		*domain_name,
    char		*account_name,
    uint32_t		flags,
    uint32_t		privileges,
    uint32_t		audit_sid)
{
	smb_user_t	*user;

	ASSERT(session);
	ASSERT(session->s_magic == SMB_SESSION_MAGIC);
	ASSERT(cr);
	ASSERT(account_name);
	ASSERT(domain_name);

	user = kmem_cache_alloc(session->s_server->si_cache_user, KM_SLEEP);
	bzero(user, sizeof (smb_user_t));
	user->u_refcnt = 1;
	user->u_session = session;
	user->u_server = session->s_server;
	user->u_logon_time = gethrestime_sec();
	user->u_flags = flags;
	user->u_privileges = privileges;
	user->u_name_len = strlen(account_name) + 1;
	user->u_domain_len = strlen(domain_name) + 1;
	user->u_name = smb_kstrdup(account_name, user->u_name_len);
	user->u_domain = smb_kstrdup(domain_name, user->u_domain_len);
	user->u_cred = cr;
	user->u_audit_sid = audit_sid;

	if (!smb_idpool_alloc(&session->s_uid_pool, &user->u_uid)) {
		if (!smb_idpool_constructor(&user->u_tid_pool)) {
			smb_llist_constructor(&user->u_tree_list,
			    sizeof (smb_tree_t), offsetof(smb_tree_t, t_lnd));
			mutex_init(&user->u_mutex, NULL, MUTEX_DEFAULT, NULL);
			crhold(cr);
			user->u_state = SMB_USER_STATE_LOGGED_IN;
			user->u_magic = SMB_USER_MAGIC;
			smb_llist_enter(&session->s_user_list, RW_WRITER);
			smb_llist_insert_tail(&session->s_user_list, user);
			smb_llist_exit(&session->s_user_list);
			atomic_inc_32(&session->s_server->sv_open_users);
			return (user);
		}
		smb_idpool_free(&session->s_uid_pool, user->u_uid);
	}
	kmem_free(user->u_name, (size_t)user->u_name_len);
	kmem_free(user->u_domain, (size_t)user->u_domain_len);
	kmem_cache_free(session->s_server->si_cache_user, user);
	return (NULL);
}

/*
 * Create a new user based on an existing user, used to support
 * additional SessionSetupX requests for a user on a session.
 *
 * Assumes the caller has a reference on the original user from
 * a user_lookup_by_x call.
 */
smb_user_t *
smb_user_dup(
    smb_user_t		*orig_user)
{
	smb_user_t	*user;

	ASSERT(orig_user->u_magic == SMB_USER_MAGIC);
	ASSERT(orig_user->u_refcnt);

	user = smb_user_login(orig_user->u_session, orig_user->u_cred,
	    orig_user->u_domain, orig_user->u_name, orig_user->u_flags,
	    orig_user->u_privileges, orig_user->u_audit_sid);

	if (user)
		smb_user_nonauth_logon(orig_user->u_audit_sid);

	return (user);
}

/*
 * smb_user_logoff
 *
 *
 */
void
smb_user_logoff(
    smb_user_t		*user)
{
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	mutex_enter(&user->u_mutex);
	ASSERT(user->u_refcnt);
	switch (user->u_state) {
	case SMB_USER_STATE_LOGGED_IN: {
		/*
		 * The user is moved into a state indicating that the log off
		 * process has started.
		 */
		user->u_state = SMB_USER_STATE_LOGGING_OFF;
		mutex_exit(&user->u_mutex);
		atomic_dec_32(&user->u_server->sv_open_users);
		/*
		 * All the trees hanging off of this user are disconnected.
		 */
		smb_user_disconnect_trees(user);
		smb_user_auth_logoff(user->u_audit_sid);
		mutex_enter(&user->u_mutex);
		user->u_state = SMB_USER_STATE_LOGGED_OFF;
		break;
	}
	case SMB_USER_STATE_LOGGED_OFF:
	case SMB_USER_STATE_LOGGING_OFF:
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&user->u_mutex);
}

/*
 * smb_user_logoff_all
 *
 *
 */
void
smb_user_logoff_all(
    smb_session_t	*session)
{
	smb_user_t	*user;

	ASSERT(session);
	ASSERT(session->s_magic == SMB_SESSION_MAGIC);

	smb_llist_enter(&session->s_user_list, RW_READER);
	user = smb_llist_head(&session->s_user_list);
	while (user) {
		ASSERT(user->u_magic == SMB_USER_MAGIC);
		ASSERT(user->u_session == session);
		mutex_enter(&user->u_mutex);
		switch (user->u_state) {
		case SMB_USER_STATE_LOGGED_IN:
			/* The user is still logged in. */
			user->u_refcnt++;
			mutex_exit(&user->u_mutex);
			smb_llist_exit(&session->s_user_list);
			smb_user_logoff(user);
			smb_user_release(user);
			smb_llist_enter(&session->s_user_list, RW_READER);
			user = smb_llist_head(&session->s_user_list);
			break;
		case SMB_USER_STATE_LOGGING_OFF:
		case SMB_USER_STATE_LOGGED_OFF:
			/*
			 * The user is logged off or logging off.
			 */
			mutex_exit(&user->u_mutex);
			user = smb_llist_next(&session->s_user_list, user);
			break;
		default:
			ASSERT(0);
			mutex_exit(&user->u_mutex);
			user = smb_llist_next(&session->s_user_list, user);
			break;
		}
	}
	smb_llist_exit(&session->s_user_list);
}

/*
 * smb_user_release
 *
 *
 */
void
smb_user_release(
    smb_user_t		*user)
{
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	mutex_enter(&user->u_mutex);
	ASSERT(user->u_refcnt);
	user->u_refcnt--;
	switch (user->u_state) {
	case SMB_USER_STATE_LOGGED_OFF:
		if (user->u_refcnt == 0) {
			mutex_exit(&user->u_mutex);
			smb_user_delete(user);
			return;
		}
		break;

	case SMB_USER_STATE_LOGGED_IN:
	case SMB_USER_STATE_LOGGING_OFF:
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&user->u_mutex);
}

/*
 * smb_user_lookup_by_uid
 *
 * Find the appropriate user for this request. The request credentials
 * set here may be overridden by the tree credentials. In domain mode,
 * the user and tree credentials should be the same. In share mode, the
 * tree credentials (defined in the share definition) should override
 * the user credentials.
 */
smb_user_t *
smb_user_lookup_by_uid(
    smb_session_t	*session,
    cred_t		**cr,
    uint16_t		uid)
{
	smb_user_t	*user;

	ASSERT(session);
	ASSERT(session->s_magic == SMB_SESSION_MAGIC);
	ASSERT(cr);

	smb_llist_enter(&session->s_user_list, RW_READER);
	user = smb_llist_head(&session->s_user_list);
	while (user) {
		ASSERT(user->u_magic == SMB_USER_MAGIC);
		ASSERT(user->u_session == session);
		if (user->u_uid == uid) {
			mutex_enter(&user->u_mutex);
			switch (user->u_state) {

			case SMB_USER_STATE_LOGGED_IN:
				/* The user exists and is still logged in. */
				*cr = user->u_cred;
				user->u_refcnt++;
				mutex_exit(&user->u_mutex);
				smb_llist_exit(&session->s_user_list);
				return (user);

			case SMB_USER_STATE_LOGGING_OFF:
			case SMB_USER_STATE_LOGGED_OFF:
				/*
				 * The user exists but has logged off or is in
				 * the process of logging off.
				 */
				mutex_exit(&user->u_mutex);
				smb_llist_exit(&session->s_user_list);
				return (NULL);

			default:
				ASSERT(0);
				mutex_exit(&user->u_mutex);
				smb_llist_exit(&session->s_user_list);
				return (NULL);
			}
		}
		user = smb_llist_next(&session->s_user_list, user);
	}
	smb_llist_exit(&session->s_user_list);
	return (NULL);
}

/*
 * smb_user_lookup_by_name
 */
smb_user_t *
smb_user_lookup_by_name(smb_session_t *session, char *domain, char *name)
{
	smb_user_t	*user;
	smb_llist_t	*ulist;

	ulist = &session->s_user_list;
	smb_llist_enter(ulist, RW_READER);
	user = smb_llist_head(ulist);
	while (user) {
		ASSERT(user->u_magic == SMB_USER_MAGIC);
		if (!utf8_strcasecmp(user->u_name, name) &&
		    !utf8_strcasecmp(user->u_domain, domain)) {
			mutex_enter(&user->u_mutex);
			if (user->u_state == SMB_USER_STATE_LOGGED_IN) {
				user->u_refcnt++;
				mutex_exit(&user->u_mutex);
				break;
			}
			mutex_exit(&user->u_mutex);
		}
		user = smb_llist_next(ulist, user);
	}
	smb_llist_exit(ulist);

	return (user);
}

/*
 * smb_user_lookup_by_state
 *
 * This function returns the first user in the logged in state. If the user
 * provided is NULL the search starts from the beginning of the list passed
 * in. It a user is provided the search starts just after that user.
 */
smb_user_t *
smb_user_lookup_by_state(
    smb_session_t	*session,
    smb_user_t		*user)
{
	smb_llist_t	*lst;
	smb_user_t	*next;

	ASSERT(session);
	ASSERT(session->s_magic == SMB_SESSION_MAGIC);

	lst = &session->s_user_list;

	smb_llist_enter(lst, RW_READER);
	if (user) {
		ASSERT(user);
		ASSERT(user->u_magic == SMB_USER_MAGIC);
		ASSERT(user->u_refcnt);
		next = smb_llist_next(lst, user);
	} else {
		next = smb_llist_head(lst);
	}
	while (next) {
		ASSERT(next->u_magic == SMB_USER_MAGIC);
		ASSERT(next->u_session == session);
		mutex_enter(&next->u_mutex);
		if (next->u_state == SMB_USER_STATE_LOGGED_IN) {
			next->u_refcnt++;
			mutex_exit(&next->u_mutex);
			break;
		} else {
			ASSERT((next->u_state == SMB_USER_STATE_LOGGING_OFF) ||
			    (next->u_state == SMB_USER_STATE_LOGGED_OFF));
			mutex_exit(&next->u_mutex);
			next = smb_llist_next(lst, next);
		}
	}
	smb_llist_exit(lst);

	return (next);
}

/*
 * Find a tree by tree-id.
 */
smb_tree_t *
smb_user_lookup_tree(
    smb_user_t		*user,
    uint16_t		tid)

{
	smb_tree_t	*tree;

	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	smb_llist_enter(&user->u_tree_list, RW_READER);
	tree = smb_llist_head(&user->u_tree_list);

	while (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		ASSERT(tree->t_user == user);

		if (tree->t_tid == tid) {
			if (smb_tree_hold(tree)) {
				smb_llist_exit(&user->u_tree_list);
				return (tree);
			} else {
				smb_llist_exit(&user->u_tree_list);
				return (NULL);
			}
		}

		tree = smb_llist_next(&user->u_tree_list, tree);
	}

	smb_llist_exit(&user->u_tree_list);
	return (NULL);
}

/*
 * Find the first connected tree that matches the specified sharename.
 * If the specified tree is NULL the search starts from the beginning of
 * the user's tree list.  If a tree is provided the search starts just
 * after that tree.
 */
smb_tree_t *
smb_user_lookup_share(
    smb_user_t		*user,
    const char		*sharename,
    smb_tree_t		*tree)
{
	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);
	ASSERT(sharename);

	smb_llist_enter(&user->u_tree_list, RW_READER);

	if (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		ASSERT(tree->t_user == user);
		tree = smb_llist_next(&user->u_tree_list, tree);
	} else {
		tree = smb_llist_head(&user->u_tree_list);
	}

	while (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		ASSERT(tree->t_user == user);
		if (utf8_strcasecmp(tree->t_sharename, sharename) == 0) {
			if (smb_tree_hold(tree)) {
				smb_llist_exit(&user->u_tree_list);
				return (tree);
			}
		}
		tree = smb_llist_next(&user->u_tree_list, tree);
	}

	smb_llist_exit(&user->u_tree_list);
	return (NULL);
}

/*
 * Find the first connected tree that matches the specified volume name.
 * If the specified tree is NULL the search starts from the beginning of
 * the user's tree list.  If a tree is provided the search starts just
 * after that tree.
 */
smb_tree_t *
smb_user_lookup_volume(
    smb_user_t		*user,
    const char		*name,
    smb_tree_t		*tree)
{
	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);
	ASSERT(name);

	smb_llist_enter(&user->u_tree_list, RW_READER);

	if (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		ASSERT(tree->t_user == user);
		tree = smb_llist_next(&user->u_tree_list, tree);
	} else {
		tree = smb_llist_head(&user->u_tree_list);
	}

	while (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		ASSERT(tree->t_user == user);

		if (utf8_strcasecmp(tree->t_volume, name) == 0) {
			if (smb_tree_hold(tree)) {
				smb_llist_exit(&user->u_tree_list);
				return (tree);
			}
		}

		tree = smb_llist_next(&user->u_tree_list, tree);
	}

	smb_llist_exit(&user->u_tree_list);
	return (NULL);
}

/*
 * Disconnect all trees that match the specified client process-id.
 */
void
smb_user_close_pid(
    smb_user_t		*user,
    uint16_t		pid)
{
	smb_tree_t	*tree;

	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	tree = smb_user_get_tree(&user->u_tree_list, NULL);
	while (tree) {
		smb_tree_t *next;
		ASSERT(tree->t_user == user);
		smb_tree_close_pid(tree, pid);
		next = smb_user_get_tree(&user->u_tree_list, tree);
		smb_tree_release(tree);
		tree = next;
	}
}

/*
 * Disconnect all trees that this user has connected.
 */
void
smb_user_disconnect_trees(
    smb_user_t		*user)
{
	smb_tree_t	*tree;

	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	tree = smb_user_get_tree(&user->u_tree_list, NULL);
	while (tree) {
		ASSERT(tree->t_user == user);
		smb_tree_disconnect(tree);
		smb_tree_release(tree);
		tree = smb_user_get_tree(&user->u_tree_list, NULL);
	}
}

/*
 * Disconnect all trees that match the specified share name.
 */
void
smb_user_disconnect_share(
    smb_user_t		*user,
    const char		*sharename)
{
	smb_tree_t	*tree;
	smb_tree_t	*next;

	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);
	ASSERT(user->u_refcnt);

	tree = smb_user_lookup_share(user, sharename, NULL);
	while (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		smb_session_cancel_requests(user->u_session, tree, NULL);
		smb_tree_disconnect(tree);
		next = smb_user_lookup_share(user, sharename, tree);
		smb_tree_release(tree);
		tree = next;
	}
}

/*
 * Determine whether or not the user is an administrator.
 * Members of the administrators group have administrative rights.
 */
boolean_t
smb_user_is_admin(
    smb_user_t		*user)
{
	cred_t		*u_cred;

	ASSERT(user);
	u_cred = user->u_cred;
	ASSERT(u_cred);

	if (smb_admins_sid == NULL)
		return (B_FALSE);

	if (smb_cred_is_member(u_cred, smb_admins_sid))
		return (B_TRUE);

	return (B_FALSE);
}

/* *************************** Static Functions ***************************** */

/*
 * smb_user_delete
 */
static void
smb_user_delete(
    smb_user_t		*user)
{
	smb_session_t	*session;

	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);
	ASSERT(user->u_refcnt == 0);
	ASSERT(user->u_state == SMB_USER_STATE_LOGGED_OFF);

	session = user->u_session;
	/*
	 * Let's remove the user from the list of users of the session. This
	 * has to be done before any resources associated with the user are
	 * deleted.
	 */
	smb_llist_enter(&session->s_user_list, RW_WRITER);
	smb_llist_remove(&session->s_user_list, user);
	smb_llist_exit(&session->s_user_list);

	user->u_magic = (uint32_t)~SMB_USER_MAGIC;
	mutex_destroy(&user->u_mutex);
	smb_llist_destructor(&user->u_tree_list);
	smb_idpool_destructor(&user->u_tid_pool);
	smb_idpool_free(&session->s_uid_pool, user->u_uid);
	crfree(user->u_cred);
	kmem_free(user->u_name, (size_t)user->u_name_len);
	kmem_free(user->u_domain, (size_t)user->u_domain_len);
	kmem_cache_free(user->u_server->si_cache_user, user);
}

/*
 * Get the next connected tree in the list.  A reference is taken on
 * the tree, which can be released later with smb_tree_release().
 *
 * If the specified tree is NULL the search starts from the beginning of
 * the tree list.  If a tree is provided the search starts just after
 * that tree.
 *
 * Returns NULL if there are no connected trees in the list.
 */
static smb_tree_t *
smb_user_get_tree(
    smb_llist_t		*tree_list,
    smb_tree_t		*tree)
{
	ASSERT(tree_list);

	smb_llist_enter(tree_list, RW_READER);

	if (tree) {
		ASSERT(tree->t_magic == SMB_TREE_MAGIC);
		tree = smb_llist_next(tree_list, tree);
	} else {
		tree = smb_llist_head(tree_list);
	}

	while (tree) {
		if (smb_tree_hold(tree))
			break;

		tree = smb_llist_next(tree_list, tree);
	}

	smb_llist_exit(tree_list);
	return (tree);
}
