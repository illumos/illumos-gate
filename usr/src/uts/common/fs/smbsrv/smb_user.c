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
 * Copyright 2020 Tintri by DDN, Inc. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 * Copyright 2022-2023 RackTop Systems, Inc.
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
 *   |          |
 *   |          |
 *   |          v
 *   |  +-------------------+     +-------------------+   +-------------------+
 *   |  |       USER        |<--->|       USER        |...|       USER        |
 *   |  +-------------------+     +-------------------+   +-------------------+
 *   |
 *   |
 *   v
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
 *
 *		    | T0:  Creation/Allocation
 *		    |	   (1st session setup)
 *		    v
 *    +-----------------------------+
 *    |  SMB_USER_STATE_LOGGING_ON  |<----------+
 *    +-----------------------------+	 addl. session setup
 *		    |		|	(more proc. required)
 *		    | T2	|		^
 *		    |		|		| T1: (cont.)
 *		    |		+------->-------?
 *		    v				| T3: (fail)
 *    +-----------------------------+		v
 *    |  SMB_USER_STATE_LOGGED_ON   |	    (logged off)
 *    +-----------------------------+
 *		    |
 *		    | T4
 *		    |
 *		    v
 *    +-----------------------------+
 *    |  SMB_USER_STATE_LOGGING_OFF |
 *    +-----------------------------+
 *		    |
 *		    | T5
 *		    |
 *		    v
 *    +-----------------------------+    T6
 *    |  SMB_USER_STATE_LOGGED_OFF  |----------> Deletion/Free
 *    +-----------------------------+
 *
 * SMB_USER_STATE_LOGGING_ON
 *
 *    While in this state:
 *      - The user is in the list of users for their session.
 *      - References will be given out ONLY for session setup.
 *      - This user can not access anything yet.
 *
 * SMB_USER_STATE_LOGGED_ON
 *
 *    While in this state:
 *      - The user is in the list of users for their session.
 *      - References will be given out if the user is looked up.
 *      - The user can access files and pipes.
 *
 * SMB_USER_STATE_LOGGING_OFF
 *
 *    While in this state:
 *      - The user is in the list of users for their session.
 *      - References will not be given out if the user is looked up.
 *      - The trees the user connected are being disconnected.
 *      - The resources associated with the user remain.
 *
 * SMB_USER_STATE_LOGGED_OFF
 *
 *    While in this state:
 *      - The user is queued in the list of users of their session.
 *      - References will not be given out if the user is looked up.
 *      - The user has no more trees connected.
 *      - The resources associated with the user remain.
 *
 * Transition T0
 *
 *    First request in an SMB Session Setup sequence creates a
 *    new user object and adds it to the list of users for
 *    this session.  User UID is assigned and returned.
 *
 * Transition T1
 *
 *    Subsequent SMB Session Setup requests (on the same UID
 *    assigned in T0) update the state of this user object,
 *    communicating with smbd for the crypto work.
 *
 * Transition T2
 *
 *    If the SMB Session Setup sequence is successful, T2
 *    makes the new user object available for requests.
 *
 * Transition T3
 *
 *    If an Session Setup request gets an error other than
 *    the expected "more processing required", then T3
 *    leads to state "LOGGED_OFF" and then tear-down of the
 *    partially constructed user.
 *
 * Transition T4
 *
 *    Normal SMB User Logoff request, or session tear-down.
 *
 * Transition T5
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
 *      - The list of users of the session they belong to.
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
 *       list) have to be entered, the lock must be entered first. Additionally,
 *       one may NOT flush the deleteq of either the tree list or the ofile list
 *       while the user mutex is held.
 *
 *    2) All actions applied to a user require a reference count.
 *
 *    3) There are 2 ways of getting a reference count. One is when the user
 *       logs in. The other when the user is looked up.
 *
 *    It should be noted that the reference count of a user registers the
 *    number of references to the user in other structures (such as an smb
 *    request). The reference count is not incremented in these 2 instances:
 *
 *    1) The user is logged in. An user is anchored by their state. If there's
 *       no activity involving a user currently logged in, the reference
 *       count of that user is zero.
 *
 *    2) The user is queued in the list of users of the session. The fact of
 *       being queued in that list is NOT registered by incrementing the
 *       reference count.
 */
#include <sys/types.h>
#include <sys/sid.h>
#include <sys/priv_names.h>
#include <sys/priv.h>
#include <sys/policy.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_door.h>

#define	ADMINISTRATORS_SID	"S-1-5-32-544"

/* Don't leak object addresses */
#define	SMB_USER_SSNID(u) \
	((uintptr_t)&smb_cache_user ^ (uintptr_t)(u))

static void smb_user_delete(void *);
static int smb_user_enum_private(smb_user_t *, smb_svcenum_t *);
static void smb_user_auth_logoff(smb_user_t *);
static void smb_user_logoff_tq(void *);

/*
 * Create a new user.
 *
 * For SMB2 and later, session IDs (u_ssnid) need to be unique among all
 * current and "recent" sessions.  The session ID is derived from the
 * address of the smb_user object (obscured by XOR with a constant).
 * This adds a 3-bit generation number in the low bits, incremented
 * when we allocate an smb_user_t from its kmem cache, so it can't
 * be confused with a (recent) previous incarnation of this object.
 */
smb_user_t *
smb_user_new(smb_session_t *session)
{
	smb_user_t	*user;
	uint_t		gen;	// generation (low 3 bits of ssnid)
	uint32_t	ucount;

	ASSERT(session);
	ASSERT(session->s_magic == SMB_SESSION_MAGIC);

	user = kmem_cache_alloc(smb_cache_user, KM_SLEEP);
	gen = (user->u_ssnid + 1) & 7;
	bzero(user, sizeof (smb_user_t));

	user->u_refcnt = 1;
	user->u_session = session;
	user->u_server = session->s_server;
	user->u_logon_time = gethrestime_sec();

	if (smb_idpool_alloc(&session->s_uid_pool, &user->u_uid))
		goto errout;
	user->u_ssnid = SMB_USER_SSNID(user) + gen;

	mutex_init(&user->u_mutex, NULL, MUTEX_DEFAULT, NULL);
	user->u_state = SMB_USER_STATE_LOGGING_ON;
	user->u_magic = SMB_USER_MAGIC;

	smb_llist_enter(&session->s_user_list, RW_WRITER);
	ucount = smb_llist_get_count(&session->s_user_list);
	smb_llist_insert_tail(&session->s_user_list, user);
	smb_llist_exit(&session->s_user_list);
	smb_server_inc_users(session->s_server);

	/*
	 * If we added the first user to the session, cancel the
	 * timeout that was started in smb_session_receiver().
	 */
	if (ucount == 0) {
		timeout_id_t tmo = NULL;

		smb_rwx_rwenter(&session->s_lock, RW_WRITER);
		tmo = session->s_auth_tmo;
		session->s_auth_tmo = NULL;
		smb_rwx_rwexit(&session->s_lock);

		if (tmo != NULL)
			(void) untimeout(tmo);
	}

	return (user);

errout:
	if (user->u_uid != 0)
		smb_idpool_free(&session->s_uid_pool, user->u_uid);
	kmem_cache_free(smb_cache_user, user);
	return (NULL);
}

/*
 * Fill in the details of a user, meaning a transition
 * from state LOGGING_ON to state LOGGED_ON.
 */
int
smb_user_logon(
    smb_user_t		*user,
    cred_t		*cr,
    char		*domain_name,
    char		*account_name,
    uint32_t		flags,
    uint32_t		privileges,
    uint32_t		audit_sid)
{
	ksocket_t authsock = NULL;
	timeout_id_t tmo = NULL;

	ASSERT(user->u_magic == SMB_USER_MAGIC);
	ASSERT(cr);
	ASSERT(account_name);
	ASSERT(domain_name);

	mutex_enter(&user->u_mutex);

	if (user->u_state != SMB_USER_STATE_LOGGING_ON) {
		mutex_exit(&user->u_mutex);
		return (-1);
	}

	/*
	 * In the transition from LOGGING_ON to LOGGED_ON,
	 * we always have an auth. socket to close.
	 */
	authsock = user->u_authsock;
	user->u_authsock = NULL;
	tmo = user->u_auth_tmo;
	user->u_auth_tmo = NULL;

	user->u_state = SMB_USER_STATE_LOGGED_ON;
	user->u_flags = flags;
	user->u_name_len = strlen(account_name) + 1;
	user->u_domain_len = strlen(domain_name) + 1;
	user->u_name = smb_mem_strdup(account_name);
	user->u_domain = smb_mem_strdup(domain_name);
	user->u_audit_sid = audit_sid;

	smb_user_setcred(user, cr, privileges);

	mutex_exit(&user->u_mutex);

	/* Timeout callback takes u_mutex. See untimeout(9f) */
	if (tmo != NULL)
		(void) untimeout(tmo);

	/* This close can block, so not under the mutex. */
	if (authsock != NULL)
		smb_authsock_close(user, authsock);

	return (0);
}

/*
 * smb_user_logoff
 *
 * Change the user state to "logging off" and disconnect trees.
 * The user list must not be entered or modified here.
 *
 * We remain in state "logging off" until the last ref. is gone,
 * then smb_user_release takes us to state "logged off".
 */
void
smb_user_logoff(
    smb_user_t		*user)
{
	ksocket_t authsock = NULL;
	timeout_id_t tmo = NULL;

	ASSERT(user->u_magic == SMB_USER_MAGIC);

	mutex_enter(&user->u_mutex);
	ASSERT(user->u_refcnt);
	switch (user->u_state) {
	case SMB_USER_STATE_LOGGING_ON:
		authsock = user->u_authsock;
		user->u_authsock = NULL;
		tmo = user->u_auth_tmo;
		user->u_auth_tmo = NULL;
		user->u_state = SMB_USER_STATE_LOGGING_OFF;
		mutex_exit(&user->u_mutex);

		/* Timeout callback takes u_mutex. See untimeout(9f) */
		if (tmo != NULL)
			(void) untimeout(tmo);
		/* This close can block, so not under the mutex. */
		if (authsock != NULL)
			smb_authsock_close(user, authsock);
		break;

	case SMB_USER_STATE_LOGGED_ON:
		/*
		 * The user is moved into a state indicating that the log off
		 * process has started.
		 */
		user->u_state = SMB_USER_STATE_LOGGING_OFF;
		mutex_exit(&user->u_mutex);
		smb_session_disconnect_owned_trees(user->u_session, user);
		smb_user_auth_logoff(user);
		break;

	case SMB_USER_STATE_LOGGED_OFF:
	case SMB_USER_STATE_LOGGING_OFF:
		mutex_exit(&user->u_mutex);
		break;

	default:
		ASSERT(0);
		mutex_exit(&user->u_mutex);
		break;
	}
}

/*
 * Take a reference on a user.  Do not return a reference unless the user is in
 * the logged-in state.
 */
boolean_t
smb_user_hold(smb_user_t *user)
{
	SMB_USER_VALID(user);

	mutex_enter(&user->u_mutex);

	if (user->u_state == SMB_USER_STATE_LOGGED_ON) {
		user->u_refcnt++;
		mutex_exit(&user->u_mutex);
		return (B_TRUE);
	}

	mutex_exit(&user->u_mutex);
	return (B_FALSE);
}

/*
 * Unconditionally take a reference on a user.
 */
void
smb_user_hold_internal(smb_user_t *user)
{
	SMB_USER_VALID(user);

	mutex_enter(&user->u_mutex);
	user->u_refcnt++;
	mutex_exit(&user->u_mutex);
}

/*
 * Release a reference on a user.  If the reference count falls to
 * zero and the user has logged off, post the object for deletion.
 * Object deletion is deferred to avoid modifying a list while an
 * iteration may be in progress.
 */
void
smb_user_release(
    smb_user_t		*user)
{
	smb_session_t *ssn = user->u_session;

	SMB_USER_VALID(user);

	/* flush the tree list delete queue */
	smb_llist_flush(&ssn->s_tree_list);

	mutex_enter(&user->u_mutex);
	ASSERT(user->u_refcnt);
	user->u_refcnt--;

	switch (user->u_state) {
	case SMB_USER_STATE_LOGGING_OFF:
		if (user->u_refcnt == 0) {
			smb_session_t *ssn = user->u_session;
			user->u_state = SMB_USER_STATE_LOGGED_OFF;
			smb_llist_post(&ssn->s_user_list, user,
			    smb_user_delete);
		}
		break;

	case SMB_USER_STATE_LOGGING_ON:
	case SMB_USER_STATE_LOGGED_ON:
		break;

	case SMB_USER_STATE_LOGGED_OFF:
	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&user->u_mutex);
}

/*
 * Timeout handler for user logons that stay too long in
 * state SMB_USER_STATE_LOGGING_ON.  This is setup by a
 * timeout call in smb_authsock_open, and called in a
 * callout thread, so schedule a taskq job to do the
 * real work of logging off this user.
 */
void
smb_user_auth_tmo(void *arg)
{
	smb_user_t *user = arg;
	smb_request_t *sr;
	taskqid_t tqid;

	SMB_USER_VALID(user);

	/*
	 * If we can't allocate a request, it means the
	 * session is being torn down, so nothing to do.
	 */
	sr = smb_request_alloc(user->u_session, 0);
	if (sr == NULL)
		return;

	/*
	 * Check user state, and take a hold if it's
	 * still logging on.  If not, we're done.
	 */
	mutex_enter(&user->u_mutex);
	if (user->u_state != SMB_USER_STATE_LOGGING_ON) {
		mutex_exit(&user->u_mutex);
		smb_request_free(sr);
		return;
	}
	/* smb_user_hold_internal */
	user->u_refcnt++;
	mutex_exit(&user->u_mutex);

	/*
	 * The user hold is given to the SR, and released in
	 * smb_user_logoff_tq / smb_request_free
	 */
	sr->uid_user = user;
	sr->user_cr = user->u_cred;
	sr->sr_state = SMB_REQ_STATE_SUBMITTED;
	tqid = taskq_dispatch(
	    user->u_server->sv_worker_pool,
	    smb_user_logoff_tq, sr, TQ_SLEEP);
	VERIFY(tqid != TASKQID_INVALID);
}

/*
 * Helper for smb_user_auth_tmo()
 */
static void
smb_user_logoff_tq(void *arg)
{
	smb_request_t	*sr = arg;

	SMB_REQ_VALID(sr);

	mutex_enter(&sr->sr_mutex);
	sr->sr_worker = curthread;
	sr->sr_state = SMB_REQ_STATE_ACTIVE;
	mutex_exit(&sr->sr_mutex);

	smb_user_logoff(sr->uid_user);

	sr->sr_state = SMB_REQ_STATE_COMPLETED;
	smb_request_free(sr);
}

/*
 * Determine whether or not the user is an administrator.
 * Members of the administrators group have administrative rights.
 */
boolean_t
smb_user_is_admin(smb_user_t *user)
{
#ifdef	_KERNEL
	char		sidstr[SMB_SID_STRSZ];
	ksidlist_t	*ksidlist;
	ksid_t		*ksid;
	uint32_t	rid;
	int		ret;
#endif	/* _KERNEL */
	boolean_t	rc = B_FALSE;

	ASSERT(user);
	ASSERT(user->u_cred);

	if (SMB_USER_IS_ADMIN(user))
		return (B_TRUE);

#ifdef	_KERNEL
	(void) strlcpy(sidstr, ADMINISTRATORS_SID, SMB_SID_STRSZ);
	ret = smb_sid_splitstr(sidstr, &rid);
	ASSERT3S(ret, ==, 0);

	ksidlist = crgetsidlist(user->u_cred);
	ASSERT(ksidlist);

	ksid = crgetsid(user->u_cred, KSID_USER);
	ASSERT(ksid != NULL);
	ASSERT(ksid->ks_domain != NULL);
	ASSERT(ksid->ks_domain->kd_name != NULL);

	if ((rid == ksid->ks_rid &&
	    strcmp(sidstr, ksid_getdomain(ksid)) == 0) ||
	    ksidlist_has_sid(ksidlist, sidstr, rid)) {
		user->u_flags |= SMB_USER_FLAG_ADMIN;
		rc = B_TRUE;
	}

#endif	/* _KERNEL */
	return (rc);
}

/*
 * This function should be called with a hold on the user.
 */
boolean_t
smb_user_namecmp(smb_user_t *user, const char *name)
{
	char		*fq_name;
	boolean_t	match;

	if (smb_strcasecmp(name, user->u_name, 0) == 0)
		return (B_TRUE);

	fq_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	(void) snprintf(fq_name, MAXNAMELEN, "%s\\%s",
	    user->u_domain, user->u_name);

	match = (smb_strcasecmp(name, fq_name, 0) == 0);
	if (!match) {
		(void) snprintf(fq_name, MAXNAMELEN, "%s@%s",
		    user->u_name, user->u_domain);

		match = (smb_strcasecmp(name, fq_name, 0) == 0);
	}

	kmem_free(fq_name, MAXNAMELEN);
	return (match);
}

/*
 * If the enumeration request is for user data, handle the request
 * here.  Otherwise, pass it on to the trees.
 *
 * This function should be called with a hold on the user.
 */
int
smb_user_enum(smb_user_t *user, smb_svcenum_t *svcenum)
{
	int		rc = 0;

	ASSERT(user);
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	if (svcenum->se_type == SMB_SVCENUM_TYPE_USER)
		return (smb_user_enum_private(user, svcenum));

	return (rc);
}

/*
 * Count references by trees this user owns,
 * and allow waiting for them to go away.
 */
void
smb_user_inc_trees(smb_user_t *user)
{
	mutex_enter(&user->u_mutex);
	user->u_owned_tree_cnt++;
	mutex_exit(&user->u_mutex);
}

void
smb_user_dec_trees(smb_user_t *user)
{
	mutex_enter(&user->u_mutex);
	user->u_owned_tree_cnt--;
	if (user->u_owned_tree_cnt == 0)
		cv_broadcast(&user->u_owned_tree_cv);
	mutex_exit(&user->u_mutex);
}

int smb_user_wait_tree_tmo = 30;

/*
 * Wait (up to 30 sec.) for trees to go away.
 * Should happen in less than a second.
 */
void
smb_user_wait_trees(smb_user_t *user)
{
	clock_t	time;

	time = SEC_TO_TICK(smb_user_wait_tree_tmo) + ddi_get_lbolt();
	mutex_enter(&user->u_mutex);
	while (user->u_owned_tree_cnt != 0) {
		if (cv_timedwait(&user->u_owned_tree_cv,
		    &user->u_mutex, time) < 0)
			break;
	}
	mutex_exit(&user->u_mutex);
	if (user->u_owned_tree_cnt != 0) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "!smb_user_wait_trees failed");
#endif
		DTRACE_PROBE1(max__wait, smb_user_t *, user);
	}
}

/* *************************** Static Functions ***************************** */

/*
 * Delete a user.  The tree list should be empty.
 *
 * Remove the user from the session's user list before freeing resources
 * associated with the user.
 */
static void
smb_user_delete(void *arg)
{
	smb_session_t	*session;
	smb_user_t	*user = (smb_user_t *)arg;
	uint32_t	ucount;

	SMB_USER_VALID(user);
	ASSERT(user->u_refcnt == 0);
	ASSERT(user->u_state == SMB_USER_STATE_LOGGED_OFF);
	ASSERT(user->u_authsock == NULL);
	ASSERT(user->u_auth_tmo == NULL);

	session = user->u_session;

	smb_server_dec_users(session->s_server);
	smb_llist_enter(&session->s_user_list, RW_WRITER);
	smb_llist_remove(&session->s_user_list, user);
	smb_idpool_free(&session->s_uid_pool, user->u_uid);
	ucount = smb_llist_get_count(&session->s_user_list);
	smb_llist_exit(&session->s_user_list);

	/*
	 * When the last smb_user_t object goes away, schedule a timeout
	 * after which we'll terminate this session if the client hasn't
	 * authenticated another smb_user_t on this session by then.
	 */
	if (ucount == 0) {
		smb_rwx_rwenter(&session->s_lock, RW_WRITER);
		if (session->s_state == SMB_SESSION_STATE_NEGOTIATED &&
		    session->s_auth_tmo == NULL) {
			session->s_auth_tmo =
			    timeout((tmo_func_t)smb_session_disconnect,
			    session, SEC_TO_TICK(smb_session_auth_tmo));
		}
		smb_rwx_cvbcast(&session->s_lock);
		smb_rwx_rwexit(&session->s_lock);
	}

	/*
	 * This user is no longer on s_user_list, however...
	 *
	 * This is called via smb_llist_post, which means it may run
	 * BEFORE smb_user_release drops u_mutex (if another thread
	 * flushes the delete queue before we do).  Synchronize.
	 */
	mutex_enter(&user->u_mutex);
	mutex_exit(&user->u_mutex);

	user->u_magic = (uint32_t)~SMB_USER_MAGIC;
	mutex_destroy(&user->u_mutex);
	if (user->u_cred)
		crfree(user->u_cred);
	if (user->u_privcred)
		crfree(user->u_privcred);
	smb_mem_free(user->u_name);
	smb_mem_free(user->u_domain);
	kmem_cache_free(smb_cache_user, user);
}

cred_t *
smb_user_getcred(smb_user_t *user)
{
	return (user->u_cred);
}

cred_t *
smb_user_getprivcred(smb_user_t *user)
{
	return ((user->u_privcred)? user->u_privcred : user->u_cred);
}

#ifdef	_KERNEL
/*
 * Assign the user cred and privileges.
 *
 * If the user has backup and/or restore privleges, dup the cred
 * and add those privileges to this new privileged cred.
 */
void
smb_user_setcred(smb_user_t *user, cred_t *cr, uint32_t privileges)
{
	cred_t *privcred = NULL;

	ASSERT(cr);
	crhold(cr);

	/*
	 * See smb.4 bypass_traverse_checking
	 *
	 * For historical reasons, the Windows privilege is named
	 * SeChangeNotifyPrivilege, though the description is
	 * "Bypass traverse checking".
	 */
	if ((privileges & SMB_USER_PRIV_CHANGE_NOTIFY) != 0) {
		(void) crsetpriv(cr, PRIV_FILE_DAC_SEARCH, NULL);
	}

	/*
	 * Window's "take ownership privilege" is similar to our
	 * PRIV_FILE_CHOWN privilege. It's normally given to members of the
	 * "Administrators" group, which normally includes the the local
	 * Administrator (like root) and when joined to a domain,
	 * "Domain Admins".
	 */
	if ((privileges & SMB_USER_PRIV_TAKE_OWNERSHIP) != 0) {
		(void) crsetpriv(cr,
		    PRIV_FILE_CHOWN,
		    PRIV_FILE_CHOWN_SELF,
		    NULL);
	}

	/*
	 * Bypass ACL for READ accesses.
	 */
	if ((privileges & SMB_USER_PRIV_READ_FILE) != 0) {
		(void) crsetpriv(cr, PRIV_FILE_DAC_READ, NULL);
	}

	/*
	 * Bypass ACL for WRITE accesses.
	 * Include FILE_OWNER, as it covers WRITE_ACL and DELETE.
	 */
	if ((privileges & SMB_USER_PRIV_WRITE_FILE) != 0) {
		(void) crsetpriv(cr,
		    PRIV_FILE_DAC_WRITE,
		    PRIV_FILE_OWNER,
		    NULL);
	}

	/*
	 * These privileges are used only when a file is opened with
	 * 'backup intent'. These allow users to bypass certain access
	 * controls. Administrators typically have these privileges,
	 * and they are used during recursive take-ownership operations.
	 * Some commonly used tools use 'backup intent' to administrate
	 * files that do not grant explicit permissions to Administrators.
	 */
	if (privileges & (SMB_USER_PRIV_BACKUP | SMB_USER_PRIV_RESTORE))
		privcred = crdup(cr);

	if (privcred != NULL) {
		if (privileges & SMB_USER_PRIV_BACKUP) {
			(void) crsetpriv(privcred, PRIV_FILE_DAC_READ,
			    PRIV_FILE_DAC_SEARCH, PRIV_SYS_MOUNT, NULL);
		}

		if (privileges & SMB_USER_PRIV_RESTORE) {
			(void) crsetpriv(privcred, PRIV_FILE_DAC_WRITE,
			    PRIV_FILE_CHOWN, PRIV_FILE_CHOWN_SELF,
			    PRIV_FILE_DAC_SEARCH, PRIV_FILE_LINK_ANY,
			    PRIV_FILE_OWNER, PRIV_FILE_SETID,
			    PRIV_SYS_LINKDIR, PRIV_SYS_MOUNT, NULL);
		}
	}

	user->u_cred = cr;
	user->u_privcred = privcred;
	user->u_privileges = privileges;
}
#endif	/* _KERNEL */

/*
 * Determines whether a user can be granted ACCESS_SYSTEM_SECURITY
 */
boolean_t
smb_user_has_security_priv(smb_user_t *user, cred_t *cr)
{
	/* Need SeSecurityPrivilege to get/set SACL */
	if ((user->u_privileges & SMB_USER_PRIV_SECURITY) != 0)
		return (B_TRUE);

#ifdef _KERNEL
	/*
	 * ACCESS_SYSTEM_SECURITY is also granted if the file is opened with
	 * BACKUP/RESTORE intent by a user with BACKUP/RESTORE privilege,
	 * which means we'll be using u_privcred.
	 *
	 * We translate BACKUP as DAC_READ and RESTORE as DAC_WRITE,
	 * to account for our various SMB_USER_* privileges.
	 */
	if (PRIV_POLICY_ONLY(cr,
	    priv_getbyname(PRIV_FILE_DAC_READ, 0), B_FALSE) ||
	    PRIV_POLICY_ONLY(cr,
	    priv_getbyname(PRIV_FILE_DAC_WRITE, 0), B_FALSE))
		return (B_TRUE);
#else
	/*
	 * No "real" privileges in fksmbsrv, so use the SMB privs instead.
	 */
	if ((user->u_privileges &
	    (SMB_USER_PRIV_BACKUP |
	    SMB_USER_PRIV_RESTORE |
	    SMB_USER_PRIV_READ_FILE |
	    SMB_USER_PRIV_WRITE_FILE)) != 0)
		return (B_TRUE);
#endif

	return (B_FALSE);
}

/*
 * Private function to support smb_user_enum.
 */
static int
smb_user_enum_private(smb_user_t *user, smb_svcenum_t *svcenum)
{
	uint8_t *pb;
	uint_t nbytes;
	int rc;

	if (svcenum->se_nskip > 0) {
		svcenum->se_nskip--;
		return (0);
	}

	if (svcenum->se_nitems >= svcenum->se_nlimit) {
		svcenum->se_nitems = svcenum->se_nlimit;
		return (0);
	}

	pb = &svcenum->se_buf[svcenum->se_bused];
	rc = smb_user_netinfo_encode(user, pb, svcenum->se_bavail, &nbytes);
	if (rc == 0) {
		svcenum->se_bavail -= nbytes;
		svcenum->se_bused += nbytes;
		svcenum->se_nitems++;
	}

	return (rc);
}

/*
 * Encode the NetInfo for a user into a buffer.  NetInfo contains
 * information that is often needed in user space to support RPC
 * requests.
 */
int
smb_user_netinfo_encode(smb_user_t *user, uint8_t *buf, size_t buflen,
    uint32_t *nbytes)
{
	smb_netuserinfo_t	info;
	int			rc;

	smb_user_netinfo_init(user, &info);
	rc = smb_netuserinfo_encode(&info, buf, buflen, nbytes);
	smb_user_netinfo_fini(&info);

	return (rc);
}

void
smb_user_netinfo_init(smb_user_t *user, smb_netuserinfo_t *info)
{
	smb_session_t	*session;
	char		*buf;

	ASSERT(user);
	ASSERT(user->u_domain);
	ASSERT(user->u_name);

	session = user->u_session;
	ASSERT(session);
	ASSERT(session->workstation);

	info->ui_session_id = session->s_kid;
	info->ui_user_id = user->u_ssnid;
	info->ui_native_os = session->native_os;
	info->ui_ipaddr = session->ipaddr;
	info->ui_numopens = session->s_file_cnt;
	info->ui_logon_time = user->u_logon_time;
	info->ui_flags = user->u_flags;
	info->ui_posix_uid = crgetuid(user->u_cred);

	info->ui_domain_len = user->u_domain_len;
	info->ui_domain = smb_mem_strdup(user->u_domain);

	info->ui_account_len = user->u_name_len;
	info->ui_account = smb_mem_strdup(user->u_name);

	buf = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	smb_session_getclient(session, buf, MAXNAMELEN);
	info->ui_workstation_len = strlen(buf) + 1;
	info->ui_workstation = smb_mem_strdup(buf);
	kmem_free(buf, MAXNAMELEN);
}

void
smb_user_netinfo_fini(smb_netuserinfo_t *info)
{
	if (info == NULL)
		return;

	if (info->ui_domain)
		smb_mem_free(info->ui_domain);
	if (info->ui_account)
		smb_mem_free(info->ui_account);
	if (info->ui_workstation)
		smb_mem_free(info->ui_workstation);

	bzero(info, sizeof (smb_netuserinfo_t));
}

uint64_t smb_user_auth_logoff_failures;

/*
 * Tell smbd this user is going away so it can clean up their
 * audit session, autohome dir, etc.
 *
 * Note that when we're shutting down, smbd will already have set
 * smbd.s_shutting_down and therefore will ignore door calls.
 * Skip this during shutdown to reduce upcall noise.
 */
static void
smb_user_auth_logoff(smb_user_t *user)
{
	smb_server_t *sv = user->u_server;
	uint32_t audit_sid;

	if (sv->sv_state != SMB_SERVER_STATE_RUNNING)
		return;

	if (smb_threshold_enter(&sv->sv_logoff_ct) != 0) {
		smb_user_auth_logoff_failures++;
		return;
	}

	audit_sid = user->u_audit_sid;
	(void) smb_kdoor_upcall(sv, SMB_DR_USER_AUTH_LOGOFF,
	    &audit_sid, xdr_uint32_t, NULL, NULL);

	smb_threshold_exit(&sv->sv_logoff_ct);
}

boolean_t
smb_is_same_user(cred_t *cr1, cred_t *cr2)
{
	ksid_t *ks1 = crgetsid(cr1, KSID_USER);
	ksid_t *ks2 = crgetsid(cr2, KSID_USER);

	if (ks1 == NULL || ks2 == NULL) {
		return (B_FALSE);
	}
	return (ks1->ks_rid == ks2->ks_rid &&
	    strcmp(ks1->ks_domain->kd_name, ks2->ks_domain->kd_name) == 0);
}
