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
 * Copyright 2014 Nexenta Systems, Inc. All rights reserved.
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
 *      - The user is in the list of users for his session.
 *      - References will be given out ONLY for session setup.
 *      - This user can not access anything yet.
 *
 * SMB_USER_STATE_LOGGED_ON
 *
 *    While in this state:
 *      - The user is in the list of users for his session.
 *      - References will be given out if the user is looked up.
 *      - The user can access files and pipes.
 *
 * SMB_USER_STATE_LOGGING_OFF
 *
 *    While in this state:
 *      - The user is in the list of users for his session.
 *      - References will not be given out if the user is looked up.
 *      - The trees the user connected are being disconnected.
 *      - The resources associated with the user remain.
 *
 * SMB_USER_STATE_LOGGED_OFF
 *
 *    While in this state:
 *      - The user is queued in the list of users of his session.
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
 *       logs in. The other when the user is looked up.
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
#include <sys/types.h>
#include <sys/sid.h>
#include <sys/priv_names.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_door.h>

#define	ADMINISTRATORS_SID	"S-1-5-32-544"

static int smb_user_enum_private(smb_user_t *, smb_svcenum_t *);
static void smb_user_auth_logoff(smb_user_t *);


/*
 * Create a new user.
 */
smb_user_t *
smb_user_new(smb_session_t *session)
{
	smb_user_t	*user;

	ASSERT(session);
	ASSERT(session->s_magic == SMB_SESSION_MAGIC);

	user = kmem_cache_alloc(smb_cache_user, KM_SLEEP);
	bzero(user, sizeof (smb_user_t));

	user->u_refcnt = 1;
	user->u_session = session;
	user->u_server = session->s_server;
	user->u_logon_time = gethrestime_sec();

	if (smb_idpool_alloc(&session->s_uid_pool, &user->u_uid))
		goto errout;

	mutex_init(&user->u_mutex, NULL, MUTEX_DEFAULT, NULL);
	user->u_state = SMB_USER_STATE_LOGGING_ON;
	user->u_magic = SMB_USER_MAGIC;

	smb_llist_enter(&session->s_user_list, RW_WRITER);
	smb_llist_insert_tail(&session->s_user_list, user);
	smb_llist_exit(&session->s_user_list);
	smb_server_inc_users(session->s_server);

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

	ASSERT(user->u_magic == SMB_USER_MAGIC);
	ASSERT(cr);
	ASSERT(account_name);
	ASSERT(domain_name);

	mutex_enter(&user->u_mutex);

	if (user->u_state != SMB_USER_STATE_LOGGING_ON) {
		mutex_exit(&user->u_mutex);
		return (-1);
	}

	smb_authsock_close(user);

	user->u_state = SMB_USER_STATE_LOGGED_ON;
	user->u_flags = flags;
	user->u_name_len = strlen(account_name) + 1;
	user->u_domain_len = strlen(domain_name) + 1;
	user->u_name = smb_mem_strdup(account_name);
	user->u_domain = smb_mem_strdup(domain_name);
	user->u_audit_sid = audit_sid;

	smb_user_setcred(user, cr, privileges);

	mutex_exit(&user->u_mutex);

	return (0);
}

/*
 * smb_user_logoff
 *
 * Change the user state and disconnect trees.
 * The user list must not be entered or modified here.
 */
void
smb_user_logoff(
    smb_user_t		*user)
{
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	mutex_enter(&user->u_mutex);
	ASSERT(user->u_refcnt);
	switch (user->u_state) {
	case SMB_USER_STATE_LOGGING_ON: {
		smb_authsock_close(user);
		user->u_state = SMB_USER_STATE_LOGGED_OFF;
		smb_server_dec_users(user->u_server);
		break;
	}

	case SMB_USER_STATE_LOGGED_ON: {
		/*
		 * The user is moved into a state indicating that the log off
		 * process has started.
		 */
		user->u_state = SMB_USER_STATE_LOGGING_OFF;
		mutex_exit(&user->u_mutex);
		smb_session_disconnect_owned_trees(user->u_session, user);
		smb_user_auth_logoff(user);
		mutex_enter(&user->u_mutex);
		user->u_state = SMB_USER_STATE_LOGGED_OFF;
		smb_server_dec_users(user->u_server);
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
	ASSERT(user->u_magic == SMB_USER_MAGIC);

	mutex_enter(&user->u_mutex);
	ASSERT(user->u_refcnt);
	user->u_refcnt--;

	switch (user->u_state) {
	case SMB_USER_STATE_LOGGED_OFF:
		if (user->u_refcnt == 0)
			smb_session_post_user(user->u_session, user);
		break;

	case SMB_USER_STATE_LOGGING_ON:
	case SMB_USER_STATE_LOGGED_ON:
	case SMB_USER_STATE_LOGGING_OFF:
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&user->u_mutex);
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
	ksid_t		ksid1;
	ksid_t		*ksid2;
	int		i;
#endif	/* _KERNEL */
	boolean_t	rc = B_FALSE;

	ASSERT(user);
	ASSERT(user->u_cred);

	if (SMB_USER_IS_ADMIN(user))
		return (B_TRUE);

#ifdef	_KERNEL
	bzero(&ksid1, sizeof (ksid_t));
	(void) strlcpy(sidstr, ADMINISTRATORS_SID, SMB_SID_STRSZ);
	ASSERT(smb_sid_splitstr(sidstr, &ksid1.ks_rid) == 0);
	ksid1.ks_domain = ksid_lookupdomain(sidstr);

	ksidlist = crgetsidlist(user->u_cred);
	ASSERT(ksidlist);
	ASSERT(ksid1.ks_domain);
	ASSERT(ksid1.ks_domain->kd_name);

	i = 0;
	ksid2 = crgetsid(user->u_cred, KSID_USER);
	do {
		ASSERT(ksid2->ks_domain);
		ASSERT(ksid2->ks_domain->kd_name);

		if (strcmp(ksid1.ks_domain->kd_name,
		    ksid2->ks_domain->kd_name) == 0 &&
		    ksid1.ks_rid == ksid2->ks_rid) {
			user->u_flags |= SMB_USER_FLAG_ADMIN;
			rc = B_TRUE;
			break;
		}

		ksid2 = &ksidlist->ksl_sids[i];
	} while (i++ < ksidlist->ksl_nsid);

	ksid_rele(&ksid1);
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

/* *************************** Static Functions ***************************** */

/*
 * Delete a user.  The tree list should be empty.
 *
 * Remove the user from the session's user list before freeing resources
 * associated with the user.
 */
void
smb_user_delete(void *arg)
{
	smb_session_t	*session;
	smb_user_t	*user = (smb_user_t *)arg;

	SMB_USER_VALID(user);
	ASSERT(user->u_refcnt == 0);
	ASSERT(user->u_state == SMB_USER_STATE_LOGGED_OFF);
	ASSERT(user->u_authsock == NULL);

	session = user->u_session;
	smb_llist_enter(&session->s_user_list, RW_WRITER);
	smb_llist_remove(&session->s_user_list, user);
	smb_idpool_free(&session->s_uid_pool, user->u_uid);
	smb_llist_exit(&session->s_user_list);

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
	info->ui_native_os = session->native_os;
	info->ui_ipaddr = session->ipaddr;
	info->ui_numopens = session->s_file_cnt;
	info->ui_smb_uid = user->u_uid;
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

static void
smb_user_auth_logoff(smb_user_t *user)
{
	uint32_t audit_sid = user->u_audit_sid;

	(void) smb_kdoor_upcall(user->u_server, SMB_DR_USER_AUTH_LOGOFF,
	    &audit_sid, xdr_uint32_t, NULL, NULL);
}
