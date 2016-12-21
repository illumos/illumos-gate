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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * There are well defined policies for mapping uid and gid values to and
 * from utf8 strings, as specified in RFC 7530. The protocol ops that are
 * most significantly affected by any changes in policy are GETATTR and
 * SETATTR, as these have different behavior depending on whether the id
 * mapping code is executing on the client or server. Thus, the following
 * rules represents the latest incantation of the id mapping policies.
 *
 * 1) For the case in which the nfsmapid(1m) daemon has _never_ been
 *    started, the policy is to _always_ work with stringified uid's
 *    and gid's
 *
 * 2) For the case in which the nfsmapid(1m) daemon _was_ started but
 *    has either died or become unresponsive, the mapping policies are
 *    as follows:
 *
 *                      Server                             Client
 *         .-------------------------------.---------------------------------.
 *         |                               |                                 |
 *         | . Respond to req by replying  | . If attr string does not have  |
 *         |   success and map the [u/g]id |   '@' sign, attempt to decode   |
 *         |   into its literal id string  |   a stringified id; map to      |
 *         |                               |   *ID_NOBODY if not an encoded  |
 *         |                               |   id.                           |
 *         |                               |                                 |
 * GETATTR |                               | . If attr string _does_ have    |
 *         |                               |   '@' sign			     |
 *         |                               |   Map to *ID_NOBODY on failure. |
 *         |                               |                                 |
 *         | nfs_idmap_*id_str             | nfs_idmap_str_*id               |
 *         +-------------------------------+---------------------------------+
 *         |                               |                                 |
 *         | . Respond to req by returning | . _Must_ map the user's passed  |
 *         |  ECOMM, which will be mapped  |  in [u/g]id into it's network   |
 *         |  to NFS4ERR_DELAY to clnt     |  attr string, so contact the    |
 *         |                               |  daemon, retrying forever if    |
 *         |   Server must not allow the   |  necessary, unless interrupted  |
 * SETATTR |   mapping to *ID_NOBODY upon  |                                 |
 *         |   lack of communication with  |   Client _should_ specify the   |
 *         |   the daemon, which could     |   correct attr string for a     |
 *         |   result in the file being    |   SETATTR operation, otherwise  |
 *         |   inadvertently given away !  |   it can also result in the     |
 *         |                               |   file being inadvertently      |
 *         |                               |   given away !                  |
 *         |                               |                                 |
 *         | nfs_idmap_str_*id             |   nfs_idmap_*id_str             |
 *         `-------------------------------'---------------------------------'
 *
 * 3) Lastly, in order to leverage better cache utilization whenever
 *    communication with nfsmapid(1m) is currently hindered, cache
 *    entry eviction is throttled whenever nfsidmap_daemon_dh == NULL.
 *
 *
 *  Server-side behavior for upcall communication errors
 *  ====================================================
 *
 *   GETATTR - Server-side GETATTR *id to attr string conversion policies
 *             for unresponsive/dead nfsmapid(1m) daemon
 *
 *	a) If the *id is *ID_NOBODY, the string "nobody" is returned
 *
 *	b) If the *id is not *ID_NOBODY _and_ the nfsmapid(1m) daemon
 *	   _is_ operational, the daemon is contacted to convert the
 *	   [u/g]id into a string of type "[user/group]@domain"
 *
 *	c) If the nfsmapid(1m) daemon has died or has become unresponsive,
 *	   the server returns status == NFS4_OK for the GETATTR operation,
 *	   and returns a strigified [u/g]id to let the client map it into
 *	   the appropriate value.
 *
 *   SETATTR - Server-side SETATTR attr string to *id conversion policies
 *             for unresponsive/dead nfsmapid(1m) daemon
 *
 *	a) If the otw string is a stringified uid (ie. does _not_ contain
 *	   an '@' sign and is of the form "12345") then the literal uid is
 *	   decoded and it is used to perform the mapping.
 *
 *	b) If, on the other hand, the otw string _is_ of the form
 *	   "[user/group]@domain" and problems arise contacting nfsmapid(1m),
 *	   the SETATTR operation _must_ fail w/NFS4ERR_DELAY, as the server
 *	   cannot default to *ID_NOBODY, which would allow a file to be
 *	   given away by setting it's owner or owner_group to "nobody".
 */
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/disp.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/cred.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/pathname.h>
#include <sys/utsname.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/list.h>
#include <sys/sunddi.h>
#include <sys/dnlc.h>
#include <sys/sdt.h>
#include <sys/pkp_hash.h>
#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <nfs/nfsid_map.h>
#include <nfs/nfs4_idmap_impl.h>
#include <nfs/nfssys.h>

/*
 * Truly global modular globals
 */
zone_key_t			nfsidmap_zone_key;
static list_t			nfsidmap_globals_list;
static kmutex_t			nfsidmap_globals_lock;
static kmem_cache_t		*nfsidmap_cache;
static int			nfs4_idcache_tout;

/*
 * Some useful macros
 */
#define		MOD2(a, pow_of_2)	((a) & ((pow_of_2) - 1))
#define		_CACHE_TOUT		(60*60)		/* secs in 1 hour */
#define		TIMEOUT(x)		(gethrestime_sec() > \
					((x) + nfs4_idcache_tout))
/*
 * Max length of valid id string including the trailing null
 */
#define		_MAXIDSTRLEN		11

#define		ID_HASH(id, hash)					\
{									\
	(hash) = MOD2(((id) ^ NFSID_CACHE_ANCHORS), NFSID_CACHE_ANCHORS); \
}

/*
 * Prototypes
 */

static void	*nfs_idmap_init_zone(zoneid_t);
static void	 nfs_idmap_fini_zone(zoneid_t, void *);

static int	 is_stringified_id(utf8string *);
static void	 nfs_idmap_i2s_literal(uid_t, utf8string *);
static int	 nfs_idmap_s2i_literal(utf8string *, uid_t *, int);
static void	 nfs_idmap_reclaim(void *);
static void	 nfs_idmap_cache_reclaim(idmap_cache_info_t *);
static void	 nfs_idmap_cache_create(idmap_cache_info_t *, const char *);
static void	 nfs_idmap_cache_destroy(idmap_cache_info_t *);
static void	 nfs_idmap_cache_flush(idmap_cache_info_t *);

static uint_t	 nfs_idmap_cache_s2i_lkup(idmap_cache_info_t *, utf8string *,
			uint_t *, uid_t *);

static uint_t	 nfs_idmap_cache_i2s_lkup(idmap_cache_info_t *, uid_t,
			uint_t *, utf8string *);

static void	 nfs_idmap_cache_s2i_insert(idmap_cache_info_t *, uid_t,
			utf8string *, hash_stat, uint_t);

static void	 nfs_idmap_cache_i2s_insert(idmap_cache_info_t *, uid_t,
			utf8string *, hash_stat, uint_t);

static void	 nfs_idmap_cache_rment(nfsidmap_t *);

/*
 * Initialization routine for NFSv4 id mapping
 */
void
nfs_idmap_init(void)
{
	/*
	 * Initialize the kmem cache
	 */
	nfsidmap_cache = kmem_cache_create("NFS_idmap_cache",
	    sizeof (nfsidmap_t), 0, NULL, NULL, nfs_idmap_reclaim, NULL,
	    NULL, 0);
	/*
	 * If not set in "/etc/system", set to default value
	 */
	if (!nfs4_idcache_tout)
		nfs4_idcache_tout = _CACHE_TOUT;
	/*
	 * Initialize the list of nfsidmap_globals
	 */
	mutex_init(&nfsidmap_globals_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&nfsidmap_globals_list, sizeof (struct nfsidmap_globals),
	    offsetof(struct nfsidmap_globals, nig_link));
	/*
	 * Initialize the zone_key_t for per-zone idmaps
	 */
	zone_key_create(&nfsidmap_zone_key, nfs_idmap_init_zone, NULL,
	    nfs_idmap_fini_zone);
}

/*
 * Called only when module was not loaded properly
 */
void
nfs_idmap_fini(void)
{
	(void) zone_key_delete(nfsidmap_zone_key);
	list_destroy(&nfsidmap_globals_list);
	mutex_destroy(&nfsidmap_globals_lock);
	kmem_cache_destroy(nfsidmap_cache);
}

/*ARGSUSED*/
static void *
nfs_idmap_init_zone(zoneid_t zoneid)
{
	struct nfsidmap_globals *nig;

	nig = kmem_alloc(sizeof (*nig), KM_SLEEP);
	nig->nig_msg_done = 0;
	mutex_init(&nig->nfsidmap_daemon_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * nfsidmap certainly isn't running.
	 */
	nig->nfsidmap_pid = NOPID;
	nig->nfsidmap_daemon_dh = NULL;

	/*
	 * Create the idmap caches
	 */
	nfs_idmap_cache_create(&nig->u2s_ci, "u2s_cache");
	nig->u2s_ci.nfsidmap_daemon_dh = &nig->nfsidmap_daemon_dh;
	nfs_idmap_cache_create(&nig->s2u_ci, "s2u_cache");
	nig->s2u_ci.nfsidmap_daemon_dh = &nig->nfsidmap_daemon_dh;
	nfs_idmap_cache_create(&nig->g2s_ci, "g2s_cache");
	nig->g2s_ci.nfsidmap_daemon_dh = &nig->nfsidmap_daemon_dh;
	nfs_idmap_cache_create(&nig->s2g_ci, "s2g_cache");
	nig->s2g_ci.nfsidmap_daemon_dh = &nig->nfsidmap_daemon_dh;

	/*
	 * Add to global list.
	 */
	mutex_enter(&nfsidmap_globals_lock);
	list_insert_head(&nfsidmap_globals_list, nig);
	mutex_exit(&nfsidmap_globals_lock);

	return (nig);
}

/*ARGSUSED*/
static void
nfs_idmap_fini_zone(zoneid_t zoneid, void *arg)
{
	struct nfsidmap_globals *nig = arg;

	/*
	 * Remove from list.
	 */
	mutex_enter(&nfsidmap_globals_lock);
	list_remove(&nfsidmap_globals_list, nig);
	/*
	 * Destroy the idmap caches
	 */
	nfs_idmap_cache_destroy(&nig->u2s_ci);
	nfs_idmap_cache_destroy(&nig->s2u_ci);
	nfs_idmap_cache_destroy(&nig->g2s_ci);
	nfs_idmap_cache_destroy(&nig->s2g_ci);
	mutex_exit(&nfsidmap_globals_lock);
	/*
	 * Cleanup
	 */
	if (nig->nfsidmap_daemon_dh)
		door_ki_rele(nig->nfsidmap_daemon_dh);
	mutex_destroy(&nig->nfsidmap_daemon_lock);
	kmem_free(nig, sizeof (*nig));
}

/*
 * Convert a user utf-8 string identifier into its local uid.
 */
int
nfs_idmap_str_uid(utf8string *u8s, uid_t *uid, bool_t isserver)
{
	int			error;
	uint_t			hashno = 0;
	const char		*whoami = "nfs_idmap_str_uid";
	struct nfsidmap_globals *nig;
	struct mapid_arg	*mapargp;
	struct mapid_res	mapres;
	struct mapid_res	*mapresp = &mapres;
	struct mapid_res	*resp = mapresp;
	door_arg_t		door_args;
	door_handle_t		dh;

	nig = zone_getspecific(nfsidmap_zone_key, nfs_zone());
	ASSERT(nig != NULL);

	if (!u8s || !u8s->utf8string_val || u8s->utf8string_len == 0 ||
	    (u8s->utf8string_val[0] == '\0')) {
		*uid = UID_NOBODY;
		return (isserver ? EINVAL : 0);
	}

	/*
	 * If "nobody", just short circuit and bail
	 */
	if (bcmp(u8s->utf8string_val, "nobody", 6) == 0) {
		*uid = UID_NOBODY;
		return (0);
	}

	/*
	 * Start-off with upcalls disabled, and once nfsmapid(1m) is up and
	 * running, we'll leverage it's first flush to let the kernel know
	 * when it's up and available to perform mappings. Also, on client
	 * only, be smarter about when to issue upcalls by checking the
	 * string for existence of an '@' sign. If no '@' sign, then we just
	 * make our best effort to decode the string ourselves.
	 */
retry:
	mutex_enter(&nig->nfsidmap_daemon_lock);
	dh = nig->nfsidmap_daemon_dh;
	if (dh)
		door_ki_hold(dh);
	mutex_exit(&nig->nfsidmap_daemon_lock);

	if (dh == NULL || nig->nfsidmap_pid == curproc->p_pid ||
	    (!utf8_strchr(u8s, '@') && !isserver)) {
		if (dh)
			door_ki_rele(dh);
		error = nfs_idmap_s2i_literal(u8s, uid, isserver);
		/*
		 * If we get a numeric value, but we only do so because
		 * we are nfsmapid, return ENOTSUP to indicate a valid
		 * response, but not to cache it.
		 */
		if (!error && nig->nfsidmap_pid == curproc->p_pid)
			return (ENOTSUP);
		return (error);
	}

	/* cache hit */
	if (nfs_idmap_cache_s2i_lkup(&nig->s2u_ci, u8s, &hashno, uid)) {
		door_ki_rele(dh);
		return (0);
	}

	/* cache miss */
	mapargp = kmem_alloc(MAPID_ARG_LEN(u8s->utf8string_len), KM_SLEEP);
	mapargp->cmd = NFSMAPID_STR_UID;
	mapargp->u_arg.len = u8s->utf8string_len;
	(void) bcopy(u8s->utf8string_val, mapargp->str, mapargp->u_arg.len);
	mapargp->str[mapargp->u_arg.len] = '\0';

	door_args.data_ptr = (char *)mapargp;
	door_args.data_size = MAPID_ARG_LEN(mapargp->u_arg.len);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = (char *)mapresp;
	door_args.rsize = sizeof (struct mapid_res);

	error = door_ki_upcall_limited(dh, &door_args, NULL, SIZE_MAX, 0);
	if (!error) {
		resp = (struct mapid_res *)door_args.rbuf;

		/* Should never provide daemon with bad args */
		ASSERT(resp->status != NFSMAPID_INVALID);

		switch (resp->status) {
		case NFSMAPID_OK:
			/*
			 * Valid mapping. Cache it.
			 */
			*uid = resp->u_res.uid;
			nfs_idmap_cache_s2i_insert(&nig->s2u_ci, *uid,
			    u8s, HQ_HASH_HINT, hashno);
			break;

		case NFSMAPID_NUMSTR:
			/*
			 * string came in as stringified id. Don't cache !
			 *
			 * nfsmapid(1m) semantics have changed in order to
			 * support diskless clients. Thus, for stringified
			 * id's that have passwd/group entries, we'll go
			 * ahead and map them, returning no error.
			 */
			*uid = resp->u_res.uid;
			break;

		case NFSMAPID_BADDOMAIN:
			/*
			 * Make the offending "user@domain" string readily
			 * available to D scripts that enable the probe.
			 */
			DTRACE_PROBE1(nfs4__str__uid, char *, mapargp->str);
			/* FALLTHROUGH */

		case NFSMAPID_INVALID:
		case NFSMAPID_UNMAPPABLE:
		case NFSMAPID_INTERNAL:
		case NFSMAPID_BADID:
		case NFSMAPID_NOTFOUND:
		default:
			/*
			 * For now, treat all of these errors as equal.
			 *
			 * Return error on the server side, then the
			 * server returns NFS4_BADOWNER to the client.
			 * On client side, just map to UID_NOBODY.
			 */
			if (isserver)
				error = EPERM;
			else
				*uid = UID_NOBODY;
			break;
		}
		kmem_free(mapargp, MAPID_ARG_LEN(u8s->utf8string_len));
		if (resp != mapresp)
			kmem_free(door_args.rbuf, door_args.rsize);
		door_ki_rele(dh);
		return (error);
	}

	kmem_free(mapargp, MAPID_ARG_LEN(u8s->utf8string_len));
	/*
	 * We got some door error
	 */
	switch (error) {
	case EINTR:
		/*
		 * If we took an interrupt we have to bail out.
		 */
		if (ttolwp(curthread) && ISSIG(curthread, JUSTLOOKING)) {
			door_ki_rele(dh);
			return (EINTR);
		}

		/*
		 * We may have gotten EINTR for other reasons like the
		 * door being revoked on us, instead of trying to
		 * extract this out of the door handle, sleep
		 * and try again, if still revoked we will get EBADF
		 * next time through.
		 */
		/* FALLTHROUGH */
	case EAGAIN:    /* process may be forking */
		door_ki_rele(dh);
		/*
		 * Back off for a bit
		 */
		delay(hz);
		goto retry;
	default:	/* Unknown must be fatal */
	case EBADF:	/* Invalid door */
	case EINVAL:	/* Not a door, wrong target */
		/*
		 * A fatal door error, if our failing door handle is the
		 * current door handle, clean up our state and
		 * mark the server dead.
		 */
		mutex_enter(&nig->nfsidmap_daemon_lock);
		if (dh == nig->nfsidmap_daemon_dh) {
			door_ki_rele(nig->nfsidmap_daemon_dh);
			nig->nfsidmap_daemon_dh = NULL;
		}
		mutex_exit(&nig->nfsidmap_daemon_lock);
		door_ki_rele(dh);

		if (isserver)
			return (ECOMM);

		/*
		 * Note: We've already done optimizations above to check
		 *	 for '@' sign, so if we can't comm w/nfsmapid, we
		 *	 _know_ this _can't_ be a stringified uid.
		 */
		if (!nig->nig_msg_done) {
			zcmn_err(getzoneid(), CE_WARN,
			    "!%s: Can't communicate with mapping daemon "
			    "nfsmapid", whoami);

			nig->nig_msg_done = 1;
		}
		*uid = UID_NOBODY;
		return (0);
	}
	/* NOTREACHED */
}

/*
 * Convert a uid into its utf-8 string representation.
 */
int
nfs_idmap_uid_str(uid_t uid, utf8string *u8s, bool_t isserver)
{
	int			error;
	uint_t			hashno = 0;
	const char		*whoami = "nfs_idmap_uid_str";
	struct nfsidmap_globals	*nig;
	struct mapid_arg	maparg;
	struct mapid_res	mapres;
	struct mapid_res	*mapresp = &mapres;
	struct mapid_res	*resp = mapresp;
	door_arg_t		door_args;
	door_handle_t		dh;

	nig = zone_getspecific(nfsidmap_zone_key, nfs_zone());
	ASSERT(nig != NULL);

	/*
	 * If the supplied uid is "nobody", then we don't look at the
	 * cache, since we DON'T cache it in the u2s_cache. We cannot
	 * tell two strings apart from caching the same uid.
	 */
	if (uid == UID_NOBODY) {
		(void) str_to_utf8("nobody", u8s);
		return (0);
	}

	/*
	 * Start-off with upcalls disabled, and once nfsmapid(1m) is
	 * up and running, we'll leverage it's first flush to let the
	 * kernel know when it's up and available to perform mappings.
	 * We fall back to answering with stringified uid's.
	 */
retry:
	mutex_enter(&nig->nfsidmap_daemon_lock);
	dh = nig->nfsidmap_daemon_dh;
	if (dh)
		door_ki_hold(dh);
	mutex_exit(&nig->nfsidmap_daemon_lock);

	if (dh == NULL || nig->nfsidmap_pid == curproc->p_pid) {
		if (dh)
			door_ki_rele(dh);
		nfs_idmap_i2s_literal(uid, u8s);
		return (0);
	}

	/* cache hit */
	if (nfs_idmap_cache_i2s_lkup(&nig->u2s_ci, uid, &hashno, u8s)) {
		door_ki_rele(dh);
		return (0);
	}

	/* cache miss */
	maparg.cmd = NFSMAPID_UID_STR;
	maparg.u_arg.uid = uid;

	door_args.data_ptr = (char *)&maparg;
	door_args.data_size = sizeof (struct mapid_arg);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = (char *)mapresp;
	door_args.rsize = sizeof (struct mapid_res);

	error = door_ki_upcall_limited(dh, &door_args, NULL, SIZE_MAX, 0);
	if (!error) {
		resp = (struct mapid_res *)door_args.rbuf;

		/* Should never provide daemon with bad args */
		ASSERT(resp->status != NFSMAPID_INVALID);

		switch (resp->status) {
		case NFSMAPID_OK:
			/*
			 * We now have a valid result from the
			 * user-land daemon, so cache the result (if need be).
			 * Load return value first then do the caches.
			 */
			(void) str_to_utf8(resp->str, u8s);
			nfs_idmap_cache_i2s_insert(&nig->u2s_ci, uid,
			    u8s, HQ_HASH_HINT, hashno);
			break;

		case NFSMAPID_INVALID:
		case NFSMAPID_UNMAPPABLE:
		case NFSMAPID_INTERNAL:
		case NFSMAPID_BADDOMAIN:
		case NFSMAPID_BADID:
		case NFSMAPID_NOTFOUND:
		default:
			/*
			 * For now, treat all of these errors as equal.
			 */
			error = EPERM;
			break;
		}

		if (resp != mapresp)
			kmem_free(door_args.rbuf, door_args.rsize);
		door_ki_rele(dh);
		return (error);
	}

	/*
	 * We got some door error
	 */
	switch (error) {
	case EINTR:
		/*
		 * If we took an interrupt we have to bail out.
		 */
		if (ttolwp(curthread) && ISSIG(curthread, JUSTLOOKING)) {
			door_ki_rele(dh);
			return (EINTR);
		}

		/*
		 * We may have gotten EINTR for other reasons like the
		 * door being revoked on us, instead of trying to
		 * extract this out of the door handle, sleep
		 * and try again, if still revoked we will get EBADF
		 * next time through.
		 */
		/* FALLTHROUGH */
	case EAGAIN:    /* process may be forking */
		door_ki_rele(dh);
		/*
		 * Back off for a bit
		 */
		delay(hz);
		goto retry;
	default:	/* Unknown must be fatal */
	case EBADF:	/* Invalid door */
	case EINVAL:	/* Not a door, wrong target */
		/*
		 * A fatal door error, if our failing door handle is the
		 * current door handle, clean up our state and
		 * mark the server dead.
		 */
		mutex_enter(&nig->nfsidmap_daemon_lock);
		if (dh == nig->nfsidmap_daemon_dh) {
			door_ki_rele(nig->nfsidmap_daemon_dh);
			nig->nfsidmap_daemon_dh = NULL;
		}
		mutex_exit(&nig->nfsidmap_daemon_lock);
		door_ki_rele(dh);

		/*
		 * Log error on client-side only
		 */
		if (!nig->nig_msg_done && !isserver) {
			zcmn_err(getzoneid(), CE_WARN,
			    "!%s: Can't communicate with mapping daemon "
			    "nfsmapid", whoami);

			nig->nig_msg_done = 1;
		}
		nfs_idmap_i2s_literal(uid, u8s);
		return (0);
	}
	/* NOTREACHED */
}

/*
 * Convert a group utf-8 string identifier into its local gid.
 */
int
nfs_idmap_str_gid(utf8string *u8s, gid_t *gid, bool_t isserver)
{
	int			error;
	uint_t			hashno = 0;
	const char		*whoami = "nfs_idmap_str_gid";
	struct nfsidmap_globals *nig;
	struct mapid_arg	*mapargp;
	struct mapid_res	mapres;
	struct mapid_res	*mapresp = &mapres;
	struct mapid_res	*resp = mapresp;
	door_arg_t		door_args;
	door_handle_t		dh;

	nig = zone_getspecific(nfsidmap_zone_key, nfs_zone());
	ASSERT(nig != NULL);

	if (!u8s || !u8s->utf8string_val || u8s->utf8string_len == 0 ||
	    (u8s->utf8string_val[0] == '\0')) {
		*gid = GID_NOBODY;
		return (isserver ? EINVAL : 0);
	}

	/*
	 * If "nobody", just short circuit and bail
	 */
	if (bcmp(u8s->utf8string_val, "nobody", 6) == 0) {
		*gid = GID_NOBODY;
		return (0);
	}

	/*
	 * Start-off with upcalls disabled, and once nfsmapid(1m) is up and
	 * running, we'll leverage it's first flush to let the kernel know
	 * when it's up and available to perform mappings. Also, on client
	 * only, be smarter about when to issue upcalls by checking the
	 * string for existence of an '@' sign. If no '@' sign, then we just
	 * make our best effort to decode the string ourselves.
	 */
retry:
	mutex_enter(&nig->nfsidmap_daemon_lock);
	dh = nig->nfsidmap_daemon_dh;
	if (dh)
		door_ki_hold(dh);
	mutex_exit(&nig->nfsidmap_daemon_lock);

	if (dh == NULL || nig->nfsidmap_pid == curproc->p_pid ||
	    (!utf8_strchr(u8s, '@') && !isserver)) {
		if (dh)
			door_ki_rele(dh);
		error = nfs_idmap_s2i_literal(u8s, gid, isserver);
		/*
		 * If we get a numeric value, but we only do so because
		 * we are nfsmapid, return ENOTSUP to indicate a valid
		 * response, but not to cache it.
		 */
		if (!error && nig->nfsidmap_pid == curproc->p_pid)
			return (ENOTSUP);
		return (error);
	}

	/* cache hit */
	if (nfs_idmap_cache_s2i_lkup(&nig->s2g_ci, u8s, &hashno, gid)) {
		door_ki_rele(dh);
		return (0);
	}

	/* cache miss */
	mapargp = kmem_alloc(MAPID_ARG_LEN(u8s->utf8string_len), KM_SLEEP);
	mapargp->cmd = NFSMAPID_STR_GID;
	mapargp->u_arg.len = u8s->utf8string_len;
	(void) bcopy(u8s->utf8string_val, mapargp->str, mapargp->u_arg.len);
	mapargp->str[mapargp->u_arg.len] = '\0';

	door_args.data_ptr = (char *)mapargp;
	door_args.data_size = MAPID_ARG_LEN(mapargp->u_arg.len);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = (char *)mapresp;
	door_args.rsize = sizeof (struct mapid_res);

	error = door_ki_upcall_limited(dh, &door_args, NULL, SIZE_MAX, 0);
	if (!error) {
		resp = (struct mapid_res *)door_args.rbuf;

		/* Should never provide daemon with bad args */
		ASSERT(resp->status != NFSMAPID_INVALID);

		switch (resp->status) {
		case NFSMAPID_OK:
			/*
			 * Valid mapping. Cache it.
			 */
			*gid = resp->u_res.gid;
			error = 0;
			nfs_idmap_cache_s2i_insert(&nig->s2g_ci, *gid,
			    u8s, HQ_HASH_HINT, hashno);
			break;

		case NFSMAPID_NUMSTR:
			/*
			 * string came in as stringified id. Don't cache !
			 *
			 * nfsmapid(1m) semantics have changed in order to
			 * support diskless clients. Thus, for stringified
			 * id's that have passwd/group entries, we'll go
			 * ahead and map them, returning no error.
			 */
			*gid = resp->u_res.gid;
			break;

		case NFSMAPID_BADDOMAIN:
			/*
			 * Make the offending "group@domain" string readily
			 * available to D scripts that enable the probe.
			 */
			DTRACE_PROBE1(nfs4__str__gid, char *, mapargp->str);
			/* FALLTHROUGH */

		case NFSMAPID_INVALID:
		case NFSMAPID_UNMAPPABLE:
		case NFSMAPID_INTERNAL:
		case NFSMAPID_BADID:
		case NFSMAPID_NOTFOUND:
		default:
			/*
			 * For now, treat all of these errors as equal.
			 *
			 * Return error on the server side, then the
			 * server returns NFS4_BADOWNER to the client.
			 * On client side, just map to GID_NOBODY.
			 */
			if (isserver)
				error = EPERM;
			else
				*gid = GID_NOBODY;
			break;
		}
		kmem_free(mapargp, MAPID_ARG_LEN(u8s->utf8string_len));
		if (resp != mapresp)
			kmem_free(door_args.rbuf, door_args.rsize);
		door_ki_rele(dh);
		return (error);
	}

	kmem_free(mapargp, MAPID_ARG_LEN(u8s->utf8string_len));
	/*
	 * We got some door error
	 */
	switch (error) {
	case EINTR:
		/*
		 * If we took an interrupt we have to bail out.
		 */
		if (ttolwp(curthread) && ISSIG(curthread, JUSTLOOKING)) {
			door_ki_rele(dh);
			return (EINTR);
		}

		/*
		 * We may have gotten EINTR for other reasons like the
		 * door being revoked on us, instead of trying to
		 * extract this out of the door handle, sleep
		 * and try again, if still revoked we will get EBADF
		 * next time through.
		 */
		/* FALLTHROUGH */
	case EAGAIN:    /* process may be forking */
		door_ki_rele(dh);
		/*
		 * Back off for a bit
		 */
		delay(hz);
		goto retry;
	default:	/* Unknown must be fatal */
	case EBADF:	/* Invalid door */
	case EINVAL:	/* Not a door, wrong target */
		/*
		 * A fatal door error, clean up our state and
		 * mark the server dead.
		 */

		mutex_enter(&nig->nfsidmap_daemon_lock);
		if (dh == nig->nfsidmap_daemon_dh) {
			door_ki_rele(nig->nfsidmap_daemon_dh);
			nig->nfsidmap_daemon_dh = NULL;
		}
		mutex_exit(&nig->nfsidmap_daemon_lock);
		door_ki_rele(dh);

		if (isserver)
			return (ECOMM);

		/*
		 * Note: We've already done optimizations above to check
		 *	 for '@' sign, so if we can't comm w/nfsmapid, we
		 *	 _know_ this _can't_ be a stringified gid.
		 */
		if (!nig->nig_msg_done) {
			zcmn_err(getzoneid(), CE_WARN,
			    "!%s: Can't communicate with mapping daemon "
			    "nfsmapid", whoami);

			nig->nig_msg_done = 1;
		}
		*gid = GID_NOBODY;
		return (0);
	}
	/* NOTREACHED */
}

/*
 * Convert a gid into its utf-8 string representation.
 */
int
nfs_idmap_gid_str(gid_t gid, utf8string *u8s, bool_t isserver)
{
	int			error;
	uint_t			hashno = 0;
	const char		*whoami = "nfs_idmap_gid_str";
	struct nfsidmap_globals	*nig;
	struct mapid_arg	maparg;
	struct mapid_res	mapres;
	struct mapid_res	*mapresp = &mapres;
	struct mapid_res	*resp = mapresp;
	door_arg_t		door_args;
	door_handle_t		dh;

	nig = zone_getspecific(nfsidmap_zone_key, nfs_zone());
	ASSERT(nig != NULL);

	/*
	 * If the supplied gid is "nobody", then we don't look at the
	 * cache, since we DON'T cache it in the u2s_cache. We cannot
	 * tell two strings apart from caching the same gid.
	 */
	if (gid == GID_NOBODY) {
		(void) str_to_utf8("nobody", u8s);
		return (0);
	}

	/*
	 * Start-off with upcalls disabled, and once nfsmapid(1m) is
	 * up and running, we'll leverage it's first flush to let the
	 * kernel know when it's up and available to perform mappings.
	 * We fall back to answering with stringified gid's.
	 */
retry:
	mutex_enter(&nig->nfsidmap_daemon_lock);
	dh = nig->nfsidmap_daemon_dh;
	if (dh)
		door_ki_hold(dh);
	mutex_exit(&nig->nfsidmap_daemon_lock);

	if (dh == NULL || nig->nfsidmap_pid == curproc->p_pid) {
		if (dh)
			door_ki_rele(dh);
		nfs_idmap_i2s_literal(gid, u8s);
		return (0);
	}

	/* cache hit */
	if (nfs_idmap_cache_i2s_lkup(&nig->g2s_ci, gid, &hashno, u8s)) {
		door_ki_rele(dh);
		return (0);
	}

	/* cache miss */
	maparg.cmd = NFSMAPID_GID_STR;
	maparg.u_arg.gid = gid;

	door_args.data_ptr = (char *)&maparg;
	door_args.data_size = sizeof (struct mapid_arg);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = (char *)mapresp;
	door_args.rsize = sizeof (struct mapid_res);

	error = door_ki_upcall_limited(dh, &door_args, NULL, SIZE_MAX, 0);
	if (!error) {
		resp = (struct mapid_res *)door_args.rbuf;

		/* Should never provide daemon with bad args */
		ASSERT(resp->status != NFSMAPID_INVALID);

		switch (resp->status) {
		case NFSMAPID_OK:
			/*
			 * We now have a valid result from the
			 * user-land daemon, so cache the result (if need be).
			 * Load return value first then do the caches.
			 */
			(void) str_to_utf8(resp->str, u8s);
			nfs_idmap_cache_i2s_insert(&nig->g2s_ci, gid,
			    u8s, HQ_HASH_HINT, hashno);
			break;

		case NFSMAPID_INVALID:
		case NFSMAPID_UNMAPPABLE:
		case NFSMAPID_INTERNAL:
		case NFSMAPID_BADDOMAIN:
		case NFSMAPID_BADID:
		case NFSMAPID_NOTFOUND:
		default:
			/*
			 * For now, treat all of these errors as equal.
			 */
			error = EPERM;
			break;
		}

		if (resp != mapresp)
			kmem_free(door_args.rbuf, door_args.rsize);
		door_ki_rele(dh);
		return (error);
	}

	/*
	 * We got some door error
	 */
	switch (error) {
	case EINTR:
		/*
		 * If we took an interrupt we have to bail out.
		 */
		if (ttolwp(curthread) && ISSIG(curthread, JUSTLOOKING)) {
			door_ki_rele(dh);
			return (EINTR);
		}

		/*
		 * We may have gotten EINTR for other reasons like the
		 * door being revoked on us, instead of trying to
		 * extract this out of the door handle, sleep
		 * and try again, if still revoked we will get EBADF
		 * next time through.
		 */
		/* FALLTHROUGH */
	case EAGAIN:    /* process may be forking */
		door_ki_rele(dh);
		/*
		 * Back off for a bit
		 */
		delay(hz);
		goto retry;
	default:	/* Unknown must be fatal */
	case EBADF:	/* Invalid door */
	case EINVAL:	/* Not a door, wrong target */
		/*
		 * A fatal door error, if our failing door handle is the
		 * current door handle, clean up our state and
		 * mark the server dead.
		 */
		mutex_enter(&nig->nfsidmap_daemon_lock);
		if (dh == nig->nfsidmap_daemon_dh) {
			door_ki_rele(nig->nfsidmap_daemon_dh);
			nig->nfsidmap_daemon_dh = NULL;
		}
		door_ki_rele(dh);
		mutex_exit(&nig->nfsidmap_daemon_lock);

		/*
		 * Log error on client-side only
		 */
		if (!nig->nig_msg_done && !isserver) {
			zcmn_err(getzoneid(), CE_WARN,
			    "!%s: Can't communicate with mapping daemon "
			    "nfsmapid", whoami);

			nig->nig_msg_done = 1;
		}
		nfs_idmap_i2s_literal(gid, u8s);
		return (0);
	}
	/* NOTREACHED */
}

/* -- idmap cache management -- */

/*
 * Cache creation and initialization routine
 */
static void
nfs_idmap_cache_create(idmap_cache_info_t *cip, const char *name)
{
	int		 i;
	nfsidhq_t	*hq = NULL;

	cip->table = kmem_alloc((NFSID_CACHE_ANCHORS * sizeof (nfsidhq_t)),
	    KM_SLEEP);

	for (i = 0, hq = cip->table; i < NFSID_CACHE_ANCHORS; i++, hq++) {
		hq->hq_que_forw = hq;
		hq->hq_que_back = hq;
		mutex_init(&(hq->hq_lock), NULL, MUTEX_DEFAULT, NULL);
	}
	cip->name = name;
}

/*
 * Cache destruction routine
 *
 * Ops per hash queue
 *
 * - dequeue cache entries
 * - release string storage per entry
 * - release cache entry storage
 * - destroy HQ lock when HQ is empty
 * - once all HQ's empty, release HQ storage
 */
static void
nfs_idmap_cache_destroy(idmap_cache_info_t *cip)
{
	int		 i;
	nfsidhq_t	*hq;

	ASSERT(MUTEX_HELD(&nfsidmap_globals_lock));
	nfs_idmap_cache_flush(cip);
	/*
	 * We can safely destroy per-queue locks since the only
	 * other entity that could be mucking with this table is the
	 * kmem reaper thread which does everything under
	 * nfsidmap_globals_lock (which we're holding).
	 */
	for (i = 0, hq = cip->table; i < NFSID_CACHE_ANCHORS; i++, hq++)
		mutex_destroy(&(hq->hq_lock));
	kmem_free(cip->table, NFSID_CACHE_ANCHORS * sizeof (nfsidhq_t));
}

void
nfs_idmap_args(struct nfsidmap_args *idmp)
{
	struct nfsidmap_globals *nig;

	nig = zone_getspecific(nfsidmap_zone_key, nfs_zone());
	ASSERT(nig != NULL);

	nfs_idmap_cache_flush(&nig->u2s_ci);
	nfs_idmap_cache_flush(&nig->s2u_ci);
	nfs_idmap_cache_flush(&nig->g2s_ci);
	nfs_idmap_cache_flush(&nig->s2g_ci);

	/*
	 * nfsmapid(1m) up and running; enable upcalls
	 * State:
	 *	0	Just flush caches
	 *	1	Re-establish door knob
	 */
	if (idmp->state) {
		/*
		 * When reestablishing the nfsmapid we need to
		 * not only purge the idmap cache but also
		 * the dnlc as it will have cached uid/gid's.
		 * While heavyweight, this should almost never happen
		 */
		dnlc_purge();

		/*
		 * Invalidate the attrs of all rnodes to force new uid and gids
		 */
		nfs4_rnode_invalidate(NULL);

		mutex_enter(&nig->nfsidmap_daemon_lock);
		if (nig->nfsidmap_daemon_dh)
			door_ki_rele(nig->nfsidmap_daemon_dh);
		nig->nfsidmap_daemon_dh = door_ki_lookup(idmp->did);
		nig->nfsidmap_pid = curproc->p_pid;
		nig->nig_msg_done = 0;
		mutex_exit(&nig->nfsidmap_daemon_lock);
	}
}

/*
 * Cache flush routine
 *
 *	The only serialization required it to hold the hash chain lock
 *	when destroying cache entries.  There is no need to prevent access
 *	to all hash chains while flushing.  It is possible that (valid)
 *	entries could be cached in later hash chains after we start flushing.
 *	It is unfortunate that the entry will be instantly destroyed, but
 *	it isn't a major concern.  This is only a cache.  It'll be repopulated.
 *
 * Ops per hash queue
 *
 * - dequeue cache entries
 * - release string storage per entry
 * - release cache entry storage
 */
static void
nfs_idmap_cache_flush(idmap_cache_info_t *cip)
{
	int		 i;
	nfsidmap_t	*p, *next;
	nfsidhq_t	*hq;

	for (i = 0, hq = cip->table; i < NFSID_CACHE_ANCHORS; i++, hq++) {

		mutex_enter(&(hq->hq_lock));

		/*
		 * remove list from hash header so we can release
		 * the lock early.
		 */
		p = hq->hq_lru_forw;
		hq->hq_que_forw = hq;
		hq->hq_que_back = hq;

		mutex_exit(&(hq->hq_lock));

		/*
		 * Iterate over the orphan'd list and free all elements.
		 * There's no need to bother with remque since we're
		 * freeing the entire list.
		 */
		while (p != (nfsidmap_t *)hq) {
			next = p->id_forw;
			if (p->id_val != 0)
				kmem_free(p->id_val, p->id_len);
			kmem_cache_free(nfsidmap_cache, p);
			p = next;
		}

	}
}

static void
nfs_idmap_cache_reclaim(idmap_cache_info_t *cip)
{
	nfsidhq_t		*hq;
	nfsidmap_t		*pprev = NULL;
	int			 i;
	nfsidmap_t		*p;

	ASSERT(cip != NULL && cip->table != NULL);

	/*
	 * If the daemon is down, do not flush anything
	 */
	if ((*cip->nfsidmap_daemon_dh) == NULL)
		return;

	for (i = 0, hq = cip->table; i < NFSID_CACHE_ANCHORS; i++, hq++) {
		if (!mutex_tryenter(&(hq->hq_lock)))
			continue;

		/*
		 * Start at end of list and work backwards since LRU
		 */
		for (p = hq->hq_lru_back; p != (nfsidmap_t *)hq; p = pprev) {
			pprev = p->id_back;

			/*
			 * List is LRU. If trailing end does not
			 * contain stale entries, then no need to
			 * continue.
			 */
			if (!TIMEOUT(p->id_time))
				break;

			nfs_idmap_cache_rment(p);
		}
		mutex_exit(&(hq->hq_lock));
	}
}

/*
 * Callback reclaim function for VM.  We reap timed-out entries from all hash
 * tables in all zones.
 */
/* ARGSUSED */
void
nfs_idmap_reclaim(void *arg)
{
	struct nfsidmap_globals *nig;

	mutex_enter(&nfsidmap_globals_lock);
	for (nig = list_head(&nfsidmap_globals_list); nig != NULL;
	    nig = list_next(&nfsidmap_globals_list, nig)) {
		nfs_idmap_cache_reclaim(&nig->u2s_ci);
		nfs_idmap_cache_reclaim(&nig->s2u_ci);
		nfs_idmap_cache_reclaim(&nig->g2s_ci);
		nfs_idmap_cache_reclaim(&nig->s2g_ci);
	}
	mutex_exit(&nfsidmap_globals_lock);
}

/*
 * Search the specified cache for the existence of the specified utf-8
 * string. If found, the corresponding mapping is returned in id_buf and
 * the cache entry is updated to the head of the LRU list. The computed
 * hash queue number, is returned in hashno.
 *
 * cip    - cache info ptr
 * u8s    - utf8 string to resolve
 * hashno - hash number, retval
 * id_buf - if found, id for u8s
 */
static uint_t
nfs_idmap_cache_s2i_lkup(idmap_cache_info_t *cip, utf8string *u8s,
    uint_t *hashno, uid_t *id_buf)
{
	nfsidmap_t	*p;
	nfsidmap_t	*pnext;
	nfsidhq_t	*hq;
	char		*rqst_c_str;
	uint_t		 rqst_len;
	uint_t		 found_stat = 0;

	if ((rqst_c_str = utf8_to_str(u8s, &rqst_len, NULL)) == NULL) {
		/*
		 * Illegal string, return not found.
		 */
		return (0);
	}

	/*
	 * Compute hash queue
	 */
	*hashno = pkp_tab_hash(rqst_c_str, rqst_len - 1);
	hq = &cip->table[*hashno];

	/*
	 * Look for the entry in the HQ
	 */
	mutex_enter(&(hq->hq_lock));
	for (p = hq->hq_lru_forw; p != (nfsidmap_t *)hq; p = pnext) {

		pnext = p->id_forw;

		/*
		 * Check entry for staleness first, as user's id
		 * may have changed and may need to be remapped.
		 * Note that we don't evict entries from the cache
		 * if we're having trouble contacting nfsmapid(1m)
		 */
		if (TIMEOUT(p->id_time) && (*cip->nfsidmap_daemon_dh) != NULL) {
			nfs_idmap_cache_rment(p);
			continue;
		}

		/*
		 * Compare equal length strings
		 */
		if (p->id_len == (rqst_len - 1)) {
			if (bcmp(p->id_val, rqst_c_str, (rqst_len - 1)) == 0) {
				/*
				 * Found it. Update it and load return value.
				 */
				*id_buf = p->id_no;
				remque(p);
				insque(p, hq);
				p->id_time = gethrestime_sec();

				found_stat = 1;
				break;
			}
		}
	}
	mutex_exit(&(hq->hq_lock));

	if (rqst_c_str != NULL)
		kmem_free(rqst_c_str, rqst_len);

	return (found_stat);
}

/*
 * Search the specified cache for the existence of the specified utf8
 * string, as it may have been inserted before this instance got a chance
 * to do it. If NOT found, then a new entry is allocated for the specified
 * cache, and inserted. The hash queue number is obtained from hash_number
 * if the behavior is HQ_HASH_HINT, or computed otherwise.
 *
 * cip         - cache info ptr
 * id          - id result from upcall
 * u8s         - utf8 string to resolve
 * behavior    - hash algorithm behavior
 * hash_number - hash number iff hint
 */
static void
nfs_idmap_cache_s2i_insert(idmap_cache_info_t *cip, uid_t id, utf8string *u8s,
    hash_stat behavior, uint_t hash_number)
{
	uint_t			 hashno;
	char			*c_str;
	nfsidhq_t		*hq;
	nfsidmap_t		*newp;
	nfsidmap_t		*p;
	nfsidmap_t		*pnext;
	uint_t			 c_len;

	/*
	 * This shouldn't fail, since already successful at lkup.
	 * So, if it does happen, just drop the request-to-insert
	 * on the floor.
	 */
	if ((c_str = utf8_to_str(u8s, &c_len, NULL)) == NULL)
		return;

	/*
	 * Obtain correct hash queue to insert new entry in
	 */
	switch (behavior) {
		case HQ_HASH_HINT:
			hashno = hash_number;
			break;

		case HQ_HASH_FIND:
		default:
			hashno = pkp_tab_hash(c_str, c_len - 1);
			break;
	}
	hq = &cip->table[hashno];


	/*
	 * Look for an existing entry in the cache. If one exists
	 * update it, and return. Otherwise, allocate a new cache
	 * entry, initialize it and insert it.
	 */
	mutex_enter(&(hq->hq_lock));
	for (p = hq->hq_lru_forw; p != (nfsidmap_t *)hq; p = pnext) {

		pnext = p->id_forw;

		/*
		 * Check entry for staleness first, as user's id
		 * may have changed and may need to be remapped.
		 * Note that we don't evict entries from the cache
		 * if we're having trouble contacting nfsmapid(1m)
		 */
		if (TIMEOUT(p->id_time) && (*cip->nfsidmap_daemon_dh) != NULL) {
			nfs_idmap_cache_rment(p);
			continue;
		}

		/*
		 * Compare equal length strings
		 */
		if (p->id_len == (c_len - 1)) {
			if (bcmp(p->id_val, c_str, (c_len - 1)) == 0) {
				/*
				 * Move to front, and update time.
				 */
				remque(p);
				insque(p, hq);
				p->id_time = gethrestime_sec();

				mutex_exit(&(hq->hq_lock));
				kmem_free(c_str, c_len);
				return;
			}
		}
	}

	/*
	 * Not found ! Alloc, init and insert new entry
	 */
	newp = kmem_cache_alloc(nfsidmap_cache, KM_SLEEP);
	newp->id_len = u8s->utf8string_len;
	newp->id_val = kmem_alloc(u8s->utf8string_len, KM_SLEEP);
	bcopy(u8s->utf8string_val, newp->id_val, u8s->utf8string_len);
	newp->id_no = id;
	newp->id_time = gethrestime_sec();
	insque(newp, hq);

	mutex_exit(&(hq->hq_lock));
	kmem_free(c_str, c_len);
}

/*
 * Search the specified cache for the existence of the specified id.
 * If found, the corresponding mapping is returned in u8s and the
 * cache entry is updated to the head of the LRU list. The computed
 * hash queue number, is returned in hashno.
 *
 * cip    - cache info ptr
 * id     - id to resolve
 * hashno - hash number, retval
 * u8s    - if found, utf8 str for id
 */
static uint_t
nfs_idmap_cache_i2s_lkup(idmap_cache_info_t *cip, uid_t id, uint_t *hashno,
    utf8string *u8s)
{
	uint_t			 found_stat = 0;
	nfsidmap_t		*p;
	nfsidmap_t		*pnext;
	nfsidhq_t		*hq;
	uint_t			 hash;

	/*
	 * Compute hash queue
	 */
	ID_HASH(id, hash);
	*hashno = hash;
	hq = &cip->table[hash];

	/*
	 * Look for the entry in the HQ
	 */
	mutex_enter(&(hq->hq_lock));
	for (p = hq->hq_lru_forw; p != (nfsidmap_t *)hq; p = pnext) {

		pnext = p->id_forw;

		/*
		 * Check entry for staleness first, as user's id
		 * may have changed and may need to be remapped.
		 * Note that we don't evict entries from the cache
		 * if we're having trouble contacting nfsmapid(1m)
		 */
		if (TIMEOUT(p->id_time) && (*cip->nfsidmap_daemon_dh) != NULL) {
			nfs_idmap_cache_rment(p);
			continue;
		}

		if (p->id_no == id) {

			/*
			 * Found it. Load return value and move to head
			 */
			ASSERT(u8s->utf8string_val == NULL);
			u8s->utf8string_len = p->id_len;
			u8s->utf8string_val = kmem_alloc(p->id_len, KM_SLEEP);
			bcopy(p->id_val, u8s->utf8string_val, p->id_len);

			remque(p);
			insque(p, hq);
			p->id_time = gethrestime_sec();

			found_stat = 1;
			break;
		}
	}
	mutex_exit(&(hq->hq_lock));

	return (found_stat);
}

/*
 * Search the specified cache for the existence of the specified id,
 * as it may have been inserted before this instance got a chance to
 * do it. If NOT found, then a new entry is allocated for the specified
 * cache, and inserted. The hash queue number is obtained from hash_number
 * if the behavior is HQ_HASH_HINT, or computed otherwise.
 *
 * cip         - cache info ptr
 * id          - id to resolve
 * u8s         - utf8 result from upcall
 * behavior    - has algorithm behavior
 * hash_number - hash number iff hint
 */
static void
nfs_idmap_cache_i2s_insert(idmap_cache_info_t *cip, uid_t id, utf8string *u8s,
    hash_stat behavior, uint_t hash_number)
{
	uint_t		 hashno;
	nfsidhq_t	*hq;
	nfsidmap_t	*newp;
	nfsidmap_t	*pnext;
	nfsidmap_t	*p;


	/*
	 * Obtain correct hash queue to insert new entry in
	 */
	switch (behavior) {
		case HQ_HASH_HINT:
			hashno = hash_number;
			break;

		case HQ_HASH_FIND:
		default:
			ID_HASH(id, hashno);
			break;
	}
	hq = &cip->table[hashno];


	/*
	 * Look for an existing entry in the cache. If one exists
	 * update it, and return. Otherwise, allocate a new cache
	 * entry, initialize and insert it.
	 */
	mutex_enter(&(hq->hq_lock));
	for (p = hq->hq_lru_forw; p != (nfsidmap_t *)hq; p = pnext) {

		pnext = p->id_forw;

		/*
		 * Check entry for staleness first, as user's id
		 * may have changed and may need to be remapped.
		 * Note that we don't evict entries from the cache
		 * if we're having trouble contacting nfsmapid(1m)
		 */
		if (TIMEOUT(p->id_time) && (*cip->nfsidmap_daemon_dh) != NULL) {
			nfs_idmap_cache_rment(p);
			continue;
		}


		if ((p->id_no == id) && (p->id_len == u8s->utf8string_len)) {
			/*
			 * Found It ! Move to front, and update time.
			 */
			remque(p);
			insque(p, hq);
			p->id_time = gethrestime_sec();

			mutex_exit(&(hq->hq_lock));
			return;
		}
	}

	/*
	 * Not found ! Alloc, init and insert new entry
	 */
	newp = kmem_cache_alloc(nfsidmap_cache, KM_SLEEP);
	newp->id_len = u8s->utf8string_len;
	newp->id_val = kmem_alloc(u8s->utf8string_len, KM_SLEEP);
	bcopy(u8s->utf8string_val, newp->id_val, u8s->utf8string_len);
	newp->id_no = id;
	newp->id_time = gethrestime_sec();
	insque(newp, hq);

	mutex_exit(&(hq->hq_lock));
}

/*
 * Remove and free one cache entry
 */
static void
nfs_idmap_cache_rment(nfsidmap_t *p)
{
	remque(p);
	if (p->id_val != 0)
		kmem_free(p->id_val, p->id_len);
	kmem_cache_free(nfsidmap_cache, p);
}

#ifndef		UID_MAX
#define		UID_MAX		2147483647		/* see limits.h */
#endif

#ifndef		isdigit
#define		isdigit(c)	((c) >= '0' && (c) <= '9')
#endif

static int
is_stringified_id(utf8string *u8s)
{
	int	i;

	for (i = 0; i < u8s->utf8string_len; i++)
		if (!isdigit(u8s->utf8string_val[i]))
			return (0);
	return (1);
}

int
nfs_idmap_s2i_literal(utf8string *u8s, uid_t *id, int isserver)
{
	long	tmp;
	int	convd;
	char	ids[_MAXIDSTRLEN];

	/*
	 * "nobody" unless we can actually decode it.
	 */
	*id = UID_NOBODY;

	/*
	 * We're here because it has already been determined that the
	 * string contains no '@' _or_ the nfsmapid daemon has yet to
	 * be started.
	 */
	if (!is_stringified_id(u8s))
		return (0);

	/*
	 * If utf8string_len is greater than _MAXIDSTRLEN-1, then the id
	 * is going to be greater than UID_MAX. Return id of "nobody"
	 * right away.
	 */
	if (u8s->utf8string_len >= _MAXIDSTRLEN)
		return (isserver ? EPERM : 0);

	/*
	 * Make sure we pass a NULL terminated 'C' string to ddi_strtol
	 */
	bcopy(u8s->utf8string_val, ids, u8s->utf8string_len);
	ids[u8s->utf8string_len] = '\0';
	convd = ddi_strtol(ids, NULL, 10, &tmp);
	if (convd == 0 && tmp >= 0 && tmp <= UID_MAX) {
		*id = tmp;
		return (0);
	}
	return (isserver ? EPERM : 0);
}

static void
nfs_idmap_i2s_literal(uid_t id, utf8string *u8s)
{
	char	ids[_MAXIDSTRLEN];

	(void) snprintf(ids, _MAXIDSTRLEN, "%d", id);
	(void) str_to_utf8(ids, u8s);
}

/* -- Utility functions -- */

char *
utf8_strchr(utf8string *u8s, const char c)
{
	int	i;
	char	*u8p = u8s->utf8string_val;
	int	len = u8s->utf8string_len;

	for (i = 0; i < len; i++)
		if (u8p[i] == c)
			return (&u8p[i]);
	return (NULL);
}
