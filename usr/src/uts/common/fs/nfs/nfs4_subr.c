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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

/*
 *  	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All Rights Reserved
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/vtrace.h>
#include <sys/session.h>
#include <sys/thread.h>
#include <sys/dnlc.h>
#include <sys/cred.h>
#include <sys/priv.h>
#include <sys/list.h>
#include <sys/sdt.h>
#include <sys/policy.h>

#include <rpc/types.h>
#include <rpc/xdr.h>

#include <nfs/nfs.h>

#include <nfs/nfs_clnt.h>

#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_clnt.h>

/*
 * client side statistics
 */
static const struct clstat4 clstat4_tmpl = {
	{ "calls",	KSTAT_DATA_UINT64 },
	{ "badcalls",	KSTAT_DATA_UINT64 },
	{ "referrals",	KSTAT_DATA_UINT64 },
	{ "referlinks",	KSTAT_DATA_UINT64 },
	{ "clgets",	KSTAT_DATA_UINT64 },
	{ "cltoomany",	KSTAT_DATA_UINT64 },
#ifdef DEBUG
	{ "clalloc",	KSTAT_DATA_UINT64 },
	{ "noresponse",	KSTAT_DATA_UINT64 },
	{ "failover",	KSTAT_DATA_UINT64 },
	{ "remap",	KSTAT_DATA_UINT64 },
#endif
};

#ifdef DEBUG
struct clstat4_debug clstat4_debug = {
	{ "nrnode",	KSTAT_DATA_UINT64 },
	{ "access",	KSTAT_DATA_UINT64 },
	{ "dirent",	KSTAT_DATA_UINT64 },
	{ "dirents",	KSTAT_DATA_UINT64 },
	{ "reclaim",	KSTAT_DATA_UINT64 },
	{ "clreclaim",	KSTAT_DATA_UINT64 },
	{ "f_reclaim",	KSTAT_DATA_UINT64 },
	{ "a_reclaim",	KSTAT_DATA_UINT64 },
	{ "r_reclaim",	KSTAT_DATA_UINT64 },
	{ "r_path",	KSTAT_DATA_UINT64 },
};
#endif

/*
 * We keep a global list of per-zone client data, so we can clean up all zones
 * if we get low on memory.
 */
static list_t nfs4_clnt_list;
static kmutex_t nfs4_clnt_list_lock;
zone_key_t nfs4clnt_zone_key;

static struct kmem_cache *chtab4_cache;

#ifdef DEBUG
static int nfs4_rfscall_debug;
static int nfs4_try_failover_any;
int nfs4_utf8_debug = 0;
#endif

/*
 * NFSv4 readdir cache implementation
 */
typedef struct rddir4_cache_impl {
	rddir4_cache	rc;		/* readdir cache element */
	kmutex_t	lock;		/* lock protects count */
	uint_t		count;		/* reference count */
	avl_node_t	tree;		/* AVL tree link */
} rddir4_cache_impl;

static int rddir4_cache_compar(const void *, const void *);
static void rddir4_cache_free(rddir4_cache_impl *);
static rddir4_cache *rddir4_cache_alloc(int);
static void rddir4_cache_hold(rddir4_cache *);
static int try_failover(enum clnt_stat);

static int nfs4_readdir_cache_hits = 0;
static int nfs4_readdir_cache_waits = 0;
static int nfs4_readdir_cache_misses = 0;

/*
 * Shared nfs4 functions
 */

/*
 * Copy an nfs_fh4.  The destination storage (to->nfs_fh4_val) must already
 * be allocated.
 */

void
nfs_fh4_copy(nfs_fh4 *from, nfs_fh4 *to)
{
	to->nfs_fh4_len = from->nfs_fh4_len;
	bcopy(from->nfs_fh4_val, to->nfs_fh4_val, to->nfs_fh4_len);
}

/*
 * nfs4cmpfh - compare 2 filehandles.
 * Returns 0 if the two nfsv4 filehandles are the same, -1 if the first is
 * "less" than the second, +1 if the first is "greater" than the second.
 */

int
nfs4cmpfh(const nfs_fh4 *fh4p1, const nfs_fh4 *fh4p2)
{
	const char *c1, *c2;

	if (fh4p1->nfs_fh4_len < fh4p2->nfs_fh4_len)
		return (-1);
	if (fh4p1->nfs_fh4_len > fh4p2->nfs_fh4_len)
		return (1);
	for (c1 = fh4p1->nfs_fh4_val, c2 = fh4p2->nfs_fh4_val;
	    c1 < fh4p1->nfs_fh4_val + fh4p1->nfs_fh4_len;
	    c1++, c2++) {
		if (*c1 < *c2)
			return (-1);
		if (*c1 > *c2)
			return (1);
	}

	return (0);
}

/*
 * Compare two v4 filehandles.  Return zero if they're the same, non-zero
 * if they're not.  Like nfs4cmpfh(), but different filehandle
 * representation, and doesn't provide information about greater than or
 * less than.
 */

int
nfs4cmpfhandle(nfs4_fhandle_t *fh1, nfs4_fhandle_t *fh2)
{
	if (fh1->fh_len == fh2->fh_len)
		return (bcmp(fh1->fh_buf, fh2->fh_buf, fh1->fh_len));

	return (1);
}

int
stateid4_cmp(stateid4 *s1, stateid4 *s2)
{
	if (bcmp(s1, s2, sizeof (stateid4)) == 0)
		return (1);
	else
		return (0);
}

nfsstat4
puterrno4(int error)
{
	switch (error) {
	case 0:
		return (NFS4_OK);
	case EPERM:
		return (NFS4ERR_PERM);
	case ENOENT:
		return (NFS4ERR_NOENT);
	case EINTR:
		return (NFS4ERR_IO);
	case EIO:
		return (NFS4ERR_IO);
	case ENXIO:
		return (NFS4ERR_NXIO);
	case ENOMEM:
		return (NFS4ERR_RESOURCE);
	case EACCES:
		return (NFS4ERR_ACCESS);
	case EBUSY:
		return (NFS4ERR_IO);
	case EEXIST:
		return (NFS4ERR_EXIST);
	case EXDEV:
		return (NFS4ERR_XDEV);
	case ENODEV:
		return (NFS4ERR_IO);
	case ENOTDIR:
		return (NFS4ERR_NOTDIR);
	case EISDIR:
		return (NFS4ERR_ISDIR);
	case EINVAL:
		return (NFS4ERR_INVAL);
	case EMFILE:
		return (NFS4ERR_RESOURCE);
	case EFBIG:
		return (NFS4ERR_FBIG);
	case ENOSPC:
		return (NFS4ERR_NOSPC);
	case EROFS:
		return (NFS4ERR_ROFS);
	case EMLINK:
		return (NFS4ERR_MLINK);
	case EDEADLK:
		return (NFS4ERR_DEADLOCK);
	case ENOLCK:
		return (NFS4ERR_DENIED);
	case EREMOTE:
		return (NFS4ERR_SERVERFAULT);
	case ENOTSUP:
		return (NFS4ERR_NOTSUPP);
	case EDQUOT:
		return (NFS4ERR_DQUOT);
	case ENAMETOOLONG:
		return (NFS4ERR_NAMETOOLONG);
	case EOVERFLOW:
		return (NFS4ERR_INVAL);
	case ENOSYS:
		return (NFS4ERR_NOTSUPP);
	case ENOTEMPTY:
		return (NFS4ERR_NOTEMPTY);
	case EOPNOTSUPP:
		return (NFS4ERR_NOTSUPP);
	case ESTALE:
		return (NFS4ERR_STALE);
	case EAGAIN:
		if (curthread->t_flag & T_WOULDBLOCK) {
			curthread->t_flag &= ~T_WOULDBLOCK;
			return (NFS4ERR_DELAY);
		}
		return (NFS4ERR_LOCKED);
	default:
		return ((enum nfsstat4)error);
	}
}

int
geterrno4(enum nfsstat4 status)
{
	switch (status) {
	case NFS4_OK:
		return (0);
	case NFS4ERR_PERM:
		return (EPERM);
	case NFS4ERR_NOENT:
		return (ENOENT);
	case NFS4ERR_IO:
		return (EIO);
	case NFS4ERR_NXIO:
		return (ENXIO);
	case NFS4ERR_ACCESS:
		return (EACCES);
	case NFS4ERR_EXIST:
		return (EEXIST);
	case NFS4ERR_XDEV:
		return (EXDEV);
	case NFS4ERR_NOTDIR:
		return (ENOTDIR);
	case NFS4ERR_ISDIR:
		return (EISDIR);
	case NFS4ERR_INVAL:
		return (EINVAL);
	case NFS4ERR_FBIG:
		return (EFBIG);
	case NFS4ERR_NOSPC:
		return (ENOSPC);
	case NFS4ERR_ROFS:
		return (EROFS);
	case NFS4ERR_MLINK:
		return (EMLINK);
	case NFS4ERR_NAMETOOLONG:
		return (ENAMETOOLONG);
	case NFS4ERR_NOTEMPTY:
		return (ENOTEMPTY);
	case NFS4ERR_DQUOT:
		return (EDQUOT);
	case NFS4ERR_STALE:
		return (ESTALE);
	case NFS4ERR_BADHANDLE:
		return (ESTALE);
	case NFS4ERR_BAD_COOKIE:
		return (EINVAL);
	case NFS4ERR_NOTSUPP:
		return (EOPNOTSUPP);
	case NFS4ERR_TOOSMALL:
		return (EINVAL);
	case NFS4ERR_SERVERFAULT:
		return (EIO);
	case NFS4ERR_BADTYPE:
		return (EINVAL);
	case NFS4ERR_DELAY:
		return (ENXIO);
	case NFS4ERR_SAME:
		return (EPROTO);
	case NFS4ERR_DENIED:
		return (ENOLCK);
	case NFS4ERR_EXPIRED:
		return (EPROTO);
	case NFS4ERR_LOCKED:
		return (EACCES);
	case NFS4ERR_GRACE:
		return (EAGAIN);
	case NFS4ERR_FHEXPIRED:	/* if got here, failed to get a new fh */
		return (ESTALE);
	case NFS4ERR_SHARE_DENIED:
		return (EACCES);
	case NFS4ERR_WRONGSEC:
		return (EPERM);
	case NFS4ERR_CLID_INUSE:
		return (EAGAIN);
	case NFS4ERR_RESOURCE:
		return (EAGAIN);
	case NFS4ERR_MOVED:
		return (EPROTO);
	case NFS4ERR_NOFILEHANDLE:
		return (EIO);
	case NFS4ERR_MINOR_VERS_MISMATCH:
		return (ENOTSUP);
	case NFS4ERR_STALE_CLIENTID:
		return (EIO);
	case NFS4ERR_STALE_STATEID:
		return (EIO);
	case NFS4ERR_OLD_STATEID:
		return (EIO);
	case NFS4ERR_BAD_STATEID:
		return (EIO);
	case NFS4ERR_BAD_SEQID:
		return (EIO);
	case NFS4ERR_NOT_SAME:
		return (EPROTO);
	case NFS4ERR_LOCK_RANGE:
		return (EPROTO);
	case NFS4ERR_SYMLINK:
		return (EPROTO);
	case NFS4ERR_RESTOREFH:
		return (EPROTO);
	case NFS4ERR_LEASE_MOVED:
		return (EPROTO);
	case NFS4ERR_ATTRNOTSUPP:
		return (ENOTSUP);
	case NFS4ERR_NO_GRACE:
		return (EPROTO);
	case NFS4ERR_RECLAIM_BAD:
		return (EPROTO);
	case NFS4ERR_RECLAIM_CONFLICT:
		return (EPROTO);
	case NFS4ERR_BADXDR:
		return (EINVAL);
	case NFS4ERR_LOCKS_HELD:
		return (EIO);
	case NFS4ERR_OPENMODE:
		return (EACCES);
	case NFS4ERR_BADOWNER:
		/*
		 * Client and server are in different DNS domains
		 * and the NFSMAPID_DOMAIN in /etc/default/nfs
		 * doesn't match.  No good answer here.  Return
		 * EACCESS, which translates to "permission denied".
		 */
		return (EACCES);
	case NFS4ERR_BADCHAR:
		return (EINVAL);
	case NFS4ERR_BADNAME:
		return (EINVAL);
	case NFS4ERR_BAD_RANGE:
		return (EIO);
	case NFS4ERR_LOCK_NOTSUPP:
		return (ENOTSUP);
	case NFS4ERR_OP_ILLEGAL:
		return (EINVAL);
	case NFS4ERR_DEADLOCK:
		return (EDEADLK);
	case NFS4ERR_FILE_OPEN:
		return (EACCES);
	case NFS4ERR_ADMIN_REVOKED:
		return (EPROTO);
	case NFS4ERR_CB_PATH_DOWN:
		return (EPROTO);
	default:
#ifdef DEBUG
		zcmn_err(getzoneid(), CE_WARN, "geterrno4: got status %d",
		    status);
#endif
		return ((int)status);
	}
}

void
nfs4_log_badowner(mntinfo4_t *mi, nfs_opnum4 op)
{
	nfs4_server_t *server;

	/*
	 * Return if already printed/queued a msg
	 * for this mount point.
	 */
	if (mi->mi_flags & MI4_BADOWNER_DEBUG)
		return;
	/*
	 * Happens once per client <-> server pair.
	 */
	if (nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER,
	    mi->mi_flags & MI4_INT))
		return;

	server = find_nfs4_server(mi);
	if (server == NULL) {
		nfs_rw_exit(&mi->mi_recovlock);
		return;
	}

	if (!(server->s_flags & N4S_BADOWNER_DEBUG)) {
		zcmn_err(mi->mi_zone->zone_id, CE_WARN,
		    "!NFSMAPID_DOMAIN does not match"
		    " the server: %s domain.\n"
		    "Please check configuration",
		    mi->mi_curr_serv->sv_hostname);
		server->s_flags |= N4S_BADOWNER_DEBUG;
	}
	mutex_exit(&server->s_lock);
	nfs4_server_rele(server);
	nfs_rw_exit(&mi->mi_recovlock);

	/*
	 * Happens once per mntinfo4_t.
	 * This error is deemed as one of the recovery facts "RF_BADOWNER",
	 * queue this in the mesg queue for this mount_info. This message
	 * is not printed, meaning its absent from id_to_dump_solo_fact()
	 * but its there for inspection if the queue is ever dumped/inspected.
	 */
	mutex_enter(&mi->mi_lock);
	if (!(mi->mi_flags & MI4_BADOWNER_DEBUG)) {
		nfs4_queue_fact(RF_BADOWNER, mi, NFS4ERR_BADOWNER, 0, op,
		    FALSE, NULL, 0, NULL);
		mi->mi_flags |= MI4_BADOWNER_DEBUG;
	}
	mutex_exit(&mi->mi_lock);
}

int
nfs4_time_ntov(nfstime4 *ntime, timestruc_t *vatime)
{
	int64_t sec;
	int32_t nsec;

	/*
	 * Here check that the nfsv4 time is valid for the system.
	 * nfsv4 time value is a signed 64-bit, and the system time
	 * may be either int64_t or int32_t (depends on the kernel),
	 * so if the kernel is 32-bit, the nfsv4 time value may not fit.
	 */
#ifndef _LP64
	if (! NFS4_TIME_OK(ntime->seconds)) {
		return (EOVERFLOW);
	}
#endif

	/* Invalid to specify 1 billion (or more) nsecs */
	if (ntime->nseconds >= 1000000000)
		return (EINVAL);

	if (ntime->seconds < 0) {
		sec = ntime->seconds + 1;
		nsec = -1000000000 + ntime->nseconds;
	} else {
		sec = ntime->seconds;
		nsec = ntime->nseconds;
	}

	vatime->tv_sec = sec;
	vatime->tv_nsec = nsec;

	return (0);
}

int
nfs4_time_vton(timestruc_t *vatime, nfstime4 *ntime)
{
	int64_t sec;
	uint32_t nsec;

	/*
	 * nfsv4 time value is a signed 64-bit, and the system time
	 * may be either int64_t or int32_t (depends on the kernel),
	 * so all system time values will fit.
	 */
	if (vatime->tv_nsec >= 0) {
		sec = vatime->tv_sec;
		nsec = vatime->tv_nsec;
	} else {
		sec = vatime->tv_sec - 1;
		nsec = 1000000000 + vatime->tv_nsec;
	}
	ntime->seconds = sec;
	ntime->nseconds = nsec;

	return (0);
}

/*
 * Converts a utf8 string to a valid null terminated filename string.
 *
 * XXX - Not actually translating the UTF-8 string as per RFC 2279.
 *	 For now, just validate that the UTF-8 string off the wire
 *	 does not have characters that will freak out UFS, and leave
 *	 it at that.
 */
char *
utf8_to_fn(utf8string *u8s, uint_t *lenp, char *s)
{
	ASSERT(lenp != NULL);

	if (u8s == NULL || u8s->utf8string_len <= 0 ||
	    u8s->utf8string_val == NULL)
		return (NULL);

	/*
	 * Check for obvious illegal filename chars
	 */
	if (utf8_strchr(u8s, '/') != NULL) {
#ifdef DEBUG
		if (nfs4_utf8_debug) {
			char *path;
			int len = u8s->utf8string_len;

			path = kmem_alloc(len + 1, KM_SLEEP);
			bcopy(u8s->utf8string_val, path, len);
			path[len] = '\0';

			zcmn_err(getzoneid(), CE_WARN,
			    "Invalid UTF-8 filename: %s", path);

			kmem_free(path, len + 1);
		}
#endif
		return (NULL);
	}

	return (utf8_to_str(u8s, lenp, s));
}

/*
 * Converts a utf8 string to a C string.
 * kmem_allocs a new string if not supplied
 */
char *
utf8_to_str(utf8string *str, uint_t *lenp, char *s)
{
	char	*sp;
	char	*u8p;
	int	len;
	int	 i;

	ASSERT(lenp != NULL);

	if (str == NULL)
		return (NULL);

	u8p = str->utf8string_val;
	len = str->utf8string_len;
	if (len <= 0 || u8p == NULL) {
		if (s)
			*s = '\0';
		return (NULL);
	}

	sp = s;
	if (sp == NULL)
		sp = kmem_alloc(len + 1, KM_SLEEP);

	/*
	 * At least check for embedded nulls
	 */
	for (i = 0; i < len; i++) {
		sp[i] = u8p[i];
		if (u8p[i] == '\0') {
#ifdef	DEBUG
			zcmn_err(getzoneid(), CE_WARN,
			    "Embedded NULL in UTF-8 string");
#endif
			if (s == NULL)
				kmem_free(sp, len + 1);
			return (NULL);
		}
	}
	sp[len] = '\0';
	*lenp = len + 1;

	return (sp);
}

/*
 * str_to_utf8 - converts a null-terminated C string to a utf8 string
 */
utf8string *
str_to_utf8(char *nm, utf8string *str)
{
	int len;

	if (str == NULL)
		return (NULL);

	if (nm == NULL || *nm == '\0') {
		str->utf8string_len = 0;
		str->utf8string_val = NULL;
	}

	len = strlen(nm);

	str->utf8string_val = kmem_alloc(len, KM_SLEEP);
	str->utf8string_len = len;
	bcopy(nm, str->utf8string_val, len);

	return (str);
}

utf8string *
utf8_copy(utf8string *src, utf8string *dest)
{
	if (src == NULL)
		return (NULL);
	if (dest == NULL)
		return (NULL);

	if (src->utf8string_len > 0) {
		dest->utf8string_val = kmem_alloc(src->utf8string_len,
		    KM_SLEEP);
		bcopy(src->utf8string_val, dest->utf8string_val,
		    src->utf8string_len);
		dest->utf8string_len = src->utf8string_len;
	} else {
		dest->utf8string_val = NULL;
		dest->utf8string_len = 0;
	}

	return (dest);
}

int
utf8_compare(const utf8string *a, const utf8string *b)
{
	int mlen, cmp;
	int alen, blen;
	char *aval, *bval;

	if ((a == NULL) && (b == NULL))
		return (0);
	else if (a == NULL)
		return (-1);
	else if (b == NULL)
		return (1);

	alen = a->utf8string_len;
	blen = b->utf8string_len;
	aval = a->utf8string_val;
	bval = b->utf8string_val;

	if (((alen == 0) || (aval == NULL)) &&
	    ((blen == 0) || (bval == NULL)))
		return (0);
	else if ((alen == 0) || (aval == NULL))
		return (-1);
	else if ((blen == 0) || (bval == NULL))
		return (1);

	mlen = MIN(alen, blen);
	cmp = strncmp(aval, bval, mlen);

	if ((cmp == 0) && (alen == blen))
		return (0);
	else if ((cmp == 0) && (alen < blen))
		return (-1);
	else if (cmp == 0)
		return (1);
	else if (cmp < 0)
		return (-1);
	return (1);
}

/*
 * utf8_dir_verify - checks that the utf8 string is valid
 */
nfsstat4
utf8_dir_verify(utf8string *str)
{
	char *nm;
	int len;

	if (str == NULL)
		return (NFS4ERR_INVAL);

	nm = str->utf8string_val;
	len = str->utf8string_len;
	if (nm == NULL || len == 0) {
		return (NFS4ERR_INVAL);
	}

	if (len == 1 && nm[0] == '.')
		return (NFS4ERR_BADNAME);
	if (len == 2 && nm[0] == '.' && nm[1] == '.')
		return (NFS4ERR_BADNAME);

	if (utf8_strchr(str, '/') != NULL)
		return (NFS4ERR_BADNAME);

	if (utf8_strchr(str, '\0') != NULL)
		return (NFS4ERR_BADNAME);

	return (NFS4_OK);
}

/*
 * from rpcsec module (common/rpcsec)
 */
extern int sec_clnt_geth(CLIENT *, struct sec_data *, cred_t *, AUTH **);
extern void sec_clnt_freeh(AUTH *);
extern void sec_clnt_freeinfo(struct sec_data *);

/*
 * authget() gets an auth handle based on the security
 * information from the servinfo in mountinfo.
 * The auth handle is stored in ch_client->cl_auth.
 *
 * First security flavor of choice is to use sv_secdata
 * which is initiated by the client. If that fails, get
 * secinfo from the server and then select one from the
 * server secinfo list .
 *
 * For RPCSEC_GSS flavor, upon success, a secure context is
 * established between client and server.
 */
int
authget(servinfo4_t *svp, CLIENT *ch_client, cred_t *cr)
{
	int error, i;

	/*
	 * SV4_TRYSECINFO indicates to try the secinfo list from
	 * sv_secinfo until a successful one is reached. Point
	 * sv_currsec to the selected security mechanism for
	 * later sessions.
	 */
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
	if ((svp->sv_flags & SV4_TRYSECINFO) && svp->sv_secinfo) {
		for (i = svp->sv_secinfo->index; i < svp->sv_secinfo->count;
		    i++) {
			if (!(error = sec_clnt_geth(ch_client,
			    &svp->sv_secinfo->sdata[i],
			    cr, &ch_client->cl_auth))) {

				svp->sv_currsec = &svp->sv_secinfo->sdata[i];
				svp->sv_secinfo->index = i;
				/* done */
				svp->sv_flags &= ~SV4_TRYSECINFO;
				break;
			}

			/*
			 * Allow the caller retry with the security flavor
			 * pointed by svp->sv_secinfo->index when
			 * ETIMEDOUT/ECONNRESET occurs.
			 */
			if (error == ETIMEDOUT || error == ECONNRESET) {
				svp->sv_secinfo->index = i;
				break;
			}
		}
	} else {
		/* sv_currsec points to one of the entries in sv_secinfo */
		if (svp->sv_currsec) {
			error = sec_clnt_geth(ch_client, svp->sv_currsec, cr,
			    &ch_client->cl_auth);
		} else {
			/* If it's null, use sv_secdata. */
			error = sec_clnt_geth(ch_client, svp->sv_secdata, cr,
			    &ch_client->cl_auth);
		}
	}
	nfs_rw_exit(&svp->sv_lock);

	return (error);
}

/*
 * Common handle get program for NFS, NFS ACL, and NFS AUTH client.
 */
int
clget4(clinfo_t *ci, servinfo4_t *svp, cred_t *cr, CLIENT **newcl,
    struct chtab **chp, struct nfs4_clnt *nfscl)
{
	struct chhead *ch, *newch;
	struct chhead **plistp;
	struct chtab *cp;
	int error;
	k_sigset_t smask;

	if (newcl == NULL || chp == NULL || ci == NULL)
		return (EINVAL);

	*newcl = NULL;
	*chp = NULL;

	/*
	 * Find an unused handle or create one
	 */
	newch = NULL;
	nfscl->nfscl_stat.clgets.value.ui64++;
top:
	/*
	 * Find the correct entry in the cache to check for free
	 * client handles.  The search is based on the RPC program
	 * number, program version number, dev_t for the transport
	 * device, and the protocol family.
	 */
	mutex_enter(&nfscl->nfscl_chtable4_lock);
	plistp = &nfscl->nfscl_chtable4;
	for (ch = nfscl->nfscl_chtable4; ch != NULL; ch = ch->ch_next) {
		if (ch->ch_prog == ci->cl_prog &&
		    ch->ch_vers == ci->cl_vers &&
		    ch->ch_dev == svp->sv_knconf->knc_rdev &&
		    (strcmp(ch->ch_protofmly,
		    svp->sv_knconf->knc_protofmly) == 0))
			break;
		plistp = &ch->ch_next;
	}

	/*
	 * If we didn't find a cache entry for this quadruple, then
	 * create one.  If we don't have one already preallocated,
	 * then drop the cache lock, create one, and then start over.
	 * If we did have a preallocated entry, then just add it to
	 * the front of the list.
	 */
	if (ch == NULL) {
		if (newch == NULL) {
			mutex_exit(&nfscl->nfscl_chtable4_lock);
			newch = kmem_alloc(sizeof (*newch), KM_SLEEP);
			newch->ch_timesused = 0;
			newch->ch_prog = ci->cl_prog;
			newch->ch_vers = ci->cl_vers;
			newch->ch_dev = svp->sv_knconf->knc_rdev;
			newch->ch_protofmly = kmem_alloc(
			    strlen(svp->sv_knconf->knc_protofmly) + 1,
			    KM_SLEEP);
			(void) strcpy(newch->ch_protofmly,
			    svp->sv_knconf->knc_protofmly);
			newch->ch_list = NULL;
			goto top;
		}
		ch = newch;
		newch = NULL;
		ch->ch_next = nfscl->nfscl_chtable4;
		nfscl->nfscl_chtable4 = ch;
	/*
	 * We found a cache entry, but if it isn't on the front of the
	 * list, then move it to the front of the list to try to take
	 * advantage of locality of operations.
	 */
	} else if (ch != nfscl->nfscl_chtable4) {
		*plistp = ch->ch_next;
		ch->ch_next = nfscl->nfscl_chtable4;
		nfscl->nfscl_chtable4 = ch;
	}

	/*
	 * If there was a free client handle cached, then remove it
	 * from the list, init it, and use it.
	 */
	if (ch->ch_list != NULL) {
		cp = ch->ch_list;
		ch->ch_list = cp->ch_list;
		mutex_exit(&nfscl->nfscl_chtable4_lock);
		if (newch != NULL) {
			kmem_free(newch->ch_protofmly,
			    strlen(newch->ch_protofmly) + 1);
			kmem_free(newch, sizeof (*newch));
		}
		(void) clnt_tli_kinit(cp->ch_client, svp->sv_knconf,
		    &svp->sv_addr, ci->cl_readsize, ci->cl_retrans, cr);

		/*
		 * Get an auth handle.
		 */
		error = authget(svp, cp->ch_client, cr);
		if (error || cp->ch_client->cl_auth == NULL) {
			CLNT_DESTROY(cp->ch_client);
			kmem_cache_free(chtab4_cache, cp);
			return ((error != 0) ? error : EINTR);
		}
		ch->ch_timesused++;
		*newcl = cp->ch_client;
		*chp = cp;
		return (0);
	}

	/*
	 * There weren't any free client handles which fit, so allocate
	 * a new one and use that.
	 */
#ifdef DEBUG
	atomic_inc_64(&nfscl->nfscl_stat.clalloc.value.ui64);
#endif
	mutex_exit(&nfscl->nfscl_chtable4_lock);

	nfscl->nfscl_stat.cltoomany.value.ui64++;
	if (newch != NULL) {
		kmem_free(newch->ch_protofmly, strlen(newch->ch_protofmly) + 1);
		kmem_free(newch, sizeof (*newch));
	}

	cp = kmem_cache_alloc(chtab4_cache, KM_SLEEP);
	cp->ch_head = ch;

	sigintr(&smask, (int)ci->cl_flags & MI4_INT);
	error = clnt_tli_kcreate(svp->sv_knconf, &svp->sv_addr, ci->cl_prog,
	    ci->cl_vers, ci->cl_readsize, ci->cl_retrans, cr, &cp->ch_client);
	sigunintr(&smask);

	if (error != 0) {
		kmem_cache_free(chtab4_cache, cp);
#ifdef DEBUG
		atomic_dec_64(&nfscl->nfscl_stat.clalloc.value.ui64);
#endif
		/*
		 * Warning is unnecessary if error is EINTR.
		 */
		if (error != EINTR) {
			nfs_cmn_err(error, CE_WARN,
			    "clget: couldn't create handle: %m\n");
		}
		return (error);
	}
	(void) CLNT_CONTROL(cp->ch_client, CLSET_PROGRESS, NULL);
	auth_destroy(cp->ch_client->cl_auth);

	/*
	 * Get an auth handle.
	 */
	error = authget(svp, cp->ch_client, cr);
	if (error || cp->ch_client->cl_auth == NULL) {
		CLNT_DESTROY(cp->ch_client);
		kmem_cache_free(chtab4_cache, cp);
#ifdef DEBUG
		atomic_dec_64(&nfscl->nfscl_stat.clalloc.value.ui64);
#endif
		return ((error != 0) ? error : EINTR);
	}
	ch->ch_timesused++;
	*newcl = cp->ch_client;
	ASSERT(cp->ch_client->cl_nosignal == FALSE);
	*chp = cp;
	return (0);
}

static int
nfs_clget4(mntinfo4_t *mi, servinfo4_t *svp, cred_t *cr, CLIENT **newcl,
    struct chtab **chp, struct nfs4_clnt *nfscl)
{
	clinfo_t ci;
	bool_t is_recov;
	int firstcall, error = 0;

	/*
	 * Set read buffer size to rsize
	 * and add room for RPC headers.
	 */
	ci.cl_readsize = mi->mi_tsize;
	if (ci.cl_readsize != 0)
		ci.cl_readsize += (RPC_MAXDATASIZE - NFS_MAXDATA);

	/*
	 * If soft mount and server is down just try once.
	 * meaning: do not retransmit.
	 */
	if (!(mi->mi_flags & MI4_HARD) && (mi->mi_flags & MI4_DOWN))
		ci.cl_retrans = 0;
	else
		ci.cl_retrans = mi->mi_retrans;

	ci.cl_prog = mi->mi_prog;
	ci.cl_vers = mi->mi_vers;
	ci.cl_flags = mi->mi_flags;

	/*
	 * clget4 calls authget() to get an auth handle. For RPCSEC_GSS
	 * security flavor, the client tries to establish a security context
	 * by contacting the server. If the connection is timed out or reset,
	 * e.g. server reboot, we will try again.
	 */
	is_recov = (curthread == mi->mi_recovthread);
	firstcall = 1;

	do {
		error = clget4(&ci, svp, cr, newcl, chp, nfscl);

		if (error == 0)
			break;

		/*
		 * For forced unmount and zone shutdown, bail out but
		 * let the recovery thread do one more transmission.
		 */
		if ((FS_OR_ZONE_GONE4(mi->mi_vfsp)) &&
		    (!is_recov || !firstcall)) {
			error = EIO;
			break;
		}

		/* do not retry for soft mount */
		if (!(mi->mi_flags & MI4_HARD))
			break;

		/* let the caller deal with the failover case */
		if (FAILOVER_MOUNT4(mi))
			break;

		firstcall = 0;

	} while (error == ETIMEDOUT || error == ECONNRESET);

	return (error);
}

void
clfree4(CLIENT *cl, struct chtab *cp, struct nfs4_clnt *nfscl)
{
	if (cl->cl_auth != NULL) {
		sec_clnt_freeh(cl->cl_auth);
		cl->cl_auth = NULL;
	}

	/*
	 * Timestamp this cache entry so that we know when it was last
	 * used.
	 */
	cp->ch_freed = gethrestime_sec();

	/*
	 * Add the free client handle to the front of the list.
	 * This way, the list will be sorted in youngest to oldest
	 * order.
	 */
	mutex_enter(&nfscl->nfscl_chtable4_lock);
	cp->ch_list = cp->ch_head->ch_list;
	cp->ch_head->ch_list = cp;
	mutex_exit(&nfscl->nfscl_chtable4_lock);
}

#define	CL_HOLDTIME	60	/* time to hold client handles */

static void
clreclaim4_zone(struct nfs4_clnt *nfscl, uint_t cl_holdtime)
{
	struct chhead *ch;
	struct chtab *cp;	/* list of objects that can be reclaimed */
	struct chtab *cpe;
	struct chtab *cpl;
	struct chtab **cpp;
#ifdef DEBUG
	int n = 0;
	clstat4_debug.clreclaim.value.ui64++;
#endif

	/*
	 * Need to reclaim some memory, so step through the cache
	 * looking through the lists for entries which can be freed.
	 */
	cp = NULL;

	mutex_enter(&nfscl->nfscl_chtable4_lock);

	/*
	 * Here we step through each non-NULL quadruple and start to
	 * construct the reclaim list pointed to by cp.  Note that
	 * cp will contain all eligible chtab entries.  When this traversal
	 * completes, chtab entries from the last quadruple will be at the
	 * front of cp and entries from previously inspected quadruples have
	 * been appended to the rear of cp.
	 */
	for (ch = nfscl->nfscl_chtable4; ch != NULL; ch = ch->ch_next) {
		if (ch->ch_list == NULL)
			continue;
		/*
		 * Search each list for entries older then
		 * cl_holdtime seconds.  The lists are maintained
		 * in youngest to oldest order so that when the
		 * first entry is found which is old enough, then
		 * all of the rest of the entries on the list will
		 * be old enough as well.
		 */
		cpl = ch->ch_list;
		cpp = &ch->ch_list;
		while (cpl != NULL &&
		    cpl->ch_freed + cl_holdtime > gethrestime_sec()) {
			cpp = &cpl->ch_list;
			cpl = cpl->ch_list;
		}
		if (cpl != NULL) {
			*cpp = NULL;
			if (cp != NULL) {
				cpe = cpl;
				while (cpe->ch_list != NULL)
					cpe = cpe->ch_list;
				cpe->ch_list = cp;
			}
			cp = cpl;
		}
	}

	mutex_exit(&nfscl->nfscl_chtable4_lock);

	/*
	 * If cp is empty, then there is nothing to reclaim here.
	 */
	if (cp == NULL)
		return;

	/*
	 * Step through the list of entries to free, destroying each client
	 * handle and kmem_free'ing the memory for each entry.
	 */
	while (cp != NULL) {
#ifdef DEBUG
		n++;
#endif
		CLNT_DESTROY(cp->ch_client);
		cpl = cp->ch_list;
		kmem_cache_free(chtab4_cache, cp);
		cp = cpl;
	}

#ifdef DEBUG
	/*
	 * Update clalloc so that nfsstat shows the current number
	 * of allocated client handles.
	 */
	atomic_add_64(&nfscl->nfscl_stat.clalloc.value.ui64, -n);
#endif
}

/* ARGSUSED */
static void
clreclaim4(void *all)
{
	struct nfs4_clnt *nfscl;

	/*
	 * The system is low on memory; go through and try to reclaim some from
	 * every zone on the system.
	 */
	mutex_enter(&nfs4_clnt_list_lock);
	nfscl = list_head(&nfs4_clnt_list);
	for (; nfscl != NULL; nfscl = list_next(&nfs4_clnt_list, nfscl))
		clreclaim4_zone(nfscl, CL_HOLDTIME);
	mutex_exit(&nfs4_clnt_list_lock);
}

/*
 * Minimum time-out values indexed by call type
 * These units are in "eights" of a second to avoid multiplies
 */
static unsigned int minimum_timeo[] = {
	6, 7, 10
};

#define	SHORTWAIT	(NFS_COTS_TIMEO / 10)

/*
 * Back off for retransmission timeout, MAXTIMO is in hz of a sec
 */
#define	MAXTIMO	(20*hz)
#define	backoff(tim)	(((tim) < MAXTIMO) ? dobackoff(tim) : (tim))
#define	dobackoff(tim)	((((tim) << 1) > MAXTIMO) ? MAXTIMO : ((tim) << 1))

static int
nfs4_rfscall(mntinfo4_t *mi, rpcproc_t which, xdrproc_t xdrargs, caddr_t argsp,
    xdrproc_t xdrres, caddr_t resp, cred_t *icr, int *doqueue,
    enum clnt_stat *rpc_statusp, int flags, struct nfs4_clnt *nfscl)
{
	CLIENT *client;
	struct chtab *ch;
	cred_t *cr = icr;
	struct rpc_err rpcerr, rpcerr_tmp;
	enum clnt_stat status;
	int error;
	struct timeval wait;
	int timeo;		/* in units of hz */
	bool_t tryagain, is_recov;
	bool_t cred_cloned = FALSE;
	k_sigset_t smask;
	servinfo4_t *svp;
#ifdef DEBUG
	char *bufp;
#endif
	int firstcall;

	rpcerr.re_status = RPC_SUCCESS;

	/*
	 * If we know that we are rebooting then let's
	 * not bother with doing any over the wireness.
	 */
	mutex_enter(&mi->mi_lock);
	if (mi->mi_flags & MI4_SHUTDOWN) {
		mutex_exit(&mi->mi_lock);
		return (EIO);
	}
	mutex_exit(&mi->mi_lock);

	/* For TSOL, use a new cred which has net_mac_aware flag */
	if (!cred_cloned && is_system_labeled()) {
		cred_cloned = TRUE;
		cr = crdup(icr);
		(void) setpflags(NET_MAC_AWARE, 1, cr);
	}

	/*
	 * clget() calls clnt_tli_kinit() which clears the xid, so we
	 * are guaranteed to reprocess the retry as a new request.
	 */
	svp = mi->mi_curr_serv;
	rpcerr.re_errno = nfs_clget4(mi, svp, cr, &client, &ch, nfscl);
	if (rpcerr.re_errno != 0)
		return (rpcerr.re_errno);

	timeo = (mi->mi_timeo * hz) / 10;

	/*
	 * If hard mounted fs, retry call forever unless hard error
	 * occurs.
	 *
	 * For forced unmount, let the recovery thread through but return
	 * an error for all others.  This is so that user processes can
	 * exit quickly.  The recovery thread bails out after one
	 * transmission so that it can tell if it needs to continue.
	 *
	 * For zone shutdown, behave as above to encourage quick
	 * process exit, but also fail quickly when servers have
	 * timed out before and reduce the timeouts.
	 */
	is_recov = (curthread == mi->mi_recovthread);
	firstcall = 1;
	do {
		tryagain = FALSE;

		NFS4_DEBUG(nfs4_rfscall_debug, (CE_NOTE,
		    "nfs4_rfscall: vfs_flag=0x%x, %s",
		    mi->mi_vfsp->vfs_flag,
		    is_recov ? "recov thread" : "not recov thread"));

		/*
		 * It's possible while we're retrying the admin
		 * decided to reboot.
		 */
		mutex_enter(&mi->mi_lock);
		if (mi->mi_flags & MI4_SHUTDOWN) {
			mutex_exit(&mi->mi_lock);
			clfree4(client, ch, nfscl);
			if (cred_cloned)
				crfree(cr);
			return (EIO);
		}
		mutex_exit(&mi->mi_lock);

		if ((mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED) &&
		    (!is_recov || !firstcall)) {
			clfree4(client, ch, nfscl);
			if (cred_cloned)
				crfree(cr);
			return (EIO);
		}

		if (zone_status_get(curproc->p_zone) >= ZONE_IS_SHUTTING_DOWN) {
			mutex_enter(&mi->mi_lock);
			if ((mi->mi_flags & MI4_TIMEDOUT) ||
			    !is_recov || !firstcall) {
				mutex_exit(&mi->mi_lock);
				clfree4(client, ch, nfscl);
				if (cred_cloned)
					crfree(cr);
				return (EIO);
			}
			mutex_exit(&mi->mi_lock);
			timeo = (MIN(mi->mi_timeo, SHORTWAIT) * hz) / 10;
		}

		firstcall = 0;
		TICK_TO_TIMEVAL(timeo, &wait);

		/*
		 * Mask out all signals except SIGHUP, SIGINT, SIGQUIT
		 * and SIGTERM. (Preserving the existing masks).
		 * Mask out SIGINT if mount option nointr is specified.
		 */
		sigintr(&smask, (int)mi->mi_flags & MI4_INT);
		if (!(mi->mi_flags & MI4_INT))
			client->cl_nosignal = TRUE;

		/*
		 * If there is a current signal, then don't bother
		 * even trying to send out the request because we
		 * won't be able to block waiting for the response.
		 * Simply assume RPC_INTR and get on with it.
		 */
		if (ttolwp(curthread) != NULL && ISSIG(curthread, JUSTLOOKING))
			status = RPC_INTR;
		else {
			status = CLNT_CALL(client, which, xdrargs, argsp,
			    xdrres, resp, wait);
		}

		if (!(mi->mi_flags & MI4_INT))
			client->cl_nosignal = FALSE;
		/*
		 * restore original signal mask
		 */
		sigunintr(&smask);

		switch (status) {
		case RPC_SUCCESS:
			break;

		case RPC_INTR:
			/*
			 * There is no way to recover from this error,
			 * even if mount option nointr is specified.
			 * SIGKILL, for example, cannot be blocked.
			 */
			rpcerr.re_status = RPC_INTR;
			rpcerr.re_errno = EINTR;
			break;

		case RPC_UDERROR:
			/*
			 * If the NFS server is local (vold) and
			 * it goes away then we get RPC_UDERROR.
			 * This is a retryable error, so we would
			 * loop, so check to see if the specific
			 * error was ECONNRESET, indicating that
			 * target did not exist at all.  If so,
			 * return with RPC_PROGUNAVAIL and
			 * ECONNRESET to indicate why.
			 */
			CLNT_GETERR(client, &rpcerr);
			if (rpcerr.re_errno == ECONNRESET) {
				rpcerr.re_status = RPC_PROGUNAVAIL;
				rpcerr.re_errno = ECONNRESET;
				break;
			}
			/*FALLTHROUGH*/

		default:		/* probably RPC_TIMEDOUT */

			if (IS_UNRECOVERABLE_RPC(status))
				break;

			/*
			 * increment server not responding count
			 */
			mutex_enter(&mi->mi_lock);
			mi->mi_noresponse++;
			mutex_exit(&mi->mi_lock);
#ifdef DEBUG
			nfscl->nfscl_stat.noresponse.value.ui64++;
#endif
			/*
			 * On zone shutdown, mark server dead and move on.
			 */
			if (zone_status_get(curproc->p_zone) >=
			    ZONE_IS_SHUTTING_DOWN) {
				mutex_enter(&mi->mi_lock);
				mi->mi_flags |= MI4_TIMEDOUT;
				mutex_exit(&mi->mi_lock);
				clfree4(client, ch, nfscl);
				if (cred_cloned)
					crfree(cr);
				return (EIO);
			}

			/*
			 * NFS client failover support:
			 * return and let the caller take care of
			 * failover.  We only return for failover mounts
			 * because otherwise we want the "not responding"
			 * message, the timer updates, etc.
			 */
			if (mi->mi_vers == 4 && FAILOVER_MOUNT4(mi) &&
			    (error = try_failover(status)) != 0) {
				clfree4(client, ch, nfscl);
				if (cred_cloned)
					crfree(cr);
				*rpc_statusp = status;
				return (error);
			}

			if (flags & RFSCALL_SOFT)
				break;

			tryagain = TRUE;

			/*
			 * The call is in progress (over COTS).
			 * Try the CLNT_CALL again, but don't
			 * print a noisy error message.
			 */
			if (status == RPC_INPROGRESS)
				break;

			timeo = backoff(timeo);
			CLNT_GETERR(client, &rpcerr_tmp);

			mutex_enter(&mi->mi_lock);
			if (!(mi->mi_flags & MI4_PRINTED)) {
				mi->mi_flags |= MI4_PRINTED;
				mutex_exit(&mi->mi_lock);
				if ((status == RPC_CANTSEND) &&
				    (rpcerr_tmp.re_errno == ENOBUFS))
					nfs4_queue_fact(RF_SENDQ_FULL, mi, 0,
					    0, 0, FALSE, NULL, 0, NULL);
				else
					nfs4_queue_fact(RF_SRV_NOT_RESPOND, mi,
					    0, 0, 0, FALSE, NULL, 0, NULL);
			} else
				mutex_exit(&mi->mi_lock);

			if (*doqueue && nfs_has_ctty()) {
				*doqueue = 0;
				if (!(mi->mi_flags & MI4_NOPRINT)) {
					if ((status == RPC_CANTSEND) &&
					    (rpcerr_tmp.re_errno == ENOBUFS))
						nfs4_queue_fact(RF_SENDQ_FULL,
						    mi, 0, 0, 0, FALSE, NULL,
						    0, NULL);
					else
						nfs4_queue_fact(
						    RF_SRV_NOT_RESPOND, mi, 0,
						    0, 0, FALSE, NULL, 0, NULL);
				}
			}
		}
	} while (tryagain);

	DTRACE_PROBE2(nfs4__rfscall_debug, enum clnt_stat, status,
	    int, rpcerr.re_errno);

	if (status != RPC_SUCCESS) {
		zoneid_t zoneid = mi->mi_zone->zone_id;

		/*
		 * Let soft mounts use the timed out message.
		 */
		if (status == RPC_INPROGRESS)
			status = RPC_TIMEDOUT;
		nfscl->nfscl_stat.badcalls.value.ui64++;
		if (status != RPC_INTR) {
			mutex_enter(&mi->mi_lock);
			mi->mi_flags |= MI4_DOWN;
			mutex_exit(&mi->mi_lock);
			CLNT_GETERR(client, &rpcerr);
#ifdef DEBUG
			bufp = clnt_sperror(client, svp->sv_hostname);
			zprintf(zoneid, "NFS%d %s failed for %s\n",
			    mi->mi_vers, mi->mi_rfsnames[which], bufp);
			if (nfs_has_ctty()) {
				if (!(mi->mi_flags & MI4_NOPRINT)) {
					uprintf("NFS%d %s failed for %s\n",
					    mi->mi_vers, mi->mi_rfsnames[which],
					    bufp);
				}
			}
			kmem_free(bufp, MAXPATHLEN);
#else
			zprintf(zoneid,
			    "NFS %s failed for server %s: error %d (%s)\n",
			    mi->mi_rfsnames[which], svp->sv_hostname,
			    status, clnt_sperrno(status));
			if (nfs_has_ctty()) {
				if (!(mi->mi_flags & MI4_NOPRINT)) {
					uprintf(
				"NFS %s failed for server %s: error %d (%s)\n",
					    mi->mi_rfsnames[which],
					    svp->sv_hostname, status,
					    clnt_sperrno(status));
				}
			}
#endif
			/*
			 * when CLNT_CALL() fails with RPC_AUTHERROR,
			 * re_errno is set appropriately depending on
			 * the authentication error
			 */
			if (status == RPC_VERSMISMATCH ||
			    status == RPC_PROGVERSMISMATCH)
				rpcerr.re_errno = EIO;
		}
	} else {
		/*
		 * Test the value of mi_down and mi_printed without
		 * holding the mi_lock mutex.  If they are both zero,
		 * then it is okay to skip the down and printed
		 * processing.  This saves on a mutex_enter and
		 * mutex_exit pair for a normal, successful RPC.
		 * This was just complete overhead.
		 */
		if (mi->mi_flags & (MI4_DOWN | MI4_PRINTED)) {
			mutex_enter(&mi->mi_lock);
			mi->mi_flags &= ~MI4_DOWN;
			if (mi->mi_flags & MI4_PRINTED) {
				mi->mi_flags &= ~MI4_PRINTED;
				mutex_exit(&mi->mi_lock);
				if (!(mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED))
					nfs4_queue_fact(RF_SRV_OK, mi, 0, 0,
					    0, FALSE, NULL, 0, NULL);
			} else
				mutex_exit(&mi->mi_lock);
		}

		if (*doqueue == 0) {
			if (!(mi->mi_flags & MI4_NOPRINT) &&
			    !(mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED))
				nfs4_queue_fact(RF_SRV_OK, mi, 0, 0, 0,
				    FALSE, NULL, 0, NULL);

			*doqueue = 1;
		}
	}

	clfree4(client, ch, nfscl);
	if (cred_cloned)
		crfree(cr);

	ASSERT(rpcerr.re_status == RPC_SUCCESS || rpcerr.re_errno != 0);

	TRACE_1(TR_FAC_NFS, TR_RFSCALL_END, "nfs4_rfscall_end:errno %d",
	    rpcerr.re_errno);

	*rpc_statusp = status;
	return (rpcerr.re_errno);
}

/*
 * rfs4call - general wrapper for RPC calls initiated by the client
 */
void
rfs4call(mntinfo4_t *mi, COMPOUND4args_clnt *argsp, COMPOUND4res_clnt *resp,
    cred_t *cr, int *doqueue, int flags, nfs4_error_t *ep)
{
	int i, error;
	enum clnt_stat rpc_status = NFS4_OK;
	int num_resops;
	struct nfs4_clnt *nfscl;

	ASSERT(nfs_zone() == mi->mi_zone);
	nfscl = zone_getspecific(nfs4clnt_zone_key, nfs_zone());
	ASSERT(nfscl != NULL);

	nfscl->nfscl_stat.calls.value.ui64++;
	mi->mi_reqs[NFSPROC4_COMPOUND].value.ui64++;

	/* Set up the results struct for XDR usage */
	resp->argsp = argsp;
	resp->array = NULL;
	resp->status = 0;
	resp->decode_len = 0;

	error = nfs4_rfscall(mi, NFSPROC4_COMPOUND,
	    xdr_COMPOUND4args_clnt, (caddr_t)argsp,
	    xdr_COMPOUND4res_clnt, (caddr_t)resp, cr,
	    doqueue, &rpc_status, flags, nfscl);

	/* Return now if it was an RPC error */
	if (error) {
		ep->error = error;
		ep->stat = resp->status;
		ep->rpc_status = rpc_status;
		return;
	}

	/* else we'll count the processed operations */
	num_resops = resp->decode_len;
	for (i = 0; i < num_resops; i++) {
		/*
		 * Count the individual operations
		 * processed by the server.
		 */
		if (resp->array[i].resop >= NFSPROC4_NULL &&
		    resp->array[i].resop <= OP_WRITE)
			mi->mi_reqs[resp->array[i].resop].value.ui64++;
	}

	ep->error = 0;
	ep->stat = resp->status;
	ep->rpc_status = rpc_status;
}

/*
 * nfs4rename_update - updates stored state after a rename.  Currently this
 * is the path of the object and anything under it, and the filehandle of
 * the renamed object.
 */
void
nfs4rename_update(vnode_t *renvp, vnode_t *ndvp, nfs_fh4 *nfh4p, char *nnm)
{
	sfh4_update(VTOR4(renvp)->r_fh, nfh4p);
	fn_move(VTOSV(renvp)->sv_name, VTOSV(ndvp)->sv_name, nnm);
}

/*
 * Routine to look up the filehandle for the given path and rootvp.
 *
 * Return values:
 * - success: returns zero and *statp is set to NFS4_OK, and *fhp is
 *   updated.
 * - error: return value (errno value) and/or *statp is set appropriately.
 */
#define	RML_ORDINARY	1
#define	RML_NAMED_ATTR	2
#define	RML_ATTRDIR	3

static void
remap_lookup(nfs4_fname_t *fname, vnode_t *rootvp,
    int filetype, cred_t *cr,
    nfs_fh4 *fhp, nfs4_ga_res_t *garp,		/* fh, attrs for object */
    nfs_fh4 *pfhp, nfs4_ga_res_t *pgarp,	/* fh, attrs for parent */
    nfs4_error_t *ep)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 *argop;
	nfs_resop4 *resop;
	int num_argops;
	lookup4_param_t lookuparg;
	nfs_fh4 *tmpfhp;
	int doqueue = 1;
	char *path;
	mntinfo4_t *mi;

	ASSERT(fname != NULL);
	ASSERT(rootvp->v_type == VDIR);

	mi = VTOMI4(rootvp);
	path = fn_path(fname);
	switch (filetype) {
	case RML_NAMED_ATTR:
		lookuparg.l4_getattrs = LKP4_LAST_NAMED_ATTR;
		args.ctag = TAG_REMAP_LOOKUP_NA;
		break;
	case RML_ATTRDIR:
		lookuparg.l4_getattrs = LKP4_LAST_ATTRDIR;
		args.ctag = TAG_REMAP_LOOKUP_AD;
		break;
	case RML_ORDINARY:
		lookuparg.l4_getattrs = LKP4_ALL_ATTRIBUTES;
		args.ctag = TAG_REMAP_LOOKUP;
		break;
	default:
		ep->error = EINVAL;
		return;
	}
	lookuparg.argsp = &args;
	lookuparg.resp = &res;
	lookuparg.header_len = 1;	/* Putfh */
	lookuparg.trailer_len = 0;
	lookuparg.ga_bits = NFS4_VATTR_MASK;
	lookuparg.mi = VTOMI4(rootvp);

	(void) nfs4lookup_setup(path, &lookuparg, 1);

	/* 0: putfh directory */
	argop = args.array;
	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = VTOR4(rootvp)->r_fh;

	num_argops = args.array_len;

	rfs4call(mi, &args, &res, cr, &doqueue, RFSCALL_SOFT, ep);

	if (ep->error || res.status != NFS4_OK)
		goto exit;

	/* get the object filehandle */
	resop = &res.array[res.array_len - 2];
	if (resop->resop != OP_GETFH) {
		nfs4_queue_event(RE_FAIL_REMAP_OP, mi, NULL,
		    0, NULL, NULL, 0, NULL, 0, TAG_NONE, TAG_NONE, 0, 0);
		ep->stat = NFS4ERR_SERVERFAULT;
		goto exit;
	}
	tmpfhp = &resop->nfs_resop4_u.opgetfh.object;
	if (tmpfhp->nfs_fh4_len > NFS4_FHSIZE) {
		nfs4_queue_event(RE_FAIL_REMAP_LEN, mi, NULL,
		    tmpfhp->nfs_fh4_len, NULL, NULL, 0, NULL, 0, TAG_NONE,
		    TAG_NONE, 0, 0);
		ep->stat = NFS4ERR_SERVERFAULT;
		goto exit;
	}
	fhp->nfs_fh4_val = kmem_alloc(tmpfhp->nfs_fh4_len, KM_SLEEP);
	nfs_fh4_copy(tmpfhp, fhp);

	/* get the object attributes */
	resop = &res.array[res.array_len - 1];
	if (garp && resop->resop == OP_GETATTR)
		*garp = resop->nfs_resop4_u.opgetattr.ga_res;

	/* See if there are enough fields in the response for parent info */
	if ((int)res.array_len - 5 <= 0)
		goto exit;

	/* get the parent filehandle */
	resop = &res.array[res.array_len - 5];
	if (resop->resop != OP_GETFH) {
		nfs4_queue_event(RE_FAIL_REMAP_OP, mi, NULL,
		    0, NULL, NULL, 0, NULL, 0, TAG_NONE, TAG_NONE, 0, 0);
		ep->stat = NFS4ERR_SERVERFAULT;
		goto exit;
	}
	tmpfhp = &resop->nfs_resop4_u.opgetfh.object;
	if (tmpfhp->nfs_fh4_len > NFS4_FHSIZE) {
		nfs4_queue_event(RE_FAIL_REMAP_LEN, mi, NULL,
		    tmpfhp->nfs_fh4_len, NULL, NULL, 0, NULL, 0, TAG_NONE,
		    TAG_NONE, 0, 0);
		ep->stat = NFS4ERR_SERVERFAULT;
		goto exit;
	}
	pfhp->nfs_fh4_val = kmem_alloc(tmpfhp->nfs_fh4_len, KM_SLEEP);
	nfs_fh4_copy(tmpfhp, pfhp);

	/* get the parent attributes */
	resop = &res.array[res.array_len - 4];
	if (pgarp && resop->resop == OP_GETATTR)
		*pgarp = resop->nfs_resop4_u.opgetattr.ga_res;

exit:
	/*
	 * It is too hard to remember where all the OP_LOOKUPs are
	 */
	nfs4args_lookup_free(argop, num_argops);
	kmem_free(argop, lookuparg.arglen * sizeof (nfs_argop4));

	if (!ep->error)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	kmem_free(path, strlen(path)+1);
}

/*
 * NFS client failover / volatile filehandle support
 *
 * Recover the filehandle for the given rnode.
 *
 * Errors are returned via the nfs4_error_t parameter.
 */

void
nfs4_remap_file(mntinfo4_t *mi, vnode_t *vp, int flags, nfs4_error_t *ep)
{
	int is_stub;
	rnode4_t *rp = VTOR4(vp);
	vnode_t *rootvp = NULL;
	vnode_t *dvp = NULL;
	cred_t *cr, *cred_otw;
	nfs4_ga_res_t gar, pgar;
	nfs_fh4 newfh = {0, NULL}, newpfh = {0, NULL};
	int filetype = RML_ORDINARY;
	nfs4_recov_state_t recov = {NULL, 0, 0};
	int badfhcount = 0;
	nfs4_open_stream_t *osp = NULL;
	bool_t first_time = TRUE;	/* first time getting OTW cred */
	bool_t last_time = FALSE;	/* last time getting OTW cred */

	NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
	    "nfs4_remap_file: remapping %s", rnode4info(rp)));
	ASSERT(nfs4_consistent_type(vp));

	if (vp->v_flag & VROOT) {
		nfs4_remap_root(mi, ep, flags);
		return;
	}

	/*
	 * Given the root fh, use the path stored in
	 * the rnode to find the fh for the new server.
	 */
	ep->error = VFS_ROOT(mi->mi_vfsp, &rootvp);
	if (ep->error != 0)
		return;

	cr = curthread->t_cred;
	ASSERT(cr != NULL);
get_remap_cred:
	/*
	 * Releases the osp, if it is provided.
	 * Puts a hold on the cred_otw and the new osp (if found).
	 */
	cred_otw = nfs4_get_otw_cred_by_osp(rp, cr, &osp,
	    &first_time, &last_time);
	ASSERT(cred_otw != NULL);

	if (rp->r_flags & R4ISXATTR) {
		filetype = RML_NAMED_ATTR;
		(void) vtodv(vp, &dvp, cred_otw, FALSE);
	}

	if (vp->v_flag & V_XATTRDIR) {
		filetype = RML_ATTRDIR;
	}

	if (filetype == RML_ORDINARY && rootvp->v_type == VREG) {
		/* file mount, doesn't need a remap */
		goto done;
	}

again:
	remap_lookup(rp->r_svnode.sv_name, rootvp, filetype, cred_otw,
	    &newfh, &gar, &newpfh, &pgar, ep);

	NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
	    "nfs4_remap_file: remap_lookup returned %d/%d",
	    ep->error, ep->stat));

	if (last_time == FALSE && ep->error == EACCES) {
		crfree(cred_otw);
		if (dvp != NULL)
			VN_RELE(dvp);
		goto get_remap_cred;
	}
	if (ep->error != 0)
		goto done;

	switch (ep->stat) {
	case NFS4_OK:
		badfhcount = 0;
		if (recov.rs_flags & NFS4_RS_DELAY_MSG) {
			mutex_enter(&rp->r_statelock);
			rp->r_delay_interval = 0;
			mutex_exit(&rp->r_statelock);
			uprintf("NFS File Available..\n");
		}
		break;
	case NFS4ERR_FHEXPIRED:
	case NFS4ERR_BADHANDLE:
	case NFS4ERR_STALE:
		/*
		 * If we ran into filehandle problems, we should try to
		 * remap the root vnode first and hope life gets better.
		 * But we need to avoid loops.
		 */
		if (badfhcount++ > 0)
			goto done;
		if (newfh.nfs_fh4_len != 0) {
			kmem_free(newfh.nfs_fh4_val, newfh.nfs_fh4_len);
			newfh.nfs_fh4_len = 0;
		}
		if (newpfh.nfs_fh4_len != 0) {
			kmem_free(newpfh.nfs_fh4_val, newpfh.nfs_fh4_len);
			newpfh.nfs_fh4_len = 0;
		}
		/* relative path - remap rootvp then retry */
		VN_RELE(rootvp);
		rootvp = NULL;
		nfs4_remap_root(mi, ep, flags);
		if (ep->error != 0 || ep->stat != NFS4_OK)
			goto done;
		ep->error = VFS_ROOT(mi->mi_vfsp, &rootvp);
		if (ep->error != 0)
			goto done;
		goto again;
	case NFS4ERR_DELAY:
		badfhcount = 0;
		nfs4_set_delay_wait(vp);
		ep->error = nfs4_wait_for_delay(vp, &recov);
		if (ep->error != 0)
			goto done;
		goto again;
	case NFS4ERR_ACCESS:
		/* get new cred, try again */
		if (last_time == TRUE)
			goto done;
		if (dvp != NULL)
			VN_RELE(dvp);
		crfree(cred_otw);
		goto get_remap_cred;
	default:
		goto done;
	}

	/*
	 * Check on the new and old rnodes before updating;
	 * if the vnode type or size changes, issue a warning
	 * and mark the file dead.
	 */
	mutex_enter(&rp->r_statelock);
	if (flags & NFS4_REMAP_CKATTRS) {
		if (vp->v_type != gar.n4g_va.va_type ||
		    (vp->v_type != VDIR &&
		    rp->r_size != gar.n4g_va.va_size)) {
			NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
			    "nfs4_remap_file: size %d vs. %d, type %d vs. %d",
			    (int)rp->r_size, (int)gar.n4g_va.va_size,
			    vp->v_type, gar.n4g_va.va_type));
			mutex_exit(&rp->r_statelock);
			nfs4_queue_event(RE_FILE_DIFF, mi,
			    rp->r_server->sv_hostname, 0, vp, NULL, 0, NULL, 0,
			    TAG_NONE, TAG_NONE, 0, 0);
			nfs4_fail_recov(vp, NULL, 0, NFS4_OK);
			goto done;
		}
	}
	ASSERT(gar.n4g_va.va_type != VNON);
	rp->r_server = mi->mi_curr_serv;

	/*
	 * Turn this object into a "stub" object if we
	 * crossed an underlying server fs boundary.
	 *
	 * This stub will be for a mirror-mount.
	 * A referral would look like a boundary crossing
	 * as well, but would not be the same type of object,
	 * so we would expect to mark the object dead.
	 *
	 * See comment in r4_do_attrcache() for more details.
	 */
	is_stub = 0;
	if (gar.n4g_fsid_valid) {
		(void) nfs_rw_enter_sig(&rp->r_server->sv_lock, RW_READER, 0);
		rp->r_srv_fsid = gar.n4g_fsid;
		if (!FATTR4_FSID_EQ(&gar.n4g_fsid, &rp->r_server->sv_fsid))
			is_stub = 1;
		nfs_rw_exit(&rp->r_server->sv_lock);
#ifdef DEBUG
	} else {
		NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
		    "remap_file: fsid attr not provided by server.  rp=%p",
		    (void *)rp));
#endif
	}
	if (is_stub)
		r4_stub_mirrormount(rp);
	else
		r4_stub_none(rp);
	mutex_exit(&rp->r_statelock);
	nfs4_attrcache_noinval(vp, &gar, gethrtime()); /* force update */
	sfh4_update(rp->r_fh, &newfh);
	ASSERT(nfs4_consistent_type(vp));

	/*
	 * If we got parent info, use it to update the parent
	 */
	if (newpfh.nfs_fh4_len != 0) {
		if (rp->r_svnode.sv_dfh != NULL)
			sfh4_update(rp->r_svnode.sv_dfh, &newpfh);
		if (dvp != NULL) {
			/* force update of attrs */
			nfs4_attrcache_noinval(dvp, &pgar, gethrtime());
		}
	}
done:
	if (newfh.nfs_fh4_len != 0)
		kmem_free(newfh.nfs_fh4_val, newfh.nfs_fh4_len);
	if (newpfh.nfs_fh4_len != 0)
		kmem_free(newpfh.nfs_fh4_val, newpfh.nfs_fh4_len);
	if (cred_otw != NULL)
		crfree(cred_otw);
	if (rootvp != NULL)
		VN_RELE(rootvp);
	if (dvp != NULL)
		VN_RELE(dvp);
	if (osp != NULL)
		open_stream_rele(osp, rp);
}

/*
 * Client-side failover support: remap the filehandle for vp if it appears
 * necessary.  errors are returned via the nfs4_error_t parameter; though,
 * if there is a problem, we will just try again later.
 */

void
nfs4_check_remap(mntinfo4_t *mi, vnode_t *vp, int flags, nfs4_error_t *ep)
{
	if (vp == NULL)
		return;

	if (!(vp->v_vfsp->vfs_flag & VFS_RDONLY))
		return;

	if (VTOR4(vp)->r_server == mi->mi_curr_serv)
		return;

	nfs4_remap_file(mi, vp, flags, ep);
}

/*
 * nfs4_make_dotdot() - find or create a parent vnode of a non-root node.
 *
 * Our caller has a filehandle for ".." relative to a particular
 * directory object.  We want to find or create a parent vnode
 * with that filehandle and return it.  We can of course create
 * a vnode from this filehandle, but we need to also make sure
 * that if ".." is a regular file (i.e. dvp is a V_XATTRDIR)
 * that we have a parent FH for future reopens as well.  If
 * we have a remap failure, we won't be able to reopen this
 * file, but we won't treat that as fatal because a reopen
 * is at least unlikely.  Someday nfs4_reopen() should look
 * for a missing parent FH and try a remap to recover from it.
 *
 * need_start_op argument indicates whether this function should
 * do a start_op before calling remap_lookup().  This should
 * be FALSE, if you are the recovery thread or in an op; otherwise,
 * set it to TRUE.
 */
int
nfs4_make_dotdot(nfs4_sharedfh_t *fhp, hrtime_t t, vnode_t *dvp,
    cred_t *cr, vnode_t **vpp, int need_start_op)
{
	mntinfo4_t *mi = VTOMI4(dvp);
	nfs4_fname_t *np = NULL, *pnp = NULL;
	vnode_t *vp = NULL, *rootvp = NULL;
	rnode4_t *rp;
	nfs_fh4 newfh = {0, NULL}, newpfh = {0, NULL};
	nfs4_ga_res_t gar, pgar;
	vattr_t va, pva;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	nfs4_sharedfh_t *sfh = NULL, *psfh = NULL;
	nfs4_recov_state_t recov_state;

#ifdef DEBUG
	/*
	 * ensure need_start_op is correct
	 */
	{
		int no_need_start_op = (tsd_get(nfs4_tsd_key) ||
		    (curthread == mi->mi_recovthread));
		/* C needs a ^^ operator! */
		ASSERT(((need_start_op) && (!no_need_start_op)) ||
		    ((! need_start_op) && (no_need_start_op)));
	}
#endif
	ASSERT(VTOMI4(dvp)->mi_zone == nfs_zone());

	NFS4_DEBUG(nfs4_client_shadow_debug, (CE_NOTE,
	    "nfs4_make_dotdot: called with fhp %p, dvp %s", (void *)fhp,
	    rnode4info(VTOR4(dvp))));

	/*
	 * rootvp might be needed eventually. Holding it now will
	 * ensure that r4find_unlocked() will find it, if ".." is the root.
	 */
	e.error = VFS_ROOT(mi->mi_vfsp, &rootvp);
	if (e.error != 0)
		goto out;
	rp = r4find_unlocked(fhp, mi->mi_vfsp);
	if (rp != NULL) {
		*vpp = RTOV4(rp);
		VN_RELE(rootvp);
		return (0);
	}

	/*
	 * Since we don't have the rnode, we have to go over the wire.
	 * remap_lookup() can get all of the filehandles and attributes
	 * we need in one operation.
	 */
	np = fn_parent(VTOSV(dvp)->sv_name);
	/* if a parent was not found return an error */
	if (np == NULL) {
		e.error = ENOENT;
		goto out;
	}

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;
recov_retry:
	if (need_start_op) {
		e.error = nfs4_start_fop(mi, rootvp, NULL, OH_LOOKUP,
		    &recov_state, NULL);
		if (e.error != 0) {
			goto out;
		}
	}

	pgar.n4g_va.va_type = VNON;
	gar.n4g_va.va_type = VNON;

	remap_lookup(np, rootvp, RML_ORDINARY, cr,
	    &newfh, &gar, &newpfh, &pgar, &e);
	if (nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp)) {
		if (need_start_op) {
			bool_t abort;

			abort = nfs4_start_recovery(&e, mi,
			    rootvp, NULL, NULL, NULL, OP_LOOKUP, NULL, NULL,
			    NULL);
			if (abort) {
				nfs4_end_fop(mi, rootvp, NULL, OH_LOOKUP,
				    &recov_state, FALSE);
				if (e.error == 0)
					e.error = EIO;
				goto out;
			}
			nfs4_end_fop(mi, rootvp, NULL, OH_LOOKUP,
			    &recov_state, TRUE);
			goto recov_retry;
		}
		if (e.error == 0)
			e.error = EIO;
		goto out;
	}

	va = gar.n4g_va;
	pva = pgar.n4g_va;

	if ((e.error != 0) ||
	    (va.va_type != VDIR)) {
		if (need_start_op)
			nfs4_end_fop(mi, rootvp, NULL, OH_LOOKUP,
			    &recov_state, FALSE);
		if (e.error == 0)
			e.error = EIO;
		goto out;
	}

	if (e.stat != NFS4_OK) {
		if (need_start_op)
			nfs4_end_fop(mi, rootvp, NULL, OH_LOOKUP,
			    &recov_state, FALSE);
		e.error = EIO;
		goto out;
	}

	/*
	 * It is possible for remap_lookup() to return with no error,
	 * but without providing the parent filehandle and attrs.
	 */
	if (pva.va_type != VDIR) {
		/*
		 * Call remap_lookup() again, this time with the
		 * newpfh and pgar args in the first position.
		 */
		pnp = fn_parent(np);
		if (pnp != NULL) {
			remap_lookup(pnp, rootvp, RML_ORDINARY, cr,
			    &newpfh, &pgar, NULL, NULL, &e);
			/*
			 * This remap_lookup call modifies pgar. The following
			 * line prevents trouble when checking the va_type of
			 * pva later in this code.
			 */
			pva = pgar.n4g_va;

			if (nfs4_needs_recovery(&e, FALSE,
			    mi->mi_vfsp)) {
				if (need_start_op) {
					bool_t abort;

					abort = nfs4_start_recovery(&e, mi,
					    rootvp, NULL, NULL, NULL,
					    OP_LOOKUP, NULL, NULL, NULL);
					if (abort) {
						nfs4_end_fop(mi, rootvp, NULL,
						    OH_LOOKUP, &recov_state,
						    FALSE);
						if (e.error == 0)
							e.error = EIO;
						goto out;
					}
					nfs4_end_fop(mi, rootvp, NULL,
					    OH_LOOKUP, &recov_state, TRUE);
					goto recov_retry;
				}
				if (e.error == 0)
					e.error = EIO;
				goto out;
			}

			if (e.stat != NFS4_OK) {
				if (need_start_op)
					nfs4_end_fop(mi, rootvp, NULL,
					    OH_LOOKUP, &recov_state, FALSE);
				e.error = EIO;
				goto out;
			}
		}
		if ((pnp == NULL) ||
		    (e.error != 0) ||
		    (pva.va_type == VNON)) {
			if (need_start_op)
				nfs4_end_fop(mi, rootvp, NULL, OH_LOOKUP,
				    &recov_state, FALSE);
			if (e.error == 0)
				e.error = EIO;
			goto out;
		}
	}
	ASSERT(newpfh.nfs_fh4_len != 0);
	if (need_start_op)
		nfs4_end_fop(mi, rootvp, NULL, OH_LOOKUP, &recov_state, FALSE);
	psfh = sfh4_get(&newpfh, mi);

	sfh = sfh4_get(&newfh, mi);
	vp = makenfs4node_by_fh(sfh, psfh, &np, &gar, mi, cr, t);

out:
	if (np != NULL)
		fn_rele(&np);
	if (pnp != NULL)
		fn_rele(&pnp);
	if (newfh.nfs_fh4_len != 0)
		kmem_free(newfh.nfs_fh4_val, newfh.nfs_fh4_len);
	if (newpfh.nfs_fh4_len != 0)
		kmem_free(newpfh.nfs_fh4_val, newpfh.nfs_fh4_len);
	if (sfh != NULL)
		sfh4_rele(&sfh);
	if (psfh != NULL)
		sfh4_rele(&psfh);
	if (rootvp != NULL)
		VN_RELE(rootvp);
	*vpp = vp;
	return (e.error);
}

#ifdef DEBUG
size_t r_path_memuse = 0;
#endif

/*
 * NFS client failover support
 *
 * sv4_free() frees the malloc'd portion of a "servinfo_t".
 */
void
sv4_free(servinfo4_t *svp)
{
	servinfo4_t *next;
	struct knetconfig *knconf;

	while (svp != NULL) {
		next = svp->sv_next;
		if (svp->sv_dhsec)
			sec_clnt_freeinfo(svp->sv_dhsec);
		if (svp->sv_secdata)
			sec_clnt_freeinfo(svp->sv_secdata);
		if (svp->sv_save_secinfo &&
		    svp->sv_save_secinfo != svp->sv_secinfo)
			secinfo_free(svp->sv_save_secinfo);
		if (svp->sv_secinfo)
			secinfo_free(svp->sv_secinfo);
		if (svp->sv_hostname && svp->sv_hostnamelen > 0)
			kmem_free(svp->sv_hostname, svp->sv_hostnamelen);
		knconf = svp->sv_knconf;
		if (knconf != NULL) {
			if (knconf->knc_protofmly != NULL)
				kmem_free(knconf->knc_protofmly, KNC_STRSIZE);
			if (knconf->knc_proto != NULL)
				kmem_free(knconf->knc_proto, KNC_STRSIZE);
			kmem_free(knconf, sizeof (*knconf));
		}
		knconf = svp->sv_origknconf;
		if (knconf != NULL) {
			if (knconf->knc_protofmly != NULL)
				kmem_free(knconf->knc_protofmly, KNC_STRSIZE);
			if (knconf->knc_proto != NULL)
				kmem_free(knconf->knc_proto, KNC_STRSIZE);
			kmem_free(knconf, sizeof (*knconf));
		}
		if (svp->sv_addr.buf != NULL && svp->sv_addr.maxlen != 0)
			kmem_free(svp->sv_addr.buf, svp->sv_addr.maxlen);
		if (svp->sv_path != NULL) {
			kmem_free(svp->sv_path, svp->sv_pathlen);
		}
		nfs_rw_destroy(&svp->sv_lock);
		kmem_free(svp, sizeof (*svp));
		svp = next;
	}
}

void
nfs4_printfhandle(nfs4_fhandle_t *fhp)
{
	int *ip;
	char *buf;
	size_t bufsize;
	char *cp;

	/*
	 * 13 == "(file handle:"
	 * maximum of NFS_FHANDLE / sizeof (*ip) elements in fh_buf times
	 *	1 == ' '
	 *	8 == maximum strlen of "%x"
	 * 3 == ")\n\0"
	 */
	bufsize = 13 + ((NFS_FHANDLE_LEN / sizeof (*ip)) * (1 + 8)) + 3;
	buf = kmem_alloc(bufsize, KM_NOSLEEP);
	if (buf == NULL)
		return;

	cp = buf;
	(void) strcpy(cp, "(file handle:");
	while (*cp != '\0')
		cp++;
	for (ip = (int *)fhp->fh_buf;
	    ip < (int *)&fhp->fh_buf[fhp->fh_len];
	    ip++) {
		(void) sprintf(cp, " %x", *ip);
		while (*cp != '\0')
			cp++;
	}
	(void) strcpy(cp, ")\n");

	zcmn_err(getzoneid(), CE_CONT, "%s", buf);

	kmem_free(buf, bufsize);
}

/*
 * The NFSv4 readdir cache subsystem.
 *
 * We provide a set of interfaces to allow the rest of the system to utilize
 * a caching mechanism while encapsulating the details of the actual
 * implementation.  This should allow for better maintainability and
 * extensibility by consolidating the implementation details in one location.
 */

/*
 * Comparator used by AVL routines.
 */
static int
rddir4_cache_compar(const void *x, const void *y)
{
	rddir4_cache_impl *ai = (rddir4_cache_impl *)x;
	rddir4_cache_impl *bi = (rddir4_cache_impl *)y;
	rddir4_cache *a = &ai->rc;
	rddir4_cache *b = &bi->rc;

	if (a->nfs4_cookie == b->nfs4_cookie) {
		if (a->buflen == b->buflen)
			return (0);
		if (a->buflen < b->buflen)
			return (-1);
		return (1);
	}

	if (a->nfs4_cookie < b->nfs4_cookie)
			return (-1);

	return (1);
}

/*
 * Allocate an opaque handle for the readdir cache.
 */
void
rddir4_cache_create(rnode4_t *rp)
{
	ASSERT(rp->r_dir == NULL);

	rp->r_dir = kmem_alloc(sizeof (avl_tree_t), KM_SLEEP);

	avl_create(rp->r_dir, rddir4_cache_compar, sizeof (rddir4_cache_impl),
	    offsetof(rddir4_cache_impl, tree));
}

/*
 *  Purge the cache of all cached readdir responses.
 */
void
rddir4_cache_purge(rnode4_t *rp)
{
	rddir4_cache_impl	*rdip;
	rddir4_cache_impl	*nrdip;

	ASSERT(MUTEX_HELD(&rp->r_statelock));

	if (rp->r_dir == NULL)
		return;

	rdip = avl_first(rp->r_dir);

	while (rdip != NULL) {
		nrdip = AVL_NEXT(rp->r_dir, rdip);
		avl_remove(rp->r_dir, rdip);
		rdip->rc.flags &= ~RDDIRCACHED;
		rddir4_cache_rele(rp, &rdip->rc);
		rdip = nrdip;
	}
	ASSERT(avl_numnodes(rp->r_dir) == 0);
}

/*
 * Destroy the readdir cache.
 */
void
rddir4_cache_destroy(rnode4_t *rp)
{
	ASSERT(MUTEX_HELD(&rp->r_statelock));
	if (rp->r_dir == NULL)
		return;

	rddir4_cache_purge(rp);
	avl_destroy(rp->r_dir);
	kmem_free(rp->r_dir, sizeof (avl_tree_t));
	rp->r_dir = NULL;
}

/*
 * Locate a readdir response from the readdir cache.
 *
 * Return values:
 *
 * NULL - If there is an unrecoverable situation like the operation may have
 *	  been interrupted.
 *
 * rddir4_cache * - A pointer to a rddir4_cache is returned to the caller.
 *		    The flags are set approprately, such that the caller knows
 *		    what state the entry is in.
 */
rddir4_cache *
rddir4_cache_lookup(rnode4_t *rp, offset_t cookie, int count)
{
	rddir4_cache_impl	*rdip = NULL;
	rddir4_cache_impl	srdip;
	rddir4_cache		*srdc;
	rddir4_cache		*rdc = NULL;
	rddir4_cache		*nrdc = NULL;
	avl_index_t		where;

top:
	ASSERT(nfs_rw_lock_held(&rp->r_rwlock, RW_READER));
	ASSERT(MUTEX_HELD(&rp->r_statelock));
	/*
	 * Check to see if the readdir cache has been disabled.  If so, then
	 * simply allocate an rddir4_cache entry and return it, since caching
	 * operations do not apply.
	 */
	if (rp->r_dir == NULL) {
		if (nrdc == NULL) {
			/*
			 * Drop the lock because we are doing a sleeping
			 * allocation.
			 */
			mutex_exit(&rp->r_statelock);
			rdc = rddir4_cache_alloc(KM_SLEEP);
			rdc->nfs4_cookie = cookie;
			rdc->buflen = count;
			mutex_enter(&rp->r_statelock);
			return (rdc);
		}
		return (nrdc);
	}

	srdc = &srdip.rc;
	srdc->nfs4_cookie = cookie;
	srdc->buflen = count;

	rdip = avl_find(rp->r_dir, &srdip, &where);

	/*
	 * If we didn't find an entry then create one and insert it
	 * into the cache.
	 */
	if (rdip == NULL) {
		/*
		 * Check for the case where we have made a second pass through
		 * the cache due to a lockless allocation.  If we find that no
		 * thread has already inserted this entry, do the insert now
		 * and return.
		 */
		if (nrdc != NULL) {
			avl_insert(rp->r_dir, nrdc->data, where);
			nrdc->flags |= RDDIRCACHED;
			rddir4_cache_hold(nrdc);
			return (nrdc);
		}

#ifdef DEBUG
		nfs4_readdir_cache_misses++;
#endif
		/*
		 * First, try to allocate an entry without sleeping.  If that
		 * fails then drop the lock and do a sleeping allocation.
		 */
		nrdc = rddir4_cache_alloc(KM_NOSLEEP);
		if (nrdc != NULL) {
			nrdc->nfs4_cookie = cookie;
			nrdc->buflen = count;
			avl_insert(rp->r_dir, nrdc->data, where);
			nrdc->flags |= RDDIRCACHED;
			rddir4_cache_hold(nrdc);
			return (nrdc);
		}

		/*
		 * Drop the lock and do a sleeping allocation.	We incur
		 * additional overhead by having to search the cache again,
		 * but this case should be rare.
		 */
		mutex_exit(&rp->r_statelock);
		nrdc = rddir4_cache_alloc(KM_SLEEP);
		nrdc->nfs4_cookie = cookie;
		nrdc->buflen = count;
		mutex_enter(&rp->r_statelock);
		/*
		 * We need to take another pass through the cache
		 * since we dropped our lock to perform the alloc.
		 * Another thread may have come by and inserted the
		 * entry we are interested in.
		 */
		goto top;
	}

	/*
	 * Check to see if we need to free our entry.  This can happen if
	 * another thread came along beat us to the insert.  We can
	 * safely call rddir4_cache_free directly because no other thread
	 * would have a reference to this entry.
	 */
	if (nrdc != NULL)
		rddir4_cache_free((rddir4_cache_impl *)nrdc->data);

#ifdef DEBUG
	nfs4_readdir_cache_hits++;
#endif
	/*
	 * Found something.  Make sure it's ready to return.
	 */
	rdc = &rdip->rc;
	rddir4_cache_hold(rdc);
	/*
	 * If the cache entry is in the process of being filled in, wait
	 * until this completes.  The RDDIRWAIT bit is set to indicate that
	 * someone is waiting and when the thread currently filling the entry
	 * is done, it should do a cv_broadcast to wakeup all of the threads
	 * waiting for it to finish. If the thread wakes up to find that
	 * someone new is now trying to complete the the entry, go back
	 * to sleep.
	 */
	while (rdc->flags & RDDIR) {
		/*
		 * The entry is not complete.
		 */
		nfs_rw_exit(&rp->r_rwlock);
		rdc->flags |= RDDIRWAIT;
#ifdef DEBUG
		nfs4_readdir_cache_waits++;
#endif
		while (rdc->flags & RDDIRWAIT) {
			if (!cv_wait_sig(&rdc->cv, &rp->r_statelock)) {
				/*
				 * We got interrupted, probably the user
				 * typed ^C or an alarm fired.  We free the
				 * new entry if we allocated one.
				 */
				rddir4_cache_rele(rp, rdc);
				mutex_exit(&rp->r_statelock);
				(void) nfs_rw_enter_sig(&rp->r_rwlock,
				    RW_READER, FALSE);
				mutex_enter(&rp->r_statelock);
				return (NULL);
			}
		}
		mutex_exit(&rp->r_statelock);
		(void) nfs_rw_enter_sig(&rp->r_rwlock,
		    RW_READER, FALSE);
		mutex_enter(&rp->r_statelock);
	}

	/*
	 * The entry we were waiting on may have been purged from
	 * the cache and should no longer be used, release it and
	 * start over.
	 */
	if (!(rdc->flags & RDDIRCACHED)) {
		rddir4_cache_rele(rp, rdc);
		goto top;
	}

	/*
	 * The entry is completed.  Return it.
	 */
	return (rdc);
}

/*
 * Allocate a cache element and return it.  Can return NULL if memory is
 * low.
 */
static rddir4_cache *
rddir4_cache_alloc(int flags)
{
	rddir4_cache_impl	*rdip = NULL;
	rddir4_cache		*rc = NULL;

	rdip = kmem_alloc(sizeof (rddir4_cache_impl), flags);

	if (rdip != NULL) {
		rc = &rdip->rc;
		rc->data = (void *)rdip;
		rc->nfs4_cookie = 0;
		rc->nfs4_ncookie = 0;
		rc->entries = NULL;
		rc->eof = 0;
		rc->entlen = 0;
		rc->buflen = 0;
		rc->actlen = 0;
		/*
		 * A readdir is required so set the flag.
		 */
		rc->flags = RDDIRREQ;
		cv_init(&rc->cv, NULL, CV_DEFAULT, NULL);
		rc->error = 0;
		mutex_init(&rdip->lock, NULL, MUTEX_DEFAULT, NULL);
		rdip->count = 1;
#ifdef DEBUG
		atomic_inc_64(&clstat4_debug.dirent.value.ui64);
#endif
	}
	return (rc);
}

/*
 * Increment the reference count to this cache element.
 */
static void
rddir4_cache_hold(rddir4_cache *rc)
{
	rddir4_cache_impl *rdip = (rddir4_cache_impl *)rc->data;

	mutex_enter(&rdip->lock);
	rdip->count++;
	mutex_exit(&rdip->lock);
}

/*
 * Release a reference to this cache element.  If the count is zero then
 * free the element.
 */
void
rddir4_cache_rele(rnode4_t *rp, rddir4_cache *rdc)
{
	rddir4_cache_impl *rdip = (rddir4_cache_impl *)rdc->data;

	ASSERT(MUTEX_HELD(&rp->r_statelock));

	/*
	 * Check to see if we have any waiters.  If so, we can wake them
	 * so that they can proceed.
	 */
	if (rdc->flags & RDDIRWAIT) {
		rdc->flags &= ~RDDIRWAIT;
		cv_broadcast(&rdc->cv);
	}

	mutex_enter(&rdip->lock);
	ASSERT(rdip->count > 0);
	if (--rdip->count == 0) {
		mutex_exit(&rdip->lock);
		rddir4_cache_free(rdip);
	} else
		mutex_exit(&rdip->lock);
}

/*
 * Free a cache element.
 */
static void
rddir4_cache_free(rddir4_cache_impl *rdip)
{
	rddir4_cache *rc = &rdip->rc;

#ifdef DEBUG
	atomic_dec_64(&clstat4_debug.dirent.value.ui64);
#endif
	if (rc->entries != NULL)
		kmem_free(rc->entries, rc->buflen);
	cv_destroy(&rc->cv);
	mutex_destroy(&rdip->lock);
	kmem_free(rdip, sizeof (*rdip));
}

/*
 * Snapshot callback for nfs:0:nfs4_client as registered with the kstat
 * framework.
 */
static int
cl4_snapshot(kstat_t *ksp, void *buf, int rw)
{
	ksp->ks_snaptime = gethrtime();
	if (rw == KSTAT_WRITE) {
		bcopy(buf, ksp->ks_private, sizeof (clstat4_tmpl));
#ifdef DEBUG
		/*
		 * Currently only the global zone can write to kstats, but we
		 * add the check just for paranoia.
		 */
		if (INGLOBALZONE(curproc))
			bcopy((char *)buf + sizeof (clstat4_tmpl),
			    &clstat4_debug, sizeof (clstat4_debug));
#endif
	} else {
		bcopy(ksp->ks_private, buf, sizeof (clstat4_tmpl));
#ifdef DEBUG
		/*
		 * If we're displaying the "global" debug kstat values, we
		 * display them as-is to all zones since in fact they apply to
		 * the system as a whole.
		 */
		bcopy(&clstat4_debug, (char *)buf + sizeof (clstat4_tmpl),
		    sizeof (clstat4_debug));
#endif
	}
	return (0);
}



/*
 * Zone support
 */
static void *
clinit4_zone(zoneid_t zoneid)
{
	kstat_t *nfs4_client_kstat;
	struct nfs4_clnt *nfscl;
	uint_t ndata;

	nfscl = kmem_alloc(sizeof (*nfscl), KM_SLEEP);
	mutex_init(&nfscl->nfscl_chtable4_lock, NULL, MUTEX_DEFAULT, NULL);
	nfscl->nfscl_chtable4 = NULL;
	nfscl->nfscl_zoneid = zoneid;

	bcopy(&clstat4_tmpl, &nfscl->nfscl_stat, sizeof (clstat4_tmpl));
	ndata = sizeof (clstat4_tmpl) / sizeof (kstat_named_t);
#ifdef DEBUG
	ndata += sizeof (clstat4_debug) / sizeof (kstat_named_t);
#endif
	if ((nfs4_client_kstat = kstat_create_zone("nfs", 0, "nfs4_client",
	    "misc", KSTAT_TYPE_NAMED, ndata,
	    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE, zoneid)) != NULL) {
		nfs4_client_kstat->ks_private = &nfscl->nfscl_stat;
		nfs4_client_kstat->ks_snapshot = cl4_snapshot;
		kstat_install(nfs4_client_kstat);
	}
	mutex_enter(&nfs4_clnt_list_lock);
	list_insert_head(&nfs4_clnt_list, nfscl);
	mutex_exit(&nfs4_clnt_list_lock);

	return (nfscl);
}

/*ARGSUSED*/
static void
clfini4_zone(zoneid_t zoneid, void *arg)
{
	struct nfs4_clnt *nfscl = arg;
	chhead_t *chp, *next;

	if (nfscl == NULL)
		return;
	mutex_enter(&nfs4_clnt_list_lock);
	list_remove(&nfs4_clnt_list, nfscl);
	mutex_exit(&nfs4_clnt_list_lock);
	clreclaim4_zone(nfscl, 0);
	for (chp = nfscl->nfscl_chtable4; chp != NULL; chp = next) {
		ASSERT(chp->ch_list == NULL);
		kmem_free(chp->ch_protofmly, strlen(chp->ch_protofmly) + 1);
		next = chp->ch_next;
		kmem_free(chp, sizeof (*chp));
	}
	kstat_delete_byname_zone("nfs", 0, "nfs4_client", zoneid);
	mutex_destroy(&nfscl->nfscl_chtable4_lock);
	kmem_free(nfscl, sizeof (*nfscl));
}

/*
 * Called by endpnt_destructor to make sure the client handles are
 * cleaned up before the RPC endpoints.  This becomes a no-op if
 * clfini_zone (above) is called first.  This function is needed
 * (rather than relying on clfini_zone to clean up) because the ZSD
 * callbacks have no ordering mechanism, so we have no way to ensure
 * that clfini_zone is called before endpnt_destructor.
 */
void
clcleanup4_zone(zoneid_t zoneid)
{
	struct nfs4_clnt *nfscl;

	mutex_enter(&nfs4_clnt_list_lock);
	nfscl = list_head(&nfs4_clnt_list);
	for (; nfscl != NULL; nfscl = list_next(&nfs4_clnt_list, nfscl)) {
		if (nfscl->nfscl_zoneid == zoneid) {
			clreclaim4_zone(nfscl, 0);
			break;
		}
	}
	mutex_exit(&nfs4_clnt_list_lock);
}

int
nfs4_subr_init(void)
{
	/*
	 * Allocate and initialize the client handle cache
	 */
	chtab4_cache = kmem_cache_create("client_handle4_cache",
	    sizeof (struct chtab), 0, NULL, NULL, clreclaim4, NULL,
	    NULL, 0);

	/*
	 * Initialize the list of per-zone client handles (and associated data).
	 * This needs to be done before we call zone_key_create().
	 */
	list_create(&nfs4_clnt_list, sizeof (struct nfs4_clnt),
	    offsetof(struct nfs4_clnt, nfscl_node));

	/*
	 * Initialize the zone_key for per-zone client handle lists.
	 */
	zone_key_create(&nfs4clnt_zone_key, clinit4_zone, NULL, clfini4_zone);

	if (nfs4err_delay_time == 0)
		nfs4err_delay_time = NFS4ERR_DELAY_TIME;

	return (0);
}

int
nfs4_subr_fini(void)
{
	/*
	 * Deallocate the client handle cache
	 */
	kmem_cache_destroy(chtab4_cache);

	/*
	 * Destroy the zone_key
	 */
	(void) zone_key_delete(nfs4clnt_zone_key);

	return (0);
}
/*
 * Set or Clear direct I/O flag
 * VOP_RWLOCK() is held for write access to prevent a race condition
 * which would occur if a process is in the middle of a write when
 * directio flag gets set. It is possible that all pages may not get flushed.
 *
 * This is a copy of nfs_directio, changes here may need to be made
 * there and vice versa.
 */

int
nfs4_directio(vnode_t *vp, int cmd, cred_t *cr)
{
	int	error = 0;
	rnode4_t *rp;

	rp = VTOR4(vp);

	if (cmd == DIRECTIO_ON) {

		if (rp->r_flags & R4DIRECTIO)
			return (0);

		/*
		 * Flush the page cache.
		 */

		(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);

		if (rp->r_flags & R4DIRECTIO) {
			VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
			return (0);
		}

		if (nfs4_has_pages(vp) &&
		    ((rp->r_flags & R4DIRTY) || rp->r_awcount > 0)) {
			error = VOP_PUTPAGE(vp, (offset_t)0, (uint_t)0,
			    B_INVAL, cr, NULL);
			if (error) {
				if (error == ENOSPC || error == EDQUOT) {
					mutex_enter(&rp->r_statelock);
					if (!rp->r_error)
						rp->r_error = error;
					mutex_exit(&rp->r_statelock);
				}
				VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
				return (error);
			}
		}

		mutex_enter(&rp->r_statelock);
		rp->r_flags |= R4DIRECTIO;
		mutex_exit(&rp->r_statelock);
		VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);
		return (0);
	}

	if (cmd == DIRECTIO_OFF) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags &= ~R4DIRECTIO;	/* disable direct mode */
		mutex_exit(&rp->r_statelock);
		return (0);
	}

	return (EINVAL);
}

/*
 * Return TRUE if the file has any pages.  Always go back to
 * the master vnode to check v_pages since none of the shadows
 * can have pages.
 */

bool_t
nfs4_has_pages(vnode_t *vp)
{
	rnode4_t *rp;

	rp = VTOR4(vp);
	if (IS_SHADOW(vp, rp))
		vp = RTOV4(rp);	/* RTOV4 always gives the master */

	return (vn_has_cached_data(vp));
}

/*
 * This table is used to determine whether the client should attempt
 * failover based on the clnt_stat value returned by CLNT_CALL.  The
 * clnt_stat is used as an index into the table.  If
 * the error value that corresponds to the clnt_stat value in the
 * table is non-zero, then that is the error to be returned AND
 * that signals that failover should be attempted.
 *
 * Special note: If the RPC_ values change, then direct indexing of the
 * table is no longer valid, but having the RPC_ values in the table
 * allow the functions to detect the change and issue a warning.
 * In this case, the code will always attempt failover as a defensive
 * measure.
 */

static struct try_failover_tab {
	enum clnt_stat	cstat;
	int		error;
} try_failover_table [] = {

	RPC_SUCCESS,		0,
	RPC_CANTENCODEARGS,	0,
	RPC_CANTDECODERES,	0,
	RPC_CANTSEND,		ECOMM,
	RPC_CANTRECV,		ECOMM,
	RPC_TIMEDOUT,		ETIMEDOUT,
	RPC_VERSMISMATCH,	0,
	RPC_AUTHERROR,		0,
	RPC_PROGUNAVAIL,	0,
	RPC_PROGVERSMISMATCH,	0,
	RPC_PROCUNAVAIL,	0,
	RPC_CANTDECODEARGS,	0,
	RPC_SYSTEMERROR,	ENOSR,
	RPC_UNKNOWNHOST,	EHOSTUNREACH,
	RPC_RPCBFAILURE,	ENETUNREACH,
	RPC_PROGNOTREGISTERED,	ECONNREFUSED,
	RPC_FAILED,		ETIMEDOUT,
	RPC_UNKNOWNPROTO,	EHOSTUNREACH,
	RPC_INTR,		0,
	RPC_UNKNOWNADDR,	EHOSTUNREACH,
	RPC_TLIERROR,		0,
	RPC_NOBROADCAST,	EHOSTUNREACH,
	RPC_N2AXLATEFAILURE,	ECONNREFUSED,
	RPC_UDERROR,		0,
	RPC_INPROGRESS,		0,
	RPC_STALERACHANDLE,	EINVAL,
	RPC_CANTCONNECT,	ECONNREFUSED,
	RPC_XPRTFAILED,		ECONNABORTED,
	RPC_CANTCREATESTREAM,	ECONNREFUSED,
	RPC_CANTSTORE,		ENOBUFS
};

/*
 * nfs4_try_failover - determine whether the client should
 * attempt failover based on the values stored in the nfs4_error_t.
 */
int
nfs4_try_failover(nfs4_error_t *ep)
{
	if (ep->error == ETIMEDOUT || ep->stat == NFS4ERR_RESOURCE)
		return (TRUE);

	if (ep->error && ep->rpc_status != RPC_SUCCESS)
		return (try_failover(ep->rpc_status) != 0 ? TRUE : FALSE);

	return (FALSE);
}

/*
 * try_failover - internal version of nfs4_try_failover, called
 * only by rfscall and aclcall.  Determine if failover is warranted
 * based on the clnt_stat and return the error number if it is.
 */
static int
try_failover(enum clnt_stat rpc_status)
{
	int err = 0;

	if (rpc_status == RPC_SUCCESS)
		return (0);

#ifdef	DEBUG
	if (rpc_status != 0 && nfs4_try_failover_any) {
		err = ETIMEDOUT;
		goto done;
	}
#endif
	/*
	 * The rpc status is used as an index into the table.
	 * If the rpc status is outside of the range of the
	 * table or if the rpc error numbers have been changed
	 * since the table was constructed, then print a warning
	 * (DEBUG only) and try failover anyway.  Otherwise, just
	 * grab the resulting error number out of the table.
	 */
	if (rpc_status < RPC_SUCCESS || rpc_status >=
	    sizeof (try_failover_table)/sizeof (try_failover_table[0]) ||
	    try_failover_table[rpc_status].cstat != rpc_status) {

		err = ETIMEDOUT;
#ifdef	DEBUG
		cmn_err(CE_NOTE, "try_failover: unexpected rpc error %d",
		    rpc_status);
#endif
	} else
		err = try_failover_table[rpc_status].error;

done:
	if (rpc_status)
		NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
		    "nfs4_try_failover: %strying failover on error %d",
		    err ? "" : "NOT ", rpc_status));

	return (err);
}

void
nfs4_error_zinit(nfs4_error_t *ep)
{
	ep->error = 0;
	ep->stat = NFS4_OK;
	ep->rpc_status = RPC_SUCCESS;
}

void
nfs4_error_init(nfs4_error_t *ep, int error)
{
	ep->error = error;
	ep->stat = NFS4_OK;
	ep->rpc_status = RPC_SUCCESS;
}


#ifdef DEBUG

/*
 * Return a 16-bit hash for filehandle, stateid, clientid, owner.
 * use the same algorithm as for NFS v3.
 *
 */
int
hash16(void *p, int len)
{
	int i, rem;
	uint_t *wp;
	uint_t key = 0;

	/* protect against non word aligned */
	if ((rem = len & 3) != 0)
		len &= ~3;

	for (i = 0, wp = (uint_t *)p; i < len; i += 4, wp++) {
		key ^= (*wp >> 16) ^ *wp;
	}

	/* hash left-over bytes */
	for (i = 0; i < rem; i++)
		key ^= *((uchar_t *)p + i);

	return (key & 0xffff);
}

/*
 * rnode4info - return filehandle and path information for an rnode.
 * XXX MT issues: uses a single static buffer, no locking of path.
 */
char *
rnode4info(rnode4_t *rp)
{
	static char buf[80];
	nfs4_fhandle_t fhandle;
	char *path;
	char *type;

	if (rp == NULL)
		return ("null");
	if (rp->r_flags & R4ISXATTR)
		type = "attr";
	else if (RTOV4(rp)->v_flag & V_XATTRDIR)
		type = "attrdir";
	else if (RTOV4(rp)->v_flag & VROOT)
		type = "root";
	else if (RTOV4(rp)->v_type == VDIR)
		type = "dir";
	else if (RTOV4(rp)->v_type == VREG)
		type = "file";
	else
		type = "other";
	sfh4_copyval(rp->r_fh, &fhandle);
	path = fn_path(rp->r_svnode.sv_name);
	(void) snprintf(buf, 80, "$%p[%s], type=%s, flags=%04X, FH=%04X\n",
	    (void *)rp, path, type, rp->r_flags,
	    hash16((void *)&fhandle.fh_buf, fhandle.fh_len));
	kmem_free(path, strlen(path)+1);
	return (buf);
}
#endif
