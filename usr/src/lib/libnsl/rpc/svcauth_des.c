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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * svcauth_des.c, server-side des authentication
 *
 * We insure for the service the following:
 * (1) The timestamp microseconds do not exceed 1 million.
 * (2) The timestamp plus the window is less than the current time.
 * (3) The timestamp is not less than the one previously
 *	seen in the current session.
 *
 * It is up to the server to determine if the window size is
 * too small.
 *
 */

#include "mt.h"
#include "rpc_mt.h"
#include <assert.h>
#include <rpc/des_crypt.h>
#include <rpc/rpc.h>
#include <sys/types.h>
#include <sys/param.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>

#include <syslog.h>

extern int key_decryptsession_pk(const char *, netobj *, des_block *);

#define	USEC_PER_SEC	((ulong_t)1000000L)
#define	BEFORE(t1, t2) timercmp(t1, t2, < /* EMPTY */)


/*
 * LRU cache of conversation keys and some other useful items.
 */
#define	DEF_AUTHDES_CACHESZ 128
int authdes_cachesz = DEF_AUTHDES_CACHESZ;
struct cache_entry {
	des_block key;			/* conversation key */
	char *rname;			/* client's name */
	uint_t window;			/* credential lifetime window */
	struct timeval laststamp;	/* detect replays of creds */
	char *localcred;		/* generic local credential */
	int index;			/* where are we in array? */
	struct cache_entry *prev;	/* prev entry on LRU list */
	struct cache_entry *next;	/* next entry on LRU list */
};

static const char __getucredstr[] = "authdes_getucred:";

static struct cache_entry *_rpc_authdes_cache;	/* [authdes_cachesz] */
static struct cache_entry *cache_head;	/* cache (in LRU order) */
static struct cache_entry *cache_tail;	/* cache (in LRU order) */

/*
 *	A rwlock_t would seem to make more sense, but it turns out we always
 *	muck with the cache entries, so would always need a write lock (in
 *	which case, we might as well use a mutex).
 */
extern mutex_t	authdes_lock;


static int cache_init(void);		/* initialize the cache */
					/* find an entry in the cache */
static int cache_spot(des_block *, char *, struct timeval *);
static void cache_ref(uint32_t);	/* note that sid was ref'd */
static void invalidate(char *);		/* invalidate entry in cache */
static void __msgout(int, const char *, const char *);
static void __msgout2(const char *, const char *);

/*
 * cache statistics
 */
struct {
	ulong_t ncachehits;	/* times cache hit, and is not replay */
	ulong_t ncachereplays;	/* times cache hit, and is replay */
	ulong_t ncachemisses;	/* times cache missed */
} svcauthdes_stats;

/*
 * Service side authenticator for AUTH_DES
 */
enum auth_stat
__svcauth_des(struct svc_req *rqst, struct rpc_msg *msg)
{
	int32_t		*ixdr;
	des_block	cryptbuf[2];
	struct authdes_cred	*cred;
	struct authdes_verf	verf;
	int	status;
	struct cache_entry	*entry;
	uint32_t sid;
	int cache_spot_id;
	des_block	*sessionkey, init_sessionkey;
	des_block	ivec;
	uint_t	window;
	struct timeval	timestamp;
	uint32_t	namelen;
	struct area {
		struct authdes_cred area_cred;
		char area_netname[MAXNETNAMELEN+1];
	} *area;
	int	fullname_rcvd = 0;
	int from_cache = 0;

	(void) mutex_lock(&authdes_lock);
	if (_rpc_authdes_cache == NULL) {
		int ret = cache_init();
		if (ret == -1) {
			(void) mutex_unlock(&authdes_lock);
			return (AUTH_FAILED);
		}
	}
	(void) mutex_unlock(&authdes_lock);

	/* LINTED pointer cast */
	area = (struct area *)rqst->rq_clntcred;
	cred = (struct authdes_cred *)&area->area_cred;

	if ((uint_t)msg->rm_call.cb_cred.oa_length == 0)
		return (AUTH_BADCRED);
	/*
	 * Get the credential
	 */
	/* LINTED pointer cast */
	ixdr = (int32_t *)msg->rm_call.cb_cred.oa_base;
	cred->adc_namekind = IXDR_GET_ENUM(ixdr, enum authdes_namekind);
	switch (cred->adc_namekind) {
	case ADN_FULLNAME:
		namelen = IXDR_GET_U_INT32(ixdr);
		if (namelen > MAXNETNAMELEN)
			return (AUTH_BADCRED);
		cred->adc_fullname.name = area->area_netname;
		(void) memcpy(cred->adc_fullname.name, ixdr, (uint_t)namelen);
		cred->adc_fullname.name[namelen] = 0;
		ixdr += (RNDUP(namelen) / BYTES_PER_XDR_UNIT);
		cred->adc_fullname.key.key.high = (uint32_t)*ixdr++;
		cred->adc_fullname.key.key.low = (uint32_t)*ixdr++;
		cred->adc_fullname.window = (uint32_t)*ixdr++;
		fullname_rcvd++;
		break;
	case ADN_NICKNAME:
		cred->adc_nickname = (uint32_t)*ixdr++;
		break;
	default:
		return (AUTH_BADCRED);
	}

	if ((uint_t)msg->rm_call.cb_verf.oa_length == 0)
		return (AUTH_BADVERF);
	/*
	 * Get the verifier
	 */
	/* LINTED pointer cast */
	ixdr = (int32_t *)msg->rm_call.cb_verf.oa_base;
	verf.adv_xtimestamp.key.high = (uint32_t)*ixdr++;
	verf.adv_xtimestamp.key.low = (uint32_t)*ixdr++;
	verf.adv_int_u = (uint32_t)*ixdr++;

	(void) mutex_lock(&authdes_lock);

	/*
	 * Get the conversation key
	 */
	if (fullname_rcvd) {	/* ADN_FULLNAME */
		netobj	pkey;
		char	pkey_data[1024];

again:
		init_sessionkey = cred->adc_fullname.key;
		sessionkey = &init_sessionkey;

		if (!__getpublickey_cached(cred->adc_fullname.name,
				pkey_data, &from_cache)) {
			/*
			 * if the user has no public key, treat them as the
			 * unauthenticated identity - nobody. If this
			 * works, it means the client didn't find the
			 * user's keys and used nobody's secret key
			 * as a backup.
			 */
			if (!__getpublickey_cached("nobody",
						pkey_data, &from_cache)) {
				__msgout(LOG_INFO,
				"_svcauth_des: no public key for nobody or ",
				cred->adc_fullname.name);
				(void) mutex_unlock(&authdes_lock);
				return (AUTH_BADCRED); /* no key */
			}

			/*
			 * found a public key for nobody. change
			 * the fullname id to nobody, so the caller
			 * thinks the client specified nobody
			 * as the user identity.
			 */
			(void) strcpy(cred->adc_fullname.name, "nobody");
		}
		pkey.n_bytes = pkey_data;
		pkey.n_len = strlen(pkey_data) + 1;
		if (key_decryptsession_pk(cred->adc_fullname.name, &pkey,
				sessionkey) < 0) {
			if (from_cache) {
				__getpublickey_flush(cred->adc_fullname.name);
				goto again;
			}
			__msgout(LOG_INFO,
			    "_svcauth_des: key_decryptsessionkey failed for",
			    cred->adc_fullname.name);
			(void) mutex_unlock(&authdes_lock);
			return (AUTH_BADCRED);	/* key not found */
		}
	} else { /* ADN_NICKNAME */
		sid = cred->adc_nickname;
		if (sid >= authdes_cachesz) {
			__msgout(LOG_INFO, "_svcauth_des:", "bad nickname");
			(void) mutex_unlock(&authdes_lock);
			return (AUTH_BADCRED);	/* garbled credential */
		}
		/* actually check that the entry is not null */
		entry = &_rpc_authdes_cache[sid];
		if (entry->rname == NULL) {
			(void) mutex_unlock(&authdes_lock);
			return (AUTH_BADCRED);	/* cached out */
		}
		sessionkey = &_rpc_authdes_cache[sid].key;
	}

	/*
	 * Decrypt the timestamp
	 */
	cryptbuf[0] = verf.adv_xtimestamp;
	if (fullname_rcvd) {	/* ADN_FULLNAME */
		cryptbuf[1].key.high = cred->adc_fullname.window;
		cryptbuf[1].key.low = verf.adv_winverf;
		ivec.key.high = ivec.key.low = 0;
		status = cbc_crypt((char *)sessionkey, (char *)cryptbuf,
			2 * (int)sizeof (des_block), DES_DECRYPT | DES_HW,
			(char *)&ivec);
	} else {
		status = ecb_crypt((char *)sessionkey, (char *)cryptbuf,
			(int)sizeof (des_block), DES_DECRYPT | DES_HW);
	}
	if (DES_FAILED(status)) {
		if (fullname_rcvd && from_cache) {
			__getpublickey_flush(cred->adc_fullname.name);
			goto again;
		}
		__msgout(LOG_ERR, "_svcauth_des: DES decryption failure for",
			fullname_rcvd ? cred->adc_fullname.name :
			_rpc_authdes_cache[sid].rname);
		(void) mutex_unlock(&authdes_lock);
		return (AUTH_FAILED);	/* system error */
	}

	/*
	 * XDR the decrypted timestamp
	 */
	ixdr = (int32_t *)cryptbuf;
	timestamp.tv_sec = IXDR_GET_INT32(ixdr);
	timestamp.tv_usec = IXDR_GET_INT32(ixdr);

	/*
	 * Check for valid credentials and verifiers.
	 * They could be invalid because the key was flushed
	 * out of the cache, and so a new session should begin.
	 * Be sure and send AUTH_REJECTED{CRED, VERF} if this is the case.
	 */
	{
		struct timeval current;
		int	nick;
		int	winverf;

		if (fullname_rcvd) {
			window = IXDR_GET_U_INT32(ixdr);
			winverf = IXDR_GET_U_INT32(ixdr);
			if (winverf != window - 1) {
				if (from_cache) {
					__getpublickey_flush(
						cred->adc_fullname.name);
					goto again;
				}
				__msgout(LOG_INFO,
					"_svcauth_des: corrupted window from",
					cred->adc_fullname.name);
				(void) mutex_unlock(&authdes_lock);
				/* garbled credential or invalid secret key */
				return (AUTH_BADCRED);
			}
			cache_spot_id = cache_spot(sessionkey,
						cred->adc_fullname.name,

					&timestamp);
			if (cache_spot_id < 0) {
			__msgout(LOG_INFO,
				"_svcauth_des: replayed credential from",
				cred->adc_fullname.name);
				(void) mutex_unlock(&authdes_lock);
				return (AUTH_REJECTEDCRED);	/* replay */
			} else sid = cache_spot_id;
			nick = 0;
		} else {	/* ADN_NICKNAME */
			window = _rpc_authdes_cache[sid].window;
			nick = 1;
		}

		if ((ulong_t)timestamp.tv_usec >= USEC_PER_SEC) {
			if (fullname_rcvd && from_cache) {
				__getpublickey_flush(cred->adc_fullname.name);
				goto again;
			}
		__msgout(LOG_INFO,
			"_svcauth_des: invalid timestamp received from",
			fullname_rcvd ? cred->adc_fullname.name :
				_rpc_authdes_cache[sid].rname);
			/* cached out (bad key), or garbled verifier */
			(void) mutex_unlock(&authdes_lock);
			return (nick ? AUTH_REJECTEDVERF : AUTH_BADVERF);
		}
		if (nick && BEFORE(&timestamp,
				&_rpc_authdes_cache[sid].laststamp)) {
			if (fullname_rcvd && from_cache) {
				__getpublickey_flush(cred->adc_fullname.name);
				goto again;
			}
			__msgout(LOG_INFO,
	"_svcauth_des: timestamp is earlier than the one previously seen from",
			fullname_rcvd ? cred->adc_fullname.name :
				_rpc_authdes_cache[sid].rname);
			(void) mutex_unlock(&authdes_lock);
			return (AUTH_REJECTEDVERF);	/* replay */
		}
		(void) gettimeofday(&current, NULL);
		current.tv_sec -= window;	/* allow for expiration */
		if (!BEFORE(&current, &timestamp)) {
			if (fullname_rcvd && from_cache) {
				__getpublickey_flush(cred->adc_fullname.name);
				goto again;
			}
			__msgout(LOG_INFO,
				"_svcauth_des: timestamp expired for",
				fullname_rcvd ? cred->adc_fullname.name :
					_rpc_authdes_cache[sid].rname);
			/* replay, or garbled credential */
			(void) mutex_unlock(&authdes_lock);
			return (nick ? AUTH_REJECTEDVERF : AUTH_BADCRED);
		}
	}

	/*
	 * Set up the reply verifier
	 */
	verf.adv_nickname = sid;

	/*
	 * xdr the timestamp before encrypting
	 */
	ixdr = (int32_t *)cryptbuf;
	IXDR_PUT_INT32(ixdr, timestamp.tv_sec - 1);
	IXDR_PUT_INT32(ixdr, timestamp.tv_usec);

	/*
	 * encrypt the timestamp
	 */
	status = ecb_crypt((char *)sessionkey, (char *)cryptbuf,
				(int)sizeof (des_block), DES_ENCRYPT | DES_HW);
	if (DES_FAILED(status)) {
		__msgout(LOG_ERR, "_svcauth_des: DES encryption failure for",
			fullname_rcvd ? cred->adc_fullname.name :
			_rpc_authdes_cache[sid].rname);
		(void) mutex_unlock(&authdes_lock);
		return (AUTH_FAILED);	/* system error */
	}
	verf.adv_xtimestamp = cryptbuf[0];

	/*
	 * Serialize the reply verifier, and update rqst
	 */
	/* LINTED pointer cast */
	ixdr = (int32_t *)msg->rm_call.cb_verf.oa_base;
	*ixdr++ = (int32_t)verf.adv_xtimestamp.key.high;
	*ixdr++ = (int32_t)verf.adv_xtimestamp.key.low;
	*ixdr++ = (int32_t)verf.adv_int_u;

	rqst->rq_xprt->xp_verf.oa_flavor = AUTH_DES;
	rqst->rq_xprt->xp_verf.oa_base = msg->rm_call.cb_verf.oa_base;
	rqst->rq_xprt->xp_verf.oa_length =
		(char *)ixdr - msg->rm_call.cb_verf.oa_base;
	if (rqst->rq_xprt->xp_verf.oa_length > MAX_AUTH_BYTES) {
		__msgout(LOG_ERR,
			"_svcauth_des: Authenticator length error",
			fullname_rcvd ? cred->adc_fullname.name :
			_rpc_authdes_cache[sid].rname);
		(void) mutex_unlock(&authdes_lock);
		return (AUTH_REJECTEDVERF);
	}

	/*
	 * We succeeded, commit the data to the cache now and
	 * finish cooking the credential.
	 */
	entry = &_rpc_authdes_cache[sid];
	entry->laststamp = timestamp;
	cache_ref(sid);
	if (cred->adc_namekind == ADN_FULLNAME) {
		cred->adc_fullname.window = window;
		cred->adc_nickname = sid;	/* save nickname */
		if (entry->rname != NULL)
			free(entry->rname);
		entry->rname = malloc(strlen(cred->adc_fullname.name) + 1);
		if (entry->rname != NULL) {
			(void) strcpy(entry->rname, cred->adc_fullname.name);
		} else {
			__msgout(LOG_CRIT, "_svcauth_des:", "out of memory");
			(void) mutex_unlock(&authdes_lock);
			return (AUTH_FAILED);
		}
		entry->key = *sessionkey;
		entry->window = window;
		/* mark any cached cred invalid */
		invalidate(entry->localcred);
	} else { /* ADN_NICKNAME */
		/*
		 * nicknames are cooked into fullnames
		 */
		cred->adc_namekind = ADN_FULLNAME;
		cred->adc_fullname.name = entry->rname;
		cred->adc_fullname.key = entry->key;
		cred->adc_fullname.window = entry->window;
	}
	(void) mutex_unlock(&authdes_lock);
	return (AUTH_OK);	/* we made it! */
}


/*
 * Initialize the cache
 */
static int
cache_init(void)
{
	int i;

/* LOCK HELD ON ENTRY: authdes_lock */

	assert(MUTEX_HELD(&authdes_lock));
	_rpc_authdes_cache =
		malloc(sizeof (struct cache_entry) * authdes_cachesz);
	if (_rpc_authdes_cache == NULL) {
		__msgout(LOG_CRIT, "cache_init:", "out of memory");
		return (-1);
	}
	(void) memset(_rpc_authdes_cache, 0,
		sizeof (struct cache_entry) * authdes_cachesz);

	/*
	 * Initialize the lru chain (linked-list)
	 */
	for (i = 1; i < (authdes_cachesz - 1); i++) {
		_rpc_authdes_cache[i].index = i;
		_rpc_authdes_cache[i].next = &_rpc_authdes_cache[i + 1];
		_rpc_authdes_cache[i].prev = &_rpc_authdes_cache[i - 1];
	}
	cache_head = &_rpc_authdes_cache[0];
	cache_tail = &_rpc_authdes_cache[authdes_cachesz - 1];

	/*
	 * These elements of the chain need special attention...
	 */
	cache_head->index = 0;
	cache_tail->index = authdes_cachesz - 1;
	cache_head->next = &_rpc_authdes_cache[1];
	cache_head->prev = cache_tail;
	cache_tail->next = cache_head;
	cache_tail->prev = &_rpc_authdes_cache[authdes_cachesz - 2];
	return (0);
}


/*
 * Find the lru victim
 */
static uint32_t
cache_victim(void)
{
/* LOCK HELD ON ENTRY: authdes_lock */

	assert(MUTEX_HELD(&authdes_lock));
	return (cache_head->index);			/* list in lru order */
}

/*
 * Note that sid was referenced
 */
static void
cache_ref(uint32_t sid)
{
	struct cache_entry *curr = &_rpc_authdes_cache[sid];


/* LOCK HELD ON ENTRY: authdes_lock */

	assert(MUTEX_HELD(&authdes_lock));

	/*
	 * move referenced item from its place on the LRU chain
	 * to the tail of the chain while checking for special
	 * conditions (mainly for performance).
	 */
	if (cache_tail == curr) {			/* no work to do */
		/*EMPTY*/;
	} else if (cache_head == curr) {
		cache_head = cache_head->next;
		cache_tail = curr;
	} else {
		(curr->next)->prev = curr->prev;	/* fix thy neighbor */
		(curr->prev)->next = curr->next;
		curr->next = cache_head;		/* fix thy self... */
		curr->prev = cache_tail;
		cache_head->prev = curr;		/* fix the head  */
		cache_tail->next = curr;		/* fix the tail  */
		cache_tail = curr;			/* move the tail */
	}
}

/*
 * Find a spot in the cache for a credential containing
 * the items given. Return -1 if a replay is detected, otherwise
 * return the spot in the cache.
 */
static int
cache_spot(des_block *key, char *name, struct timeval *timestamp)
{
	struct cache_entry *cp;
	int i;
	uint32_t hi;

/* LOCK HELD ON ENTRY: authdes_lock */

	assert(MUTEX_HELD(&authdes_lock));
	hi = key->key.high;
	for (cp = _rpc_authdes_cache, i = 0; i < authdes_cachesz; i++, cp++) {
		if (cp->key.key.high == hi &&
		    cp->key.key.low == key->key.low &&
		    cp->rname != NULL &&
		    memcmp(cp->rname, name, strlen(name) + 1) == 0) {
			if (BEFORE(timestamp, &cp->laststamp)) {
				svcauthdes_stats.ncachereplays++;
				return (-1);	/* replay */
			}
			svcauthdes_stats.ncachehits++;
			return (i);
			/* refresh */
		}
	}
	svcauthdes_stats.ncachemisses++;
	return (cache_victim());
}


/*
 * Local credential handling stuff.
 * NOTE: bsd unix dependent.
 * Other operating systems should put something else here.
 */
#define	UNKNOWN 	-2	/* grouplen, if cached cred is unknown user */
#define	INVALID		-1 	/* grouplen, if cache entry is invalid */

struct bsdcred {
	uid_t uid;		/* cached uid */
	gid_t gid;		/* cached gid */
	short grouplen;	/* length of cached groups */
	gid_t groups[1];	/* cached groups allocate _SC_NGROUPS_MAX */
};

static void
invalidate(char *cred)
{
	if (cred == NULL)
		return;
	/* LINTED pointer cast */
	((struct bsdcred *)cred)->grouplen = INVALID;
}

/*
 * Map a des credential into a unix cred.
 * We cache the credential here so the application does
 * not have to make an rpc call every time to interpret
 * the credential.
 */
int
authdes_getucred(const struct authdes_cred *adc, uid_t *uid, gid_t *gid,
    short *grouplen, gid_t *groups)
{
	uint32_t sid;
	int i;
	uid_t i_uid;
	gid_t i_gid;
	int i_grouplen;
	struct bsdcred *cred;

	sid = adc->adc_nickname;
	if (sid >= authdes_cachesz) {
		__msgout2(__getucredstr, "invalid nickname");
		return (0);
	}
	(void) mutex_lock(&authdes_lock);
	/* LINTED pointer cast */
	cred = (struct bsdcred *)_rpc_authdes_cache[sid].localcred;
	if (cred == NULL) {
		static size_t bsdcred_sz;

		if (bsdcred_sz == 0) {
			bsdcred_sz = sizeof (struct bsdcred) +
			    (sysconf(_SC_NGROUPS_MAX) - 1) * sizeof (gid_t);
		}
		cred = malloc(bsdcred_sz);
		if (cred == NULL) {
			__msgout2(__getucredstr, "out of memory");
			(void) mutex_unlock(&authdes_lock);
			return (0);
		}
		_rpc_authdes_cache[sid].localcred = (char *)cred;
		cred->grouplen = INVALID;
	}
	if (cred->grouplen == INVALID) {
		/*
		 * not in cache: lookup
		 */
		if (!netname2user(adc->adc_fullname.name, (uid_t *)&i_uid,
			(gid_t *)&i_gid, &i_grouplen, (gid_t *)groups)) {
			__msgout2(__getucredstr, "unknown netname");
			/* mark as lookup up, but not found */
			cred->grouplen = UNKNOWN;
			(void) mutex_unlock(&authdes_lock);
			return (0);
		}
		__msgout2(__getucredstr, "missed ucred cache");
		*uid = cred->uid = i_uid;
		*gid = cred->gid = i_gid;
		*grouplen = cred->grouplen = i_grouplen;
		for (i = i_grouplen - 1; i >= 0; i--) {
			cred->groups[i] = groups[i];
		}
		(void) mutex_unlock(&authdes_lock);
		return (1);
	}
	if (cred->grouplen == UNKNOWN) {
		/*
		 * Already lookup up, but no match found
		 */
		(void) mutex_unlock(&authdes_lock);
		return (0);
	}

	/*
	 * cached credentials
	 */
	*uid = cred->uid;
	*gid = cred->gid;
	*grouplen = cred->grouplen;
	for (i = cred->grouplen - 1; i >= 0; i--) {
		groups[i] = cred->groups[i];
	}
	(void) mutex_unlock(&authdes_lock);
	return (1);
}


static void
__msgout(int level, const char *str, const char *strarg)
{
	(void) syslog(level, "%s %s", str, strarg);
}


static void
__msgout2(const char *str, const char *str2)
{
	(void) syslog(LOG_DEBUG, "%s %s", str, str2);
}
