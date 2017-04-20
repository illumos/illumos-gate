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
 * Copyright 2017 Joyent Inc
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
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
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/tiuser.h>
#include <sys/tihdr.h>
#include <sys/t_kuser.h>
#include <sys/t_lock.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/auth_des.h>
#include <rpc/rpc_msg.h>
#include <rpc/svc.h>
#include <rpc/svc_auth.h>
#include <rpc/clnt.h>
#include <rpc/des_crypt.h>

#define	USEC_PER_SEC 1000000
#define	BEFORE(t1, t2) timercmp(t1, t2, < /* COMMENT HERE TO DEFEAT CSTYLE */)

/*
 * Cache of conversation keys and some other useful items.
 * The hash table size is controled via authdes_cachesz variable.
 * The authdes_cachesz has to be the power of 2.
 */
#define	AUTHDES_CACHE_TABLE_SZ 1024
static int authdes_cachesz = AUTHDES_CACHE_TABLE_SZ;
#define	HASH(key) ((key) & (authdes_cachesz - 1))

/* low water mark for the number of cache entries */
static int low_cache_entries = 128;

struct authdes_cache_entry {
	uint32_t nickname;		/* nick name id */
	uint32_t window;		/* credential lifetime window */
	des_block key;			/* conversation key */
	time_t	ref_time;		/* time referenced previously */
	char *rname;			/* client's name */
	caddr_t localcred;		/* generic local credential */
	struct authdes_cache_entry *prev, *next;  /* hash table linked list */
	struct authdes_cache_entry *lru_prev, *lru_next; /* LRU linked list */
	kmutex_t lock;			/* cache entry lock */
};
static struct authdes_cache_entry **authdes_cache; /* [authdes_cachesz] */
static struct authdes_cache_entry *lru_first = NULL;
static struct authdes_cache_entry *lru_last = NULL;
static kmutex_t authdes_lock;		/* cache table lock */

static struct kmem_cache *authdes_cache_handle;
static uint32_t	Nickname = 0;

static struct authdes_cache_entry *authdes_cache_new(char *,
					des_block *, uint32_t);
static struct authdes_cache_entry *authdes_cache_get(uint32_t);
static void authdes_cache_reclaim(void *);
static void sweep_cache();

/*
 * After 12 hours, check and delete cache entries that have been
 * idled for more than 10 hours.
 */
static time_t authdes_sweep_interval = 12*60*60;
static time_t authdes_cache_time = 10*60*60;
static time_t authdes_last_swept = 0;

/*
 * cache statistics
 */
static int authdes_ncache = 0; /* number of current cached entries */
static int authdes_ncachehits = 0; /* #times cache hit */
static int authdes_ncachemisses = 0; /* #times cache missed */

#define	NOT_DEAD(ptr)   ASSERT((((intptr_t)(ptr)) != 0xdeadbeef))
#define	IS_ALIGNED(ptr) ASSERT((((intptr_t)(ptr)) & 3) == 0)

/*
 * Service side authenticator for AUTH_DES
 */
enum auth_stat
_svcauth_des(struct svc_req *rqst, struct rpc_msg *msg)
{
	int32_t *ixdr;
	des_block cryptbuf[2];
	struct authdes_cred *cred;
	struct authdes_verf verf;
	int status;
	des_block *sessionkey;
	des_block ivec;
	uint32_t window, winverf, namelen;
	bool_t nick;
	struct timeval timestamp, current_time;
	struct authdes_cache_entry *nick_entry;
	struct area {
		struct authdes_cred area_cred;
		char area_netname[MAXNETNAMELEN+1];
	} *area;
	timestruc_t now;

	mutex_enter(&authdes_lock);
	if (authdes_cache == NULL) {
		authdes_cache = kmem_zalloc(
			sizeof (struct authdes_cache_entry *) * authdes_cachesz,
			KM_SLEEP);
	}
	mutex_exit(&authdes_lock);

	CTASSERT(sizeof (struct area) <= RQCRED_SIZE);
	/* LINTED pointer alignment */
	area = (struct area *)rqst->rq_clntcred;
	cred = (struct authdes_cred *)&area->area_cred;

	/*
	 * Get the credential
	 */
	/* LINTED pointer alignment */
	ixdr = (int32_t *)msg->rm_call.cb_cred.oa_base;
	cred->adc_namekind = IXDR_GET_ENUM(ixdr, enum authdes_namekind);
	switch (cred->adc_namekind) {
	case ADN_FULLNAME:
		namelen = IXDR_GET_U_INT32(ixdr);
		if (namelen > MAXNETNAMELEN)
			return (AUTH_BADCRED);
		cred->adc_fullname.name = area->area_netname;
		bcopy(ixdr, cred->adc_fullname.name, namelen);
		cred->adc_fullname.name[namelen] = 0;
		ixdr += (RNDUP(namelen) / BYTES_PER_XDR_UNIT);
		cred->adc_fullname.key.key.high = (uint32_t)*ixdr++;
		cred->adc_fullname.key.key.low = (uint32_t)*ixdr++;
		cred->adc_fullname.window = (uint32_t)*ixdr++;
		nick = FALSE;
		break;
	case ADN_NICKNAME:
		cred->adc_nickname = (uint32_t)*ixdr++;
		nick = TRUE;
		break;
	default:
		return (AUTH_BADCRED);
	}

	/*
	 * Get the verifier
	 */
	/* LINTED pointer alignment */
	ixdr = (int32_t *)msg->rm_call.cb_verf.oa_base;
	verf.adv_xtimestamp.key.high = (uint32_t)*ixdr++;
	verf.adv_xtimestamp.key.low =  (uint32_t)*ixdr++;
	verf.adv_int_u = (uint32_t)*ixdr++;


	/*
	 * Get the conversation key
	 */
	if (!nick) { /* ADN_FULLNAME */
		sessionkey = &cred->adc_fullname.key;
		if (key_decryptsession(cred->adc_fullname.name, sessionkey) !=
		    RPC_SUCCESS) {
		    return (AUTH_BADCRED); /* key not found */
		}
	} else { /* ADN_NICKNAME */
		mutex_enter(&authdes_lock);
		if (!(nick_entry = authdes_cache_get(cred->adc_nickname))) {
		    RPCLOG(1, "_svcauth_des: nickname %d not in the cache\n",
						cred->adc_nickname);
		    mutex_exit(&authdes_lock);
		    return (AUTH_BADCRED);	/* need refresh */
		}
		sessionkey = &nick_entry->key;
		mutex_enter(&nick_entry->lock);
		mutex_exit(&authdes_lock);
	}

	/*
	 * Decrypt the timestamp
	 */
	cryptbuf[0] = verf.adv_xtimestamp;
	if (!nick) { /* ADN_FULLNAME */
		cryptbuf[1].key.high = cred->adc_fullname.window;
		cryptbuf[1].key.low = verf.adv_winverf;
		ivec.key.high = ivec.key.low = 0;
		status = cbc_crypt((char *)sessionkey, (char *)cryptbuf,
		    2 * sizeof (des_block), DES_DECRYPT, (char *)&ivec);
	} else { /* ADN_NICKNAME */
		status = ecb_crypt((char *)sessionkey, (char *)cryptbuf,
		    sizeof (des_block), DES_DECRYPT);
	}
	if (DES_FAILED(status)) {
		RPCLOG0(1, "_svcauth_des: decryption failure\n");
		if (nick) {
			mutex_exit(&nick_entry->lock);
		}
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
	if (!nick) { /* ADN_FULLNAME */
		window = IXDR_GET_U_INT32(ixdr);
		winverf = IXDR_GET_U_INT32(ixdr);
		if (winverf != window - 1) {
			RPCLOG(1, "_svcauth_des: window verifier mismatch %d\n",
				winverf);
			return (AUTH_BADCRED);	/* garbled credential */
		}
	} else { /* ADN_NICKNAME */
		window = nick_entry->window;
	}

	if (timestamp.tv_usec >= USEC_PER_SEC) {
		RPCLOG(1, "_svcauth_des: invalid usecs %ld\n",
					timestamp.tv_usec);
		/* cached out (bad key), or garbled verifier */
		if (nick) {
			mutex_exit(&nick_entry->lock);
		}
		return (nick ? AUTH_REJECTEDVERF : AUTH_BADVERF);
	}

	gethrestime(&now);
	current_time.tv_sec = now.tv_sec;
	current_time.tv_usec = now.tv_nsec / 1000;

	current_time.tv_sec -= window;	/* allow for expiration */
	if (!BEFORE(&current_time, &timestamp)) {
		RPCLOG0(1, "_svcauth_des: timestamp expired\n");
		/* replay, or garbled credential */
		if (nick) {
			mutex_exit(&nick_entry->lock);
		}
		return (nick ? AUTH_REJECTEDVERF : AUTH_BADCRED);
	}

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
	    sizeof (des_block), DES_ENCRYPT);
	if (DES_FAILED(status)) {
		RPCLOG0(1, "_svcauth_des: encryption failure\n");
		if (nick) {
			mutex_exit(&nick_entry->lock);
		}
		return (AUTH_FAILED);	/* system error */
	}
	verf.adv_xtimestamp = cryptbuf[0];

	/*
	 * If a ADN_FULLNAME, create a new nickname cache entry.
	 */
	if (!nick) {
	    mutex_enter(&authdes_lock);
	    if (!(nick_entry = authdes_cache_new(cred->adc_fullname.name,
					sessionkey, window))) {
		RPCLOG0(1, "_svcauth_des: can not create new cache entry\n");
		mutex_exit(&authdes_lock);
		return (AUTH_FAILED);
	    }
	    mutex_enter(&nick_entry->lock);
	    mutex_exit(&authdes_lock);
	}
	verf.adv_nickname = nick_entry->nickname;

	/*
	 * Serialize the reply verifier, and update rqst
	 */
	/* LINTED pointer alignment */
	ixdr = (int32_t *)msg->rm_call.cb_verf.oa_base;
	*ixdr++ = (int32_t)verf.adv_xtimestamp.key.high;
	*ixdr++ = (int32_t)verf.adv_xtimestamp.key.low;
	*ixdr++ = (int32_t)verf.adv_int_u;

	rqst->rq_xprt->xp_verf.oa_flavor = AUTH_DES;
	rqst->rq_xprt->xp_verf.oa_base = msg->rm_call.cb_verf.oa_base;
	rqst->rq_xprt->xp_verf.oa_length =
	    (uint_t)((char *)ixdr - msg->rm_call.cb_verf.oa_base);
	if (rqst->rq_xprt->xp_verf.oa_length > MAX_AUTH_BYTES) {
		RPCLOG0(1, "_svcauth_des: invalid oa length\n");
		mutex_exit(&nick_entry->lock);
		return (AUTH_BADVERF);
	}

	/*
	 * We succeeded and finish cooking the credential.
	 * nicknames are cooked into fullnames
	 */
	if (!nick) {
		cred->adc_nickname = nick_entry->nickname;
		cred->adc_fullname.window = window;
	} else { /* ADN_NICKNAME */
		cred->adc_namekind = ADN_FULLNAME;
		cred->adc_fullname.name = nick_entry->rname;
		cred->adc_fullname.key = nick_entry->key;
		cred->adc_fullname.window = nick_entry->window;
	}
	mutex_exit(&nick_entry->lock);

	/*
	 * For every authdes_sweep_interval, delete cache entries that have been
	 * idled for authdes_cache_time.
	 */
	mutex_enter(&authdes_lock);
	if ((gethrestime_sec() - authdes_last_swept) > authdes_sweep_interval)
		sweep_cache();

	mutex_exit(&authdes_lock);

	return (AUTH_OK);	/* we made it! */
}

/*
 * Initialization upon loading the rpcsec module.
 */
void
svcauthdes_init(void)
{
	mutex_init(&authdes_lock, NULL, MUTEX_DEFAULT, NULL);
	/*
	 * Allocate des cache handle
	 */
	authdes_cache_handle = kmem_cache_create("authdes_cache_handle",
			sizeof (struct authdes_cache_entry), 0, NULL, NULL,
			authdes_cache_reclaim, NULL, NULL, 0);
}

/*
 * Final actions upon exiting the rpcsec module.
 */
void
svcauthdes_fini(void)
{
	mutex_destroy(&authdes_lock);
	kmem_cache_destroy(authdes_cache_handle);
}

/*
 * Local credential handling stuff.
 * NOTE: bsd unix dependent.
 * Other operating systems should put something else here.
 */

struct bsdcred {
	uid_t uid;		/* cached uid */
	gid_t gid;		/* cached gid */
	short valid;		/* valid creds */
	short grouplen;	/* length of cached groups */
	gid_t groups[1];	/* cached groups - allocate ngroups_max */
};

/*
 * Map a des credential into a unix cred.
 * We cache the credential here so the application does
 * not have to make an rpc call every time to interpret
 * the credential.
 */
int
kauthdes_getucred(const struct authdes_cred *adc, cred_t *cr)
{
	uid_t i_uid;
	gid_t i_gid;
	int i_grouplen;
	struct bsdcred *cred;
	struct authdes_cache_entry *nickentry;

	mutex_enter(&authdes_lock);
	if (!(nickentry = authdes_cache_get(adc->adc_nickname))) {
		RPCLOG0(1, "authdes_getucred:  invalid nickname\n");
		mutex_exit(&authdes_lock);
		return (0);
	}

	mutex_enter(&nickentry->lock);
	mutex_exit(&authdes_lock);
	/* LINTED pointer alignment */
	cred = (struct bsdcred *)nickentry->localcred;
	if (!cred->valid) {
		/*
		 * not in cache: lookup
		 */
		if (netname2user(adc->adc_fullname.name, &i_uid, &i_gid,
		    &i_grouplen, &cred->groups[0]) != RPC_SUCCESS) {
			/*
			 * Probably a host principal, since at this
			 * point we have valid keys. Note that later
			 * if the principal is not in the root list
			 * for NFS, we will be mapped to that exported
			 * file system's anonymous user, typically
			 * NOBODY. keyserv KEY_GETCRED will fail for a
			 * root-netnames so we assume root here.
			 * Currently NFS is the only caller of this
			 * routine. If other RPC services call this
			 * routine, it is up to that service to
			 * differentiate between local and remote
			 * roots.
			 */
			i_uid = 0;
			i_gid = 0;
			i_grouplen = 0;
		}
		RPCLOG0(2, "authdes_getucred:  missed ucred cache\n");
		cred->uid = i_uid;
		cred->gid = i_gid;
		cred->grouplen = (short)i_grouplen;
		cred->valid = 1;
	}

	/*
	 * cached credentials
	 */
	if (crsetugid(cr, cred->uid, cred->gid) != 0 ||
	    crsetgroups(cr, cred->grouplen, &cred->groups[0]) != 0) {
		mutex_exit(&nickentry->lock);
		return (0);
	}
	mutex_exit(&nickentry->lock);
	return (1);
}

/*
 * Create a new cache_entry and put it in authdes_cache table.
 * Caller should have already locked the authdes_cache table.
 */
struct authdes_cache_entry *
authdes_cache_new(char *fullname, des_block *sessionkey, uint32_t window) {

	struct authdes_cache_entry *new, *head;
	struct bsdcred *ucred;
	int index;

	if (!(new = kmem_cache_alloc(authdes_cache_handle, KM_SLEEP))) {
		return (NULL);
	}

	if (!(new->rname = kmem_alloc(strlen(fullname) + 1, KM_NOSLEEP))) {
		kmem_cache_free(authdes_cache_handle, new);
		return (NULL);
	}

	if (!(ucred = kmem_alloc(sizeof (struct bsdcred) +
	    (ngroups_max - 1) * sizeof (gid_t), KM_NOSLEEP))) {
		kmem_free(new->rname, strlen(fullname) + 1);
		kmem_cache_free(authdes_cache_handle, new);
		return (NULL);
	}

	(void) strcpy(new->rname, fullname);
	ucred->valid = 0;
	new->localcred = (caddr_t)ucred;
	new->key = *sessionkey;
	new->window = window;
	new->ref_time = gethrestime_sec();
	new->nickname = Nickname++;
	mutex_init(&new->lock, NULL, MUTEX_DEFAULT, NULL);

	/* put new into the hash table */
	index = HASH(new->nickname);
	head = authdes_cache[index];
	if ((new->next = head) != NULL) {
		head->prev = new;
	}
	authdes_cache[index] = new;
	new->prev = NULL;

	/* update the LRU list */
	new->lru_prev = NULL;
	if ((new->lru_next = lru_first) != NULL) {
		lru_first->lru_prev = new;
	} else {
		lru_last = new;
	}
	lru_first = new;

	authdes_ncache++;
	return (new);
}

/*
 * Get an existing cache entry from authdes_cache table.
 * The caller should have locked the authdes_cache table.
 */
struct authdes_cache_entry *
authdes_cache_get(uint32_t nickname) {

	struct authdes_cache_entry *cur = NULL;
	int index = HASH(nickname);

	ASSERT(MUTEX_HELD(&authdes_lock));
	for (cur = authdes_cache[index]; cur; cur = cur->next) {
		if ((cur->nickname == nickname)) {
			/* find it, update the LRU list */
			if (cur != lru_first) {
			    cur->lru_prev->lru_next = cur->lru_next;
			    if (cur->lru_next != NULL) {
				cur->lru_next->lru_prev = cur->lru_prev;
			    } else {
				lru_last = cur->lru_prev;
			    }
			    cur->lru_prev = NULL;
			    cur->lru_next = lru_first;
			    lru_first->lru_prev = cur;
			    lru_first = cur;
			}

			cur->ref_time = gethrestime_sec();
			authdes_ncachehits++;
			return (cur);
		}
	}

	authdes_ncachemisses++;
	return (NULL);
}

/*
 * authdes_cache_reclaim() is called by the kernel memory allocator
 * when memory is low. This routine will reclaim 25% of the least recent
 * used cache entries above the low water mark (low_cache_entries).
 * If the cache entries have already hit the low water mark, it will
 * return 1 cache entry.
 */
/*ARGSUSED*/
void
authdes_cache_reclaim(void *pdata) {
	struct authdes_cache_entry *p;
	int n, i;

	mutex_enter(&authdes_lock);
	n = authdes_ncache - low_cache_entries;
	n = n > 0 ? n/4 : 1;

	for (i = 0; i < n; i++) {
		if ((p = lru_last) == lru_first)
			break;

		/* Update the hash linked list */
		if (p->prev == NULL) {
			authdes_cache[HASH(p->nickname)] = p->next;
		} else {
			p->prev->next = p->next;
		}
		if (p->next != NULL) {
			p->next->prev = p->prev;
		}

		/* update the LRU linked list */
		p->lru_prev->lru_next = NULL;
		lru_last = p->lru_prev;

		kmem_free(p->rname, strlen(p->rname) + 1);
		kmem_free(p->localcred, sizeof (struct bsdcred) +
		    (ngroups_max - 1) * sizeof (gid_t));
		mutex_destroy(&p->lock);
		kmem_cache_free(authdes_cache_handle, p);

		authdes_ncache--;
	}
	mutex_exit(&authdes_lock);
	RPCLOG(4, "_svcauth_des: %d cache entries reclaimed...\n",
				authdes_ncache);
}

/*
 *  Walk through the LRU doubly-linked list and delete the cache
 *  entries that have not been used for more than authdes_cache_time.
 *
 *  Caller should have locked the cache table.
 */
void
sweep_cache() {
	struct authdes_cache_entry *p;

	ASSERT(MUTEX_HELD(&authdes_lock));
	while ((p = lru_last) != lru_first) {
		IS_ALIGNED(p);
		NOT_DEAD(p);

		/*
		 * If the last LRU entry idled less than authdes_cache_time,
		 * we are done with the sweeping.
		 */
		if (p->ref_time + authdes_cache_time > gethrestime_sec())
			break;

		/* update the hash linked list */
		if (p->prev == NULL) {
			authdes_cache[HASH(p->nickname)] = p->next;
		} else {
			p->prev->next = p->next;
		}
		if (p->next != NULL) {
			p->next->prev = p->prev;
		}

		/* update the LRU linked list */
		p->lru_prev->lru_next = NULL;
		lru_last = p->lru_prev;

		kmem_free(p->rname, strlen(p->rname) + 1);
		kmem_free(p->localcred, sizeof (struct bsdcred) +
		    (ngroups_max - 1) * sizeof (gid_t));
		mutex_destroy(&p->lock);
		kmem_cache_free(authdes_cache_handle, p);

		authdes_ncache--;
	}

	authdes_last_swept = gethrestime_sec();
	RPCLOG(4, "_svcauth_des: sweeping cache...#caches left = %d\n",
				authdes_ncache);
}
