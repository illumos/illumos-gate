/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Do the real work of the keyserver.
 * Store secret keys. Compute common keys,
 * and use them to decrypt and encrypt DES keys.
 * Cache the common keys, so the expensive computation is avoided.
 */
#include <stdio.h>
#include <stdlib.h>
#include <mp.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>
#include <rpc/des_crypt.h>
#include <rpcsvc/nis_dhext.h>
#include <sys/errno.h>
#include <string.h>
#include <thread.h>
#include <syslog.h>

#include "debug.h"
#include "keyserv_cache.h"

extern char ROOTKEY[];
extern mechanism_t **mechs;
extern char **cache_options;
extern int *cache_size;
extern int disk_caching;

static MINT *MODULUS;
static int hash_keys();
static keystatus pk_crypt();
static keystatus pk_crypt3();
static int nodefaultkeys = 0;

#define	DES		"des"
#define	DESALIAS	"dh192-0"
#define	DHMECHSTR	"diffie_hellman"
#define	CLASSIC_PK_DH(k, a)	(((k) == 192) && ((a) == 0))

/*
 * Exponential caching management
 */
struct cachekey_list {
	keybuf secret;
	keybuf public;
	des_block deskey;
	struct cachekey_list *next;
};
#define	KEY_HASH_SIZE	256
static struct cachekey_list *g_cachedkeys[KEY_HASH_SIZE];
static rwlock_t g_cachedkeys_lock = DEFAULTRWLOCK;

#ifdef DEBUG
int
test_debug(debug_level level, char *file, int line)
{
	if (level < debugging)
		return (0);
	fprintf(stderr, "file %s,\tline %d :\t", file, line);
	return (1);
}

int
real_debug(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	(void) vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");
	fflush(stderr);
	return (1);
}
#endif /* DEBUG */

struct cacheuid_list {
	uid_t uid;
	int refcnt;
	keybuf3 *secretkey;
	keybuf3 *publickey;
	netnamestr netname;
	des_block key;
	struct cacheuid_list *next;
};

#define	NUMHASHBUCKETS	256
#define	HASH_UID(x) (x & 0xff)

struct mechdata {
	struct cacheuid_list *bucket[NUMHASHBUCKETS];
};

struct psdata {
	struct cachekey3_list *common[NUMHASHBUCKETS];
};

struct mechentry {
	mutex_t mech_lock;
	struct mechdata *mechdata;
	mutex_t ps_lock;
	struct psdata *psdata;
};

/*
 * we don't need to worry about locking for the keylen + algtype
 * sparse array because it is created once and for all during
 * initialization when there are no threads. The mechentry field
 * and everything underneath it needs protection and this is what
 * the *_lock fields are for.
 */
struct algtypelist {
	algtype_t algtype;
	struct algtypelist *next;
	struct mechentry mech;
};

struct keylenlist {
	keylen_t keylen;
	struct algtypelist *ap;
	struct keylenlist *next;
};

#define	KEYSERV_VERSION	"1.0"

static struct mechtable {
	char *version;
	struct keylenlist *kp;
} mechtable = {KEYSERV_VERSION, NULL};

static struct keylenlist **
getkeylen(keylen_t k)
{
	struct keylenlist **kpp;

	debug(KEYSERV_DEBUG1, ("getkeylen key: %d", k));
	for (kpp = &mechtable.kp;
		*kpp != NULL && (*kpp)->keylen != k;
		kpp = &(*kpp)->next)
		debug(KEYSERV_DEBUG0, ("getkeylen failed %x", kpp));
	debug(KEYSERV_DEBUG0, ("getkeylen return: %x", kpp));
	return (kpp);
}

static void
appendkeylist(struct keylenlist **kpp, keylen_t k)
{
	struct keylenlist *kp;

	if (*kpp == NULL) {
		kp = (struct keylenlist *)malloc(sizeof (*kp));
		if (kp == NULL) {
			debug(KEYSERV_INFO, ("appendkeylist : malloc failed"));
			return;
		}
		debug(KEYSERV_DEBUG, ("appendkeylist : %x %x %d", kpp, kp, k));
		kp->keylen = k;
		kp->ap = NULL;
		kp->next = NULL;
		*kpp = kp;
	} else {
		/*EMPTY*/
		/* do nothing; only happens for multiple algtypes */
		debug(KEYSERV_DEBUG0,
			("appendkeylist called for non tail element"));
	}
}

static struct algtypelist **
getalgtype(struct keylenlist **kpp, algtype_t a)
{
	struct algtypelist **app;

	debug(KEYSERV_DEBUG1, ("getalgtype key: %d", a));
	for (app = &(*kpp)->ap;
		*app != NULL && (*app)->algtype != a;
		app = &(*app)->next)
		debug(KEYSERV_DEBUG0, ("getalgtype key: %x", app));
	debug(KEYSERV_DEBUG0, ("getalgtype return: %x", app));
	return (app);
}

static void
appendalgtype(struct algtypelist **app, algtype_t a)
{
	struct algtypelist *ap;

	if (*app == NULL) {
		ap = (struct algtypelist *)malloc(sizeof (*ap));
		if (ap == NULL) {
			debug(KEYSERV_INFO, ("appendalgtype : malloc failed"));
			return;
		}
		debug(KEYSERV_DEBUG, ("appendalgtype : %x %x %d", app, ap, a));
		ap->algtype = a;
		mutex_init(&ap->mech.mech_lock, USYNC_THREAD, NULL);
		mutex_init(&ap->mech.ps_lock, USYNC_THREAD, NULL);
		ap->mech.mechdata = NULL;
		ap->mech.psdata = NULL;
		ap->next = NULL;
		*app = ap;
	} else {
		/*EMPTY*/
		/* don't mind duplicate (keylen,algtype) paris for now. */
		debug(KEYSERV_DEBUG0,
			("appendalgtype called for non tail element"));
	}
}

static struct mechentry *
getmechtype(keylen_t k, algtype_t a)
{
	struct keylenlist **kpp;
	struct algtypelist **app;

	debug(KEYSERV_DEBUG1, ("getmechtype %d %d", k, a));
	kpp = getkeylen(k);
	if (*kpp == NULL) {
		debug(KEYSERV_DEBUG0, ("getmechtype %d not found in keys", k));
		return (0);
	}
	app = getalgtype(kpp, a);
	if (*app == NULL) {
		debug(KEYSERV_DEBUG0, ("getmechtype %d not found in algs", a));
		return (0);
	}
	debug(KEYSERV_DEBUG0, ("getmechtype found %x", app));
	debug(KEYSERV_DEBUG0, ("getmechtype return %x", &(*app)->mech));
	return (&(*app)->mech);
}

static keybuf3 *
getkeybuf3(int k)
{
	keybuf3 *buf;

	debug(KEYSERV_DEBUG, ("getkeybuf3 malloc %d", k));
	buf = (keybuf3 *) malloc(sizeof (*buf));
	if (buf == NULL) {
		debug(KEYSERV_DEBUG, ("getkeybuf3 malloc failed"));
		syslog(LOG_ERR, "file %s line %d: malloc failed",
			__FILE__, __LINE__);
		return (NULL);
	}
	buf->keybuf3_len = k;
	/* XXX special case k==0 */
	if (k == 0) {
		buf->keybuf3_val = NULL;
	} else {
		buf->keybuf3_val = (char *)malloc(k);
		if (buf->keybuf3_val == NULL) {
			debug(KEYSERV_DEBUG, ("getkeybuf3 malloc failed"));
			free(buf);
			syslog(LOG_ERR, "file %s line %d: malloc failed",
				__FILE__, __LINE__);
			return (NULL);
		}
	}
	debug(KEYSERV_DEBUG1, ("getkeybuf3 ret %x", buf));
	return (buf);
}

static void
freekeybuf3(keybuf3 *kp)
{
	debug(KEYSERV_DEBUG1, ("freekeybuf3 %x", kp));
	if (kp == NULL)
		return;
	if (kp->keybuf3_val) {
		/* XXX kp->keybuf3_len != 0? */
		free(kp->keybuf3_val);
	}
	free(kp);
}

static keybuf3 *
cpykeybuf3(keybuf3 *src)
{
	keybuf3 *dst;

	if (src == NULL) {
		return (NULL);
	}
	if ((dst = getkeybuf3(src->keybuf3_len)) == NULL) {
		return (NULL);
	}
	memcpy(dst->keybuf3_val, src->keybuf3_val, src->keybuf3_len);
	debug(KEYSERV_DEBUG0, ("cpykeybuf3 ret %x", dst));
	return (dst);
}

static keybuf3 *
setkeybuf3(char *src, int len)
{
	keybuf3 *dst;

	if ((dst = getkeybuf3(++len)) == NULL) {
		return (NULL);
	}
	memcpy(dst->keybuf3_val, src, len);
	return (dst);
}

static int
cmpkeybuf3(keybuf3 *k1, keybuf3 *k2)
{
	if ((k1 == NULL) || (k2 == NULL)) {
		syslog(LOG_ERR, "cmpkeybuf3: invalid parameter: %x, %x",
			k1, k2);
		return (0);
	}
	if (k1->keybuf3_len != k2->keybuf3_len) {
		return (0);
	}
	return (!memcmp(k1->keybuf3_val, k2->keybuf3_val, k1->keybuf3_len));
}

static int
storekeybuf3(keybuf3 *dst, keybuf3 *src)
{
	keybuf3 *tmp;

	if ((tmp = cpykeybuf3(src)) == NULL) {
		return (0);
	}
	*dst = *tmp;
	free(tmp); /* but not the contents */
	debug(KEYSERV_DEBUG0, ("storekeybuf3 ret %d %x",
		dst->keybuf3_len, dst->keybuf3_val));
	return (1);
}

static deskeyarray *
getdeskeyarray(int k)
{
	deskeyarray *buf;

	debug(KEYSERV_DEBUG, ("getdeskeyarray malloc %d", k));
	buf = (deskeyarray *) malloc(sizeof (*buf));
	if (buf == NULL) {
		debug(KEYSERV_DEBUG, ("getdeskeyarray malloc failed"));
		syslog(LOG_ERR, "file %s line %d: malloc failed",
			__FILE__, __LINE__);
		return (NULL);
	}
	buf->deskeyarray_len = k;
	/* XXX special case k==0 */
	if (k == 0) {
		buf->deskeyarray_val = NULL;
	} else {
		buf->deskeyarray_val = (des_block *)
			malloc(k * sizeof (des_block));
		if (buf->deskeyarray_val == NULL) {
			debug(KEYSERV_DEBUG, ("getdeskeyarray malloc failed"));
			free(buf);
			syslog(LOG_ERR, "file %s line %d: malloc failed",
				__FILE__, __LINE__);
			return (NULL);
		}
	}
	debug(KEYSERV_DEBUG1, ("getdeskeyarray ret %x", buf));
	return (buf);
}

static deskeyarray *
cpydeskeyarray(deskeyarray *src)
{
	deskeyarray *dst;

	if (src == NULL) {
		return (NULL);
	}
	if ((dst = getdeskeyarray(src->deskeyarray_len)) == NULL) {
		return (NULL);
	}
	memcpy(dst->deskeyarray_val, src->deskeyarray_val,
		src->deskeyarray_len * sizeof (des_block));
	debug(KEYSERV_DEBUG0, ("cpydeskeyarray ret %x", dst));
	return (dst);
}

static int
storedeskeyarray(deskeyarray *dst, deskeyarray *src)
{
	deskeyarray *tmp;

	if ((tmp = cpydeskeyarray(src)) == NULL) {
		return (0);
	}
	*dst = *tmp;
	free(tmp); /* but not the contents */
	debug(KEYSERV_DEBUG0, ("storedeskeyarray ret %d %x",
		dst->deskeyarray_len, dst->deskeyarray_val));
	return (1);
}

int
setdeskeyarray(deskeyarray *dst, int k)
{
	deskeyarray *tmp;

	if ((tmp = getdeskeyarray(k)) == NULL) {
		return (0);
	}
	*dst = *tmp;
	free(tmp); /* but not the contents */
	debug(KEYSERV_DEBUG0, ("setdeskeyarray ret %d %x",
		dst->deskeyarray_len, dst->deskeyarray_val));
	return (1);
}

static int
cachehit3(keybuf3 *public, keybuf3 *secret, struct cachekey3_list *cp)
{
	return (cmpkeybuf3(public, cp->public) &&
		cmpkeybuf3(secret, cp->secret));
}

static struct cacheuid_list **
mapuid2cache(uid_t uid, struct mechdata *mdp)
{
	struct cacheuid_list **cpp;
	int hash = HASH_UID(uid);

	debug(KEYSERV_DEBUG, ("mapuid2cache %d %d %x", uid, hash, mdp));
	for (cpp = &mdp->bucket[hash];
		*cpp != NULL && (*cpp)->uid != uid;
		cpp = &(*cpp)->next) {
		debug(KEYSERV_DEBUG0, ("mapuid2cache %x", cpp));
	}
	debug(KEYSERV_DEBUG, ("mapuid2cache ret %x", cpp));
	return (cpp);
}

static int
appendsecretkey3(struct mechentry *mp, uid_t uid, setkeyarg3 *skey)
{
	struct mechdata *mdp;
	struct cacheuid_list **cpp, *cp;
	keybuf3 nullkey = {0, NULL};

	debug(KEYSERV_DEBUG, ("appendsecretkey3 %x", mp));
	if ((skey == NULL) || (mp == NULL)) {
		return (0);
	}
	if (skey->key.keybuf3_len == 0) {
		return (0);
	}
	mutex_lock(&mp->mech_lock);
	if ((mdp = mp->mechdata) == NULL) {
		mdp = (struct mechdata *)calloc(1, sizeof (*mdp));
		if (mdp == NULL) {
			mutex_unlock(&mp->mech_lock);
			debug(KEYSERV_INFO,
				("appendsecretkey3 : calloc failed"));
			return (0);
		}
		mp->mechdata = mdp;
	}
	cpp = mapuid2cache(uid, mdp);
	if (*cpp == NULL) {
		cp = (struct cacheuid_list *)malloc(sizeof (*cp));
		if (cp == NULL) {
			mutex_unlock(&mp->mech_lock);
			debug(KEYSERV_INFO,
				("appendsecretkey3 : malloc failed"));
			syslog(LOG_ERR, "file %s line %d: malloc failed",
				__FILE__, __LINE__);
			return (0);
		}
		memset(cp, 0, sizeof (*cp));
		cp->uid = uid;
		*cpp = cp;
	} else {
		cp = *cpp;
	}
	freekeybuf3(cp->secretkey);
	if ((cp->secretkey = cpykeybuf3(&skey->key)) == NULL) {
		mutex_unlock(&mp->mech_lock);
		return (0);
	}
	freekeybuf3(cp->publickey);
	if ((cp->publickey = cpykeybuf3(&nullkey)) == NULL) {
		mutex_unlock(&mp->mech_lock);
		return (0);
	}
	mutex_unlock(&mp->mech_lock);
	return (1);
}

/*
 * Store the vers 3 secretkey for this uid
 */
static int
storesecretkey3(uid_t uid, setkeyarg3 *skey)
{
	struct mechentry *mp;

	if (skey == NULL) {
		return (0);
	}
	if ((mp = getmechtype(skey->keylen, skey->algtype)) == NULL) {
		return (0);
	}
	return (appendsecretkey3(mp, uid, skey));
}

/*
 * Set the vers 3 secretkey key for this uid
 */
keystatus
pk_setkey3(uid_t uid, setkeyarg3 *skey)
{
	if (!storesecretkey3(uid, skey)) {
		return (KEY_SYSTEMERR);
	}
	return (KEY_SUCCESS);
}

/*
 * Set the secretkey key for this uid
 */
keystatus
pk_setkey(uid, skey)
	uid_t uid;
	keybuf skey;
{
	int storesecretkey(uid_t, keybuf);

	if (!storesecretkey(uid, skey)) {
		return (KEY_SYSTEMERR);
	}
	return (KEY_SUCCESS);
}

int
storeotherrootkeys(FILE *fp, char *netname, char *passwd, char *osecret)
{
	des_block master;
	struct keylenlist *kp;
	struct algtypelist *ap;
	keybuf3 *secret;
	setkeyarg3 skey;

	debug(KEYSERV_DEBUG, ("storeotherrootkeys %s %s",
		netname, passwd));
	passwd2des_g(passwd, netname, strlen(netname), &master, FALSE);
	for (kp = mechtable.kp; kp != NULL; kp = kp->next) {
		debug(KEYSERV_DEBUG0,
			("storeotherrootkeys key %d", kp->keylen));
		for (ap = kp->ap; ap != NULL; ap = ap->next) {
			debug(KEYSERV_DEBUG,
				("storeotherrootkeys alg: %d", ap->algtype));
			if ((secret = getkeybuf3(kp->keylen/4+1)) == NULL) {
				return (0);
			}
			debug(KEYSERV_DEBUG,
				("storeotherrootkeys calling getsecretkey_g"));
			if (!getsecretkey_g(netname,
				kp->keylen, ap->algtype,
				secret->keybuf3_val, secret->keybuf3_len,
				passwd)) {
				debug(KEYSERV_INFO,
				("Can't find %s's secret key", netname));
				return (0);
			}
			if (*secret->keybuf3_val == 0) { /* XXX */
				debug(KEYSERV_INFO,
				("Password does not decrypt secret key for %s",
					netname));
				return (0);
			}
			skey.key = *secret;
			free(secret); /* but not the buffer it points to */
			skey.userkey = master;
			skey.keylen = kp->keylen;
			skey.algtype = ap->algtype;
			if (CLASSIC_PK_DH(kp->keylen, ap->algtype)) {
				pk_setkey((uid_t)0, osecret);
				fprintf(fp, "%s\n", osecret);
			}
			if (pk_setkey3(0, &skey) != KEY_SUCCESS) {
				return (0);
			}
			if (!CLASSIC_PK_DH(kp->keylen, ap->algtype)) {
				fprintf(fp, "%s %d\n", skey.key.keybuf3_val,
					ap->algtype);
			}
		}
	}
	return (1);
}

/*
 * prohibit the nobody key on this machine k (the -d flag)
 */
int
pk_nodefaultkeys()
{
	nodefaultkeys = 1;
	return (0);
}

static void
freedisklist(struct cacheuid_list *cp)
{
	if (cp == NULL) {
		return;
	}
	free(cp->netname); /* ok even if this is NULL */
	freekeybuf3(cp->secretkey);
	freekeybuf3(cp->publickey);
}

keystatus
pk_clear3(uid_t uid)
{
	struct keylenlist *kp;
	struct algtypelist *ap;
	struct mechdata *mdp;
	struct cacheuid_list **cpp, *cp;

	debug(KEYSERV_DEBUG, ("pk_clear3 %d", uid));
	for (kp = mechtable.kp; kp != NULL; kp = kp->next) {
		debug(KEYSERV_DEBUG0, ("pk_clear3 key %d", kp->keylen));
		for (ap = kp->ap; ap != NULL; ap = ap->next) {
			debug(KEYSERV_DEBUG0,
				("pk_clear3 alg: %d", ap->algtype));
			mutex_lock(&ap->mech.mech_lock);
			if ((mdp = ap->mech.mechdata) == NULL) {
				mutex_unlock(&ap->mech.mech_lock);
				continue;
			}
			cpp = mapuid2cache(uid, mdp);
			if (*cpp == NULL) {
				mutex_unlock(&ap->mech.mech_lock);
				continue;
			}
			cp = (*cpp)->next;
			freedisklist(*cpp);
			*cpp = cp;
			mutex_unlock(&ap->mech.mech_lock);
		}
	}
	/* XXX clear stuff out of the common key cache as well? */
	/* XXX return success only if something was removed? */
	return (KEY_SUCCESS);
}

/*
 * Set the modulus for all our Diffie-Hellman operations
 */
int
setmodulus(modx)
	char *modx;
{
	MODULUS = mp_xtom(modx);
	return (0);
}

/*
 * Encrypt the key using the public key associated with remote_name and the
 * secret key associated with uid.
 */
keystatus
pk_encrypt(uid, remote_name, remote_key, key)
	uid_t uid;
	char *remote_name;
	netobj	*remote_key;
	des_block *key;
{
	return (pk_crypt(uid, remote_name, remote_key, key, DES_ENCRYPT));
}

/*
 * Encrypt the key using the public key associated with remote_name and the
 * secret key associated with uid using vers 3
 */
keystatus
pk_encrypt3(
	uid_t uid,
	cryptkeyarg3 *arg,
	deskeyarray *key
)
{
	return (pk_crypt3(uid, arg, key, DES_ENCRYPT));
}

/*
 * Decrypt the key using the public key associated with remote_name and the
 * secret key associated with uid.
 */
keystatus
pk_decrypt(uid, remote_name, remote_key, key)
	uid_t uid;
	char *remote_name;
	netobj *remote_key;
	des_block *key;
{
	return (pk_crypt(uid, remote_name, remote_key, key, DES_DECRYPT));
}

/*
 * Decrypt the key using the public key associated with remote_name and the
 * secret key associated with uid using vers 3
 */
keystatus
pk_decrypt3(
	uid_t uid,
	cryptkeyarg3 *arg,
	deskeyarray *key
)
{
	return (pk_crypt3(uid, arg, key, DES_DECRYPT));
}

/*
 * Key storage management
 */

#define	KEY_ONLY 0
#define	KEY_NAME 1
struct secretkey_netname_list {
	uid_t uid;
	key_netstarg keynetdata;
	uchar_t sc_flag;
	struct secretkey_netname_list *next;
};

#define	HASH_UID(x)	(x & 0xff)
static struct secretkey_netname_list *g_secretkey_netname[KEY_HASH_SIZE];
static rwlock_t g_secretkey_netname_lock = DEFAULTRWLOCK;

/*
 * Store the keys and netname for this uid
 */
static int
store_netname(uid, netstore)
	uid_t uid;
	key_netstarg *netstore;
{
	struct secretkey_netname_list *new;
	struct secretkey_netname_list **l;
	int hash = HASH_UID(uid);

	(void) rw_wrlock(&g_secretkey_netname_lock);
	for (l = &g_secretkey_netname[hash]; *l != NULL && (*l)->uid != uid;
			l = &(*l)->next) {
	}
	if (*l == NULL) {
/* LINTED pointer alignment */
		new = (struct secretkey_netname_list *)malloc(sizeof (*new));
		if (new == NULL) {
			(void) rw_unlock(&g_secretkey_netname_lock);
			return (0);
		}
		new->uid = uid;
		new->next = NULL;
		*l = new;
	} else {
		new = *l;
		if (new->keynetdata.st_netname)
			(void) free(new->keynetdata.st_netname);
	}
	memcpy(new->keynetdata.st_priv_key, netstore->st_priv_key,
		HEXKEYBYTES);
	memcpy(new->keynetdata.st_pub_key, netstore->st_pub_key, HEXKEYBYTES);

	if (netstore->st_netname)
		new->keynetdata.st_netname = strdup(netstore->st_netname);
	else
		new->keynetdata.st_netname = (char *)NULL;
	new->sc_flag = KEY_NAME;
	(void) rw_unlock(&g_secretkey_netname_lock);
	return (1);

}

static int
appendnetname3(struct mechentry *mp, uid_t uid, key_netstarg3 *net)
{
	struct mechdata *mdp;
	struct cacheuid_list **cpp, *cp;

	debug(KEYSERV_DEBUG, ("appendnetname3 %x", mp));
	if ((mp == NULL) || (net == NULL)) {
		return (0);
	}
	mutex_lock(&mp->mech_lock);
	if ((mdp = mp->mechdata) == NULL) {
		mdp = (struct mechdata *)calloc(1, sizeof (*mdp));
		if (mdp == NULL) {
			mutex_unlock(&mp->mech_lock);
			debug(KEYSERV_INFO, ("appendnetname3 : calloc failed"));
			return (0);
		}
		mp->mechdata = mdp;
	}
	cpp = mapuid2cache(uid, mdp);
	if (*cpp == NULL) {
		cp = (struct cacheuid_list *)malloc(sizeof (*cp));
		if (cp == NULL) {
			mutex_unlock(&mp->mech_lock);
			debug(KEYSERV_INFO, ("appendnetname3 : malloc failed"));
			syslog(LOG_ERR, "file %s line %d: malloc failed",
				__FILE__, __LINE__);
			return (0);
		}
		memset(cp, 0, sizeof (*cp));
		cp->uid = uid;
		*cpp = cp;
	} else {
		cp = *cpp;
	}
	freekeybuf3(cp->secretkey);
	if ((cp->secretkey = cpykeybuf3(&net->st_priv_key)) == NULL) {
		mutex_unlock(&mp->mech_lock);
		return (0);
	}
	freekeybuf3(cp->publickey);
	if ((cp->publickey = cpykeybuf3(&net->st_pub_key)) == NULL) {
		mutex_unlock(&mp->mech_lock);
		return (0);
	}
	free(cp->netname);
	if (net->st_netname) {
		cp->netname = strdup(net->st_netname);
	} else {
		cp->netname = (char *)NULL;
	}
	mutex_unlock(&mp->mech_lock);
	return (1);
}

keystatus
pk_netput(uid, netstore)
	uid_t uid;
	key_netstarg *netstore;
{

	if (!store_netname(uid, netstore)) {
		return (KEY_SYSTEMERR);
	}
	return (KEY_SUCCESS);
}

/*
 * Store the keys and netname for this uid vers 3
 */
static int
store_netname3(uid_t uid, key_netstarg3 *net)
{
	struct mechentry *mp;
	key_netstarg netstore;

	if (net == NULL) {
		return (0);
	}
	if ((mp = getmechtype(net->keylen, net->algtype)) == NULL) {
		return (0);
	}
	if (uid == 0 && CLASSIC_PK_DH(net->keylen, net->algtype)) {
		memcpy(netstore.st_priv_key, net->st_priv_key.keybuf3_val,
			HEXKEYBYTES);
		memset(netstore.st_pub_key, 0, HEXKEYBYTES);
		netstore.st_netname = net->st_netname;
		if (pk_netput(uid, &netstore) != KEY_SUCCESS) {
			(void) fprintf(stderr,
			"keyserv: could not set root's key and netname.\n");
			return (0);
		}
	}
	return (appendnetname3(mp, uid, net));
}

keystatus
pk_netput3(uid_t uid, key_netstarg3 *netstore)
{

	if (!store_netname3(uid, netstore)) {
		return (KEY_SYSTEMERR);
	}
	return (KEY_SUCCESS);
}

int
addmasterkey(char *master, char *netname, algtype_t algtype)
{
	keybuf3 *secret, *public;
	int bytelen = strlen(master);
	keylen_t keylen = bytelen*4;
	key_netstarg3 tmp;

	if ((secret = setkeybuf3(master, bytelen)) == NULL) {
		return (0);
	}
	if ((public = getkeybuf3(bytelen+1)) == NULL) {
		/* the +1 is mandated by getpublickey_g() */
		return (0);
	}
	/*
	 * getpublickey_g(netname, keylen, algtype,
	 *  public->keybuf3_val, public->keybuf3_len);
	 * cannot be called since rpc.nisd is not up yet
	 * so we continue to return a zero filled public key
	 * as in the earlier version
	 */
	memset(public->keybuf3_val, 0, bytelen+1);
	tmp.st_priv_key = *secret;
	free(secret);
	tmp.st_pub_key = *public;
	free(public);
	tmp.st_netname = strdup(netname);
	tmp.keylen = keylen;
	tmp.algtype = algtype;
	return (store_netname3(0, &tmp));
}

/*
 * Fetch the keys and netname for this uid
 */
static int
fetch_netname(uid, key_netst)
	uid_t uid;
	struct key_netstarg *key_netst;
{
	struct secretkey_netname_list *l;
	int hash = HASH_UID(uid);

	(void) rw_rdlock(&g_secretkey_netname_lock);
	for (l = g_secretkey_netname[hash]; l != NULL; l = l->next) {
		if ((l->uid == uid) && (l->sc_flag == KEY_NAME)) {

			memcpy(key_netst->st_priv_key,
				l->keynetdata.st_priv_key, HEXKEYBYTES);

			memcpy(key_netst->st_pub_key,
				l->keynetdata.st_pub_key, HEXKEYBYTES);

			if (l->keynetdata.st_netname)
				strcpy(key_netst->st_netname,
						l->keynetdata.st_netname);
			else
				key_netst->st_netname = NULL;
			(void) rw_unlock(&g_secretkey_netname_lock);
			return (1);
		}
	}
	(void) rw_unlock(&g_secretkey_netname_lock);
	return (0);
}

static void
remove_ref(struct cacheuid_list *cp)
{
	debug(KEYSERV_DEBUG0, ("remove_ref %x", cp));
	/*
	 * XXX
	 * if we are going to do this along the lines of vn_rele,
	 * more stuff needs to be done here and the access to refcnt
	 * needs to be mutex locked. Keep it simple for now.
	 */
	cp->refcnt--;
}

static void
add_ref(struct cacheuid_list **cpp)
{
	struct cacheuid_list *cp;

	if (cpp == NULL) {
		return;
	}
	/*LINTED assignment operator "=" found where "==" was expected*/
	if (cp = *cpp) {
		debug(KEYSERV_DEBUG0, ("add_ref %x", cp));
		cp->refcnt++;
	}
}

static struct cacheuid_list *
getcachekey3(uid_t uid, struct mechentry *mp)
{
	struct cacheuid_list **cpp, *cp;
	struct mechdata *mdp;

	debug(KEYSERV_DEBUG1, ("getcachekey3 %d %x", uid, mp));
	if (mp == NULL) {
		return (0);
	}
	mutex_lock(&mp->mech_lock);
	if ((mdp = mp->mechdata) == NULL) {
		mutex_unlock(&mp->mech_lock);
		debug(KEYSERV_DEBUG0, ("getcachekey3 ret 0"));
		return (0);
	}
	cpp = mapuid2cache(uid, mdp);
	cp = *cpp;
	add_ref(cpp);
	mutex_unlock(&mp->mech_lock);
	debug(KEYSERV_DEBUG0, ("getcachekey3 ret %x", *cpp));
	return (cp);
}

/*
 * Fetch any available cache for this uid (vers 3)
 */
static struct cacheuid_list *
getanycache3(uid_t uid)
{
	struct keylenlist *kp;
	struct algtypelist *ap;
	struct mechdata *mdp;
	struct cacheuid_list **cpp, *cp;

	debug(KEYSERV_DEBUG, ("getanycache3 %d", uid));
	for (kp = mechtable.kp; kp != NULL; kp = kp->next) {
		debug(KEYSERV_DEBUG0, ("getanycache3 key %d", kp->keylen));
		for (ap = kp->ap; ap != NULL; ap = ap->next) {
			debug(KEYSERV_DEBUG0,
				("getanycache3 alg: %d", ap->algtype));
			mutex_lock(&ap->mech.mech_lock);
			if ((mdp = ap->mech.mechdata) == NULL) {
				mutex_unlock(&ap->mech.mech_lock);
				continue;
			}
			cpp = mapuid2cache(uid, mdp);
			if (*cpp == NULL) {
				mutex_unlock(&ap->mech.mech_lock);
				continue;
			}
			cp = *cpp;
			cp->refcnt++;
			mutex_unlock(&ap->mech.mech_lock);
			return (cp);
		}
	}
	return (NULL);
}

static struct cacheuid_list *
fetchcache3(uid_t uid, keylen_t k, algtype_t a)
{
	struct mechentry *mp;
	struct cacheuid_list *cp;

	debug(KEYSERV_DEBUG, ("fetchcache3 %d %d %d", uid, k, a));
	if ((mp = getmechtype(k, a)) == NULL) {
		return (NULL);
	}
	if ((cp = getcachekey3(uid, mp)) == NULL) {
		return (NULL);
	}
	debug(KEYSERV_DEBUG, ("fetchcache3 ret %x", cp));
	return (cp);
}

/*
 * Fetch the keys and netname for this uid vers 3
 */
static int
fetch_netname3(uid_t uid, mechtype *net, key_netstarg3 *ret)
{
	struct cacheuid_list *cp;

	if ((net == NULL) || (ret == NULL)) {
		return (0);
	}
	debug(KEYSERV_DEBUG, ("fetch_netname3 %d %d %d",
		uid, net->keylen, net->algtype));
	if (net->keylen == 0) {
		cp = getanycache3(uid);
	} else {
		cp = fetchcache3(uid, net->keylen, net->algtype);
	}
	debug(KEYSERV_DEBUG, ("fetch_netname3 cp %x", cp));
	if (cp == NULL) {
		return (0);
	}
	debug(KEYSERV_DEBUG, ("fetch_netname3 sec %x", cp->secretkey));
	if (!storekeybuf3(&ret->st_priv_key, cp->secretkey)) {
		return (0);
	}
	debug(KEYSERV_DEBUG, ("fetch_netname3 pub %x", cp->publickey));
	if (!storekeybuf3(&ret->st_pub_key, cp->publickey)) {
		return (0);
	}
	if (cp->netname) {
		debug(KEYSERV_DEBUG, ("fetch_netname3 net %s", cp->netname));
		ret->st_netname = strdup(cp->netname);
	} else {
		ret->st_netname = NULL;
	}
	remove_ref(cp);
	return (1);
}

keystatus
pk_netget(uid, netstore)
	uid_t uid;
	key_netstarg *netstore;
{
	if (!fetch_netname(uid, netstore)) {
		return (KEY_SYSTEMERR);
	}
	return (KEY_SUCCESS);
}

keystatus
pk_netget3(uid_t uid, mechtype *net, key_netstarg3 *ret)
{
	if (!fetch_netname3(uid, net, ret)) {
		return (KEY_SYSTEMERR);
	}
	return (KEY_SUCCESS);
}

#define	cachehit(pub, sec, list)	\
		(memcmp(pub, (list)->public, sizeof (keybuf)) == 0 && \
		memcmp(sec, (list)->secret, sizeof (keybuf)) == 0)

/*
 * Try to find the common key in the cache
 */
static int
readcache(pub, sec, deskey, hash)
	char *pub;
	char *sec;
	des_block *deskey;
	int hash;
{
	register struct cachekey_list **l;

	for (l = &g_cachedkeys[hash]; (*l) != NULL && !cachehit(pub, sec, *l);
		l = &(*l)->next)
		;
	if ((*l) == NULL)
		return (0);
	*deskey = (*l)->deskey;
	return (1);
}

/*
 * cache result of expensive multiple precision exponential operation
 */
static int
writecache(pub, sec, deskey, hash)
	char *pub;
	char *sec;
	des_block *deskey;
	int hash;
{
	struct cachekey_list *new;

	new = (struct cachekey_list *)malloc(sizeof (struct cachekey_list));
	if (new == NULL) {
		return (0);
	}
	memcpy(new->public, pub, sizeof (keybuf));
	memcpy(new->secret, sec, sizeof (keybuf));
	new->deskey = *deskey;

	new->next = g_cachedkeys[hash];
	g_cachedkeys[hash] = new;
	return (1);
}

/*
 * Choose middle 64 bits of the common key to use as our des key, possibly
 * overwriting the lower order bits by setting parity.
 */
static int
extractdeskey(ck, deskey)
	MINT *ck;
	des_block *deskey;
{
	void _mp_move(MINT *, MINT *);
	MINT *a;
	short r;
	int i;
	short base = (1 << 8);
	char *k;

	a = mp_itom(0);
	_mp_move(ck, a);
	for (i = 0; i < ((KEYSIZE - 64) / 2) / 8; i++) {
		mp_sdiv(a, base, a, &r);
	}
	k = deskey->c;
	for (i = 0; i < 8; i++) {
		mp_sdiv(a, base, a, &r);
		*k++ = r;
	}
	mp_mfree(a);
	des_setparity((char *)deskey);
	return (0);
}

static bool_t
fetchsecretkey(uid, buf)
	uid_t uid;
	char *buf;
{
	struct secretkey_netname_list *l;
	int hash = HASH_UID(uid);

	(void) rw_rdlock(&g_secretkey_netname_lock);
	for (l = g_secretkey_netname[hash]; l != NULL; l = l->next) {
		if (l->uid == uid) {
			memcpy(buf, l->keynetdata.st_priv_key,
				sizeof (keybuf));
			(void) rw_unlock(&g_secretkey_netname_lock);
			return (TRUE);
		}
	}
	(void) rw_unlock(&g_secretkey_netname_lock);
	return (FALSE);
}

static keybuf3 *
fetchsecretkey3(uid_t uid, keylen_t k, algtype_t a)
{
	struct cacheuid_list *cp;

	debug(KEYSERV_DEBUG, ("fetchsecretkey3 %d %d %d", uid, k, a));
	if ((cp = fetchcache3(uid, k, a)) == NULL) {
		return (NULL);
	}
	debug(KEYSERV_DEBUG, ("fetchsecretkey3 ret %x", cp->secretkey));
	return (cp->secretkey);
}

/*
 * Do the work of pk_encrypt && pk_decrypt
 */
static keystatus
pk_crypt(uid, remote_name, remote_key, key, mode)
	uid_t uid;
	char *remote_name;
	netobj *remote_key;
	des_block *key;
	int mode;
{
	char xsecret[1024];
	char xpublic[1024];
	des_block deskey;
	int err;
	MINT *public;
	MINT *secret;
	MINT *common;
	char zero[8];
	int hash;

	if (!fetchsecretkey(uid, xsecret) || xsecret[0] == 0) {
		memset(zero, 0, sizeof (zero));
		if (nodefaultkeys)
			return (KEY_NOSECRET);

		if (!getsecretkey("nobody", xsecret, zero) || xsecret[0] == 0) {
			return (KEY_NOSECRET);
		}
	}
	if (remote_key) {
		memcpy(xpublic, remote_key->n_bytes, remote_key->n_len);
	} else {
		if (!getpublickey(remote_name, xpublic)) {
			if (nodefaultkeys || !getpublickey("nobody", xpublic))
				return (KEY_UNKNOWN);
		}
	}

	xsecret[HEXKEYBYTES] = '\0';
	xpublic[HEXKEYBYTES] = '\0';

	hash = hash_keys(xpublic, xsecret);
	(void) rw_rdlock(&g_cachedkeys_lock);
	if (!readcache(xpublic, xsecret, &deskey, hash)) {
		(void) rw_unlock(&g_cachedkeys_lock);
		(void) rw_wrlock(&g_cachedkeys_lock);
		if (!readcache(xpublic, xsecret, &deskey, hash)) {
			public = mp_xtom(xpublic);
			secret = mp_xtom(xsecret);
			/* Sanity Check on public and private keys */
			if (public == NULL || secret == NULL) {
				(void) rw_unlock(&g_cachedkeys_lock);
				return (KEY_SYSTEMERR);
			}
			common = mp_itom(0);
			mp_pow(public, secret, MODULUS, common);
			extractdeskey(common, &deskey);
			writecache(xpublic, xsecret, &deskey, hash);
			mp_mfree(secret);
			mp_mfree(public);
			mp_mfree(common);
		}
	}
	(void) rw_unlock(&g_cachedkeys_lock);

	err = ecb_crypt((char *)&deskey, (char *)key, sizeof (des_block),
		DES_HW | mode);
	if (DES_FAILED(err)) {
		return (KEY_SYSTEMERR);
	}
	return (KEY_SUCCESS);
}

static int
hash_keys3(keybuf3 *p, keybuf3 *s)
{
	int i;
	int hash = 0;
	char *pub = p->keybuf3_val;
	char *sec = s->keybuf3_val;

	debug(KEYSERV_DEBUG, ("hash_keys3 public %d %s",
		p->keybuf3_len, pub));
	debug(KEYSERV_DEBUG, ("hash_keys3 secret %d %s",
		s->keybuf3_len, sec));
	for (i = 0; i < s->keybuf3_len; i += 6, pub += 6, sec += 6) {
		hash ^= *pub;
		hash ^= *sec;
	}
	debug(KEYSERV_DEBUG, ("hash_keys3 ret %d", hash & 0xff));
	return (hash & 0xff);
}

static struct cachekey3_list **
map_ps2cache(keybuf3 *public, keybuf3 *secret, struct psdata *pdp)
{
	struct cachekey3_list **cpp;
	int hash = hash_keys3(public, secret);

	debug(KEYSERV_DEBUG, ("map_ps2cache %x %d", pdp, hash));
	for (cpp = &pdp->common[hash];
		*cpp != NULL && !(cachehit3(public, secret, *cpp));
		cpp = &(*cpp)->next) {
		debug(KEYSERV_DEBUG0, ("map_ps2cache %x", cpp));
	}
	debug(KEYSERV_DEBUG, ("map_ps2cache ret %x", cpp));
	return (cpp);
}

static struct cachekey3_list *
getdeskey3(
	keylen_t keylen,
	algtype_t algtype,
	int desarylen,
	keybuf3 *public,
	keybuf3 *secret,
	uid_t uid
)
{
	struct mechentry *mp;
	struct psdata *pdp;
	struct cachekey3_list **cpp, *cp, *cachep;
	struct cacheuid_list *cu;
	int i;
	int cached = 0;

	debug(KEYSERV_DEBUG, ("getdeskey3 %d %d %d %x %x",
		keylen, algtype, desarylen, public, secret));
	if ((mp = getmechtype(keylen, algtype)) == NULL) {
		return (0);
	}
	(void) mutex_lock(&mp->ps_lock);
	if ((pdp = mp->psdata) == NULL) {
		if ((pdp = (struct psdata *)calloc(1, sizeof (*pdp))) ==
			NULL) {
			mutex_unlock(&mp->ps_lock);
			debug(KEYSERV_INFO, ("getdeskey3 : calloc failed"));
			return (0);
		}
		mp->psdata = pdp;
	}
	debug(KEYSERV_DEBUG, ("getdeskey3 %x", pdp));
	cpp = map_ps2cache(public, secret, pdp);
	if (*cpp == NULL) {
		debug(KEYSERV_DEBUG, ("getdeskey3 calling fetchcache3"));
		if (disk_caching &&
			(cu = fetchcache3(uid, keylen, algtype)) != NULL) {
			debug(KEYSERV_DEBUG,
				("getdeskey3 calling cache_retrieve"));
			if ((cachep = cache_retrieve(keylen, algtype, uid,
				public, cu->key)) != NULL) {
				if (cmpkeybuf3(cachep->secret, cu->secretkey)) {
					cached = 1;
				} else {
					debug(KEYSERV_DEBUG,
					("getdeskey3 calling cache_remove"));
					cache_remove(keylen, algtype,
						uid, NULL);
				}
			}
		}
		if (cached) {
			cp = cachep;
		} else {
			if ((cp = (struct cachekey3_list *)
				malloc(sizeof (*cp))) == NULL) {
				mutex_unlock(&mp->ps_lock);
				debug(KEYSERV_INFO,
					("getdeskey3 : malloc failed"));
				syslog(LOG_ERR,
					"file %s line %d: malloc failed",
					__FILE__, __LINE__);
				return (0);
			}
			cp->refcnt = 0;
			cp->next = NULL;
			if ((cp->public = cpykeybuf3(public)) == NULL) {
				mutex_unlock(&mp->ps_lock);
				return (0);
			}
			if ((cp->secret = cpykeybuf3(secret)) == NULL) {
				mutex_unlock(&mp->ps_lock);
				return (0);
			}
			if (!setdeskeyarray(&cp->deskey, desarylen)) {
				mutex_unlock(&mp->ps_lock);
				return (0);
			}
			debug(KEYSERV_DEBUG, ("getdeskey3 %x %x %x",
				cp->public, cp->secret,
				cp->deskey.deskeyarray_val));
			debug(KEYSERV_DEBUG,
				("getdeskey3 calling __gen_common_dhkeys_g"));
			if (!__gen_common_dhkeys_g(public->keybuf3_val,
				secret->keybuf3_val,
				keylen, algtype,
				cp->deskey.deskeyarray_val, desarylen)) {
				mutex_unlock(&mp->ps_lock);
				return (0);
			}
			for (i = 0; i < desarylen; i++) {
				debug(KEYSERV_DEBUG0,
					("getdeskey3 gendh key : (%x,%x)",
					cp->deskey.deskeyarray_val[i].key.high,
					cp->deskey.deskeyarray_val[i].key.low));
			}
			if (disk_caching && cu != NULL) {
				debug(KEYSERV_DEBUG,
					("getdeskey3 calling cache_insert"));
				cache_insert(keylen, algtype, uid, cp->deskey,
					cu->key, public, secret);
			}
		}
		*cpp = cp;
	} else {
		cp = *cpp;
	}
	cp->refcnt++;
	mutex_unlock(&mp->ps_lock);
	debug(KEYSERV_DEBUG, ("getdeskey3 ret %x", cp));
	return (cp);
}

keystatus
pk_get_conv_key3(uid_t uid, deskeyarg3 *arg, cryptkeyres3 *res)
{
	keybuf3 *xsecret, *xpublic;
	char zero[8];
	struct cachekey3_list *cp;

	debug(KEYSERV_DEBUG, ("pk_get_conv_key3 %d %x %x",
		uid, arg, res));
	if ((xsecret = fetchsecretkey3(uid,
		arg->keylen, arg->algtype)) == NULL) {
		if (nodefaultkeys)
			return (KEY_NOSECRET);
		memset(zero, 0, sizeof (zero));
		if ((xsecret = getkeybuf3(arg->keylen/4+1)) == NULL) {
			return (KEY_SYSTEMERR);
		}
		debug(KEYSERV_DEBUG,
			("pk_get_conv_key3 calling getsecretkey_g"));
		if (!getsecretkey_g("nobody",
			arg->keylen, arg->algtype,
			xsecret->keybuf3_val, xsecret->keybuf3_len,
			zero) || *xsecret->keybuf3_val == 0) { /* XXX */
			debug(KEYSERV_DEBUG,
			("pk_get_conv_key3 calling getsecretkey_g failed"));
			return (KEY_NOSECRET);
		}
		debug(KEYSERV_DEBUG,
			("pk_get_conv_key3 calling getsecretkey_g succeeded"));
	}
	xpublic = &arg->pub_key;
	if ((cp = getdeskey3(arg->keylen, arg->algtype, arg->nkeys,
		xpublic, xsecret, uid)) == NULL) {
		return (KEY_SYSTEMERR);
	}
	storedeskeyarray(&res->cryptkeyres3_u.deskey, &cp->deskey);
	return (KEY_SUCCESS);
}

/*
 * Do the work of pk_encrypt3 && pk_decrypt3
 */
static keystatus
pk_crypt3(
	uid_t uid,
	cryptkeyarg3 *arg,
	deskeyarray *key,
	int mode
)
{
	keybuf3 *xsecret = NULL, *xpublic = NULL;
	char zero[8];
	struct cachekey3_list *cp;
	int err;
	int xsecret_alloc = 0;
	char ivec[8];

	memset(ivec, 0, 8);
	debug(KEYSERV_DEBUG1, ("pk_crypt3 %d %x %x %d",
		uid, arg, key, mode));
	if ((xsecret = fetchsecretkey3(uid,
		arg->keylen, arg->algtype)) == NULL) {
		if (nodefaultkeys)
			return (KEY_NOSECRET);
		memset(zero, 0, sizeof (zero));
		if ((xsecret = getkeybuf3(arg->keylen/4+1)) == NULL) {
			return (KEY_SYSTEMERR);
		}
		xsecret_alloc = 1;
		debug(KEYSERV_DEBUG1, ("pk_crypt3 calling getsecretkey_g"));
		if (!getsecretkey_g("nobody",
			arg->keylen, arg->algtype,
			xsecret->keybuf3_val, xsecret->keybuf3_len,
			zero) || *xsecret->keybuf3_val == 0) { /* XXX */
			debug(KEYSERV_DEBUG,
				("pk_crypt3 calling getsecretkey_g failed"));
			freekeybuf3(xsecret);
			return (KEY_NOSECRET);
		}
		/* XXX optimize to cache nobody's secret key? */
		debug(KEYSERV_DEBUG0,
			("pk_crypt3 calling getsecretkey_g succeeded"));
	}
	if (arg->remotekey.keybuf3_len) {
		if ((xpublic = cpykeybuf3(&arg->remotekey)) == NULL) {
			if (xsecret_alloc) freekeybuf3(xsecret);
			return (KEY_SYSTEMERR);
		}
	} else {
		if ((xpublic = getkeybuf3(arg->keylen/4+1)) == NULL) {
			if (xsecret_alloc) freekeybuf3(xsecret);
			return (KEY_SYSTEMERR);
		}
		debug(KEYSERV_DEBUG1, ("pk_crypt3 calling getpublickey_g"));
		if (!getpublickey_g(arg->remotename,
			arg->keylen, arg->algtype,
			xpublic->keybuf3_val, xpublic->keybuf3_len)) {
			debug(KEYSERV_DEBUG0,
				("pk_crypt3 calling getpublickey_g nobody"));
			if (nodefaultkeys || !getpublickey_g("nobody",
				arg->keylen, arg->algtype,
				xpublic->keybuf3_val, xpublic->keybuf3_len)) {
				debug(KEYSERV_DEBUG,
			("pk_crypt3 calling getpublickey_g nobody failed"));
				if (xsecret_alloc) freekeybuf3(xsecret);
				freekeybuf3(xpublic);
				return (KEY_UNKNOWN);
			}
		}
		debug(KEYSERV_DEBUG0,
			("pk_crypt3 calling getpublickey_g succeeded"));
	}

	if ((cp = getdeskey3(arg->keylen, arg->algtype,
		arg->deskey.deskeyarray_len, xpublic, xsecret, uid)) == NULL) {
		if (xsecret_alloc) freekeybuf3(xsecret);
		freekeybuf3(xpublic);
		return (KEY_SYSTEMERR);
	}
	storedeskeyarray(key, &arg->deskey);
	if (CLASSIC_PK_DH(arg->keylen, arg->algtype)) {
		/*EMPTY*/
		debug(KEYSERV_DEBUG1,
			("pk_crypt3 WARNING received 192-bit key"));
	} else {
		debug(KEYSERV_DEBUG,
			("pk_crypt3 calling __cbc_triple_crypt"));
		err = __cbc_triple_crypt(cp->deskey.deskeyarray_val,
			(char *)key->deskeyarray_val,
			cp->deskey.deskeyarray_len*sizeof (des_block),
			DES_HW | mode, ivec);
		if (DES_FAILED(err)) {
			debug(KEYSERV_DEBUG,
		("pk_crypt3 calling ecb_crypt/__cbc_triple_crypt failed"));
			if (xsecret_alloc) freekeybuf3(xsecret);
			freekeybuf3(xpublic);
			return (KEY_SYSTEMERR);
		}
		debug(KEYSERV_DEBUG,
			("pk_crypt3 calling __cbc_triple_crypt succeeded"));
	}
	if (xsecret_alloc) freekeybuf3(xsecret);
	freekeybuf3(xpublic);
	return (KEY_SUCCESS);
}

keystatus
pk_get_conv_key(uid, pubkey, result)
	uid_t uid;
	keybuf pubkey;
	cryptkeyres *result;
{
	char xsecret[1024];
	char xpublic[1024];
	MINT *public;
	MINT *secret;
	MINT *common;
	char zero[8];
	int hash;

	if (!fetchsecretkey(uid, xsecret) || xsecret[0] == 0) {
		memset(zero, 0, sizeof (zero));
		if (nodefaultkeys)
			return (KEY_NOSECRET);

		if (!getsecretkey("nobody", xsecret, zero) ||
			xsecret[0] == 0)
			return (KEY_NOSECRET);
	}

	memcpy(xpublic, pubkey, sizeof (keybuf));
	xsecret[HEXKEYBYTES] = '\0';
	xpublic[HEXKEYBYTES] = '\0';

	hash = hash_keys(xpublic, xsecret);
	(void) rw_rdlock(&g_cachedkeys_lock);
	if (!readcache(xpublic, xsecret, &result->cryptkeyres_u.deskey, hash)) {
		(void) rw_unlock(&g_cachedkeys_lock);
		(void) rw_wrlock(&g_cachedkeys_lock);
		if (!readcache(xpublic, xsecret, &result->cryptkeyres_u.deskey,
									hash)) {
			public = mp_xtom(xpublic);
			secret = mp_xtom(xsecret);
			/* Sanity Check on public and private keys */
			if (public == NULL || secret == NULL) {
				(void) rw_unlock(&g_cachedkeys_lock);
				return (KEY_SYSTEMERR);
			}
			common = mp_itom(0);
			mp_pow(public, secret, MODULUS, common);
			extractdeskey(common, &result->cryptkeyres_u.deskey);
			writecache(xpublic, xsecret,
					&result->cryptkeyres_u.deskey, hash);
			mp_mfree(secret);
			mp_mfree(public);
			mp_mfree(common);
		}
	}
	(void) rw_unlock(&g_cachedkeys_lock);

	return (KEY_SUCCESS);
}

#define	findsec(sec, list)	\
		(memcmp(sec, (list)->secret, sizeof (keybuf)) == 0)

/*
 * Remove common keys from the cache.
 */
static int
removecache(sec)
	char *sec;
{
	struct cachekey_list *found;
	register struct cachekey_list **l;
	int i;

	(void) rw_wrlock(&g_cachedkeys_lock);
	for (i = 0; i < KEY_HASH_SIZE; i++) {
		for (l = &g_cachedkeys[i]; (*l) != NULL; ) {
			if (findsec(sec, *l)) {
				found = *l;
				*l = (*l)->next;
				memset((char *)found, 0,
					sizeof (struct cachekey_list));
				free(found);
			} else {
				l = &(*l)->next;
			}
		}
	}
	(void) rw_unlock(&g_cachedkeys_lock);
	return (1);
}

/*
 * Store the secretkey for this uid
 */
int
storesecretkey(uid, key)
	uid_t uid;
	keybuf key;
{
	struct secretkey_netname_list *new;
	struct secretkey_netname_list **l;
	int hash = HASH_UID(uid);

	(void) rw_wrlock(&g_secretkey_netname_lock);
	for (l = &g_secretkey_netname[hash]; *l != NULL && (*l)->uid != uid;
			l = &(*l)->next) {
	}
	if (*l == NULL) {
		if (key[0] == '\0') {
			(void) rw_unlock(&g_secretkey_netname_lock);
			return (0);
		}
		new = (struct secretkey_netname_list *)malloc(sizeof (*new));
		if (new == NULL) {
			(void) rw_unlock(&g_secretkey_netname_lock);
			return (0);
		}
		new->uid = uid;
		new->sc_flag = KEY_ONLY;
		memset(new->keynetdata.st_pub_key, 0, HEXKEYBYTES);
		new->keynetdata.st_netname = NULL;
		new->next = NULL;
		*l = new;
	} else {
		new = *l;
		if (key[0] == '\0')
			removecache(new->keynetdata.st_priv_key);
	}

	memcpy(new->keynetdata.st_priv_key, key,
		HEXKEYBYTES);
	(void) rw_unlock(&g_secretkey_netname_lock);
	return (1);
}

static int
hexdigit(val)
	int val;
{
	return ("0123456789abcdef"[val]);
}

int
bin2hex(bin, hex, size)
	unsigned char *bin;
	unsigned char *hex;
	int size;
{
	int i;

	for (i = 0; i < size; i++) {
		*hex++ = hexdigit(*bin >> 4);
		*hex++ = hexdigit(*bin++ & 0xf);
	}
	return (0);
}

static int
hexval(dig)
	char dig;
{
	if ('0' <= dig && dig <= '9') {
		return (dig - '0');
	} else if ('a' <= dig && dig <= 'f') {
		return (dig - 'a' + 10);
	} else if ('A' <= dig && dig <= 'F') {
		return (dig - 'A' + 10);
	} else {
		return (-1);
	}
}

int
hex2bin(hex, bin, size)
	unsigned char *hex;
	unsigned char *bin;
	int size;
{
	int i;

	for (i = 0; i < size; i++) {
		*bin = hexval(*hex++) << 4;
		*bin++ |= hexval(*hex++);
	}
	return (0);
}

static int
hash_keys(pub, sec)
	char *pub;
	char *sec;
{
	int i;
	int hash = 0;

	for (i = 0; i < HEXKEYBYTES; i += 6, pub += 6, sec += 6) {
		hash ^= *pub;
		hash ^= *sec;
	}
	return (hash & 0xff);
}

/*
 * problem:  keyserv loads keys from /etc/.rootkey based on nisauthconf(8)
 *           which is too nis+-centric (see secure_rpc(3NSL)).
 *
 * So we want to make sure there is always a AUTH_DES compat entry
 * in the "list" of nis+ mechs so that the 192bit key always gets loaded so
 * non-nis+ services that use AUTH_DES (e.g. nfs) won't get hosed.  The real
 * hacky part of it is we muck with the array returned from
 * __nis_get_mechanisms which we really don't have any business
 * doing cause we should not know/care how that is implemented.  A better
 * way would be to change the __nis_get_mechanisms interface or add another
 * one similiar to it that forces the "des" compat entry into the list.
 *
 * Return ptr to mechs array on success, else NULL on memory errs.
 */
mechanism_t **
getmechwrap()
{
	mechanism_t	**mechs = __nis_get_mechanisms(FALSE);
	mechanism_t	**mechsbak = NULL;
	mechanism_t	*desmech = NULL;
	int		i = 0;

	if (mechs) {
		/* got some valid mechs and possibly the AUTH_DES compat one */
		for (i = 0; mechs[i]; i++) {
			if (AUTH_DES_COMPAT_CHK(mechs[i]))
				return (mechs);
		}
		/* i == number of ptrs not counting terminating NULL */
	}

	/* AUTH_DES compat entry not found, let's add it */
	if ((desmech = malloc(sizeof (mechanism_t))) == NULL) {
		if (mechs)
			__nis_release_mechanisms(mechs);
		return (NULL);
	}
	desmech->mechname = NULL;
	desmech->alias = NIS_SEC_CF_DES_ALIAS;
	desmech->keylen = AUTH_DES_KEYLEN;
	desmech->algtype = AUTH_DES_ALGTYPE;
	desmech->qop = NULL;
	desmech->secserv = rpc_gss_svc_default;

	mechsbak = mechs;
	/* mechs == NULL and i == 0 is valid "no mechs configed" case */
	if ((mechs = (mechanism_t **)realloc(mechs,
			sizeof (mechanism_t *) * (i + 2))) == NULL) {
		if (mechsbak)
			__nis_release_mechanisms(mechsbak);
		free(desmech);
		return (NULL);
	}
	mechs[i] = desmech;
	mechs[i+1] = NULL;

	return (mechs);
}

int
init_mechs()
{
	int nmechs, oldmechseen;
	mechanism_t **mechpp;
	char **cpp;

	if (!(mechs = getmechwrap()))
		return (-1);

	/*
	 * find how many mechanisms were specified and also
	 * setup the mechanism table for unique keylen/algtype pair
	 */
	nmechs = 0;
	for (mechpp = mechs; *mechpp != NULL; mechpp++) {
		struct keylenlist **kpp;
		struct algtypelist **app;

		nmechs++;
		if (((*mechpp)->keylen < 0) || ((*mechpp)->algtype < 0)) {
			continue;
		}
		kpp = getkeylen((*mechpp)->keylen);
		appendkeylist(kpp, (*mechpp)->keylen);
		app = getalgtype(kpp, (*mechpp)->algtype);
		appendalgtype(app, (*mechpp)->algtype);
	}

	/*
	 * set of mechs for getsubopt()
	 */
	cache_options = (char **)calloc((size_t)nmechs + 1,
	    sizeof (*cache_options));
	if (cache_options == NULL) {
		(void) fprintf(stderr, "unable to allocate option array");
		return (-1);
	}
	/*
	 * cache sizes
	 */
	cache_size = (int *)calloc((size_t)nmechs, sizeof (int));
	if (cache_size == NULL) {
		(void) fprintf(stderr, "unable to allocate cache array");
		return (-1);
	}

	oldmechseen = 0;
	cpp = cache_options;
	for (mechpp = mechs; *mechpp != NULL; mechpp++) {
		/*
		 * usual case: a DH-style mechanism type, with an alias
		 */
		if ((*mechpp)->mechname != NULL &&
		    strncmp((*mechpp)->mechname, DHMECHSTR,
		    strlen(DHMECHSTR)) == 0 &&
		    (*mechpp)->alias != NULL) {
			/*
			 * Is this trad 192-DH? already added?
			 */
			if (strcmp((*mechpp)->alias, DESALIAS) == 0) {
				if (oldmechseen) {
					continue;
				}
				oldmechseen++;
			}

			*cpp++ = (*mechpp)->alias;
			continue;
		}

		/*
		 * HACK: we recognise a special alias for traditional
		 * 192-bit DH, unless the latter has already been mentioned
		 * in it's full form
		 */
		if ((*mechpp)->mechname == NULL && (*mechpp)->alias != NULL &&
		    strcmp((*mechpp)->alias, DES) == 0 && !oldmechseen) {
			*cpp++ = DESALIAS;
			oldmechseen++;
			continue;
		}

		/*
		 * Ignore anything else
		 */
	}

	/* Terminate the options list */
	*cpp = NULL;

	return (0);
}
