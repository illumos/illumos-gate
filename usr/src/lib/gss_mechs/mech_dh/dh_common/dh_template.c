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
 *	dh_template.c
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <dh_gssapi.h>
#include <dlfcn.h>
#include "../dh_common/dh_common.h"

extern int key_encryptsession_pk_g();
extern int key_decryptsession_pk_g();
extern int key_gendes_g();
extern int key_secretkey_is_set_g();

static int __encrypt(const char *remotename, des_block deskeys[], int no_keys);
static int __decrypt(const char *remotename,
		    des_block deskeys[], int no_keys, int *key_cached);
static int __gendes(des_block deskeys[], int no_keys);
static int __secret_is_set(void);
static char *__get_principal(void);

/*
 * This module defines the entry point for gss_mech_initialize and the
 * key opts for Diffie-Hellman mechanism of type algorithm 0. Each algorithm
 * 0 mechanism defines its OID, MODULUS, ROOT, KEYLEN, ALGTYPE (which should
 * be zero) and HEX_KEY_BYTES. That module then will #include this file.
 */

/* The keyopts for the per mechanism context */
static dh_keyopts_desc dh_keyopts = {
	__encrypt,
	__decrypt,
	__gendes,
	__secret_is_set,
	__get_principal
};

/* The gss_context for this mechanism */
static struct gss_config  dh_mech;

/*
 * gss_mech_initialize: This is the libgss entry point to bring this
 * mechanism on line.  It is just a wrap to pass the pointer to its
 * gss_config structure, OID, and the above keyopts to the common
 * __dh_geneirc_initialize routine. We return null on failure, otherwise
 * we return the mechanism's gss_mechanism.
 */
gss_mechanism
gss_mech_initialize()
{
	gss_mechanism mech;

	mech = __dh_generic_initialize(&dh_mech, OID, &dh_keyopts);

	if (mech == NULL) {
		return (NULL);
	}

	return (mech);
}

/*
 * A NIS+ server will define the function __rpcsec_gss_is_server.
 * This function will return one when it is appropriate to get public
 * keys out of the per process public key cache. Appropriateness here
 * is when the name server just put the public key in the cache from a
 * received directory object, typically from the cold start file.
 */
static int
dh_getpublickey(const char *remote, keylen_t keylen, algtype_t algtype,
		char *pk, size_t pklen)
{
	static mutex_t init_nis_pubkey_lock = DEFAULTMUTEX;
	static int init_nis_pubkey = 0;
	static int (*nis_call)();
	static const char NIS_SYMBOL[] = "__rpcsec_gss_is_server";

	if (!init_nis_pubkey) {
		(void) mutex_lock(&init_nis_pubkey_lock);
		if (!init_nis_pubkey) {
			void *dlhandle = dlopen(0, RTLD_NOLOAD);
			if (dlhandle == 0) {
				syslog(LOG_ERR, "dh: Could not dlopen "
				    "in dh_getpublickey for %s. "
				    "dlopen returned %s", remote, dlerror());
			} else {
				nis_call = (int (*)())
					dlsym(dlhandle, NIS_SYMBOL);
			}
			init_nis_pubkey = 1;
		}
		(void) mutex_unlock(&init_nis_pubkey_lock);
	}
	if (nis_call && (*nis_call)()) {
		int key_cached;
		return (__getpublickey_cached_g(remote, keylen, algtype,
					    pk, pklen, &key_cached));
	}

	/*
	 * If we're not being called by a nis plus server or that
	 * server does not want to get the keys from the cache we
	 * get the key in the normal manner.
	 */

	return (getpublickey_g(remote, keylen, algtype, pk, pklen));
}


/*
 * Routine to encrypt a set of session keys with keys derived from
 * the common key with the caller and the remote principal.
 */
static int __encrypt(const char *remotename, des_block deskeys[], int no_keys)
{
	char pk[HEX_KEY_BYTES+1];

	/*
	 * Get the public key out of the cache if this is a NIS+
	 * server. The reason is that the server may be a root replica
	 * that has just been created. It will not yet have the
	 * public key data to talk to its master. When the cold start
	 * file is read the public keys that are found there are
	 * cached. We will use the cache to get the public key data so
	 * the server will not hang or dump core. We call NIS_getpublickey
	 * to get the appropriate public key from NIS+. If that fails
	 * we just try to get the public key in the normal manner.
	 */

	if (!dh_getpublickey(remotename, KEYLEN, 0, pk, sizeof (pk)))
			return (-1);

	if (key_encryptsession_pk_g(remotename, pk,
				    KEYLEN, ALGTYPE, deskeys, no_keys))
		return (-1);

	return (0);
}

/*
 * Routine to decrypt a set of session keys with the common key that
 * is held between the caller and the remote principal.
 */
static int __decrypt(const char *remotename,
		    des_block deskeys[], int no_keys, int *key_cached)
{
	int *use_cache = key_cached;
	char pk[HEX_KEY_BYTES+1];

	if (key_cached) {
		use_cache = *key_cached ? key_cached : 0;
		*key_cached = 0;
	}

#ifdef DH_DEBUG
	syslog(LOG_DEBUG, "dh: __decrypt is %s cache for %s\n",
		use_cache ? "using" : "not using", remotename);
#endif

	/*
	 * If we are not using the cache, flush the entry for remotename.
	 * It may be bad. The call to __getpublickey_cached_g below will
	 * repopulate the cache with the current public key.
	 */
	if (!use_cache)
		__getpublickey_flush_g(remotename, KEYLEN, ALGTYPE);

	/* Get the public key */
	if (!__getpublickey_cached_g(remotename, KEYLEN,
				    0, pk, sizeof (pk), use_cache))
		return (-1);

#if DH_DEBUG
	if (use_cache)
		syslog(LOG_DEBUG, "dh: __decrypt cache = %d\n", *key_cached);
#endif

	if (key_decryptsession_pk_g(remotename, pk,
				    KEYLEN, ALGTYPE, deskeys, no_keys)) {

		return (-1);
	}

	return (0);
}

/*
 * Routine to generate a set of random session keys.
 */
static int __gendes(des_block deskeys[], int no_keys)
{

	memset(deskeys, 0, no_keys* sizeof (des_block));
	if (key_gendes_g(deskeys, no_keys))
			return (-1);

	return (0);
}

/*
 * Routine that will return true if this mechanism corresponding
 * private keys has been set.
 */
static int __secret_is_set(void)
{
	return (key_secretkey_is_set_g(KEYLEN, ALGTYPE));
}

/*
 * Routine to retrieve the callers principal name. Note it is up to
 * the caller to free the result.
 */
static char * __get_principal(void)
{
	char netname[MAXNETNAMELEN+1];

	if (getnetname(netname))
		return (strdup(netname));

	return (NULL);
}
