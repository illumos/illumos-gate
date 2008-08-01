/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2001 Atsushi Onoe
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IEEE 802.11 generic crypto support
 */
#include <sys/types.h>
#include <sys/note.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/strsun.h>
#include "net80211_impl.h"

extern const struct ieee80211_cipher wep;
extern const struct ieee80211_cipher tkip;
extern const struct ieee80211_cipher ccmp;

/*
 * Table of registered cipher modules.
 */
static const char *cipher_modnames[] = {
	"wlan_wep",	/* IEEE80211_CIPHER_WEP */
	"wlan_tkip",	/* IEEE80211_CIPHER_TKIP */
	"wlan_aes_ocb",	/* IEEE80211_CIPHER_AES_OCB */
	"wlan_ccmp",	/* IEEE80211_CIPHER_AES_CCM */
	"wlan_ckip",	/* IEEE80211_CIPHER_CKIP */
};

/*
 * Default "null" key management routines.
 */
/* ARGSUSED */
static int
nulldev_key_alloc(ieee80211com_t *ic, const struct ieee80211_key *k,
	ieee80211_keyix *keyix, ieee80211_keyix *rxkeyix)
{
	*keyix = 0;	/* use key index 0 for ucast key */
	*rxkeyix = IEEE80211_KEYIX_NONE;
	return (1);
}

/* ARGSUSED */
static int
nulldev_key_delete(ieee80211com_t *ic, const struct ieee80211_key *k)
{
	return (1);
}

/* ARGSUSED */
static int
nulldev_key_set(ieee80211com_t *ic, const struct ieee80211_key *k,
	const uint8_t *mac)
{
	return (1);
}

/* ARGSUSED */
static void
nulldev_key_update(ieee80211com_t *ic)
{
	/* noop */
}

/*
 * Reset key state to an unused state.  The crypto
 * key allocation mechanism insures other state (e.g.
 * key data) is properly setup before a key is used.
 */
void
ieee80211_crypto_resetkey(ieee80211com_t *ic,
    struct ieee80211_key *k, ieee80211_keyix ix)
{
	k->wk_cipher = &ieee80211_cipher_none;
	k->wk_private = k->wk_cipher->ic_attach(ic, k);
	k->wk_keyix = ix;
	k->wk_flags = IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV;
}

/*
 * Establish a relationship between the specified key and cipher
 * and, if necessary, allocate a hardware index from the driver.
 * Note that when a fixed key index is required it must be specified
 * and we blindly assign it w/o consulting the driver.
 *
 * This must be the first call applied to a key; all the other key
 * routines assume wk_cipher is setup.
 *
 * Locking must be handled by the caller using:
 *	ieee80211_key_update_begin(ic);
 *	ieee80211_key_update_end(ic);
 */
int
ieee80211_crypto_newkey(ieee80211com_t *ic, int cipher, int flags,
    struct ieee80211_key *key)
{
	const struct ieee80211_cipher *cip;
	ieee80211_keyix keyix, rxkeyix;
	void *keyctx;
	uint16_t oflags;

	/*
	 * Validate cipher and set reference to cipher routines.
	 */
	if (cipher >= IEEE80211_CIPHER_MAX) {
		ieee80211_dbg(IEEE80211_MSG_CRYPTO, "ieee80211_crypto_newkey: "
		    "invalid cipher %u\n", cipher);
		return (0);
	}
	cip = ic->ic_ciphers[cipher];
	/* already load all the ciphers, cip can't be NULL */
	if (cip == NULL) {
		ieee80211_dbg(IEEE80211_MSG_CRYPTO, "ieee80211_crypto_newkey: "
		    "unable to load cipher %u, module %s\n",
		    cipher, cipher < IEEE80211_N(cipher_modnames) ?
		    cipher_modnames[cipher] : "<unknown>");
		return (0);
	}

	oflags = key->wk_flags;
	flags &= IEEE80211_KEY_COMMON;
	/*
	 * If the hardware does not support the cipher then
	 * fallback to a host-based implementation.
	 */
	if ((ic->ic_caps & (1<<cipher)) == 0) {
		ieee80211_dbg(IEEE80211_MSG_CRYPTO, "ieee80211_crypto_newkey: "
		    "no h/w support for cipher %s, falling back to s/w\n",
		    cip->ic_name);
		flags |= IEEE80211_KEY_SWCRYPT;
	}
	/*
	 * Hardware TKIP with software MIC is an important
	 * combination; we handle it by flagging each key,
	 * the cipher modules honor it.
	 */
	if (cipher == IEEE80211_CIPHER_TKIP &&
	    (ic->ic_caps & IEEE80211_C_TKIPMIC) == 0) {
		ieee80211_dbg(IEEE80211_MSG_CRYPTO,
		    "no h/w support for TKIP MIC, falling back to s/w\n");
		flags |= IEEE80211_KEY_SWMIC;
	}

	/*
	 * Bind cipher to key instance.  Note we do this
	 * after checking the device capabilities so the
	 * cipher module can optimize space usage based on
	 * whether or not it needs to do the cipher work.
	 */
	if (key->wk_cipher != cip || key->wk_flags != flags) {
again:
		/*
		 * Fillin the flags so cipher modules can see s/w
		 * crypto requirements and potentially allocate
		 * different state and/or attach different method
		 * pointers.
		 */
		key->wk_flags = (uint16_t)flags;
		keyctx = cip->ic_attach(ic, key);
		if (keyctx == NULL) {
			ieee80211_dbg(IEEE80211_MSG_CRYPTO, "crypto_setkey: "
			    "unable to attach cipher %s\n", cip->ic_name);
			key->wk_flags = oflags;	/* restore old flags */
			return (0);
		}
		CIPHER_DETACH(key);		/* Detach old cipher */
		key->wk_cipher = cip;
		key->wk_private = keyctx;
	}
	/*
	 * Commit to requested usage so driver can see the flags.
	 */
	key->wk_flags = (uint16_t)flags;

	/*
	 * Ask the driver for a key index if we don't have one.
	 * Note that entries in the global key table always have
	 * an index; this means it's safe to call this routine
	 * for these entries just to setup the reference to the
	 * cipher template.  Note also that when using software
	 * crypto we also call the driver to give us a key index.
	 */
	if (key->wk_keyix == IEEE80211_KEYIX_NONE) {
		if (!DEV_KEY_ALLOC(ic, key, &keyix, &rxkeyix)) {
			/*
			 * Driver has no room; fallback to doing crypto
			 * in the host.  We change the flags and start the
			 * procedure over.  If we get back here then there's
			 * no hope and we bail.  Note that this can leave
			 * the key in a inconsistent state if the caller
			 * continues to use it.
			 */
			if ((key->wk_flags & IEEE80211_KEY_SWCRYPT) == 0) {
				ieee80211_dbg(IEEE80211_MSG_CRYPTO,
				    "crypto_setkey: "
				    "no h/w resources for cipher %s, "
				    "falling back to s/w\n", cip->ic_name);
				oflags = key->wk_flags;
				flags |= IEEE80211_KEY_SWCRYPT;
				if (cipher == IEEE80211_CIPHER_TKIP)
					flags |= IEEE80211_KEY_SWMIC;
				goto again;
			}
			ieee80211_dbg(IEEE80211_MSG_CRYPTO, "crypto_setkey: "
			    "unable to setup cipher %s\n", cip->ic_name);
			return (0);
		}
		key->wk_keyix = keyix;
		key->wk_rxkeyix = rxkeyix;
	}
	return (1);
}

/*
 * Remove the key (no locking, for internal use).
 */
static int
ieee80211_crypto_delkey_locked(ieee80211com_t *ic, struct ieee80211_key *key)
{
	uint16_t keyix;

	ASSERT(key->wk_cipher != NULL);

	keyix = key->wk_keyix;
	if (keyix != IEEE80211_KEYIX_NONE) {
		/*
		 * Remove hardware entry.
		 */
		if (!DEV_KEY_DELETE(ic, key)) {
			ieee80211_dbg(IEEE80211_MSG_CRYPTO,
			    "ieee80211_crypto_delkey_locked: ",
			    "driverdeletes key %u failed\n", keyix);
		}
	}
	CIPHER_DETACH(key);
	bzero(key, sizeof (struct ieee80211_key));
	/* NB: cannot depend on key index to decide this */
	ieee80211_crypto_resetkey(ic, key, IEEE80211_KEYIX_NONE);
	return (1);
}

/*
 * Remove the specified key.
 */
int
ieee80211_crypto_delkey(ieee80211com_t *ic, struct ieee80211_key *key)
{
	int status;

	KEY_UPDATE_BEGIN(ic);
	status = ieee80211_crypto_delkey_locked(ic, key);
	KEY_UPDATE_END(ic);
	return (status);
}

/*
 * Clear the global key table.
 */
static void
ieee80211_crypto_delglobalkeys(ieee80211com_t *ic)
{
	int i;

	KEY_UPDATE_BEGIN(ic);
	for (i = 0; i < IEEE80211_WEP_NKID; i++)
		(void) ieee80211_crypto_delkey_locked(ic, &ic->ic_nw_keys[i]);
	KEY_UPDATE_END(ic);
}

/*
 * Set the contents of the specified key.
 *
 * Locking must be handled by the caller using:
 *	ieee80211_key_update_begin(ic);
 *	ieee80211_key_update_end(ic);
 */
int
ieee80211_crypto_setkey(ieee80211com_t *ic, struct ieee80211_key *key,
    const uint8_t *macaddr)
{
	const struct ieee80211_cipher *cip = key->wk_cipher;

	ASSERT(cip != NULL);

	ieee80211_dbg(IEEE80211_MSG_CRYPTO, "ieee80211_crypto_setkey: "
	    "%s keyix %u flags 0x%x mac %s len %u\n",
	    cip->ic_name, key->wk_keyix, key->wk_flags,
	    ieee80211_macaddr_sprintf(macaddr), key->wk_keylen);

	/*
	 * Give cipher a chance to validate key contents.
	 * should happen before modifying state.
	 */
	if (cip->ic_setkey(key) == 0) {
		ieee80211_dbg(IEEE80211_MSG_CRYPTO, "ieee80211_crypto_setkey: "
		    "cipher %s rejected key index %u len %u flags 0x%x\n",
		    cip->ic_name, key->wk_keyix, key->wk_keylen,
		    key->wk_flags);
		return (0);
	}
	if (key->wk_keyix == IEEE80211_KEYIX_NONE) {
		ieee80211_dbg(IEEE80211_MSG_CRYPTO, "ieee80211_crypto_setkey: "
		    "no key index; should not happen!\n");
		return (0);
	}
	return (DEV_KEY_SET(ic, key, macaddr));
}

/*
 * Return the transmit key to use in sending a frame.
 */
struct ieee80211_key *
ieee80211_crypto_getkey(ieee80211com_t *ic)
{
	if (ic->ic_def_txkey == IEEE80211_KEYIX_NONE ||
	    KEY_UNDEFINED(ic->ic_nw_keys[ic->ic_def_txkey]))
		return (NULL);
	return (&ic->ic_nw_keys[ic->ic_def_txkey]);
}

uint8_t
ieee80211_crypto_getciphertype(ieee80211com_t *ic)
{
	struct ieee80211_key *key;
	uint32_t cipher;
	static const uint8_t ciphermap[] = {
		WIFI_SEC_WEP,	/* IEEE80211_CIPHER_WEP */
		WIFI_SEC_WPA,	/* IEEE80211_CIPHER_TKIP */
		(uint8_t)-1,	/* IEEE80211_CIPHER_AES_OCB */
		WIFI_SEC_WPA,	/* IEEE80211_CIPHER_AES_CCM */
		(uint8_t)-1,	/* IEEE80211_CIPHER_CKIP */
		WIFI_SEC_NONE,	/* IEEE80211_CIPHER_NONE */
	};

	if ((ic->ic_flags & IEEE80211_F_PRIVACY) == 0)
		return (WIFI_SEC_NONE);

	key = ieee80211_crypto_getkey(ic);
	if (key == NULL)
		return (WIFI_SEC_NONE);

	cipher = key->wk_cipher->ic_cipher;
	ASSERT(cipher < IEEE80211_N(ciphermap));
	return (ciphermap[cipher]);
}

/*
 * Add privacy headers appropriate for the specified key.
 */
struct ieee80211_key *
ieee80211_crypto_encap(ieee80211com_t *ic, mblk_t *mp)
{
	struct ieee80211_key *k;
	const struct ieee80211_cipher *cip;
	uint8_t keyix;

	if (ic->ic_def_txkey == IEEE80211_KEYIX_NONE) {
		ieee80211_dbg(IEEE80211_MSG_CRYPTO,
		    "ieee80211_crypto_encap: %s",
		    " No default xmit key for frame\n");
		return (NULL);
	}
	keyix = ic->ic_def_txkey;
	k = &ic->ic_nw_keys[ic->ic_def_txkey];
	cip = k->wk_cipher;
	return (cip->ic_encap(k, mp, keyix<<6) ? k : NULL);
}

/*
 * Validate and strip privacy headers (and trailer) for a
 * received frame that has the WEP/Privacy bit set.
 */
struct ieee80211_key *
ieee80211_crypto_decap(ieee80211com_t *ic, mblk_t *mp, int hdrlen)
{
	struct ieee80211_key *k;
	const struct ieee80211_cipher *cip;
	uint8_t *ivp;
	uint8_t keyid;

	/* NB: this minimum size data frame could be bigger */
	if (MBLKL(mp) < IEEE80211_WEP_MINLEN) {
		ieee80211_dbg(IEEE80211_MSG_CRYPTO, "ieee80211_crypto_decap:"
		    " WEP data frame too short, len %u\n",
		    MBLKL(mp));
		return (NULL);
	}
	/*
	 * Locate the key. If unicast and there is no unicast
	 * key then we fall back to the key id in the header.
	 * This assumes unicast keys are only configured when
	 * the key id in the header is meaningless (typically 0).
	 */
	ivp = mp->b_rptr + hdrlen;
	keyid = ivp[IEEE80211_WEP_IVLEN];
	k = &ic->ic_nw_keys[keyid >> 6];

	/* check to avoid panic when wep is on but key is not set */
	if (k->wk_cipher == &ieee80211_cipher_none ||
	    k->wk_cipher == NULL)
		return (NULL);

	cip = k->wk_cipher;
	return ((cip->ic_decap)(k, mp, hdrlen) ? k : NULL);
}

/*
 * Setup crypto support.
 */
void
ieee80211_crypto_attach(ieee80211com_t *ic)
{
	struct ieee80211_crypto_state *cs = &ic->ic_crypto;
	int i;

	(void) crypto_mech2id(SUN_CKM_RC4); /* Load RC4 */
	(void) crypto_mech2id(SUN_CKM_AES_CBC); /* Load AES-CBC */
	(void) crypto_mech2id(SUN_CKM_AES_CCM); /* Load AES-CCM */

	/* NB: we assume everything is pre-zero'd */
	cs->cs_def_txkey = IEEE80211_KEYIX_NONE;
	for (i = 0; i < IEEE80211_WEP_NKID; i++) {
		ieee80211_crypto_resetkey(ic, &cs->cs_nw_keys[i],
		    IEEE80211_KEYIX_NONE);
	}

	/*
	 * Initialize the driver key support routines to noop entries.
	 * This is useful especially for the cipher test modules.
	 */
	cs->cs_key_alloc = nulldev_key_alloc;
	cs->cs_key_set = nulldev_key_set;
	cs->cs_key_delete = nulldev_key_delete;
	cs->cs_key_update_begin = nulldev_key_update;
	cs->cs_key_update_end = nulldev_key_update;

	ieee80211_crypto_register(ic, &wep);
	ieee80211_crypto_register(ic, &tkip);
	ieee80211_crypto_register(ic, &ccmp);
}

/*
 * Teardown crypto support.
 */
void
ieee80211_crypto_detach(ieee80211com_t *ic)
{
	ieee80211_crypto_delglobalkeys(ic);

	ieee80211_crypto_unregister(ic, &wep);
	ieee80211_crypto_unregister(ic, &tkip);
	ieee80211_crypto_unregister(ic, &ccmp);
}

/*
 * Register a crypto cipher module.
 */
void
ieee80211_crypto_register(ieee80211com_t *ic,
    const struct ieee80211_cipher *cip)
{
	if (cip->ic_cipher >= IEEE80211_CIPHER_MAX) {
		ieee80211_err("ieee80211_crypto_register: "
		    "cipher %s has an invalid cipher index %u\n",
		    cip->ic_name, cip->ic_cipher);
		return;
	}
	if (ic->ic_ciphers[cip->ic_cipher] != NULL &&
	    ic->ic_ciphers[cip->ic_cipher] != cip) {
		ieee80211_err("ieee80211_crypto_register: "
		    "cipher %s registered with a different template\n",
		    cip->ic_name);
		return;
	}
	ic->ic_ciphers[cip->ic_cipher] = cip;
}

/*
 * Unregister a crypto cipher module.
 */
void
ieee80211_crypto_unregister(ieee80211com_t *ic,
    const struct ieee80211_cipher *cip)
{
	if (cip->ic_cipher >= IEEE80211_CIPHER_MAX) {
		ieee80211_err("ieee80211_crypto_unregister: "
		    "cipher %s has an invalid cipher index %u\n",
		    cip->ic_name, cip->ic_cipher);
		return;
	}
	if (ic->ic_ciphers[cip->ic_cipher] != NULL &&
	    ic->ic_ciphers[cip->ic_cipher] != cip) {
		ieee80211_err("ieee80211_crypto_unregister: "
		    "cipher %s registered with a different template\n",
		    cip->ic_name);
		return;
	}
	/* NB: don't complain about not being registered */
	ic->ic_ciphers[cip->ic_cipher] = NULL;
}
