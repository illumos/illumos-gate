/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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

#ifndef _SYS_NET80211_CRYPTO_H
#define	_SYS_NET80211_CRYPTO_H

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/stream.h>
#include <sys/mac.h>
#endif
#include <sys/net80211_proto.h>

/*
 * 802.11 protocol crypto-related definitions.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	IEEE80211_MAX_WPA_IE		40	/* IEEE802.11i */
/*
 * Max size of optional information elements.  We artificially
 * constrain this; it's limited only by the max frame size (and
 * the max parameter size of the wireless extensions).
 */
#define	IEEE80211_MAX_OPT_IE		256

#define	IEEE80211_MLME_ASSOC		1	/* associate station */
#define	IEEE80211_MLME_DISASSOC		2	/* disassociate station */
#define	IEEE80211_MLME_DEAUTH		3	/* deauthenticate station */
#define	IEEE80211_MLME_AUTHORIZE	4	/* authorize station */
#define	IEEE80211_MLME_UNAUTHORIZE	5	/* unauthorize station */

/*
 * NB: these values are ordered carefully; there are lots of
 * of implications in any reordering.
 */
#define	IEEE80211_CIPHER_WEP		0
#define	IEEE80211_CIPHER_TKIP		1
#define	IEEE80211_CIPHER_AES_OCB	2
#define	IEEE80211_CIPHER_AES_CCM	3
#define	IEEE80211_CIPHER_CKIP		4
#define	IEEE80211_CIPHER_NONE		5	/* pseudo value */

#define	IEEE80211_CIPHER_MAX		(IEEE80211_CIPHER_NONE+1)

/*
 * Maxmium length of key in bytes
 * WEP key length present in the 802.11 standard is 40-bit.
 * Many implementations also support 104-bit WEP keys.
 * 802.11i standardize TKIP/CCMP use 128-bit key
 */
#define	IEEE80211_KEYBUF_SIZE		16
#define	IEEE80211_MICBUF_SIZE		(8+8)	/* space for both tx+rx keys */

/* Key Flags */
#define	IEEE80211_KEY_XMIT		0x01	/* key used for xmit */
#define	IEEE80211_KEY_RECV		0x02	/* key used for recv */
#define	IEEE80211_KEY_GROUP		/* key used for WPA group operation */ \
					0x04
#define	IEEE80211_KEY_SWCRYPT		0x10	/* host-based encrypt/decrypt */
#define	IEEE80211_KEY_SWMIC		0x20	/* host-based enmic/demic */
#define	IEEE80211_KEY_COMMON 		/* common flags passed in by apps */ \
	(IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV | IEEE80211_KEY_GROUP)

#define	IEEE80211_KEY_DEFAULT		0x80	/* default xmit key */

/* WEP */
#define	IEEE80211_WEP_KEYLEN		5	/* 40bit */
#define	IEEE80211_WEP_IVLEN		3	/* 24bit */
#define	IEEE80211_WEP_KIDLEN		1	/* 1 octet */
#define	IEEE80211_WEP_CRCLEN		4	/* CRC-32 */
#define	IEEE80211_WEP_NKID		4	/* number of key ids */

/*
 * 802.11i defines an extended IV for use with non-WEP ciphers.
 * When the EXTIV bit is set in the key id byte an additional
 * 4 bytes immediately follow the IV for TKIP.  For CCMP the
 * EXTIV bit is likewise set but the 8 bytes represent the
 * CCMP header rather than IV+extended-IV.
 */
#define	IEEE80211_WEP_EXTIV		0x20
#define	IEEE80211_WEP_EXTIVLEN		4	/* extended IV length */
#define	IEEE80211_WEP_MICLEN		8	/* trailing MIC */

#define	IEEE80211_WEP_HDRLEN					\
	(IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN)
#define	IEEE80211_WEP_MINLEN					\
	(sizeof (struct ieee80211_frame) +			\
	IEEE80211_WEP_HDRLEN + IEEE80211_WEP_CRCLEN)

/* Maximum number of keys */
#define	IEEE80211_KEY_MAX		IEEE80211_WEP_NKID

typedef uint16_t	ieee80211_keyix;	/* h/w key index */

#define	IEEE80211_KEYIX_NONE	((ieee80211_keyix) -1)

#ifdef _KERNEL

struct ieee80211com;
struct ieee80211_key;

/*
 * Template for a supported cipher.  Ciphers register with the
 * crypto code.
 *
 * ic_attach - Initialize cipher. The return value is set to wk_private
 * ic_detach - Destruct a cipher.
 * ic_setkey - Validate key contents
 * ic_encap  - Encrypt the 802.11 MAC payload
 * ic_decap  - Decrypt the 802.11 MAC payload
 * ic_enmic  - Add MIC
 * ic_demic  - Check and remove MIC
 */
struct ieee80211_cipher {
	const char	*ic_name;	/* printable name */
	uint32_t	ic_cipher;	/* IEEE80211_CIPHER_* */
	uint32_t	ic_header;	/* size of privacy header (bytes) */
	uint32_t	ic_trailer;	/* size of privacy trailer (bytes) */
	uint32_t	ic_miclen;	/* size of mic trailer (bytes) */
	void		*(*ic_attach)(struct ieee80211com *,
				struct ieee80211_key *);
	void		(*ic_detach)(struct ieee80211_key *);
	int32_t		(*ic_setkey)(struct ieee80211_key *);
	int32_t		(*ic_encap)(struct ieee80211_key *, mblk_t *,
				uint8_t keyid);
	int32_t		(*ic_decap)(struct ieee80211_key *, mblk_t *, int);
	int32_t		(*ic_enmic)(struct ieee80211_key *, mblk_t *, int);
	int32_t		(*ic_demic)(struct ieee80211_key *, mblk_t *, int);
};
extern	const struct ieee80211_cipher ieee80211_cipher_none;

struct ieee80211_key {
	uint8_t		wk_keylen;	/* key length in bytes */
	uint8_t		wk_pad;
	uint16_t	wk_flags;
	uint8_t		wk_key[IEEE80211_KEYBUF_SIZE+IEEE80211_MICBUF_SIZE];
	ieee80211_keyix	wk_keyix;	/* h/w key index */
	ieee80211_keyix	wk_rxkeyix;	/* optional h/w rx key index */
	uint64_t	wk_keyrsc;	/* key receive sequence counter */
	uint64_t	wk_keytsc;	/* key transmit sequence counter */
	const struct ieee80211_cipher	*wk_cipher;
	void		*wk_private;	/* private cipher state */
};
#define	wk_txmic	wk_key+IEEE80211_KEYBUF_SIZE+0
#define	wk_rxmic	wk_key+IEEE80211_KEYBUF_SIZE+8

/*
 * Crypto state kept in each ieee80211com.
 */
struct ieee80211_crypto_state {
	struct ieee80211_key	cs_nw_keys[IEEE80211_KEY_MAX];
	ieee80211_keyix		cs_def_txkey;	/* default/group tx key index */
	uint16_t		cs_max_keyix;	/* max h/w key index */

	int			(*cs_key_alloc)(struct ieee80211com *,
					const struct ieee80211_key *,
					ieee80211_keyix *, ieee80211_keyix *);
	int			(*cs_key_delete)(struct ieee80211com *,
					const struct ieee80211_key *);
	int			(*cs_key_set)(struct ieee80211com *,
					const struct ieee80211_key *,
					const uint8_t mac[IEEE80211_ADDR_LEN]);
	void			(*cs_key_update_begin)(struct ieee80211com *);
	void			(*cs_key_update_end)(struct ieee80211com *);
};

/*
 * Key update synchronization methods.
 */
#define	KEY_UPDATE_BEGIN(ic)		\
	(ic)->ic_crypto.cs_key_update_begin(ic)
#define	KEY_UPDATE_END(ic)		\
	(ic)->ic_crypto.cs_key_update_end(ic)
#define	KEY_UNDEFINED(k)		\
	((k).wk_cipher == &ieee80211_cipher_none)

#define	DEV_KEY_ALLOC(ic, k, kix, rkix) \
	(ic)->ic_crypto.cs_key_alloc(ic, k, kix, rkix)
#define	DEV_KEY_DELETE(ic, k)		\
	(ic)->ic_crypto.cs_key_delete(ic, k)
#define	DEV_KEY_SET(ic, k, m)		\
	(ic)->ic_crypto.cs_key_set(ic, k, m)

#define	CIPHER_DETACH(k)		\
	(k)->wk_cipher->ic_detach(k)
#define	CIPHER_ATTACH(k)		\
	(k)->wk_cipher->ic_attach(k)

#define	ieee80211_crypto_demic(ic, k, m, force)		\
	(((k)->wk_cipher->ic_miclen > 0) ?		\
	(k)->wk_cipher->ic_demic(k, m, force) :		\
	1)

#define	ieee80211_crypto_enmic(ic, k, m, force)		\
	((k)->wk_cipher->ic_miclen > 0 ?		\
	(k)->wk_cipher->ic_enmic(k, m, force) :		\
	1)

void ieee80211_crypto_attach(struct ieee80211com *ic);
void ieee80211_crypto_detach(struct ieee80211com *ic);
void ieee80211_crypto_register(struct ieee80211com *ic,
    const struct ieee80211_cipher *);
void ieee80211_crypto_unregister(struct ieee80211com *ic,
    const struct ieee80211_cipher *);
void ieee80211_crypto_resetkey(struct ieee80211com *, struct ieee80211_key *,
	ieee80211_keyix);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NET80211_CRYPTO_H */
