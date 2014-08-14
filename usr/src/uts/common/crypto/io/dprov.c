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
 * Dummy Cryptographic Provider:
 *
 * This file implements a "dummy" cryptographic provider. It is implemented
 * as a pseudo device driver.
 *
 */

/*
 * This driver implements a KEF provider with the following capabilities:
 *
 * - registration/unregistration with KEF
 * - digest entry points
 * - mac entry points
 * - ctx management
 * - support for async requests
 * - cipher entry points
 * - dual entry points
 * - sign entry points
 * - verify entry points
 * - dual operations entry points
 * - dual cipher/mac operation entry points
 * - session management
 * - object management
 * - key management
 * - provider management
 *
 * In order to avoid duplicating the implementation of algorithms
 * provided by software providers, this pseudo driver acts as
 * a consumer of the framework. When invoking one of the framework's
 * entry points, the driver specifies the software provider to
 * be used for the operation.
 *
 * User management: we implement a PKCS#11 style provider which supports:
 * - one normal user with a PIN, and
 * - one SO user with a PIN.
 * These values are kept in the per-instance structure, and are initialized
 * with the provider management entry points.
 *
 */


#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ksynch.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/model.h>
#include <sys/note.h>
#include <sys/random.h>
#include <sys/byteorder.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>

#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/sysmacros.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>

#include <sys/sha2.h>
#include <modes/modes.h>
#include <aes/aes_impl.h>
#include <des/des_impl.h>
#include <ecc/ecc_impl.h>
#include <blowfish/blowfish_impl.h>

/*
 * Debugging macros.
 */
#ifdef DEBUG
#define	D_INIT		0x00000001	/* _init/_fini/_info */
#define	D_ATTACH	0x00000002	/* attach/detach */
#define	D_DIGEST	0x00000010	/* digest entry points */
#define	D_MAC		0x00000020	/* mac entry points */
#define	D_CONTEXT	0x00000040	/* context entry points */
#define	D_CIPHER	0x00000080	/* cipher entry points */
#define	D_SIGN		0x00000100	/* sign entry points */
#define	D_VERIFY	0x00000200	/* verify entry points */
#define	D_SESSION	0x00000400	/* session management entry points */
#define	D_MGMT		0x00000800	/* provider management entry points */
#define	D_DUAL		0x00001000	/* dual ops */
#define	D_CIPHER_MAC	0x00002000	/* cipher/mac dual ops */
#define	D_OBJECT	0x00004000	/* object management */
#define	D_RANDOM	0x00008000	/* random number generation */
#define	D_KEY		0x00010000	/* key management */

static uint32_t dprov_debug = 0;

#define	DPROV_DEBUG(f, x)	if (dprov_debug & (f)) { (void) printf x; }
#define	DPROV_CALL(f, r, x)	if (dprov_debug & (f)) { (void) r x; }
#else /* DEBUG */
#define	DPROV_DEBUG(f, x)
#define	DPROV_CALL(f, r, x)
#endif /* DEBUG */

static int nostore_key_gen;
static boolean_t dprov_no_multipart = B_FALSE;
static int dprov_max_digestsz = INT_MAX;

/*
 * DDI entry points.
 */
static int dprov_attach(dev_info_t *, ddi_attach_cmd_t);
static int dprov_detach(dev_info_t *, ddi_detach_cmd_t);
static int dprov_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

/*
 * Module linkage.
 */
static struct cb_ops cbops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	dprov_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	dprov_attach,		/* devo_attach */
	dprov_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cbops,			/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Pseudo KCF Prov (drv)",
	&devops
};

static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	"Pseudo KCF Prov (crypto)"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	&modlcrypto,
	NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */

typedef enum dprov_mech_type {
	MD4_MECH_INFO_TYPE,		/* SUN_CKM_MD4 */

	MD5_MECH_INFO_TYPE,		/* SUN_CKM_MD5 */
	MD5_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_MD5_HMAC */
	MD5_HMAC_GEN_MECH_INFO_TYPE,	/* SUN_CKM_MD5_HMAC_GENERAL */

	SHA1_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA1_HMAC */
	SHA1_HMAC_GEN_MECH_INFO_TYPE,	/* SUN_CKM_SHA1_HMAC_GENERAL */
	SHA1_MECH_INFO_TYPE,		/* SUN_CKM_SHA1 */

	SHA256_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA256_HMAC */
	SHA256_HMAC_GEN_MECH_INFO_TYPE,	/* SUN_CKM_SHA256_HMAC_GENERAL */
	SHA256_MECH_INFO_TYPE,		/* SUN_CKM_SHA256 */
	SHA384_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA384_HMAC */
	SHA384_HMAC_GEN_MECH_INFO_TYPE,	/* SUN_CKM_SHA384_HMAC_GENERAL */
	SHA384_MECH_INFO_TYPE,		/* SUN_CKM_SHA384 */
	SHA512_HMAC_MECH_INFO_TYPE,	/* SUN_CKM_SHA512_HMAC */
	SHA512_HMAC_GEN_MECH_INFO_TYPE,	/* SUN_CKM_SHA512_HMAC_GENERAL */
	SHA512_MECH_INFO_TYPE,		/* SUN_CKM_SHA512 */

	DES_CBC_MECH_INFO_TYPE,		/* SUN_CKM_DES_CBC */
	DES3_CBC_MECH_INFO_TYPE,	/* SUN_CKM_DES3_CBC */
	DES_ECB_MECH_INFO_TYPE,		/* SUN_CKM_DES_ECB */
	DES3_ECB_MECH_INFO_TYPE,	/* SUN_CKM_DES3_ECB */

	BLOWFISH_CBC_MECH_INFO_TYPE,	/* SUN_CKM_BLOWFISH_CBC */
	BLOWFISH_ECB_MECH_INFO_TYPE,	/* SUN_CKM_BLOWFISH_ECB */
	AES_CBC_MECH_INFO_TYPE,		/* SUN_CKM_AES_CBC */
	AES_ECB_MECH_INFO_TYPE,		/* SUN_CKM_AES_ECB */
	AES_CTR_MECH_INFO_TYPE,		/* SUN_CKM_AES_CTR */
	AES_CCM_MECH_INFO_TYPE,		/* SUN_CKM_AES_CCM */
	AES_GCM_MECH_INFO_TYPE,		/* SUN_CKM_AES_GCM */
	AES_GMAC_MECH_INFO_TYPE,	/* SUN_CKM_AES_GMAC */
	RC4_MECH_INFO_TYPE,		/* SUN_CKM_RC4 */
	RSA_PKCS_MECH_INFO_TYPE,	/* SUN_CKM_RSA_PKCS */
	RSA_X_509_MECH_INFO_TYPE,	/* SUN_CKM_RSA_X_509 */
	MD5_RSA_PKCS_MECH_INFO_TYPE,	/* SUN_CKM_MD5_RSA_PKCS */
	SHA1_RSA_PKCS_MECH_INFO_TYPE,	/* SUN_CKM_SHA1_RSA_PKCS */
	SHA256_RSA_PKCS_MECH_INFO_TYPE,	/* SUN_CKM_SHA256_RSA_PKCS */
	SHA384_RSA_PKCS_MECH_INFO_TYPE,	/* SUN_CKM_SHA384_RSA_PKCS */
	SHA512_RSA_PKCS_MECH_INFO_TYPE,	/* SUN_CKM_SHA512_RSA_PKCS */
	MD5_KEY_DERIVATION_MECH_INFO_TYPE, /* SUN_CKM_MD5_KEY_DERIVATION */
	SHA1_KEY_DERIVATION_MECH_INFO_TYPE, /* SUN_CKM_SHA1_KEY_DERIVATION */
	/* SUN_CKM_SHA256_KEY_DERIVATION */
	SHA256_KEY_DERIVATION_MECH_INFO_TYPE,
	/* SUN_CKM_SHA384_KEY_DERIVATION */
	SHA384_KEY_DERIVATION_MECH_INFO_TYPE,
	/* SUN_CKM_SHA512_KEY_DERIVATION */
	SHA512_KEY_DERIVATION_MECH_INFO_TYPE,
	DES_KEY_GEN_MECH_INFO_TYPE,	/* SUN_CKM_DES_KEY_GEN */
	DES3_KEY_GEN_MECH_INFO_TYPE,	/* SUN_CKM_DES3_KEY_GEN */
	AES_KEY_GEN_MECH_INFO_TYPE,	/* SUN_CKM_AES_KEY_GEN */
	BLOWFISH_KEY_GEN_MECH_INFO_TYPE,	/* SUN_CKM_BLOWFISH_KEY_GEN */
	RC4_KEY_GEN_MECH_INFO_TYPE,	/* SUN_CKM_RC4_KEY_GEN */
	EC_KEY_PAIR_GEN_MECH_INFO_TYPE,	/* SUN_CKM_EC_KEY_PAIR_GEN */
	ECDSA_MECH_INFO_TYPE,		/* SUN_CKM_ECDSA */
	ECDSA_SHA1_MECH_INFO_TYPE,	/* SUN_CKM_ECDSA_SHA1 */
	ECDH1_DERIVE_MECH_INFO_TYPE,	/* SUN_CKM_ECDH1_DERIVE */
	DH_PKCS_KEY_PAIR_GEN_MECH_INFO_TYPE, /* SUN_CKM_DH_PKCS_KEY_PAIR_GEN */
	DH_PKCS_DERIVE_MECH_INFO_TYPE,	/* SUN_CKM_DH_PKCS_DERIVE */
	RSA_PKCS_KEY_PAIR_GEN_MECH_INFO_TYPE /* SUN_CKM_RSA_PKCS_KEY_PAIR_GEN */
} dprov_mech_type_t;

/*
 * Mechanism info structure passed to KCF during registration.
 */
#define	MD5_DIGEST_LEN		16	/* MD5 digest size */
#define	MD5_HMAC_BLOCK_SIZE	64	/* MD5-HMAC block size */
#define	MD5_HMAC_MIN_KEY_LEN	1	/* MD5-HMAC min key length in bytes */
#define	MD5_HMAC_MAX_KEY_LEN	INT_MAX	/* MD5-HMAC max key length in bytes */

#define	SHA1_DIGEST_LEN		20	/* SHA1 digest size */
#define	SHA1_HMAC_BLOCK_SIZE	64	/* SHA1-HMAC block size */
#define	SHA1_HMAC_MIN_KEY_LEN	1	/* SHA1-HMAC min key length in bytes */
#define	SHA1_HMAC_MAX_KEY_LEN	INT_MAX	/* SHA1-HMAC max key length in bytes */

#define	DES_KEY_LEN		8	/* DES key length in bytes */
#define	DES3_KEY_LEN		24	/* DES3 key length in bytes */

#define	BLOWFISH_MIN_KEY_LEN	32	/* Blowfish min key length in bits */
#define	BLOWFISH_MAX_KEY_LEN	448	/* Blowfish max key length in bits */

#define	AES_MIN_KEY_LEN		16	/* AES min key length in bytes */
#define	AES_MAX_KEY_LEN		32	/* AES max key length in bytes */

#define	ARCFOUR_MIN_KEY_BITS	40	/* RC4 min supported key size */
#define	ARCFOUR_MAX_KEY_BITS	2048	/* RC4 max supported key size */

#define	RSA_MIN_KEY_LEN		256	/* RSA min key length in bits */
#define	RSA_MAX_KEY_LEN		4096	/* RSA max key length in bits */

#define	DH_MIN_KEY_LEN		64	/* DH min key length in bits */
#define	DH_MAX_KEY_LEN		4096	/* DH max key length in bits */

#define	DPROV_CKM_MD5_KEY_DERIVATION	"CKM_MD5_KEY_DERIVATION"
#define	DPROV_CKM_SHA1_KEY_DERIVATION	"CKM_SHA1_KEY_DERIVATION"
#define	DPROV_CKM_SHA256_KEY_DERIVATION	"CKM_SHA256_KEY_DERIVATION"
#define	DPROV_CKM_SHA384_KEY_DERIVATION	"CKM_SHA384_KEY_DERIVATION"
#define	DPROV_CKM_SHA512_KEY_DERIVATION	"CKM_SHA512_KEY_DERIVATION"
#define	DPROV_CKM_DES_KEY_GEN		"CKM_DES_KEY_GEN"
#define	DPROV_CKM_DES3_KEY_GEN		"CKM_DES3_KEY_GEN"
#define	DPROV_CKM_AES_KEY_GEN		"CKM_AES_KEY_GEN"
#define	DPROV_CKM_BLOWFISH_KEY_GEN	"CKM_BLOWFISH_KEY_GEN"
#define	DPROV_CKM_RC4_KEY_GEN		"CKM_RC4_KEY_GEN"
#define	DPROV_CKM_RSA_PKCS_KEY_PAIR_GEN	"CKM_RSA_PKCS_KEY_PAIR_GEN"
#define	DPROV_CKM_EC_KEY_PAIR_GEN	"CKM_EC_KEY_PAIR_GEN"
#define	DPROV_CKM_ECDSA			"CKM_ECDSA"
#define	DPROV_CKM_ECDSA_SHA1		"CKM_ECDSA_SHA1"
#define	DPROV_CKM_ECDH1_DERIVE		"CKM_ECDH1_DERIVE"
#define	DPROV_CKM_DH_PKCS_KEY_PAIR_GEN	"CKM_DH_PKCS_KEY_PAIR_GEN"
#define	DPROV_CKM_DH_PKCS_DERIVE	"CKM_DH_PKCS_DERIVE"

static crypto_mech_info_t dprov_mech_info_tab[] = {
	/* MD4 */
	{SUN_CKM_MD4, MD4_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC, 0, 0,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* MD5 */
	{SUN_CKM_MD5, MD5_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC, 0, 0,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* MD5-HMAC */
	{SUN_CKM_MD5_HMAC, MD5_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    MD5_HMAC_MIN_KEY_LEN, MD5_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* MD5-HMAC GENERAL */
	{SUN_CKM_MD5_HMAC_GENERAL, MD5_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    MD5_HMAC_MIN_KEY_LEN, MD5_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SHA1 */
	{SUN_CKM_SHA1, SHA1_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC, 0, 0,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA1-HMAC */
	{SUN_CKM_SHA1_HMAC, SHA1_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    SHA1_HMAC_MIN_KEY_LEN, SHA1_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SHA1-HMAC GENERAL */
	{SUN_CKM_SHA1_HMAC_GENERAL, SHA1_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    SHA1_HMAC_MIN_KEY_LEN, SHA1_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SHA256 */
	{SUN_CKM_SHA256, SHA256_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC, 0, 0,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA256-HMAC */
	{SUN_CKM_SHA256_HMAC, SHA256_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SHA256-HMAC GENERAL */
	{SUN_CKM_SHA256_HMAC_GENERAL, SHA256_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SHA384 */
	{SUN_CKM_SHA384, SHA384_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC, 0, 0,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA384-HMAC */
	{SUN_CKM_SHA384_HMAC, SHA384_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SHA384-HMAC GENERAL */
	{SUN_CKM_SHA384_HMAC_GENERAL, SHA384_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SHA512 */
	{SUN_CKM_SHA512, SHA512_MECH_INFO_TYPE,
	    CRYPTO_FG_DIGEST | CRYPTO_FG_DIGEST_ATOMIC, 0, 0,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA512-HMAC */
	{SUN_CKM_SHA512_HMAC, SHA512_HMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* SHA512-HMAC GENERAL */
	{SUN_CKM_SHA512_HMAC_GENERAL, SHA512_HMAC_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_MAC | CRYPTO_FG_MAC_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_ENCRYPT_MAC | CRYPTO_FG_MAC_DECRYPT |
	    CRYPTO_FG_ENCRYPT_MAC_ATOMIC | CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    SHA2_HMAC_MIN_KEY_LEN, SHA2_HMAC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* DES-CBC */
	{SUN_CKM_DES_CBC, DES_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    DES_KEY_LEN, DES_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* DES3-CBC */
	{SUN_CKM_DES3_CBC, DES3_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    DES3_KEY_LEN, DES3_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* DES-ECB */
	{SUN_CKM_DES_ECB, DES_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    DES_KEY_LEN, DES_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* DES3-ECB */
	{SUN_CKM_DES3_ECB, DES3_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    DES3_KEY_LEN, DES3_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* BLOWFISH-CBC */
	{SUN_CKM_BLOWFISH_CBC, BLOWFISH_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC, BLOWFISH_MIN_KEY_LEN,
	    BLOWFISH_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* BLOWFISH-ECB */
	{SUN_CKM_BLOWFISH_ECB, BLOWFISH_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC, BLOWFISH_MIN_KEY_LEN,
	    BLOWFISH_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* AES-CBC */
	{SUN_CKM_AES_CBC, AES_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES-ECB */
	{SUN_CKM_AES_ECB, AES_ECB_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES-CTR */
	{SUN_CKM_AES_CTR, AES_CTR_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES-CCM */
	{SUN_CKM_AES_CCM, AES_CCM_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES-GCM */
	{SUN_CKM_AES_GCM, AES_GCM_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES-GMAC */
	{SUN_CKM_AES_GMAC, AES_GMAC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_ENCRYPT_MAC |
	    CRYPTO_FG_MAC_DECRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT_ATOMIC | CRYPTO_FG_ENCRYPT_MAC_ATOMIC |
	    CRYPTO_FG_MAC_DECRYPT_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    AES_MIN_KEY_LEN, AES_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* RC4 */
	{SUN_CKM_RC4, RC4_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC,
	    ARCFOUR_MIN_KEY_BITS, ARCFOUR_MAX_KEY_BITS,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS | CRYPTO_CAN_SHARE_OPSTATE},
	/* RSA_PKCS */
	{SUN_CKM_RSA_PKCS, RSA_PKCS_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_SIGN_RECOVER | CRYPTO_FG_SIGN_RECOVER_ATOMIC |
	    CRYPTO_FG_VERIFY_RECOVER | CRYPTO_FG_VERIFY_RECOVER_ATOMIC,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* RSA_X_509 */
	{SUN_CKM_RSA_X_509, RSA_X_509_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_ENCRYPT_ATOMIC |
	    CRYPTO_FG_DECRYPT | CRYPTO_FG_DECRYPT_ATOMIC |
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC |
	    CRYPTO_FG_SIGN_RECOVER | CRYPTO_FG_SIGN_RECOVER_ATOMIC |
	    CRYPTO_FG_VERIFY_RECOVER | CRYPTO_FG_VERIFY_RECOVER_ATOMIC,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* MD5_RSA_PKCS */
	{SUN_CKM_MD5_RSA_PKCS, MD5_RSA_PKCS_MECH_INFO_TYPE,
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA1_RSA_PKCS */
	{SUN_CKM_SHA1_RSA_PKCS, SHA1_RSA_PKCS_MECH_INFO_TYPE,
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA256_RSA_PKCS */
	{SUN_CKM_SHA256_RSA_PKCS, SHA256_RSA_PKCS_MECH_INFO_TYPE,
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA384_RSA_PKCS */
	{SUN_CKM_SHA384_RSA_PKCS, SHA384_RSA_PKCS_MECH_INFO_TYPE,
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA512_RSA_PKCS */
	{SUN_CKM_SHA512_RSA_PKCS, SHA512_RSA_PKCS_MECH_INFO_TYPE,
	    CRYPTO_FG_SIGN | CRYPTO_FG_SIGN_ATOMIC |
	    CRYPTO_FG_VERIFY | CRYPTO_FG_VERIFY_ATOMIC,
	    RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* MD5_KEY_DERIVATION */
	{DPROV_CKM_MD5_KEY_DERIVATION, MD5_KEY_DERIVATION_MECH_INFO_TYPE,
	    CRYPTO_FG_DERIVE, 0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA1_KEY_DERIVATION */
	{DPROV_CKM_SHA1_KEY_DERIVATION, SHA1_KEY_DERIVATION_MECH_INFO_TYPE,
	    CRYPTO_FG_DERIVE, 0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA256_KEY_DERIVATION */
	{DPROV_CKM_SHA256_KEY_DERIVATION, SHA256_KEY_DERIVATION_MECH_INFO_TYPE,
	    CRYPTO_FG_DERIVE, 0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA384_KEY_DERIVATION */
	{DPROV_CKM_SHA384_KEY_DERIVATION, SHA384_KEY_DERIVATION_MECH_INFO_TYPE,
	    CRYPTO_FG_DERIVE, 0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* SHA512_KEY_DERIVATION */
	{DPROV_CKM_SHA512_KEY_DERIVATION, SHA512_KEY_DERIVATION_MECH_INFO_TYPE,
	    CRYPTO_FG_DERIVE, 0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* DES_KEY_GENERATION */
	{DPROV_CKM_DES_KEY_GEN, DES_KEY_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_GENERATE, DES_KEY_LEN, DES_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* DES3_KEY_GENERATION */
	{DPROV_CKM_DES3_KEY_GEN, DES3_KEY_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_GENERATE, DES3_KEY_LEN, DES3_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* AES_KEY_GENERATION */
	{DPROV_CKM_AES_KEY_GEN, AES_KEY_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_GENERATE, AES_MIN_KEY_LEN, AES_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* BLOWFISH_KEY_GENERATION */
	{DPROV_CKM_BLOWFISH_KEY_GEN, BLOWFISH_KEY_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_GENERATE, BLOWFISH_MIN_KEY_LEN, BLOWFISH_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* RC4_KEY_GENERATION */
	{DPROV_CKM_RC4_KEY_GEN, RC4_KEY_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_GENERATE, ARCFOUR_MIN_KEY_BITS, ARCFOUR_MAX_KEY_BITS,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* DH_PKCS_KEY_PAIR_GEN */
	{DPROV_CKM_DH_PKCS_KEY_PAIR_GEN, DH_PKCS_KEY_PAIR_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_GENERATE_KEY_PAIR, DH_MIN_KEY_LEN, DH_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* DH_PKCS_DERIVE */
	{DPROV_CKM_DH_PKCS_DERIVE, DH_PKCS_DERIVE_MECH_INFO_TYPE,
	    CRYPTO_FG_DERIVE, 0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* RSA_PKCS_KEY_PAIR_GEN */
	{DPROV_CKM_RSA_PKCS_KEY_PAIR_GEN, RSA_PKCS_KEY_PAIR_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_GENERATE_KEY_PAIR, RSA_MIN_KEY_LEN, RSA_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* EC_KEY_PAIR_GEN */
	{DPROV_CKM_EC_KEY_PAIR_GEN, EC_KEY_PAIR_GEN_MECH_INFO_TYPE,
	    CRYPTO_FG_GENERATE_KEY_PAIR, EC_MIN_KEY_LEN, EC_MAX_KEY_LEN,
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* ECDSA */
	{DPROV_CKM_ECDSA, ECDSA_MECH_INFO_TYPE,
	    CRYPTO_FG_SIGN | CRYPTO_FG_VERIFY |
	    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_VERIFY_ATOMIC |
	    EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* ECDSA_SHA1 */
	{DPROV_CKM_ECDSA_SHA1, ECDSA_SHA1_MECH_INFO_TYPE,
	    CRYPTO_FG_SIGN | CRYPTO_FG_VERIFY |
	    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_VERIFY_ATOMIC |
	    EC_MIN_KEY_LEN, EC_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BITS},
	/* ECDH1_DERIVE */
	{DPROV_CKM_ECDH1_DERIVE, ECDH1_DERIVE_MECH_INFO_TYPE,
	    CRYPTO_FG_DERIVE, 0, 0, CRYPTO_KEYSIZE_UNIT_IN_BITS}
};

/*
 * Crypto Values
 *
 * These values are the used in the STC ef test suite.  If they are changed
 * the test suite needs to be changed.
 */
static uchar_t dh_value[8] = { 'd', 'h', 'd', 'h', 'd', 'h', 'd', '\0' };
char public_exponent[3] = { 0x01, 0x00, 0x01 };
static uchar_t private_exponent[128] = {
	0x8e, 0xc9, 0x70, 0x57, 0x6b, 0xcd, 0xfb, 0xa9,
	0x19, 0xad, 0xcd, 0x91, 0x69, 0xd5, 0x52, 0xec,
	0x72, 0x1e, 0x45, 0x15, 0x06, 0xdc, 0x65, 0x2d,
	0x98, 0xc4, 0xce, 0x33, 0x54, 0x15, 0x70, 0x8d,
	0xfa, 0x65, 0xea, 0x53, 0x44, 0xf3, 0x3e, 0x3f,
	0xb4, 0x4c, 0x60, 0xd5, 0x01, 0x2d, 0xa4, 0x12,
	0x99, 0xbf, 0x3f, 0x0b, 0xcd, 0xbb, 0x24, 0x10,
	0x60, 0x30, 0x5e, 0x58, 0xf8, 0x59, 0xaa, 0xd1,
	0x63, 0x3b, 0xbc, 0xcb, 0x94, 0x58, 0x38, 0x24,
	0xfc, 0x65, 0x25, 0xc5, 0xa6, 0x51, 0xa2, 0x2e,
	0xf1, 0x5e, 0xf5, 0xc1, 0xf5, 0x46, 0xf7, 0xbd,
	0xc7, 0x62, 0xa8, 0xe2, 0x27, 0xd6, 0x94, 0x5b,
	0xd3, 0xa2, 0xb5, 0x76, 0x42, 0x67, 0x6b, 0x86,
	0x91, 0x97, 0x4d, 0x07, 0x92, 0x00, 0x4a, 0xdf,
	0x0b, 0x65, 0x64, 0x05, 0x03, 0x48, 0x27, 0xeb,
	0xce, 0x9a, 0x49, 0x7f, 0x3e, 0x10, 0xe0, 0x01
};

static uchar_t modulus[128] = {
	0x94, 0x32, 0xb9, 0x12, 0x1d, 0x68, 0x2c, 0xda,
	0x2b, 0xe0, 0xe4, 0x97, 0x1b, 0x4d, 0xdc, 0x43,
	0xdf, 0x38, 0x6e, 0x7b, 0x9f, 0x07, 0x58, 0xae,
	0x9d, 0x82, 0x1e, 0xc7, 0xbc, 0x92, 0xbf, 0xd3,
	0xce, 0x00, 0xbb, 0x91, 0xc9, 0x79, 0x06, 0x03,
	0x1f, 0xbc, 0x9f, 0x94, 0x75, 0x29, 0x5f, 0xd7,
	0xc5, 0xf3, 0x73, 0x8a, 0xa4, 0x35, 0x43, 0x7a,
	0x00, 0x32, 0x97, 0x3e, 0x86, 0xef, 0x70, 0x6f,
	0x18, 0x56, 0x15, 0xaa, 0x6a, 0x87, 0xe7, 0x8d,
	0x7d, 0xdd, 0x1f, 0xa4, 0xe4, 0x31, 0xd4, 0x7a,
	0x8c, 0x0e, 0x20, 0xd2, 0x23, 0xf5, 0x57, 0x3c,
	0x1b, 0xa8, 0x44, 0xa4, 0x57, 0x8f, 0x33, 0x52,
	0xad, 0x83, 0xae, 0x4a, 0x97, 0xa6, 0x1e, 0xa6,
	0x2b, 0xfa, 0xea, 0xeb, 0x6e, 0x71, 0xb8, 0xb6,
	0x0a, 0x36, 0xed, 0x83, 0xce, 0xb0, 0xdf, 0xc1,
	0xd4, 0x3a, 0xe9, 0x99, 0x6f, 0xf3, 0x96, 0xb7
};


static void dprov_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t dprov_control_ops = {
	dprov_provider_status
};

#define	DPROV_MANUFACTURER	"SUNW                            "
#define	DPROV_MODEL		"dprov           "
#define	DPROV_ALLSPACES		"                "

static int dprov_digest_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_req_handle_t);
static int dprov_digest(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_digest_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_digest_key(crypto_ctx_t *, crypto_key_t *,
    crypto_req_handle_t);
static int dprov_digest_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_digest_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);

static crypto_digest_ops_t dprov_digest_ops = {
	dprov_digest_init,
	dprov_digest,
	dprov_digest_update,
	dprov_digest_key,
	dprov_digest_final,
	dprov_digest_atomic
};

static int dprov_mac_init(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_mac(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_mac_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_mac_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_mac_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_mac_verify_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_mac_ops_t dprov_mac_ops = {
	dprov_mac_init,
	dprov_mac,
	dprov_mac_update,
	dprov_mac_final,
	dprov_mac_atomic,
	dprov_mac_verify_atomic
};

static int dprov_encrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_encrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_encrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int dprov_encrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_encrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static int dprov_decrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_decrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_decrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int dprov_decrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_decrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_cipher_ops_t dprov_cipher_ops = {
	dprov_encrypt_init,
	dprov_encrypt,
	dprov_encrypt_update,
	dprov_encrypt_final,
	dprov_encrypt_atomic,
	dprov_decrypt_init,
	dprov_decrypt,
	dprov_decrypt_update,
	dprov_decrypt_final,
	dprov_decrypt_atomic
};

static int dprov_sign_init(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_sign(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_sign_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_sign_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_sign_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_sign_recover_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_sign_recover(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_sign_recover_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t,
    crypto_req_handle_t);

static crypto_sign_ops_t dprov_sign_ops = {
	dprov_sign_init,
	dprov_sign,
	dprov_sign_update,
	dprov_sign_final,
	dprov_sign_atomic,
	dprov_sign_recover_init,
	dprov_sign_recover,
	dprov_sign_recover_atomic
};

static int dprov_verify_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_verify(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_verify_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_verify_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_verify_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_verify_recover_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_verify_recover(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int dprov_verify_recover_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t,
    crypto_req_handle_t);

static crypto_verify_ops_t dprov_verify_ops = {
	dprov_verify_init,
	dprov_verify,
	dprov_verify_update,
	dprov_verify_final,
	dprov_verify_atomic,
	dprov_verify_recover_init,
	dprov_verify_recover,
	dprov_verify_recover_atomic
};

static int dprov_digest_encrypt_update(crypto_ctx_t *, crypto_ctx_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
static int dprov_decrypt_digest_update(crypto_ctx_t *, crypto_ctx_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
static int dprov_sign_encrypt_update(crypto_ctx_t *, crypto_ctx_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
static int dprov_decrypt_verify_update(crypto_ctx_t *, crypto_ctx_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);

static crypto_dual_ops_t dprov_dual_ops = {
	dprov_digest_encrypt_update,
	dprov_decrypt_digest_update,
	dprov_sign_encrypt_update,
	dprov_decrypt_verify_update
};

static int dprov_encrypt_mac_init(crypto_ctx_t *,
    crypto_mechanism_t *, crypto_key_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_encrypt_mac(crypto_ctx_t *,
    crypto_data_t *, crypto_dual_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_encrypt_mac_update(crypto_ctx_t *,
    crypto_data_t *, crypto_dual_data_t *, crypto_req_handle_t);
static int dprov_encrypt_mac_final(crypto_ctx_t *,
    crypto_dual_data_t *, crypto_data_t *, crypto_req_handle_t);
static int dprov_encrypt_mac_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_dual_data_t *, crypto_data_t *, crypto_spi_ctx_template_t,
    crypto_spi_ctx_template_t, crypto_req_handle_t);

static int dprov_mac_decrypt_init(crypto_ctx_t *,
    crypto_mechanism_t *, crypto_key_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_mac_decrypt(crypto_ctx_t *,
    crypto_dual_data_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dprov_mac_decrypt_update(crypto_ctx_t *,
    crypto_dual_data_t *, crypto_data_t *, crypto_req_handle_t);
static int dprov_mac_decrypt_final(crypto_ctx_t *,
    crypto_data_t *, crypto_data_t *, crypto_req_handle_t);
static int dprov_mac_decrypt_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_mechanism_t *, crypto_key_t *, crypto_dual_data_t *,
    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dprov_mac_verify_decrypt_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_mechanism_t *, crypto_key_t *, crypto_dual_data_t *,
    crypto_data_t *, crypto_data_t *, crypto_spi_ctx_template_t,
    crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_dual_cipher_mac_ops_t dprov_cipher_mac_ops = {
	dprov_encrypt_mac_init,
	dprov_encrypt_mac,
	dprov_encrypt_mac_update,
	dprov_encrypt_mac_final,
	dprov_encrypt_mac_atomic,
	dprov_mac_decrypt_init,
	dprov_mac_decrypt,
	dprov_mac_decrypt_update,
	dprov_mac_decrypt_final,
	dprov_mac_decrypt_atomic,
	dprov_mac_verify_decrypt_atomic
};

static int dprov_seed_random(crypto_provider_handle_t, crypto_session_id_t,
    uchar_t *, size_t, uint_t, uint32_t, crypto_req_handle_t);
static int dprov_generate_random(crypto_provider_handle_t, crypto_session_id_t,
    uchar_t *, size_t, crypto_req_handle_t);

static crypto_random_number_ops_t dprov_random_number_ops = {
	dprov_seed_random,
	dprov_generate_random
};

static int dprov_session_open(crypto_provider_handle_t, crypto_session_id_t *,
    crypto_req_handle_t);
static int dprov_session_close(crypto_provider_handle_t, crypto_session_id_t,
    crypto_req_handle_t);
static int dprov_session_login(crypto_provider_handle_t, crypto_session_id_t,
    crypto_user_type_t, char *, size_t, crypto_req_handle_t);
static int dprov_session_logout(crypto_provider_handle_t, crypto_session_id_t,
    crypto_req_handle_t);

static crypto_session_ops_t dprov_session_ops = {
	dprov_session_open,
	dprov_session_close,
	dprov_session_login,
	dprov_session_logout
};

static int dprov_object_create(crypto_provider_handle_t, crypto_session_id_t,
    crypto_object_attribute_t *, uint_t, crypto_object_id_t *,
    crypto_req_handle_t);
static int dprov_object_copy(crypto_provider_handle_t, crypto_session_id_t,
    crypto_object_id_t, crypto_object_attribute_t *, uint_t,
    crypto_object_id_t *, crypto_req_handle_t);
static int dprov_object_destroy(crypto_provider_handle_t, crypto_session_id_t,
    crypto_object_id_t, crypto_req_handle_t);
static int dprov_object_get_size(crypto_provider_handle_t, crypto_session_id_t,
    crypto_object_id_t, size_t *, crypto_req_handle_t);
static int dprov_object_get_attribute_value(crypto_provider_handle_t,
    crypto_session_id_t, crypto_object_id_t,
    crypto_object_attribute_t *, uint_t, crypto_req_handle_t);
static int dprov_object_set_attribute_value(crypto_provider_handle_t,
    crypto_session_id_t, crypto_object_id_t,
    crypto_object_attribute_t *,  uint_t, crypto_req_handle_t);
static int dprov_object_find_init(crypto_provider_handle_t, crypto_session_id_t,
    crypto_object_attribute_t *, uint_t, void **,
    crypto_req_handle_t);
static int dprov_object_find(crypto_provider_handle_t, void *,
    crypto_object_id_t *, uint_t, uint_t *, crypto_req_handle_t);
static int dprov_object_find_final(crypto_provider_handle_t, void *,
    crypto_req_handle_t);

static crypto_object_ops_t dprov_object_ops = {
	dprov_object_create,
	dprov_object_copy,
	dprov_object_destroy,
	dprov_object_get_size,
	dprov_object_get_attribute_value,
	dprov_object_set_attribute_value,
	dprov_object_find_init,
	dprov_object_find,
	dprov_object_find_final
};

static int dprov_key_generate(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_object_attribute_t *, uint_t,
    crypto_object_id_t *, crypto_req_handle_t);
static int dprov_key_generate_pair(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_object_attribute_t *,
    uint_t, crypto_object_attribute_t *, uint_t, crypto_object_id_t *,
    crypto_object_id_t *, crypto_req_handle_t);
static int dprov_key_wrap(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_object_id_t *,
    uchar_t *, size_t *, crypto_req_handle_t);
static int dprov_key_unwrap(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, uchar_t *, size_t *,
    crypto_object_attribute_t *, uint_t,
    crypto_object_id_t *, crypto_req_handle_t);
static int dprov_key_derive(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_object_attribute_t *,
    uint_t, crypto_object_id_t *, crypto_req_handle_t);

static crypto_key_ops_t dprov_key_ops = {
	dprov_key_generate,
	dprov_key_generate_pair,
	dprov_key_wrap,
	dprov_key_unwrap,
	dprov_key_derive
};

static int dprov_ext_info(crypto_provider_handle_t,
    crypto_provider_ext_info_t *, crypto_req_handle_t);
static int dprov_init_token(crypto_provider_handle_t, char *, size_t,
    char *, crypto_req_handle_t);
static int dprov_init_pin(crypto_provider_handle_t, crypto_session_id_t,
    char *, size_t, crypto_req_handle_t);
static int dprov_set_pin(crypto_provider_handle_t, crypto_session_id_t,
    char *, size_t, char *, size_t, crypto_req_handle_t);

static crypto_provider_management_ops_t dprov_management_ops = {
	dprov_ext_info,
	dprov_init_token,
	dprov_init_pin,
	dprov_set_pin
};

static int dprov_free_context(crypto_ctx_t *);
static int dprov_copyin_mechanism(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_mechanism_t *, int *error, int);
static int dprov_copyout_mechanism(crypto_provider_handle_t,
    crypto_mechanism_t *, crypto_mechanism_t *, int *error, int);
static int dprov_free_mechanism(crypto_provider_handle_t,
    crypto_mechanism_t *);

static crypto_ctx_ops_t dprov_ctx_ops = {
	NULL,
	dprov_free_context
};

static crypto_mech_ops_t dprov_mech_ops = {
	dprov_copyin_mechanism,
	dprov_copyout_mechanism,
	dprov_free_mechanism
};

static int dprov_nostore_key_generate(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_object_attribute_t *,
    uint_t, crypto_object_attribute_t *, uint_t, crypto_req_handle_t);
static int dprov_nostore_key_generate_pair(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_object_attribute_t *,
    uint_t, crypto_object_attribute_t *, uint_t, crypto_object_attribute_t *,
    uint_t, crypto_object_attribute_t *, uint_t, crypto_req_handle_t);
static int dprov_nostore_key_derive(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_object_attribute_t *, uint_t, crypto_object_attribute_t *,
    uint_t, crypto_req_handle_t);

static crypto_nostore_key_ops_t dprov_nostore_key_ops = {
	dprov_nostore_key_generate,
	dprov_nostore_key_generate_pair,
	dprov_nostore_key_derive
};

static crypto_ops_t dprov_crypto_ops = {
	&dprov_control_ops,
	&dprov_digest_ops,
	&dprov_cipher_ops,
	&dprov_mac_ops,
	&dprov_sign_ops,
	&dprov_verify_ops,
	&dprov_dual_ops,
	&dprov_cipher_mac_ops,
	&dprov_random_number_ops,
	&dprov_session_ops,
	&dprov_object_ops,
	&dprov_key_ops,
	&dprov_management_ops,
	&dprov_ctx_ops,
	&dprov_mech_ops
};


/* maximum SO and user PIN lengths */
#define	DPROV_MAX_PIN_LEN	128

/*
 * Objects: each session is associated with an array of objects.
 * Unlike PKCS#11, the objects cannot be shared between sessions.
 * The ioctl driver multiplexes PKCS#11 sessions to providers
 * sessions in order to support this semantic. This simplifies
 * the CSPI greatly since the provider does not have to associate
 * sessions with a user space process.
 * There is also a per-instance array of objects, which correspond
 * to PKCS#11 token objects. These objects can be shared by multiple
 * sesions.
 *
 * Token objects are identified by having a CKA_TOKEN attribute B_TRUE.
 * Private objects are identified by having a CKA_PRIVATE attribute
 * set to B_TRUE.
 */

#define	DPROV_MAX_OBJECTS	128	/* max # of objects */
#define	DPROV_MAX_ATTR		64	/* max # of attributes per object */

/* object description */
typedef struct dprov_object {
	crypto_object_attribute_t do_attr[DPROV_MAX_ATTR]; /* attributes */
	uint_t do_token_idx;		/* index in per-instance table */
					/* for token objects. */
	boolean_t do_destroyed;		/* object has been destroyed. */
					/* keep object around until all */
					/* sessions that refer to it */
					/* are closed, but mark it */
					/* destroyed so that references */
					/* to the object fail. */
					/* used for token objects only */
	uint_t do_refcnt;
} dprov_object_t;

/*
 * If a session has a reference to a dprov_object_t,
 * it REFHOLD()s.
 */
#define	DPROV_OBJECT_REFHOLD(object) {		\
	atomic_inc_32(&(object)->do_refcnt);	\
	ASSERT((object)->do_refcnt != 0);		\
}

/*
 * Releases a reference to an object. When the last
 * reference is released, the object is freed.
 */
#define	DPROV_OBJECT_REFRELE(object) {				\
	ASSERT((object)->do_refcnt != 0);			\
	membar_exit();						\
	if (atomic_dec_32_nv(&(object)->do_refcnt) == 0)	\
		dprov_free_object(object);			\
}

/*
 * Object attributes are passed to the provider using crypto_object_attribute
 * structures, which contain the type of the attribute, a pointer to
 * it's value, and the length of its value. The attribute types values
 * are defined by the PKCS#11 specification. This provider only cares
 * about a subset of these attributes. In order to avoid having to
 * include the PKCS#11 header files, we define here the attributes values
 * which are used by the provider.
 */

#define	DPROV_CKA_CLASS			0x00000000
#define	DPROV_CKA_TOKEN			0x00000001
#define	DPROV_CKA_PRIVATE		0x00000002
#define	DPROV_CKA_VALUE			0x00000011
#define	DPROV_CKA_CERTIFICATE_TYPE	0x00000080
#define	DPROV_CKA_KEY_TYPE		0x00000100
#define	DPROV_CKA_SENSITIVE		0x00000103
#define	DPROV_CKA_ENCRYPT		0x00000104
#define	DPROV_CKA_DECRYPT		0x00000105
#define	DPROV_CKA_WRAP			0x00000106
#define	DPROV_CKA_UNWRAP		0x00000107
#define	DPROV_CKA_SIGN			0x00000108
#define	DPROV_CKA_SIGN_RECOVER		0x00000109
#define	DPROV_CKA_VERIFY		0x0000010A
#define	DPROV_CKA_VERIFY_RECOVER	0x0000010B
#define	DPROV_CKA_DERIVE		0x0000010C
#define	DPROV_CKA_MODULUS		0x00000120
#define	DPROV_CKA_MODULUS_BITS		0x00000121
#define	DPROV_CKA_PUBLIC_EXPONENT	0x00000122
#define	DPROV_CKA_PRIVATE_EXPONENT	0x00000123
#define	DPROV_CKA_PRIME			0x00000130
#define	DPROV_CKA_BASE			0x00000132
#define	DPROV_CKA_VALUE_BITS		0x00000160
#define	DPROV_CKA_VALUE_LEN		0x00000161
#define	DPROV_CKA_EXTRACTABLE		0x00000162
#define	DPROV_CKA_EC_PARAMS		0x00000180
#define	DPROV_CKA_EC_POINT		0x00000181
#define	DPROV_HW_FEATURE_TYPE		0x00000300

/*
 * Object classes from PKCS#11
 */
#define	DPROV_CKO_DATA			0x00000000
#define	DPROV_CKO_CERTIFICATE		0x00000001
#define	DPROV_CKO_PUBLIC_KEY		0x00000002
#define	DPROV_CKO_PRIVATE_KEY		0x00000003
#define	DPROV_CKO_SECRET_KEY		0x00000004
#define	DPROV_CKO_HW_FEATURE		0x00000005
#define	DPROV_CKO_DOMAIN_PARAMETERS	0x00000006
#define	DPROV_CKO_VENDOR_DEFINED	0x80000000

/*
 * A few key types from PKCS#11
 */
#define	DPROV_CKK_RSA			0x00000000
#define	DPROV_CKK_GENERIC_SECRET	0x00000010
#define	DPROV_CKK_RC4			0x00000012
#define	DPROV_CKK_DES			0x00000013
#define	DPROV_CKK_DES3			0x00000015
#define	DPROV_CKK_AES			0x0000001F
#define	DPROV_CKK_BLOWFISH		0x00000020

/*
 * Find object context. Allows the find object init/find/final
 * to store data persistent across calls.
 */
typedef struct dprov_find_ctx {
	crypto_object_id_t fc_ids[DPROV_MAX_OBJECTS];	/* object ids */
	uint_t fc_nids;			/* number of ids in fc_ids */
	uint_t fc_next;			/* next id to return */
} dprov_find_ctx_t;

/*
 * Session management: each instance is associated with an array
 * of sessions. KEF providers sessions are always R/W the library and
 * the ioctl maintain the PKCS#11 R/W attributes for the session.
 */

#define	DPROV_MIN_SESSIONS	32	/* # of sessions to start with */

typedef enum dprov_session_state {
	DPROV_SESSION_STATE_PUBLIC,	/* public (default) */
	DPROV_SESSION_STATE_SO,		/* SO logged in */
	DPROV_SESSION_STATE_USER	/* user logged in */
} dprov_session_state_t;

/* session description */
typedef struct dprov_session {
	dprov_session_state_t ds_state;	/* session state */
	dprov_object_t *ds_objects[DPROV_MAX_OBJECTS];	/* session objects */
} dprov_session_t;


static crypto_provider_info_t dprov_prov_info = {
	CRYPTO_SPI_VERSION_2,
	"Dummy Pseudo HW Provider",
	CRYPTO_HW_PROVIDER,
	NULL,				/* pi_provider_dev */
	NULL,				/* pi_provider_handle */
	&dprov_crypto_ops,
	sizeof (dprov_mech_info_tab)/sizeof (crypto_mech_info_t),
	dprov_mech_info_tab,
	0,				/* pi_logical_provider_count */
	NULL,				/* pi_logical_providers */
	0				/* pi_flags */
};

/*
 * Per-instance info.
 */
typedef struct dprov_state {
	kmutex_t ds_lock;		/* per-instance lock */
	dev_info_t *ds_dip;		/* device info */
	crypto_kcf_provider_handle_t ds_prov_handle;	/* framework handle */
	taskq_t *ds_taskq;		/* taskq for async behavior */
	char ds_user_pin[DPROV_MAX_PIN_LEN];	/* normal user PIN */
	uint_t ds_user_pin_len;
	char ds_so_pin[DPROV_MAX_PIN_LEN];	/* SO PIN */
	uint_t ds_so_pin_len;
	dprov_session_t **ds_sessions;	/* sessions for this instance */
	uint_t ds_sessions_slots;	/* number of session slots */
	uint_t ds_sessions_count;	/* number of open sessions */
	boolean_t ds_token_initialized;	/* provider initialized? */
	boolean_t ds_user_pin_set;	/* user pin set? */
	char ds_label[CRYPTO_EXT_SIZE_LABEL];		/* "token" label */
	dprov_object_t *ds_objects[DPROV_MAX_OBJECTS];	/* "token" objects */
} dprov_state_t;


/*
 * A taskq is associated with each instance of the pseudo driver in order
 * to simulate the asynchronous execution of requests.
 * The following defines the taskq request structures.
 */

/* request types */
typedef enum dprov_req_type {
	/* digest requests */
	DPROV_REQ_DIGEST_INIT = 1,
	DPROV_REQ_DIGEST,
	DPROV_REQ_DIGEST_UPDATE,
	DPROV_REQ_DIGEST_KEY,
	DPROV_REQ_DIGEST_FINAL,
	DPROV_REQ_DIGEST_ATOMIC,
	/* cipher requests */
	DPROV_REQ_ENCRYPT_INIT,
	DPROV_REQ_ENCRYPT,
	DPROV_REQ_ENCRYPT_UPDATE,
	DPROV_REQ_ENCRYPT_FINAL,
	DPROV_REQ_ENCRYPT_ATOMIC,
	DPROV_REQ_DECRYPT_INIT,
	DPROV_REQ_DECRYPT,
	DPROV_REQ_DECRYPT_UPDATE,
	DPROV_REQ_DECRYPT_FINAL,
	DPROV_REQ_DECRYPT_ATOMIC,
	/* mac requests */
	DPROV_REQ_MAC_INIT,
	DPROV_REQ_MAC,
	DPROV_REQ_MAC_UPDATE,
	DPROV_REQ_MAC_FINAL,
	DPROV_REQ_MAC_ATOMIC,
	DPROV_REQ_MAC_VERIFY_ATOMIC,
	/* sign requests */
	DPROV_REQ_SIGN_INIT,
	DPROV_REQ_SIGN,
	DPROV_REQ_SIGN_UPDATE,
	DPROV_REQ_SIGN_FINAL,
	DPROV_REQ_SIGN_ATOMIC,
	DPROV_REQ_SIGN_RECOVER_INIT,
	DPROV_REQ_SIGN_RECOVER,
	DPROV_REQ_SIGN_RECOVER_ATOMIC,
	/* verify requests */
	DPROV_REQ_VERIFY_INIT,
	DPROV_REQ_VERIFY,
	DPROV_REQ_VERIFY_UPDATE,
	DPROV_REQ_VERIFY_FINAL,
	DPROV_REQ_VERIFY_ATOMIC,
	DPROV_REQ_VERIFY_RECOVER_INIT,
	DPROV_REQ_VERIFY_RECOVER,
	DPROV_REQ_VERIFY_RECOVER_ATOMIC,
	/* dual ops requests */
	DPROV_REQ_DIGEST_ENCRYPT_UPDATE,
	DPROV_REQ_DECRYPT_DIGEST_UPDATE,
	DPROV_REQ_SIGN_ENCRYPT_UPDATE,
	DPROV_REQ_DECRYPT_VERIFY_UPDATE,
	/* dual cipher/mac requests */
	DPROV_REQ_ENCRYPT_MAC_INIT,
	DPROV_REQ_ENCRYPT_MAC,
	DPROV_REQ_ENCRYPT_MAC_UPDATE,
	DPROV_REQ_ENCRYPT_MAC_FINAL,
	DPROV_REQ_ENCRYPT_MAC_ATOMIC,
	DPROV_REQ_MAC_DECRYPT_INIT,
	DPROV_REQ_MAC_DECRYPT,
	DPROV_REQ_MAC_DECRYPT_UPDATE,
	DPROV_REQ_MAC_DECRYPT_FINAL,
	DPROV_REQ_MAC_DECRYPT_ATOMIC,
	DPROV_REQ_MAC_VERIFY_DECRYPT_ATOMIC,
	/* random number ops */
	DPROV_REQ_RANDOM_SEED,
	DPROV_REQ_RANDOM_GENERATE,
	/* session management requests */
	DPROV_REQ_SESSION_OPEN,
	DPROV_REQ_SESSION_CLOSE,
	DPROV_REQ_SESSION_LOGIN,
	DPROV_REQ_SESSION_LOGOUT,
	/* object management requests */
	DPROV_REQ_OBJECT_CREATE,
	DPROV_REQ_OBJECT_COPY,
	DPROV_REQ_OBJECT_DESTROY,
	DPROV_REQ_OBJECT_GET_SIZE,
	DPROV_REQ_OBJECT_GET_ATTRIBUTE_VALUE,
	DPROV_REQ_OBJECT_SET_ATTRIBUTE_VALUE,
	DPROV_REQ_OBJECT_FIND_INIT,
	DPROV_REQ_OBJECT_FIND,
	DPROV_REQ_OBJECT_FIND_FINAL,
	/* key management requests */
	DPROV_REQ_KEY_GENERATE,
	DPROV_REQ_KEY_GENERATE_PAIR,
	DPROV_REQ_KEY_WRAP,
	DPROV_REQ_KEY_UNWRAP,
	DPROV_REQ_KEY_DERIVE,
	/* provider management requests */
	DPROV_REQ_MGMT_EXTINFO,
	DPROV_REQ_MGMT_INITTOKEN,
	DPROV_REQ_MGMT_INITPIN,
	DPROV_REQ_MGMT_SETPIN,
	/* no (key)store key management requests */
	DPROV_REQ_NOSTORE_KEY_GENERATE,
	DPROV_REQ_NOSTORE_KEY_GENERATE_PAIR,
	DPROV_REQ_NOSTORE_KEY_DERIVE
} dprov_req_type_t;

/* for DPROV_REQ_DIGEST requests */
typedef struct dprov_digest_req {
	crypto_mechanism_t *dr_mechanism;
	crypto_ctx_t *dr_ctx;
	crypto_data_t *dr_data;
	crypto_key_t *dr_key;
	crypto_data_t *dr_digest;
} dprov_digest_req_t;

/* for DPROV_REQ_MAC requests */
typedef struct dprov_mac_req {
	crypto_mechanism_t *dr_mechanism;
	crypto_ctx_t *dr_ctx;
	crypto_key_t *dr_key;
	crypto_data_t *dr_data;
	crypto_data_t *dr_mac;
	crypto_session_id_t dr_session_id;
} dprov_mac_req_t;

/* for DPROV_REQ_ENCRYPT and DPROV_REQ_DECRYPT requests */
typedef struct dprov_cipher_req {
	crypto_mechanism_t *dr_mechanism;
	crypto_ctx_t *dr_ctx;
	crypto_key_t *dr_key;
	crypto_data_t *dr_plaintext;
	crypto_data_t *dr_ciphertext;
	crypto_session_id_t dr_session_id;
} dprov_cipher_req_t;

/* for DPROV_REQ_SIGN requests */
typedef struct dprov_sign_req {
	crypto_mechanism_t *sr_mechanism;
	crypto_ctx_t *sr_ctx;
	crypto_key_t *sr_key;
	crypto_data_t *sr_data;
	crypto_data_t *sr_signature;
	crypto_session_id_t sr_session_id;
} dprov_sign_req_t;

/* for DPROV_REQ_VERIFY requests */
typedef struct dprov_verify_req {
	crypto_mechanism_t *vr_mechanism;
	crypto_ctx_t *vr_ctx;
	crypto_key_t *vr_key;
	crypto_data_t *vr_data;
	crypto_data_t *vr_signature;
	crypto_session_id_t vr_session_id;
} dprov_verify_req_t;

/* for dual ops requests */
typedef struct dprov_dual_req {
	crypto_ctx_t *dr_signverify_ctx;
	crypto_ctx_t *dr_cipher_ctx;
	crypto_data_t *dr_plaintext;
	crypto_data_t *dr_ciphertext;
} dprov_dual_req_t;

/* for cipher/mac dual ops requests */
typedef struct dprov_cipher_mac_req {
	crypto_session_id_t mr_session_id;
	crypto_ctx_t *mr_ctx;
	crypto_mechanism_t *mr_cipher_mech;
	crypto_key_t *mr_cipher_key;
	crypto_mechanism_t *mr_mac_mech;
	crypto_key_t *mr_mac_key;
	crypto_dual_data_t *mr_dual_data;
	crypto_data_t *mr_data;
	crypto_data_t *mr_mac;
} dprov_cipher_mac_req_t;

/* for DPROV_REQ_RANDOM requests */
typedef struct dprov_random_req {
	uchar_t *rr_buf;
	size_t rr_len;
	crypto_session_id_t rr_session_id;
	uint_t rr_entropy_est;
	uint32_t rr_flags;
} dprov_random_req_t;

/* for DPROV_REQ_SESSION requests */
typedef struct dprov_session_req {
	crypto_session_id_t *sr_session_id_ptr;
	crypto_session_id_t sr_session_id;
	crypto_user_type_t sr_user_type;
	char *sr_pin;
	size_t sr_pin_len;
} dprov_session_req_t;

/* for DPROV_REQ_OBJECT requests */
typedef struct dprov_object_req {
	crypto_session_id_t or_session_id;
	crypto_object_id_t or_object_id;
	crypto_object_attribute_t *or_template;
	uint_t or_attribute_count;
	crypto_object_id_t *or_object_id_ptr;
	size_t *or_object_size;
	void **or_find_pp;
	void *or_find_p;
	uint_t or_max_object_count;
	uint_t *or_object_count_ptr;
} dprov_object_req_t;

/* for DPROV_REQ_KEY requests */
typedef struct dprov_key_req {
	crypto_session_id_t kr_session_id;
	crypto_mechanism_t *kr_mechanism;
	crypto_object_attribute_t *kr_template;
	uint_t kr_attribute_count;
	crypto_object_id_t *kr_object_id_ptr;
	crypto_object_attribute_t *kr_private_key_template;
	uint_t kr_private_key_attribute_count;
	crypto_object_id_t *kr_private_key_object_id_ptr;
	crypto_key_t *kr_key;
	uchar_t *kr_wrapped_key;
	size_t *kr_wrapped_key_len_ptr;
	crypto_object_attribute_t *kr_out_template1;
	crypto_object_attribute_t *kr_out_template2;
	uint_t kr_out_attribute_count1;
	uint_t kr_out_attribute_count2;
} dprov_key_req_t;

/* for DPROV_REQ_MGMT requests */
typedef struct dprov_mgmt_req {
	crypto_session_id_t mr_session_id;
	char *mr_pin;
	size_t mr_pin_len;
	char *mr_old_pin;
	size_t mr_old_pin_len;
	char *mr_label;
	crypto_provider_ext_info_t *mr_ext_info;
} dprov_mgmt_req_t;

/* request, as queued on taskq */
typedef struct dprov_req {
	dprov_req_type_t dr_type;
	dprov_state_t *dr_softc;
	crypto_req_handle_t dr_kcf_req;
	union {
		dprov_digest_req_t dru_digest_req;
		dprov_mac_req_t dru_mac_req;
		dprov_cipher_req_t dru_cipher_req;
		dprov_sign_req_t dru_sign_req;
		dprov_verify_req_t dru_verify_req;
		dprov_dual_req_t dru_dual_req;
		dprov_cipher_mac_req_t dru_cipher_mac_req;
		dprov_random_req_t dru_random_req;
		dprov_session_req_t dru_session_req;
		dprov_object_req_t dru_object_req;
		dprov_key_req_t dru_key_req;
		dprov_mgmt_req_t dru_mgmt_req;
	} dr_req;
} dprov_req_t;

/* shortcuts for union fields */
#define	dr_digest_req		dr_req.dru_digest_req
#define	dr_mac_req		dr_req.dru_mac_req
#define	dr_cipher_req		dr_req.dru_cipher_req
#define	dr_sign_req		dr_req.dru_sign_req
#define	dr_verify_req		dr_req.dru_verify_req
#define	dr_dual_req		dr_req.dru_dual_req
#define	dr_cipher_mac_req	dr_req.dru_cipher_mac_req
#define	dr_random_req		dr_req.dru_random_req
#define	dr_session_req		dr_req.dru_session_req
#define	dr_object_req		dr_req.dru_object_req
#define	dr_key_req		dr_req.dru_key_req
#define	dr_mgmt_req		dr_req.dru_mgmt_req

/* prototypes for the tasq dispatcher functions */
static void dprov_digest_task(dprov_req_t *);
static void dprov_mac_task(dprov_req_t *);
static void dprov_sign_task(dprov_req_t *);
static void dprov_verify_task(dprov_req_t *);
static void dprov_dual_task(dprov_req_t *);
static void dprov_cipher_task(dprov_req_t *);
static void dprov_cipher_mac_task(dprov_req_t *);
static void dprov_random_task(dprov_req_t *);
static void dprov_session_task(dprov_req_t *);
static void dprov_object_task(dprov_req_t *);
static void dprov_key_task(dprov_req_t *);
static void dprov_mgmt_task(dprov_req_t *);

/* helper functions */
static int dprov_digest_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_mechanism_t *, crypto_data_t *, crypto_key_t *,
    crypto_data_t *, crypto_ctx_t *, int);
static int dprov_cipher_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_ctx_t *, crypto_session_id_t, int);
static int dprov_mac_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_mechanism_t *, crypto_data_t *,
    crypto_key_t *, crypto_data_t *, crypto_ctx_t *, crypto_session_id_t, int);
static int dprov_sign_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_ctx_t *, crypto_session_id_t, int);
static int dprov_verify_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_data_t *, crypto_data_t *, crypto_ctx_t *, crypto_session_id_t, int);
static int dprov_dual_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_ctx_t *, crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *);
static int dprov_cipher_mac_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_ctx_t *, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_dual_data_t *, crypto_data_t *, crypto_data_t *, int);
static int dprov_random_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, uchar_t *, size_t, crypto_session_id_t, uint_t,
    uint32_t);
static int dprov_session_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_session_id_t *, crypto_session_id_t,
    crypto_user_type_t, char *, size_t);
static int dprov_object_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_session_id_t, crypto_object_id_t,
    crypto_object_attribute_t *, uint_t, crypto_object_id_t *, size_t *,
    void **, void *, uint_t, uint_t *, int);
static int dprov_key_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_session_id_t, crypto_mechanism_t *,
    crypto_object_attribute_t *, uint_t, crypto_object_id_t *,
    crypto_object_attribute_t *, uint_t, crypto_object_id_t *,
    crypto_key_t *, uchar_t *, size_t *, crypto_object_attribute_t *,
    uint_t, crypto_object_attribute_t *, uint_t);
static int dprov_mgmt_submit_req(dprov_req_type_t, dprov_state_t *,
    crypto_req_handle_t, crypto_session_id_t, char *, size_t, char *, size_t,
    char *, crypto_provider_ext_info_t *);
static int dprov_get_sw_prov(crypto_mechanism_t *, kcf_provider_desc_t **,
    crypto_mech_type_t *);

/* object management helper functions */
static void dprov_free_object(dprov_object_t *);
static void dprov_release_session_objects(dprov_session_t *);
static void dprov_adjust_attrs(crypto_object_attribute_t *, int);
static boolean_t dprov_object_is_private(dprov_object_t *);
static boolean_t dprov_object_is_token(dprov_object_t *);
static int dprov_key_value_secret(dprov_state_t *, crypto_session_id_t,
    dprov_req_type_t, crypto_key_t *, crypto_key_t *);
static int dprov_key_attr_asymmetric(dprov_state_t *, crypto_session_id_t,
    dprov_req_type_t, crypto_key_t *, crypto_key_t *);
static int dprov_get_object_attr_boolean(dprov_object_t *, uint64_t,
	boolean_t *);
static int dprov_get_object_attr_ulong(dprov_object_t *, uint64_t, ulong_t *);
static int dprov_get_object_attr_array(dprov_object_t *, uint64_t, void **,
    size_t *);
static int dprov_get_key_attr_ulong(crypto_key_t *, uint64_t, ulong_t *);
static int dprov_get_key_attr_array(crypto_key_t *, uint64_t, void **,
    size_t *);
static int dprov_create_object_from_template(dprov_state_t *, dprov_session_t *,
    crypto_object_attribute_t *, uint_t, crypto_object_id_t *, boolean_t,
    boolean_t);
static int dprov_get_template_attr_scalar_common(crypto_object_attribute_t *,
    uint_t, uint64_t, void *, size_t);
static int dprov_get_template_attr_boolean(crypto_object_attribute_t *,
    uint_t, uint64_t, boolean_t *);
static int dprov_get_template_attr_ulong(crypto_object_attribute_t *, uint_t,
    uint64_t, ulong_t *);
static int dprov_template_attr_present(crypto_object_attribute_t *, uint_t,
    uint64_t);
static int dprov_get_template_attr_array(crypto_object_attribute_t *, uint_t,
    uint64_t, void **, size_t *);
static int dprov_destroy_object(dprov_state_t *, dprov_session_t *,
    crypto_object_id_t);
static int dprov_object_set_attr(dprov_session_t *, crypto_object_id_t,
    crypto_object_attribute_t *, uint_t, boolean_t);
static int dprov_find_attr(crypto_object_attribute_t *, uint_t, uint64_t);
static boolean_t dprov_attributes_match(dprov_object_t *,
    crypto_object_attribute_t *, uint_t);

/* retrieve the softc and instance number from a SPI crypto context */
#define	DPROV_SOFTC_FROM_CTX(ctx, softc, instance) {	\
	(softc) = (dprov_state_t *)(ctx)->cc_provider;	\
	(instance) = ddi_get_instance((softc)->ds_dip);	\
}

/* retrieve the softc and instance number from a taskq request */
#define	DPROV_SOFTC_FROM_REQ(req, softc, instance) {	\
	(softc) = (req)->dr_softc;			\
	(instance) = ddi_get_instance((softc)->ds_dip);	\
}

/*
 * The dprov private context most of the time contains a pointer to the
 * crypto_context_t that was allocated when calling a KCF function.
 * Dual cipher/mac operations however require the dprov driver
 * to maintain the contexts associated with the separate cipher
 * and mac operations. These two types of dprov contexts are
 * defined below.
 */
typedef enum dprov_ctx_type {
	DPROV_CTX_SINGLE,
	DPROV_CTX_DUAL
} dprov_ctx_type_t;

/*
 * When the context refers to a single KCF context, the
 * cc_provider field of a crypto_ctx_t points to a structure of
 * type dprov_ctx_single.
 */
typedef struct dprov_ctx_single {
	dprov_ctx_type_t dc_type;
	crypto_context_t dc_ctx;
	boolean_t dc_svrfy_to_mac;
} dprov_ctx_single_t;

/*
 * When the context is used for cipher/mac operations, it contains
 * pointers to to KCF contexts, one for the cipher operation, the
 * other for the mac operation.
 */
typedef struct dprov_ctx_dual {
	dprov_ctx_type_t cd_type;
	crypto_context_t cd_cipher_ctx;
	crypto_context_t cd_mac_ctx;
} dprov_ctx_dual_t;

/*
 * Helper macros for context accessors. These macros return the
 * k-API context corresponding to the given SPI context for
 * single and dual cipher/mac operations.
 */

#define	DPROV_CTX_P(_ctx) \
	((dprov_ctx_single_t *)(_ctx)->cc_provider_private)

#define	DPROV_CTX_SINGLE(_ctx)	((DPROV_CTX_P(_ctx))->dc_ctx)

#define	DPROV_CTX_DUAL_CIPHER(_ctx) \
	(((dprov_ctx_dual_t *)(_ctx)->cc_provider_private)->cd_cipher_ctx)

#define	DPROV_CTX_DUAL_MAC(_ctx) \
	(((dprov_ctx_dual_t *)(_ctx)->cc_provider_private)->cd_mac_ctx)

static int dprov_alloc_context(dprov_req_type_t, crypto_ctx_t *);



static void *statep;	/* state pointer */

/*
 * DDI entry points.
 */
int
_init(void)
{
	int error;

	DPROV_DEBUG(D_INIT, ("dprov: in _init\n"));

	if ((error = ddi_soft_state_init(&statep, sizeof (dprov_state_t),
	    0)) != 0)
		return (error);

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	int error;

	DPROV_DEBUG(D_INIT, ("dprov: in _fini\n"));

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	ddi_soft_state_fini(&statep);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	DPROV_DEBUG(D_INIT, ("dprov: in _info\n"));

	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
dprov_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int instance = getminor((dev_t)arg);
	dprov_state_t *softc;

	DPROV_DEBUG(D_ATTACH, ("dprov: in dprov_getinfo() for %d\n",
	    instance));

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		softc = ddi_get_soft_state(statep, instance);
		*result = softc->ds_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
dprov_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	dprov_state_t *softc;
	char devname[256];
	int ret;

	DPROV_DEBUG(D_ATTACH, ("dprov: in dprov_attach() for %d\n",
	    instance));

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/* get new softc and initialize it */
	if (ddi_soft_state_zalloc(statep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	softc = ddi_get_soft_state(statep, instance);
	mutex_init(&softc->ds_lock, NULL, MUTEX_DRIVER, NULL);
	softc->ds_dip = dip;
	softc->ds_prov_handle = NULL;

	/* create minor node */
	(void) sprintf(devname, "dprov%d", instance);
	if (ddi_create_minor_node(dip, devname, S_IFCHR, instance,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "attach: failed creating minor node");
		mutex_destroy(&softc->ds_lock);
		ddi_soft_state_free(statep, instance);
		return (DDI_FAILURE);
	}

	nostore_key_gen = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "nostore_key_gen", 0);
	if (nostore_key_gen != 0) {
		dprov_prov_info.pi_interface_version = CRYPTO_SPI_VERSION_3;
		dprov_crypto_ops.co_object_ops = NULL;
		dprov_crypto_ops.co_nostore_key_ops = &dprov_nostore_key_ops;
	}

	dprov_max_digestsz = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "max_digest_sz", INT_MAX);
	if (dprov_max_digestsz != INT_MAX && dprov_max_digestsz != 0 &&
	    dprov_max_digestsz != DDI_PROP_NOT_FOUND) {
		dprov_no_multipart = B_TRUE;
		dprov_prov_info.pi_flags |=
		    (CRYPTO_HASH_NO_UPDATE | CRYPTO_HMAC_NO_UPDATE);
	}

	/* create taskq */
	softc->ds_taskq = taskq_create(devname, 1, minclsyspri,
	    crypto_taskq_minalloc, crypto_taskq_maxalloc, TASKQ_PREPOPULATE);

	/* initialize table of sessions */
	softc->ds_sessions = kmem_zalloc(DPROV_MIN_SESSIONS *
	    sizeof (dprov_session_t *), KM_SLEEP);
	softc->ds_sessions_slots = DPROV_MIN_SESSIONS;
	softc->ds_sessions_count = 0;

	/* initialized done by init_token entry point */
	softc->ds_token_initialized = B_TRUE;

	(void) memset(softc->ds_label, ' ', CRYPTO_EXT_SIZE_LABEL);
	bcopy("Dummy Pseudo HW Provider", softc->ds_label, 24);

	bcopy("changeme", softc->ds_user_pin, 8);
	softc->ds_user_pin_len = 8;
	softc->ds_user_pin_set = B_TRUE;

	/* register with the crypto framework */
	dprov_prov_info.pi_provider_dev.pd_hw = dip;
	dprov_prov_info.pi_provider_handle = softc;

	if (dprov_no_multipart) { /* Export only single part */
		dprov_digest_ops.digest_update = NULL;
		dprov_digest_ops.digest_key = NULL;
		dprov_digest_ops.digest_final = NULL;
		dprov_object_ops.object_create = NULL;
	}

	if ((ret = crypto_register_provider(&dprov_prov_info,
	    &softc->ds_prov_handle)) != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
		    "dprov crypto_register_provider() failed (0x%x)", ret);
		taskq_destroy(softc->ds_taskq);
		kmem_free(softc->ds_sessions, softc->ds_sessions_slots *
		    sizeof (dprov_session_t *));
		mutex_destroy(&softc->ds_lock);
		ddi_soft_state_free(statep, instance);
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	/*
	 * This call is for testing only; it is not required by the SPI.
	 */
	crypto_provider_notification(softc->ds_prov_handle,
	    CRYPTO_PROVIDER_READY);

	return (DDI_SUCCESS);
}

static int
dprov_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	dprov_state_t *softc = ddi_get_soft_state(statep, instance);
	dprov_session_t *session;
	int i, ret;

	DPROV_DEBUG(D_ATTACH, ("dprov: in dprov_detach() for %d\n",
	    instance));

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	/* unregister from the crypto framework */
	if (softc->ds_prov_handle != NULL)
		if ((ret = crypto_unregister_provider(
		    softc->ds_prov_handle)) != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "dprov_detach: "
			    "crypto_unregister_provider() "
			    "failed (0x%x)", ret);
			return (DDI_FAILURE);
		}


	taskq_destroy(softc->ds_taskq);

	for (i = 0; i < softc->ds_sessions_slots; i++) {
		if ((session = softc->ds_sessions[i]) == NULL)
			continue;

		dprov_release_session_objects(session);

		kmem_free(session, sizeof (dprov_session_t));
		softc->ds_sessions_count--;

	}

	kmem_free(softc->ds_sessions, softc->ds_sessions_slots *
	    sizeof (dprov_session_t *));
	/* free token objects */
	for (i = 0; i < DPROV_MAX_OBJECTS; i++)
		if (softc->ds_objects[i] != NULL)
			dprov_free_object(softc->ds_objects[i]);

	mutex_destroy(&softc->ds_lock);
	ddi_soft_state_free(statep, instance);

	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

/*
 * Control entry points.
 */
static void
dprov_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	_NOTE(ARGUNUSED(provider))

	*status = CRYPTO_PROVIDER_READY;
}

/*
 * Digest entry points.
 */

static int
dprov_digest_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_init: started\n", instance));

	/* check mechanism */
	if (mechanism->cm_type != MD4_MECH_INFO_TYPE &&
	    mechanism->cm_type != MD5_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA1_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA256_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA384_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA512_MECH_INFO_TYPE) {
		cmn_err(CE_WARN, "dprov_digest_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* submit request to the taskq */
	error = dprov_digest_submit_req(DPROV_REQ_DIGEST_INIT, softc, req,
	    mechanism, NULL, NULL, NULL, ctx, KM_SLEEP);

	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_init: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_digest(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	if (dprov_no_multipart && data->cd_length > dprov_max_digestsz)
		return (CRYPTO_BUFFER_TOO_BIG);

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest: started\n", instance));

	/* submit request to the taskq */
	error = dprov_digest_submit_req(DPROV_REQ_DIGEST, softc, req,
	    NULL, data, NULL, digest, ctx, KM_NOSLEEP);

	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest: done, err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_digest_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_update: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_digest_submit_req(DPROV_REQ_DIGEST_UPDATE, softc,
	    req, NULL, data, NULL, NULL, ctx, KM_NOSLEEP);

	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_update: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_digest_key(crypto_ctx_t *ctx, crypto_key_t *key, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_key: started\n", instance));

	/* submit request to the taskq */
	error = dprov_digest_submit_req(DPROV_REQ_DIGEST_KEY, softc, req, NULL,
	    NULL, key, NULL, ctx, KM_NOSLEEP);

	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_key: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_digest_final(crypto_ctx_t *ctx, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_final: started\n", instance));

	/* submit request to the taskq */
	error = dprov_digest_submit_req(DPROV_REQ_DIGEST_FINAL, softc, req,
	    NULL, NULL, NULL, digest, ctx, KM_NOSLEEP);

	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_final: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/* ARGSUSED */
static int
dprov_digest_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_data_t *data, crypto_data_t *digest,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	if (dprov_no_multipart && data->cd_length > dprov_max_digestsz)
		return (CRYPTO_BUFFER_TOO_BIG);

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_atomic: started\n",
	    instance));

	/* check mechanism */
	if (mechanism->cm_type != MD4_MECH_INFO_TYPE &&
	    mechanism->cm_type != MD5_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA1_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA256_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA384_MECH_INFO_TYPE &&
	    mechanism->cm_type != SHA512_MECH_INFO_TYPE) {
		cmn_err(CE_WARN, "dprov_digest_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* submit request to the taskq */
	error = dprov_digest_submit_req(DPROV_REQ_DIGEST_ATOMIC, softc, req,
	    mechanism, data, NULL, digest, NULL, KM_SLEEP);

	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_atomic: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/*
 * MAC entry points.
 */

/*
 * Checks whether the specified mech_type is supported by mac
 * entry points.
 */
static boolean_t
dprov_valid_mac_mech(crypto_mech_type_t mech_type)
{
	return (mech_type == MD5_HMAC_MECH_INFO_TYPE ||
	    mech_type == MD5_HMAC_GEN_MECH_INFO_TYPE ||
	    mech_type == SHA1_HMAC_MECH_INFO_TYPE ||
	    mech_type == SHA1_HMAC_GEN_MECH_INFO_TYPE ||
	    mech_type == SHA256_HMAC_MECH_INFO_TYPE ||
	    mech_type == SHA256_HMAC_GEN_MECH_INFO_TYPE ||
	    mech_type == SHA384_HMAC_MECH_INFO_TYPE ||
	    mech_type == SHA384_HMAC_GEN_MECH_INFO_TYPE ||
	    mech_type == SHA512_HMAC_MECH_INFO_TYPE ||
	    mech_type == SHA512_HMAC_GEN_MECH_INFO_TYPE ||
	    mech_type == AES_GMAC_MECH_INFO_TYPE);
}

static int
dprov_mac_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_init: started\n", instance));

	/* check mechanism */
	if (!dprov_valid_mac_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_mac_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_mac_submit_req(DPROV_REQ_MAC_INIT, softc, req,
	    mechanism, NULL, key, NULL, ctx, 0, KM_SLEEP);

	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_init: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_mac(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *mac,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac: started\n", instance));

	/* submit request to the taskq */
	error = dprov_mac_submit_req(DPROV_REQ_MAC, softc, req,
	    NULL, data, NULL, mac, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac: done, err = 0x%x\n", instance,
	    error));

	return (error);
}

static int
dprov_mac_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_update: started\n", instance));

	/* submit request to the taskq */
	error = dprov_mac_submit_req(DPROV_REQ_MAC_UPDATE, softc,
	    req, NULL, data, NULL, NULL, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_update: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_mac_final(crypto_ctx_t *ctx, crypto_data_t *mac, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_final: started\n", instance));

	/* submit request to the taskq */
	error = dprov_mac_submit_req(DPROV_REQ_MAC_FINAL, softc, req,
	    NULL, NULL, NULL, mac, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_final: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_mac_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_atomic: started\n", instance));

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	if (!dprov_valid_mac_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_mac_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* submit request to the taskq */
	error = dprov_mac_submit_req(DPROV_REQ_MAC_ATOMIC, softc, req,
	    mechanism, data, key, mac, NULL, session_id, KM_SLEEP);

	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_atomic: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_mac_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *mac,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_verify_atomic: started\n",
	    instance));

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	if (!dprov_valid_mac_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_mac_verify_atomic: unexpected mech "
		    "type 0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* submit request to the taskq */
	error = dprov_mac_submit_req(DPROV_REQ_MAC_VERIFY_ATOMIC, softc, req,
	    mechanism, data, key, mac, NULL, session_id, KM_SLEEP);

	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_verify_atomic: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/*
 * Cipher (encrypt/decrypt) entry points.
 */

/*
 * Checks whether the specified mech_type is supported by cipher entry
 * points.
 */
static boolean_t
dprov_valid_cipher_mech(crypto_mech_type_t mech_type)
{
	return (mech_type == DES_CBC_MECH_INFO_TYPE ||
	    mech_type == DES3_CBC_MECH_INFO_TYPE ||
	    mech_type == DES_ECB_MECH_INFO_TYPE ||
	    mech_type == DES3_ECB_MECH_INFO_TYPE ||
	    mech_type == BLOWFISH_CBC_MECH_INFO_TYPE ||
	    mech_type == BLOWFISH_ECB_MECH_INFO_TYPE ||
	    mech_type == AES_CBC_MECH_INFO_TYPE ||
	    mech_type == AES_ECB_MECH_INFO_TYPE ||
	    mech_type == AES_CTR_MECH_INFO_TYPE ||
	    mech_type == AES_CCM_MECH_INFO_TYPE ||
	    mech_type == AES_GCM_MECH_INFO_TYPE ||
	    mech_type == AES_GMAC_MECH_INFO_TYPE ||
	    mech_type == RC4_MECH_INFO_TYPE ||
	    mech_type == RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == RSA_X_509_MECH_INFO_TYPE ||
	    mech_type == MD5_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA1_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA256_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA384_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA512_RSA_PKCS_MECH_INFO_TYPE);
}

static boolean_t
is_publickey_mech(crypto_mech_type_t mech_type)
{
	return (mech_type == RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == RSA_X_509_MECH_INFO_TYPE ||
	    mech_type == MD5_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA1_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA256_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA384_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA512_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == ECDSA_SHA1_MECH_INFO_TYPE ||
	    mech_type == ECDSA_MECH_INFO_TYPE);
}


/* ARGSUSED */
static int
dprov_encrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_encrypt_init: started\n",
	    instance));

	/* check mechanism */
	if (!dprov_valid_cipher_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_encrypt_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* submit request to the taskq */
	error = dprov_cipher_submit_req(DPROV_REQ_ENCRYPT_INIT, softc,
	    req, mechanism, key, NULL, NULL, ctx, 0, KM_SLEEP);

	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_encrypt_init: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/* ARGSUSED */
static int
dprov_encrypt(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_encrypt: started\n", instance));

	/* submit request to the taskq */
	error = dprov_cipher_submit_req(DPROV_REQ_ENCRYPT, softc,
	    req, NULL, NULL, plaintext, ciphertext, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_encrypt: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/* ARGSUSED */
static int
dprov_encrypt_update(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_encrypt_update: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_cipher_submit_req(DPROV_REQ_ENCRYPT_UPDATE, softc,
	    req, NULL, NULL, plaintext, ciphertext, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_encrypt_update: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/* ARGSUSED */
static int
dprov_encrypt_final(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_encrypt_final: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_cipher_submit_req(DPROV_REQ_ENCRYPT_FINAL, softc,
	    req, NULL, NULL, NULL, ciphertext, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_encrypt_final: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_encrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_encrypt_atomic: started\n", instance));

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	if (!dprov_valid_cipher_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_encrypt_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	error = dprov_cipher_submit_req(DPROV_REQ_ENCRYPT_ATOMIC, softc,
	    req, mechanism, key, plaintext, ciphertext, NULL, session_id,
	    KM_SLEEP);

	DPROV_DEBUG(D_MAC, ("(%d) dprov_encrypt_atomic: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/* ARGSUSED */
static int
dprov_decrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_decrypt_init: started\n",
	    instance));

	/* check mechanism */
	if (!dprov_valid_cipher_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_decrypt_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	/* submit request to the taskq */
	error = dprov_cipher_submit_req(DPROV_REQ_DECRYPT_INIT, softc,
	    req, mechanism, key, NULL, NULL, ctx, 0, KM_SLEEP);

	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_decrypt_init: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/* ARGSUSED */
static int
dprov_decrypt(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;

	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_decrypt: started\n", instance));

	/* submit request to the taskq */
	error = dprov_cipher_submit_req(DPROV_REQ_DECRYPT, softc,
	    req, NULL, NULL, plaintext, ciphertext, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_decrypt: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/* ARGSUSED */
static int
dprov_decrypt_update(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_decrypt_update: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_cipher_submit_req(DPROV_REQ_DECRYPT_UPDATE, softc,
	    req, NULL, NULL, plaintext, ciphertext, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_decrypt_update: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/* ARGSUSED */
static int
dprov_decrypt_final(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_decrypt_final: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_cipher_submit_req(DPROV_REQ_DECRYPT_FINAL, softc,
	    req, NULL, NULL, plaintext, NULL, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_decrypt_final: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_decrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_decrypt_atomic: started\n", instance));

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	if (!dprov_valid_cipher_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_atomic_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	error = dprov_cipher_submit_req(DPROV_REQ_DECRYPT_ATOMIC, softc,
	    req, mechanism, key, plaintext, ciphertext, NULL, session_id,
	    KM_SLEEP);

	DPROV_DEBUG(D_MAC, ("(%d) dprov_decrypt_atomic: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/*
 * Sign entry points.
 */

/*
 * Checks whether the specified mech_type is supported by sign/verify
 * entry points.
 */
static boolean_t
dprov_valid_sign_verif_mech(crypto_mech_type_t mech_type)
{
	return (mech_type == MD5_HMAC_MECH_INFO_TYPE ||
	    mech_type == MD5_HMAC_GEN_MECH_INFO_TYPE ||
	    mech_type == SHA1_HMAC_MECH_INFO_TYPE ||
	    mech_type == SHA1_HMAC_GEN_MECH_INFO_TYPE ||
	    mech_type == SHA256_HMAC_MECH_INFO_TYPE ||
	    mech_type == SHA256_HMAC_GEN_MECH_INFO_TYPE ||
	    mech_type == SHA384_HMAC_MECH_INFO_TYPE ||
	    mech_type == SHA384_HMAC_GEN_MECH_INFO_TYPE ||
	    mech_type == SHA512_HMAC_MECH_INFO_TYPE ||
	    mech_type == SHA512_HMAC_GEN_MECH_INFO_TYPE ||
	    mech_type == RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == RSA_X_509_MECH_INFO_TYPE ||
	    mech_type == MD5_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA1_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA256_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA384_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == SHA512_RSA_PKCS_MECH_INFO_TYPE ||
	    mech_type == ECDSA_SHA1_MECH_INFO_TYPE ||
	    mech_type == ECDSA_MECH_INFO_TYPE);
}

static int
dprov_sign_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_init: started\n", instance));

	/* check mechanism */
	if (!dprov_valid_sign_verif_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_sign_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_sign_submit_req(DPROV_REQ_SIGN_INIT, softc, req,
	    mechanism, key, NULL, NULL, ctx, 0, KM_SLEEP);

	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_init: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_sign(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_data_t *signature, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign: started\n", instance));

	/* submit request to the taskq */
	error = dprov_sign_submit_req(DPROV_REQ_SIGN, softc, req,
	    NULL, NULL, data, signature, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_sign_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_update: started\n", instance));

	/* submit request to the taskq */
	error = dprov_sign_submit_req(DPROV_REQ_SIGN_UPDATE, softc, req,
	    NULL, NULL, data, NULL, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_update: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_sign_final(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_final: started\n", instance));

	/* submit request to the taskq */
	error = dprov_sign_submit_req(DPROV_REQ_SIGN_FINAL, softc, req,
	    NULL, NULL, NULL, signature, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_final: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_sign_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_atomic: started\n", instance));

	/* check mechanism */
	if (!dprov_valid_sign_verif_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_sign_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_sign_submit_req(DPROV_REQ_SIGN_ATOMIC, softc, req,
	    mechanism, key, data, signature, NULL, session_id, KM_SLEEP);

	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_atomic: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_sign_recover_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_recover_init: started\n",
	    instance));

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_sign_submit_req(DPROV_REQ_SIGN_RECOVER_INIT, softc, req,
	    mechanism, key, NULL, NULL, ctx, 0, KM_SLEEP);

	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_recover_init: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_sign_recover(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_data_t *signature, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_recover: started\n", instance));

	/* submit request to the taskq */
	error = dprov_sign_submit_req(DPROV_REQ_SIGN_RECOVER, softc, req,
	    NULL, NULL, data, signature, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_recover: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_sign_recover_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_recover_atomic: started\n",
	    instance));

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_sign_submit_req(DPROV_REQ_SIGN_RECOVER_ATOMIC, softc, req,
	    mechanism, key, data, signature, NULL, session_id, KM_SLEEP);

	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_recover_atomic: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

/*
 * Verify entry points.
 */

static int
dprov_verify_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_init: started\n", instance));

	/* check mechanism */
	if (!dprov_valid_sign_verif_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_verify_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	error = dprov_verify_submit_req(DPROV_REQ_VERIFY_INIT, softc, req,
	    mechanism, key, NULL, NULL, ctx, 0, KM_SLEEP);

	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_init: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_verify(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify: started\n", instance));

	/* submit request to the taskq */
	error = dprov_verify_submit_req(DPROV_REQ_VERIFY, softc, req,
	    NULL, NULL, data, signature, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_verify_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_update: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_verify_submit_req(DPROV_REQ_VERIFY_UPDATE, softc, req,
	    NULL, NULL, data, NULL, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_update: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_verify_final(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_final: started\n", instance));

	/* submit request to the taskq */
	error = dprov_verify_submit_req(DPROV_REQ_VERIFY_FINAL, softc, req,
	    NULL, NULL, NULL, signature, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_final: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_atomic: started\n",
	    instance));

	/* check mechanism */
	if (!dprov_valid_sign_verif_mech(mechanism->cm_type)) {
		cmn_err(CE_WARN, "dprov_verify_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_verify_submit_req(DPROV_REQ_VERIFY_ATOMIC, softc, req,
	    mechanism, key, data, signature, NULL, session_id, KM_SLEEP);

	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_atomic: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_verify_recover_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_recover_init: started\n",
	    instance));

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_verify_submit_req(DPROV_REQ_VERIFY_RECOVER_INIT, softc,
	    req, mechanism, key, NULL, NULL, ctx, 0, KM_SLEEP);

	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_recover_init: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_verify_recover(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_data_t *data, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_recover: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_verify_submit_req(DPROV_REQ_VERIFY_RECOVER, softc, req,
	    NULL, NULL, data, signature, ctx, 0, KM_NOSLEEP);

	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_recover: done err = 0x%x\n",
	    instance, error));

	return (error);
}

static int
dprov_verify_recover_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *signature, crypto_data_t *data,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_recover_atomic: started\n",
	    instance));

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_verify_submit_req(DPROV_REQ_VERIFY_RECOVER_ATOMIC, softc,
	    req, mechanism, key, data, signature, NULL, session_id, KM_SLEEP);

	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_recover_atomic: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

/*
 * Dual operations entry points.
 */

static int
dprov_digest_encrypt_update(crypto_ctx_t *digest_ctx,
    crypto_ctx_t *encrypt_ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(digest_ctx, softc, instance);
	DPROV_DEBUG(D_DUAL, ("(%d) dprov_digest_encrypt_update: started\n",
	    instance));

	if (digest_ctx->cc_provider != encrypt_ctx->cc_provider)
		return (CRYPTO_INVALID_CONTEXT);

	/* submit request to the taskq */
	error = dprov_dual_submit_req(DPROV_REQ_DIGEST_ENCRYPT_UPDATE,
	    softc, req, digest_ctx, encrypt_ctx, plaintext, ciphertext);

	DPROV_DEBUG(D_DUAL, ("(%d) dprov_digest_encrypt_update: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_decrypt_digest_update(crypto_ctx_t *decrypt_ctx, crypto_ctx_t *digest_ctx,
    crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(decrypt_ctx, softc, instance);
	DPROV_DEBUG(D_DUAL, ("(%d) dprov_decrypt_digest_update: started\n",
	    instance));

	if (decrypt_ctx->cc_provider != digest_ctx->cc_provider)
		return (CRYPTO_INVALID_CONTEXT);

	/* submit request to the taskq */
	error = dprov_dual_submit_req(DPROV_REQ_DECRYPT_DIGEST_UPDATE,
	    softc, req, digest_ctx, decrypt_ctx, plaintext, ciphertext);

	DPROV_DEBUG(D_DUAL, ("(%d) dprov_decrypt_digest_update: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_sign_encrypt_update(crypto_ctx_t *sign_ctx, crypto_ctx_t *encrypt_ctx,
    crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(sign_ctx, softc, instance);
	DPROV_DEBUG(D_DUAL, ("(%d) dprov_sign_encrypt_update: started\n",
	    instance));

	if (sign_ctx->cc_provider != encrypt_ctx->cc_provider)
		return (CRYPTO_INVALID_CONTEXT);

	/* submit request to the taskq */
	error = dprov_dual_submit_req(DPROV_REQ_SIGN_ENCRYPT_UPDATE,
	    softc, req, sign_ctx, encrypt_ctx, plaintext, ciphertext);

	DPROV_DEBUG(D_DUAL, ("(%d) dprov_sign_encrypt_update: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_decrypt_verify_update(crypto_ctx_t *decrypt_ctx, crypto_ctx_t *verify_ctx,
    crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(decrypt_ctx, softc, instance);
	DPROV_DEBUG(D_DUAL, ("(%d) dprov_decrypt_verify_update: started\n",
	    instance));

	if (decrypt_ctx->cc_provider != verify_ctx->cc_provider)
		return (CRYPTO_INVALID_CONTEXT);

	/* submit request to the taskq */
	error = dprov_dual_submit_req(DPROV_REQ_DECRYPT_VERIFY_UPDATE,
	    softc, req, verify_ctx, decrypt_ctx, plaintext, ciphertext);

	DPROV_DEBUG(D_DUAL, ("(%d) dprov_decrypt_verify_update: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

/*
 * Dual cipher-mac entry points.
 */

static int
dprov_encrypt_mac_init(crypto_ctx_t *ctx, crypto_mechanism_t *encrypt_mech,
    crypto_key_t *encrypt_key, crypto_mechanism_t *mac_mech,
    crypto_key_t *mac_key, crypto_spi_ctx_template_t encr_ctx_template,
    crypto_spi_ctx_template_t mac_ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_encrypt_mac_init: started\n",
	    instance));

	/* check mechanisms */
	if (!dprov_valid_cipher_mech(encrypt_mech->cm_type)) {
		cmn_err(CE_WARN, "dprov_encrypt_mac_init: unexpected encrypt "
		    "mech type 0x%llx\n",
		    (unsigned long long)encrypt_mech->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}
	if (!dprov_valid_mac_mech(mac_mech->cm_type)) {
		cmn_err(CE_WARN, "dprov_encrypt_mac_init: unexpected mac "
		    "mech type 0x%llx\n",
		    (unsigned long long)mac_mech->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (encr_ctx_template != NULL || mac_ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_ENCRYPT_MAC_INIT,
	    softc, req, ctx, 0, encrypt_mech, encrypt_key, mac_mech, mac_key,
	    NULL, NULL, NULL, KM_SLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_encrypt_mac_init: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_encrypt_mac(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_dual_data_t *ciphertext, crypto_data_t *mac, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_encrypt_mac: started\n",
	    instance));

	/*
	 * submit request to the taskq
	 * Careful! cihertext/plaintext order inversion
	 */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_ENCRYPT_MAC,
	    softc, req, ctx, 0, NULL, NULL, NULL, NULL,
	    ciphertext, plaintext, mac, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_encrypt_mac: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_encrypt_mac_update(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_dual_data_t *ciphertext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_encrypt_mac_update: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_ENCRYPT_MAC_UPDATE,
	    softc, req, ctx, 0, NULL, NULL, NULL, NULL,
	    ciphertext, plaintext, NULL, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_encrypt_mac_update: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_encrypt_mac_final(crypto_ctx_t *ctx,
    crypto_dual_data_t *ciphertext, crypto_data_t *mac,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_encrypt_mac_final: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_ENCRYPT_MAC_FINAL,
	    softc, req, ctx, 0, NULL, NULL, NULL, NULL,
	    ciphertext, NULL, mac, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_encrypt_mac_final: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_encrypt_mac_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *encrypt_mech,
    crypto_key_t *encrypt_key, crypto_mechanism_t *mac_mech,
    crypto_key_t *mac_key, crypto_data_t *plaintext,
    crypto_dual_data_t *ciphertext, crypto_data_t *mac,
    crypto_spi_ctx_template_t encr_ctx_template,
    crypto_spi_ctx_template_t mac_ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_encrypt_mac_atomic: started\n",
	    instance));

	/* check mechanisms */
	if (!dprov_valid_cipher_mech(encrypt_mech->cm_type)) {
		cmn_err(CE_WARN, "dprov_encrypt_mac_atomic: unexpected encrypt "
		    "mech type 0x%llx\n",
		    (unsigned long long)encrypt_mech->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}
	if (!dprov_valid_mac_mech(mac_mech->cm_type)) {
		cmn_err(CE_WARN, "dprov_encrypt_mac_atomic: unexpected mac "
		    "mech type 0x%llx\n",
		    (unsigned long long)mac_mech->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (encr_ctx_template != NULL || mac_ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_ENCRYPT_MAC_ATOMIC,
	    softc, req, NULL, session_id, encrypt_mech, encrypt_key, mac_mech,
	    mac_key, ciphertext, plaintext, mac, KM_SLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_encrypt_mac_atomic: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_mac_decrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mac_mech,
    crypto_key_t *mac_key, crypto_mechanism_t *decrypt_mech,
    crypto_key_t *decrypt_key, crypto_spi_ctx_template_t mac_ctx_template,
    crypto_spi_ctx_template_t decr_ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_decrypt_init: started\n",
	    instance));

	/* check mechanisms */
	if (!dprov_valid_cipher_mech(decrypt_mech->cm_type)) {
		cmn_err(CE_WARN, "dprov_mac_decrypt_init: unexpected decrypt "
		    "mech type 0x%llx\n",
		    (unsigned long long)decrypt_mech->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}
	if (!dprov_valid_mac_mech(mac_mech->cm_type)) {
		cmn_err(CE_WARN, "dprov_mac_decrypt_init: unexpected mac "
		    "mech type 0x%llx\n",
		    (unsigned long long)mac_mech->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (decr_ctx_template != NULL || mac_ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_MAC_DECRYPT_INIT,
	    softc, req, ctx, 0, decrypt_mech, decrypt_key, mac_mech, mac_key,
	    NULL, NULL, NULL, KM_SLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_decrypt_init: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_mac_decrypt(crypto_ctx_t *ctx, crypto_dual_data_t *ciphertext,
    crypto_data_t *mac, crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_decrypt: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_MAC_DECRYPT,
	    softc, req, ctx, 0, NULL, NULL, NULL, NULL,
	    ciphertext, plaintext, mac, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_decrypt: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_mac_decrypt_update(crypto_ctx_t *ctx, crypto_dual_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_decrypt_update: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_MAC_DECRYPT_UPDATE,
	    softc, req, ctx, 0, NULL, NULL, NULL, NULL,
	    ciphertext, plaintext, NULL, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_decrypt_update: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_mac_decrypt_final(crypto_ctx_t *ctx, crypto_data_t *mac,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	/* extract softc and instance number from context */
	DPROV_SOFTC_FROM_CTX(ctx, softc, instance);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_decrypt_final: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_MAC_DECRYPT_FINAL,
	    softc, req, ctx, 0, NULL, NULL, NULL, NULL,
	    NULL, plaintext, mac, KM_NOSLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_decrypt_final: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_mac_decrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mac_mech,
    crypto_key_t *mac_key, crypto_mechanism_t *decrypt_mech,
    crypto_key_t *decrypt_key, crypto_dual_data_t *ciphertext,
    crypto_data_t *mac, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t mac_ctx_template,
    crypto_spi_ctx_template_t decr_ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_decrypt_atomic: started\n",
	    instance));

	/* check mechanisms */
	if (!dprov_valid_cipher_mech(decrypt_mech->cm_type)) {
		cmn_err(CE_WARN, "dprov_mac_decrypt_atomic: unexpected encrypt "
		    "mech type 0x%llx\n",
		    (unsigned long long)decrypt_mech->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}
	if (!dprov_valid_mac_mech(mac_mech->cm_type)) {
		cmn_err(CE_WARN, "dprov_mac_decrypt_atomic: unexpected mac "
		    "mech type 0x%llx\n",
		    (unsigned long long)mac_mech->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (decr_ctx_template != NULL || mac_ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_MAC_DECRYPT_ATOMIC,
	    softc, req, NULL, session_id, decrypt_mech, decrypt_key, mac_mech,
	    mac_key, ciphertext, plaintext, mac, KM_SLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_decrypt_atomic: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

static int
dprov_mac_verify_decrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mac_mech,
    crypto_key_t *mac_key, crypto_mechanism_t *decrypt_mech,
    crypto_key_t *decrypt_key, crypto_dual_data_t *ciphertext,
    crypto_data_t *mac, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t mac_ctx_template,
    crypto_spi_ctx_template_t decr_ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_verify_decrypt_atomic:"
	    "started\n", instance));

	/* check mechanisms */
	if (!dprov_valid_cipher_mech(decrypt_mech->cm_type)) {
		cmn_err(CE_WARN, "dprov_mac_verify_decrypt_atomic: "
		    "unexpected encrypt mech type 0x%llx\n",
		    (unsigned long long)decrypt_mech->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}
	if (!dprov_valid_mac_mech(mac_mech->cm_type)) {
		cmn_err(CE_WARN, "dprov_mac_verify_decrypt_atomic: "
		    "unexpected mac mech type 0x%llx\n",
		    (unsigned long long)mac_mech->cm_type);
		return (CRYPTO_MECHANISM_INVALID);
	}

	if (decr_ctx_template != NULL || mac_ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* submit request to the taskq */
	error = dprov_cipher_mac_submit_req(DPROV_REQ_MAC_VERIFY_DECRYPT_ATOMIC,
	    softc, req, NULL, session_id, decrypt_mech, decrypt_key, mac_mech,
	    mac_key, ciphertext, plaintext, mac, KM_SLEEP);

	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_mac_verify_decrypt_atomic: done "
	    "err = 0x%x\n", instance, error));

	return (error);
}

/*
 * Random number entry points.
 */

static int
dprov_seed_random(crypto_provider_handle_t provider,  crypto_session_id_t sid,
    uchar_t *buf, size_t len, uint_t entropy_est, uint32_t flags,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_RANDOM, ("(%d) dprov_seed_random: started\n",
	    instance));

	error = dprov_random_submit_req(DPROV_REQ_RANDOM_SEED, softc,
	    req, buf, len, sid, entropy_est, flags);

	DPROV_DEBUG(D_RANDOM, ("(%d) dprov_seed_random: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_generate_random(crypto_provider_handle_t provider,
    crypto_session_id_t sid, uchar_t *buf, size_t len, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_RANDOM, ("(%d) dprov_generate_random: started\n",
	    instance));

	error = dprov_random_submit_req(DPROV_REQ_RANDOM_GENERATE, softc,
	    req, buf, len, sid, 0, 0);

	DPROV_DEBUG(D_RANDOM, ("(%d) dprov_generate_random: done "
	    "err = 0x0%x\n", instance, error));

	return (error);
}

/*
 * Session Management entry points.
 */

static int
dprov_session_open(crypto_provider_handle_t provider,
    crypto_session_id_t *session_id, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_SESSION, ("(%d) dprov_session_open: started\n",
	    instance));

	error = dprov_session_submit_req(DPROV_REQ_SESSION_OPEN, softc,
	    req, session_id, 0, 0, NULL, 0);

	DPROV_DEBUG(D_SESSION, ("(%d) dprov_session_open: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_session_close(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_SESSION, ("(%d) dprov_session_close: started\n",
	    instance));

	error = dprov_session_submit_req(DPROV_REQ_SESSION_CLOSE, softc,
	    req, 0, session_id, 0, NULL, 0);

	DPROV_DEBUG(D_SESSION, ("(%d) dprov_session_close: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_session_login(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_user_type_t user_type,
    char *pin, size_t pin_len, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_SESSION, ("(%d) dprov_session_login: started\n",
	    instance));

	error = dprov_session_submit_req(DPROV_REQ_SESSION_LOGIN, softc,
	    req, 0, session_id, user_type, pin, pin_len);

	DPROV_DEBUG(D_SESSION, ("(%d) dprov_session_login: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_session_logout(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_SESSION, ("(%d) dprov_session_logout: started\n",
	    instance));

	error = dprov_session_submit_req(DPROV_REQ_SESSION_LOGOUT, softc,
	    req, 0, session_id, 0, NULL, 0);

	DPROV_DEBUG(D_SESSION, ("(%d) dprov_session_logout: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/*
 * Object management entry points.
 */

static int
dprov_object_create(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_attribute_t *template,
    uint_t attribute_count, crypto_object_id_t *object,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_create: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_object_submit_req(DPROV_REQ_OBJECT_CREATE, softc, req,
	    session_id, 0, template, attribute_count, object, NULL, NULL,
	    NULL, 0, NULL, KM_NOSLEEP);

	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_create: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_object_copy(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_id_t object,
    crypto_object_attribute_t *template, uint_t attribute_count,
    crypto_object_id_t *new_object, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_copy: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_object_submit_req(DPROV_REQ_OBJECT_COPY, softc, req,
	    session_id, object, template, attribute_count, new_object,
	    NULL, NULL, NULL, 0, NULL, KM_NOSLEEP);

	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_copy: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_object_destroy(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_id_t object,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_destroy: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_object_submit_req(DPROV_REQ_OBJECT_DESTROY, softc, req,
	    session_id, object, NULL, 0, NULL, NULL, NULL, NULL, 0, NULL,
	    KM_NOSLEEP);

	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_destroy: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_object_get_size(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_id_t object,
    size_t *size, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_get_size: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_object_submit_req(DPROV_REQ_OBJECT_GET_SIZE, softc, req,
	    session_id, object, NULL, 0, NULL, size, NULL, NULL, 0, NULL,
	    KM_NOSLEEP);

	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_get_size: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_object_get_attribute_value(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_id_t object,
    crypto_object_attribute_t *template, uint_t attribute_count,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_get_attribute_value: "
	    "started\n", instance));

	/* submit request to the taskq */
	error = dprov_object_submit_req(DPROV_REQ_OBJECT_GET_ATTRIBUTE_VALUE,
	    softc, req, session_id, object, template, attribute_count,
	    NULL, NULL, NULL, NULL, 0, NULL, KM_NOSLEEP);

	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_get_attribute_value: "
	    "done err = 0x0%x\n", instance, error));

	return (error);
}

static int
dprov_object_set_attribute_value(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_id_t object,
    crypto_object_attribute_t *template, uint_t attribute_count,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_set_attribute_value: "
	    "started\n", instance));

	/* submit request to the taskq */
	error = dprov_object_submit_req(DPROV_REQ_OBJECT_SET_ATTRIBUTE_VALUE,
	    softc, req, session_id, object, template, attribute_count,
	    NULL, NULL, NULL, NULL, 0, NULL, KM_NOSLEEP);

	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_set_attribute_value: "
	    "done err = 0x0%x\n", instance, error));

	return (error);
}

static int
dprov_object_find_init(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_object_attribute_t *template,
    uint_t attribute_count, void **provider_private,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_find_init: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_object_submit_req(DPROV_REQ_OBJECT_FIND_INIT, softc, req,
	    session_id, 0, template, attribute_count, NULL, NULL,
	    provider_private, NULL, 0, NULL, KM_SLEEP);

	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_find_init: done "
	    "err = 0x0%x\n", instance, error));

	return (error);
}

static int
dprov_object_find(crypto_provider_handle_t provider, void *provider_private,
    crypto_object_id_t *objects, uint_t max_object_count,
    uint_t *object_count, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_find: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_object_submit_req(DPROV_REQ_OBJECT_FIND, softc, req,
	    0, 0, NULL, 0, objects, NULL, NULL, provider_private,
	    max_object_count, object_count, KM_NOSLEEP);


	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_find: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_object_find_final(crypto_provider_handle_t provider,
    void *provider_private, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_find_final: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_object_submit_req(DPROV_REQ_OBJECT_FIND_FINAL, softc, req,
	    0, 0, NULL, 0, NULL, NULL, NULL, provider_private,
	    0, NULL, KM_NOSLEEP);

	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_find_final: done "
	    "err = 0x0%x\n", instance, error));

	return (error);
}

/*
 * Key management entry points.
 */

static int
dprov_key_generate(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_object_attribute_t *template, uint_t attribute_count,
    crypto_object_id_t *object, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_generate: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_key_submit_req(DPROV_REQ_KEY_GENERATE, softc, req,
	    session_id, mechanism, template, attribute_count, object, NULL,
	    0, NULL, NULL, NULL, 0, NULL, 0, NULL, 0);

	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_generate: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_key_generate_pair(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_object_attribute_t *public_key_template,
    uint_t public_key_attribute_count,
    crypto_object_attribute_t *private_key_template,
    uint_t private_key_attribute_count,
    crypto_object_id_t *public_key, crypto_object_id_t *private_key,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_generate_pair: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_key_submit_req(DPROV_REQ_KEY_GENERATE_PAIR, softc, req,
	    session_id, mechanism, public_key_template,
	    public_key_attribute_count, public_key, private_key_template,
	    private_key_attribute_count, private_key, NULL, NULL, 0, NULL, 0,
	    NULL, 0);

	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_generate_pair: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_key_wrap(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *wrapping_key, crypto_object_id_t *key,
    uchar_t *wrapped_key, size_t *wrapped_key_len_ptr, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_wrap: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_key_submit_req(DPROV_REQ_KEY_WRAP, softc, req,
	    session_id, mechanism, NULL, 0, key, NULL,
	    0, NULL, wrapping_key, wrapped_key, wrapped_key_len_ptr,
	    NULL, 0, NULL, 0);

	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_wrap: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_key_unwrap(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *unwrapping_key, uchar_t *wrapped_key,
    size_t *wrapped_key_len_ptr, crypto_object_attribute_t *template,
    uint_t attribute_count, crypto_object_id_t *key, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_unwrap: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_key_submit_req(DPROV_REQ_KEY_UNWRAP, softc, req,
	    session_id, mechanism, template, attribute_count, key, NULL,
	    0, NULL, unwrapping_key, wrapped_key, wrapped_key_len_ptr,
	    NULL, 0, NULL, 0);

	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_unwrap: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_key_derive(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *base_key, crypto_object_attribute_t *template,
    uint_t attribute_count, crypto_object_id_t *key, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_derive: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_key_submit_req(DPROV_REQ_KEY_DERIVE, softc, req,
	    session_id, mechanism, template, attribute_count, key, NULL,
	    0, NULL, base_key, NULL, 0, NULL, 0, NULL, 0);

	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_derive: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

/*
 * Provider management entry points.
 */

static int
dprov_ext_info(crypto_provider_handle_t provider,
    crypto_provider_ext_info_t *ext_info, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_MGMT, ("(%d) dprov_ext_info: started\n",
	    instance));

	error = dprov_mgmt_submit_req(DPROV_REQ_MGMT_EXTINFO, softc, req,
	    0, NULL, 0, NULL, 0, NULL, ext_info);

	DPROV_DEBUG(D_MGMT, ("(%d) dprov_ext_info: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_init_token(crypto_provider_handle_t provider, char *pin, size_t pin_len,
    char *label, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_MGMT, ("(%d) dprov_init_token: started\n",
	    instance));

	error = dprov_mgmt_submit_req(DPROV_REQ_MGMT_INITTOKEN, softc, req,
	    0, pin, pin_len, NULL, 0, label, NULL);

	DPROV_DEBUG(D_MGMT, ("(%d) dprov_init_token: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_init_pin(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, char *pin, size_t pin_len,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_MGMT, ("(%d) dprov_init_pin: started\n",
	    instance));

	error = dprov_mgmt_submit_req(DPROV_REQ_MGMT_INITPIN, softc, req,
	    session_id, pin, pin_len, NULL, 0, NULL, NULL);

	DPROV_DEBUG(D_MGMT, ("(%d) dprov_init_pin: done err = 0x0%x\n",
	    instance, error));

	return (error);
}

static int
dprov_set_pin(crypto_provider_handle_t provider, crypto_session_id_t session_id,
    char *old_pin, size_t old_pin_len, char *new_pin, size_t new_pin_len,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_MGMT, ("(%d) dprov_set_pin: started\n",
	    instance));

	error = dprov_mgmt_submit_req(DPROV_REQ_MGMT_SETPIN, softc, req,
	    session_id, new_pin, new_pin_len, old_pin, old_pin_len, NULL, NULL);

	DPROV_DEBUG(D_MGMT, ("(%d) dprov_set_pin: done err = 0x0%x\n",
	    instance, error));

	return (error);
}


/*
 * Context management entry points.
 */

/*
 * Allocate a dprov-private context based on the specified dprov request.
 * For dual cipher/mac requests, the allocated context will
 * contain a structure dprov_ctx_dual_t, for other request types,
 * it will contain a dprov_ctx_single.
 * Returns one of the CRYPTO_ status codes.
 */
static int
dprov_alloc_context(dprov_req_type_t req_type, crypto_ctx_t *spi_ctx)
{
	dprov_ctx_single_t *dprov_private;

	switch (req_type) {
	case DPROV_REQ_ENCRYPT_MAC_INIT:
	case DPROV_REQ_MAC_DECRYPT_INIT:
		dprov_private = kmem_zalloc(sizeof (dprov_ctx_dual_t),
		    KM_NOSLEEP);
		if (dprov_private == NULL)
			return (CRYPTO_HOST_MEMORY);
		dprov_private->dc_type = DPROV_CTX_DUAL;
		break;
	default:
		dprov_private = kmem_zalloc(sizeof (dprov_ctx_single_t),
		    KM_NOSLEEP);
		if (dprov_private == NULL)
			return (CRYPTO_HOST_MEMORY);
		dprov_private->dc_type = DPROV_CTX_SINGLE;
		dprov_private->dc_svrfy_to_mac = B_FALSE;
		break;
	}

	spi_ctx->cc_provider_private = (void *)dprov_private;

	return (CRYPTO_SUCCESS);
}

static int
dprov_free_context(crypto_ctx_t *ctx)
{
	if (ctx->cc_provider_private == NULL)
		return (CRYPTO_SUCCESS);

	DPROV_DEBUG(D_CONTEXT, ("dprov_free_context\n"));

	{
		/*
		 * The dprov private context could contain either
		 * a dprov_ctx_single_t or a dprov_ctx_dual_t. Free
		 * the context based on its type. The k-API contexts
		 * that were attached to the dprov private context
		 * are freed by the framework.
		 */
		dprov_ctx_single_t *ctx_single =
		    (dprov_ctx_single_t *)(ctx->cc_provider_private);

		if (ctx_single->dc_type == DPROV_CTX_SINGLE) {
			crypto_context_t context = DPROV_CTX_SINGLE(ctx);

			/*
			 * This case happens for the crypto_cancel_ctx() case.
			 * We have to cancel the SW provider context also.
			 */
			if (context != NULL)
				crypto_cancel_ctx(context);

			kmem_free(ctx_single, sizeof (dprov_ctx_single_t));
		} else {
			crypto_context_t cipher_context =
			    DPROV_CTX_DUAL_CIPHER(ctx);
			crypto_context_t mac_context = DPROV_CTX_DUAL_MAC(ctx);

			/* See comments above. */
			if (cipher_context != NULL)
				crypto_cancel_ctx(cipher_context);
			if (mac_context != NULL)
				crypto_cancel_ctx(mac_context);

			ASSERT(ctx_single->dc_type == DPROV_CTX_DUAL);
			kmem_free(ctx_single, sizeof (dprov_ctx_dual_t));
		}
		ctx->cc_provider_private = NULL;
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Resource control checks don't need to be done. Why? Because this routine
 * knows the size of the structure, and it can't be overridden by a user.
 * This is different from the crypto module, which has no knowledge of
 * specific mechanisms, and therefore has to trust specified size of the
 * parameter.  This trust, or lack of trust, is why the size of the
 * parameter has to be charged against the project resource control.
 */
static int
copyin_aes_ccm_mech(crypto_mechanism_t *in_mech, crypto_mechanism_t *out_mech,
    int *out_error, int mode)
{
	STRUCT_DECL(crypto_mechanism, mech);
	STRUCT_DECL(CK_AES_CCM_PARAMS, params);
	CK_AES_CCM_PARAMS *aes_ccm_params;
	caddr_t pp;
	size_t param_len;
	int error = 0;
	int rv = 0;

	STRUCT_INIT(mech, mode);
	STRUCT_INIT(params, mode);
	bcopy(in_mech, STRUCT_BUF(mech), STRUCT_SIZE(mech));
	pp = STRUCT_FGETP(mech, cm_param);
	param_len = STRUCT_FGET(mech, cm_param_len);

	if (param_len != STRUCT_SIZE(params)) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	out_mech->cm_type = STRUCT_FGET(mech, cm_type);
	out_mech->cm_param = NULL;
	out_mech->cm_param_len = 0;
	if (pp != NULL) {
		size_t nonce_len, auth_data_len, total_param_len;

		if (copyin((char *)pp, STRUCT_BUF(params), param_len) != 0) {
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}

		nonce_len = STRUCT_FGET(params, ulNonceSize);
		auth_data_len = STRUCT_FGET(params, ulAuthDataSize);

		/* allocate param structure */
		total_param_len =
		    sizeof (CK_AES_CCM_PARAMS) + nonce_len + auth_data_len;
		aes_ccm_params = kmem_alloc(total_param_len, KM_NOSLEEP);
		if (aes_ccm_params == NULL) {
			rv = CRYPTO_HOST_MEMORY;
			goto out;
		}
		aes_ccm_params->ulMACSize = STRUCT_FGET(params, ulMACSize);
		aes_ccm_params->ulNonceSize = nonce_len;
		aes_ccm_params->ulAuthDataSize = auth_data_len;
		aes_ccm_params->ulDataSize
		    = STRUCT_FGET(params, ulDataSize);
		aes_ccm_params->nonce
		    = (uchar_t *)aes_ccm_params + sizeof (CK_AES_CCM_PARAMS);
		aes_ccm_params->authData
		    = aes_ccm_params->nonce + nonce_len;

		if (copyin((char *)STRUCT_FGETP(params, nonce),
		    aes_ccm_params->nonce, nonce_len) != 0) {
			kmem_free(aes_ccm_params, total_param_len);
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		if (copyin((char *)STRUCT_FGETP(params, authData),
		    aes_ccm_params->authData, auth_data_len) != 0) {
			kmem_free(aes_ccm_params, total_param_len);
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		out_mech->cm_param = (char *)aes_ccm_params;
		out_mech->cm_param_len = sizeof (CK_AES_CCM_PARAMS);
	}
out:
	*out_error = error;
	return (rv);
}

/*
 * Resource control checks don't need to be done. Why? Because this routine
 * knows the size of the structure, and it can't be overridden by a user.
 * This is different from the crypto module, which has no knowledge of
 * specific mechanisms, and therefore has to trust specified size of the
 * parameter.  This trust, or lack of trust, is why the size of the
 * parameter has to be charged against the project resource control.
 */
static int
copyin_aes_gcm_mech(crypto_mechanism_t *in_mech, crypto_mechanism_t *out_mech,
    int *out_error, int mode)
{
	STRUCT_DECL(crypto_mechanism, mech);
	STRUCT_DECL(CK_AES_GCM_PARAMS, params);
	CK_AES_GCM_PARAMS *aes_gcm_params;
	caddr_t pp;
	size_t param_len;
	int error = 0;
	int rv = 0;

	STRUCT_INIT(mech, mode);
	STRUCT_INIT(params, mode);
	bcopy(in_mech, STRUCT_BUF(mech), STRUCT_SIZE(mech));
	pp = STRUCT_FGETP(mech, cm_param);
	param_len = STRUCT_FGET(mech, cm_param_len);

	if (param_len != STRUCT_SIZE(params)) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	out_mech->cm_type = STRUCT_FGET(mech, cm_type);
	out_mech->cm_param = NULL;
	out_mech->cm_param_len = 0;
	if (pp != NULL) {
		size_t nonce_len, auth_data_len, total_param_len;

		if (copyin((char *)pp, STRUCT_BUF(params), param_len) != 0) {
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}

		nonce_len = STRUCT_FGET(params, ulIvLen);
		auth_data_len = STRUCT_FGET(params, ulAADLen);

		/* allocate param structure */
		total_param_len =
		    sizeof (CK_AES_GCM_PARAMS) + nonce_len + auth_data_len;
		aes_gcm_params = kmem_alloc(total_param_len, KM_NOSLEEP);
		if (aes_gcm_params == NULL) {
			rv = CRYPTO_HOST_MEMORY;
			goto out;
		}
		aes_gcm_params->ulTagBits = STRUCT_FGET(params, ulTagBits);
		aes_gcm_params->ulIvLen = nonce_len;
		aes_gcm_params->ulAADLen = auth_data_len;
		aes_gcm_params->pIv
		    = (uchar_t *)aes_gcm_params + sizeof (CK_AES_GCM_PARAMS);
		aes_gcm_params->pAAD = aes_gcm_params->pIv + nonce_len;

		if (copyin((char *)STRUCT_FGETP(params, pIv),
		    aes_gcm_params->pIv, nonce_len) != 0) {
			kmem_free(aes_gcm_params, total_param_len);
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		if (copyin((char *)STRUCT_FGETP(params, pAAD),
		    aes_gcm_params->pAAD, auth_data_len) != 0) {
			kmem_free(aes_gcm_params, total_param_len);
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		out_mech->cm_param = (char *)aes_gcm_params;
		out_mech->cm_param_len = sizeof (CK_AES_GCM_PARAMS);
	}
out:
	*out_error = error;
	return (rv);
}

static int
copyin_aes_gmac_mech(crypto_mechanism_t *in_mech, crypto_mechanism_t *out_mech,
    int *out_error, int mode)
{
	STRUCT_DECL(crypto_mechanism, mech);
	STRUCT_DECL(CK_AES_GMAC_PARAMS, params);
	CK_AES_GMAC_PARAMS *aes_gmac_params;
	caddr_t pp;
	size_t param_len;
	int error = 0;
	int rv = 0;

	STRUCT_INIT(mech, mode);
	STRUCT_INIT(params, mode);
	bcopy(in_mech, STRUCT_BUF(mech), STRUCT_SIZE(mech));
	pp = STRUCT_FGETP(mech, cm_param);
	param_len = STRUCT_FGET(mech, cm_param_len);

	if (param_len != STRUCT_SIZE(params)) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	out_mech->cm_type = STRUCT_FGET(mech, cm_type);
	out_mech->cm_param = NULL;
	out_mech->cm_param_len = 0;
	if (pp != NULL) {
		size_t auth_data_len, total_param_len;

		if (copyin((char *)pp, STRUCT_BUF(params), param_len) != 0) {
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}

		auth_data_len = STRUCT_FGET(params, ulAADLen);

		/* allocate param structure */
		total_param_len = sizeof (CK_AES_GMAC_PARAMS) +
		    AES_GMAC_IV_LEN + auth_data_len;
		aes_gmac_params = kmem_alloc(total_param_len, KM_NOSLEEP);
		if (aes_gmac_params == NULL) {
			rv = CRYPTO_HOST_MEMORY;
			goto out;
		}
		aes_gmac_params->ulAADLen = auth_data_len;
		aes_gmac_params->pIv
		    = (uchar_t *)aes_gmac_params + sizeof (CK_AES_GMAC_PARAMS);
		aes_gmac_params->pAAD = aes_gmac_params->pIv + AES_GMAC_IV_LEN;

		if (copyin((char *)STRUCT_FGETP(params, pIv),
		    aes_gmac_params->pIv, AES_GMAC_IV_LEN) != 0) {
			kmem_free(aes_gmac_params, total_param_len);
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		if (copyin((char *)STRUCT_FGETP(params, pAAD),
		    aes_gmac_params->pAAD, auth_data_len) != 0) {
			kmem_free(aes_gmac_params, total_param_len);
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		out_mech->cm_param = (char *)aes_gmac_params;
		out_mech->cm_param_len = sizeof (CK_AES_GMAC_PARAMS);
	}
out:
	*out_error = error;
	return (rv);
}

/*
 * Resource control checks don't need to be done. Why? Because this routine
 * knows the size of the structure, and it can't be overridden by a user.
 * This is different from the crypto module, which has no knowledge of
 * specific mechanisms, and therefore has to trust specified size of the
 * parameter.  This trust, or lack of trust, is why the size of the
 * parameter has to be charged against the project resource control.
 */
static int
copyin_aes_ctr_mech(crypto_mechanism_t *in_mech, crypto_mechanism_t *out_mech,
    int *out_error, int mode)
{
	STRUCT_DECL(crypto_mechanism, mech);
	STRUCT_DECL(CK_AES_CTR_PARAMS, params);
	CK_AES_CTR_PARAMS *aes_ctr_params;
	caddr_t pp;
	size_t param_len;
	int error = 0;
	int rv = 0;

	STRUCT_INIT(mech, mode);
	STRUCT_INIT(params, mode);
	bcopy(in_mech, STRUCT_BUF(mech), STRUCT_SIZE(mech));
	pp = STRUCT_FGETP(mech, cm_param);
	param_len = STRUCT_FGET(mech, cm_param_len);

	if (param_len != STRUCT_SIZE(params)) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	out_mech->cm_type = STRUCT_FGET(mech, cm_type);
	out_mech->cm_param = NULL;
	out_mech->cm_param_len = 0;
	if (pp != NULL) {
		if (copyin((char *)pp, STRUCT_BUF(params), param_len) != 0) {
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		/* allocate param structure and counter block */
		aes_ctr_params = kmem_alloc(sizeof (CK_AES_CTR_PARAMS),
		    KM_NOSLEEP);
		if (aes_ctr_params == NULL) {
			rv = CRYPTO_HOST_MEMORY;
			goto out;
		}
		aes_ctr_params->ulCounterBits = STRUCT_FGET(params,
		    ulCounterBits);
		bcopy(STRUCT_FGETP(params, cb), aes_ctr_params->cb, 16);
		out_mech->cm_param = (char *)aes_ctr_params;
		out_mech->cm_param_len = sizeof (CK_AES_CTR_PARAMS);
	}
out:
	*out_error = error;
	return (rv);
}

static int
copyin_ecc_mech(crypto_mechanism_t *in_mech, crypto_mechanism_t *out_mech,
    int *out_error, int mode)
{
	STRUCT_DECL(crypto_mechanism, mech);
	STRUCT_DECL(CK_ECDH1_DERIVE_PARAMS, params);
	CK_ECDH1_DERIVE_PARAMS *ecc_params;
	caddr_t pp;
	size_t param_len, shared_data_len, public_data_len;
	int error = 0;
	int rv = 0;

	STRUCT_INIT(mech, mode);
	STRUCT_INIT(params, mode);
	bcopy(in_mech, STRUCT_BUF(mech), STRUCT_SIZE(mech));
	pp = STRUCT_FGETP(mech, cm_param);
	param_len = STRUCT_FGET(mech, cm_param_len);

	if (param_len != STRUCT_SIZE(params)) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	out_mech->cm_type = STRUCT_FGET(mech, cm_type);
	out_mech->cm_param = NULL;
	out_mech->cm_param_len = 0;
	if (pp != NULL) {
		if (copyin((char *)pp, STRUCT_BUF(params), param_len) != 0) {
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		shared_data_len = STRUCT_FGET(params, ulSharedDataLen);
		public_data_len = STRUCT_FGET(params, ulPublicDataLen);
		/* allocate param structure and buffers */
		ecc_params = kmem_alloc(sizeof (CK_ECDH1_DERIVE_PARAMS) +
		    roundup(shared_data_len, sizeof (caddr_t)) +
		    roundup(public_data_len, sizeof (caddr_t)), KM_NOSLEEP);
		if (ecc_params == NULL) {
			rv = CRYPTO_HOST_MEMORY;
			goto out;
		}
		ecc_params->pSharedData = (uchar_t *)ecc_params +
		    sizeof (CK_ECDH1_DERIVE_PARAMS);
		ecc_params->pPublicData = (uchar_t *)ecc_params->pSharedData +
		    roundup(shared_data_len, sizeof (caddr_t));
		if (copyin((char *)STRUCT_FGETP(params, pSharedData),
		    ecc_params->pSharedData, shared_data_len) != 0) {
			kmem_free(ecc_params, sizeof (CK_ECDH1_DERIVE_PARAMS) +
			    roundup(shared_data_len, sizeof (caddr_t)) +
			    roundup(public_data_len, sizeof (caddr_t)));
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		ecc_params->ulSharedDataLen = shared_data_len;

		if (copyin((char *)STRUCT_FGETP(params, pPublicData),
		    ecc_params->pPublicData, public_data_len) != 0) {
			kmem_free(ecc_params, sizeof (CK_ECDH1_DERIVE_PARAMS) +
			    roundup(shared_data_len, sizeof (caddr_t)) +
			    roundup(public_data_len, sizeof (caddr_t)));
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		ecc_params->ulPublicDataLen = public_data_len;
		ecc_params->kdf = STRUCT_FGET(params, kdf);
		out_mech->cm_param = (char *)ecc_params;
		out_mech->cm_param_len = sizeof (CK_ECDH1_DERIVE_PARAMS);
	}
out:
	*out_error = error;
	return (rv);
}

/* ARGSUSED */
static int
copyout_aes_ctr_mech(crypto_mechanism_t *in_mech, crypto_mechanism_t *out_mech,
    int *out_error, int mode)
{
	STRUCT_DECL(crypto_mechanism, mech);
	STRUCT_DECL(CK_AES_CTR_PARAMS, params);
	caddr_t pp;
	size_t param_len;
	int error = 0;
	int rv = 0;

	STRUCT_INIT(mech, mode);
	STRUCT_INIT(params, mode);
	bcopy(out_mech, STRUCT_BUF(mech), STRUCT_SIZE(mech));
	pp = STRUCT_FGETP(mech, cm_param);
	param_len = STRUCT_FGET(mech, cm_param_len);
	if (param_len != STRUCT_SIZE(params)) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	if (copyin((char *)pp, STRUCT_BUF(params), param_len) != 0) {
		error = EFAULT;
		goto out;
	}

	/* for testing, overwrite the iv with 16 X 'A' */
	(void) memset(STRUCT_FGETP(params, cb), 'A', 16);
	if (copyout((char *)pp, STRUCT_BUF(params),  param_len) != 0) {
		error = EFAULT;
		goto out;
	}
out:
	*out_error = error;
	return (rv);
}

/* ARGSUSED */
static int
dprov_copyin_mechanism(crypto_provider_handle_t provider,
    crypto_mechanism_t *umech, crypto_mechanism_t *kmech,
    int *out_error, int mode)
{
	STRUCT_DECL(crypto_mechanism, mech);
	size_t param_len, expected_param_len;
	caddr_t pp;
	char *param;
	int rv;
	int error = 0;

	ASSERT(!servicing_interrupt());

	STRUCT_INIT(mech, mode);
	bcopy(umech, STRUCT_BUF(mech), STRUCT_SIZE(mech));
	pp = STRUCT_FGETP(mech, cm_param);
	param_len = STRUCT_FGET(mech, cm_param_len);

	kmech->cm_param = NULL;
	kmech->cm_param_len = 0;

	switch (kmech->cm_type) {
	case DES_CBC_MECH_INFO_TYPE:
	case DES3_CBC_MECH_INFO_TYPE:
		expected_param_len = DES_BLOCK_LEN;
		break;

	case BLOWFISH_CBC_MECH_INFO_TYPE:
		expected_param_len = BLOWFISH_BLOCK_LEN;
		break;

	case AES_CBC_MECH_INFO_TYPE:
		expected_param_len = AES_BLOCK_LEN;
		break;

	case AES_CTR_MECH_INFO_TYPE:
	case SHA1_KEY_DERIVATION_MECH_INFO_TYPE:	/* for testing only */
		rv = copyin_aes_ctr_mech(umech, kmech, &error, mode);
		goto out;

	case ECDH1_DERIVE_MECH_INFO_TYPE:
		rv = copyin_ecc_mech(umech, kmech, &error, mode);
		goto out;

	case AES_CCM_MECH_INFO_TYPE:
		rv = copyin_aes_ccm_mech(umech, kmech, &error, mode);
		goto out;

	case AES_GCM_MECH_INFO_TYPE:
		rv = copyin_aes_gcm_mech(umech, kmech, &error, mode);
		goto out;

	case AES_GMAC_MECH_INFO_TYPE:
		rv = copyin_aes_gmac_mech(umech, kmech, &error, mode);
		goto out;

	case DH_PKCS_DERIVE_MECH_INFO_TYPE:
		expected_param_len = param_len;
		break;

	default:
		/* nothing to do - mechanism has no parameters */
		rv = CRYPTO_SUCCESS;
		goto out;
	}

	if (param_len != expected_param_len) {
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
		goto out;
	}
	if (pp == NULL) {
		rv = CRYPTO_MECHANISM_PARAM_INVALID;
		goto out;
	}
	if ((param = kmem_alloc(param_len, KM_NOSLEEP)) == NULL) {
		rv = CRYPTO_HOST_MEMORY;
		goto out;
	}
	if (copyin((char *)pp, param, param_len) != 0) {
		kmem_free(param, param_len);
		error = EFAULT;
		rv = CRYPTO_FAILED;
		goto out;
	}
	kmech->cm_param = (char *)param;
	kmech->cm_param_len = param_len;
	rv = CRYPTO_SUCCESS;
out:
	*out_error = error;
	return (rv);
}

/* ARGSUSED */
static int
dprov_copyout_mechanism(crypto_provider_handle_t provider,
    crypto_mechanism_t *kmech, crypto_mechanism_t *umech,
    int *out_error, int mode)
{
	ASSERT(!servicing_interrupt());

	switch (kmech->cm_type) {
	case AES_CTR_MECH_INFO_TYPE:
	case SHA1_KEY_DERIVATION_MECH_INFO_TYPE:	/* for testing only */
		return (copyout_aes_ctr_mech(kmech, umech, out_error, mode));
	case ECDH1_DERIVE_MECH_INFO_TYPE:
		return (CRYPTO_SUCCESS);
	default:
		return (CRYPTO_MECHANISM_INVALID);
	}
}

/*
 * Free mechanism parameter that was allocated by the provider.
 */
/* ARGSUSED */
static int
dprov_free_mechanism(crypto_provider_handle_t provider,
    crypto_mechanism_t *mech)
{
	size_t len;

	if (mech->cm_param == NULL || mech->cm_param_len == 0)
		return (CRYPTO_SUCCESS);

	switch (mech->cm_type) {
	case AES_CTR_MECH_INFO_TYPE:
	case SHA1_KEY_DERIVATION_MECH_INFO_TYPE:
		len = sizeof (CK_AES_CTR_PARAMS);
		break;
	case ECDH1_DERIVE_MECH_INFO_TYPE: {
		CK_ECDH1_DERIVE_PARAMS *ecc_params;

		/* LINTED: pointer alignment */
		ecc_params = (CK_ECDH1_DERIVE_PARAMS *)mech->cm_param;
		kmem_free(ecc_params, sizeof (CK_ECDH1_DERIVE_PARAMS) +
		    roundup(ecc_params->ulSharedDataLen, sizeof (caddr_t)) +
		    roundup(ecc_params->ulPublicDataLen, sizeof (caddr_t)));
		return (CRYPTO_SUCCESS);
	}
	case AES_CCM_MECH_INFO_TYPE: {
		CK_AES_CCM_PARAMS *params;
		size_t total_param_len;

		if ((mech->cm_param != NULL) && (mech->cm_param_len != 0)) {
			/* LINTED: pointer alignment */
			params = (CK_AES_CCM_PARAMS *)mech->cm_param;
			total_param_len = mech->cm_param_len +
			    params->ulNonceSize + params->ulAuthDataSize;
			kmem_free(params, total_param_len);
			mech->cm_param = NULL;
			mech->cm_param_len = 0;
		}
		return (CRYPTO_SUCCESS);
	}
	case AES_GMAC_MECH_INFO_TYPE: {
		CK_AES_GMAC_PARAMS *params;
		size_t total_param_len;

		if ((mech->cm_param != NULL) && (mech->cm_param_len != 0)) {
			/* LINTED: pointer alignment */
			params = (CK_AES_GMAC_PARAMS *)mech->cm_param;
			total_param_len = mech->cm_param_len +
			    AES_GMAC_IV_LEN + params->ulAADLen;
			kmem_free(params, total_param_len);
			mech->cm_param = NULL;
			mech->cm_param_len = 0;
		}
		return (CRYPTO_SUCCESS);
	}
	case AES_GCM_MECH_INFO_TYPE: {
		CK_AES_GCM_PARAMS *params;
		size_t total_param_len;

		if ((mech->cm_param != NULL) && (mech->cm_param_len != 0)) {
			/* LINTED: pointer alignment */
			params = (CK_AES_GCM_PARAMS *)mech->cm_param;
			total_param_len = mech->cm_param_len +
			    params->ulIvLen + params->ulAADLen;
			kmem_free(params, total_param_len);
			mech->cm_param = NULL;
			mech->cm_param_len = 0;
		}
		return (CRYPTO_SUCCESS);
	}

	default:
		len = mech->cm_param_len;
	}
	kmem_free(mech->cm_param, len);
	return (CRYPTO_SUCCESS);
}

/*
 * No (Key)Store Key management entry point.
 */
static int
dprov_nostore_key_generate(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_object_attribute_t *template, uint_t attribute_count,
    crypto_object_attribute_t *out_template, uint_t out_attribute_count,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_KEY, ("(%d) dprov_nostore_key_generate: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_key_submit_req(DPROV_REQ_NOSTORE_KEY_GENERATE,
	    softc, req, session_id, mechanism, template, attribute_count,
	    NULL, NULL, 0, NULL, NULL, NULL, 0, out_template,
	    out_attribute_count, NULL, 0);

	DPROV_DEBUG(D_KEY, ("(%d) dprov_nostore_key_generate: "
	    "done err = 0x0%x\n", instance, error));

	return (error);
}

static int
dprov_nostore_key_generate_pair(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_object_attribute_t *public_key_template,
    uint_t public_key_attribute_count,
    crypto_object_attribute_t *private_key_template,
    uint_t private_key_attribute_count,
    crypto_object_attribute_t *out_public_key_template,
    uint_t out_public_key_attribute_count,
    crypto_object_attribute_t *out_private_key_template,
    uint_t out_private_key_attribute_count,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_KEY, ("(%d) dprov_nostore_key_generate_pair: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_key_submit_req(DPROV_REQ_NOSTORE_KEY_GENERATE_PAIR,
	    softc, req, session_id, mechanism, public_key_template,
	    public_key_attribute_count, NULL, private_key_template,
	    private_key_attribute_count, NULL, NULL, NULL, 0,
	    out_public_key_template, out_public_key_attribute_count,
	    out_private_key_template, out_private_key_attribute_count);

	DPROV_DEBUG(D_KEY, ("(%d) dprov_nostore_key_generate_pair: "
	    "done err = 0x0%x\n", instance, error));

	return (error);
}

static int
dprov_nostore_key_derive(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *base_key, crypto_object_attribute_t *template,
    uint_t attribute_count, crypto_object_attribute_t *out_template,
    uint_t out_attribute_count, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dprov_state_t *softc = (dprov_state_t *)provider;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;

	instance = ddi_get_instance(softc->ds_dip);
	DPROV_DEBUG(D_KEY, ("(%d) dprov_nostore_key_derive: started\n",
	    instance));

	/* submit request to the taskq */
	error = dprov_key_submit_req(DPROV_REQ_NOSTORE_KEY_DERIVE, softc, req,
	    session_id, mechanism, template, attribute_count, NULL, NULL,
	    0, NULL, base_key, NULL, 0, out_template, out_attribute_count,
	    NULL, 0);

	DPROV_DEBUG(D_KEY, ("(%d) dprov_nostore_key_derive: "
	    "done err = 0x0%x\n", instance, error));

	return (error);
}

/*
 * Allocate a dprov taskq request and initialize the common fields.
 * Return NULL if the memory allocation failed.
 */
static dprov_req_t *
dprov_alloc_req(dprov_req_type_t req_type, dprov_state_t *softc,
    crypto_req_handle_t kcf_req, int kmflag)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = kmem_alloc(sizeof (dprov_req_t), kmflag)) == NULL)
		return (NULL);

	taskq_req->dr_type = req_type;
	taskq_req->dr_softc = softc;
	taskq_req->dr_kcf_req = kcf_req;

	return (taskq_req);
}

/*
 * Dispatch a dprov request on the taskq associated with a softc.
 * Returns CRYPTO_HOST_MEMORY if the request cannot be queued,
 * CRYPTO_QUEUED on success.
 */
static int
dprov_taskq_dispatch(dprov_state_t *softc, dprov_req_t *taskq_req,
    task_func_t *func, int kmflag)
{
	if (taskq_dispatch(softc->ds_taskq, func, taskq_req,
	    kmflag == KM_NOSLEEP ? TQ_NOSLEEP : TQ_SLEEP) == (taskqid_t)0) {
		kmem_free(taskq_req, sizeof (dprov_req_t));
		return (CRYPTO_HOST_MEMORY);
	} else
		return (CRYPTO_QUEUED);
}

/*
 * Helper function to submit digest operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_digest_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req,
    crypto_mechanism_t *mechanism, crypto_data_t *data, crypto_key_t *key,
    crypto_data_t *digest, crypto_ctx_t *ctx, int kmflag)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req, kmflag)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_digest_req.dr_mechanism = mechanism;
	taskq_req->dr_digest_req.dr_ctx = ctx;
	taskq_req->dr_digest_req.dr_data = data;
	taskq_req->dr_digest_req.dr_key = key;
	taskq_req->dr_digest_req.dr_digest = digest;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_digest_task, kmflag));
}

/*
 * Helper function to submit mac operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_mac_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req,
    crypto_mechanism_t *mechanism, crypto_data_t *data, crypto_key_t *key,
    crypto_data_t *mac, crypto_ctx_t *ctx, crypto_session_id_t sid, int kmflag)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req, kmflag)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_mac_req.dr_mechanism = mechanism;
	taskq_req->dr_mac_req.dr_ctx = ctx;
	taskq_req->dr_mac_req.dr_data = data;
	taskq_req->dr_mac_req.dr_key = key;
	taskq_req->dr_mac_req.dr_mac = mac;
	taskq_req->dr_mac_req.dr_session_id = sid;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_mac_task, kmflag));
}

/*
 * Helper function to submit sign operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_sign_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req,
    crypto_mechanism_t *mechanism, crypto_key_t *key, crypto_data_t *data,
    crypto_data_t *signature, crypto_ctx_t *ctx, crypto_session_id_t sid,
    int kmflag)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req, kmflag)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_sign_req.sr_mechanism = mechanism;
	taskq_req->dr_sign_req.sr_ctx = ctx;
	taskq_req->dr_sign_req.sr_key = key;
	taskq_req->dr_sign_req.sr_data = data;
	taskq_req->dr_sign_req.sr_signature = signature;
	taskq_req->dr_sign_req.sr_session_id = sid;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_sign_task, kmflag));
}

/*
 * Helper function to submit verify operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_verify_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req,
    crypto_mechanism_t *mechanism, crypto_key_t *key, crypto_data_t *data,
    crypto_data_t *signature, crypto_ctx_t *ctx, crypto_session_id_t sid,
    int kmflag)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req, kmflag)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_verify_req.vr_mechanism = mechanism;
	taskq_req->dr_verify_req.vr_ctx = ctx;
	taskq_req->dr_verify_req.vr_key = key;
	taskq_req->dr_verify_req.vr_data = data;
	taskq_req->dr_verify_req.vr_signature = signature;
	taskq_req->dr_verify_req.vr_session_id = sid;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_verify_task, kmflag));
}

/*
 * Helper function to submit dual operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_dual_submit_req(dprov_req_type_t req_type, dprov_state_t *softc,
    crypto_req_handle_t req, crypto_ctx_t *signverify_ctx,
    crypto_ctx_t *cipher_ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req,
	    KM_NOSLEEP)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_dual_req.dr_signverify_ctx = signverify_ctx;
	taskq_req->dr_dual_req.dr_cipher_ctx = cipher_ctx;
	taskq_req->dr_dual_req.dr_plaintext = plaintext;
	taskq_req->dr_dual_req.dr_ciphertext = ciphertext;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_dual_task, KM_NOSLEEP));
}

/*
 * Helper function to submit dual cipher/mac operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_cipher_mac_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req, crypto_ctx_t *ctx,
    crypto_session_id_t sid, crypto_mechanism_t *cipher_mech,
    crypto_key_t *cipher_key, crypto_mechanism_t *mac_mech,
    crypto_key_t *mac_key, crypto_dual_data_t *dual_data,
    crypto_data_t *data, crypto_data_t *mac, int kmflag)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req, kmflag)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_cipher_mac_req.mr_session_id = sid;
	taskq_req->dr_cipher_mac_req.mr_ctx = ctx;
	taskq_req->dr_cipher_mac_req.mr_cipher_mech = cipher_mech;
	taskq_req->dr_cipher_mac_req.mr_cipher_key = cipher_key;
	taskq_req->dr_cipher_mac_req.mr_mac_mech = mac_mech;
	taskq_req->dr_cipher_mac_req.mr_mac_key = mac_key;
	taskq_req->dr_cipher_mac_req.mr_dual_data = dual_data;
	taskq_req->dr_cipher_mac_req.mr_data = data;
	taskq_req->dr_cipher_mac_req.mr_mac = mac;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_cipher_mac_task, kmflag));
}

/*
 * Helper function to submit cipher operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_cipher_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req,
    crypto_mechanism_t *mechanism, crypto_key_t *key, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_ctx_t *ctx, crypto_session_id_t sid,
    int kmflag)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req, kmflag)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_cipher_req.dr_mechanism = mechanism;
	taskq_req->dr_cipher_req.dr_ctx = ctx;
	taskq_req->dr_cipher_req.dr_key = key;
	taskq_req->dr_cipher_req.dr_plaintext = plaintext;
	taskq_req->dr_cipher_req.dr_ciphertext = ciphertext;
	taskq_req->dr_cipher_req.dr_session_id = sid;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_cipher_task, kmflag));
}

/*
 * Helper function to submit random number operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_random_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req, uchar_t *buf, size_t len,
    crypto_session_id_t sid, uint_t entropy_est, uint32_t flags)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req,
	    KM_NOSLEEP)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_random_req.rr_buf = buf;
	taskq_req->dr_random_req.rr_len = len;
	taskq_req->dr_random_req.rr_session_id = sid;
	taskq_req->dr_random_req.rr_entropy_est = entropy_est;
	taskq_req->dr_random_req.rr_flags = flags;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_random_task, KM_NOSLEEP));
}


/*
 * Helper function to submit session management operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_session_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req,
    crypto_session_id_t *session_id_ptr, crypto_session_id_t session_id,
    crypto_user_type_t user_type, char *pin, size_t pin_len)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req,
	    KM_NOSLEEP)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_session_req.sr_session_id_ptr = session_id_ptr;
	taskq_req->dr_session_req.sr_session_id = session_id;
	taskq_req->dr_session_req.sr_user_type = user_type;
	taskq_req->dr_session_req.sr_pin = pin;
	taskq_req->dr_session_req.sr_pin_len = pin_len;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_session_task, KM_NOSLEEP));
}

/*
 * Helper function to submit object management operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_object_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req,
    crypto_session_id_t session_id, crypto_object_id_t object_id,
    crypto_object_attribute_t *template, uint_t attribute_count,
    crypto_object_id_t *object_id_ptr, size_t *object_size,
    void **find_pp, void *find_p, uint_t max_object_count,
    uint_t *object_count_ptr, int kmflag)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req,
	    kmflag)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_object_req.or_session_id = session_id;
	taskq_req->dr_object_req.or_object_id = object_id;
	taskq_req->dr_object_req.or_template = template;
	taskq_req->dr_object_req.or_attribute_count = attribute_count;
	taskq_req->dr_object_req.or_object_id_ptr = object_id_ptr;
	taskq_req->dr_object_req.or_object_size = object_size;
	taskq_req->dr_object_req.or_find_pp = find_pp;
	taskq_req->dr_object_req.or_find_p = find_p;
	taskq_req->dr_object_req.or_max_object_count = max_object_count;
	taskq_req->dr_object_req.or_object_count_ptr = object_count_ptr;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_object_task, KM_NOSLEEP));
}

/*
 * Helper function to submit key management operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_key_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_object_attribute_t *template, uint_t attribute_count,
    crypto_object_id_t *object_id_ptr,
    crypto_object_attribute_t *private_key_template,
    uint_t private_key_attribute_count,
    crypto_object_id_t *private_key_object_id_ptr, crypto_key_t *key,
    uchar_t *wrapped_key, size_t *wrapped_key_len_ptr,
    crypto_object_attribute_t *out_template1, uint_t out_attribute_count1,
    crypto_object_attribute_t *out_template2, uint_t out_attribute_count2)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req,
	    KM_NOSLEEP)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_key_req.kr_session_id = session_id;
	taskq_req->dr_key_req.kr_mechanism = mechanism;
	taskq_req->dr_key_req.kr_template = template;
	taskq_req->dr_key_req.kr_attribute_count = attribute_count;
	taskq_req->dr_key_req.kr_object_id_ptr = object_id_ptr;
	taskq_req->dr_key_req.kr_private_key_template = private_key_template;
	taskq_req->dr_key_req.kr_private_key_attribute_count =
	    private_key_attribute_count;
	taskq_req->dr_key_req.kr_private_key_object_id_ptr =
	    private_key_object_id_ptr;
	taskq_req->dr_key_req.kr_key = key;
	taskq_req->dr_key_req.kr_wrapped_key = wrapped_key;
	taskq_req->dr_key_req.kr_wrapped_key_len_ptr = wrapped_key_len_ptr;
	taskq_req->dr_key_req.kr_out_template1 = out_template1;
	taskq_req->dr_key_req.kr_out_attribute_count1 = out_attribute_count1;
	taskq_req->dr_key_req.kr_out_template2 = out_template2;
	taskq_req->dr_key_req.kr_out_attribute_count2 = out_attribute_count2;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_key_task, KM_NOSLEEP));
}

/*
 * Helper function to submit provider management operations to the taskq.
 * Returns one of the CRYPTO_ errors.
 */
static int
dprov_mgmt_submit_req(dprov_req_type_t req_type,
    dprov_state_t *softc, crypto_req_handle_t req,
    crypto_session_id_t session_id, char *pin, size_t pin_len,
    char *old_pin, size_t old_pin_len, char *label,
    crypto_provider_ext_info_t *ext_info)
{
	dprov_req_t *taskq_req;

	if ((taskq_req = dprov_alloc_req(req_type, softc, req,
	    KM_NOSLEEP)) == NULL)
		return (CRYPTO_HOST_MEMORY);

	taskq_req->dr_mgmt_req.mr_session_id = session_id;
	taskq_req->dr_mgmt_req.mr_pin = pin;
	taskq_req->dr_mgmt_req.mr_pin_len = pin_len;
	taskq_req->dr_mgmt_req.mr_old_pin = old_pin;
	taskq_req->dr_mgmt_req.mr_old_pin_len = old_pin_len;
	taskq_req->dr_mgmt_req.mr_label = label;
	taskq_req->dr_mgmt_req.mr_ext_info = ext_info;

	return (dprov_taskq_dispatch(softc, taskq_req,
	    (task_func_t *)dprov_mgmt_task, KM_NOSLEEP));
}

/*
 * Helper function for taskq dispatcher routines. Notify the framework
 * that the operation corresponding to the specified request is done,
 * and pass it the error code. Finally, free the taskq_req.
 */
static void
dprov_op_done(dprov_req_t *taskq_req, int error)
{
	/* notify framework that request is completed */
	crypto_op_notification(taskq_req->dr_kcf_req, error);

	/* free taskq request structure */
	kmem_free(taskq_req, sizeof (dprov_req_t));
}

/*
 * taskq dispatcher function for digest operations.
 */
static void
dprov_digest_task(dprov_req_t *taskq_req)
{
	kcf_provider_desc_t *pd;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;
	crypto_ctx_t *ctx = taskq_req->dr_digest_req.dr_ctx;
	crypto_mechanism_t mech;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_task: started\n", instance));

	switch (taskq_req->dr_type) {

	case DPROV_REQ_DIGEST_INIT:
		/* allocate a dprov-private context */
		if ((error = dprov_alloc_context(taskq_req->dr_type, ctx)) !=
		    CRYPTO_SUCCESS)
			break;

		/* structure assignment */
		mech = *taskq_req->dr_digest_req.dr_mechanism;

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(
		    taskq_req->dr_digest_req.dr_mechanism, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* Use a session id of zero since we use a software provider */
		error = crypto_digest_init_prov(pd, 0, &mech,
		    &DPROV_CTX_SINGLE(ctx), NULL);

		/* release provider reference */
		KCF_PROV_REFRELE(pd);
		break;

	case DPROV_REQ_DIGEST:
		error = crypto_digest_single(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_digest_req.dr_data,
		    taskq_req->dr_digest_req.dr_digest, NULL);

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_DIGEST_UPDATE:
		error = crypto_digest_update(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_digest_req.dr_data, NULL);
		break;

	case DPROV_REQ_DIGEST_KEY: {
		crypto_data_t data;
		crypto_key_t key;
		size_t len;

		mutex_enter(&softc->ds_lock);
		error = dprov_key_value_secret(softc, ctx->cc_session,
		    taskq_req->dr_type, taskq_req->dr_digest_req.dr_key, &key);
		mutex_exit(&softc->ds_lock);
		if (error != CRYPTO_SUCCESS)
			break;

		/* key lengths are specified in bits */
		len = CRYPTO_BITS2BYTES(key.ck_length);
		data.cd_format = CRYPTO_DATA_RAW;
		data.cd_offset = 0;
		data.cd_length = len;
		data.cd_raw.iov_base = key.ck_data;
		data.cd_raw.iov_len = len;
		error = crypto_digest_update(DPROV_CTX_SINGLE(ctx),
		    &data, NULL);
		break;
	}

	case DPROV_REQ_DIGEST_FINAL:
		error = crypto_digest_final(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_digest_req.dr_digest, NULL);
		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_DIGEST_ATOMIC:
		/* structure assignment */
		mech = *taskq_req->dr_digest_req.dr_mechanism;

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(
		    taskq_req->dr_digest_req.dr_mechanism, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* use a session id of zero since we use a software provider */
		error = crypto_digest_prov(pd, 0, &mech,
		    taskq_req->dr_digest_req.dr_data,
		    taskq_req->dr_digest_req.dr_digest, NULL);

		/* release provider reference */
		KCF_PROV_REFRELE(pd);

		break;
	}

	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_digest_task: end\n", instance));
}

/*
 * taskq dispatcher function for mac operations.
 */
static void
dprov_mac_task(dprov_req_t *taskq_req)
{
	kcf_provider_desc_t *pd;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;
	crypto_ctx_t *ctx = taskq_req->dr_mac_req.dr_ctx;
	crypto_key_t key;
	crypto_mechanism_t mech;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_task: started\n", instance));

	switch (taskq_req->dr_type) {

	case DPROV_REQ_MAC_INIT:
		/* allocate a dprov-private context */
		if ((error = dprov_alloc_context(taskq_req->dr_type, ctx)) !=
		    CRYPTO_SUCCESS)
			break;

		/* get key value */
		mutex_enter(&softc->ds_lock);
		error = dprov_key_value_secret(softc, ctx->cc_session,
		    taskq_req->dr_type, taskq_req->dr_mac_req.dr_key, &key);
		mutex_exit(&softc->ds_lock);
		if (error != CRYPTO_SUCCESS)
			break;

		/* structure assignment */
		mech = *taskq_req->dr_mac_req.dr_mechanism;

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(
		    taskq_req->dr_mac_req.dr_mechanism, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* Use a session id of zero since we use a software provider */
		error = crypto_mac_init_prov(pd, 0, &mech, &key, NULL,
		    &DPROV_CTX_SINGLE(ctx), NULL);

		/* release provider reference */
		KCF_PROV_REFRELE(pd);
		break;

	case DPROV_REQ_MAC:
		error = crypto_mac_single(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_mac_req.dr_data,
		    taskq_req->dr_mac_req.dr_mac, NULL);

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_MAC_UPDATE:
		error = crypto_mac_update(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_mac_req.dr_data, NULL);
		break;

	case DPROV_REQ_MAC_FINAL:
		error = crypto_mac_final(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_mac_req.dr_mac, NULL);
		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_MAC_ATOMIC:
	case DPROV_REQ_MAC_VERIFY_ATOMIC:
		/* get key value */
		mutex_enter(&softc->ds_lock);
		error = dprov_key_value_secret(softc,
		    taskq_req->dr_mac_req.dr_session_id,
		    taskq_req->dr_type, taskq_req->dr_mac_req.dr_key, &key);
		mutex_exit(&softc->ds_lock);
		if (error != CRYPTO_SUCCESS)
			break;

		/* structure assignment */
		mech = *taskq_req->dr_mac_req.dr_mechanism;

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(
		    taskq_req->dr_mac_req.dr_mechanism, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* use a session id of zero since we use a software provider */
		if (taskq_req->dr_type == DPROV_REQ_MAC_ATOMIC)
			error = crypto_mac_prov(pd, 0, &mech,
			    taskq_req->dr_mac_req.dr_data,
			    &key, NULL, taskq_req->dr_mac_req.dr_mac, NULL);
		else
			error = crypto_mac_verify_prov(pd, 0, &mech,
			    taskq_req->dr_mac_req.dr_data,
			    &key, NULL, taskq_req->dr_mac_req.dr_mac, NULL);

		/* release provider reference */
		KCF_PROV_REFRELE(pd);

		break;
	}

	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_task: end\n", instance));
}

/*
 * taskq dispatcher function for sign operations.
 */
static void
dprov_sign_task(dprov_req_t *taskq_req)
{
	kcf_provider_desc_t *pd;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;
	crypto_ctx_t *ctx = taskq_req->dr_sign_req.sr_ctx;
	crypto_key_t key, *keyp;
	crypto_mechanism_t mech;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_task: started\n", instance));

	switch (taskq_req->dr_type) {

	case DPROV_REQ_SIGN_INIT:
	case DPROV_REQ_SIGN_RECOVER_INIT:
		/* allocate a dprov-private context */
		if ((error = dprov_alloc_context(taskq_req->dr_type, ctx)) !=
		    CRYPTO_SUCCESS)
			break;

		/* structure assignment */
		mech = *taskq_req->dr_sign_req.sr_mechanism;
		if (dprov_valid_mac_mech(mech.cm_type)) {
			DPROV_CTX_P(ctx)->dc_svrfy_to_mac = B_TRUE;
		}

		mutex_enter(&softc->ds_lock);
		if (is_publickey_mech(mech.cm_type)) {
			if ((error = dprov_key_attr_asymmetric(softc,
			    ctx->cc_session, taskq_req->dr_type,
			    taskq_req->dr_sign_req.sr_key, &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		} else {
			if ((error = dprov_key_value_secret(softc,
			    ctx->cc_session, taskq_req->dr_type,
			    taskq_req->dr_sign_req.sr_key, &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		}
		mutex_exit(&softc->ds_lock);

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(
		    taskq_req->dr_sign_req.sr_mechanism, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		if (DPROV_CTX_P(ctx)->dc_svrfy_to_mac) {
			error = crypto_mac_init_prov(pd, 0, &mech, keyp, NULL,
			    &DPROV_CTX_SINGLE(ctx), NULL);

			/* release provider reference */
			KCF_PROV_REFRELE(pd);
			break;
		}

		/* Use a session id of zero since we use a software provider */
		if (taskq_req->dr_type == DPROV_REQ_SIGN_INIT)
			error = crypto_sign_init_prov(pd, 0, &mech, keyp,
			    NULL, &DPROV_CTX_SINGLE(ctx), NULL);
		else
			error = crypto_sign_recover_init_prov(pd, 0, &mech,
			    keyp, NULL, &DPROV_CTX_SINGLE(ctx), NULL);

		/* release provider reference */
		KCF_PROV_REFRELE(pd);

		break;

	case DPROV_REQ_SIGN:
		if (DPROV_CTX_P(ctx)->dc_svrfy_to_mac) {
			/* Emulate using update and final */
			error = crypto_mac_update(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_mac_req.dr_data, NULL);
			if (error == CRYPTO_SUCCESS) {
				error = crypto_mac_final(DPROV_CTX_SINGLE(ctx),
				    taskq_req->dr_mac_req.dr_mac, NULL);
			}
		} else {
			error = crypto_sign_single(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_sign_req.sr_data,
			    taskq_req->dr_sign_req.sr_signature, NULL);
		}

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_SIGN_UPDATE:
		if (DPROV_CTX_P(ctx)->dc_svrfy_to_mac) {
			error = crypto_mac_update(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_mac_req.dr_data, NULL);
		} else {
			error = crypto_sign_update(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_sign_req.sr_data, NULL);
		}
		break;

	case DPROV_REQ_SIGN_FINAL:
		if (DPROV_CTX_P(ctx)->dc_svrfy_to_mac) {
			error = crypto_mac_final(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_mac_req.dr_mac, NULL);
		} else {
			error = crypto_sign_final(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_sign_req.sr_signature, NULL);
		}

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_SIGN_ATOMIC:
	case DPROV_REQ_SIGN_RECOVER_ATOMIC:
		/* structure assignment */
		mech = *taskq_req->dr_sign_req.sr_mechanism;

		mutex_enter(&softc->ds_lock);
		/* get key value for secret key algorithms */
		if (is_publickey_mech(mech.cm_type)) {
			if ((error = dprov_key_attr_asymmetric(softc,
			    taskq_req->dr_sign_req.sr_session_id,
			    taskq_req->dr_type,
			    taskq_req->dr_sign_req.sr_key, &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		} else {
			if ((error = dprov_key_value_secret(softc,
			    taskq_req->dr_sign_req.sr_session_id,
			    taskq_req->dr_type,
			    taskq_req->dr_sign_req.sr_key, &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		}
		mutex_exit(&softc->ds_lock);

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(
		    taskq_req->dr_sign_req.sr_mechanism, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* Use a session id of zero since we use a software provider */
		if (taskq_req->dr_type == DPROV_REQ_SIGN_ATOMIC)
			error = crypto_sign_prov(pd, 0, &mech, keyp,
			    taskq_req->dr_sign_req.sr_data,
			    NULL, taskq_req->dr_sign_req.sr_signature, NULL);
		else
			error = crypto_sign_recover_prov(pd, 0, &mech, keyp,
			    taskq_req->dr_sign_req.sr_data,
			    NULL, taskq_req->dr_sign_req.sr_signature, NULL);

		/* release provider reference */
		KCF_PROV_REFRELE(pd);
		break;

	case DPROV_REQ_SIGN_RECOVER:
		error = crypto_sign_recover_single(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_sign_req.sr_data,
		    taskq_req->dr_sign_req.sr_signature, NULL);

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;
	}

	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_SIGN, ("(%d) dprov_sign_task: end\n", instance));
}

static int
emulate_verify_with_mac(crypto_ctx_t *ctx, crypto_data_t *in_mac)
{
	int error;
	crypto_data_t tmpd;
	crypto_data_t *out_mac;
	char digest[SHA512_DIGEST_LENGTH];

	bzero(&tmpd, sizeof (crypto_data_t));
	tmpd.cd_format = CRYPTO_DATA_RAW;
	tmpd.cd_length = SHA512_DIGEST_LENGTH;
	tmpd.cd_raw.iov_base = digest;
	tmpd.cd_raw.iov_len = SHA512_DIGEST_LENGTH;
	out_mac = &tmpd;

	error = crypto_mac_final(DPROV_CTX_SINGLE(ctx), out_mac, NULL);
	if (in_mac->cd_length != out_mac->cd_length ||
	    (bcmp(digest, (unsigned char *)in_mac->cd_raw.iov_base +
	    in_mac->cd_offset, out_mac->cd_length) != 0)) {
		error = CRYPTO_INVALID_MAC;
	}

	return (error);
}

/*
 * taskq dispatcher function for verify operations.
 */
static void
dprov_verify_task(dprov_req_t *taskq_req)
{
	kcf_provider_desc_t *pd;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;
	crypto_ctx_t *ctx = taskq_req->dr_verify_req.vr_ctx;
	crypto_key_t key, *keyp;
	crypto_mechanism_t mech;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_task: started\n", instance));

	switch (taskq_req->dr_type) {

	case DPROV_REQ_VERIFY_INIT:
	case DPROV_REQ_VERIFY_RECOVER_INIT:
		/* allocate a dprov-private context */
		if ((error = dprov_alloc_context(taskq_req->dr_type, ctx)) !=
		    CRYPTO_SUCCESS)
			break;

		/* structure assignment */
		mech = *taskq_req->dr_verify_req.vr_mechanism;
		if (dprov_valid_mac_mech(mech.cm_type)) {
			DPROV_CTX_P(ctx)->dc_svrfy_to_mac = B_TRUE;
		}

		mutex_enter(&softc->ds_lock);
		/* get key value for secret key algorithms */
		if (is_publickey_mech(mech.cm_type)) {
			if ((error = dprov_key_attr_asymmetric(softc,
			    ctx->cc_session, taskq_req->dr_type,
			    taskq_req->dr_verify_req.vr_key, &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		} else {
			if ((error = dprov_key_value_secret(softc,
			    ctx->cc_session, taskq_req->dr_type,
			    taskq_req->dr_verify_req.vr_key, &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		}
		mutex_exit(&softc->ds_lock);

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(
		    taskq_req->dr_verify_req.vr_mechanism, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;


		if (DPROV_CTX_P(ctx)->dc_svrfy_to_mac) {
			error = crypto_mac_init_prov(pd, 0, &mech, keyp, NULL,
			    &DPROV_CTX_SINGLE(ctx), NULL);

			/* release provider reference */
			KCF_PROV_REFRELE(pd);
			break;
		}

		/* Use a session id of zero since we use a software provider */
		if (taskq_req->dr_type == DPROV_REQ_VERIFY_INIT)
			error = crypto_verify_init_prov(pd, 0, &mech, keyp,
			    NULL, &DPROV_CTX_SINGLE(ctx), NULL);
		else
			error = crypto_verify_recover_init_prov(pd, 0, &mech,
			    keyp, NULL, &DPROV_CTX_SINGLE(ctx), NULL);

		/* release provider reference */
		KCF_PROV_REFRELE(pd);

		break;

	case DPROV_REQ_VERIFY:
		if (DPROV_CTX_P(ctx)->dc_svrfy_to_mac) {
			/* Emulate using update and final */
			error = crypto_mac_update(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_mac_req.dr_data, NULL);
			if (error == CRYPTO_SUCCESS) {
				error = emulate_verify_with_mac(ctx,
				    taskq_req->dr_mac_req.dr_mac);
			}
		} else {
			error = crypto_verify_single(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_verify_req.vr_data,
			    taskq_req->dr_verify_req.vr_signature, NULL);
		}

		ASSERT(error != CRYPTO_BUFFER_TOO_SMALL);
		DPROV_CTX_SINGLE(ctx) = NULL;
		(void) dprov_free_context(ctx);
		break;

	case DPROV_REQ_VERIFY_UPDATE:
		if (DPROV_CTX_P(ctx)->dc_svrfy_to_mac) {
			error = crypto_mac_update(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_mac_req.dr_data, NULL);
		} else {
			error = crypto_verify_update(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_verify_req.vr_data, NULL);
		}
		break;

	case DPROV_REQ_VERIFY_FINAL:
		if (DPROV_CTX_P(ctx)->dc_svrfy_to_mac) {
			error = emulate_verify_with_mac(ctx,
			    taskq_req->dr_mac_req.dr_mac);
		} else {
			error = crypto_verify_final(DPROV_CTX_SINGLE(ctx),
			    taskq_req->dr_verify_req.vr_signature, NULL);
		}

		ASSERT(error != CRYPTO_BUFFER_TOO_SMALL);
		DPROV_CTX_SINGLE(ctx) = NULL;
		(void) dprov_free_context(ctx);
		break;

	case DPROV_REQ_VERIFY_ATOMIC:
	case DPROV_REQ_VERIFY_RECOVER_ATOMIC:
		/* structure assignment */
		mech = *taskq_req->dr_verify_req.vr_mechanism;

		mutex_enter(&softc->ds_lock);
		/* get key value for secret key algorithms */
		if (is_publickey_mech(mech.cm_type)) {
			if ((error = dprov_key_attr_asymmetric(softc,
			    taskq_req->dr_verify_req.vr_session_id,
			    taskq_req->dr_type,
			    taskq_req->dr_verify_req.vr_key, &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		} else {
			if ((error = dprov_key_value_secret(softc,
			    taskq_req->dr_verify_req.vr_session_id,
			    taskq_req->dr_type,
			    taskq_req->dr_verify_req.vr_key, &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		}
		mutex_exit(&softc->ds_lock);

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(
		    taskq_req->dr_verify_req.vr_mechanism, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* Use a session id of zero since we use a software provider */
		if (taskq_req->dr_type == DPROV_REQ_VERIFY_ATOMIC)
			error = crypto_verify_prov(pd, 0, &mech, keyp,
			    taskq_req->dr_verify_req.vr_data,
			    NULL, taskq_req->dr_verify_req.vr_signature, NULL);
		else
			/*
			 * crypto_verify_recover_prov() has different argument
			 * order than crypto_verify_prov().
			 */
			error = crypto_verify_recover_prov(pd, 0, &mech, keyp,
			    taskq_req->dr_verify_req.vr_signature,
			    NULL, taskq_req->dr_verify_req.vr_data, NULL);

		/* release provider reference */
		KCF_PROV_REFRELE(pd);
		break;

	case DPROV_REQ_VERIFY_RECOVER:
		/*
		 * crypto_verify_recover_single() has different argument
		 * order than crypto_verify_single().
		 */
		error = crypto_verify_recover_single(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_verify_req.vr_signature,
		    taskq_req->dr_verify_req.vr_data, NULL);

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;
	}

	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_VERIFY, ("(%d) dprov_verify_task: end\n", instance));
}

/*
 * taskq dispatcher function for dual operations.
 */
static void
dprov_dual_task(dprov_req_t *taskq_req)
{
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;
	crypto_ctx_t *signverify_ctx = taskq_req->dr_dual_req.dr_signverify_ctx;
	crypto_ctx_t *cipher_ctx = taskq_req->dr_dual_req.dr_cipher_ctx;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_DUAL, ("(%d) dprov_dual_task: started\n", instance));

	switch (taskq_req->dr_type) {

	case DPROV_REQ_DIGEST_ENCRYPT_UPDATE:
		error = crypto_digest_encrypt_update(
		    DPROV_CTX_SINGLE(signverify_ctx),
		    DPROV_CTX_SINGLE(cipher_ctx),
		    taskq_req->dr_dual_req.dr_plaintext,
		    taskq_req->dr_dual_req.dr_ciphertext, NULL);
		break;

	case DPROV_REQ_DECRYPT_DIGEST_UPDATE:
		error = crypto_decrypt_digest_update(
		    DPROV_CTX_SINGLE(cipher_ctx),
		    DPROV_CTX_SINGLE(signverify_ctx),
		    taskq_req->dr_dual_req.dr_ciphertext,
		    taskq_req->dr_dual_req.dr_plaintext, NULL);
		break;

	case DPROV_REQ_SIGN_ENCRYPT_UPDATE:
		error = crypto_sign_encrypt_update(
		    DPROV_CTX_SINGLE(signverify_ctx),
		    DPROV_CTX_SINGLE(cipher_ctx),
		    taskq_req->dr_dual_req.dr_plaintext,
		    taskq_req->dr_dual_req.dr_ciphertext, NULL);
		break;

	case DPROV_REQ_DECRYPT_VERIFY_UPDATE:
		error = crypto_decrypt_verify_update(
		    DPROV_CTX_SINGLE(cipher_ctx),
		    DPROV_CTX_SINGLE(signverify_ctx),
		    taskq_req->dr_dual_req.dr_ciphertext,
		    taskq_req->dr_dual_req.dr_plaintext, NULL);
		break;
	}

	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_DUAL, ("(%d) dprov_dual_task: end\n", instance));
}

/*
 * taskq dispatcher function for cipher operations.
 */
static void
dprov_cipher_task(dprov_req_t *taskq_req)
{
	kcf_provider_desc_t *pd;
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;
	crypto_ctx_t *ctx = taskq_req->dr_cipher_req.dr_ctx;
	crypto_key_t key, *keyp;
	crypto_mechanism_t mech;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_CIPHER, ("(%d) dprov_cipher_task: started\n", instance));

	switch (taskq_req->dr_type) {

	case DPROV_REQ_ENCRYPT_INIT:
	case DPROV_REQ_DECRYPT_INIT:
		/* allocate a dprov-private context */
		if ((error = dprov_alloc_context(taskq_req->dr_type, ctx)) !=
		    CRYPTO_SUCCESS)
			break;

		/* structure assignment */
		mech = *taskq_req->dr_cipher_req.dr_mechanism;

		mutex_enter(&softc->ds_lock);
		/* get key value for secret key algorithms */
		if (is_publickey_mech(mech.cm_type)) {
			if ((error = dprov_key_attr_asymmetric(softc,
			    ctx->cc_session, taskq_req->dr_type,
			    taskq_req->dr_cipher_req.dr_key, &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		} else {
			if ((error = dprov_key_value_secret(softc,
			    ctx->cc_session, taskq_req->dr_type,
			    taskq_req->dr_cipher_req.dr_key, &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		}
		mutex_exit(&softc->ds_lock);

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(
		    taskq_req->dr_cipher_req.dr_mechanism, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* Use a session id of zero since we use a software provider */
		if (taskq_req->dr_type == DPROV_REQ_ENCRYPT_INIT)
			error = crypto_encrypt_init_prov(pd, 0, &mech, keyp,
			    NULL, &DPROV_CTX_SINGLE(ctx), NULL);
		else
			error = crypto_decrypt_init_prov(pd, 0, &mech, keyp,
			    NULL, &DPROV_CTX_SINGLE(ctx), NULL);

		if (ctx->cc_flags & CRYPTO_INIT_OPSTATE) {
			crypto_ctx_t *lctx =
			    (crypto_ctx_t *)(DPROV_CTX_SINGLE(ctx));

			ctx->cc_opstate = lctx->cc_provider_private;
			ctx->cc_flags |= CRYPTO_USE_OPSTATE;
		}

		/* release provider reference */
		KCF_PROV_REFRELE(pd);
		break;

	case DPROV_REQ_ENCRYPT:
		error = crypto_encrypt_single(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_cipher_req.dr_plaintext,
		    taskq_req->dr_cipher_req.dr_ciphertext, NULL);

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_DECRYPT:
		error = crypto_decrypt_single(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_cipher_req.dr_ciphertext,
		    taskq_req->dr_cipher_req.dr_plaintext, NULL);

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_ENCRYPT_UPDATE:
		ASSERT(!(ctx->cc_flags & CRYPTO_INIT_OPSTATE) ||
		    (ctx->cc_flags & CRYPTO_USE_OPSTATE));
		error = crypto_encrypt_update(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_cipher_req.dr_plaintext,
		    taskq_req->dr_cipher_req.dr_ciphertext, NULL);
		break;

	case DPROV_REQ_DECRYPT_UPDATE:
		ASSERT(!(ctx->cc_flags & CRYPTO_INIT_OPSTATE) ||
		    (ctx->cc_flags & CRYPTO_USE_OPSTATE));
		error = crypto_decrypt_update(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_cipher_req.dr_ciphertext,
		    taskq_req->dr_cipher_req.dr_plaintext, NULL);
		break;

	case DPROV_REQ_ENCRYPT_FINAL:
		error = crypto_encrypt_final(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_cipher_req.dr_ciphertext, NULL);
		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_DECRYPT_FINAL:
		error = crypto_decrypt_final(DPROV_CTX_SINGLE(ctx),
		    taskq_req->dr_cipher_req.dr_plaintext, NULL);
		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_SINGLE(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_ENCRYPT_ATOMIC:
	case DPROV_REQ_DECRYPT_ATOMIC:
		/* structure assignment */
		mech = *taskq_req->dr_cipher_req.dr_mechanism;

		mutex_enter(&softc->ds_lock);
		/* get key value for secret key algorithms */
		if (is_publickey_mech(mech.cm_type)) {
			if ((error = dprov_key_attr_asymmetric(softc,
			    taskq_req->dr_cipher_req.dr_session_id,
			    taskq_req->dr_type,
			    taskq_req->dr_cipher_req.dr_key,
			    &key)) != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		} else {
			if ((error = dprov_key_value_secret(softc,
			    taskq_req->dr_cipher_req.dr_session_id,
			    taskq_req->dr_type, taskq_req->dr_cipher_req.dr_key,
			    &key))
			    != CRYPTO_SUCCESS) {
				mutex_exit(&softc->ds_lock);
				break;
			}
			keyp = &key;
		}
		mutex_exit(&softc->ds_lock);

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(
		    taskq_req->dr_cipher_req.dr_mechanism, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* use a session id of zero since we use a software provider */
		if (taskq_req->dr_type == DPROV_REQ_ENCRYPT_ATOMIC)
			error = crypto_encrypt_prov(pd, 0, &mech,
			    taskq_req->dr_cipher_req.dr_plaintext,
			    keyp, NULL,
			    taskq_req->dr_cipher_req.dr_ciphertext, NULL);
		else
			error = crypto_decrypt_prov(pd, 0, &mech,
			    taskq_req->dr_cipher_req.dr_ciphertext,
			    keyp, NULL,
			    taskq_req->dr_cipher_req.dr_plaintext, NULL);

		/* release provider reference */
		KCF_PROV_REFRELE(pd);

		break;
	}

	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_MAC, ("(%d) dprov_mac_task: end\n", instance));
}

/*
 * Helper function for the cipher/mac dual operation taskq dispatch
 * function. Initialize the cipher and mac key values and find the
 * providers that can process the request for the specified mechanisms.
 */
static int
dprov_cipher_mac_key_pd(dprov_state_t *softc, crypto_session_id_t sid,
    dprov_req_t *taskq_req, crypto_key_t *cipher_key, crypto_key_t *mac_key,
    kcf_provider_desc_t **cipher_pd, kcf_provider_desc_t **mac_pd,
    crypto_mech_type_t *cipher_mech_type, crypto_mech_type_t *mac_mech_type)
{
	int error;

	/* get the cipher key value */
	mutex_enter(&softc->ds_lock);
	error = dprov_key_value_secret(softc, sid, DPROV_REQ_ENCRYPT_ATOMIC,
	    taskq_req->dr_cipher_mac_req.mr_cipher_key, cipher_key);
	if (error != CRYPTO_SUCCESS) {
		mutex_exit(&softc->ds_lock);
		return (error);
	}

	/* get the mac key value */
	error = dprov_key_value_secret(softc, sid, DPROV_REQ_MAC_ATOMIC,
	    taskq_req->dr_cipher_mac_req.mr_mac_key, mac_key);
	mutex_exit(&softc->ds_lock);
	if (error != CRYPTO_SUCCESS)
		return (error);

	/* get the SW provider to perform the cipher operation */
	if ((error = dprov_get_sw_prov(
	    taskq_req->dr_cipher_mac_req.mr_cipher_mech, cipher_pd,
	    cipher_mech_type)) != CRYPTO_SUCCESS)
		return (error);

	/* get the SW provider to perform the mac operation */
	error = dprov_get_sw_prov(taskq_req->dr_cipher_mac_req.mr_mac_mech,
	    mac_pd, mac_mech_type);

	return (error);
}

/*
 * taskq dispatcher function for cipher/mac dual operations.
 */
static void
dprov_cipher_mac_task(dprov_req_t *taskq_req)
{
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;
	crypto_ctx_t *ctx = taskq_req->dr_cipher_mac_req.mr_ctx;
	kcf_provider_desc_t *cipher_pd;
	kcf_provider_desc_t *mac_pd;
	crypto_key_t cipher_key;
	crypto_key_t mac_key;
	crypto_dual_data_t *dual_data =
	    taskq_req->dr_cipher_mac_req.mr_dual_data;
	crypto_data_t cipher_data;
	crypto_data_t mac_data;
	crypto_mechanism_t cipher_mech, mac_mech;
	crypto_session_id_t session_id;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_cipher_mac_task: started\n",
	    instance));

	switch (taskq_req->dr_type) {
	case DPROV_REQ_ENCRYPT_MAC_INIT:
	case DPROV_REQ_MAC_DECRYPT_INIT:
		/* structure assignment */
		cipher_mech = *taskq_req->dr_cipher_mac_req.mr_cipher_mech;
		mac_mech = *taskq_req->dr_cipher_mac_req.mr_mac_mech;

		/* get the keys values and providers to use for operations */
		if ((error = dprov_cipher_mac_key_pd(softc, ctx->cc_session,
		    taskq_req, &cipher_key, &mac_key, &cipher_pd, &mac_pd,
		    &cipher_mech.cm_type, &mac_mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* allocate a dprov-private context */
		if ((error = dprov_alloc_context(taskq_req->dr_type, ctx)) !=
		    CRYPTO_SUCCESS)
			break;

		if (taskq_req->dr_type == DPROV_REQ_ENCRYPT_MAC_INIT)
			/* do the encryption initialization */
			error = crypto_encrypt_init_prov(cipher_pd, 0,
			    &cipher_mech, &cipher_key, NULL,
			    &DPROV_CTX_DUAL_CIPHER(ctx), NULL);
		else
			/* do the decryption initialization */
			error = crypto_decrypt_init_prov(cipher_pd, 0,
			    &cipher_mech, &cipher_key, NULL,
			    &DPROV_CTX_DUAL_CIPHER(ctx), NULL);
		if (error != CRYPTO_SUCCESS)
			break;

		/* do the mac initialization */
		if ((error = crypto_mac_init_prov(mac_pd, 0,
		    &mac_mech, &mac_key, NULL, &DPROV_CTX_DUAL_MAC(ctx),
		    NULL)) != CRYPTO_SUCCESS)
			break;

		/* release references to providers */
		KCF_PROV_REFRELE(cipher_pd);
		KCF_PROV_REFRELE(mac_pd);

		break;

	case DPROV_REQ_ENCRYPT_MAC: {
		size_t encrypted;
		boolean_t inplace;

		crypto_data_t *plaintext_tmp, *ciphertext_tmp;

		cipher_data = *((crypto_data_t *)dual_data);

		/* do an encrypt update */
		inplace = (taskq_req->dr_cipher_mac_req.mr_data == NULL);
		if (inplace) {
			plaintext_tmp = &cipher_data;
			ciphertext_tmp = NULL;
		} else {
			plaintext_tmp = taskq_req->dr_cipher_mac_req.mr_data;
			ciphertext_tmp = &cipher_data;
		}
		if ((error = crypto_encrypt_update(DPROV_CTX_DUAL_CIPHER(ctx),
		    plaintext_tmp, ciphertext_tmp, NULL)) != CRYPTO_SUCCESS)
			break;

		/* do an encrypt final */
		encrypted = cipher_data.cd_length;

		cipher_data.cd_offset += encrypted;
		cipher_data.cd_length = dual_data->dd_len1 - encrypted;

		if ((error = crypto_encrypt_final(DPROV_CTX_DUAL_CIPHER(ctx),
		    &cipher_data, NULL)) != CRYPTO_SUCCESS)
			break;

		/*
		 * Do a mac update on the resulting ciphertext, but with no
		 * more bytes than specified by dual_data, and starting at
		 * offset specified by dual_data. For in-place operations,
		 * we use the length specified by the dual_data.
		 */
		mac_data = cipher_data;
		mac_data.cd_offset = dual_data->dd_offset2;
		mac_data.cd_length = dual_data->dd_len2;
		if ((error = crypto_mac_update(DPROV_CTX_DUAL_MAC(ctx),
		    &mac_data, NULL)) != CRYPTO_SUCCESS)
			break;

		/* do a mac final */
		error = crypto_mac_final(DPROV_CTX_DUAL_MAC(ctx),
		    taskq_req->dr_cipher_mac_req.mr_mac, NULL);

		/* Set the total size of the ciphertext, when successful */
		if (error == CRYPTO_SUCCESS)
			dual_data->dd_len1 = encrypted + cipher_data.cd_length;

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_DUAL_CIPHER(ctx) = NULL;
			DPROV_CTX_DUAL_MAC(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;
	}

	case DPROV_REQ_ENCRYPT_MAC_UPDATE: {
		crypto_data_t *plaintext_tmp, *ciphertext_tmp;
		size_t encrypted;
		ssize_t maclen;
		boolean_t inplace;

		cipher_data = *((crypto_data_t *)dual_data);

		/* do an encrypt update */
		inplace = (taskq_req->dr_cipher_mac_req.mr_data == NULL);
		if (inplace) {
			plaintext_tmp = &cipher_data;
			ciphertext_tmp = NULL;
		} else {
			plaintext_tmp = taskq_req->dr_cipher_mac_req.mr_data;
			ciphertext_tmp = &cipher_data;
		}
		if ((error = crypto_encrypt_update(DPROV_CTX_DUAL_CIPHER(ctx),
		    plaintext_tmp, ciphertext_tmp, NULL)) != CRYPTO_SUCCESS)
			break;

		encrypted = cipher_data.cd_length;

		/*
		 * Do a mac update on the resulting ciphertext, but with no
		 * more bytes than specified by dual_data, and starting at
		 * offset specified by dual_data. For in-place operations,
		 * we use the length specified by the dual_data.
		 * There is an edge case, when the encryption step produced
		 * zero bytes in the ciphertext. Only the portion between
		 * offset2 and offset1 is then thrown in the MAC mix.
		 */
		maclen = dual_data->dd_offset1 - dual_data->dd_offset2 +
		    encrypted;
		if (maclen > 0) {
			mac_data = cipher_data;
			mac_data.cd_offset = dual_data->dd_offset2;
			mac_data.cd_length = min(dual_data->dd_len2, maclen);
			if ((error = crypto_mac_update(DPROV_CTX_DUAL_MAC(ctx),
			    &mac_data, NULL)) != CRYPTO_SUCCESS)
				break;
		}
		/* Set the total size of the ciphertext, when successful */
		if (error == CRYPTO_SUCCESS)
			dual_data->dd_len1 = encrypted;

		break;
	}

	case DPROV_REQ_ENCRYPT_MAC_FINAL:
		cipher_data = *((crypto_data_t *)dual_data);

		/* do an encrypt final */
		if ((error = crypto_encrypt_final(DPROV_CTX_DUAL_CIPHER(ctx),
		    taskq_req->dr_cipher_mac_req.mr_data == NULL ?
		    &cipher_data : taskq_req->dr_cipher_mac_req.mr_data,
		    NULL)) != CRYPTO_SUCCESS)
			break;

		/*
		 * If ciphertext length is different from zero, do a mac
		 * update on it. This does not apply to in-place since we
		 * do not allow partial updates, hence no final residual.
		 */
		if (taskq_req->dr_cipher_mac_req.mr_data != NULL &&
		    taskq_req->dr_cipher_mac_req.mr_data->cd_length > 0)
			if ((error = crypto_mac_update(DPROV_CTX_DUAL_MAC(ctx),
			    taskq_req->dr_cipher_mac_req.mr_data, NULL)) !=
			    CRYPTO_SUCCESS)
				break;

		/* do a mac final */
		error = crypto_mac_final(DPROV_CTX_DUAL_MAC(ctx),
		    taskq_req->dr_cipher_mac_req.mr_mac, NULL);

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_DUAL_CIPHER(ctx) = NULL;
			DPROV_CTX_DUAL_MAC(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_ENCRYPT_MAC_ATOMIC: {
		crypto_data_t *plaintext_tmp, *ciphertext_tmp;
		boolean_t inplace;

		cipher_data = *((crypto_data_t *)dual_data);

		/* do an encrypt atomic */
		inplace = (taskq_req->dr_cipher_mac_req.mr_data == NULL);
		if (inplace) {
			plaintext_tmp = &cipher_data;
			ciphertext_tmp = NULL;
		} else {
			plaintext_tmp = taskq_req->dr_cipher_mac_req.mr_data;
			ciphertext_tmp = &cipher_data;
		}

		/* structure assignment */
		cipher_mech = *taskq_req->dr_cipher_mac_req.mr_cipher_mech;
		mac_mech = *taskq_req->dr_cipher_mac_req.mr_mac_mech;
		session_id = taskq_req->dr_cipher_mac_req.mr_session_id;

		/* get the keys values and providers to use for operations */
		if ((error = dprov_cipher_mac_key_pd(softc, session_id,
		    taskq_req, &cipher_key, &mac_key, &cipher_pd, &mac_pd,
		    &cipher_mech.cm_type, &mac_mech.cm_type)) !=
		    CRYPTO_SUCCESS)
			break;

		/* do the atomic encrypt */
		if ((error = crypto_encrypt_prov(cipher_pd, 0,
		    &cipher_mech, plaintext_tmp, &cipher_key, NULL,
		    ciphertext_tmp, NULL)) != CRYPTO_SUCCESS)
			break;

		/* do the atomic mac */
		mac_data = cipher_data;
		mac_data.cd_length = dual_data->dd_len2;
		mac_data.cd_offset = dual_data->dd_offset2;
		error = crypto_mac_prov(mac_pd, 0, &mac_mech, &mac_data,
		    &mac_key, NULL, taskq_req->dr_cipher_mac_req.mr_mac, NULL);

		dual_data->dd_len1 = cipher_data.cd_length;

		break;
	}

	case DPROV_REQ_MAC_DECRYPT: {
		uint_t decrypted;
		crypto_data_t plaintext_tmp;

		cipher_data = *((crypto_data_t *)dual_data);

		/* do a mac update and final on the ciphertext */
		if ((error = crypto_mac_update(DPROV_CTX_DUAL_MAC(ctx),
		    &mac_data, NULL)) != CRYPTO_SUCCESS)
			break;

		/* do a mac final */
		if ((error = crypto_mac_final(DPROV_CTX_DUAL_MAC(ctx),
		    taskq_req->dr_cipher_mac_req.mr_mac, NULL)) !=
		    CRYPTO_SUCCESS)
			break;

		/* do an decrypt update */
		cipher_data = mac_data;
		cipher_data.cd_length = dual_data->dd_len2;
		cipher_data.cd_offset = dual_data->dd_offset2;
		if (taskq_req->dr_cipher_mac_req.mr_data == NULL)
			/* in-place */
			plaintext_tmp = cipher_data;
		else
			plaintext_tmp = *taskq_req->dr_cipher_mac_req.mr_data;

		if ((error = crypto_decrypt_update(DPROV_CTX_DUAL_CIPHER(ctx),
		    &cipher_data, taskq_req->dr_cipher_mac_req.mr_data,
		    NULL)) != CRYPTO_SUCCESS)
			break;

		/* do an decrypt final */
		if (taskq_req->dr_cipher_mac_req.mr_data == NULL)
			/* in-place, everything must have been decrypted */
			decrypted = cipher_data.cd_length;
		else
			decrypted =
			    taskq_req->dr_cipher_mac_req.mr_data->cd_length;
		plaintext_tmp.cd_offset += decrypted;
		plaintext_tmp.cd_length -= decrypted;

		error = crypto_decrypt_final(DPROV_CTX_DUAL_CIPHER(ctx),
		    &plaintext_tmp, NULL);
		if (taskq_req->dr_cipher_mac_req.mr_data != NULL)
			taskq_req->dr_cipher_mac_req.mr_data->cd_length +=
			    plaintext_tmp.cd_length;

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_DUAL_MAC(ctx) = NULL;
			DPROV_CTX_DUAL_CIPHER(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;
	}

	case DPROV_REQ_MAC_DECRYPT_UPDATE:
		cipher_data = *((crypto_data_t *)dual_data);

		/* do mac update */
		if ((error = crypto_mac_update(DPROV_CTX_DUAL_MAC(ctx),
		    &cipher_data, NULL)) != CRYPTO_SUCCESS)
			break;

		/* do a decrypt update */
		cipher_data.cd_length = dual_data->dd_len2;
		cipher_data.cd_offset = dual_data->dd_offset2;
		error = crypto_decrypt_update(DPROV_CTX_DUAL_CIPHER(ctx),
		    &cipher_data, taskq_req->dr_cipher_mac_req.mr_data, NULL);

		break;

	case DPROV_REQ_MAC_DECRYPT_FINAL:
		/* do a mac final */
		if ((error = crypto_mac_final(DPROV_CTX_DUAL_MAC(ctx),
		    taskq_req->dr_cipher_mac_req.mr_mac, NULL)) !=
		    CRYPTO_SUCCESS)
			break;

		/* do a decrypt final */
		error = crypto_decrypt_final(DPROV_CTX_DUAL_CIPHER(ctx),
		    taskq_req->dr_cipher_mac_req.mr_data, NULL);

		if (error != CRYPTO_BUFFER_TOO_SMALL) {
			DPROV_CTX_DUAL_MAC(ctx) = NULL;
			DPROV_CTX_DUAL_CIPHER(ctx) = NULL;
			(void) dprov_free_context(ctx);
		}
		break;

	case DPROV_REQ_MAC_DECRYPT_ATOMIC:
	case DPROV_REQ_MAC_VERIFY_DECRYPT_ATOMIC:
		cipher_data = *((crypto_data_t *)dual_data);

		/* structure assignment */
		cipher_mech = *taskq_req->dr_cipher_mac_req.mr_cipher_mech;
		mac_mech = *taskq_req->dr_cipher_mac_req.mr_mac_mech;
		session_id = taskq_req->dr_cipher_mac_req.mr_session_id;

		/* get the keys values and providers to use for operations */
		if ((error = dprov_cipher_mac_key_pd(softc, session_id,
		    taskq_req, &cipher_key, &mac_key, &cipher_pd, &mac_pd,
		    &cipher_mech.cm_type, &mac_mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* do the atomic mac */
		if (taskq_req->dr_type == DPROV_REQ_MAC_DECRYPT_ATOMIC)
			error = crypto_mac_prov(mac_pd, 0, &mac_mech,
			    &cipher_data, &mac_key, NULL,
			    taskq_req->dr_cipher_mac_req.mr_mac, NULL);
		else
			/* DPROV_REQ_MAC_VERIFY_DECRYPT_ATOMIC */
			error = crypto_mac_verify_prov(mac_pd, 0, &mac_mech,
			    &cipher_data, &mac_key, NULL,
			    taskq_req->dr_cipher_mac_req.mr_mac, NULL);

		if (error != CRYPTO_SUCCESS)
			break;

		/* do the atomic decrypt */
		cipher_data.cd_length = dual_data->dd_len2;
		cipher_data.cd_offset = dual_data->dd_offset2;
		error = crypto_decrypt_prov(cipher_pd, 0, &cipher_mech,
		    &cipher_data, &cipher_key, NULL,
		    taskq_req->dr_cipher_mac_req.mr_data, NULL);

		break;
	}

	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_CIPHER_MAC, ("(%d) dprov_cipher_mac_task: end\n",
	    instance));
}

/*
 * taskq dispatcher function for random number generation.
 */
static void
dprov_random_task(dprov_req_t *taskq_req)
{
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_SUCCESS;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_RANDOM, ("(%d) dprov_random_task: started\n", instance));

	mutex_enter(&softc->ds_lock);

	switch (taskq_req->dr_type) {

	DPROV_REQ_RANDOM_SEED:
		/*
		 * Since we don't really generate random numbers
		 * nothing to do.
		 */
		break;

	case DPROV_REQ_RANDOM_GENERATE: {
		uint_t i;
		uchar_t c = 0;

		/*
		 * We don't generate random numbers so that the result
		 * of the operation can be checked during testing.
		 */

		for (i = 0; i < taskq_req->dr_random_req.rr_len; i++)
			taskq_req->dr_random_req.rr_buf[i] = c++;

		break;
	}
	}

	mutex_exit(&softc->ds_lock);
	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_RANDOM, ("(%d) dprov_random_task: end\n", instance));
}


/*
 * taskq dispatcher function for session management operations.
 */
static void
dprov_session_task(dprov_req_t *taskq_req)
{
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;
	crypto_session_id_t session_id =
	    taskq_req->dr_session_req.sr_session_id;
	dprov_session_t *session;
	dprov_object_t *object;
	int i;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_SESSION, ("(%d) dprov_session_task: started\n",
	    instance));

	mutex_enter(&softc->ds_lock);

	if (taskq_req->dr_type != DPROV_REQ_SESSION_OPEN)
		/* validate session id and get ptr to session */
		if ((session = softc->ds_sessions[session_id]) == NULL) {
			mutex_exit(&softc->ds_lock);
			dprov_op_done(taskq_req, CRYPTO_SESSION_HANDLE_INVALID);
			return;
		}

	switch (taskq_req->dr_type) {

	case DPROV_REQ_SESSION_OPEN: {
		dprov_session_t **new_sessions;

		if (softc->ds_token_initialized == B_FALSE) {
			error = CRYPTO_OPERATION_NOT_INITIALIZED;
			break;
		}

		/* search for available session slot */
		for (i = 0; i < softc->ds_sessions_slots; i++)
			if (softc->ds_sessions[i] == NULL)
				break;

		if (i == softc->ds_sessions_slots) {
			/* ran out of slots, grow sessions array */
			new_sessions = kmem_zalloc(
			    2 * softc->ds_sessions_slots *
			    sizeof (dprov_session_t *), KM_NOSLEEP);
			if (new_sessions == NULL) {
				error = CRYPTO_SESSION_COUNT;
				break;
			}
			bcopy(softc->ds_sessions, new_sessions,
			    softc->ds_sessions_slots *
			    sizeof (dprov_session_t *));
			kmem_free(softc->ds_sessions, softc->ds_sessions_slots *
			    sizeof (dprov_session_t *));
			softc->ds_sessions = new_sessions;
			softc->ds_sessions_slots *= 2;
		}

		/* allocate and initialize new session */
		softc->ds_sessions[i] = kmem_zalloc(
		    sizeof (dprov_session_t), KM_NOSLEEP);
		if (softc->ds_sessions[i] == NULL) {
			error = CRYPTO_HOST_MEMORY;
			break;
		}
		softc->ds_sessions_count++;

		/* initialize session state */
		softc->ds_sessions[i]->ds_state = DPROV_SESSION_STATE_PUBLIC;

		/* return new session id to caller */
		*(taskq_req->dr_session_req.sr_session_id_ptr) = i;

		error = CRYPTO_SUCCESS;
		break;
	}

	case DPROV_REQ_SESSION_CLOSE:
		softc->ds_sessions[session_id] = NULL;

		if (softc->ds_token_initialized == B_FALSE) {
			error = CRYPTO_OPERATION_NOT_INITIALIZED;
			break;
		}

		dprov_release_session_objects(session);

		/* free session state and corresponding slot */
		kmem_free(session, sizeof (dprov_session_t));
		softc->ds_sessions_count--;

		error = CRYPTO_SUCCESS;
		break;

	case DPROV_REQ_SESSION_LOGIN: {
		char *pin = taskq_req->dr_session_req.sr_pin;
		size_t pin_len = taskq_req->dr_session_req.sr_pin_len;
		crypto_user_type_t user_type =
		    taskq_req->dr_session_req.sr_user_type;

		/* check user type */
		if (user_type != CRYPTO_SO && user_type != CRYPTO_USER) {
			error = CRYPTO_USER_TYPE_INVALID;
			break;
		}

		/* check pin length */
		if (pin_len > DPROV_MAX_PIN_LEN) {
			error = CRYPTO_PIN_LEN_RANGE;
			break;
		}

		/* check pin */
		if (pin == NULL) {
			error = CRYPTO_PIN_INVALID;
			break;
		}

		/* validate PIN state */
		if ((user_type == CRYPTO_SO) && !softc->ds_token_initialized ||
		    (user_type == CRYPTO_USER) && !softc->ds_user_pin_set) {
			error = CRYPTO_USER_PIN_NOT_INITIALIZED;
			break;
		}

		if ((user_type == CRYPTO_SO &&
		    softc->ds_sessions[session_id]->ds_state ==
		    DPROV_SESSION_STATE_SO) ||
		    (user_type == CRYPTO_USER &&
		    softc->ds_sessions[session_id]->ds_state ==
		    DPROV_SESSION_STATE_USER)) {
			/* SO or user already logged in */
			error = CRYPTO_USER_ALREADY_LOGGED_IN;
			break;
		}

		if (softc->ds_sessions[session_id]->ds_state !=
		    DPROV_SESSION_STATE_PUBLIC) {
			/* another user already logged in */
			error = CRYPTO_USER_ANOTHER_ALREADY_LOGGED_IN;
			break;
		}

		/* everything's fine, update session */
		softc->ds_sessions[session_id]->ds_state =
		    user_type == CRYPTO_SO ?
		    DPROV_SESSION_STATE_SO : DPROV_SESSION_STATE_USER;

		error = CRYPTO_SUCCESS;
		break;
	}

	case DPROV_REQ_SESSION_LOGOUT:
		/* fail if not logged in */
		if (softc->ds_sessions[session_id]->ds_state ==
		    DPROV_SESSION_STATE_PUBLIC) {
			error = CRYPTO_USER_NOT_LOGGED_IN;
			break;
		}

		/*
		 * Destroy all private session objects.
		 * Invalidate handles to all private objects.
		 */
		for (i = 0; i < DPROV_MAX_OBJECTS; i++) {
			object = softc->ds_sessions[session_id]->ds_objects[i];
			if (object != NULL && dprov_object_is_private(object)) {
				if (!dprov_object_is_token(object))
					/* It's a session object, free it */
					DPROV_OBJECT_REFRELE(object);
				softc->ds_sessions[session_id]->ds_objects[i] =
				    NULL;
			}
		}

		/* update session state */
		softc->ds_sessions[session_id]->ds_state =
		    DPROV_SESSION_STATE_PUBLIC;

		error = CRYPTO_SUCCESS;
		break;
	}

	mutex_exit(&softc->ds_lock);
	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_SESSION, ("(%d) dprov_session_task: end\n", instance));
}

/* return true if attribute is defined to be a PKCS#11 long */
static boolean_t
fixed_size_attribute(crypto_attr_type_t type)
{
	return (type == DPROV_CKA_CLASS ||
	    type == DPROV_CKA_CERTIFICATE_TYPE ||
	    type == DPROV_CKA_KEY_TYPE ||
	    type == DPROV_HW_FEATURE_TYPE);
}

/*
 * Attributes defined to be a PKCS#11 long causes problems for dprov
 * because 32-bit applications set the size to 4 and 64-bit applications
 * set the size to 8. dprov always stores these fixed-size attributes
 * as uint32_t.
 */
static ssize_t
attribute_size(crypto_attr_type_t type, ssize_t len)
{
	if (fixed_size_attribute(type))
		return (sizeof (uint32_t));

	return (len);
}

/*
 * taskq dispatcher function for object management operations.
 */
static void
dprov_object_task(dprov_req_t *taskq_req)
{
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;
	crypto_object_id_t object_id = taskq_req->dr_object_req.or_object_id;
	crypto_session_id_t session_id = taskq_req->dr_object_req.or_session_id;
	crypto_object_attribute_t *template =
	    taskq_req->dr_object_req.or_template;
	uint_t attr_count = taskq_req->dr_object_req.or_attribute_count;
	dprov_object_t *object;
	dprov_session_t *session;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_task: started\n", instance));

	mutex_enter(&softc->ds_lock);

	/* validate session id and get ptr to session */
	if ((session = softc->ds_sessions[session_id]) == NULL) {
		mutex_exit(&softc->ds_lock);
		dprov_op_done(taskq_req, CRYPTO_SESSION_HANDLE_INVALID);
		return;
	}

	switch (taskq_req->dr_type) {

	case DPROV_REQ_OBJECT_CREATE:
		/* create the object from the specified template */
		if ((error = dprov_create_object_from_template(softc, session,
		    template, attr_count,
		    taskq_req->dr_object_req.or_object_id_ptr, B_TRUE,
		    B_FALSE)) != CRYPTO_SUCCESS)
			break;

		break;

	case DPROV_REQ_OBJECT_COPY:
		/* check object id */
		if (object_id >= DPROV_MAX_OBJECTS ||
		    (object = session->ds_objects[object_id]) == NULL) {
			error = CRYPTO_OBJECT_HANDLE_INVALID;
			break;
		}

		/*
		 * Create a new object from the object passed as
		 * argument.
		 */
		if ((error = dprov_create_object_from_template(softc, session,
		    object->do_attr, DPROV_MAX_ATTR,
		    taskq_req->dr_object_req.or_object_id_ptr, B_TRUE,
		    B_FALSE)) != CRYPTO_SUCCESS)
			break;

		/*
		 * Add the attributes specified by the template to the
		 * newly created object, replacing existing ones if needed.
		 */
		error = dprov_object_set_attr(session,
		    *taskq_req->dr_object_req.or_object_id_ptr,
		    taskq_req->dr_object_req.or_template,
		    taskq_req->dr_object_req.or_attribute_count, B_TRUE);

		break;

	case DPROV_REQ_OBJECT_DESTROY:
		/* destroy the object */
		error = dprov_destroy_object(softc, session,
		    taskq_req->dr_object_req.or_object_id);

		break;

	case DPROV_REQ_OBJECT_GET_SIZE:
		/* get ptr to object */
		if (object_id >= DPROV_MAX_OBJECTS ||
		    session->ds_objects[object_id] == NULL) {
			error = CRYPTO_OBJECT_HANDLE_INVALID;
			break;
		}

		/*
		 * The PKCS11 specification does not specifies what
		 * the object size really is, here we just return
		 * the number of possible attributes of the object.
		 */
		*taskq_req->dr_object_req.or_object_size = DPROV_MAX_ATTR;

		error = CRYPTO_SUCCESS;
		break;

	case DPROV_REQ_OBJECT_GET_ATTRIBUTE_VALUE: {
		crypto_attr_type_t type;
		size_t olen, tlen;
		offset_t offset;
		int tmpl_idx;
		int object_idx;
		ulong_t class = DPROV_CKO_DATA;
		boolean_t extractable = B_TRUE;

		error = CRYPTO_SUCCESS;

		/* get ptr to object */
		if (object_id >= DPROV_MAX_OBJECTS ||
		    (object = session->ds_objects[object_id]) == NULL) {
			error = CRYPTO_OBJECT_HANDLE_INVALID;
			break;
		}

		(void) dprov_get_object_attr_boolean(object,
		    DPROV_CKA_EXTRACTABLE, &extractable);

		(void) dprov_get_object_attr_ulong(object,
		    DPROV_CKA_CLASS, &class);

		/* return the specified attributes, when possible */
		for (tmpl_idx = 0; tmpl_idx < attr_count; tmpl_idx++) {
			/*
			 * Attribute can't be revealed if the CKA_EXTRACTABLE
			 * attribute is set to false.
			 */
			type = template[tmpl_idx].oa_type;
			if (!extractable && class == DPROV_CKO_SECRET_KEY) {
				if (type == DPROV_CKA_VALUE) {
					template[tmpl_idx].oa_value_len = -1;
					error = CRYPTO_ATTRIBUTE_SENSITIVE;
					continue;
				}
			}
			if (!extractable && class == DPROV_CKO_PRIVATE_KEY) {
				if (type == DPROV_CKA_PRIVATE_EXPONENT) {
					template[tmpl_idx].oa_value_len = -1;
					error = CRYPTO_ATTRIBUTE_SENSITIVE;
					continue;
				}
			}

			object_idx = dprov_find_attr(object->do_attr,
			    DPROV_MAX_ATTR, type);
			if (object_idx == -1) {
				/* attribute not found in object */
				template[tmpl_idx].oa_value_len = -1;
				error = CRYPTO_ATTRIBUTE_TYPE_INVALID;
				continue;
			}

			tlen = template[tmpl_idx].oa_value_len;
			olen = object->do_attr[object_idx].oa_value_len;
			/* return attribute length */
			if (template[tmpl_idx].oa_value == NULL) {
				/*
				 * The size of the attribute is set by the
				 * library according to the data model of the
				 * application, so don't overwrite it with
				 * dprov's size.
				 */
				if (!fixed_size_attribute(type))
					template[tmpl_idx].oa_value_len = olen;
				continue;
			}

			if (tlen < olen) {
				template[tmpl_idx].oa_value_len = -1;
				error = CRYPTO_BUFFER_TOO_SMALL;
				continue;
			}

			/* copy attribute value */
			bzero(template[tmpl_idx].oa_value, tlen);

			offset = 0;
#ifdef _BIG_ENDIAN
			if (fixed_size_attribute(type)) {
				offset = tlen - olen;
			}
#endif
			bcopy(object->do_attr[object_idx].oa_value,
			    &template[tmpl_idx].oa_value[offset], olen);

			/* don't update length for fixed-size attributes */
			if (!fixed_size_attribute(type))
				template[tmpl_idx].oa_value_len = olen;
		}

		break;
	}

	case DPROV_REQ_OBJECT_SET_ATTRIBUTE_VALUE:
		/*
		 * Add the attributes specified by the template to the
		 * newly created object, replacing existing ones if needed.
		 */
		error = dprov_object_set_attr(session,
		    taskq_req->dr_object_req.or_object_id,
		    taskq_req->dr_object_req.or_template,
		    taskq_req->dr_object_req.or_attribute_count, B_TRUE);

		break;

	case DPROV_REQ_OBJECT_FIND_INIT: {
		dprov_find_ctx_t *find_ctx;
		int so_idx;		/* session object index */
		int to_idx;		/* token object index */

		error = CRYPTO_SUCCESS;
		/* allocate find context */
		find_ctx = kmem_zalloc(sizeof (dprov_find_ctx_t), KM_SLEEP);
		*taskq_req->dr_object_req.or_find_pp = find_ctx;

		/* first go through the existing session objects */
		for (so_idx = 0; so_idx < DPROV_MAX_OBJECTS; so_idx++) {
			if ((object = session->ds_objects[so_idx]) == NULL)
				continue;

			/* setting count to zero means find all objects */
			if (attr_count > 0) {
				if (!dprov_attributes_match(object, template,
				    attr_count))
					continue;
			}

			/* session object attributes matches template */
			find_ctx->fc_ids[find_ctx->fc_nids] = so_idx;
			find_ctx->fc_nids++;
		}

		/*
		 * Go through the token object. For each token object
		 * that can be accessed:
		 * If there was already an session object id assigned
		 * to that token object, skip it, since it was returned
		 * during the check of session objects, else,
		 * assign a new object id for that token object and
		 * add it to the array of matching objects.
		 */
		for (to_idx = 0; to_idx < DPROV_MAX_OBJECTS &&
		    error == CRYPTO_SUCCESS; to_idx++) {
			if ((object = softc->ds_objects[to_idx]) == NULL)
				continue;

			/* setting count to zero means find all objects */
			if (attr_count > 0) {
				if (!dprov_attributes_match(object, template,
				    attr_count))
					continue;
			}

			/* if the the object has been destroyed, skip it */
			if (object->do_destroyed)
				continue;

			/* skip object if it cannot be accessed from session */
			if (dprov_object_is_private(object) &&
			    session->ds_state != DPROV_SESSION_STATE_USER)
				continue;

			/*
			 * Is there already a session object id for this
			 * token object?
			 */
			for (so_idx = 0; so_idx < DPROV_MAX_OBJECTS; so_idx++)
				if (session->ds_objects[so_idx] != NULL &&
				    session->ds_objects[so_idx]->do_token_idx ==
				    to_idx)
					break;
			if (so_idx < DPROV_MAX_OBJECTS)
				/* object found in session table, skip it */
				continue;

			/* find free session slot for this object */
			for (so_idx = 0; so_idx < DPROV_MAX_OBJECTS; so_idx++)
				if (session->ds_objects[so_idx] == NULL)
					break;
			if (so_idx == DPROV_MAX_OBJECTS) {
				/* ran out of session objects slots */
				kmem_free(find_ctx, sizeof (dprov_find_ctx_t));
				error = CRYPTO_HOST_MEMORY;
				break;
			}

			/* add object to session objects table */
			session->ds_objects[so_idx] = object;
			DPROV_OBJECT_REFHOLD(object);

			/* add object to list of objects to return */
			find_ctx->fc_ids[find_ctx->fc_nids] = so_idx;
			find_ctx->fc_nids++;
		}

		break;
	}

	case DPROV_REQ_OBJECT_FIND: {
		crypto_object_id_t *object_ids =
		    taskq_req->dr_object_req.or_object_id_ptr;
		uint_t max_object_count =
		    taskq_req->dr_object_req.or_max_object_count;
		dprov_find_ctx_t *find_ctx =
		    taskq_req->dr_object_req.or_find_p;
		uint_t ret_oid_idx;

		/* return the desired number of object ids */
		for (ret_oid_idx = 0; ret_oid_idx < max_object_count &&
		    find_ctx->fc_next < find_ctx->fc_nids; ret_oid_idx++)
			object_ids[ret_oid_idx] =
			    find_ctx->fc_ids[find_ctx->fc_next++];

		*taskq_req->dr_object_req.or_object_count_ptr = ret_oid_idx;

		error = CRYPTO_SUCCESS;
		break;
	}

	case DPROV_REQ_OBJECT_FIND_FINAL:
		kmem_free(taskq_req->dr_object_req.or_find_p,
		    sizeof (dprov_find_ctx_t));

		error = CRYPTO_SUCCESS;
		break;
	}

	mutex_exit(&softc->ds_lock);
	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_OBJECT, ("(%d) dprov_object_task: end\n", instance));
}

/*
 * Copy attribute values into a template. RSA values are precomputed.
 */
static int
nostore_copy_attribute(crypto_object_attribute_t *template, uint_t count,
    uint64_t attr_type)
{
	void *value, *dprov_attribute_value;
	size_t dprov_attribute_size;
	size_t value_len = 0;
	int error;

	switch (attr_type) {
	case DPROV_CKA_VALUE:
		dprov_attribute_size = sizeof (dh_value);
		dprov_attribute_value = dh_value;
		break;

	case DPROV_CKA_MODULUS:
		dprov_attribute_size = sizeof (modulus);
		dprov_attribute_value = modulus;
		break;

	case DPROV_CKA_PUBLIC_EXPONENT:
		dprov_attribute_size = sizeof (public_exponent);
		dprov_attribute_value = public_exponent;
		break;

	case DPROV_CKA_PRIVATE_EXPONENT:
		dprov_attribute_size = sizeof (private_exponent);
		dprov_attribute_value = private_exponent;
		break;

	default:
		return (CRYPTO_ATTRIBUTE_TYPE_INVALID);
	}

	error = dprov_get_template_attr_array(template, count, attr_type,
	    &value, &value_len);
	if (error != CRYPTO_SUCCESS)
		return (error);

	if (value_len < dprov_attribute_size)
		return (CRYPTO_BUFFER_TOO_SMALL);

	/*
	 * The updated template will be returned to libpkcs11.
	 */
	bcopy(dprov_attribute_value, value, dprov_attribute_size);

	return (CRYPTO_SUCCESS);
}

static void
fill_dh(void *value, size_t len)
{
	int i = 0;
	char *p = value;
	while (i < len) {
		p[i++] = 'D';
		if (i >= len)
			break;
		p[i++] = 'H';
	}
}

/*
 * taskq dispatcher function for key management operations.
 */
static void
dprov_key_task(dprov_req_t *taskq_req)
{
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;
	kcf_provider_desc_t *pd;
	crypto_session_id_t session_id = taskq_req->dr_key_req.kr_session_id;
	dprov_session_t *session;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_task: started\n", instance));

	mutex_enter(&softc->ds_lock);

	/* validate session id and get ptr to session */
	if ((session = softc->ds_sessions[session_id]) == NULL) {
		mutex_exit(&softc->ds_lock);
		dprov_op_done(taskq_req, CRYPTO_SESSION_HANDLE_INVALID);
		return;
	}

	switch (taskq_req->dr_type) {
	case DPROV_REQ_KEY_GENERATE: {
		crypto_mechanism_t *mechp;
		crypto_object_id_t *object_id_ptr;
		crypto_object_attribute_t *template;
		crypto_object_attribute_t attribute;
		uint_t attribute_count;
		ulong_t key_type = ~0UL, class = ~0UL;
		ulong_t value_len;
		size_t key_len = 0;

		error = CRYPTO_SUCCESS;

		template = taskq_req->dr_key_req.kr_template;
		attribute_count = taskq_req->dr_key_req.kr_attribute_count;
		object_id_ptr = taskq_req->dr_key_req.kr_object_id_ptr;
		mechp = taskq_req->dr_key_req.kr_mechanism;

		/* optional */
		(void) dprov_get_template_attr_ulong(template, attribute_count,
		    DPROV_CKA_CLASS, &class);

		/* optional */
		(void) dprov_get_template_attr_ulong(template, attribute_count,
		    DPROV_CKA_KEY_TYPE, &key_type);

		if (class != ~0UL && class != DPROV_CKO_SECRET_KEY) {
			error = CRYPTO_TEMPLATE_INCONSISTENT;
			break;
		}

		switch (mechp->cm_type) {
		case DES_KEY_GEN_MECH_INFO_TYPE:
			if (key_type != ~0UL && key_type != DPROV_CKK_DES) {
				error = CRYPTO_TEMPLATE_INCONSISTENT;
				break;
			}
			key_len = DES_KEY_LEN;
			key_type = DPROV_CKK_DES;
			break;

		case DES3_KEY_GEN_MECH_INFO_TYPE:
			if (key_type != ~0UL && key_type != DPROV_CKK_DES3) {
				error = CRYPTO_TEMPLATE_INCONSISTENT;
				break;
			}
			key_len = DES3_KEY_LEN;
			key_type = DPROV_CKK_DES3;
			break;

		case AES_KEY_GEN_MECH_INFO_TYPE:
			if (key_type != ~0UL && key_type != DPROV_CKK_AES) {
				error = CRYPTO_TEMPLATE_INCONSISTENT;
				break;
			}
			if (dprov_get_template_attr_ulong(template,
			    attribute_count, DPROV_CKA_VALUE_LEN,
			    &value_len) != CRYPTO_SUCCESS) {
				error = CRYPTO_TEMPLATE_INCOMPLETE;
				break;
			}
			if (value_len >= AES_MAX_KEY_LEN) {
				error = CRYPTO_ATTRIBUTE_VALUE_INVALID;
				break;
			}
			key_len = value_len;
			key_type = DPROV_CKK_AES;
			break;

		case BLOWFISH_KEY_GEN_MECH_INFO_TYPE:
			if (key_type != ~0UL &&
			    key_type != DPROV_CKK_BLOWFISH) {
				error = CRYPTO_TEMPLATE_INCONSISTENT;
				break;
			}
			if (dprov_get_template_attr_ulong(template,
			    attribute_count, DPROV_CKA_VALUE_LEN,
			    &value_len) != CRYPTO_SUCCESS) {
				error = CRYPTO_TEMPLATE_INCOMPLETE;
				break;
			}
			if (value_len >= BLOWFISH_MAX_KEY_LEN) {
				error = CRYPTO_ATTRIBUTE_VALUE_INVALID;
				break;
			}
			key_len = value_len;
			key_type = DPROV_CKK_BLOWFISH;
			break;

		case RC4_KEY_GEN_MECH_INFO_TYPE:
			if (key_type != ~0UL && key_type != DPROV_CKK_RC4) {
				error = CRYPTO_TEMPLATE_INCONSISTENT;
				break;
			}
			if (dprov_get_template_attr_ulong(template,
			    attribute_count, DPROV_CKA_VALUE_LEN,
			    &value_len) != CRYPTO_SUCCESS) {
				error = CRYPTO_TEMPLATE_INCOMPLETE;
				break;
			}
			if (value_len >=
			    CRYPTO_BITS2BYTES(ARCFOUR_MAX_KEY_BITS)) {
				error = CRYPTO_ATTRIBUTE_VALUE_INVALID;
				break;
			}
			key_len = value_len;
			key_type = DPROV_CKK_RC4;
			break;

		default:
			error = CRYPTO_MECHANISM_INVALID;
		}

		if (error != CRYPTO_SUCCESS)
			break;

		error = dprov_create_object_from_template(softc, session,
		    template, attribute_count, object_id_ptr, B_FALSE, B_TRUE);

		if (error != CRYPTO_SUCCESS)
			break;

		/* make sure class is set */
		attribute.oa_type = DPROV_CKA_CLASS;
		attribute.oa_value = (char *)&class;
		attribute.oa_value_len = sizeof (ulong_t);
		error = dprov_object_set_attr(session, *object_id_ptr,
		    &attribute, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_object;
		}

		/* make sure key_type is set */
		attribute.oa_type = DPROV_CKA_KEY_TYPE;
		attribute.oa_value = (char *)&key_type;
		attribute.oa_value_len = sizeof (ulong_t);
		error = dprov_object_set_attr(session, *object_id_ptr,
		    &attribute, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_object;
		}

		attribute.oa_type = DPROV_CKA_VALUE;
		attribute.oa_value = kmem_alloc(key_len, KM_SLEEP);
		attribute.oa_value_len = key_len;

		if (random_get_pseudo_bytes((uchar_t *)attribute.oa_value,
		    key_len) != 0) {
			bzero(attribute.oa_value, key_len);
			kmem_free(attribute.oa_value, key_len);
			goto destroy_object;
		}
		error = dprov_object_set_attr(session, *object_id_ptr,
		    &attribute, 1, B_FALSE);

		bzero(attribute.oa_value, key_len);
		kmem_free(attribute.oa_value, key_len);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_object;
		}
		break;

destroy_object:
		(void) dprov_destroy_object(softc, session, *object_id_ptr);
		break;
	}

	case DPROV_REQ_KEY_GENERATE_PAIR: {
		crypto_mechanism_t *mechp;
		crypto_object_id_t *pub_object_id_ptr;
		crypto_object_id_t *pri_object_id_ptr;
		crypto_object_attribute_t *pub_template;
		crypto_object_attribute_t *pri_template;
		crypto_object_attribute_t attribute;
		uint_t pub_attribute_count;
		uint_t pri_attribute_count;
		ulong_t pub_key_type = ~0UL, pub_class = ~0UL;
		ulong_t pri_key_type = ~0UL, pri_class = ~0UL;

		pub_template = taskq_req->dr_key_req.kr_template;
		pub_attribute_count = taskq_req->dr_key_req.kr_attribute_count;
		pub_object_id_ptr = taskq_req->dr_key_req.kr_object_id_ptr;
		pri_template = taskq_req->dr_key_req.kr_private_key_template;
		pri_attribute_count =
		    taskq_req->dr_key_req.kr_private_key_attribute_count;
		pri_object_id_ptr =
		    taskq_req->dr_key_req.kr_private_key_object_id_ptr;
		mechp = taskq_req->dr_key_req.kr_mechanism;

		error = CRYPTO_SUCCESS;

		/* optional */
		(void) dprov_get_template_attr_ulong(pub_template,
		    pub_attribute_count, DPROV_CKA_CLASS, &pub_class);

		/* optional */
		(void) dprov_get_template_attr_ulong(pri_template,
		    pri_attribute_count, DPROV_CKA_CLASS, &pri_class);

		/* optional */
		(void) dprov_get_template_attr_ulong(pub_template,
		    pub_attribute_count, DPROV_CKA_KEY_TYPE, &pub_key_type);

		/* optional */
		(void) dprov_get_template_attr_ulong(pri_template,
		    pri_attribute_count, DPROV_CKA_KEY_TYPE, &pri_key_type);

		if (pub_class != ~0UL && pub_class != DPROV_CKO_PUBLIC_KEY) {
			error = CRYPTO_TEMPLATE_INCONSISTENT;
			break;
		}

		if (pri_class != ~0UL && pri_class != DPROV_CKO_PRIVATE_KEY) {
			error = CRYPTO_TEMPLATE_INCONSISTENT;
			break;
		}

		switch (mechp->cm_type) {
		case RSA_PKCS_KEY_PAIR_GEN_MECH_INFO_TYPE:
			if (pub_key_type != ~0UL &&
			    pub_key_type != DPROV_CKK_RSA) {
				error = CRYPTO_TEMPLATE_INCONSISTENT;
				break;
			}
			pub_key_type = DPROV_CKK_RSA;

			if (pri_key_type != ~0UL &&
			    pri_key_type != DPROV_CKK_RSA) {
				error = CRYPTO_TEMPLATE_INCONSISTENT;
				break;
			}
			pri_key_type = DPROV_CKK_RSA;

			if (pub_class != ~0UL &&
			    pub_class != DPROV_CKO_PUBLIC_KEY) {
				error = CRYPTO_TEMPLATE_INCONSISTENT;
				break;
			}
			pub_class = DPROV_CKO_PUBLIC_KEY;

			if (pri_class != ~0UL &&
			    pri_class != DPROV_CKO_PRIVATE_KEY) {
				error = CRYPTO_TEMPLATE_INCONSISTENT;
				break;
			}
			pri_class = DPROV_CKO_PRIVATE_KEY;
			break;

		default:
			error = CRYPTO_MECHANISM_INVALID;
		}

		if (error != CRYPTO_SUCCESS)
			break;

		error = dprov_create_object_from_template(softc, session,
		    pub_template, pub_attribute_count, pub_object_id_ptr,
		    B_FALSE, B_TRUE);

		if (error != CRYPTO_SUCCESS)
			break;

		/* make sure class is set */
		attribute.oa_type = DPROV_CKA_CLASS;
		attribute.oa_value = (char *)&pub_class;
		attribute.oa_value_len = sizeof (ulong_t);
		error = dprov_object_set_attr(session, *pub_object_id_ptr,
		    &attribute, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_public_object;
		}

		/* make sure key_type is set */
		attribute.oa_type = DPROV_CKA_KEY_TYPE;
		attribute.oa_value = (char *)&pub_key_type;
		attribute.oa_value_len = sizeof (ulong_t);
		error = dprov_object_set_attr(session, *pub_object_id_ptr,
		    &attribute, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_public_object;
		}

		attribute.oa_type = DPROV_CKA_MODULUS;
		attribute.oa_value = (char *)modulus;
		attribute.oa_value_len = sizeof (modulus);
		error = dprov_object_set_attr(session, *pub_object_id_ptr,
		    &attribute, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_public_object;
		}

		attribute.oa_type = DPROV_CKA_PUBLIC_EXPONENT;
		attribute.oa_value = public_exponent;
		attribute.oa_value_len = sizeof (public_exponent);
		error = dprov_object_set_attr(session, *pub_object_id_ptr,
		    &attribute, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_public_object;
		}

		error = dprov_create_object_from_template(softc, session,
		    pri_template, pri_attribute_count, pri_object_id_ptr,
		    B_FALSE, B_TRUE);

		if (error != CRYPTO_SUCCESS)
			break;

		/* make sure class is set */
		attribute.oa_type = DPROV_CKA_CLASS;
		attribute.oa_value = (char *)&pri_class;
		attribute.oa_value_len = sizeof (ulong_t);
		error = dprov_object_set_attr(session, *pri_object_id_ptr,
		    &attribute, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_private_object;
		}

		/* make sure key_type is set */
		attribute.oa_type = DPROV_CKA_KEY_TYPE;
		attribute.oa_value = (char *)&pri_key_type;
		attribute.oa_value_len = sizeof (ulong_t);
		error = dprov_object_set_attr(session, *pri_object_id_ptr,
		    &attribute, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_private_object;
		}

		attribute.oa_type = DPROV_CKA_MODULUS;
		attribute.oa_value = (char *)modulus;
		attribute.oa_value_len = sizeof (modulus);
		error = dprov_object_set_attr(session, *pri_object_id_ptr,
		    &attribute, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_private_object;
		}

		attribute.oa_type = DPROV_CKA_PRIVATE_EXPONENT;
		attribute.oa_value = (char *)private_exponent;
		attribute.oa_value_len = sizeof (private_exponent);
		error = dprov_object_set_attr(session, *pri_object_id_ptr,
		    &attribute, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			goto destroy_private_object;
		}
		break;

destroy_private_object:
		(void) dprov_destroy_object(softc, session,
		    *pri_object_id_ptr);
destroy_public_object:
		(void) dprov_destroy_object(softc, session,
		    *pub_object_id_ptr);

		break;
	}

	case DPROV_REQ_KEY_WRAP: {
		crypto_mechanism_t mech, *mechp;
		crypto_key_t key, *keyp;
		crypto_object_id_t object_id;
		ulong_t class = DPROV_CKO_DATA;
		boolean_t extractable = B_TRUE;
		dprov_object_t *object;
		int object_idx;
		char *plaintext_key;
		size_t plaintext_key_len;
		crypto_data_t plaintext;
		crypto_data_t ciphertext;
		size_t *lenp;

		mechp = taskq_req->dr_key_req.kr_mechanism;
		/* structure assignment */
		mech = *mechp;

		/* get wrapping key value */
		if (is_publickey_mech(mech.cm_type)) {
			if ((error = dprov_key_attr_asymmetric(softc,
			    session_id, taskq_req->dr_type,
			    taskq_req->dr_key_req.kr_key,
			    &key)) != CRYPTO_SUCCESS)
				break;
			keyp = &key;
		} else {
			if ((error = dprov_key_value_secret(softc,
			    session_id, taskq_req->dr_type,
			    taskq_req->dr_key_req.kr_key,
			    &key)) != CRYPTO_SUCCESS)
				break;
			keyp = &key;
		}

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(mechp, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		object_id = *taskq_req->dr_key_req.kr_object_id_ptr;
		if (object_id >= DPROV_MAX_OBJECTS) {
			error = CRYPTO_KEY_HANDLE_INVALID;
			break;
		}

		/* get ptr to object */
		if ((object = session->ds_objects[object_id]) == NULL) {
			error = CRYPTO_OBJECT_HANDLE_INVALID;
			break;
		}

		(void) dprov_get_object_attr_boolean(object,
		    DPROV_CKA_EXTRACTABLE, &extractable);

		if (!extractable) {
			error = CRYPTO_ATTRIBUTE_SENSITIVE;
			break;
		}

		(void) dprov_get_object_attr_ulong(object,
		    DPROV_CKA_CLASS, &class);

		switch (class) {
		case DPROV_CKO_SECRET_KEY:
			object_idx = dprov_find_attr(object->do_attr,
			    DPROV_MAX_ATTR, DPROV_CKA_VALUE);
			if (object_idx == -1) {
				error = CRYPTO_ATTRIBUTE_TYPE_INVALID;
				break;
			}
			break;

			case DPROV_CKO_PRIVATE_KEY:
			/*
			 * PKCS#11 says that ASN.1 should be used to encode
			 * specific attributes before encrypting the blob.
			 * We only encrypt the private exponent for the
			 * purpose of testing.
			 */
			object_idx = dprov_find_attr(object->do_attr,
			    DPROV_MAX_ATTR, DPROV_CKA_PRIVATE_EXPONENT);
			if (object_idx == -1) {
				error = CRYPTO_ATTRIBUTE_TYPE_INVALID;
				break;
			}
			break;
		default:
			error = CRYPTO_KEY_NOT_WRAPPABLE;
			break;
		}
		if (error != CRYPTO_SUCCESS)
			break;

		plaintext_key = object->do_attr[object_idx].oa_value;
		plaintext_key_len = object->do_attr[object_idx].oa_value_len;
		lenp = taskq_req->dr_key_req.kr_wrapped_key_len_ptr;

		/* session id is 0 for software provider */
		plaintext.cd_format = CRYPTO_DATA_RAW;
		plaintext.cd_offset = 0;
		plaintext.cd_length = plaintext_key_len;
		plaintext.cd_raw.iov_base = plaintext_key;
		plaintext.cd_raw.iov_len = plaintext_key_len;
		plaintext.cd_miscdata = NULL;

		ciphertext.cd_format = CRYPTO_DATA_RAW;
		ciphertext.cd_offset = 0;
		ciphertext.cd_length = *lenp;
		ciphertext.cd_raw.iov_base =
		    (char *)taskq_req->dr_key_req.kr_wrapped_key;
		ciphertext.cd_raw.iov_len = ciphertext.cd_length;
		ciphertext.cd_miscdata = NULL;

		error = crypto_encrypt_prov(pd, 0, &mech, &plaintext, keyp,
		    NULL, &ciphertext, NULL);

		KCF_PROV_REFRELE(pd);
		if (error == CRYPTO_SUCCESS ||
		    error == CRYPTO_BUFFER_TOO_SMALL) {
			*lenp = ciphertext.cd_length;
		}
		break;
	}

	case DPROV_REQ_KEY_UNWRAP: {
		crypto_mechanism_t mech, *mechp;
		crypto_key_t key, *keyp;
		crypto_object_id_t *object_id_ptr;
		ulong_t class = DPROV_CKO_DATA;
		uchar_t *wrapped_key;
		char *plaintext_buf;
		size_t wrapped_key_len;
		crypto_data_t plaintext;
		crypto_data_t ciphertext;
		crypto_object_attribute_t unwrapped_key;
		crypto_object_attribute_t *template;
		uint_t attribute_count;

		template = taskq_req->dr_key_req.kr_template;
		attribute_count = taskq_req->dr_key_req.kr_attribute_count;
		object_id_ptr = taskq_req->dr_key_req.kr_object_id_ptr;

		/* all objects must have an object class attribute */
		if (dprov_get_template_attr_ulong(template, attribute_count,
		    DPROV_CKA_CLASS, &class) != CRYPTO_SUCCESS) {
			error = CRYPTO_TEMPLATE_INCOMPLETE;
			break;
		}

		mechp = taskq_req->dr_key_req.kr_mechanism;
		/* structure assignment */
		mech = *mechp;

		/* get unwrapping key value */
		if (is_publickey_mech(mech.cm_type)) {
			if ((error = dprov_key_attr_asymmetric(softc,
			    session_id, taskq_req->dr_type,
			    taskq_req->dr_key_req.kr_key,
			    &key)) != CRYPTO_SUCCESS)
				break;
			keyp = &key;
		} else {
			if ((error = dprov_key_value_secret(softc,
			    session_id, taskq_req->dr_type,
			    taskq_req->dr_key_req.kr_key,
			    &key)) != CRYPTO_SUCCESS)
				break;
			keyp = &key;
		}

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(mechp, &pd,
		    &mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		wrapped_key = taskq_req->dr_key_req.kr_wrapped_key;
		wrapped_key_len = *taskq_req->dr_key_req.kr_wrapped_key_len_ptr;
		ciphertext.cd_format = CRYPTO_DATA_RAW;
		ciphertext.cd_offset = 0;
		ciphertext.cd_length = wrapped_key_len;
		ciphertext.cd_raw.iov_base = (char *)wrapped_key;
		ciphertext.cd_raw.iov_len = wrapped_key_len;
		ciphertext.cd_miscdata = NULL;

		/*
		 * Plaintext length is less than or equal to
		 * the length of the ciphertext.
		 */
		plaintext_buf = kmem_alloc(wrapped_key_len, KM_SLEEP);
		plaintext.cd_format = CRYPTO_DATA_RAW;
		plaintext.cd_offset = 0;
		plaintext.cd_length = wrapped_key_len;
		plaintext.cd_raw.iov_base = plaintext_buf;
		plaintext.cd_raw.iov_len = wrapped_key_len;
		plaintext.cd_miscdata = NULL;

		error = crypto_decrypt_prov(pd, 0, &mech, &ciphertext, keyp,
		    NULL, &plaintext, NULL);

		KCF_PROV_REFRELE(pd);

		if (error != CRYPTO_SUCCESS)
			goto free_unwrapped_key;

		error = dprov_create_object_from_template(softc, session,
		    template, attribute_count, object_id_ptr, B_FALSE, B_FALSE);

		if (error != CRYPTO_SUCCESS)
			goto free_unwrapped_key;

		switch (class) {
		case DPROV_CKO_SECRET_KEY:
			unwrapped_key.oa_type = DPROV_CKA_VALUE;
			unwrapped_key.oa_value_len = plaintext.cd_length;
			unwrapped_key.oa_value = plaintext_buf;
			break;
		case DPROV_CKO_PRIVATE_KEY:
			/*
			 * PKCS#11 says that ASN.1 should be used to encode
			 * specific attributes before encrypting the blob.
			 * We only encrypt the private exponent for the
			 * purpose of testing.
			 */
			unwrapped_key.oa_type = DPROV_CKA_PRIVATE_EXPONENT;
			unwrapped_key.oa_value_len = plaintext.cd_length;
			unwrapped_key.oa_value = plaintext_buf;
			break;
		default:
			error = CRYPTO_TEMPLATE_INCONSISTENT;
			goto free_unwrapped_key;
		}

		if ((error = dprov_object_set_attr(session, *object_id_ptr,
		    &unwrapped_key, 1, B_FALSE)) == CRYPTO_SUCCESS)
			break;	/* don't free the unwrapped key */

		/* failure */
		(void) dprov_destroy_object(softc, session, *object_id_ptr);
		break;

free_unwrapped_key:
		bzero(plaintext_buf, wrapped_key_len);
		kmem_free(plaintext_buf, wrapped_key_len);
		break;
	}

	case DPROV_REQ_KEY_DERIVE: {
		crypto_mechanism_t digest_mech, *mechp;
		crypto_key_t key, *base_keyp;
		crypto_object_id_t *object_id_ptr;
		crypto_data_t data;
		crypto_data_t digest;
		size_t hash_size;
		char *digest_buf;
		crypto_object_attribute_t derived_key;
		crypto_object_attribute_t *template;
		uint_t attribute_count;
		ulong_t key_type;
		void *value;
		size_t value_len = 0;

		error = CRYPTO_SUCCESS;

		template = taskq_req->dr_key_req.kr_template;
		attribute_count = taskq_req->dr_key_req.kr_attribute_count;
		object_id_ptr = taskq_req->dr_key_req.kr_object_id_ptr;

		/* required */
		if (dprov_get_template_attr_ulong(template, attribute_count,
		    DPROV_CKA_KEY_TYPE, &key_type) != CRYPTO_SUCCESS) {
			error = CRYPTO_TEMPLATE_INCOMPLETE;
			break;
		}

		mechp = taskq_req->dr_key_req.kr_mechanism;
		/* structure assignment */
		digest_mech = *mechp;

		switch (digest_mech.cm_type) {
		case SHA1_KEY_DERIVATION_MECH_INFO_TYPE:
			hash_size = SHA1_DIGEST_LEN;
			digest_mech.cm_type = SHA1_MECH_INFO_TYPE;
			break;

		case SHA256_KEY_DERIVATION_MECH_INFO_TYPE:
			hash_size = SHA256_DIGEST_LENGTH;
			digest_mech.cm_type = SHA256_MECH_INFO_TYPE;
			break;

		case SHA384_KEY_DERIVATION_MECH_INFO_TYPE:
			hash_size = SHA384_DIGEST_LENGTH;
			digest_mech.cm_type = SHA384_MECH_INFO_TYPE;
			break;

		case SHA512_KEY_DERIVATION_MECH_INFO_TYPE:
			hash_size = SHA512_DIGEST_LENGTH;
			digest_mech.cm_type = SHA512_MECH_INFO_TYPE;
			break;

		case MD5_KEY_DERIVATION_MECH_INFO_TYPE:
			hash_size = MD5_DIGEST_LEN;
			digest_mech.cm_type = MD5_MECH_INFO_TYPE;
			break;

		default:
			error = CRYPTO_MECHANISM_INVALID;
		}

		if (error != CRYPTO_SUCCESS)
			break;

		/* CKA_VALUE is optional */
		(void) dprov_get_template_attr_array(template, attribute_count,
		    DPROV_CKA_VALUE, &value, &value_len);

		/* check for inconsistent value length */
		switch (key_type) {
		case DPROV_CKK_GENERIC_SECRET:
			if (value_len > 0) {
				if (value_len > hash_size)
					error = CRYPTO_ATTRIBUTE_VALUE_INVALID;
			} else {
				value_len = hash_size;
			}
			break;

		case DPROV_CKK_RC4:
		case DPROV_CKK_AES:
			if (value_len == 0 ||
			    value_len > hash_size) {
				error = CRYPTO_ATTRIBUTE_VALUE_INVALID;
			}
			break;

		case DPROV_CKK_DES:
			if (value_len > 0 &&
			    value_len != DES_KEY_LEN) {
				error = CRYPTO_ATTRIBUTE_VALUE_INVALID;
			}
			value_len = DES_KEY_LEN;
			break;

		case DPROV_CKK_DES3:
			if (value_len > 0 &&
			    value_len != DES3_KEY_LEN) {
				error = CRYPTO_ATTRIBUTE_VALUE_INVALID;
			}
			value_len = DES3_KEY_LEN;
			break;

		default:
			error = CRYPTO_ATTRIBUTE_VALUE_INVALID;
			break;
		}

		if (error != CRYPTO_SUCCESS)
			break;

		/* get the software provider for this mechanism */
		if ((error = dprov_get_sw_prov(&digest_mech, &pd,
		    &digest_mech.cm_type)) != CRYPTO_SUCCESS)
			break;

		/* get the base key */
		error = dprov_key_value_secret(softc, session_id,
		    taskq_req->dr_type, taskq_req->dr_key_req.kr_key, &key);
		if (error != CRYPTO_SUCCESS)
			break;

		base_keyp = &key;

		data.cd_format = CRYPTO_DATA_RAW;
		data.cd_offset = 0;
		data.cd_length = CRYPTO_BITS2BYTES(base_keyp->ck_length);
		data.cd_raw.iov_base = base_keyp->ck_data;
		data.cd_raw.iov_len = data.cd_length;

		digest_buf = kmem_alloc(hash_size, KM_SLEEP);
		digest.cd_format = CRYPTO_DATA_RAW;
		digest.cd_offset = 0;
		digest.cd_length = hash_size;
		digest.cd_raw.iov_base = digest_buf;
		digest.cd_raw.iov_len = hash_size;

		error = crypto_digest_prov(pd, 0, &digest_mech, &data,
		    &digest, NULL);

		KCF_PROV_REFRELE(pd);

		if (error != CRYPTO_SUCCESS)
			goto free_derived_key;

		error = dprov_create_object_from_template(softc, session,
		    template, attribute_count, object_id_ptr, B_FALSE, B_FALSE);

		if (error != CRYPTO_SUCCESS)
			goto free_derived_key;

		derived_key.oa_type = DPROV_CKA_VALUE;
		derived_key.oa_value = digest_buf;
		derived_key.oa_value_len = value_len;

		error = dprov_object_set_attr(session, *object_id_ptr,
		    &derived_key, 1, B_FALSE);

		if (error != CRYPTO_SUCCESS) {
			(void) dprov_destroy_object(softc, session,
			    *object_id_ptr);
		}

free_derived_key:
		bzero(digest_buf, hash_size);
		kmem_free(digest_buf, hash_size);
		break;
	}

	case DPROV_REQ_NOSTORE_KEY_GENERATE: {
		crypto_object_attribute_t *out_template;
		uint_t out_attribute_count;
		void *value;
		size_t value_len = 0;

		out_template = taskq_req->dr_key_req.kr_out_template1;
		out_attribute_count =
		    taskq_req->dr_key_req.kr_out_attribute_count1;

		error = dprov_get_template_attr_array(out_template,
		    out_attribute_count, DPROV_CKA_VALUE, &value, &value_len);
		if (error != CRYPTO_SUCCESS)
			break;

		/* fill the entire array with pattern */
		{
			int i = 0;
			char *p = value;
			while (i < value_len) {
				p[i++] = 'A';
				if (i >= value_len)
					break;
				p[i++] = 'B';
				if (i >= value_len)
					break;
				p[i++] = 'C';
			}
		}

		error = CRYPTO_SUCCESS;
		break;
	}

	case DPROV_REQ_NOSTORE_KEY_GENERATE_PAIR: {
		crypto_mechanism_t *mechp;
		crypto_object_attribute_t *pub_template;
		crypto_object_attribute_t *pri_template;
		uint_t pub_attribute_count;
		uint_t pri_attribute_count;
		crypto_object_attribute_t *out_pub_template;
		crypto_object_attribute_t *out_pri_template;
		uint_t out_pub_attribute_count;
		uint_t out_pri_attribute_count;

		mechp = taskq_req->dr_key_req.kr_mechanism;
		pub_template = taskq_req->dr_key_req.kr_template;
		pub_attribute_count = taskq_req->dr_key_req.kr_attribute_count;
		pri_template = taskq_req->dr_key_req.kr_private_key_template;
		pri_attribute_count =
		    taskq_req->dr_key_req.kr_private_key_attribute_count;
		out_pub_template = taskq_req->dr_key_req.kr_out_template1;
		out_pub_attribute_count =
		    taskq_req->dr_key_req.kr_out_attribute_count1;
		out_pri_template = taskq_req->dr_key_req.kr_out_template2;
		out_pri_attribute_count =
		    taskq_req->dr_key_req.kr_out_attribute_count2;

		switch (mechp->cm_type) {
		case RSA_PKCS_KEY_PAIR_GEN_MECH_INFO_TYPE:
			error = nostore_copy_attribute(out_pub_template,
			    out_pub_attribute_count, DPROV_CKA_MODULUS);
			if (error != CRYPTO_SUCCESS)
				break;

			error = nostore_copy_attribute(out_pub_template,
			    out_pub_attribute_count, DPROV_CKA_PUBLIC_EXPONENT);
			if (error == CRYPTO_ARGUMENTS_BAD) {
				size_t tmp_len = 0;
				void *tmp;

				/* public exponent must be here */
				error = dprov_get_template_attr_array(
				    pub_template, pub_attribute_count,
				    DPROV_CKA_PUBLIC_EXPONENT, &tmp, &tmp_len);
				if (error != CRYPTO_SUCCESS)
					break;
			}
			error = nostore_copy_attribute(out_pri_template,
			    out_pri_attribute_count, DPROV_CKA_MODULUS);
			if (error != CRYPTO_SUCCESS)
				break;

			error = nostore_copy_attribute(out_pri_template,
			    out_pri_attribute_count,
			    DPROV_CKA_PRIVATE_EXPONENT);
			break;

		case DH_PKCS_KEY_PAIR_GEN_MECH_INFO_TYPE:
			/*
			 * There is no software provider for DH mechanism;
			 * Just return pre-defined values.
			 */
			error = nostore_copy_attribute(out_pub_template,
			    out_pub_attribute_count, DPROV_CKA_VALUE);
			error = nostore_copy_attribute(out_pri_template,
			    out_pri_attribute_count, DPROV_CKA_VALUE);
			break;

		case EC_KEY_PAIR_GEN_MECH_INFO_TYPE: {
			crypto_mechanism_t mech, *mechp;
			kcf_req_params_t params;
			crypto_object_attribute_t *pub_template;
			uint_t pub_attribute_count;
			crypto_object_attribute_t *out_pub_template;
			crypto_object_attribute_t *out_pri_template;
			uint_t out_pub_attribute_count;
			uint_t out_pri_attribute_count;

			mechp = taskq_req->dr_key_req.kr_mechanism;
			pub_template = taskq_req->dr_key_req.kr_template;
			pub_attribute_count =
			    taskq_req->dr_key_req.kr_attribute_count;
			out_pub_template =
			    taskq_req->dr_key_req.kr_out_template1;
			out_pub_attribute_count =
			    taskq_req->dr_key_req.kr_out_attribute_count1;
			out_pri_template =
			    taskq_req->dr_key_req.kr_out_template2;
			out_pri_attribute_count =
			    taskq_req->dr_key_req.kr_out_attribute_count2;

			/* get the software provider for this mechanism */
			mech = *mechp;
			if ((error = dprov_get_sw_prov(mechp, &pd,
			    &mech.cm_type)) != CRYPTO_SUCCESS)
				break;
			/*
			 * Turn 32-bit values into 64-bit values for certain
			 * attributes like CKA_CLASS.
			 */
			dprov_adjust_attrs(pub_template, pub_attribute_count);
			dprov_adjust_attrs(pri_template, pri_attribute_count);

			/* bypass the kernel API for now */
			KCF_WRAP_NOSTORE_KEY_OPS_PARAMS(&params,
			    KCF_OP_KEY_GENERATE_PAIR,
			    0, /* session 0 for sw provider */
			    &mech, pub_template, pub_attribute_count,
			    pri_template, pri_attribute_count, NULL,
			    out_pub_template, out_pub_attribute_count,
			    out_pri_template, out_pri_attribute_count);

			error = kcf_submit_request(pd, NULL, NULL, &params,
			    B_FALSE);

			KCF_PROV_REFRELE(pd);
			break;
		}
		default:
			error = CRYPTO_MECHANISM_INVALID;
		}
		break;
	}

	case DPROV_REQ_NOSTORE_KEY_DERIVE: {
		crypto_mechanism_t *mechp;
		crypto_object_attribute_t *in_template, *out_template;
		crypto_key_t *base_key;
		uint_t in_attribute_count, out_attribute_count;
		ulong_t key_type;
		void *value;
		size_t value_len = 0;
		size_t value_len_value = 0;

		in_template = taskq_req->dr_key_req.kr_template;
		out_template = taskq_req->dr_key_req.kr_out_template1;
		in_attribute_count = taskq_req->dr_key_req.kr_attribute_count;
		out_attribute_count =
		    taskq_req->dr_key_req.kr_out_attribute_count1;
		mechp = taskq_req->dr_key_req.kr_mechanism;
		base_key = taskq_req->dr_key_req.kr_key;

		/*
		 * CKA_VALUE must be present so the derived key can
		 * be returned by value.
		 */
		if (dprov_get_template_attr_array(out_template,
		    out_attribute_count, DPROV_CKA_VALUE, &value,
		    &value_len) != CRYPTO_SUCCESS) {
			error = CRYPTO_TEMPLATE_INCOMPLETE;
			break;
		}

		if (dprov_get_template_attr_ulong(in_template,
		    in_attribute_count, DPROV_CKA_KEY_TYPE,
		    &key_type) != CRYPTO_SUCCESS) {
			error = CRYPTO_TEMPLATE_INCOMPLETE;
			break;
		}
		switch (mechp->cm_type) {
		case DH_PKCS_DERIVE_MECH_INFO_TYPE: {
			size_t tmp_len = 0;
			void *tmp;

			if (base_key->ck_format != CRYPTO_KEY_ATTR_LIST) {
				error = CRYPTO_ARGUMENTS_BAD;
				break;
			}

			if ((dprov_get_template_attr_array(base_key->ck_attrs,
			    base_key->ck_count, DPROV_CKA_BASE, &tmp,
			    &tmp_len) != CRYPTO_SUCCESS) ||
			    (dprov_get_template_attr_array(base_key->ck_attrs,
			    base_key->ck_count, DPROV_CKA_PRIME, &tmp,
			    &tmp_len) != CRYPTO_SUCCESS) ||
			    (dprov_get_template_attr_array(base_key->ck_attrs,
			    base_key->ck_count, DPROV_CKA_VALUE, &tmp,
			    &tmp_len) != CRYPTO_SUCCESS)) {
				error = CRYPTO_TEMPLATE_INCOMPLETE;
				break;
			}

			/*
			 * CKA_VALUE is added to the derived key template by
			 * the library.
			 */
			error = CRYPTO_SUCCESS;
			switch (key_type) {
			case DPROV_CKK_AES:
				if (dprov_get_template_attr_ulong(in_template,
				    in_attribute_count, DPROV_CKA_VALUE_LEN,
				    &value_len_value) != CRYPTO_SUCCESS) {
					error = CRYPTO_TEMPLATE_INCOMPLETE;
					break;
				}
				if (value_len != value_len_value) {
					error = CRYPTO_TEMPLATE_INCONSISTENT;
					break;
				}
			default:
				error = CRYPTO_MECHANISM_INVALID;
			}
			if (error == CRYPTO_SUCCESS)
				fill_dh(value, value_len);
			break;
		}
		case ECDH1_DERIVE_MECH_INFO_TYPE: {
			crypto_mechanism_t mech;
			kcf_req_params_t params;

			/* get the software provider for this mechanism */
			mech = *mechp;
			if ((error = dprov_get_sw_prov(mechp, &pd,
			    &mech.cm_type)) != CRYPTO_SUCCESS)
				break;

			/*
			 * Turn 32-bit values into 64-bit values for certain
			 * attributes like CKA_VALUE_LEN.
			 */
			dprov_adjust_attrs(in_template, in_attribute_count);

			/* bypass the kernel API for now */
			KCF_WRAP_NOSTORE_KEY_OPS_PARAMS(&params,
			    KCF_OP_KEY_DERIVE,
			    0, /* session 0 for sw provider */
			    &mech, in_template, in_attribute_count,
			    NULL, 0, base_key,
			    out_template, out_attribute_count,
			    NULL, 0);

			error = kcf_submit_request(pd, NULL, NULL, &params,
			    B_FALSE);

			KCF_PROV_REFRELE(pd);
			break;
		}

		default:
			error = CRYPTO_MECHANISM_INVALID;
		}
		break;
	default:
		error = CRYPTO_MECHANISM_INVALID;
	}
	} /* end case */

	mutex_exit(&softc->ds_lock);
	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_KEY, ("(%d) dprov_key_task: end\n", instance));
}

/*
 * taskq dispatcher function for provider management operations.
 */
static void
dprov_mgmt_task(dprov_req_t *taskq_req)
{
	dprov_state_t *softc;
	/* LINTED E_FUNC_SET_NOT_USED */
	int instance;
	int error = CRYPTO_NOT_SUPPORTED;

	DPROV_SOFTC_FROM_REQ(taskq_req, softc, instance);
	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_mgmt_task: started\n", instance));

	mutex_enter(&softc->ds_lock);

	switch (taskq_req->dr_type) {
	case DPROV_REQ_MGMT_EXTINFO: {
		crypto_provider_ext_info_t *ext_info =
		    taskq_req->dr_mgmt_req.mr_ext_info;

		(void) memset(ext_info->ei_label, ' ', CRYPTO_EXT_SIZE_LABEL);
		if (!softc->ds_token_initialized) {
			bcopy("(not initialized)", ext_info->ei_label,
			    strlen("(not initialized)"));
		} else {
			bcopy(softc->ds_label, ext_info->ei_label,
			    CRYPTO_EXT_SIZE_LABEL);
		}

		bcopy(DPROV_MANUFACTURER, ext_info->ei_manufacturerID,
		    CRYPTO_EXT_SIZE_MANUF);
		bcopy(DPROV_MODEL, ext_info->ei_model, CRYPTO_EXT_SIZE_MODEL);

		(void) snprintf((char *)ext_info->ei_serial_number, 16, "%d%s",
		    instance, DPROV_ALLSPACES);
		/* PKCS#11 blank padding */
		ext_info->ei_serial_number[15] = ' ';
		ext_info->ei_max_session_count = CRYPTO_EFFECTIVELY_INFINITE;
		ext_info->ei_max_pin_len = (ulong_t)DPROV_MAX_PIN_LEN;
		ext_info->ei_min_pin_len = 1;
		ext_info->ei_total_public_memory = CRYPTO_EFFECTIVELY_INFINITE;
		ext_info->ei_free_public_memory = CRYPTO_EFFECTIVELY_INFINITE;
		ext_info->ei_total_private_memory = CRYPTO_EFFECTIVELY_INFINITE;
		ext_info->ei_free_private_memory = CRYPTO_EFFECTIVELY_INFINITE;
		ext_info->ei_hardware_version.cv_major = 1;
		ext_info->ei_hardware_version.cv_minor = 0;
		ext_info->ei_firmware_version.cv_major = 1;
		ext_info->ei_firmware_version.cv_minor = 0;

		ext_info->ei_flags = CRYPTO_EXTF_RNG |
		    CRYPTO_EXTF_LOGIN_REQUIRED |
		    CRYPTO_EXTF_DUAL_CRYPTO_OPERATIONS;
		if (softc->ds_user_pin_set)
			ext_info->ei_flags |= CRYPTO_EXTF_USER_PIN_INITIALIZED;
		if (softc->ds_token_initialized)
			ext_info->ei_flags |= CRYPTO_EXTF_TOKEN_INITIALIZED;

		ext_info->ei_hash_max_input_len = dprov_max_digestsz;
		ext_info->ei_hmac_max_input_len = dprov_max_digestsz;
		error = CRYPTO_SUCCESS;
		break;
	}
	case DPROV_REQ_MGMT_INITTOKEN: {
		char *pin = taskq_req->dr_mgmt_req.mr_pin;
		size_t pin_len = taskq_req->dr_mgmt_req.mr_pin_len;
		char *label = taskq_req->dr_mgmt_req.mr_label;

		/* cannot initialize token when a session is open */
		if (softc->ds_sessions_count > 0) {
			error = CRYPTO_SESSION_EXISTS;
			break;
		}

		/* check PIN length */
		if (pin_len > DPROV_MAX_PIN_LEN) {
			error = CRYPTO_PIN_LEN_RANGE;
			break;
		}

		/* check PIN */
		if (pin == NULL) {
			error = CRYPTO_PIN_INVALID;
			break;
		}

		/*
		 * If the token has already been initialized, need
		 * to validate supplied PIN.
		 */
		if (softc->ds_token_initialized &&
		    (softc->ds_so_pin_len != pin_len ||
		    strncmp(softc->ds_so_pin, pin, pin_len) != 0)) {
			/* invalid SO PIN */
			error = CRYPTO_PIN_INCORRECT;
			break;
		}

		/* set label */
		bcopy(label, softc->ds_label, CRYPTO_EXT_SIZE_LABEL);

		/* set new SO PIN, update state */
		bcopy(pin, softc->ds_so_pin, pin_len);
		softc->ds_so_pin_len = pin_len;
		softc->ds_token_initialized = B_TRUE;
		softc->ds_user_pin_set = B_FALSE;

		error = CRYPTO_SUCCESS;
		break;
	}
	case DPROV_REQ_MGMT_INITPIN: {
		char *pin = taskq_req->dr_mgmt_req.mr_pin;
		size_t pin_len = taskq_req->dr_mgmt_req.mr_pin_len;
		crypto_session_id_t session_id =
		    taskq_req->dr_mgmt_req.mr_session_id;

		/* check session id */
		if (softc->ds_sessions[session_id] == NULL) {
			error = CRYPTO_SESSION_HANDLE_INVALID;
			break;
		}

		/* fail if not logged in as SO */
		if (softc->ds_sessions[session_id]->ds_state !=
		    DPROV_SESSION_STATE_SO) {
			error = CRYPTO_USER_NOT_LOGGED_IN;
			break;
		}

		/* check PIN length */
		if (pin_len > DPROV_MAX_PIN_LEN) {
			error = CRYPTO_PIN_LEN_RANGE;
			break;
		}

		/* check PIN */
		if (pin == NULL) {
			error = CRYPTO_PIN_INVALID;
			break;
		}

		/* set new normal user PIN */
		bcopy(pin, softc->ds_user_pin, pin_len);
		softc->ds_user_pin_len = pin_len;
		softc->ds_user_pin_set = B_TRUE;

		error = CRYPTO_SUCCESS;
		break;
	}
	case DPROV_REQ_MGMT_SETPIN: {
		char *new_pin = taskq_req->dr_mgmt_req.mr_pin;
		size_t new_pin_len = taskq_req->dr_mgmt_req.mr_pin_len;
		char *old_pin = taskq_req->dr_mgmt_req.mr_old_pin;
		size_t old_pin_len = taskq_req->dr_mgmt_req.mr_old_pin_len;
		crypto_session_id_t session_id =
		    taskq_req->dr_mgmt_req.mr_session_id;

		/* check session id */
		if (softc->ds_sessions[session_id] == NULL) {
			error = CRYPTO_SESSION_HANDLE_INVALID;
			break;
		}

		/* check PIN length */
		if (old_pin_len > DPROV_MAX_PIN_LEN ||
		    new_pin_len > DPROV_MAX_PIN_LEN) {
			error = CRYPTO_PIN_LEN_RANGE;
			break;
		}

		/* check PIN */
		if (old_pin == NULL || new_pin == NULL) {
			error = CRYPTO_PIN_INVALID;
			break;
		}

		/* check user PIN state */
		if (!softc->ds_user_pin_set) {
			error = CRYPTO_USER_PIN_NOT_INITIALIZED;
			break;
		}

		/*
		 * If the token has already been initialized, need
		 * to validate supplied PIN.
		 */
		if (softc->ds_user_pin_len != old_pin_len ||
		    strncmp(softc->ds_user_pin, old_pin, old_pin_len) != 0) {
			/* invalid SO PIN */
			error = CRYPTO_PIN_INCORRECT;
			break;
		}

		/* set new PIN */
		bcopy(new_pin, softc->ds_user_pin, new_pin_len);
		softc->ds_user_pin_len = new_pin_len;

		error = CRYPTO_SUCCESS;
		break;
	}
	}

	mutex_exit(&softc->ds_lock);
	dprov_op_done(taskq_req, error);
	DPROV_DEBUG(D_DIGEST, ("(%d) dprov_mgmt_task: end\n", instance));
}

/*
 * Returns in the location pointed to by pd a pointer to the descriptor
 * for the software provider for the specified mechanism.
 * The provider descriptor is returned held. Returns one of the CRYPTO_
 * error codes on failure, CRYPTO_SUCCESS on success.
 */
static int
dprov_get_sw_prov(crypto_mechanism_t *mech, kcf_provider_desc_t **pd,
    crypto_mech_type_t *provider_mech_type)
{
	crypto_mech_type_t kcf_mech_type = CRYPTO_MECH_INVALID;
	int i, rv;

	/* lookup the KCF mech type associated with our mech type */
	for (i = 0; i < sizeof (dprov_mech_info_tab)/
	    sizeof (crypto_mech_info_t); i++) {
		if (mech->cm_type == dprov_mech_info_tab[i].cm_mech_number) {
			kcf_mech_type = crypto_mech2id_common(
			    dprov_mech_info_tab[i].cm_mech_name, B_TRUE);
		}
	}

	rv = kcf_get_sw_prov(kcf_mech_type, pd, NULL, B_TRUE);
	if (rv == CRYPTO_SUCCESS)
		*provider_mech_type = kcf_mech_type;

	return (rv);
}

/*
 * Object management helper functions.
 */

/*
 * Given a crypto_key_t, return whether the key can be used or not
 * for the specified request. The attributes used here are defined
 * in table 42 of the PKCS#11 spec (Common secret key attributes).
 */
static int
dprov_key_can_use(dprov_object_t *object, dprov_req_type_t req_type)
{
	boolean_t ret = 0;
	int rv = CRYPTO_SUCCESS;

	/* check if object is allowed for specified operation */
	switch (req_type) {
	case DPROV_REQ_ENCRYPT_INIT:
	case DPROV_REQ_ENCRYPT_ATOMIC:
		rv = dprov_get_object_attr_boolean(object,
		    DPROV_CKA_ENCRYPT, &ret);
		break;
	case DPROV_REQ_DECRYPT_INIT:
	case DPROV_REQ_DECRYPT_ATOMIC:
		rv = dprov_get_object_attr_boolean(object,
		    DPROV_CKA_DECRYPT, &ret);
		break;
	case DPROV_REQ_SIGN_INIT:
	case DPROV_REQ_SIGN_ATOMIC:
	case DPROV_REQ_MAC_INIT:
	case DPROV_REQ_MAC_ATOMIC:
	case DPROV_REQ_MAC_VERIFY_ATOMIC:
		rv = dprov_get_object_attr_boolean(object,
		    DPROV_CKA_SIGN, &ret);
		break;
	case DPROV_REQ_SIGN_RECOVER_INIT:
	case DPROV_REQ_SIGN_RECOVER_ATOMIC:
		rv = dprov_get_object_attr_boolean(object,
		    DPROV_CKA_SIGN_RECOVER, &ret);
		break;
	case DPROV_REQ_VERIFY_INIT:
	case DPROV_REQ_VERIFY_ATOMIC:
		rv = dprov_get_object_attr_boolean(object,
		    DPROV_CKA_VERIFY, &ret);
		break;
	case DPROV_REQ_VERIFY_RECOVER_INIT:
	case DPROV_REQ_VERIFY_RECOVER_ATOMIC:
		rv = dprov_get_object_attr_boolean(object,
		    DPROV_CKA_VERIFY_RECOVER, &ret);
		break;
	case DPROV_REQ_KEY_WRAP:
		rv = dprov_get_object_attr_boolean(object,
		    DPROV_CKA_WRAP, &ret);
		break;
	case DPROV_REQ_KEY_UNWRAP:
		rv = dprov_get_object_attr_boolean(object,
		    DPROV_CKA_UNWRAP, &ret);
		break;
	case DPROV_REQ_DIGEST_KEY:
		/*
		 * There is no attribute to check for; therefore,
		 * any secret key can be used.
		 */
		ret = B_TRUE;
		rv = CRYPTO_SUCCESS;
		break;
	case DPROV_REQ_KEY_DERIVE:
		rv = dprov_get_object_attr_boolean(object,
		    DPROV_CKA_DERIVE, &ret);
		break;
	}

	if (rv != CRYPTO_SUCCESS || !ret)
		return (CRYPTO_KEY_FUNCTION_NOT_PERMITTED);

	return (CRYPTO_SUCCESS);
}

/*
 * Given a crypto_key_t corresponding to a secret key (i.e. for
 * use with symmetric crypto algorithms) specified in raw format, by
 * attribute, or by reference, initialize the ck_data and ck_length
 * fields of the ret_key argument so that they specify the key value
 * and length.
 *
 * For a key by value, this function uess the ck_data and ck_length,
 * for a key by reference, it looks up the corresponding object and
 * returns the appropriate attribute. For a key by attribute, it returns
 * the appropriate attribute. The attributes used are CKA_VALUE to retrieve
 * the value of the key, and CKA_VALUE_LEN to retrieve its length in bytes.
 */
static int
dprov_key_value_secret(dprov_state_t *softc, crypto_session_id_t session_id,
    dprov_req_type_t req_type, crypto_key_t *key, crypto_key_t *ret_key)
{
	ulong_t key_type;
	int ret = CRYPTO_SUCCESS;

	ret_key->ck_format = CRYPTO_KEY_RAW;

	switch (key->ck_format) {

	case CRYPTO_KEY_RAW:
		ret_key->ck_data = key->ck_data;
		ret_key->ck_length = key->ck_length;
		break;

	case CRYPTO_KEY_ATTR_LIST: {
		void *value;
		size_t len, value_len;

		if ((ret = dprov_get_key_attr_ulong(key, DPROV_CKA_KEY_TYPE,
		    &key_type)) != CRYPTO_SUCCESS)
			break;

		if ((ret = dprov_get_key_attr_array(key, DPROV_CKA_VALUE,
		    &value, &len)) != CRYPTO_SUCCESS)
			break;

		/*
		 * The length of the array is expressed in bytes.
		 * Convert to bits now since that's how keys are measured.
		 */
		len  = CRYPTO_BYTES2BITS(len);

		/* optional */
		if ((dprov_get_key_attr_ulong(key, DPROV_CKA_VALUE_LEN,
		    &value_len)) == CRYPTO_SUCCESS) {
			len = value_len;
		}

		ret_key->ck_data = value;
		ret_key->ck_length = (uint_t)len;

		break;
	}

	case CRYPTO_KEY_REFERENCE: {
		dprov_object_t *object;
		void *value;
		size_t len, value_len;

		/* check session id */
		if (softc->ds_sessions[session_id] == NULL) {
			ret = CRYPTO_SESSION_HANDLE_INVALID;
			break;
		}

		if (key->ck_obj_id >= DPROV_MAX_OBJECTS) {
			ret = CRYPTO_KEY_HANDLE_INVALID;
			goto bail;
		}

		/* check if object id specified by key is valid */
		object = softc->ds_sessions[session_id]->
		    ds_objects[key->ck_obj_id];
		if (object == NULL) {
			ret = CRYPTO_KEY_HANDLE_INVALID;
			goto bail;
		}

		/* check if object can be used for operation */
		if ((ret = dprov_key_can_use(object, req_type)) !=
		    CRYPTO_SUCCESS)
			goto bail;

		if ((ret = dprov_get_object_attr_ulong(object,
		    DPROV_CKA_KEY_TYPE, &key_type)) != CRYPTO_SUCCESS)
			goto bail;

		if ((ret = dprov_get_object_attr_array(object,
		    DPROV_CKA_VALUE, &value, &len)) != CRYPTO_SUCCESS)
			goto bail;

		/* optional */
		if ((dprov_get_object_attr_ulong(object, DPROV_CKA_VALUE_LEN,
		    &value_len)) == CRYPTO_SUCCESS) {
			len = value_len;
		}

		/*
		 * The length of attributes are in bytes.
		 * Convert to bits now since that's how keys are measured.
		 */
		len  = CRYPTO_BYTES2BITS(len);

		ret_key->ck_data = value;
		ret_key->ck_length = (uint_t)len;
bail:
		break;
	}

	default:
		ret = CRYPTO_ARGUMENTS_BAD;
		break;
	}

	return (ret);
}

/*
 * Get the attribute list for the specified asymmetric key.
 */
static int
dprov_key_attr_asymmetric(dprov_state_t *softc, crypto_session_id_t session_id,
    dprov_req_type_t req_type, crypto_key_t *key, crypto_key_t *ret_key)
{
	int ret = CRYPTO_SUCCESS;

	ret_key->ck_format = CRYPTO_KEY_ATTR_LIST;

	switch (key->ck_format) {

	case CRYPTO_KEY_ATTR_LIST:
		ret_key->ck_attrs = key->ck_attrs;
		ret_key->ck_count = key->ck_count;
		break;

	case CRYPTO_KEY_REFERENCE: {
		dprov_object_t *object;

		/* check session id */
		if (softc->ds_sessions[session_id] == NULL) {
			ret = CRYPTO_SESSION_HANDLE_INVALID;
			break;
		}

		/* check if object id specified by key is valid */
		object = softc->ds_sessions[session_id]->
		    ds_objects[key->ck_obj_id];
		if (object == NULL) {
			ret = CRYPTO_KEY_HANDLE_INVALID;
			break;
		}

		/* check if object can be used for operation */
		if ((ret = dprov_key_can_use(object, req_type)) !=
		    CRYPTO_SUCCESS)
			break;

		ret_key->ck_attrs = object->do_attr;
		ret_key->ck_count = DPROV_MAX_ATTR;
		break;
	}

	default:
		ret = CRYPTO_ARGUMENTS_BAD;
	}

	return (ret);
}

/*
 * Return the index of an attribute of specified type found in
 * the specified array of attributes. If the attribute cannot
 * found, return -1.
 */
static int
dprov_find_attr(crypto_object_attribute_t *attr, uint_t nattr,
    uint64_t attr_type)
{
	int i;

	for (i = 0; i < nattr; i++)
		if (attr[i].oa_value != NULL &&
		    attr[i].oa_type == attr_type)
			return (i);

	return (-1);
}

/*
 * Given the given object template and session, return whether
 * an object can be created from that template according to the
 * following rules:
 * - private objects can be created only by a logged-in user
 */
static int
dprov_template_can_create(dprov_session_t *session,
    crypto_object_attribute_t *template, uint_t nattr,
    boolean_t check_for_secret)
{
	boolean_t is_private = B_FALSE;
	ulong_t key_type, class;
	int error;

	/* check CKA_PRIVATE attribute value */
	error = dprov_get_template_attr_boolean(template, nattr,
	    DPROV_CKA_PRIVATE, &is_private);
	if (error == CRYPTO_SUCCESS && is_private) {
		/* it's a private object */
		if (session->ds_state != DPROV_SESSION_STATE_USER) {
			/*
			 * Cannot create private object with SO or public
			 * sessions.
			 */
			return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
		}
	}

	/* all objects must have an object class attribute */
	if (dprov_get_template_attr_ulong(template, nattr, DPROV_CKA_CLASS,
	    &class) != CRYPTO_SUCCESS) {
		return (CRYPTO_TEMPLATE_INCOMPLETE);
	}

	/* key objects must have a key type attribute */
	if (class == DPROV_CKO_SECRET_KEY ||
	    class == DPROV_CKO_PUBLIC_KEY ||
	    class == DPROV_CKO_PRIVATE_KEY) {
		if (!dprov_template_attr_present(template, nattr,
		    DPROV_CKA_KEY_TYPE)) {
			return (CRYPTO_TEMPLATE_INCOMPLETE);
		}
	}

	/* check for RSA public key attributes that must be present */
	if (class == DPROV_CKO_PUBLIC_KEY) {
		if (dprov_get_template_attr_ulong(template, nattr,
		    DPROV_CKA_KEY_TYPE, &key_type) == CRYPTO_SUCCESS) {
			if (key_type == DPROV_CKK_RSA) {
				if (!dprov_template_attr_present(template,
				    nattr, DPROV_CKA_MODULUS) ||
				    !dprov_template_attr_present(template,
				    nattr, DPROV_CKA_PUBLIC_EXPONENT)) {
					return (CRYPTO_TEMPLATE_INCOMPLETE);
				}

				/* these attributes should not be present */
				if (dprov_template_attr_present(template, nattr,
				    DPROV_CKA_MODULUS_BITS)) {
					return (CRYPTO_TEMPLATE_INCONSISTENT);
				}
			}
		}
	}

	/* check for RSA private key attributes that must be present */
	if (class == DPROV_CKO_PRIVATE_KEY) {
		if (dprov_get_template_attr_ulong(template, nattr,
		    DPROV_CKA_KEY_TYPE, &key_type) == CRYPTO_SUCCESS) {
			if (key_type == DPROV_CKK_RSA) {
				if (!dprov_template_attr_present(template,
				    nattr, DPROV_CKA_MODULUS))
					return (CRYPTO_TEMPLATE_INCOMPLETE);

				if (check_for_secret) {
					if (!dprov_template_attr_present(
					    template, nattr,
					    DPROV_CKA_PRIVATE_EXPONENT))
						return (
						    CRYPTO_TEMPLATE_INCOMPLETE);
				}
			}
		}
	}

	/* check for secret key attributes that must be present */
	if (class == DPROV_CKO_SECRET_KEY) {
		if (check_for_secret) {
			if (!dprov_template_attr_present(template, nattr,
			    DPROV_CKA_VALUE)) {
				return (CRYPTO_TEMPLATE_INCOMPLETE);
			}
		}

		/* these attributes should not be present */
		if (dprov_template_attr_present(template, nattr,
		    DPROV_CKA_VALUE_LEN)) {
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		}
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Create an object from the specified template. Checks whether the
 * object can be created according to its attributes and the state
 * of the session. The new session object id is returned. If the
 * object is a token object, it is added to the per-instance object
 * table as well.
 */
static int
dprov_create_object_from_template(dprov_state_t *softc,
    dprov_session_t *session, crypto_object_attribute_t *template,
    uint_t nattr, crypto_object_id_t *object_id, boolean_t check_for_secret,
    boolean_t force)
{
	dprov_object_t *object;
	boolean_t is_token = B_FALSE;
	boolean_t extractable_attribute_present = B_FALSE;
	boolean_t sensitive_attribute_present = B_FALSE;
	boolean_t private_attribute_present = B_FALSE;
	boolean_t token_attribute_present = B_FALSE;
	uint_t i;
	int error;
	uint_t attr;
	uint_t oattr;
	crypto_attr_type_t type;
	size_t old_len, new_len;
	offset_t offset;

	if (nattr > DPROV_MAX_ATTR)
		return (CRYPTO_HOST_MEMORY);

	if (!force) {
		/* verify that object can be created */
		if ((error = dprov_template_can_create(session, template,
		    nattr, check_for_secret)) != CRYPTO_SUCCESS)
			return (error);
	}

	/* allocate new object */
	object = kmem_zalloc(sizeof (dprov_object_t), KM_SLEEP);
	if (object == NULL)
		return (CRYPTO_HOST_MEMORY);

	/* is it a token object? */
	/* check CKA_TOKEN attribute value */
	error = dprov_get_template_attr_boolean(template, nattr,
	    DPROV_CKA_TOKEN, &is_token);
	if (error == CRYPTO_SUCCESS && is_token) {
		/* token object, add it to the per-instance object table */
		for (i = 0; i < DPROV_MAX_OBJECTS; i++)
			if (softc->ds_objects[i] == NULL)
				break;
		if (i == DPROV_MAX_OBJECTS)
			/* no free slot */
			return (CRYPTO_HOST_MEMORY);
		softc->ds_objects[i] = object;
		object->do_token_idx = i;
		DPROV_OBJECT_REFHOLD(object);
	}

	/* add object to session object table */
	for (i = 0; i < DPROV_MAX_OBJECTS; i++)
		if (session->ds_objects[i] == NULL)
			break;
	if (i == DPROV_MAX_OBJECTS) {
		/* no more session object slots */
		DPROV_OBJECT_REFRELE(object);
		return (CRYPTO_HOST_MEMORY);
	}
	session->ds_objects[i] = object;
	DPROV_OBJECT_REFHOLD(object);
	*object_id = i;

	/* initialize object from template */
	for (attr = 0, oattr = 0; attr < nattr; attr++) {
		if (template[attr].oa_value == NULL)
			continue;
		type = template[attr].oa_type;
		old_len = template[attr].oa_value_len;
		new_len = attribute_size(type, old_len);

		if (type == DPROV_CKA_EXTRACTABLE) {
			extractable_attribute_present = B_TRUE;
		} else if (type == DPROV_CKA_PRIVATE) {
			private_attribute_present = B_TRUE;
		} else if (type == DPROV_CKA_TOKEN) {
			token_attribute_present = B_TRUE;
		}
		object->do_attr[oattr].oa_type = type;
		object->do_attr[oattr].oa_value_len = new_len;

		object->do_attr[oattr].oa_value = kmem_zalloc(new_len,
		    KM_SLEEP);

		offset = 0;
#ifdef _BIG_ENDIAN
		if (fixed_size_attribute(type)) {
			offset = old_len - new_len;
		}
#endif
		bcopy(&template[attr].oa_value[offset],
		    object->do_attr[oattr].oa_value, new_len);
		oattr++;
	}

	/* add boolean attributes that must be present */
	if (extractable_attribute_present == B_FALSE) {
		object->do_attr[oattr].oa_type = DPROV_CKA_EXTRACTABLE;
		object->do_attr[oattr].oa_value_len = 1;
		object->do_attr[oattr].oa_value = kmem_alloc(1, KM_SLEEP);
		object->do_attr[oattr].oa_value[0] = B_TRUE;
		oattr++;
	}

	if (private_attribute_present == B_FALSE) {
		object->do_attr[oattr].oa_type = DPROV_CKA_PRIVATE;
		object->do_attr[oattr].oa_value_len = 1;
		object->do_attr[oattr].oa_value = kmem_alloc(1, KM_SLEEP);
		object->do_attr[oattr].oa_value[0] = B_FALSE;
		oattr++;
	}

	if (token_attribute_present == B_FALSE) {
		object->do_attr[oattr].oa_type = DPROV_CKA_TOKEN;
		object->do_attr[oattr].oa_value_len = 1;
		object->do_attr[oattr].oa_value = kmem_alloc(1, KM_SLEEP);
		object->do_attr[oattr].oa_value[0] = B_FALSE;
		oattr++;
	}

	if (sensitive_attribute_present == B_FALSE) {
		object->do_attr[oattr].oa_type = DPROV_CKA_SENSITIVE;
		object->do_attr[oattr].oa_value_len = 1;
		object->do_attr[oattr].oa_value = kmem_alloc(1, KM_SLEEP);
		object->do_attr[oattr].oa_value[0] = B_FALSE;
		oattr++;
	}
	return (CRYPTO_SUCCESS);
}

/*
 * Checks whether or not the object matches the specified attributes.
 *
 * PKCS#11 attributes which are longs are stored in uint32_t containers
 * so they can be matched by both 32 and 64-bit applications.
 */
static boolean_t
dprov_attributes_match(dprov_object_t *object,
    crypto_object_attribute_t *template, uint_t nattr)
{
	crypto_attr_type_t type;
	size_t tlen, olen, diff;
	int ta_idx;	/* template attribute index */
	int oa_idx;	/* object attribute index */

	for (ta_idx = 0; ta_idx < nattr; ta_idx++) {
		/* no value for template attribute */
		if (template[ta_idx].oa_value == NULL)
			continue;

		/* find attribute in object */
		type = template[ta_idx].oa_type;
		oa_idx = dprov_find_attr(object->do_attr, DPROV_MAX_ATTR, type);

		if (oa_idx == -1)
			/* attribute not found in object */
			return (B_FALSE);

		tlen = template[ta_idx].oa_value_len;
		olen = object->do_attr[oa_idx].oa_value_len;
		if (tlen < olen)
			return (B_FALSE);

		diff = 0;
#ifdef _BIG_ENDIAN
		/* application may think attribute is 8 bytes */
		if (fixed_size_attribute(type))
			diff = tlen - olen;
#endif

		if (bcmp(&template[ta_idx].oa_value[diff],
		    object->do_attr[oa_idx].oa_value, olen) != 0)
			/* value mismatch */
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Destroy the object specified by its session and object id.
 */
static int
dprov_destroy_object(dprov_state_t *softc, dprov_session_t *session,
    crypto_object_id_t object_id)
{
	dprov_object_t *object;

	if ((object = session->ds_objects[object_id]) == NULL)
		return (CRYPTO_OBJECT_HANDLE_INVALID);

	/* remove from session table */
	session->ds_objects[object_id] = NULL;

	if (dprov_object_is_token(object)) {
		if (!object->do_destroyed) {
			object->do_destroyed = B_TRUE;
			/* remove from per-instance token table */
			softc->ds_objects[object->do_token_idx] = NULL;
			DPROV_OBJECT_REFRELE(object);
		} else {
			DPROV_DEBUG(D_OBJECT, ("dprov_destroy_object: "
			    "object %p already destroyed\n", (void *)object));
		}
	}

	DPROV_OBJECT_REFRELE(object);
	return (CRYPTO_SUCCESS);
}

static int
dprov_object_can_modify(dprov_object_t *object,
    crypto_object_attribute_t *template, uint_t nattr)
{
	ulong_t object_class;

	/* all objects should have an object class attribute */
	if (dprov_get_object_attr_ulong(object, DPROV_CKA_CLASS,
	    &object_class) != CRYPTO_SUCCESS) {
		return (CRYPTO_SUCCESS);
	}

	if (object_class == DPROV_CKO_SECRET_KEY ||
	    object_class == DPROV_CKO_PUBLIC_KEY ||
	    object_class == DPROV_CKO_PRIVATE_KEY) {
		if (dprov_template_attr_present(template, nattr,
		    DPROV_CKA_CLASS) ||
		    dprov_template_attr_present(template, nattr,
		    DPROV_CKA_KEY_TYPE))
			return (CRYPTO_TEMPLATE_INCONSISTENT);
	}

	switch (object_class) {
	case DPROV_CKO_SECRET_KEY:
		if (dprov_template_attr_present(template, nattr,
		    DPROV_CKA_VALUE))
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		break;

	case DPROV_CKO_PUBLIC_KEY:
		if (dprov_template_attr_present(template, nattr,
		    DPROV_CKA_MODULUS) ||
		    dprov_template_attr_present(template, nattr,
		    DPROV_CKA_PUBLIC_EXPONENT))
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		break;

	case DPROV_CKO_PRIVATE_KEY:
		if (dprov_template_attr_present(template, nattr,
		    DPROV_CKA_MODULUS) ||
		    dprov_template_attr_present(template, nattr,
		    DPROV_CKA_PRIVATE_EXPONENT))
			return (CRYPTO_TEMPLATE_INCONSISTENT);
		break;

	default:
		return (CRYPTO_SUCCESS);
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Set the attributes specified by the template in the specified object,
 * replacing existing ones if needed.
 */
static int
dprov_object_set_attr(dprov_session_t *session, crypto_object_id_t object_id,
    crypto_object_attribute_t *template, uint_t nattr,
    boolean_t check_attributes)
{
	crypto_attr_type_t type;
	dprov_object_t *object;
	size_t old_len, new_len;
	uint_t i, j;
	int error;

	if ((object = session->ds_objects[object_id]) == NULL)
		return (CRYPTO_OBJECT_HANDLE_INVALID);

	if (check_attributes) {
		/* verify that attributes in the template can be modified */
		if ((error = dprov_object_can_modify(object, template, nattr))
		    != CRYPTO_SUCCESS)
			return (error);
	}

	/* go through the attributes specified in the template */
	for (i = 0; i < nattr; i++) {
		if (template[i].oa_value == NULL)
			continue;

		/* find attribute in object */
		type = template[i].oa_type;
		j = dprov_find_attr(object->do_attr, DPROV_MAX_ATTR, type);

		if (j != -1) {
			/* attribute already exists, free old value */
			kmem_free(object->do_attr[j].oa_value,
			    object->do_attr[j].oa_value_len);
		} else {
			/* attribute does not exist, create it */
			for (j = 0; j < DPROV_MAX_ATTR; j++)
				if (object->do_attr[j].oa_value == NULL)
					break;
			if (j == DPROV_MAX_ATTR)
				/* ran out of attribute slots */
				return (CRYPTO_HOST_MEMORY);
		}

		old_len = template[i].oa_value_len;
		new_len = attribute_size(type, old_len);

		/* set object attribute value */
		object->do_attr[j].oa_value = kmem_alloc(new_len, KM_SLEEP);
		bcopy(&template[i].oa_value[old_len - new_len],
		    object->do_attr[j].oa_value, new_len);
		object->do_attr[j].oa_value_len = new_len;

		/* and the type */
		object->do_attr[j].oa_type = type;
	}

	return (CRYPTO_SUCCESS);
}


/*
 * Free the specified object.
 */
static void
dprov_free_object(dprov_object_t *object)
{
	int i;

	/* free the object attributes values */
	for (i = 0; i < DPROV_MAX_ATTR; i++)
		if (object->do_attr[i].oa_value != NULL)
			kmem_free(object->do_attr[i].oa_value,
			    object->do_attr[i].oa_value_len);

	/* free the object */
	kmem_free(object, sizeof (dprov_object_t));
}

/*
 * Checks whether the specified object is a private or public object.
 */
static boolean_t
dprov_object_is_private(dprov_object_t *object)
{
	boolean_t ret;
	int err;

	err = dprov_get_object_attr_boolean(object, DPROV_CKA_PRIVATE, &ret);

	if (err != CRYPTO_SUCCESS)
		/* by default, CKA_PRIVATE is false */
		ret = B_FALSE;

	return (ret);
}

/*
 * Checks whether the specified object is a token or session object.
 */
static boolean_t
dprov_object_is_token(dprov_object_t *object)
{
	boolean_t ret;
	int err;

	err = dprov_get_object_attr_boolean(object, DPROV_CKA_TOKEN, &ret);

	if (err != CRYPTO_SUCCESS)
		/* by default, CKA_TOKEN is false */
		ret = B_FALSE;

	return (ret);
}

/*
 * Common function used by the dprov_get_object_attr_*() family of
 * functions. Returns the value of the specified attribute of specified
 * length. Returns CRYPTO_SUCCESS on success, CRYPTO_ATTRIBUTE_VALUE_INVALID
 * if the length of the attribute does not match the specified length,
 * or CRYPTO_ARGUMENTS_BAD if the attribute cannot be found.
 */
static int
dprov_get_object_attr_scalar_common(dprov_object_t *object, uint64_t attr_type,
				    void *value, size_t value_len)
{
	int attr_idx;
	size_t oa_value_len;
	size_t offset = 0;

	if ((attr_idx = dprov_find_attr(object->do_attr, DPROV_MAX_ATTR,
	    attr_type)) == -1)
		return (CRYPTO_ARGUMENTS_BAD);

	oa_value_len = object->do_attr[attr_idx].oa_value_len;
	if (oa_value_len != value_len) {
		/*
		 * For some attributes, it's okay to copy the value
		 * into a larger container, e.g. copy an unsigned
		 * 32-bit integer into a 64-bit container.
		 */
		if (attr_type == DPROV_CKA_VALUE_LEN ||
		    attr_type == DPROV_CKA_KEY_TYPE ||
		    attr_type == DPROV_CKA_CLASS) {
			if (oa_value_len < value_len) {
#ifdef _BIG_ENDIAN
				offset = value_len - oa_value_len;
#endif
				bzero(value, value_len);
				goto do_copy;
			}
		}
		/* incorrect attribute value length */
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

do_copy:
	bcopy(object->do_attr[attr_idx].oa_value, (uchar_t *)value + offset,
	    oa_value_len);

	return (CRYPTO_SUCCESS);
}

/*
 * Get the value of the a boolean attribute from the specified object.
 */
static int
dprov_get_object_attr_boolean(dprov_object_t *object, uint64_t attr_type,
    boolean_t *attr_value)
{
	uchar_t val;
	int ret;

	/* PKCS#11 defines a boolean as one byte */
	ret = dprov_get_object_attr_scalar_common(object, attr_type, &val, 1);
	if (ret == CRYPTO_SUCCESS) {
		*attr_value = (val == '\0') ? B_FALSE : B_TRUE;
	}
	return (ret);
}

/*
 * Get the value of a ulong_t attribute from the specified object.
 */
static int
dprov_get_object_attr_ulong(dprov_object_t *object, uint64_t attr_type,
    ulong_t *attr_value)
{
	return (dprov_get_object_attr_scalar_common(object, attr_type,
	    attr_value, sizeof (ulong_t)));
}

/*
 * Find the specified byte array attribute of specified type in
 * the specified object. Returns CRYPTO_SUCCESS
 * on success or CRYPTO_ARGUMENTS_BAD if the specified
 * attribute cannot be found.
 */
static int
dprov_get_object_attr_array(dprov_object_t *object, uint64_t attr_type,
    void **array, size_t *len)
{
	int attr_idx;

	if ((attr_idx = dprov_find_attr(object->do_attr, DPROV_MAX_ATTR,
	    attr_type)) == -1)
		return (CRYPTO_ARGUMENTS_BAD);

	*array = object->do_attr[attr_idx].oa_value;
	*len = object->do_attr[attr_idx].oa_value_len;

	return (CRYPTO_SUCCESS);
}

/*
 * Common function used by the dprov_get_template_attr_*() family of
 * functions. Returns the value of the specified attribute of specified
 * length. Returns CRYPTO_SUCCESS on success, CRYPTO_ATTRIBUTE_VALUE_INVALID
 * if the length of the attribute does not match the specified length,
 * or CRYPTO_ARGUMENTS_BAD if the attribute cannot be found.
 */
static int
dprov_get_template_attr_scalar_common(crypto_object_attribute_t *template,
    uint_t nattr, uint64_t attr_type, void *value, size_t value_len)
{
	size_t oa_value_len;
	size_t offset = 0;
	int attr_idx;

	if ((attr_idx = dprov_find_attr(template, nattr, attr_type)) == -1)
		return (CRYPTO_ARGUMENTS_BAD);

	oa_value_len = template[attr_idx].oa_value_len;
	if (oa_value_len != value_len) {
		/*
		 * For some attributes, it's okay to copy the value
		 * into a larger container, e.g. copy an unsigned
		 * 32-bit integer into a 64-bit container.
		 */
		if (attr_type == DPROV_CKA_VALUE_LEN ||
		    attr_type == DPROV_CKA_KEY_TYPE ||
		    attr_type == DPROV_CKA_CLASS) {
			if (oa_value_len < value_len) {
#ifdef _BIG_ENDIAN
				offset = value_len - oa_value_len;
#endif
				bzero(value, value_len);
				goto do_copy;
			}
		}
		/* incorrect attribute value length */
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);
	}

do_copy:
	bcopy(template[attr_idx].oa_value, (uchar_t *)value + offset,
	    oa_value_len);

	return (CRYPTO_SUCCESS);
}

/*
 * Get the value of the a boolean attribute from the specified template
 */
static int
dprov_get_template_attr_boolean(crypto_object_attribute_t *template,
    uint_t nattr, uint64_t attr_type, boolean_t *attr_value)
{
	uchar_t val;
	int ret;

	/* PKCS#11 defines a boolean as one byte */
	ret = dprov_get_template_attr_scalar_common(template, nattr,
	    attr_type, &val, 1);
	if (ret == CRYPTO_SUCCESS) {
		*attr_value = (val == '\0') ? B_FALSE : B_TRUE;
	}
	return (ret);
}

/*
 * Get the value of a ulong_t attribute from the specified template.
 */
static int
dprov_get_template_attr_ulong(crypto_object_attribute_t *template,
    uint_t nattr, uint64_t attr_type, ulong_t *attr_value)
{
	return (dprov_get_template_attr_scalar_common(template, nattr,
	    attr_type, attr_value, sizeof (ulong_t)));
}

static int
dprov_template_attr_present(crypto_object_attribute_t *template,
    uint_t nattr, uint64_t attr_type)
{
	return (dprov_find_attr(template, nattr,
	    attr_type) == -1 ? B_FALSE : B_TRUE);
}

/*
 * Find the specified byte array attribute of specified type in
 * the specified template. Returns CRYPTO_SUCCESS on success or
 * CRYPTO_ARGUMENTS_BAD if the specified attribute cannot be found.
 */
static int
dprov_get_template_attr_array(crypto_object_attribute_t *template,
    uint_t nattr, uint64_t attr_type, void **array, size_t *len)
{
	int attr_idx;

	if ((attr_idx = dprov_find_attr(template, nattr, attr_type)) == -1)
		return (CRYPTO_ARGUMENTS_BAD);

	*array = template[attr_idx].oa_value;
	*len = template[attr_idx].oa_value_len;

	return (CRYPTO_SUCCESS);
}

/*
 * Common function used by the dprov_get_key_attr_*() family of
 * functions. Returns the value of the specified attribute of specified
 * length. Returns CRYPTO_SUCCESS on success, CRYPTO_ATTRIBUTE_VALUE_INVALID
 * if the length of the attribute does not match the specified length,
 * or CRYPTO_ARGUMENTS_BAD if the attribute cannot be found.
 */
static int
dprov_get_key_attr_scalar_common(crypto_key_t *key, uint64_t attr_type,
    void *value, size_t value_len)
{
	int attr_idx;

	ASSERT(key->ck_format == CRYPTO_KEY_ATTR_LIST);

	if ((attr_idx = dprov_find_attr(key->ck_attrs, key->ck_count,
	    attr_type)) == -1)
		return (CRYPTO_ARGUMENTS_BAD);

	if (key->ck_attrs[attr_idx].oa_value_len != value_len)
		/* incorrect attribute value length */
		return (CRYPTO_ATTRIBUTE_VALUE_INVALID);

	bcopy(key->ck_attrs[attr_idx].oa_value, value, value_len);

	return (CRYPTO_SUCCESS);
}

/*
 * Get the value of a ulong_t attribute from the specified key.
 */
static int
dprov_get_key_attr_ulong(crypto_key_t *key, uint64_t attr_type,
    ulong_t *attr_value)
{
	return (dprov_get_key_attr_scalar_common(key, attr_type,
	    attr_value, sizeof (ulong_t)));
}

/*
 * Find the specified byte array attribute of specified type in
 * the specified key by attributes. Returns CRYPTO_SUCCESS
 * on success or CRYPTO_ARGUMENTS_BAD if the specified
 * attribute cannot be found.
 */
static int
dprov_get_key_attr_array(crypto_key_t *key, uint64_t attr_type,
    void **array, size_t *len)
{
	int attr_idx;

	ASSERT(key->ck_format == CRYPTO_KEY_ATTR_LIST);

	if ((attr_idx = dprov_find_attr(key->ck_attrs, key->ck_count,
	    attr_type)) == -1)
		return (CRYPTO_ARGUMENTS_BAD);

	*array = key->ck_attrs[attr_idx].oa_value;
	*len = key->ck_attrs[attr_idx].oa_value_len;

	return (CRYPTO_SUCCESS);
}

static void
dprov_release_session_objects(dprov_session_t *session)
{
	dprov_object_t *object;
	int i;

	for (i = 0; i < DPROV_MAX_OBJECTS; i++) {
		object = session->ds_objects[i];
		if (object != NULL) {
			DPROV_OBJECT_REFRELE(object);
		}
	}
}

/*
 * Adjust an attribute list by turning 32-bit values into 64-bit values
 * for certain attributes like CKA_CLASS. Assumes that at least 8 bytes
 * of storage have been allocated for all attributes.
 */
static void
dprov_adjust_attrs(crypto_object_attribute_t *in, int in_count)
{
	int i;
	size_t offset = 0;
	ulong_t tmp = 0;

	for (i = 0; i < in_count; i++) {
		/*
		 * For some attributes, it's okay to copy the value
		 * into a larger container, e.g. copy an unsigned
		 * 32-bit integer into a 64-bit container.
		 */
		if (in[i].oa_type == CKA_VALUE_LEN ||
		    in[i].oa_type == CKA_KEY_TYPE ||
		    in[i].oa_type == CKA_CLASS) {
			if (in[i].oa_value_len < sizeof (ulong_t)) {
#ifdef _BIG_ENDIAN
				offset = sizeof (ulong_t) - in[i].oa_value_len;
#endif
				bcopy(in[i].oa_value, (uchar_t *)&tmp + offset,
				    in[i].oa_value_len);
				bcopy(&tmp, in[i].oa_value, sizeof (ulong_t));
				in[i].oa_value_len = sizeof (ulong_t);
			}
		}
	}
}
