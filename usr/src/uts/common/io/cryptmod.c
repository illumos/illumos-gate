/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2018, Joyent, Inc.
 *
 * STREAMS Crypto Module
 *
 * This module is used to facilitate Kerberos encryption
 * operations for the telnet daemon and rlogin daemon.
 * Because the Solaris telnet and rlogin daemons run mostly
 * in-kernel via 'telmod' and 'rlmod', this module must be
 * pushed on the STREAM *below* telmod or rlmod.
 *
 * Parts of the 3DES key derivation code are covered by the
 * following copyright.
 *
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/time.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strlog.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/strsun.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/cryptmod.h>
#include <sys/crc32.h>
#include <sys/policy.h>

#include <sys/crypto/api.h>

/*
 * Function prototypes.
 */
static	int	cryptmodopen(queue_t *, dev_t *, int, int, cred_t *);
static  void	cryptmodrput(queue_t *, mblk_t *);
static  void	cryptmodwput(queue_t *, mblk_t *);
static	int	cryptmodclose(queue_t *, int, cred_t *);
static	int	cryptmodwsrv(queue_t *);
static	int	cryptmodrsrv(queue_t *);

static mblk_t *do_encrypt(queue_t *q, mblk_t *mp);
static mblk_t *do_decrypt(queue_t *q, mblk_t *mp);

#define	CRYPTMOD_ID 5150

#define	CFB_BLKSZ 8

#define	K5CLENGTH 5

static struct module_info	cryptmod_minfo = {
	CRYPTMOD_ID,	/* mi_idnum */
	"cryptmod",	/* mi_idname */
	0,		/* mi_minpsz */
	INFPSZ,		/* mi_maxpsz */
	65536,		/* mi_hiwat */
	1024		/* mi_lowat */
};

static struct qinit	cryptmod_rinit = {
	(int (*)())cryptmodrput,	/* qi_putp */
	cryptmodrsrv,	/* qi_svc */
	cryptmodopen,	/* qi_qopen */
	cryptmodclose,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&cryptmod_minfo,	/* qi_minfo */
	NULL		/* qi_mstat */
};

static struct qinit	cryptmod_winit = {
	(int (*)())cryptmodwput,	/* qi_putp */
	cryptmodwsrv,	/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&cryptmod_minfo,	/* qi_minfo */
	NULL		/* qi_mstat */
};

static struct streamtab	cryptmod_info = {
	&cryptmod_rinit,	/* st_rdinit */
	&cryptmod_winit,	/* st_wrinit */
	NULL,	/* st_muxrinit */
	NULL	/* st_muxwinit */
};

typedef struct {
	uint_t hash_len;
	uint_t confound_len;
	int (*hashfunc)();
} hash_info_t;

#define	MAX_CKSUM_LEN 20
#define	CONFOUNDER_LEN 8

#define	SHA1_HASHSIZE 20
#define	MD5_HASHSIZE 16
#define	CRC32_HASHSIZE 4
#define	MSGBUF_SIZE 4096
#define	CONFOUNDER_BYTES 128


static int crc32_calc(uchar_t *, uchar_t *, uint_t);
static int md5_calc(uchar_t *, uchar_t *, uint_t);
static int sha1_calc(uchar_t *, uchar_t *, uint_t);

static hash_info_t null_hash = {0, 0, NULL};
static hash_info_t crc32_hash = {CRC32_HASHSIZE, CONFOUNDER_LEN, crc32_calc};
static hash_info_t md5_hash = {MD5_HASHSIZE, CONFOUNDER_LEN, md5_calc};
static hash_info_t sha1_hash = {SHA1_HASHSIZE, CONFOUNDER_LEN, sha1_calc};

static crypto_mech_type_t sha1_hmac_mech = CRYPTO_MECH_INVALID;
static crypto_mech_type_t md5_hmac_mech = CRYPTO_MECH_INVALID;
static crypto_mech_type_t sha1_hash_mech = CRYPTO_MECH_INVALID;
static crypto_mech_type_t md5_hash_mech = CRYPTO_MECH_INVALID;

static int kef_crypt(struct cipher_data_t *, void *,
		    crypto_data_format_t, size_t, int);
static mblk_t *
arcfour_hmac_md5_encrypt(queue_t *, struct tmodinfo *,
		mblk_t *, hash_info_t *);
static mblk_t *
arcfour_hmac_md5_decrypt(queue_t *, struct tmodinfo *,
		mblk_t *, hash_info_t *);

static int
do_hmac(crypto_mech_type_t, crypto_key_t *, char *, int, char *, int);

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

static struct fmodsw fsw = {
	"cryptmod",
	&cryptmod_info,
	D_MP | D_MTQPAIR
};

/*
 * Module linkage information for the kernel.
 */
static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	"STREAMS encryption module",
	&fsw
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlstrmod,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
cleanup(struct cipher_data_t *cd)
{
	if (cd->key != NULL) {
		bzero(cd->key, cd->keylen);
		kmem_free(cd->key, cd->keylen);
		cd->key = NULL;
	}

	if (cd->ckey != NULL) {
		/*
		 * ckey is a crypto_key_t structure which references
		 * "cd->key" for its raw key data.  Since that was already
		 * cleared out, we don't need another "bzero" here.
		 */
		kmem_free(cd->ckey, sizeof (crypto_key_t));
		cd->ckey = NULL;
	}

	if (cd->block != NULL) {
		kmem_free(cd->block, cd->blocklen);
		cd->block = NULL;
	}

	if (cd->saveblock != NULL) {
		kmem_free(cd->saveblock, cd->blocklen);
		cd->saveblock = NULL;
	}

	if (cd->ivec != NULL) {
		kmem_free(cd->ivec, cd->ivlen);
		cd->ivec = NULL;
	}

	if (cd->d_encr_key.ck_data != NULL) {
		bzero(cd->d_encr_key.ck_data, cd->keylen);
		kmem_free(cd->d_encr_key.ck_data, cd->keylen);
	}

	if (cd->d_hmac_key.ck_data != NULL) {
		bzero(cd->d_hmac_key.ck_data, cd->keylen);
		kmem_free(cd->d_hmac_key.ck_data, cd->keylen);
	}

	if (cd->enc_tmpl != NULL)
		(void) crypto_destroy_ctx_template(cd->enc_tmpl);

	if (cd->hmac_tmpl != NULL)
		(void) crypto_destroy_ctx_template(cd->hmac_tmpl);

	if (cd->ctx != NULL) {
		crypto_cancel_ctx(cd->ctx);
		cd->ctx = NULL;
	}
}

/* ARGSUSED */
static int
cryptmodopen(queue_t *rq, dev_t *dev, int oflag, int sflag, cred_t *crp)
{
	struct tmodinfo	*tmi;
	ASSERT(rq);

	if (sflag != MODOPEN)
		return (EINVAL);

	(void) (STRLOG(CRYPTMOD_ID, 0, 5, SL_TRACE|SL_NOTE,
			"cryptmodopen: opening module(PID %d)",
			ddi_get_pid()));

	if (rq->q_ptr != NULL) {
		cmn_err(CE_WARN, "cryptmodopen: already opened");
		return (0);
	}

	/*
	 * Allocate and initialize per-Stream structure.
	 */
	tmi = (struct tmodinfo *)kmem_zalloc(sizeof (struct tmodinfo),
						KM_SLEEP);

	tmi->enc_data.method = CRYPT_METHOD_NONE;
	tmi->dec_data.method = CRYPT_METHOD_NONE;

	tmi->ready = (CRYPT_READ_READY | CRYPT_WRITE_READY);

	rq->q_ptr = WR(rq)->q_ptr = tmi;

	sha1_hmac_mech = crypto_mech2id(SUN_CKM_SHA1_HMAC);
	md5_hmac_mech = crypto_mech2id(SUN_CKM_MD5_HMAC);
	sha1_hash_mech = crypto_mech2id(SUN_CKM_SHA1);
	md5_hash_mech = crypto_mech2id(SUN_CKM_MD5);

	qprocson(rq);

	return (0);
}

/* ARGSUSED */
static int
cryptmodclose(queue_t *rq, int flags __unused, cred_t *credp __unused)
{
	struct tmodinfo *tmi = (struct tmodinfo *)rq->q_ptr;
	ASSERT(tmi);

	qprocsoff(rq);

	cleanup(&tmi->enc_data);
	cleanup(&tmi->dec_data);

	kmem_free(tmi, sizeof (struct tmodinfo));
	rq->q_ptr = WR(rq)->q_ptr = NULL;

	return (0);
}

/*
 * plaintext_offset
 *
 * Calculate exactly how much space is needed in front
 * of the "plaintext" in an mbuf so it can be positioned
 * 1 time instead of potentially moving the data multiple
 * times.
 */
static int
plaintext_offset(struct cipher_data_t *cd)
{
	int headspace = 0;

	/* 4 byte length prepended to all RCMD msgs */
	if (ANY_RCMD_MODE(cd->option_mask))
		headspace += RCMD_LEN_SZ;

	/* RCMD V2 mode adds an additional 4 byte plaintext length */
	if (cd->option_mask & CRYPTOPT_RCMD_MODE_V2)
		headspace += RCMD_LEN_SZ;

	/* Need extra space for hash and counfounder */
	switch (cd->method) {
	case CRYPT_METHOD_DES_CBC_NULL:
		headspace += null_hash.hash_len + null_hash.confound_len;
		break;
	case CRYPT_METHOD_DES_CBC_CRC:
		headspace += crc32_hash.hash_len + crc32_hash.confound_len;
		break;
	case CRYPT_METHOD_DES_CBC_MD5:
		headspace += md5_hash.hash_len + md5_hash.confound_len;
		break;
	case CRYPT_METHOD_DES3_CBC_SHA1:
		headspace += sha1_hash.confound_len;
		break;
	case CRYPT_METHOD_ARCFOUR_HMAC_MD5:
		headspace += md5_hash.hash_len + md5_hash.confound_len;
		break;
	case CRYPT_METHOD_AES128:
	case CRYPT_METHOD_AES256:
		headspace += DEFAULT_AES_BLOCKLEN;
		break;
	case CRYPT_METHOD_DES_CFB:
	case CRYPT_METHOD_NONE:
		break;
	}

	return (headspace);
}
/*
 * encrypt_size
 *
 * Calculate the resulting size when encrypting 'plainlen' bytes
 * of data.
 */
static size_t
encrypt_size(struct cipher_data_t *cd, size_t plainlen)
{
	size_t cipherlen;

	switch (cd->method) {
	case CRYPT_METHOD_DES_CBC_NULL:
		cipherlen = (size_t)P2ROUNDUP(null_hash.hash_len +
					    plainlen, 8);
		break;
	case CRYPT_METHOD_DES_CBC_MD5:
		cipherlen = (size_t)P2ROUNDUP(md5_hash.hash_len +
					    md5_hash.confound_len +
					    plainlen, 8);
		break;
	case CRYPT_METHOD_DES_CBC_CRC:
		cipherlen = (size_t)P2ROUNDUP(crc32_hash.hash_len +
					    crc32_hash.confound_len +
					    plainlen, 8);
		break;
	case CRYPT_METHOD_DES3_CBC_SHA1:
		cipherlen = (size_t)P2ROUNDUP(sha1_hash.confound_len +
					    plainlen, 8) +
					    sha1_hash.hash_len;
		break;
	case CRYPT_METHOD_ARCFOUR_HMAC_MD5:
		cipherlen = (size_t)P2ROUNDUP(md5_hash.confound_len +
				plainlen, 1) + md5_hash.hash_len;
		break;
	case CRYPT_METHOD_AES128:
	case CRYPT_METHOD_AES256:
		/* No roundup for AES-CBC-CTS */
		cipherlen = DEFAULT_AES_BLOCKLEN + plainlen +
			AES_TRUNCATED_HMAC_LEN;
		break;
	case CRYPT_METHOD_DES_CFB:
	case CRYPT_METHOD_NONE:
		cipherlen = plainlen;
		break;
	}

	return (cipherlen);
}

/*
 * des_cfb_encrypt
 *
 * Encrypt the mblk data using DES with cipher feedback.
 *
 * Given that V[i] is the initial 64 bit vector, V[n] is the nth 64 bit
 * vector, D[n] is the nth chunk of 64 bits of data to encrypt
 * (decrypt), and O[n] is the nth chunk of 64 bits of encrypted
 * (decrypted) data, then:
 *
 *  V[0] = DES(V[i], key)
 *  O[n] = D[n] <exclusive or > V[n]
 *  V[n+1] = DES(O[n], key)
 *
 * The size of the message being encrypted does not change in this
 * algorithm, num_bytes in == num_bytes out.
 */
static mblk_t *
des_cfb_encrypt(queue_t *q, struct tmodinfo *tmi, mblk_t *mp)
{
	int savedbytes;
	char *iptr, *optr, *lastoutput;

	lastoutput = optr = (char *)mp->b_rptr;
	iptr = (char *)mp->b_rptr;
	savedbytes = tmi->enc_data.bytes % CFB_BLKSZ;

	while (iptr < (char *)mp->b_wptr) {
		/*
		 * Do DES-ECB.
		 * The first time this runs, the 'tmi->enc_data.block' will
		 * contain the initialization vector that should have been
		 * passed in with the SETUP ioctl.
		 *
		 * V[n] = DES(V[n-1], key)
		 */
		if (!(tmi->enc_data.bytes % CFB_BLKSZ)) {
			int retval = 0;
			retval = kef_crypt(&tmi->enc_data,
					tmi->enc_data.block,
					CRYPTO_DATA_RAW,
					tmi->enc_data.blocklen,
					CRYPT_ENCRYPT);

			if (retval != CRYPTO_SUCCESS) {
#ifdef DEBUG
				cmn_err(CE_WARN, "des_cfb_encrypt: kef_crypt "
					"failed - error 0x%0x", retval);
#endif
				mp->b_datap->db_type = M_ERROR;
				mp->b_rptr = mp->b_datap->db_base;
				*mp->b_rptr = EIO;
				mp->b_wptr = mp->b_rptr + sizeof (char);
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
				qreply(WR(q), mp);
				return (NULL);
			}
		}

		/* O[n] = I[n] ^ V[n] */
		*(optr++) = *(iptr++) ^
		    tmi->enc_data.block[tmi->enc_data.bytes % CFB_BLKSZ];

		tmi->enc_data.bytes++;
		/*
		 * Feedback the encrypted output as the input to next DES call.
		 */
		if (!(tmi->enc_data.bytes % CFB_BLKSZ)) {
			char *dbptr = tmi->enc_data.block;
			/*
			 * Get the last bits of input from the previous
			 * msg block that we haven't yet used as feedback input.
			 */
			if (savedbytes > 0) {
				bcopy(tmi->enc_data.saveblock,
				    dbptr, (size_t)savedbytes);
				dbptr += savedbytes;
			}

			/*
			 * Now copy the correct bytes from the current input
			 * stream and update the 'lastoutput' ptr
			 */
			bcopy(lastoutput, dbptr,
				(size_t)(CFB_BLKSZ - savedbytes));

			lastoutput += (CFB_BLKSZ - savedbytes);
			savedbytes = 0;
		}
	}
	/*
	 * If there are bytes of input here that we need in the next
	 * block to build an ivec, save them off here.
	 */
	if (lastoutput < optr) {
		bcopy(lastoutput,
		    tmi->enc_data.saveblock + savedbytes,
		    (uint_t)(optr - lastoutput));
	}
	return (mp);
}

/*
 * des_cfb_decrypt
 *
 * Decrypt the data in the mblk using DES in Cipher Feedback mode
 *
 * # bytes in == # bytes out, no padding, confounding, or hashing
 * is added.
 *
 */
static mblk_t *
des_cfb_decrypt(queue_t *q, struct tmodinfo *tmi, mblk_t *mp)
{
	uint_t len;
	uint_t savedbytes;
	char *iptr;
	char *lastinput;
	uint_t cp;

	len = MBLKL(mp);

	/* decrypted output goes into the new data buffer */
	lastinput = iptr = (char *)mp->b_rptr;

	savedbytes = tmi->dec_data.bytes % tmi->dec_data.blocklen;

	/*
	 * Save the input CFB_BLKSZ bytes at a time.
	 * We are trying to decrypt in-place, but need to keep
	 * a small sliding window of encrypted text to be
	 * used to construct the feedback buffer.
	 */
	cp = ((tmi->dec_data.blocklen - savedbytes) > len ? len :
		tmi->dec_data.blocklen - savedbytes);

	bcopy(lastinput, tmi->dec_data.saveblock + savedbytes, cp);
	savedbytes += cp;

	lastinput += cp;

	while (iptr < (char *)mp->b_wptr) {
		/*
		 * Do DES-ECB.
		 * The first time this runs, the 'tmi->dec_data.block' will
		 * contain the initialization vector that should have been
		 * passed in with the SETUP ioctl.
		 */
		if (!(tmi->dec_data.bytes % CFB_BLKSZ)) {
			int retval;
			retval = kef_crypt(&tmi->dec_data,
					tmi->dec_data.block,
					CRYPTO_DATA_RAW,
					tmi->dec_data.blocklen,
					CRYPT_ENCRYPT);

			if (retval != CRYPTO_SUCCESS) {
#ifdef DEBUG
				cmn_err(CE_WARN, "des_cfb_decrypt: kef_crypt "
					"failed - status 0x%0x", retval);
#endif
				mp->b_datap->db_type = M_ERROR;
				mp->b_rptr = mp->b_datap->db_base;
				*mp->b_rptr = EIO;
				mp->b_wptr = mp->b_rptr + sizeof (char);
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
				qreply(WR(q), mp);
				return (NULL);
			}
		}

		/*
		 * To decrypt, XOR the input with the output from the DES call
		 */
		*(iptr++) ^= tmi->dec_data.block[tmi->dec_data.bytes %
				CFB_BLKSZ];

		tmi->dec_data.bytes++;

		/*
		 * Feedback the encrypted input for next DES call.
		 */
		if (!(tmi->dec_data.bytes % tmi->dec_data.blocklen)) {
			char *dbptr = tmi->dec_data.block;
			/*
			 * Get the last bits of input from the previous block
			 * that we haven't yet processed.
			 */
			if (savedbytes > 0) {
				bcopy(tmi->dec_data.saveblock,
				    dbptr, savedbytes);
				dbptr += savedbytes;
			}

			savedbytes = 0;

			/*
			 * This block makes sure that our local
			 * buffer of input data is full and can
			 * be accessed from the beginning.
			 */
			if (lastinput < (char *)mp->b_wptr) {

				/* How many bytes are left in the mblk? */
				cp = (((char *)mp->b_wptr - lastinput) >
					tmi->dec_data.blocklen ?
					tmi->dec_data.blocklen :
					(char *)mp->b_wptr - lastinput);

				/* copy what we need */
				bcopy(lastinput, tmi->dec_data.saveblock,
					cp);

				lastinput += cp;
				savedbytes = cp;
			}
		}
	}

	return (mp);
}

/*
 * crc32_calc
 *
 * Compute a CRC32 checksum on the input
 */
static int
crc32_calc(uchar_t *buf, uchar_t *input, uint_t len)
{
	uint32_t crc;

	CRC32(crc, input, len, 0, crc32_table);

	buf[0] = (uchar_t)(crc & 0xff);
	buf[1] = (uchar_t)((crc >> 8) & 0xff);
	buf[2] = (uchar_t)((crc >> 16) & 0xff);
	buf[3] = (uchar_t)((crc >> 24) & 0xff);

	return (CRYPTO_SUCCESS);
}

static int
kef_digest(crypto_mech_type_t digest_type,
	uchar_t *input, uint_t inlen,
	uchar_t *output, uint_t hashlen)
{
	iovec_t v1, v2;
	crypto_data_t d1, d2;
	crypto_mechanism_t mech;
	int rv;

	mech.cm_type = digest_type;
	mech.cm_param = 0;
	mech.cm_param_len = 0;

	v1.iov_base = (void *)input;
	v1.iov_len = inlen;

	d1.cd_format = CRYPTO_DATA_RAW;
	d1.cd_offset = 0;
	d1.cd_length = v1.iov_len;
	d1.cd_raw = v1;

	v2.iov_base = (void *)output;
	v2.iov_len = hashlen;

	d2.cd_format = CRYPTO_DATA_RAW;
	d2.cd_offset = 0;
	d2.cd_length = v2.iov_len;
	d2.cd_raw = v2;

	rv = crypto_digest(&mech, &d1, &d2, NULL);

	return (rv);
}

/*
 * sha1_calc
 *
 * Get a SHA1 hash on the input data.
 */
static int
sha1_calc(uchar_t *output, uchar_t *input, uint_t inlen)
{
	int rv;

	rv = kef_digest(sha1_hash_mech, input, inlen, output, SHA1_HASHSIZE);

	return (rv);
}

/*
 * Get an MD5 hash on the input data.
 * md5_calc
 *
 */
static int
md5_calc(uchar_t *output, uchar_t *input, uint_t inlen)
{
	int rv;

	rv = kef_digest(md5_hash_mech, input, inlen, output, MD5_HASHSIZE);

	return (rv);
}

/*
 * nfold
 * duplicate the functionality of the krb5_nfold function from
 * the userland kerberos mech.
 * This is needed to derive keys for use with 3DES/SHA1-HMAC
 * ciphers.
 */
static void
nfold(int inbits, uchar_t *in, int outbits, uchar_t *out)
{
	int a, b, c, lcm;
	int byte, i, msbit;

	inbits >>= 3;
	outbits >>= 3;

	/* first compute lcm(n,k) */
	a = outbits;
	b = inbits;

	while (b != 0) {
		c = b;
		b = a%b;
		a = c;
	}

	lcm = outbits*inbits/a;

	/* now do the real work */

	bzero(out, outbits);
	byte = 0;

	/*
	 * Compute the msbit in k which gets added into this byte
	 * first, start with the msbit in the first, unrotated byte
	 * then, for each byte, shift to the right for each repetition
	 * last, pick out the correct byte within that shifted repetition
	 */
	for (i = lcm-1; i >= 0; i--) {
		msbit = (((inbits<<3)-1)
			+(((inbits<<3)+13)*(i/inbits))
			+((inbits-(i%inbits))<<3)) %(inbits<<3);

		/* pull out the byte value itself */
		byte += (((in[((inbits-1)-(msbit>>3))%inbits]<<8)|
			(in[((inbits)-(msbit>>3))%inbits]))
			>>((msbit&7)+1))&0xff;

		/* do the addition */
		byte += out[i%outbits];
		out[i%outbits] = byte&0xff;

		byte >>= 8;
	}

	/* if there's a carry bit left over, add it back in */
	if (byte) {
		for (i = outbits-1; i >= 0; i--) {
			/* do the addition */
			byte += out[i];
			out[i] = byte&0xff;

			/* keep around the carry bit, if any */
			byte >>= 8;
		}
	}
}

#define	smask(step) ((1<<step)-1)
#define	pstep(x, step) (((x)&smask(step))^(((x)>>step)&smask(step)))
#define	parity_char(x) pstep(pstep(pstep((x), 4), 2), 1)

/*
 * Duplicate the functionality of the "dk_derive_key" function
 * in the Kerberos mechanism.
 */
static int
derive_key(struct cipher_data_t *cdata, uchar_t *constdata,
	int constlen, char *dkey, int keybytes,
	int blocklen)
{
	int rv = 0;
	int n = 0, i;
	char *inblock;
	char *rawkey;
	char *zeroblock;
	char *saveblock;

	inblock = kmem_zalloc(blocklen, KM_SLEEP);
	rawkey = kmem_zalloc(keybytes, KM_SLEEP);
	zeroblock = kmem_zalloc(blocklen, KM_SLEEP);

	if (constlen == blocklen)
		bcopy(constdata, inblock, blocklen);
	else
		nfold(constlen * 8, constdata,
			blocklen * 8, (uchar_t *)inblock);

	/*
	 * zeroblock is an IV of all 0's.
	 *
	 * The "block" section of the cdata record is used as the
	 * IV for crypto operations in the kef_crypt function.
	 *
	 * We use 'block' as a generic IV data buffer because it
	 * is attached to the stream state data and thus can
	 * be used to hold information that must carry over
	 * from processing of one mblk to another.
	 *
	 * Here, we save the current IV and replace it with
	 * and empty IV (all 0's) for use when deriving the
	 * keys.  Once the key derivation is done, we swap the
	 * old IV back into place.
	 */
	saveblock = cdata->block;
	cdata->block = zeroblock;

	while (n < keybytes) {
		rv = kef_crypt(cdata, inblock, CRYPTO_DATA_RAW,
				blocklen, CRYPT_ENCRYPT);
		if (rv != CRYPTO_SUCCESS) {
			/* put the original IV block back in place */
			cdata->block = saveblock;
			cmn_err(CE_WARN, "failed to derive a key: %0x", rv);
			goto cleanup;
		}

		if (keybytes - n < blocklen) {
			bcopy(inblock, rawkey+n, (keybytes-n));
			break;
		}
		bcopy(inblock, rawkey+n, blocklen);
		n += blocklen;
	}
	/* put the original IV block back in place */
	cdata->block = saveblock;

	/* finally, make the key */
	if (cdata->method == CRYPT_METHOD_DES3_CBC_SHA1) {
		/*
		 * 3DES key derivation requires that we make sure the
		 * key has the proper parity.
		 */
		for (i = 0; i < 3; i++) {
			bcopy(rawkey+(i*7), dkey+(i*8), 7);

			/* 'dkey' is our derived key output buffer */
			dkey[i*8+7] = (((dkey[i*8]&1)<<1) |
					((dkey[i*8+1]&1)<<2) |
					((dkey[i*8+2]&1)<<3) |
					((dkey[i*8+3]&1)<<4) |
					((dkey[i*8+4]&1)<<5) |
					((dkey[i*8+5]&1)<<6) |
					((dkey[i*8+6]&1)<<7));

			for (n = 0; n < 8; n++) {
				dkey[i*8 + n] &=  0xfe;
				dkey[i*8 + n] |= 1^parity_char(dkey[i*8 + n]);
			}
		}
	} else if (IS_AES_METHOD(cdata->method)) {
		bcopy(rawkey, dkey, keybytes);
	}
cleanup:
	kmem_free(inblock, blocklen);
	kmem_free(zeroblock, blocklen);
	kmem_free(rawkey, keybytes);
	return (rv);
}

/*
 * create_derived_keys
 *
 * Algorithm for deriving a new key and an HMAC key
 * before computing the 3DES-SHA1-HMAC operation on the plaintext
 * This algorithm matches the work done by Kerberos mechanism
 * in userland.
 */
static int
create_derived_keys(struct cipher_data_t *cdata, uint32_t usage,
		crypto_key_t *enckey, crypto_key_t *hmackey)
{
	uchar_t constdata[K5CLENGTH];
	int keybytes;
	int rv;

	constdata[0] = (usage>>24)&0xff;
	constdata[1] = (usage>>16)&0xff;
	constdata[2] = (usage>>8)&0xff;
	constdata[3] = usage & 0xff;
	/* Use "0xAA" for deriving encryption key */
	constdata[4] = 0xAA; /* from MIT Kerberos code */

	enckey->ck_length = cdata->keylen * 8;
	enckey->ck_format = CRYPTO_KEY_RAW;
	enckey->ck_data = kmem_zalloc(cdata->keylen, KM_SLEEP);

	switch (cdata->method) {
		case CRYPT_METHOD_DES_CFB:
		case CRYPT_METHOD_DES_CBC_NULL:
		case CRYPT_METHOD_DES_CBC_MD5:
		case CRYPT_METHOD_DES_CBC_CRC:
			keybytes = 8;
			break;
		case CRYPT_METHOD_DES3_CBC_SHA1:
			keybytes = CRYPT_DES3_KEYBYTES;
			break;
		case CRYPT_METHOD_ARCFOUR_HMAC_MD5:
		case CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP:
			keybytes = CRYPT_ARCFOUR_KEYBYTES;
			break;
		case CRYPT_METHOD_AES128:
			keybytes = CRYPT_AES128_KEYBYTES;
			break;
		case CRYPT_METHOD_AES256:
			keybytes = CRYPT_AES256_KEYBYTES;
			break;
	}

	/* derive main crypto key */
	rv = derive_key(cdata, constdata, sizeof (constdata),
		enckey->ck_data, keybytes, cdata->blocklen);

	if (rv == CRYPTO_SUCCESS) {

		/* Use "0x55" for deriving mac key */
		constdata[4] = 0x55;

		hmackey->ck_length = cdata->keylen * 8;
		hmackey->ck_format = CRYPTO_KEY_RAW;
		hmackey->ck_data = kmem_zalloc(cdata->keylen, KM_SLEEP);

		rv = derive_key(cdata, constdata, sizeof (constdata),
				hmackey->ck_data, keybytes,
				cdata->blocklen);
	} else {
		cmn_err(CE_WARN, "failed to derive crypto key: %02x", rv);
	}

	return (rv);
}

/*
 * Compute 3-DES crypto and HMAC.
 */
static int
kef_decr_hmac(struct cipher_data_t *cdata,
	mblk_t *mp, int length,
	char *hmac, int hmaclen)
{
	int rv = CRYPTO_FAILED;

	crypto_mechanism_t encr_mech;
	crypto_mechanism_t mac_mech;
	crypto_data_t dd;
	crypto_data_t mac;
	iovec_t v1;

	ASSERT(cdata != NULL);
	ASSERT(mp != NULL);
	ASSERT(hmac != NULL);

	bzero(&dd, sizeof (dd));
	dd.cd_format = CRYPTO_DATA_MBLK;
	dd.cd_offset = 0;
	dd.cd_length = length;
	dd.cd_mp = mp;

	v1.iov_base = hmac;
	v1.iov_len = hmaclen;

	mac.cd_format = CRYPTO_DATA_RAW;
	mac.cd_offset = 0;
	mac.cd_length = hmaclen;
	mac.cd_raw = v1;

	/*
	 * cdata->block holds the IVEC
	 */
	encr_mech.cm_type = cdata->mech_type;
	encr_mech.cm_param = cdata->block;

	if (cdata->block != NULL)
		encr_mech.cm_param_len = cdata->blocklen;
	else
		encr_mech.cm_param_len = 0;

	rv = crypto_decrypt(&encr_mech, &dd, &cdata->d_encr_key,
			cdata->enc_tmpl, NULL, NULL);
	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_decrypt failed: %0x", rv);
		return (rv);
	}

	mac_mech.cm_type = sha1_hmac_mech;
	mac_mech.cm_param = NULL;
	mac_mech.cm_param_len = 0;

	/*
	 * Compute MAC of the plaintext decrypted above.
	 */
	rv = crypto_mac(&mac_mech, &dd, &cdata->d_hmac_key,
			cdata->hmac_tmpl, &mac, NULL);

	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_mac failed: %0x", rv);
	}

	return (rv);
}

/*
 * Compute 3-DES crypto and HMAC.
 */
static int
kef_encr_hmac(struct cipher_data_t *cdata,
	mblk_t *mp, int length,
	char *hmac, int hmaclen)
{
	int rv = CRYPTO_FAILED;

	crypto_mechanism_t encr_mech;
	crypto_mechanism_t mac_mech;
	crypto_data_t dd;
	crypto_data_t mac;
	iovec_t v1;

	ASSERT(cdata != NULL);
	ASSERT(mp != NULL);
	ASSERT(hmac != NULL);

	bzero(&dd, sizeof (dd));
	dd.cd_format = CRYPTO_DATA_MBLK;
	dd.cd_offset = 0;
	dd.cd_length = length;
	dd.cd_mp = mp;

	v1.iov_base = hmac;
	v1.iov_len = hmaclen;

	mac.cd_format = CRYPTO_DATA_RAW;
	mac.cd_offset = 0;
	mac.cd_length = hmaclen;
	mac.cd_raw = v1;

	/*
	 * cdata->block holds the IVEC
	 */
	encr_mech.cm_type = cdata->mech_type;
	encr_mech.cm_param = cdata->block;

	if (cdata->block != NULL)
		encr_mech.cm_param_len = cdata->blocklen;
	else
		encr_mech.cm_param_len = 0;

	mac_mech.cm_type = sha1_hmac_mech;
	mac_mech.cm_param = NULL;
	mac_mech.cm_param_len = 0;

	rv = crypto_mac(&mac_mech, &dd, &cdata->d_hmac_key,
			cdata->hmac_tmpl, &mac, NULL);

	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_mac failed: %0x", rv);
		return (rv);
	}

	rv = crypto_encrypt(&encr_mech, &dd, &cdata->d_encr_key,
			cdata->enc_tmpl, NULL, NULL);
	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_encrypt failed: %0x", rv);
	}

	return (rv);
}

/*
 * kef_crypt
 *
 * Use the Kernel encryption framework to provide the
 * crypto operations for the indicated data.
 */
static int
kef_crypt(struct cipher_data_t *cdata,
	void *indata, crypto_data_format_t fmt,
	size_t length, int mode)
{
	int rv = CRYPTO_FAILED;

	crypto_mechanism_t mech;
	crypto_key_t crkey;
	iovec_t v1;
	crypto_data_t d1;

	ASSERT(cdata != NULL);
	ASSERT(indata != NULL);
	ASSERT(fmt == CRYPTO_DATA_RAW || fmt == CRYPTO_DATA_MBLK);

	bzero(&crkey, sizeof (crkey));
	bzero(&d1, sizeof (d1));

	crkey.ck_format = CRYPTO_KEY_RAW;
	crkey.ck_data =  cdata->key;

	/* keys are measured in bits, not bytes, so multiply by 8 */
	crkey.ck_length = cdata->keylen * 8;

	if (fmt == CRYPTO_DATA_RAW) {
		v1.iov_base = (char *)indata;
		v1.iov_len = length;
	}

	d1.cd_format = fmt;
	d1.cd_offset = 0;
	d1.cd_length = length;
	if (fmt == CRYPTO_DATA_RAW)
		d1.cd_raw = v1;
	else if (fmt == CRYPTO_DATA_MBLK)
		d1.cd_mp = (mblk_t *)indata;

	mech.cm_type = cdata->mech_type;
	mech.cm_param = cdata->block;
	/*
	 * cdata->block holds the IVEC
	 */
	if (cdata->block != NULL)
		mech.cm_param_len = cdata->blocklen;
	else
		mech.cm_param_len = 0;

	/*
	 * encrypt and decrypt in-place
	 */
	if (mode == CRYPT_ENCRYPT)
		rv = crypto_encrypt(&mech, &d1, &crkey, NULL, NULL, NULL);
	else
		rv = crypto_decrypt(&mech, &d1, &crkey, NULL, NULL, NULL);

	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "%s returned error %08x",
			(mode == CRYPT_ENCRYPT ? "crypto_encrypt" :
				"crypto_decrypt"), rv);
		return (CRYPTO_FAILED);
	}

	return (rv);
}

static int
do_hmac(crypto_mech_type_t mech,
	crypto_key_t *key,
	char *data, int datalen,
	char *hmac, int hmaclen)
{
	int rv = 0;
	crypto_mechanism_t mac_mech;
	crypto_data_t dd;
	crypto_data_t mac;
	iovec_t vdata, vmac;

	mac_mech.cm_type = mech;
	mac_mech.cm_param = NULL;
	mac_mech.cm_param_len = 0;

	vdata.iov_base = data;
	vdata.iov_len = datalen;

	bzero(&dd, sizeof (dd));
	dd.cd_format = CRYPTO_DATA_RAW;
	dd.cd_offset = 0;
	dd.cd_length = datalen;
	dd.cd_raw = vdata;

	vmac.iov_base = hmac;
	vmac.iov_len = hmaclen;

	mac.cd_format = CRYPTO_DATA_RAW;
	mac.cd_offset = 0;
	mac.cd_length = hmaclen;
	mac.cd_raw = vmac;

	/*
	 * Compute MAC of the plaintext decrypted above.
	 */
	rv = crypto_mac(&mac_mech, &dd, key, NULL, &mac, NULL);

	if (rv != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_mac failed: %0x", rv);
	}

	return (rv);
}

#define	XOR_BLOCK(src, dst) \
	(dst)[0] ^= (src)[0]; \
	(dst)[1] ^= (src)[1]; \
	(dst)[2] ^= (src)[2]; \
	(dst)[3] ^= (src)[3]; \
	(dst)[4] ^= (src)[4]; \
	(dst)[5] ^= (src)[5]; \
	(dst)[6] ^= (src)[6]; \
	(dst)[7] ^= (src)[7]; \
	(dst)[8] ^= (src)[8]; \
	(dst)[9] ^= (src)[9]; \
	(dst)[10] ^= (src)[10]; \
	(dst)[11] ^= (src)[11]; \
	(dst)[12] ^= (src)[12]; \
	(dst)[13] ^= (src)[13]; \
	(dst)[14] ^= (src)[14]; \
	(dst)[15] ^= (src)[15]

#define	xorblock(x, y) XOR_BLOCK(y, x)

static int
aes_cbc_cts_encrypt(struct tmodinfo *tmi, uchar_t *plain, size_t length)
{
	int result = CRYPTO_SUCCESS;
	unsigned char tmp[DEFAULT_AES_BLOCKLEN];
	unsigned char tmp2[DEFAULT_AES_BLOCKLEN];
	unsigned char tmp3[DEFAULT_AES_BLOCKLEN];
	int nblocks = 0, blockno;
	crypto_data_t ct, pt;
	crypto_mechanism_t mech;

	mech.cm_type = tmi->enc_data.mech_type;
	if (tmi->enc_data.ivlen > 0 && tmi->enc_data.ivec != NULL) {
		bcopy(tmi->enc_data.ivec, tmp, DEFAULT_AES_BLOCKLEN);
	} else {
		bzero(tmp, sizeof (tmp));
	}
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	nblocks = (length + DEFAULT_AES_BLOCKLEN - 1) / DEFAULT_AES_BLOCKLEN;

	bzero(&ct, sizeof (crypto_data_t));
	bzero(&pt, sizeof (crypto_data_t));

	if (nblocks == 1) {
		pt.cd_format = CRYPTO_DATA_RAW;
		pt.cd_length = length;
		pt.cd_raw.iov_base = (char *)plain;
		pt.cd_raw.iov_len = length;

		result = crypto_encrypt(&mech, &pt,
			&tmi->enc_data.d_encr_key, NULL, NULL, NULL);

		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "aes_cbc_cts_encrypt: "
				"crypto_encrypt failed: %0x", result);
		}
	} else {
		size_t nleft;

		ct.cd_format = CRYPTO_DATA_RAW;
		ct.cd_offset = 0;
		ct.cd_length = DEFAULT_AES_BLOCKLEN;

		pt.cd_format = CRYPTO_DATA_RAW;
		pt.cd_offset = 0;
		pt.cd_length = DEFAULT_AES_BLOCKLEN;

		result = crypto_encrypt_init(&mech,
				&tmi->enc_data.d_encr_key,
				tmi->enc_data.enc_tmpl,
				&tmi->enc_data.ctx, NULL);

		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "aes_cbc_cts_encrypt: "
				"crypto_encrypt_init failed: %0x", result);
			goto cleanup;
		}

		for (blockno = 0; blockno < nblocks - 2; blockno++) {
			xorblock(tmp, plain + blockno * DEFAULT_AES_BLOCKLEN);

			pt.cd_raw.iov_base = (char *)tmp;
			pt.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

			ct.cd_raw.iov_base = (char *)plain +
				blockno * DEFAULT_AES_BLOCKLEN;
			ct.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

			result = crypto_encrypt_update(tmi->enc_data.ctx,
					&pt, &ct, NULL);

			if (result != CRYPTO_SUCCESS) {
				cmn_err(CE_WARN, "aes_cbc_cts_encrypt: "
					"crypto_encrypt_update failed: %0x",
					result);
				goto cleanup;
			}
			/* copy result over original bytes */
			/* make another copy for the next XOR step */
			bcopy(plain + blockno * DEFAULT_AES_BLOCKLEN,
				tmp, DEFAULT_AES_BLOCKLEN);
		}
		/* XOR cipher text from n-3 with plain text from n-2 */
		xorblock(tmp, plain + (nblocks - 2) * DEFAULT_AES_BLOCKLEN);

		pt.cd_raw.iov_base = (char *)tmp;
		pt.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

		ct.cd_raw.iov_base = (char *)tmp2;
		ct.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

		/* encrypt XOR-ed block N-2 */
		result = crypto_encrypt_update(tmi->enc_data.ctx,
				&pt, &ct, NULL);
		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "aes_cbc_cts_encrypt: "
				"crypto_encrypt_update(2) failed: %0x",
				result);
			goto cleanup;
		}
		nleft = length - (nblocks - 1) * DEFAULT_AES_BLOCKLEN;

		bzero(tmp3, sizeof (tmp3));
		/* Save final plaintext bytes from n-1 */
		bcopy(plain + (nblocks - 1) * DEFAULT_AES_BLOCKLEN, tmp3,
			nleft);

		/* Overwrite n-1 with cipher text from n-2 */
		bcopy(tmp2, plain + (nblocks - 1) * DEFAULT_AES_BLOCKLEN,
			nleft);

		bcopy(tmp2, tmp, DEFAULT_AES_BLOCKLEN);
		/* XOR cipher text from n-1 with plain text from n-1 */
		xorblock(tmp, tmp3);

		pt.cd_raw.iov_base = (char *)tmp;
		pt.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

		ct.cd_raw.iov_base = (char *)tmp2;
		ct.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

		/* encrypt block N-2 */
		result = crypto_encrypt_update(tmi->enc_data.ctx,
			&pt, &ct, NULL);

		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "aes_cbc_cts_encrypt: "
				"crypto_encrypt_update(3) failed: %0x",
				result);
			goto cleanup;
		}

		bcopy(tmp2, plain + (nblocks - 2) * DEFAULT_AES_BLOCKLEN,
			DEFAULT_AES_BLOCKLEN);


		ct.cd_raw.iov_base = (char *)tmp2;
		ct.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

		/*
		 * Ignore the output on the final step.
		 */
		result = crypto_encrypt_final(tmi->enc_data.ctx, &ct, NULL);
		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "aes_cbc_cts_encrypt: "
				"crypto_encrypt_final(3) failed: %0x",
				result);
		}
		tmi->enc_data.ctx = NULL;
	}
cleanup:
	bzero(tmp, sizeof (tmp));
	bzero(tmp2, sizeof (tmp));
	bzero(tmp3, sizeof (tmp));
	bzero(tmi->enc_data.block, tmi->enc_data.blocklen);
	return (result);
}

static int
aes_cbc_cts_decrypt(struct tmodinfo *tmi, uchar_t *buff, size_t length)
{
	int result = CRYPTO_SUCCESS;
	unsigned char tmp[DEFAULT_AES_BLOCKLEN];
	unsigned char tmp2[DEFAULT_AES_BLOCKLEN];
	unsigned char tmp3[DEFAULT_AES_BLOCKLEN];
	int nblocks = 0, blockno;
	crypto_data_t ct, pt;
	crypto_mechanism_t mech;

	mech.cm_type = tmi->enc_data.mech_type;

	if (tmi->dec_data.ivec_usage != IVEC_NEVER &&
	    tmi->dec_data.ivlen > 0 && tmi->dec_data.ivec != NULL) {
		bcopy(tmi->dec_data.ivec, tmp, DEFAULT_AES_BLOCKLEN);
	} else {
		bzero(tmp, sizeof (tmp));
	}
	mech.cm_param_len = 0;
	mech.cm_param = NULL;

	nblocks = (length + DEFAULT_AES_BLOCKLEN - 1) / DEFAULT_AES_BLOCKLEN;

	bzero(&pt, sizeof (pt));
	bzero(&ct, sizeof (ct));

	if (nblocks == 1) {
		ct.cd_format = CRYPTO_DATA_RAW;
		ct.cd_length = length;
		ct.cd_raw.iov_base = (char *)buff;
		ct.cd_raw.iov_len = length;

		result = crypto_decrypt(&mech, &ct,
			&tmi->dec_data.d_encr_key, NULL, NULL, NULL);

		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "aes_cbc_cts_decrypt: "
				"crypto_decrypt failed: %0x", result);
			goto cleanup;
		}
	} else {
		ct.cd_format = CRYPTO_DATA_RAW;
		ct.cd_offset = 0;
		ct.cd_length = DEFAULT_AES_BLOCKLEN;

		pt.cd_format = CRYPTO_DATA_RAW;
		pt.cd_offset = 0;
		pt.cd_length = DEFAULT_AES_BLOCKLEN;

		result = crypto_decrypt_init(&mech,
				&tmi->dec_data.d_encr_key,
				tmi->dec_data.enc_tmpl,
				&tmi->dec_data.ctx, NULL);

		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "aes_cbc_cts_decrypt: "
				"crypto_decrypt_init failed: %0x", result);
			goto cleanup;
		}
		for (blockno = 0; blockno < nblocks - 2; blockno++) {
			ct.cd_raw.iov_base = (char *)buff +
				(blockno * DEFAULT_AES_BLOCKLEN);
			ct.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

			pt.cd_raw.iov_base = (char *)tmp2;
			pt.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

			/*
			 * Save the input to the decrypt so it can
			 * be used later for an XOR operation
			 */
			bcopy(buff + (blockno * DEFAULT_AES_BLOCKLEN),
				tmi->dec_data.block, DEFAULT_AES_BLOCKLEN);

			result = crypto_decrypt_update(tmi->dec_data.ctx,
					&ct, &pt, NULL);
			if (result != CRYPTO_SUCCESS) {
				cmn_err(CE_WARN, "aes_cbc_cts_decrypt: "
					"crypto_decrypt_update(1) error - "
					"result = 0x%08x", result);
				goto cleanup;
			}
			xorblock(tmp2, tmp);
			bcopy(tmp2, buff + blockno * DEFAULT_AES_BLOCKLEN,
				DEFAULT_AES_BLOCKLEN);
			/*
			 * The original cipher text is used as the xor
			 * for the next block, save it here.
			 */
			bcopy(tmi->dec_data.block, tmp, DEFAULT_AES_BLOCKLEN);
		}
		ct.cd_raw.iov_base = (char *)buff +
			((nblocks - 2) * DEFAULT_AES_BLOCKLEN);
		ct.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;
		pt.cd_raw.iov_base = (char *)tmp2;
		pt.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

		result = crypto_decrypt_update(tmi->dec_data.ctx,
				&ct, &pt, NULL);
		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN,
				"aes_cbc_cts_decrypt: "
				"crypto_decrypt_update(2) error -"
				" result = 0x%08x", result);
			goto cleanup;
		}
		bzero(tmp3, sizeof (tmp3));
		bcopy(buff + (nblocks - 1) * DEFAULT_AES_BLOCKLEN, tmp3,
			length - ((nblocks - 1) * DEFAULT_AES_BLOCKLEN));

		xorblock(tmp2, tmp3);
		bcopy(tmp2, buff + (nblocks - 1) * DEFAULT_AES_BLOCKLEN,
			length - ((nblocks - 1) * DEFAULT_AES_BLOCKLEN));

		/* 2nd to last block ... */
		bcopy(tmp3, tmp2,
			length - ((nblocks - 1) * DEFAULT_AES_BLOCKLEN));

		ct.cd_raw.iov_base = (char *)tmp2;
		ct.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;
		pt.cd_raw.iov_base = (char *)tmp3;
		pt.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;

		result = crypto_decrypt_update(tmi->dec_data.ctx,
				&ct, &pt, NULL);
		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN,
				"aes_cbc_cts_decrypt: "
				"crypto_decrypt_update(3) error - "
				"result = 0x%08x", result);
			goto cleanup;
		}
		xorblock(tmp3, tmp);


		/* Finally, update the 2nd to last block and we are done. */
		bcopy(tmp3, buff + (nblocks - 2) * DEFAULT_AES_BLOCKLEN,
			DEFAULT_AES_BLOCKLEN);

		/* Do Final step, but ignore output */
		pt.cd_raw.iov_base = (char *)tmp2;
		pt.cd_raw.iov_len = DEFAULT_AES_BLOCKLEN;
		result = crypto_decrypt_final(tmi->dec_data.ctx, &pt, NULL);
		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "aes_cbc_cts_decrypt: "
				"crypto_decrypt_final error - "
				"result = 0x%0x", result);
		}
		tmi->dec_data.ctx = NULL;
	}

cleanup:
	bzero(tmp, sizeof (tmp));
	bzero(tmp2, sizeof (tmp));
	bzero(tmp3, sizeof (tmp));
	bzero(tmi->dec_data.block, tmi->dec_data.blocklen);
	return (result);
}

/*
 * AES decrypt
 *
 * format of ciphertext when using AES
 *  +-------------+------------+------------+
 *  |  confounder | msg-data   |  hmac      |
 *  +-------------+------------+------------+
 */
static mblk_t *
aes_decrypt(queue_t *q, struct tmodinfo *tmi, mblk_t *mp,
	hash_info_t *hash)
{
	int result;
	size_t enclen;
	size_t inlen;
	uchar_t hmacbuff[64];
	uchar_t tmpiv[DEFAULT_AES_BLOCKLEN];

	inlen = (size_t)MBLKL(mp);

	enclen = inlen - AES_TRUNCATED_HMAC_LEN;
	if (tmi->dec_data.ivec_usage != IVEC_NEVER &&
		tmi->dec_data.ivec != NULL && tmi->dec_data.ivlen > 0) {
		int nblocks = (enclen + DEFAULT_AES_BLOCKLEN - 1) /
				DEFAULT_AES_BLOCKLEN;
		bcopy(mp->b_rptr + DEFAULT_AES_BLOCKLEN * (nblocks - 2),
			tmpiv, DEFAULT_AES_BLOCKLEN);
	}

	/* AES Decrypt */
	result = aes_cbc_cts_decrypt(tmi, mp->b_rptr, enclen);

	if (result != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
			"aes_decrypt:  aes_cbc_cts_decrypt "
			"failed - error %0x", result);
		goto cleanup;
	}

	/* Verify the HMAC */
	result = do_hmac(sha1_hmac_mech,
			&tmi->dec_data.d_hmac_key,
			(char *)mp->b_rptr, enclen,
			(char *)hmacbuff, hash->hash_len);

	if (result != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
			"aes_decrypt:  do_hmac failed - error %0x", result);
		goto cleanup;
	}

	if (bcmp(hmacbuff, mp->b_rptr + enclen,
		AES_TRUNCATED_HMAC_LEN) != 0) {
		result = -1;
		cmn_err(CE_WARN, "aes_decrypt: checksum verification failed");
		goto cleanup;
	}

	/* truncate the mblk at the end of the decrypted text */
	mp->b_wptr = mp->b_rptr + enclen;

	/* Adjust the beginning of the buffer to skip the confounder */
	mp->b_rptr += DEFAULT_AES_BLOCKLEN;

	if (tmi->dec_data.ivec_usage != IVEC_NEVER &&
		tmi->dec_data.ivec != NULL && tmi->dec_data.ivlen > 0)
		bcopy(tmpiv, tmi->dec_data.ivec, DEFAULT_AES_BLOCKLEN);

cleanup:
	if (result != CRYPTO_SUCCESS) {
		mp->b_datap->db_type = M_ERROR;
		mp->b_rptr = mp->b_datap->db_base;
		*mp->b_rptr = EIO;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
		qreply(WR(q), mp);
		return (NULL);
	}
	return (mp);
}

/*
 * AES encrypt
 *
 * format of ciphertext when using AES
 *  +-------------+------------+------------+
 *  |  confounder | msg-data   |  hmac      |
 *  +-------------+------------+------------+
 */
static mblk_t *
aes_encrypt(queue_t *q, struct tmodinfo *tmi, mblk_t *mp,
	hash_info_t *hash)
{
	int result;
	size_t cipherlen;
	size_t inlen;
	uchar_t hmacbuff[64];

	inlen = (size_t)MBLKL(mp);

	cipherlen = encrypt_size(&tmi->enc_data, inlen);

	ASSERT(MBLKSIZE(mp) >= cipherlen);

	/*
	 * Shift the rptr back enough to insert the confounder.
	 */
	mp->b_rptr -= DEFAULT_AES_BLOCKLEN;

	/* Get random data for confounder */
	(void) random_get_pseudo_bytes((uint8_t *)mp->b_rptr,
		DEFAULT_AES_BLOCKLEN);

	/*
	 * Because we encrypt in-place, we need to calculate
	 * the HMAC of the plaintext now, then stick it on
	 * the end of the ciphertext down below.
	 */
	result = do_hmac(sha1_hmac_mech,
			&tmi->enc_data.d_hmac_key,
			(char *)mp->b_rptr, DEFAULT_AES_BLOCKLEN + inlen,
			(char *)hmacbuff, hash->hash_len);

	if (result != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "aes_encrypt:  do_hmac failed - error %0x",
			result);
		goto cleanup;
	}
	/* Encrypt using AES-CBC-CTS */
	result = aes_cbc_cts_encrypt(tmi, mp->b_rptr,
		inlen + DEFAULT_AES_BLOCKLEN);

	if (result != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "aes_encrypt:  aes_cbc_cts_encrypt "
			"failed - error %0x", result);
		goto cleanup;
	}

	/* copy the truncated HMAC to the end of the mblk */
	bcopy(hmacbuff, mp->b_rptr + DEFAULT_AES_BLOCKLEN + inlen,
		AES_TRUNCATED_HMAC_LEN);

	mp->b_wptr = mp->b_rptr + cipherlen;

	/*
	 * The final block of cipher text (not the HMAC) is used
	 * as the next IV.
	 */
	if (tmi->enc_data.ivec_usage != IVEC_NEVER &&
	    tmi->enc_data.ivec != NULL) {
		int nblocks = (inlen + 2 * DEFAULT_AES_BLOCKLEN - 1) /
			DEFAULT_AES_BLOCKLEN;

		bcopy(mp->b_rptr + (nblocks - 2) * DEFAULT_AES_BLOCKLEN,
			tmi->enc_data.ivec, DEFAULT_AES_BLOCKLEN);
	}

cleanup:
	if (result != CRYPTO_SUCCESS) {
		mp->b_datap->db_type = M_ERROR;
		mp->b_rptr = mp->b_datap->db_base;
		*mp->b_rptr = EIO;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
		qreply(WR(q), mp);
		return (NULL);
	}
	return (mp);
}

/*
 * ARCFOUR-HMAC-MD5 decrypt
 *
 * format of ciphertext when using ARCFOUR-HMAC-MD5
 *  +-----------+------------+------------+
 *  |  hmac     | confounder |  msg-data  |
 *  +-----------+------------+------------+
 *
 */
static mblk_t *
arcfour_hmac_md5_decrypt(queue_t *q, struct tmodinfo *tmi, mblk_t *mp,
			hash_info_t *hash)
{
	int result;
	size_t cipherlen;
	size_t inlen;
	size_t saltlen;
	crypto_key_t k1, k2;
	crypto_data_t indata;
	iovec_t v1;
	uchar_t ms_exp[9] = {0xab, 0xab, 0xab, 0xab, 0xab,
				0xab, 0xab, 0xab, 0xab };
	uchar_t k1data[CRYPT_ARCFOUR_KEYBYTES];
	uchar_t k2data[CRYPT_ARCFOUR_KEYBYTES];
	uchar_t cksum[MD5_HASHSIZE];
	uchar_t saltdata[CRYPT_ARCFOUR_KEYBYTES];
	crypto_mechanism_t mech;
	int usage;

	bzero(&indata, sizeof (indata));

	/* The usage constant is 1026 for all "old" rcmd mode operations */
	if (tmi->dec_data.option_mask & CRYPTOPT_RCMD_MODE_V1)
		usage = RCMDV1_USAGE;
	else
		usage = ARCFOUR_DECRYPT_USAGE;

	/*
	 * The size at this point should be the size of
	 * all the plaintext plus the optional plaintext length
	 * needed for RCMD V2 mode.  There should also be room
	 * at the head of the mblk for the confounder and hash info.
	 */
	inlen = (size_t)MBLKL(mp);

	/*
	 * The cipherlen does not include the HMAC at the
	 * head of the buffer.
	 */
	cipherlen = inlen - hash->hash_len;

	ASSERT(MBLKSIZE(mp) >= cipherlen);
	if (tmi->dec_data.method == CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP) {
		bcopy(ARCFOUR_EXP_SALT, saltdata, strlen(ARCFOUR_EXP_SALT));
		saltdata[9] = 0;
		saltdata[10] = usage & 0xff;
		saltdata[11] = (usage >> 8) & 0xff;
		saltdata[12] = (usage >> 16) & 0xff;
		saltdata[13] = (usage >> 24) & 0xff;
		saltlen = 14;
	} else {
		saltdata[0] = usage & 0xff;
		saltdata[1] = (usage >> 8) & 0xff;
		saltdata[2] = (usage >> 16) & 0xff;
		saltdata[3] = (usage >> 24) & 0xff;
		saltlen = 4;
	}
	/*
	 * Use the salt value to create a key to be used
	 * for subsequent HMAC operations.
	 */
	result = do_hmac(md5_hmac_mech,
			tmi->dec_data.ckey,
			(char *)saltdata, saltlen,
			(char *)k1data, sizeof (k1data));
	if (result != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
			"arcfour_hmac_md5_decrypt:  do_hmac(k1)"
			"failed - error %0x", result);
		goto cleanup;
	}
	bcopy(k1data, k2data, sizeof (k1data));

	/*
	 * For the neutered MS RC4 encryption type,
	 * set the trailing 9 bytes to 0xab per the
	 * RC4-HMAC spec.
	 */
	if (tmi->dec_data.method == CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP) {
		bcopy((void *)&k1data[7], ms_exp, sizeof (ms_exp));
	}

	mech.cm_type = tmi->dec_data.mech_type;
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/*
	 * If we have not yet initialized the decryption key,
	 * context, and template, do it now.
	 */
	if (tmi->dec_data.ctx == NULL ||
	    (tmi->dec_data.option_mask & CRYPTOPT_RCMD_MODE_V1)) {
		k1.ck_format = CRYPTO_KEY_RAW;
		k1.ck_length = CRYPT_ARCFOUR_KEYBYTES * 8;
		k1.ck_data = k1data;

		tmi->dec_data.d_encr_key.ck_format = CRYPTO_KEY_RAW;
		tmi->dec_data.d_encr_key.ck_length = k1.ck_length;
		if (tmi->dec_data.d_encr_key.ck_data == NULL)
			tmi->dec_data.d_encr_key.ck_data = kmem_zalloc(
				CRYPT_ARCFOUR_KEYBYTES, KM_SLEEP);

		/*
		 * HMAC operation creates the encryption
		 * key to be used for the decrypt operations.
		 */
		result = do_hmac(md5_hmac_mech, &k1,
			(char *)mp->b_rptr, hash->hash_len,
			(char *)tmi->dec_data.d_encr_key.ck_data,
			CRYPT_ARCFOUR_KEYBYTES);


		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN,
				"arcfour_hmac_md5_decrypt:  do_hmac(k3)"
				"failed - error %0x", result);
			goto cleanup;
		}
	}

	tmi->dec_data.enc_tmpl = NULL;

	if (tmi->dec_data.ctx == NULL &&
	    (tmi->dec_data.option_mask & CRYPTOPT_RCMD_MODE_V2)) {
		/*
		 * Only create a template if we are doing
		 * chaining from block to block.
		 */
		result = crypto_create_ctx_template(&mech,
			&tmi->dec_data.d_encr_key,
			&tmi->dec_data.enc_tmpl,
			KM_SLEEP);
		if (result == CRYPTO_NOT_SUPPORTED) {
			tmi->dec_data.enc_tmpl = NULL;
		} else if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN,
				"arcfour_hmac_md5_decrypt:  "
				"failed to create dec template "
				"for RC4 encrypt: %0x", result);
			goto cleanup;
		}

		result = crypto_decrypt_init(&mech,
			&tmi->dec_data.d_encr_key,
			tmi->dec_data.enc_tmpl,
			&tmi->dec_data.ctx, NULL);

		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "crypto_decrypt_init failed:"
				" %0x", result);
			goto cleanup;
		}
	}

	/* adjust the rptr so we don't decrypt the original hmac field */

	v1.iov_base = (char *)mp->b_rptr + hash->hash_len;
	v1.iov_len = cipherlen;

	indata.cd_format = CRYPTO_DATA_RAW;
	indata.cd_offset = 0;
	indata.cd_length = cipherlen;
	indata.cd_raw = v1;

	if (tmi->dec_data.option_mask & CRYPTOPT_RCMD_MODE_V2)
		result = crypto_decrypt_update(tmi->dec_data.ctx,
			&indata, NULL, NULL);
	else
		result = crypto_decrypt(&mech, &indata,
			&tmi->dec_data.d_encr_key, NULL, NULL, NULL);

	if (result != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_decrypt_update failed:"
			" %0x", result);
		goto cleanup;
	}

	k2.ck_format = CRYPTO_KEY_RAW;
	k2.ck_length = sizeof (k2data) * 8;
	k2.ck_data = k2data;

	result = do_hmac(md5_hmac_mech,
			&k2,
			(char *)mp->b_rptr + hash->hash_len, cipherlen,
			(char *)cksum, hash->hash_len);

	if (result != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
			"arcfour_hmac_md5_decrypt:  do_hmac(k2)"
			"failed - error %0x", result);
		goto cleanup;
	}

	if (bcmp(cksum, mp->b_rptr, hash->hash_len) != 0) {
		cmn_err(CE_WARN, "arcfour_decrypt HMAC comparison failed");
		result = -1;
		goto cleanup;
	}

	/*
	 * adjust the start of the mblk to skip over the
	 * hash and confounder.
	 */
	mp->b_rptr += hash->hash_len + hash->confound_len;

cleanup:
	bzero(k1data, sizeof (k1data));
	bzero(k2data, sizeof (k2data));
	bzero(cksum, sizeof (cksum));
	bzero(saltdata, sizeof (saltdata));
	if (result != CRYPTO_SUCCESS) {
		mp->b_datap->db_type = M_ERROR;
		mp->b_rptr = mp->b_datap->db_base;
		*mp->b_rptr = EIO;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
		qreply(WR(q), mp);
		return (NULL);
	}
	return (mp);
}

/*
 * ARCFOUR-HMAC-MD5 encrypt
 *
 * format of ciphertext when using ARCFOUR-HMAC-MD5
 *  +-----------+------------+------------+
 *  |  hmac     | confounder |  msg-data  |
 *  +-----------+------------+------------+
 *
 */
static mblk_t *
arcfour_hmac_md5_encrypt(queue_t *q, struct tmodinfo *tmi, mblk_t *mp,
			hash_info_t *hash)
{
	int result;
	size_t cipherlen;
	size_t inlen;
	size_t saltlen;
	crypto_key_t k1, k2;
	crypto_data_t indata;
	iovec_t v1;
	uchar_t ms_exp[9] = {0xab, 0xab, 0xab, 0xab, 0xab,
				0xab, 0xab, 0xab, 0xab };
	uchar_t k1data[CRYPT_ARCFOUR_KEYBYTES];
	uchar_t k2data[CRYPT_ARCFOUR_KEYBYTES];
	uchar_t saltdata[CRYPT_ARCFOUR_KEYBYTES];
	crypto_mechanism_t mech;
	int usage;

	bzero(&indata, sizeof (indata));

	/* The usage constant is 1026 for all "old" rcmd mode operations */
	if (tmi->enc_data.option_mask & CRYPTOPT_RCMD_MODE_V1)
		usage = RCMDV1_USAGE;
	else
		usage = ARCFOUR_ENCRYPT_USAGE;

	mech.cm_type = tmi->enc_data.mech_type;
	mech.cm_param = NULL;
	mech.cm_param_len = 0;

	/*
	 * The size at this point should be the size of
	 * all the plaintext plus the optional plaintext length
	 * needed for RCMD V2 mode.  There should also be room
	 * at the head of the mblk for the confounder and hash info.
	 */
	inlen = (size_t)MBLKL(mp);

	cipherlen = encrypt_size(&tmi->enc_data, inlen);

	ASSERT(MBLKSIZE(mp) >= cipherlen);

	/*
	 * Shift the rptr back enough to insert
	 * the confounder and hash.
	 */
	mp->b_rptr -= (hash->confound_len + hash->hash_len);

	/* zero out the hash area */
	bzero(mp->b_rptr, (size_t)hash->hash_len);

	if (cipherlen > inlen) {
		bzero(mp->b_wptr, MBLKTAIL(mp));
	}

	if (tmi->enc_data.method == CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP) {
		bcopy(ARCFOUR_EXP_SALT, saltdata, strlen(ARCFOUR_EXP_SALT));
		saltdata[9] = 0;
		saltdata[10] = usage & 0xff;
		saltdata[11] = (usage >> 8) & 0xff;
		saltdata[12] = (usage >> 16) & 0xff;
		saltdata[13] = (usage >> 24) & 0xff;
		saltlen = 14;
	} else {
		saltdata[0] = usage & 0xff;
		saltdata[1] = (usage >> 8) & 0xff;
		saltdata[2] = (usage >> 16) & 0xff;
		saltdata[3] = (usage >> 24) & 0xff;
		saltlen = 4;
	}
	/*
	 * Use the salt value to create a key to be used
	 * for subsequent HMAC operations.
	 */
	result = do_hmac(md5_hmac_mech,
			tmi->enc_data.ckey,
			(char *)saltdata, saltlen,
			(char *)k1data, sizeof (k1data));
	if (result != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
			"arcfour_hmac_md5_encrypt:  do_hmac(k1)"
			"failed - error %0x", result);
		goto cleanup;
	}

	bcopy(k1data, k2data, sizeof (k2data));

	/*
	 * For the neutered MS RC4 encryption type,
	 * set the trailing 9 bytes to 0xab per the
	 * RC4-HMAC spec.
	 */
	if (tmi->enc_data.method == CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP) {
		bcopy((void *)&k1data[7], ms_exp, sizeof (ms_exp));
	}

	/*
	 * Get the confounder bytes.
	 */
	(void) random_get_pseudo_bytes(
			(uint8_t *)(mp->b_rptr + hash->hash_len),
			(size_t)hash->confound_len);

	k2.ck_data = k2data;
	k2.ck_format = CRYPTO_KEY_RAW;
	k2.ck_length = sizeof (k2data) * 8;

	/*
	 * This writes the HMAC to the hash area in the
	 * mblk.  The key used is the one just created by
	 * the previous HMAC operation.
	 * The data being processed is the confounder bytes
	 * PLUS the input plaintext.
	 */
	result = do_hmac(md5_hmac_mech, &k2,
			(char *)mp->b_rptr + hash->hash_len,
			hash->confound_len + inlen,
			(char *)mp->b_rptr, hash->hash_len);
	if (result != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
			"arcfour_hmac_md5_encrypt:  do_hmac(k2)"
			"failed - error %0x", result);
		goto cleanup;
	}
	/*
	 * Because of the odd way that MIT uses RC4 keys
	 * on the rlogin stream, we only need to create
	 * this key once.
	 * However, if using "old" rcmd mode, we need to do
	 * it every time.
	 */
	if (tmi->enc_data.ctx == NULL ||
	    (tmi->enc_data.option_mask & CRYPTOPT_RCMD_MODE_V1)) {
		crypto_key_t *key = &tmi->enc_data.d_encr_key;

		k1.ck_data = k1data;
		k1.ck_format = CRYPTO_KEY_RAW;
		k1.ck_length = sizeof (k1data) * 8;

		key->ck_format = CRYPTO_KEY_RAW;
		key->ck_length = k1.ck_length;
		if (key->ck_data == NULL)
			key->ck_data = kmem_zalloc(
				CRYPT_ARCFOUR_KEYBYTES, KM_SLEEP);

		/*
		 * The final HMAC operation creates the encryption
		 * key to be used for the encrypt operation.
		 */
		result = do_hmac(md5_hmac_mech, &k1,
			(char *)mp->b_rptr, hash->hash_len,
			(char *)key->ck_data, CRYPT_ARCFOUR_KEYBYTES);

		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN,
				"arcfour_hmac_md5_encrypt:  do_hmac(k3)"
				"failed - error %0x", result);
			goto cleanup;
		}
	}

	/*
	 * If the context has not been initialized, do it now.
	 */
	if (tmi->enc_data.ctx == NULL &&
	    (tmi->enc_data.option_mask & CRYPTOPT_RCMD_MODE_V2)) {
		/*
		 * Only create a template if we are doing
		 * chaining from block to block.
		 */
		result = crypto_create_ctx_template(&mech,
				&tmi->enc_data.d_encr_key,
				&tmi->enc_data.enc_tmpl,
				KM_SLEEP);
		if (result == CRYPTO_NOT_SUPPORTED) {
			tmi->enc_data.enc_tmpl = NULL;
		} else if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "failed to create enc template "
				"for RC4 encrypt: %0x", result);
			goto cleanup;
		}

		result = crypto_encrypt_init(&mech,
					&tmi->enc_data.d_encr_key,
					tmi->enc_data.enc_tmpl,
					&tmi->enc_data.ctx, NULL);
		if (result != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "crypto_encrypt_init failed:"
				" %0x", result);
			goto cleanup;
		}
	}
	v1.iov_base = (char *)mp->b_rptr + hash->hash_len;
	v1.iov_len = hash->confound_len + inlen;

	indata.cd_format = CRYPTO_DATA_RAW;
	indata.cd_offset = 0;
	indata.cd_length = hash->confound_len + inlen;
	indata.cd_raw = v1;

	if (tmi->enc_data.option_mask & CRYPTOPT_RCMD_MODE_V2)
		result = crypto_encrypt_update(tmi->enc_data.ctx,
			&indata, NULL, NULL);
	else
		result = crypto_encrypt(&mech, &indata,
			&tmi->enc_data.d_encr_key, NULL,
			NULL, NULL);

	if (result != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN, "crypto_encrypt_update failed: 0x%0x",
			result);
	}

cleanup:
	bzero(k1data, sizeof (k1data));
	bzero(k2data, sizeof (k2data));
	bzero(saltdata, sizeof (saltdata));
	if (result != CRYPTO_SUCCESS) {
		mp->b_datap->db_type = M_ERROR;
		mp->b_rptr = mp->b_datap->db_base;
		*mp->b_rptr = EIO;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
		qreply(WR(q), mp);
		return (NULL);
	}
	return (mp);
}

/*
 * DES-CBC-[HASH] encrypt
 *
 * Needed to support userland apps that must support Kerberos V5
 * encryption DES-CBC encryption modes.
 *
 * The HASH values supported are RAW(NULL), MD5, CRC32, and SHA1
 *
 * format of ciphertext for DES-CBC functions, per RFC1510 is:
 *  +-----------+----------+-------------+-----+
 *  |confounder |  cksum   |   msg-data  | pad |
 *  +-----------+----------+-------------+-----+
 *
 * format of ciphertext when using DES3-SHA1-HMAC
 *  +-----------+----------+-------------+-----+
 *  |confounder |  msg-data  |   hmac    | pad |
 *  +-----------+----------+-------------+-----+
 *
 *  The confounder is 8 bytes of random data.
 *  The cksum depends on the hash being used.
 *   4 bytes for CRC32
 *  16 bytes for MD5
 *  20 bytes for SHA1
 *   0 bytes for RAW
 *
 */
static mblk_t *
des_cbc_encrypt(queue_t *q, struct tmodinfo *tmi, mblk_t *mp, hash_info_t *hash)
{
	int result;
	size_t cipherlen;
	size_t inlen;
	size_t plainlen;

	/*
	 * The size at this point should be the size of
	 * all the plaintext plus the optional plaintext length
	 * needed for RCMD V2 mode.  There should also be room
	 * at the head of the mblk for the confounder and hash info.
	 */
	inlen = (size_t)MBLKL(mp);

	/*
	 * The output size will be a multiple of 8 because this algorithm
	 * only works on 8 byte chunks.
	 */
	cipherlen = encrypt_size(&tmi->enc_data, inlen);

	ASSERT(MBLKSIZE(mp) >= cipherlen);

	if (cipherlen > inlen) {
		bzero(mp->b_wptr, MBLKTAIL(mp));
	}

	/*
	 * Shift the rptr back enough to insert
	 * the confounder and hash.
	 */
	if (tmi->enc_data.method == CRYPT_METHOD_DES3_CBC_SHA1) {
		mp->b_rptr -= hash->confound_len;
	} else {
		mp->b_rptr -= (hash->confound_len + hash->hash_len);

		/* zero out the hash area */
		bzero(mp->b_rptr + hash->confound_len, (size_t)hash->hash_len);
	}

	/* get random confounder from our friend, the 'random' module */
	if (hash->confound_len > 0) {
		(void) random_get_pseudo_bytes((uint8_t *)mp->b_rptr,
				    (size_t)hash->confound_len);
	}

	/*
	 * For 3DES we calculate an HMAC later.
	 */
	if (tmi->enc_data.method != CRYPT_METHOD_DES3_CBC_SHA1) {
		/* calculate chksum of confounder + input */
		if (hash->hash_len > 0 && hash->hashfunc != NULL) {
			uchar_t cksum[MAX_CKSUM_LEN];

			result = hash->hashfunc(cksum, mp->b_rptr,
				cipherlen);
			if (result != CRYPTO_SUCCESS) {
				goto failure;
			}

			/* put hash in place right after the confounder */
			bcopy(cksum, (mp->b_rptr + hash->confound_len),
			    (size_t)hash->hash_len);
		}
	}
	/*
	 * In order to support the "old" Kerberos RCMD protocol,
	 * we must use the IVEC 3 different ways:
	 *   IVEC_REUSE = keep using the same IV each time, this is
	 *		ugly and insecure, but necessary for
	 *		backwards compatibility with existing MIT code.
	 *   IVEC_ONETIME = Use the ivec as initialized when the crypto
	 *		was setup (see setup_crypto routine).
	 *   IVEC_NEVER = never use an IVEC, use a bunch of 0's as the IV (yuk).
	 */
	if (tmi->enc_data.ivec_usage == IVEC_NEVER) {
		bzero(tmi->enc_data.block, tmi->enc_data.blocklen);
	} else if (tmi->enc_data.ivec_usage == IVEC_REUSE) {
		bcopy(tmi->enc_data.ivec, tmi->enc_data.block,
		    tmi->enc_data.blocklen);
	}

	if (tmi->enc_data.method == CRYPT_METHOD_DES3_CBC_SHA1) {
		/*
		 * The input length already included the hash size,
		 * don't include this in the plaintext length
		 * calculations.
		 */
		plainlen = cipherlen - hash->hash_len;

		mp->b_wptr = mp->b_rptr + plainlen;

		result = kef_encr_hmac(&tmi->enc_data,
			(void *)mp, (size_t)plainlen,
			(char *)(mp->b_rptr + plainlen),
			hash->hash_len);
	} else {
		ASSERT(mp->b_rptr + cipherlen <= DB_LIM(mp));
		mp->b_wptr = mp->b_rptr + cipherlen;
		result = kef_crypt(&tmi->enc_data, (void *)mp,
			CRYPTO_DATA_MBLK, (size_t)cipherlen,
			CRYPT_ENCRYPT);
	}
failure:
	if (result != CRYPTO_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN,
			"des_cbc_encrypt: kef_crypt encrypt "
			"failed (len: %ld) - error %0x",
			cipherlen, result);
#endif
		mp->b_datap->db_type = M_ERROR;
		mp->b_rptr = mp->b_datap->db_base;
		*mp->b_rptr = EIO;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
		qreply(WR(q), mp);
		return (NULL);
	} else if (tmi->enc_data.ivec_usage == IVEC_ONETIME) {
		/*
		 * Because we are using KEF, we must manually
		 * update our IV.
		 */
		bcopy(mp->b_wptr - tmi->enc_data.ivlen,
			tmi->enc_data.block, tmi->enc_data.ivlen);
	}
	if (tmi->enc_data.method == CRYPT_METHOD_DES3_CBC_SHA1) {
		mp->b_wptr = mp->b_rptr + cipherlen;
	}

	return (mp);
}

/*
 * des_cbc_decrypt
 *
 *
 * Needed to support userland apps that must support Kerberos V5
 * encryption DES-CBC decryption modes.
 *
 * The HASH values supported are RAW(NULL), MD5, CRC32, and SHA1
 *
 * format of ciphertext for DES-CBC functions, per RFC1510 is:
 *  +-----------+----------+-------------+-----+
 *  |confounder |  cksum   |   msg-data  | pad |
 *  +-----------+----------+-------------+-----+
 *
 * format of ciphertext when using DES3-SHA1-HMAC
 *  +-----------+----------+-------------+-----+
 *  |confounder |  msg-data  |   hmac    | pad |
 *  +-----------+----------+-------------+-----+
 *
 *  The confounder is 8 bytes of random data.
 *  The cksum depends on the hash being used.
 *   4 bytes for CRC32
 *  16 bytes for MD5
 *  20 bytes for SHA1
 *   0 bytes for RAW
 *
 */
static mblk_t *
des_cbc_decrypt(queue_t *q, struct tmodinfo *tmi, mblk_t *mp, hash_info_t *hash)
{
	uint_t inlen, datalen;
	int result = 0;
	uchar_t *optr = NULL;
	uchar_t cksum[MAX_CKSUM_LEN], newcksum[MAX_CKSUM_LEN];
	uchar_t nextiv[DEFAULT_DES_BLOCKLEN];

	/* Compute adjusted size */
	inlen = MBLKL(mp);

	optr = mp->b_rptr;

	/*
	 * In order to support the "old" Kerberos RCMD protocol,
	 * we must use the IVEC 3 different ways:
	 *   IVEC_REUSE = keep using the same IV each time, this is
	 *		ugly and insecure, but necessary for
	 *		backwards compatibility with existing MIT code.
	 *   IVEC_ONETIME = Use the ivec as initialized when the crypto
	 *		was setup (see setup_crypto routine).
	 *   IVEC_NEVER = never use an IVEC, use a bunch of 0's as the IV (yuk).
	 */
	if (tmi->dec_data.ivec_usage == IVEC_NEVER)
		bzero(tmi->dec_data.block, tmi->dec_data.blocklen);
	else if (tmi->dec_data.ivec_usage == IVEC_REUSE)
		bcopy(tmi->dec_data.ivec, tmi->dec_data.block,
		    tmi->dec_data.blocklen);

	if (tmi->dec_data.method == CRYPT_METHOD_DES3_CBC_SHA1) {
		/*
		 * Do not decrypt the HMAC at the end
		 */
		int decrypt_len = inlen - hash->hash_len;

		/*
		 * Move the wptr so the mblk appears to end
		 * BEFORE the HMAC section.
		 */
		mp->b_wptr = mp->b_rptr + decrypt_len;

		/*
		 * Because we are using KEF, we must manually update our
		 * IV.
		 */
		if (tmi->dec_data.ivec_usage == IVEC_ONETIME) {
			bcopy(mp->b_rptr + decrypt_len - tmi->dec_data.ivlen,
				nextiv, tmi->dec_data.ivlen);
		}

		result = kef_decr_hmac(&tmi->dec_data, mp, decrypt_len,
			(char *)newcksum, hash->hash_len);
	} else {
		/*
		 * Because we are using KEF, we must manually update our
		 * IV.
		 */
		if (tmi->dec_data.ivec_usage == IVEC_ONETIME) {
			bcopy(mp->b_wptr - tmi->enc_data.ivlen, nextiv,
				tmi->dec_data.ivlen);
		}
		result = kef_crypt(&tmi->dec_data, (void *)mp,
			CRYPTO_DATA_MBLK, (size_t)inlen, CRYPT_DECRYPT);
	}
	if (result != CRYPTO_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN,
			"des_cbc_decrypt: kef_crypt decrypt "
			"failed - error %0x", result);
#endif
		mp->b_datap->db_type = M_ERROR;
		mp->b_rptr = mp->b_datap->db_base;
		*mp->b_rptr = EIO;
		mp->b_wptr = mp->b_rptr + sizeof (char);
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
		qreply(WR(q), mp);
		return (NULL);
	}

	/*
	 * Manually update the IV, KEF does not track this for us.
	 */
	if (tmi->dec_data.ivec_usage == IVEC_ONETIME) {
		bcopy(nextiv, tmi->dec_data.block, tmi->dec_data.ivlen);
	}

	/* Verify the checksum(if necessary) */
	if (hash->hash_len > 0) {
		if (tmi->dec_data.method == CRYPT_METHOD_DES3_CBC_SHA1) {
			bcopy(mp->b_rptr + inlen - hash->hash_len, cksum,
				hash->hash_len);
		} else {
			bcopy(optr + hash->confound_len, cksum, hash->hash_len);

			/* zero the cksum in the buffer */
			ASSERT(optr + hash->confound_len + hash->hash_len <=
				DB_LIM(mp));
			bzero(optr + hash->confound_len, hash->hash_len);

			/* calculate MD5 chksum of confounder + input */
			if (hash->hashfunc) {
				(void) hash->hashfunc(newcksum, optr, inlen);
			}
		}

		if (bcmp(cksum, newcksum, hash->hash_len)) {
#ifdef DEBUG
			cmn_err(CE_WARN, "des_cbc_decrypt: checksum "
				"verification failed");
#endif
			mp->b_datap->db_type = M_ERROR;
			mp->b_rptr = mp->b_datap->db_base;
			*mp->b_rptr = EIO;
			mp->b_wptr = mp->b_rptr + sizeof (char);
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
			qreply(WR(q), mp);
			return (NULL);
		}
	}

	datalen = inlen - hash->confound_len - hash->hash_len;

	/* Move just the decrypted input into place if necessary */
	if (hash->confound_len > 0 || hash->hash_len > 0) {
		if (tmi->dec_data.method == CRYPT_METHOD_DES3_CBC_SHA1)
			mp->b_rptr += hash->confound_len;
		else
			mp->b_rptr += hash->confound_len + hash->hash_len;
	}

	ASSERT(mp->b_rptr + datalen <= DB_LIM(mp));
	mp->b_wptr = mp->b_rptr + datalen;

	return (mp);
}

static mblk_t *
do_decrypt(queue_t *q, mblk_t *mp)
{
	struct tmodinfo *tmi = (struct tmodinfo *)q->q_ptr;
	mblk_t *outmp;

	switch (tmi->dec_data.method) {
	case CRYPT_METHOD_DES_CFB:
		outmp = des_cfb_decrypt(q, tmi, mp);
		break;
	case CRYPT_METHOD_NONE:
		outmp = mp;
		break;
	case CRYPT_METHOD_DES_CBC_NULL:
		outmp = des_cbc_decrypt(q, tmi, mp, &null_hash);
		break;
	case CRYPT_METHOD_DES_CBC_MD5:
		outmp = des_cbc_decrypt(q, tmi, mp, &md5_hash);
		break;
	case CRYPT_METHOD_DES_CBC_CRC:
		outmp = des_cbc_decrypt(q, tmi, mp, &crc32_hash);
		break;
	case CRYPT_METHOD_DES3_CBC_SHA1:
		outmp = des_cbc_decrypt(q, tmi, mp, &sha1_hash);
		break;
	case CRYPT_METHOD_ARCFOUR_HMAC_MD5:
	case CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP:
		outmp = arcfour_hmac_md5_decrypt(q, tmi, mp, &md5_hash);
		break;
	case CRYPT_METHOD_AES128:
	case CRYPT_METHOD_AES256:
		outmp = aes_decrypt(q, tmi, mp, &sha1_hash);
		break;
	}
	return (outmp);
}

/*
 * do_encrypt
 *
 * Generic encryption routine for a single message block.
 * The input mblk may be replaced by some encrypt routines
 * because they add extra data in some cases that may exceed
 * the input mblk_t size limit.
 */
static mblk_t *
do_encrypt(queue_t *q, mblk_t *mp)
{
	struct tmodinfo *tmi = (struct tmodinfo *)q->q_ptr;
	mblk_t *outmp;

	switch (tmi->enc_data.method) {
	case CRYPT_METHOD_DES_CFB:
		outmp = des_cfb_encrypt(q, tmi, mp);
		break;
	case CRYPT_METHOD_DES_CBC_NULL:
		outmp = des_cbc_encrypt(q, tmi, mp, &null_hash);
		break;
	case CRYPT_METHOD_DES_CBC_MD5:
		outmp = des_cbc_encrypt(q, tmi, mp, &md5_hash);
		break;
	case CRYPT_METHOD_DES_CBC_CRC:
		outmp = des_cbc_encrypt(q, tmi, mp, &crc32_hash);
		break;
	case CRYPT_METHOD_DES3_CBC_SHA1:
		outmp = des_cbc_encrypt(q, tmi, mp, &sha1_hash);
		break;
	case CRYPT_METHOD_ARCFOUR_HMAC_MD5:
	case CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP:
		outmp = arcfour_hmac_md5_encrypt(q, tmi, mp, &md5_hash);
		break;
	case CRYPT_METHOD_AES128:
	case CRYPT_METHOD_AES256:
		outmp = aes_encrypt(q, tmi, mp, &sha1_hash);
		break;
	case CRYPT_METHOD_NONE:
		outmp = mp;
		break;
	}
	return (outmp);
}

/*
 * setup_crypto
 *
 * This takes the data from the CRYPTIOCSETUP ioctl
 * and sets up a cipher_data_t structure for either
 * encryption or decryption.  This is where the
 * key and initialization vector data get stored
 * prior to beginning any crypto functions.
 *
 * Special note:
 *   Some applications(e.g. telnetd) have ability to switch
 * crypto on/off periodically.  Thus, the application may call
 * the CRYPTIOCSETUP ioctl many times for the same stream.
 * If the CRYPTIOCSETUP is called with 0 length key or ivec fields
 * assume that the key, block, and saveblock fields that are already
 * set from a previous CRIOCSETUP call are still valid.  This helps avoid
 * a rekeying error that could occur if we overwrite these fields
 * with each CRYPTIOCSETUP call.
 *   In short, sometimes, CRYPTIOCSETUP is used to simply toggle on/off
 * without resetting the original crypto parameters.
 *
 */
static int
setup_crypto(struct cr_info_t *ci, struct cipher_data_t *cd, int encrypt)
{
	uint_t newblocklen;
	uint32_t enc_usage = 0, dec_usage = 0;
	int rv;

	/*
	 * Initial sanity checks
	 */
	if (!CR_METHOD_OK(ci->crypto_method)) {
		cmn_err(CE_WARN, "Illegal crypto method (%d)",
			ci->crypto_method);
		return (EINVAL);
	}
	if (!CR_OPTIONS_OK(ci->option_mask)) {
		cmn_err(CE_WARN, "Illegal crypto options (%d)",
			ci->option_mask);
		return (EINVAL);
	}
	if (!CR_IVUSAGE_OK(ci->ivec_usage)) {
		cmn_err(CE_WARN, "Illegal ivec usage value (%d)",
			ci->ivec_usage);
		return (EINVAL);
	}

	cd->method = ci->crypto_method;
	cd->bytes = 0;

	if (ci->keylen > 0) {
		if (cd->key != NULL) {
			kmem_free(cd->key, cd->keylen);
			cd->key = NULL;
			cd->keylen = 0;
		}
		/*
		 * cd->key holds the copy of the raw key bytes passed in
		 * from the userland app.
		 */
		cd->key = (char *)kmem_alloc((size_t)ci->keylen, KM_SLEEP);

		cd->keylen = ci->keylen;
		bcopy(ci->key, cd->key, (size_t)ci->keylen);
	}

	/*
	 * Configure the block size based on the type of cipher.
	 */
	switch (cd->method) {
		case CRYPT_METHOD_NONE:
			newblocklen = 0;
			break;
		case CRYPT_METHOD_DES_CFB:
			newblocklen = DEFAULT_DES_BLOCKLEN;
			cd->mech_type = crypto_mech2id(SUN_CKM_DES_ECB);
			break;
		case CRYPT_METHOD_DES_CBC_NULL:
		case CRYPT_METHOD_DES_CBC_MD5:
		case CRYPT_METHOD_DES_CBC_CRC:
			newblocklen = DEFAULT_DES_BLOCKLEN;
			cd->mech_type = crypto_mech2id(SUN_CKM_DES_CBC);
			break;
		case CRYPT_METHOD_DES3_CBC_SHA1:
			newblocklen = DEFAULT_DES_BLOCKLEN;
			cd->mech_type = crypto_mech2id(SUN_CKM_DES3_CBC);
			/* 3DES always uses the old usage constant */
			enc_usage = RCMDV1_USAGE;
			dec_usage = RCMDV1_USAGE;
			break;
		case CRYPT_METHOD_ARCFOUR_HMAC_MD5:
		case CRYPT_METHOD_ARCFOUR_HMAC_MD5_EXP:
			newblocklen = 0;
			cd->mech_type = crypto_mech2id(SUN_CKM_RC4);
			break;
		case CRYPT_METHOD_AES128:
		case CRYPT_METHOD_AES256:
			newblocklen = DEFAULT_AES_BLOCKLEN;
			cd->mech_type = crypto_mech2id(SUN_CKM_AES_ECB);
			enc_usage = AES_ENCRYPT_USAGE;
			dec_usage = AES_DECRYPT_USAGE;
			break;
	}
	if (cd->mech_type == CRYPTO_MECH_INVALID) {
		return (CRYPTO_FAILED);
	}

	/*
	 * If RC4, initialize the master crypto key used by
	 * the RC4 algorithm to derive the final encrypt and decrypt keys.
	 */
	if (cd->keylen > 0 && IS_RC4_METHOD(cd->method)) {
		/*
		 * cd->ckey is a kernel crypto key structure used as the
		 * master key in the RC4-HMAC crypto operations.
		 */
		if (cd->ckey == NULL) {
			cd->ckey = (crypto_key_t *)kmem_zalloc(
				sizeof (crypto_key_t), KM_SLEEP);
		}

		cd->ckey->ck_format = CRYPTO_KEY_RAW;
		cd->ckey->ck_data = cd->key;

		/* key length for EF is measured in bits */
		cd->ckey->ck_length = cd->keylen * 8;
	}

	/*
	 * cd->block and cd->saveblock are used as temporary storage for
	 * data that must be carried over between encrypt/decrypt operations
	 * in some of the "feedback" modes.
	 */
	if (newblocklen != cd->blocklen) {
		if (cd->block != NULL) {
			kmem_free(cd->block, cd->blocklen);
			cd->block = NULL;
		}

		if (cd->saveblock != NULL) {
			kmem_free(cd->saveblock, cd->blocklen);
			cd->saveblock = NULL;
		}

		cd->blocklen = newblocklen;
		if (cd->blocklen) {
			cd->block = (char *)kmem_zalloc((size_t)cd->blocklen,
				KM_SLEEP);
		}

		if (cd->method == CRYPT_METHOD_DES_CFB)
			cd->saveblock = (char *)kmem_zalloc(cd->blocklen,
						KM_SLEEP);
		else
			cd->saveblock = NULL;
	}

	if (ci->iveclen != cd->ivlen) {
		if (cd->ivec != NULL) {
			kmem_free(cd->ivec, cd->ivlen);
			cd->ivec = NULL;
		}
		if (ci->ivec_usage != IVEC_NEVER && ci->iveclen > 0) {
			cd->ivec = (char *)kmem_zalloc((size_t)ci->iveclen,
						KM_SLEEP);
			cd->ivlen = ci->iveclen;
		} else {
			cd->ivlen = 0;
			cd->ivec = NULL;
		}
	}
	cd->option_mask = ci->option_mask;

	/*
	 * Old protocol requires a static 'usage' value for
	 * deriving keys.  Yuk.
	 */
	if (cd->option_mask & CRYPTOPT_RCMD_MODE_V1) {
		enc_usage = dec_usage = RCMDV1_USAGE;
	}

	if (cd->ivlen > cd->blocklen) {
		cmn_err(CE_WARN, "setup_crypto: IV longer than block size");
		return (EINVAL);
	}

	/*
	 * If we are using an IVEC "correctly" (i.e. set it once)
	 * copy it here.
	 */
	if (ci->ivec_usage == IVEC_ONETIME && cd->block != NULL)
		bcopy(ci->ivec, cd->block, (size_t)cd->ivlen);

	cd->ivec_usage = ci->ivec_usage;
	if (cd->ivec != NULL) {
		/* Save the original IVEC in case we need it later */
		bcopy(ci->ivec, cd->ivec, (size_t)cd->ivlen);
	}
	/*
	 * Special handling for 3DES-SHA1-HMAC and AES crypto:
	 * generate derived keys and context templates
	 * for better performance.
	 */
	if (cd->method == CRYPT_METHOD_DES3_CBC_SHA1 ||
	    IS_AES_METHOD(cd->method)) {
		crypto_mechanism_t enc_mech;
		crypto_mechanism_t hmac_mech;

		if (cd->d_encr_key.ck_data != NULL) {
			bzero(cd->d_encr_key.ck_data, cd->keylen);
			kmem_free(cd->d_encr_key.ck_data, cd->keylen);
		}

		if (cd->d_hmac_key.ck_data != NULL) {
			bzero(cd->d_hmac_key.ck_data, cd->keylen);
			kmem_free(cd->d_hmac_key.ck_data, cd->keylen);
		}

		if (cd->enc_tmpl != NULL)
			(void) crypto_destroy_ctx_template(cd->enc_tmpl);

		if (cd->hmac_tmpl != NULL)
			(void) crypto_destroy_ctx_template(cd->hmac_tmpl);

		enc_mech.cm_type = cd->mech_type;
		enc_mech.cm_param = cd->ivec;
		enc_mech.cm_param_len = cd->ivlen;

		hmac_mech.cm_type = sha1_hmac_mech;
		hmac_mech.cm_param = NULL;
		hmac_mech.cm_param_len = 0;

		/*
		 * Create the derived keys.
		 */
		rv = create_derived_keys(cd,
			(encrypt ? enc_usage : dec_usage),
			&cd->d_encr_key, &cd->d_hmac_key);

		if (rv != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "failed to create derived "
				"keys: %0x", rv);
			return (CRYPTO_FAILED);
		}

		rv = crypto_create_ctx_template(&enc_mech,
					&cd->d_encr_key,
					&cd->enc_tmpl, KM_SLEEP);
		if (rv == CRYPTO_MECH_NOT_SUPPORTED) {
			cd->enc_tmpl = NULL;
		} else if (rv != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "failed to create enc template "
				"for d_encr_key: %0x", rv);
			return (CRYPTO_FAILED);
		}

		rv = crypto_create_ctx_template(&hmac_mech,
				&cd->d_hmac_key,
				&cd->hmac_tmpl, KM_SLEEP);
		if (rv == CRYPTO_MECH_NOT_SUPPORTED) {
			cd->hmac_tmpl = NULL;
		} else if (rv != CRYPTO_SUCCESS) {
			cmn_err(CE_WARN, "failed to create hmac template:"
				" %0x", rv);
			return (CRYPTO_FAILED);
		}
	} else if (IS_RC4_METHOD(cd->method)) {
		bzero(&cd->d_encr_key, sizeof (crypto_key_t));
		bzero(&cd->d_hmac_key, sizeof (crypto_key_t));
		cd->ctx = NULL;
		cd->enc_tmpl = NULL;
		cd->hmac_tmpl = NULL;
	}

	/* Final sanity checks, make sure no fields are NULL */
	if (cd->method != CRYPT_METHOD_NONE) {
		if (cd->block == NULL && cd->blocklen > 0) {
#ifdef DEBUG
			cmn_err(CE_WARN,
				"setup_crypto: IV block not allocated");
#endif
			return (ENOMEM);
		}
		if (cd->key == NULL && cd->keylen > 0) {
#ifdef DEBUG
			cmn_err(CE_WARN,
				"setup_crypto: key block not allocated");
#endif
			return (ENOMEM);
		}
		if (cd->method == CRYPT_METHOD_DES_CFB &&
		    cd->saveblock == NULL && cd->blocklen > 0) {
#ifdef DEBUG
			cmn_err(CE_WARN,
				"setup_crypto: save block not allocated");
#endif
			return (ENOMEM);
		}
		if (cd->ivec == NULL && cd->ivlen > 0) {
#ifdef DEBUG
			cmn_err(CE_WARN,
				"setup_crypto: IV not allocated");
#endif
			return (ENOMEM);
		}
	}
	return (0);
}

/*
 * RCMDS require a 4 byte, clear text
 * length field before each message.
 * Add it now.
 */
static mblk_t *
mklenmp(mblk_t *bp, uint32_t len)
{
	mblk_t *lenmp;
	uchar_t *ucp;

	if (bp->b_rptr - 4 < DB_BASE(bp) || DB_REF(bp) > 1) {
		lenmp = allocb(4, BPRI_MED);
		if (lenmp != NULL) {
			lenmp->b_rptr = lenmp->b_wptr = DB_LIM(lenmp);
			linkb(lenmp, bp);
			bp = lenmp;
		}
	}
	ucp = bp->b_rptr;
	*--ucp = len;
	*--ucp = len >> 8;
	*--ucp = len >> 16;
	*--ucp = len >> 24;

	bp->b_rptr = ucp;

	return (bp);
}

static mblk_t *
encrypt_block(queue_t *q, struct tmodinfo *tmi, mblk_t *mp, size_t plainlen)
{
	mblk_t *newmp;
	size_t headspace;

	mblk_t *cbp;
	size_t cipherlen;
	size_t extra = 0;
	uint32_t ptlen = (uint32_t)plainlen;
	/*
	 * If we are using the "NEW" RCMD mode,
	 * add 4 bytes to the plaintext for the
	 * plaintext length that gets prepended
	 * before encrypting.
	 */
	if (tmi->enc_data.option_mask & CRYPTOPT_RCMD_MODE_V2)
		ptlen += 4;

	cipherlen = encrypt_size(&tmi->enc_data, (size_t)ptlen);

	/*
	 * if we must allocb, then make sure its enough
	 * to hold the length field so we dont have to allocb
	 * again down below in 'mklenmp'
	 */
	if (ANY_RCMD_MODE(tmi->enc_data.option_mask)) {
		extra = sizeof (uint32_t);
	}

	/*
	 * Calculate how much space is needed in front of
	 * the data.
	 */
	headspace = plaintext_offset(&tmi->enc_data);

	/*
	 * If the current block is too small, reallocate
	 * one large enough to hold the hdr, tail, and
	 * ciphertext.
	 */
	if ((cipherlen + extra >= MBLKSIZE(mp)) || DB_REF(mp) > 1) {
		int sz = P2ROUNDUP(cipherlen+extra, 8);

		cbp = allocb_tmpl(sz, mp);
		if (cbp == NULL) {
			cmn_err(CE_WARN,
				"allocb (%d bytes) failed", sz);
			return (NULL);
		}

		cbp->b_cont = mp->b_cont;

		/*
		 * headspace includes the length fields needed
		 * for the RCMD modes (v1 == 4 bytes, V2 = 8)
		 */
		ASSERT(cbp->b_rptr + P2ROUNDUP(plainlen+headspace, 8)
			<= DB_LIM(cbp));

		cbp->b_rptr = DB_BASE(cbp) + headspace;
		bcopy(mp->b_rptr, cbp->b_rptr, plainlen);
		cbp->b_wptr = cbp->b_rptr + plainlen;

		freeb(mp);
	} else {
		size_t extra = 0;
		cbp = mp;

		/*
		 * Some ciphers add HMAC after the final block
		 * of the ciphertext, not at the beginning like the
		 * 1-DES ciphers.
		 */
		if (tmi->enc_data.method ==
			CRYPT_METHOD_DES3_CBC_SHA1 ||
		    IS_AES_METHOD(tmi->enc_data.method)) {
			extra = sha1_hash.hash_len;
		}

		/*
		 * Make sure the rptr is positioned correctly so that
		 * routines later do not have to shift this data around
		 */
		if ((cbp->b_rptr + P2ROUNDUP(cipherlen + extra, 8) >
			DB_LIM(cbp)) ||
			(cbp->b_rptr - headspace < DB_BASE(cbp))) {
			ovbcopy(cbp->b_rptr, DB_BASE(cbp) + headspace,
				plainlen);
			cbp->b_rptr = DB_BASE(cbp) + headspace;
			cbp->b_wptr = cbp->b_rptr + plainlen;
		}
	}

	ASSERT(cbp->b_rptr - headspace >= DB_BASE(cbp));
	ASSERT(cbp->b_wptr <= DB_LIM(cbp));

	/*
	 * If using RCMD_MODE_V2 (new rcmd mode), prepend
	 * the plaintext length before the actual plaintext.
	 */
	if (tmi->enc_data.option_mask & CRYPTOPT_RCMD_MODE_V2) {
		cbp->b_rptr -= RCMD_LEN_SZ;

		/* put plaintext length at head of buffer */
		*(cbp->b_rptr + 3) = (uchar_t)(plainlen & 0xff);
		*(cbp->b_rptr + 2) = (uchar_t)((plainlen >> 8) & 0xff);
		*(cbp->b_rptr + 1) = (uchar_t)((plainlen >> 16) & 0xff);
		*(cbp->b_rptr) = (uchar_t)((plainlen >> 24) & 0xff);
	}

	newmp = do_encrypt(q, cbp);

	if (newmp != NULL &&
	    (tmi->enc_data.option_mask &
	    (CRYPTOPT_RCMD_MODE_V1 | CRYPTOPT_RCMD_MODE_V2))) {
		mblk_t *lp;
		/*
		 * Add length field, required when this is
		 * used to encrypt "r*" commands(rlogin, rsh)
		 * with Kerberos.
		 */
		lp = mklenmp(newmp, plainlen);

		if (lp == NULL) {
			freeb(newmp);
			return (NULL);
		} else {
			newmp = lp;
		}
	}
	return (newmp);
}

/*
 * encrypt_msgb
 *
 * encrypt a single message. This routine adds the
 * RCMD overhead bytes when necessary.
 */
static mblk_t *
encrypt_msgb(queue_t *q, struct tmodinfo *tmi, mblk_t *mp)
{
	size_t plainlen, outlen;
	mblk_t *newmp = NULL;

	/* If not encrypting, do nothing */
	if (tmi->enc_data.method == CRYPT_METHOD_NONE) {
		return (mp);
	}

	plainlen = MBLKL(mp);
	if (plainlen == 0)
		return (NULL);

	/*
	 * If the block is too big, we encrypt in 4K chunks so that
	 * older rlogin clients do not choke on the larger buffers.
	 */
	while ((plainlen = MBLKL(mp)) > MSGBUF_SIZE) {
		mblk_t *mp1 = NULL;
		outlen = MSGBUF_SIZE;
		/*
		 * Allocate a new buffer that is only 4K bytes, the
		 * extra bytes are for crypto overhead.
		 */
		mp1 = allocb(outlen + CONFOUNDER_BYTES, BPRI_MED);
		if (mp1 == NULL) {
			cmn_err(CE_WARN,
				"allocb (%d bytes) failed",
				(int)(outlen + CONFOUNDER_BYTES));
			return (NULL);
		}
		/* Copy the next 4K bytes from the old block. */
		bcopy(mp->b_rptr, mp1->b_rptr, outlen);
		mp1->b_wptr = mp1->b_rptr + outlen;
		/* Advance the old block. */
		mp->b_rptr += outlen;

		/* encrypt the new block */
		newmp = encrypt_block(q, tmi, mp1, outlen);
		if (newmp == NULL)
			return (NULL);

		putnext(q, newmp);
	}
	newmp = NULL;
	/* If there is data left (< MSGBUF_SIZE), encrypt it. */
	if ((plainlen = MBLKL(mp)) > 0)
		newmp = encrypt_block(q, tmi, mp, plainlen);

	return (newmp);
}

/*
 * cryptmodwsrv
 *
 * Service routine for the write queue.
 *
 * Because data may be placed in the queue to hold between
 * the CRYPTIOCSTOP and CRYPTIOCSTART ioctls, the service routine is needed.
 */
static int
cryptmodwsrv(queue_t *q)
{
	mblk_t *mp;
	struct tmodinfo *tmi = (struct tmodinfo *)q->q_ptr;

	while ((mp = getq(q)) != NULL) {
		switch (mp->b_datap->db_type) {
		default:
			/*
			 * wput does not queue anything > QPCTL
			 */
			if (!canputnext(q) ||
			    !(tmi->ready & CRYPT_WRITE_READY)) {
				if (!putbq(q, mp)) {
					freemsg(mp);
				}
				return (0);
			}
			putnext(q, mp);
			break;
		case M_DATA:
			if (canputnext(q) && (tmi->ready & CRYPT_WRITE_READY)) {
				mblk_t *bp;
				mblk_t *newmsg = NULL;

				/*
				 * If multiple msgs, concat into 1
				 * to minimize crypto operations later.
				 */
				if (mp->b_cont != NULL) {
					bp = msgpullup(mp, -1);
					if (bp != NULL) {
						freemsg(mp);
						mp = bp;
					}
				}
				newmsg = encrypt_msgb(q, tmi, mp);
				if (newmsg != NULL)
					putnext(q, newmsg);
			} else {
				if (!putbq(q, mp)) {
					freemsg(mp);
				}
				return (0);
			}
			break;
		}
	}
	return (0);
}

static void
start_stream(queue_t *wq, mblk_t *mp, uchar_t dir)
{
	mblk_t *newmp = NULL;
	struct tmodinfo *tmi = (struct tmodinfo *)wq->q_ptr;

	if (dir == CRYPT_ENCRYPT) {
		tmi->ready |= CRYPT_WRITE_READY;
		(void) (STRLOG(CRYPTMOD_ID, 0, 5, SL_TRACE|SL_NOTE,
				"start_stream: restart ENCRYPT/WRITE q"));

		enableok(wq);
		qenable(wq);
	} else if (dir == CRYPT_DECRYPT) {
		/*
		 * put any extra data in the RD
		 * queue to be processed and
		 * sent back up.
		 */
		newmp = mp->b_cont;
		mp->b_cont = NULL;

		tmi->ready |= CRYPT_READ_READY;
		(void) (STRLOG(CRYPTMOD_ID, 0, 5,
				SL_TRACE|SL_NOTE,
				"start_stream: restart "
				"DECRYPT/READ q"));

		if (newmp != NULL)
			if (!putbq(RD(wq), newmp))
				freemsg(newmp);

		enableok(RD(wq));
		qenable(RD(wq));
	}

	miocack(wq, mp, 0, 0);
}

/*
 * Write-side put procedure.  Its main task is to detect ioctls and
 * FLUSH operations.  Other message types are passed on through.
 */
static void
cryptmodwput(queue_t *wq, mblk_t *mp)
{
	struct iocblk *iocp;
	struct tmodinfo *tmi = (struct tmodinfo *)wq->q_ptr;
	int ret, err;

	switch (mp->b_datap->db_type) {
	case M_DATA:
		if (wq->q_first == NULL && canputnext(wq) &&
		    (tmi->ready & CRYPT_WRITE_READY) &&
		    tmi->enc_data.method == CRYPT_METHOD_NONE) {
			putnext(wq, mp);
			return;
		}
		/* else, put it in the service queue */
		if (!putq(wq, mp)) {
			freemsg(mp);
		}
		break;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			flushq(wq, FLUSHDATA);
		}
		putnext(wq, mp);
		break;
	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case CRYPTIOCSETUP:
			ret = 0;
			(void) (STRLOG(CRYPTMOD_ID, 0, 5,
					SL_TRACE | SL_NOTE,
					"wput: got CRYPTIOCSETUP "
					"ioctl(%d)", iocp->ioc_cmd));

			if ((err = miocpullup(mp,
					sizeof (struct cr_info_t))) != 0) {
				cmn_err(CE_WARN,
				"wput: miocpullup failed for cr_info_t");
				miocnak(wq, mp, 0, err);
			} else {
				struct cr_info_t *ci;
				ci = (struct cr_info_t *)mp->b_cont->b_rptr;

				if (ci->direction_mask & CRYPT_ENCRYPT) {
				    ret = setup_crypto(ci, &tmi->enc_data, 1);
				}

				if (ret == 0 &&
				    (ci->direction_mask & CRYPT_DECRYPT)) {
				    ret = setup_crypto(ci, &tmi->dec_data, 0);
				}
				if (ret == 0 &&
				    (ci->direction_mask & CRYPT_DECRYPT) &&
				    ANY_RCMD_MODE(tmi->dec_data.option_mask)) {
					bzero(&tmi->rcmd_state,
					    sizeof (tmi->rcmd_state));
				}
				if (ret == 0) {
					miocack(wq, mp, 0, 0);
				} else {
					cmn_err(CE_WARN,
						"wput: setup_crypto failed");
					miocnak(wq, mp, 0, ret);
				}
				(void) (STRLOG(CRYPTMOD_ID, 0, 5,
						SL_TRACE|SL_NOTE,
						"wput: done with SETUP "
						"ioctl"));
			}
			break;
		case CRYPTIOCSTOP:
			(void) (STRLOG(CRYPTMOD_ID, 0, 5,
					SL_TRACE|SL_NOTE,
					"wput: got CRYPTIOCSTOP "
					"ioctl(%d)", iocp->ioc_cmd));

			if ((err = miocpullup(mp, sizeof (uint32_t))) != 0) {
				cmn_err(CE_WARN,
					"wput: CRYPTIOCSTOP ioctl wrong "
					"size (%d should be %d)",
					(int)iocp->ioc_count,
					(int)sizeof (uint32_t));
				miocnak(wq, mp, 0, err);
			} else {
				uint32_t *stopdir;

				stopdir = (uint32_t *)mp->b_cont->b_rptr;
				if (!CR_DIRECTION_OK(*stopdir)) {
					miocnak(wq, mp, 0, EINVAL);
					return;
				}

				/* disable the queues until further notice */
				if (*stopdir & CRYPT_ENCRYPT) {
					noenable(wq);
					tmi->ready &= ~CRYPT_WRITE_READY;
				}
				if (*stopdir & CRYPT_DECRYPT) {
					noenable(RD(wq));
					tmi->ready &= ~CRYPT_READ_READY;
				}

				miocack(wq, mp, 0, 0);
			}
			break;
		case CRYPTIOCSTARTDEC:
			(void) (STRLOG(CRYPTMOD_ID, 0, 5,
					SL_TRACE|SL_NOTE,
					"wput: got CRYPTIOCSTARTDEC "
					"ioctl(%d)", iocp->ioc_cmd));

			start_stream(wq, mp, CRYPT_DECRYPT);
			break;
		case CRYPTIOCSTARTENC:
			(void) (STRLOG(CRYPTMOD_ID, 0, 5,
					SL_TRACE|SL_NOTE,
					"wput: got CRYPTIOCSTARTENC "
					"ioctl(%d)", iocp->ioc_cmd));

			start_stream(wq, mp, CRYPT_ENCRYPT);
			break;
		default:
			putnext(wq, mp);
			break;
		}
		break;
	default:
		if (queclass(mp) < QPCTL) {
			if (wq->q_first != NULL || !canputnext(wq)) {
				if (!putq(wq, mp))
					freemsg(mp);
				return;
			}
		}
		putnext(wq, mp);
		break;
	}
}

/*
 * decrypt_rcmd_mblks
 *
 * Because kerberized r* commands(rsh, rlogin, etc)
 * use a 4 byte length field to indicate the # of
 * PLAINTEXT bytes that are encrypted in the field
 * that follows, we must parse out each message and
 * break out the length fields prior to sending them
 * upstream to our Solaris r* clients/servers which do
 * NOT understand this format.
 *
 * Kerberized/encrypted message format:
 * -------------------------------
 * | XXXX | N bytes of ciphertext|
 * -------------------------------
 *
 * Where: XXXX = number of plaintext bytes that were encrypted in
 *               to make the ciphertext field.  This is done
 *               because we are using a cipher that pads out to
 *               an 8 byte boundary.  We only want the application
 *               layer to see the correct number of plain text bytes,
 *               not plaintext + pad.  So, after we decrypt, we
 *               must trim the output block down to the intended
 *               plaintext length and eliminate the pad bytes.
 *
 * This routine takes the entire input message, breaks it into
 * a new message that does not contain these length fields and
 * returns a message consisting of mblks filled with just ciphertext.
 *
 */
static mblk_t *
decrypt_rcmd_mblks(queue_t *q, mblk_t *mp)
{
	mblk_t *newmp = NULL;
	size_t msglen;
	struct tmodinfo *tmi = (struct tmodinfo *)q->q_ptr;

	msglen = msgsize(mp);

	/*
	 * If we need the length field, get it here.
	 * Test the "plaintext length" indicator.
	 */
	if (tmi->rcmd_state.pt_len == 0) {
		uint32_t elen;
		int tocopy;
		mblk_t *nextp;

		/*
		 * Make sure we have recieved all 4 bytes of the
		 * length field.
		 */
		while (mp != NULL) {
			ASSERT(tmi->rcmd_state.cd_len < sizeof (uint32_t));

			tocopy = sizeof (uint32_t) -
				tmi->rcmd_state.cd_len;
			if (tocopy > msglen)
				tocopy = msglen;

			ASSERT(mp->b_rptr + tocopy <= DB_LIM(mp));
			bcopy(mp->b_rptr,
				(char *)(&tmi->rcmd_state.next_len +
					tmi->rcmd_state.cd_len), tocopy);

			tmi->rcmd_state.cd_len += tocopy;

			if (tmi->rcmd_state.cd_len >= sizeof (uint32_t)) {
				tmi->rcmd_state.next_len =
					ntohl(tmi->rcmd_state.next_len);
				break;
			}

			nextp = mp->b_cont;
			mp->b_cont = NULL;
			freeb(mp);
			mp = nextp;
		}

		if (mp == NULL) {
			return (NULL);
		}
		/*
		 * recalculate the msglen now that we've read the
		 * length and adjusted the bufptr (b_rptr).
		 */
		msglen -= tocopy;
		mp->b_rptr += tocopy;

		tmi->rcmd_state.pt_len = tmi->rcmd_state.next_len;

		if (tmi->rcmd_state.pt_len <= 0) {
			/*
			 * Return an IO error to break the connection. there
			 * is no way to recover from this.  Usually it means
			 * the app has incorrectly requested decryption on
			 * a non-encrypted stream, thus the "pt_len" field
			 * is negative.
			 */
			mp->b_datap->db_type = M_ERROR;
			mp->b_rptr = mp->b_datap->db_base;
			*mp->b_rptr = EIO;
			mp->b_wptr = mp->b_rptr + sizeof (char);

			freemsg(mp->b_cont);
			mp->b_cont = NULL;
			qreply(WR(q), mp);
			tmi->rcmd_state.cd_len = tmi->rcmd_state.pt_len = 0;
			return (NULL);
		}

		/*
		 * If this is V2 mode, then the encrypted data is actually
		 * 4 bytes bigger than the indicated len because the plaintext
		 * length is encrypted for an additional security check, but
		 * its not counted as part of the overall length we just read.
		 * Strange and confusing, but true.
		 */

		if (tmi->dec_data.option_mask & CRYPTOPT_RCMD_MODE_V2)
			elen = tmi->rcmd_state.pt_len + 4;
		else
			elen = tmi->rcmd_state.pt_len;

		tmi->rcmd_state.cd_len  = encrypt_size(&tmi->dec_data, elen);

		/*
		 * Allocate an mblk to hold the cipher text until it is
		 * all ready to be processed.
		 */
		tmi->rcmd_state.c_msg = allocb(tmi->rcmd_state.cd_len,
						BPRI_HI);
		if (tmi->rcmd_state.c_msg == NULL) {
#ifdef DEBUG
			cmn_err(CE_WARN, "decrypt_rcmd_msgb: allocb failed "
				"for %d bytes",
				(int)tmi->rcmd_state.cd_len);
#endif
			/*
			 * Return an IO error to break the connection.
			 */
			mp->b_datap->db_type = M_ERROR;
			mp->b_rptr = mp->b_datap->db_base;
			*mp->b_rptr = EIO;
			mp->b_wptr = mp->b_rptr + sizeof (char);
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
			tmi->rcmd_state.cd_len = tmi->rcmd_state.pt_len = 0;
			qreply(WR(q), mp);
			return (NULL);
		}
	}

	/*
	 * If this entire message was just the length field,
	 * free and return.  The actual data will probably be next.
	 */
	if (msglen == 0) {
		freemsg(mp);
		return (NULL);
	}

	/*
	 * Copy as much of the cipher text as possible into
	 * the new msgb (c_msg).
	 *
	 * Logic:  if we got some bytes (msglen) and we still
	 * 	"need" some bytes (len-rcvd), get them here.
	 */
	ASSERT(tmi->rcmd_state.c_msg != NULL);
	if (msglen > 0 &&
	    (tmi->rcmd_state.cd_len > MBLKL(tmi->rcmd_state.c_msg))) {
		mblk_t *bp, *nextp;
		size_t n;

		/*
		 * Walk the mblks and copy just as many bytes as we need
		 * for this particular block of cipher text.
		 */
		bp = mp;
		while (bp != NULL) {
			size_t needed;
			size_t tocopy;
			n = MBLKL(bp);

			needed = tmi->rcmd_state.cd_len -
				MBLKL(tmi->rcmd_state.c_msg);

			tocopy = (needed >= n ? n : needed);

			ASSERT(bp->b_rptr + tocopy <= DB_LIM(bp));
			ASSERT(tmi->rcmd_state.c_msg->b_wptr + tocopy <=
				DB_LIM(tmi->rcmd_state.c_msg));

			/* Copy to end of new mblk */
			bcopy(bp->b_rptr, tmi->rcmd_state.c_msg->b_wptr,
				tocopy);

			tmi->rcmd_state.c_msg->b_wptr += tocopy;

			bp->b_rptr += tocopy;

			nextp = bp->b_cont;

			/*
			 * If we used this whole block, free it and
			 * move on.
			 */
			if (!MBLKL(bp)) {
				freeb(bp);
				bp = NULL;
			}

			/* If we got what we needed, stop the loop */
			if (MBLKL(tmi->rcmd_state.c_msg) ==
			    tmi->rcmd_state.cd_len) {
				/*
				 * If there is more data in the message,
				 * its for another block of cipher text,
				 * put it back in the queue for next time.
				 */
				if (bp) {
					if (!putbq(q, bp))
						freemsg(bp);
				} else if (nextp != NULL) {
					/*
					 * If there is more, put it back in the
					 * queue for another pass thru.
					 */
					if (!putbq(q, nextp))
						freemsg(nextp);
				}
				break;
			}
			bp = nextp;
		}
	}
	/*
	 * Finally, if we received all the cipher text data for
	 * this message, decrypt it into a new msg and send it up
	 * to the app.
	 */
	if (tmi->rcmd_state.pt_len > 0 &&
	    MBLKL(tmi->rcmd_state.c_msg) == tmi->rcmd_state.cd_len) {
		mblk_t *bp;
		mblk_t *newbp;

		/*
		 * Now we can use our msg that we created when the
		 * initial message boundary was detected.
		 */
		bp = tmi->rcmd_state.c_msg;
		tmi->rcmd_state.c_msg = NULL;

		newbp = do_decrypt(q, bp);
		if (newbp != NULL) {
			bp = newbp;
			/*
			 * If using RCMD_MODE_V2 ("new" mode),
			 * look at the 4 byte plaintext length that
			 * was just decrypted and compare with the
			 * original pt_len value that was received.
			 */
			if (tmi->dec_data.option_mask &
			    CRYPTOPT_RCMD_MODE_V2) {
				uint32_t pt_len2;

				pt_len2 = *(uint32_t *)bp->b_rptr;
				pt_len2 = ntohl(pt_len2);
				/*
				 * Make sure the 2 pt len fields agree.
				 */
				if (pt_len2 != tmi->rcmd_state.pt_len) {
					cmn_err(CE_WARN,
						"Inconsistent length fields"
						" received %d != %d",
						(int)tmi->rcmd_state.pt_len,
						(int)pt_len2);
					bp->b_datap->db_type = M_ERROR;
					bp->b_rptr = bp->b_datap->db_base;
					*bp->b_rptr = EIO;
					bp->b_wptr = bp->b_rptr + sizeof (char);
					freemsg(bp->b_cont);
					bp->b_cont = NULL;
					tmi->rcmd_state.cd_len = 0;
					qreply(WR(q), bp);
					return (NULL);
				}
				bp->b_rptr += sizeof (uint32_t);
			}

			/*
			 * Trim the decrypted block the length originally
			 * indicated by the sender.  This is to remove any
			 * padding bytes that the sender added to satisfy
			 * requirements of the crypto algorithm.
			 */
			bp->b_wptr = bp->b_rptr + tmi->rcmd_state.pt_len;

			newmp = bp;

			/*
			 * Reset our state to indicate we are ready
			 * for a new message.
			 */
			tmi->rcmd_state.pt_len = 0;
			tmi->rcmd_state.cd_len = 0;
		} else {
#ifdef DEBUG
			cmn_err(CE_WARN,
				"decrypt_rcmd: do_decrypt on %d bytes failed",
				(int)tmi->rcmd_state.cd_len);
#endif
			/*
			 * do_decrypt already handled failures, just
			 * return NULL.
			 */
			tmi->rcmd_state.pt_len = 0;
			tmi->rcmd_state.cd_len = 0;
			return (NULL);
		}
	}

	/*
	 * return the new message with the 'length' fields removed
	 */
	return (newmp);
}

/*
 * cryptmodrsrv
 *
 * Read queue service routine
 * Necessary because if the ready flag is not set
 * (via CRYPTIOCSTOP/CRYPTIOCSTART ioctls) then the data
 * must remain on queue and not be passed along.
 */
static int
cryptmodrsrv(queue_t *q)
{
	mblk_t *mp, *bp;
	struct tmodinfo *tmi = (struct tmodinfo *)q->q_ptr;

	while ((mp = getq(q)) != NULL) {
		switch (mp->b_datap->db_type) {
		case M_DATA:
			if (canputnext(q) && tmi->ready & CRYPT_READ_READY) {
				/*
				 * Process "rcmd" messages differently because
				 * they contain a 4 byte plaintext length
				 * id that needs to be removed.
				 */
				if (tmi->dec_data.method != CRYPT_METHOD_NONE &&
				    (tmi->dec_data.option_mask &
				    (CRYPTOPT_RCMD_MODE_V1 |
				    CRYPTOPT_RCMD_MODE_V2))) {
					mp = decrypt_rcmd_mblks(q, mp);
					if (mp)
						putnext(q, mp);
					continue;
				}
				if ((bp = msgpullup(mp, -1)) != NULL) {
					freemsg(mp);
					if (MBLKL(bp) > 0) {
						mp = do_decrypt(q, bp);
						if (mp != NULL)
							putnext(q, mp);
					}
				}
			} else {
				if (!putbq(q, mp)) {
					freemsg(mp);
				}
				return (0);
			}
			break;
		default:
			/*
			 * rput does not queue anything > QPCTL, so we don't
			 * need to check for it here.
			 */
			if (!canputnext(q)) {
				if (!putbq(q, mp))
					freemsg(mp);
				return (0);
			}
			putnext(q, mp);
			break;
		}
	}
	return (0);
}


/*
 * Read-side put procedure.
 */
static void
cryptmodrput(queue_t *rq, mblk_t *mp)
{
	switch (mp->b_datap->db_type) {
	case M_DATA:
		if (!putq(rq, mp)) {
			freemsg(mp);
		}
		break;
	case M_FLUSH:
		if (*mp->b_rptr & FLUSHR) {
			flushq(rq, FLUSHALL);
		}
		putnext(rq, mp);
		break;
	default:
		if (queclass(mp) < QPCTL) {
			if (rq->q_first != NULL || !canputnext(rq)) {
				if (!putq(rq, mp))
					freemsg(mp);
				return;
			}
		}
		putnext(rq, mp);
		break;
	}
}
