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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * des_crypt.c, DES encryption library routines
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <rpc/trace.h>
#include <rpc/des_crypt.h>
/* EXPORT DELETE START */
#ifdef sun
#include <sys/ioctl.h>
#include <sys/des.h>
#ifdef _KERNEL
#include <sys/conf.h>
#define	getdesfd() (cdevsw[11].d_open(0, 0) ? -1 : 0)
#define	ioctl(a, b, c) (cdevsw[11].d_ioctl(0, b, c, 0) ? -1 : 0)
#ifndef CRYPT
#define	_des_crypt(a, b, c) 0
#endif
#else
#define	getdesfd()	(open("/dev/des", 0, 0))
#endif
#else
#include <des/des.h>
#endif
/* EXPORT DELETE END */
#include <rpc/rpc.h>
/* EXPORT DELETE START */

extern int __des_crypt();

static int common_crypt();

/*
 * To see if chip is installed
 */
#define	UNOPENED (-2)
static int g_desfd = UNOPENED;


/*
 * Copy 8 bytes
 */
#define	COPY8(src, dst) { \
	register char *a = (char *) dst; \
	register char *b = (char *) src; \
	*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
	*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
}

/*
 * Copy multiple of 8 bytes
 */
#define	DESCOPY(src, dst, len) { \
	register char *a = (char *) dst; \
	register char *b = (char *) src; \
	register int i; \
	for (i = (int) len; i > 0; i -= 8) { \
		*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
		*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
	} \
}
/* EXPORT DELETE END */

/*
 * CBC mode encryption
 */
int
cbc_crypt(char *key, char *buf, size_t len, unsigned int mode, char *ivec)
{
/* EXPORT DELETE START */
	int err;
	struct desparams dp;

	trace3(TR_cbc_crypt, 0, len, mode);
	dp.des_mode = CBC;
	COPY8(ivec, dp.des_ivec);
	err = common_crypt(key, buf, len, mode, &dp);
	COPY8(dp.des_ivec, ivec);
	trace3(TR_cbc_crypt, 1, len, mode);
	return (err);
#if 0
/* EXPORT DELETE END */
	return (DESERR_HWERROR);
/* EXPORT DELETE START */
#endif
/* EXPORT DELETE END */
}


/*
 * ECB mode encryption
 */
int
ecb_crypt(char *key, char *buf, size_t len, unsigned int mode)
{
/* EXPORT DELETE START */
	struct desparams dp;
	int dummy;

	trace3(TR_ecb_crypt, 0, len, mode);
	dp.des_mode = ECB;
	dummy = common_crypt(key, buf, len, mode, &dp);
	trace3(TR_ecb_crypt, 1, len, mode);
	return (dummy);
#if 0
/* EXPORT DELETE END */
	return (DESERR_HWERROR);
/* EXPORT DELETE START */
#endif
/* EXPORT DELETE END */
}


/* EXPORT DELETE START */

/*
 * Common code to cbc_crypt() & ecb_crypt()
 */
static int
common_crypt(key, buf, len, mode, desp)
	char *key;
	char *buf;
	register unsigned len;
	unsigned mode;
	register struct desparams *desp;
{
	register int desdev;
	register int res;

	trace3(TR_common_crypt, 0, len, mode);
	if ((len % 8) != 0 || len > DES_MAXDATA) {
		trace3(TR_common_crypt, 1, len, mode);
		return (DESERR_BADPARAM);
	}
	desp->des_dir =
		((mode & DES_DIRMASK) == DES_ENCRYPT) ? ENCRYPT : DECRYPT;

	desdev = mode & DES_DEVMASK;
	COPY8(key, desp->des_key);
#ifdef sun
	if (desdev == DES_HW) {
		if (g_desfd < 0) {
			if (g_desfd == -1 || (g_desfd = getdesfd()) < 0) {
				goto software;	/* no hardware device */
			}
		}

		/*
		 * hardware
		 */
		desp->des_len = len;
		if (len <= DES_QUICKLEN) {
			DESCOPY(buf, desp->des_data, len);
			res = ioctl(g_desfd, DESIOCQUICK, (char *) desp);
			DESCOPY(desp->des_data, buf, len);
		} else {
			desp->des_buf = (u_char *) buf;
			res = ioctl(g_desfd, DESIOCBLOCK, (char *) desp);
		}
		trace3(TR_common_crypt, 1, len, mode);
		return (res == 0 ? DESERR_NONE : DESERR_HWERROR);
	}
software:
#endif
	/*
	 * software
	 */
	if (!__des_crypt(buf, len, desp)) {
		trace3(TR_common_crypt, 1, len, mode);
		return (DESERR_HWERROR);
	}
	trace3(TR_common_crypt, 1, len, mode);
	return (desdev == DES_SW ? DESERR_NONE : DESERR_NOHWDEVICE);
}
/* EXPORT DELETE END */

/* EXPORT DELETE START */
static int
desN_crypt(des_block keys[], int keynum, char *buf, unsigned int len,
		unsigned int mode, char *ivec)
{
	unsigned int m = mode & (DES_ENCRYPT | DES_DECRYPT);
	unsigned int flags = mode & ~(DES_ENCRYPT | DES_DECRYPT);
	des_block svec, dvec;
	int i, j, stat;

	if (keynum < 1)
		return (DESERR_BADPARAM);

	(void) memcpy(svec.c, ivec, sizeof (des_block));
	for (i = 0; i < keynum; i++) {
		j = (mode & DES_DECRYPT) ? keynum - 1 - i : i;
		stat = cbc_crypt(keys[j].c, buf, len, m | flags, ivec);
		if (mode & DES_DECRYPT && i == 0)
			(void) memcpy(dvec.c, ivec, sizeof (des_block));

		if (DES_FAILED(stat))
			return (stat);

		m = (m == DES_ENCRYPT ? DES_DECRYPT : DES_ENCRYPT);

		if ((mode & DES_DECRYPT) || i != keynum - 1 || i%2)
			(void) memcpy(ivec, svec.c, sizeof (des_block));
	}
	if (keynum % 2 == 0)
		stat = cbc_crypt(keys[0].c, buf, len, mode, ivec);

	if (mode & DES_DECRYPT)
		(void) memcpy(ivec, dvec.c, sizeof (des_block));

	return (stat);
}
/* EXPORT DELETE END */



int
__cbc_triple_crypt(des_block keys[], char *buf,  u_int len,
			u_int mode, char *ivec)
{
/* EXPORT DELETE START */
	trace3(T___cbc_triple_crypt, 0, len, mode);
	return (desN_crypt(keys, 3, buf, len, mode, ivec));
#if 0
/* EXPORT DELETE END */
	return (DESERR_HWERROR);
/* EXPORT DELETE START */
#endif
/* EXPORT DELETE END */
}
