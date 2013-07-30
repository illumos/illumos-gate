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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * DES encryption library routines
 */

#include <sys/types.h>
#include <rpc/des_crypt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#ifdef sun
#include <sys/ioctl.h>
#include <sys/des.h>
#ifdef _KERNEL
#include <sys/conf.h>
#define	getdesfd() (cdevsw[11].d_open(0, 0) ? -1 : 0)
#define	ioctl(a, b, c) (cdevsw[11].d_ioctl(0, b, c, 0) ? -1 : 0)
#ifndef CRYPT
#define	__des_crypt(a, b, c) 0
#endif
#else
#define	getdesfd()	(open("/dev/des", 0, 0))
#endif
#else
#include <des/des.h>
#endif

#include "des_soft.h"

/*
 * To see if chip is installed
 */
#define	UNOPENED (-2)

/*
 * Copy 8 bytes
 */
#define	COPY8(src, dst) { \
	char *a = (char *)dst; \
	char *b = (char *)src; \
	*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
	*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
}

/*
 * Copy multiple of 8 bytes
 */
#define	DESCOPY(src, dst, len) { \
	char *a = (char *)dst; \
	char *b = (char *)src; \
	int i; \
	for (i = (int)len; i > 0; i -= 8) { \
		*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
		*a++ = *b++; *a++ = *b++; *a++ = *b++; *a++ = *b++; \
	} \
}
static int common_crypt(char *, char *, unsigned, unsigned, struct desparams *);

/*
 * CBC mode encryption
 */
int
cbc_crypt(char *key, char *buf, size_t len, unsigned int mode, char *ivec)
{
	int err = 0;
	struct desparams dp;

	dp.des_mode = CBC;
	COPY8(ivec, dp.des_ivec);
	err = common_crypt(key, buf, len, mode, &dp);
	COPY8(dp.des_ivec, ivec);
	return (err);
}


/*
 * ECB mode encryption
 */
int
ecb_crypt(char *key, char *buf, size_t len, unsigned int mode)
{
	int ret = 0;
	struct desparams dp;

	dp.des_mode = ECB;
	ret = common_crypt(key, buf, len, mode, &dp);
	return (ret);
}


/*
 * Common code to cbc_crypt() & ecb_crypt()
 */
static int
common_crypt(char *key, char *buf, unsigned len,
    unsigned mode, struct desparams *desp)
{
	int desdev;
	int res;
	int g_desfd = UNOPENED;

	if ((len % 8) != 0 || len > DES_MAXDATA) {
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
			res = ioctl(g_desfd, (int)DESIOCQUICK, (char *)desp);
			DESCOPY(desp->des_data, buf, len);
		} else {
			desp->des_buf = (uchar_t *)buf;
			res = ioctl(g_desfd, (int)DESIOCBLOCK, (char *)desp);
		}
		return (res == 0 ? DESERR_NONE : DESERR_HWERROR);
	}
software:
#endif
	/*
	 * software
	 */
	if (!__des_crypt(buf, len, desp)) {
		return (DESERR_HWERROR);
	}
	return (desdev == DES_SW ? DESERR_NONE : DESERR_NOHWDEVICE);
}
