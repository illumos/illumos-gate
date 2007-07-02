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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_UCODE_H
#define	_SYS_UCODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/priv.h>
#include <sys/processor.h>
#ifndef _KERNEL
#include <limits.h>
#endif
#include <ucode/ucode_errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	/dev/ucode
 */
#define	UCODE_DRIVER_NAME	"ucode"
#define	UCODE_NODE_NAME		"ucode"
#define	UCODE_MINOR		((minor_t)0x3fffful)

/*
 * Where to install the microcode
 */
#define	UCODE_INSTALL_PATH		"platform/i86pc/ucode"
#define	UCODE_INSTALL_COMMON_PATH	".f"

/*
 * ioctl numbers
 */
#define	UCODE_IOC		(('u'<<24)|('c'<<16)|('o'<<8))

#define	UCODE_GET_VERSION	(UCODE_IOC|0)
#define	UCODE_UPDATE		(UCODE_IOC|1)

struct ucode_get_rev_struct {
	uint32_t *ugv_rev;		/* microcode revision array */
	int ugv_size;			/* size of the array */
	ucode_errno_t ugv_errno;	/* EUC error code */
};

struct ucode_write_struct {
	uint32_t uw_size;	/* size of the uw_code buffer */
	uint8_t *uw_ucode;	/* pointer to the undigested microcode */
	ucode_errno_t uw_errno;	/* EUC error code */
};

#if defined(_SYSCALL32_IMPL)

#include <sys/types32.h>

struct ucode_get_rev_struct32 {
	caddr32_t ugv_rev;		/* microcode revision array */
	int ugv_size;			/* size of the array */
	ucode_errno_t ugv_errno;	/* EUC error code */
};

struct ucode_write_struct32 {
	uint32_t uw_size;	/* size of the uw_code buffer */
	caddr32_t uw_ucode;	/* pointer to the undigested microcode */
	ucode_errno_t uw_errno;	/* EUC error code */
};

#endif	/* _SYSCALL32_IMPL */

/*
 * Microcode file information
 */
typedef struct ucode_header {
	uint32_t	uh_header_ver;
	uint32_t	uh_rev;
	uint32_t	uh_date;
	uint32_t	uh_signature;
	uint32_t	uh_checksum;
	uint32_t	uh_loader_ver;
	uint32_t	uh_proc_flags;
	uint32_t	uh_body_size;
	uint32_t	uh_total_size;
	uint32_t	uh_reserved[3];
} ucode_header_t;

typedef struct ucode_ext_sig {
	uint32_t	ues_signature;
	uint32_t	ues_proc_flags;
	uint32_t	ues_checksum;
} ucode_ext_sig_t;

typedef struct ucode_ext_table {
	uint32_t	uet_count;
	uint32_t	uet_checksum;
	uint32_t	uet_reserved[3];
	ucode_ext_sig_t uet_ext_sig[1];
} ucode_ext_table_t;

typedef struct ucode_file {
	ucode_header_t		uf_header;
	uint8_t			*uf_body;
	ucode_ext_table_t	*uf_ext_table;
} ucode_file_t;


#define	UCODE_SHORT_NAME_LEN	12	/* "32-bit-sig"-"8-bit-platid"\0 */
/*
 * Length of UCODE_INSTALL_COMMON_PATH/short-name
 *	strlen(UCODE_INSTALL_COMMON_PATH) + 1 + UCODE_SHORT_NAME_LEN
 * Use sizeof which will give us the additional byte for the '/' in between
 * the common path and the file name.
 */
#define	UCODE_COMMON_NAME_LEN	\
	(sizeof (UCODE_INSTALL_COMMON_PATH) + (UCODE_SHORT_NAME_LEN))
#define	UCODE_MAX_PATH_LEN	(PATH_MAX - UCODE_COMMON_NAME_LEN)


#define	UCODE_HEADER_SIZE	(sizeof (struct ucode_header))
#define	UCODE_EXT_TABLE_SIZE	(20)	/* 20-bytes */
#define	UCODE_EXT_SIG_SIZE	(sizeof (struct ucode_ext_sig))

#define	UCODE_KB(a)	((a) << 10)	/* KB */
#define	UCODE_MB(a)	((a) << 20)	/* MB */
#define	UCODE_DEFAULT_TOTAL_SIZE	UCODE_KB(2)
#define	UCODE_DEFAULT_BODY_SIZE		(UCODE_KB(2) - UCODE_HEADER_SIZE)

/*
 * For a single microcode file, the minimum size is 1K, maximum size is 16K.
 * Such limitations, while somewhat artificial, are not only to provide better
 * sanity checks, but also avoid wasting precious memory at startup time as the
 * microcode buffer for the first processor has to be statically allocated.
 *
 * For the concatenation of all the microcode binary files, the maximum size
 * is 16M.
 */
#define	UCODE_MIN_SIZE			UCODE_KB(1)
#define	UCODE_MAX_SIZE			UCODE_KB(16)
#define	UCODE_MAX_COMBINED_SIZE		UCODE_MB(16)

#define	UCODE_SIZE_CONVERT(size, default_size) \
	((size) == 0 ? (default_size) : (size))

#define	UCODE_BODY_SIZE(size) \
	UCODE_SIZE_CONVERT((size), UCODE_DEFAULT_BODY_SIZE)

#define	UCODE_TOTAL_SIZE(size) \
	UCODE_SIZE_CONVERT((size), UCODE_DEFAULT_TOTAL_SIZE)

#define	UCODE_MATCH(sig1, sig2, pf1, pf2) \
	(((sig1) == (sig2)) && \
	(((pf1) & (pf2)) || (((pf1) == 0) && ((pf2) == 0))))

extern ucode_errno_t ucode_header_validate(ucode_header_t *);
extern uint32_t ucode_checksum(uint32_t, uint32_t, uint8_t *);
extern ucode_errno_t ucode_validate(uint8_t *, int);
extern ucode_errno_t ucode_get_rev(uint32_t *);
extern ucode_errno_t ucode_update(uint8_t *, int);

#define	UCODE_MAX_VENDORS_NAME_LEN		20

#define	UCODE_VENDORS				\
static struct {					\
	char *filestr;				\
	char *vendorstr;			\
	int  supported;				\
} ucode_vendors[] = {				\
	{ "intel", "GenuineIntel", 1 },		\
	{ "amd", "AuthenticAMD", 0 },		\
	{ NULL, NULL, 0 }				\
}

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_UCODE_H */
