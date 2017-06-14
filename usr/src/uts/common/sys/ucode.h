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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_UCODE_H
#define	_SYS_UCODE_H

#ifdef _KERNEL
#include <sys/cpuvar.h>
#endif
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
 * AMD Microcode file information
 */
typedef struct ucode_header_amd {
	uint32_t uh_date;
	uint32_t uh_patch_id;
	uint32_t uh_internal; /* patch data id & length, init flag */
	uint32_t uh_cksum;
	uint32_t uh_nb_id;
	uint32_t uh_sb_id;
	uint16_t uh_cpu_rev;
	uint8_t  uh_nb_rev;
	uint8_t  uh_sb_rev;
	uint32_t uh_bios_rev;
	uint32_t uh_match[8];
} ucode_header_amd_t;

typedef struct ucode_file_amd {
#ifndef __xpv
	ucode_header_amd_t uf_header;
	uint8_t uf_data[896];
	uint8_t uf_resv[896];
	uint8_t uf_code_present;
	uint8_t uf_code[191];
	uint8_t uf_encr[2048];
#else
	uint8_t *ucodep;
	uint32_t usize;
#endif
} ucode_file_amd_t;

typedef struct ucode_eqtbl_amd {
	uint32_t ue_inst_cpu;
	uint32_t ue_fixed_mask;
	uint32_t ue_fixed_comp;
	uint16_t ue_equiv_cpu;
	uint16_t ue_reserved;
} ucode_eqtbl_amd_t;

/*
 * Intel Microcode file information
 */
typedef struct ucode_header_intel {
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
} ucode_header_intel_t;

typedef struct ucode_ext_sig_intel {
	uint32_t	ues_signature;
	uint32_t	ues_proc_flags;
	uint32_t	ues_checksum;
} ucode_ext_sig_intel_t;

typedef struct ucode_ext_table_intel {
	uint32_t	uet_count;
	uint32_t	uet_checksum;
	uint32_t	uet_reserved[3];
	ucode_ext_sig_intel_t uet_ext_sig[1];
} ucode_ext_table_intel_t;

typedef struct ucode_file_intel {
	ucode_header_intel_t	*uf_header;
	uint8_t			*uf_body;
	ucode_ext_table_intel_t	*uf_ext_table;
} ucode_file_intel_t;

/*
 * common container
 */
typedef union ucode_file {
	ucode_file_amd_t *amd;
	ucode_file_intel_t intel;
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


#define	UCODE_HEADER_SIZE_INTEL		(sizeof (struct ucode_header_intel))
#define	UCODE_EXT_TABLE_SIZE_INTEL	(20)	/* 20-bytes */
#define	UCODE_EXT_SIG_SIZE_INTEL	(sizeof (struct ucode_ext_sig_intel))

#define	UCODE_KB(a)	((a) << 10)	/* KB */
#define	UCODE_MB(a)	((a) << 20)	/* MB */
#define	UCODE_DEFAULT_TOTAL_SIZE	UCODE_KB(2)
#define	UCODE_DEFAULT_BODY_SIZE		(UCODE_KB(2) - UCODE_HEADER_SIZE_INTEL)

/*
 * For a single microcode file, the minimum size is 1K, maximum size is 128K.
 * Such limitations, while somewhat artificial, are not only to provide better
 * sanity checks, but also avoid wasting precious memory at startup time as the
 * microcode buffer for the first processor has to be statically allocated.
 *
 * For the concatenation of all the microcode binary files, the maximum size
 * is 16M.
 */
#define	UCODE_MIN_SIZE			UCODE_KB(1)
#define	UCODE_MAX_SIZE			UCODE_KB(128)
#define	UCODE_MAX_COMBINED_SIZE		UCODE_MB(16)

#define	UCODE_SIZE_CONVERT(size, default_size) \
	((size) == 0 ? (default_size) : (size))

#define	UCODE_BODY_SIZE_INTEL(size) \
	UCODE_SIZE_CONVERT((size), UCODE_DEFAULT_BODY_SIZE)

#define	UCODE_TOTAL_SIZE_INTEL(size)			\
	UCODE_SIZE_CONVERT((size), UCODE_DEFAULT_TOTAL_SIZE)

#define	UCODE_MATCH_INTEL(sig1, sig2, pf1, pf2) \
	(((sig1) == (sig2)) && \
	(((pf1) & (pf2)) || (((pf1) == 0) && ((pf2) == 0))))

extern ucode_errno_t ucode_header_validate_intel(ucode_header_intel_t *);
extern uint32_t ucode_checksum_intel(uint32_t, uint32_t, uint8_t *);

extern ucode_errno_t ucode_validate_amd(uint8_t *, int);
extern ucode_errno_t ucode_validate_intel(uint8_t *, int);

#ifdef _KERNEL
extern ucode_errno_t ucode_get_rev(uint32_t *);
extern ucode_errno_t ucode_update(uint8_t *, int);

/*
 * Microcode specific information per core
 */
typedef struct cpu_ucode_info {
	uint32_t	cui_platid;	/* platform id */
	uint32_t	cui_rev;	/* microcode revision */
} cpu_ucode_info_t;

/*
 * Data structure used for xcall
 */
typedef struct ucode_update {
	uint32_t		sig;	/* signature */
	cpu_ucode_info_t	info;	/* ucode info */
	uint32_t		expected_rev;
	uint32_t		new_rev;
	uint8_t			*ucodep; /* pointer to ucode */
	uint32_t		usize;
} ucode_update_t;

/*
 * Microcode kernel operations
 */
struct ucode_ops {
	uint32_t	write_msr;
	int		(*capable)(cpu_t *);
	void		(*file_reset)(ucode_file_t *, processorid_t);
	void		(*read_rev)(cpu_ucode_info_t *);
	uint32_t	(*load)(ucode_file_t *, cpu_ucode_info_t *, cpu_t *);
	ucode_errno_t	(*validate)(uint8_t *, int);
	ucode_errno_t	(*extract)(ucode_update_t *, uint8_t *, int);
	ucode_errno_t	(*locate)(cpu_t *, cpu_ucode_info_t *, ucode_file_t *);
};
#else

#define	UCODE_MAX_VENDORS_NAME_LEN		20

#define	UCODE_VENDORS				\
static struct {					\
	char *filestr;				\
	char *extstr;				\
	char *vendorstr;			\
	int  supported;				\
} ucode_vendors[] = {				\
	{ "intel", "txt", "GenuineIntel", 1 },	\
	{ "amd", "bin", "AuthenticAMD", 1 },	\
	{ NULL, NULL, NULL, 0 }			\
}

/*
 * Microcode user operations
 */
struct ucode_ops {
	int		(*convert)(const char *, uint8_t *, size_t);
	ucode_errno_t	(*gen_files)(uint8_t *, int, char *);
	ucode_errno_t	(*validate)(uint8_t *, int);
};
#endif

extern const struct ucode_ops *ucode;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_UCODE_H */
