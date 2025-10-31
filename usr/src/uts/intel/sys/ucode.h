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
 *
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2022 Joyent, Inc.
 * Copyright 2025 Oxide Computer Company
 */

#ifndef	_SYS_UCODE_H
#define	_SYS_UCODE_H

#ifdef _KERNEL
#include <sys/cpuvar.h>
#include <sys/linker_set.h>
#endif
#include <sys/stdbool.h>
#include <sys/types.h>
#include <sys/priv.h>
#include <sys/processor.h>
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

#define	UCODE_KB(a)	((a) << 10)	/* KiB */
#define	UCODE_MB(a)	((a) << 20)	/* MiB */

/*
 * For a single microcode file, the following minimum and maximum sizes are
 * defined. Such limitations, while somewhat artificial, are not only to
 * provide better sanity checks, but also avoid wasting precious memory at
 * startup time as the microcode buffer for the first processor has to be
 * statically allocated.
 *
 * The last limit is for the concatenation of all the microcode binary files.
 */
#define	UCODE_MIN_SIZE			UCODE_KB(1)
#define	UCODE_MAX_SIZE			UCODE_MB(2)
#define	UCODE_MAX_COMBINED_SIZE		UCODE_MB(16)

#ifdef _KERNEL

extern ucode_errno_t ucode_get_rev(uint32_t *);
extern ucode_errno_t ucode_validate(uint8_t *, size_t);
extern ucode_errno_t ucode_update(uint8_t *, size_t);

/*
 * Microcode specific information per core
 */
typedef struct cpu_ucode_info {
	uint32_t	cui_platid;		/* platform id */
	uint32_t	cui_rev;		/* microcode revision */
	uint32_t	cui_pending_rev;	/* pending microcode revision */
	uint32_t	cui_boot_rev;		/* rev at kernel start */
	void		*cui_pending_ucode;	/* pending microcode update */
	size_t		cui_pending_size;	/* pending microcode size */
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
 * To register a microcode update method, a ucode_source_t instance should be
 * created and passed to UCODE_SOURCE() to include it in the list of sources
 * that are tried.
 */
typedef struct ucode_source {
	const char	*us_name;
	uint32_t	us_write_msr;
	bool		us_invalidate;
	bool		(*us_select)(cpu_t *);
	bool		(*us_capable)(cpu_t *);
	void		(*us_file_reset)(void);
	void		(*us_read_rev)(cpu_ucode_info_t *);
	void		(*us_load)(cpu_ucode_info_t *);
	ucode_errno_t	(*us_validate)(uint8_t *, size_t);
	ucode_errno_t	(*us_extract)(ucode_update_t *, uint8_t *, size_t);
	ucode_errno_t	(*us_locate)(cpu_t *, cpu_ucode_info_t *);
	ucode_errno_t	(*us_locate_fallback)(cpu_t *, cpu_ucode_info_t *);
} ucode_source_t;
#define	UCODE_SOURCE(x) DATA_SET(ucode_source_set, x)

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_UCODE_H */
