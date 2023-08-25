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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef	_SYS_UCODE_INTEL_H
#define	_SYS_UCODE_INTEL_H

#include <sys/types.h>
#include <ucode/ucode_errno.h>

#ifdef __cplusplus
extern "C" {
#endif

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

/*					"32-bit-sig"-"8-bit-platid"\0 */
#define	UCODE_MAX_NAME_LEN_INTEL	(sizeof ("XXXXXXXX-XX"))

#define	UCODE_HEADER_SIZE_INTEL		(sizeof (struct ucode_header_intel))
#define	UCODE_EXT_TABLE_SIZE_INTEL	(20)	/* 20-bytes */
#define	UCODE_EXT_SIG_SIZE_INTEL	(sizeof (struct ucode_ext_sig_intel))

#define	UCODE_DEFAULT_TOTAL_SIZE	UCODE_KB(2)
#define	UCODE_DEFAULT_BODY_SIZE		(UCODE_KB(2) - UCODE_HEADER_SIZE_INTEL)

#define	UCODE_SIZE_CONVERT(size, default_size) \
	((size) == 0 ? (default_size) : (size))

#define	UCODE_BODY_SIZE_INTEL(size) \
	UCODE_SIZE_CONVERT((size), UCODE_DEFAULT_BODY_SIZE)

#define	UCODE_TOTAL_SIZE_INTEL(size)			\
	UCODE_SIZE_CONVERT((size), UCODE_DEFAULT_TOTAL_SIZE)

#define	UCODE_MATCH_INTEL(sig1, sig2, pf1, pf2) \
	(((sig1) == (sig2)) && \
	(((pf1) & (pf2)) || (((pf1) == 0) && ((pf2) == 0))))

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_UCODE_INTEL_H */
