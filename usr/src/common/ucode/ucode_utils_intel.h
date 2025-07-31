/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _COMMON_UCODE_UTILS_INTEL_H
#define	_COMMON_UCODE_UTILS_INTEL_H

#include <ucode/ucode_errno.h>

#ifdef __cplusplus
extern "C" {
#endif

extern ucode_errno_t ucode_header_validate_intel(ucode_header_intel_t *);
extern uint32_t ucode_checksum_intel(uint32_t, uint32_t, uint8_t *);
extern uint32_t ucode_checksum_intel_extsig(ucode_header_intel_t *,
    ucode_ext_sig_intel_t *);
extern ucode_errno_t ucode_validate_intel(uint8_t *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _COMMON_UCODE_UTILS_INTEL_H */
