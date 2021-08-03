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
 * Copyright 2021 Oxide Computer Company
 */

#ifndef _AMDZEN_CLIENT_H
#define	_AMDZEN_CLIENT_H

/*
 * This header provides client routines to clients of the amdzen nexus driver.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int amdzen_c_smn_read32(uint_t, uint32_t, uint32_t *);
extern int amdzen_c_smn_write32(uint_t, uint32_t, uint32_t);
extern uint_t amdzen_c_df_count(void);
extern int amdzen_c_df_read32(uint_t, uint8_t, uint8_t, uint16_t, uint32_t *);
extern int amdzen_c_df_read64(uint_t, uint8_t, uint8_t, uint16_t, uint64_t *);

#ifdef __cplusplus
}
#endif

#endif /* _AMDZEN_CLIENT_H */
