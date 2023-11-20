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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _SPD_COMMON_H
#define	_SPD_COMMON_H

/*
 * This contains common definitions that are shared across all SPD revisions.
 * This header will also pull in the various version specific pieces of
 * information.
 */

#include <sys/bitext.h>
#include <libjedec.h>

#include "spd_ddr4.h"
#include "spd_ddr5.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This enumeration covers the DRAM Device Type key byte and is consistent
 * across all SPD revisions. This must be used first when identifying devices.
 */

/*
 * This is the common byte that is used across all the different SPD types to
 * determine the type of DRAM present. Its values are covered in the
 * 'spd_dram_type_t' enumeration found in libjedec.h.
 */
#define	SPD_DRAM_TYPE	0x002

/*
 * Common definitions for taking apart a JEDEC manufacturer ID. The first byte
 * is always a continuation code with a parity while the second byte is the
 * specific entry for that continuation code. The continuation code and the id
 * within a group tie into the common libjedec vendor decoding table.
 */
#define	SPD_MFG_ID0_PAR(r)	bitx8(r, 7, 7)
#define	SPD_MFG_ID0_CONT(r)	bitx8(r, 6, 0)

/*
 * DDR4 and DDR5 have a DRAM stepping revision. This is the sentinel that
 * indicates that there is no value.
 */
#define	SPD_DRAM_STEP_NOINFO	0xff

#ifdef __cplusplus
}
#endif

#endif /* _SPD_COMMON_H */
