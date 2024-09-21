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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_NVME_KIOXIA_H
#define	_SYS_NVME_KIOXIA_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * This header contains all of the current vendor-specific entries for known
 * Kioxia devices as well as common structures and definitions that are shared
 * across multiple device families.
 */

#include <sys/nvme/kioxia_cd8.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	KIOXIA_PCI_VID	0x1e0f

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_KIOXIA_H */
