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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * This header file is private to illumos and should not be shipped.
 */

#ifndef	_PCIDB_H
#define	_PCIDB_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	PCIDB_VERSION	1

typedef struct pcidb_hdl pcidb_hdl_t;
typedef struct pcidb_vendor pcidb_vendor_t;
typedef struct pcidb_device pcidb_device_t;
typedef struct pcidb_subvd pcidb_subvd_t;

extern pcidb_hdl_t *pcidb_open(int);
extern void pcidb_close(pcidb_hdl_t *);

extern pcidb_vendor_t *pcidb_lookup_vendor(pcidb_hdl_t *, uint16_t);
extern pcidb_vendor_t *pcidb_vendor_iter(pcidb_hdl_t *);
extern pcidb_vendor_t *pcidb_vendor_iter_next(pcidb_vendor_t *);

extern const char *pcidb_vendor_name(pcidb_vendor_t *);
extern uint16_t pcidb_vendor_id(pcidb_vendor_t *);

extern pcidb_device_t *pcidb_lookup_device(pcidb_hdl_t *, uint16_t, uint16_t);
extern pcidb_device_t *pcidb_lookup_device_by_vendor(pcidb_vendor_t *,
    uint16_t);
extern pcidb_device_t *pcidb_device_iter(pcidb_vendor_t *);
extern pcidb_device_t *pcidb_device_iter_next(pcidb_device_t *);

extern const char *pcidb_device_name(pcidb_device_t *);
extern uint16_t pcidb_device_id(pcidb_device_t *);
extern pcidb_vendor_t *pcidb_device_vendor(pcidb_device_t *);

extern pcidb_subvd_t *pcidb_lookup_subvd(pcidb_hdl_t *, uint16_t, uint16_t,
    uint16_t, uint16_t);
extern pcidb_subvd_t *pcidb_lookup_subvd_by_vendor(pcidb_vendor_t *, uint16_t,
    uint16_t, uint16_t);
extern pcidb_subvd_t *pcidb_lookup_subvd_by_device(pcidb_device_t *, uint16_t,
    uint16_t);
extern pcidb_subvd_t *pcidb_subvd_iter(pcidb_device_t *);
extern pcidb_subvd_t *pcidb_subvd_iter_next(pcidb_subvd_t *);

extern const char *pcidb_subvd_name(pcidb_subvd_t *);
extern uint16_t pcidb_subvd_svid(pcidb_subvd_t *);
extern uint16_t pcidb_subvd_sdid(pcidb_subvd_t *);
extern pcidb_device_t *pcidb_subvd_device(pcidb_subvd_t *);
extern pcidb_vendor_t *pcidb_subvd_vendor(pcidb_subvd_t *);

#ifdef __cplusplus
}
#endif

#endif /* _PCIDB_H */
