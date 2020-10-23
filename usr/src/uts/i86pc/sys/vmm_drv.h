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
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

#ifndef _VMM_DRV_H_
#define	_VMM_DRV_H_

#ifdef	_KERNEL

#include <sys/file.h>
#include <sys/stdbool.h>

struct vmm_hold;
typedef struct vmm_hold vmm_hold_t;

struct vmm_lease;
typedef struct vmm_lease vmm_lease_t;

/*
 * Because of tangled headers, this definitions mirrors its ioport_handler_t
 * counterpart in vmm_kernel.h.
 */
typedef int (*vmm_drv_iop_cb_t)(void *, bool, uint16_t, uint8_t, uint32_t *);

extern int vmm_drv_hold(file_t *, cred_t *, vmm_hold_t **);
extern void vmm_drv_rele(vmm_hold_t *);
extern boolean_t vmm_drv_release_reqd(vmm_hold_t *);

extern vmm_lease_t *vmm_drv_lease_sign(vmm_hold_t *, boolean_t (*)(void *),
    void *);
extern void vmm_drv_lease_break(vmm_hold_t *, vmm_lease_t *);
extern boolean_t vmm_drv_lease_expired(vmm_lease_t *);

extern void *vmm_drv_gpa2kva(vmm_lease_t *, uintptr_t, size_t);
extern int vmm_drv_msi(vmm_lease_t *, uint64_t, uint64_t);

extern int vmm_drv_ioport_hook(vmm_hold_t *, uint16_t, vmm_drv_iop_cb_t, void *,
    void **);
extern void vmm_drv_ioport_unhook(vmm_hold_t *, void **);
#endif /* _KERNEL */

#endif /* _VMM_DRV_H_ */
