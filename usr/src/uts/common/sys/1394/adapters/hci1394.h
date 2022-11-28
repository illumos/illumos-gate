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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_1394_ADAPTERS_HCI1394_H
#define	_SYS_1394_ADAPTERS_HCI1394_H


/*
 * hci1394.h
 *    This file contains general defines and function prototypes for things
 *    that did not warrant separate header files.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/1394/ieee1394.h>
#include <sys/1394/h1394.h>

#include <sys/1394/adapters/hci1394_def.h>
#include <sys/1394/adapters/hci1394_drvinfo.h>
#include <sys/1394/adapters/hci1394_tlist.h>
#include <sys/1394/adapters/hci1394_tlabel.h>
#include <sys/1394/adapters/hci1394_ioctl.h>
#include <sys/1394/adapters/hci1394_rio_regs.h>
#include <sys/1394/adapters/hci1394_ohci.h>
#include <sys/1394/adapters/hci1394_descriptors.h>
#include <sys/1394/adapters/hci1394_csr.h>
#include <sys/1394/adapters/hci1394_vendor.h>
#include <sys/1394/adapters/hci1394_buf.h>
#include <sys/1394/adapters/hci1394_q.h>
#include <sys/1394/adapters/hci1394_async.h>
#include <sys/1394/adapters/hci1394_ixl.h>
#include <sys/1394/adapters/hci1394_isoch.h>
#include <sys/1394/id1394.h>
#include <sys/1394/adapters/hci1394_state.h>


/* Number of initial states to setup. Used in call to ddi_soft_state_init() */
#define	HCI1394_INITIAL_STATES		3

/*
 * Size of the Address Map Array passed to the Service Layer. There are 4
 * sections in the OpenHCI address space. They are Physical, Posted Write,
 * Normal, and CSR space.
 */
#define	HCI1394_ADDR_MAP_SIZE		4

/* Macro to align address on a quadlet boundry */
#define	HCI1394_ALIGN_QUAD(addr) (((addr) + 3) & 0xFFFFFFFC)

/* These functions can be found in hci1394_attach.c */
int hci1394_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);

/* These functions can be found in hci1394_detach.c */
int hci1394_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
void hci1394_detach_hardware(hci1394_state_t *soft_state);
void hci1394_pci_fini(hci1394_state_t *soft_state);
void hci1394_soft_state_fini(hci1394_state_t *soft_state);
int hci1394_quiesce(dev_info_t *dip);

/* These functions can be found in hci1394_misc.c */
hci1394_statevar_t hci1394_state(hci1394_drvinfo_t *drvinfo);
int hci1394_state_set(hci1394_drvinfo_t *drvinfo, hci1394_statevar_t state);
int hci1394_open(dev_t *devp, int flag, int otyp, cred_t *credp);
int hci1394_close(dev_t dev, int flag, int otyp, cred_t *credp);
void hci1394_shutdown(dev_info_t *dip);
int hci1394_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result);

/* These functions can be found in hci1394_ioctl.c */
int hci1394_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp);

/* These functions can be found in hci1394_isr.c */
int hci1394_isr_init(hci1394_state_t *soft_state);
void hci1394_isr_fini(hci1394_state_t *soft_state);
int hci1394_isr_handler_init(hci1394_state_t *soft_state);
void hci1394_isr_handler_fini(hci1394_state_t *soft_state);
void hci1394_isr_mask_setup(hci1394_state_t *soft_state);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_H */
