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

#ifndef _IBDMA_H
#define	_IBDMA_H

/*
 * ibdma.h
 *
 * Device Management Agent prototypes and structures shared with
 * consumer (I/O Controller) via client API.
 */

/*
 * The Infiniband Device Management Agent manages an I/O Unit
 * for each IB HCA, providing a common view to of the I/O Unit
 * that presents protocol specific I/O Controllers.
 *
 * By default, the I/O Unit is unpopulated with I/O Controllers.  Each
 * underlying protocol transport registers their I/O Controller with
 * the respective I/O Unit (HCA) providing their I/O Controller profile
 * and the services they are making available.  As services change, the
 * the transport protocol calls back into the IB DMA to update their
 * profile and services.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ib/mgt/ibmf/ibmf.h>
#include <sys/ib/mgt/ib_dm_attr.h>

typedef enum ibdma_status_e {
	IBDMA_SUCCESS		= 0,	/* good status */
	IBDMA_IOC_DUPLICATE,		/* IOC GUID already exists */
	IBDMA_IOU_FULL,			/* No slots available in IOU */
	IBDMA_BAD_IOC_PROFILE,		/* IOC profile disparity */
	IBDMA_BAD_PARAM			/* Invalid function parameter */
} ibdma_status_t;

/*
 * I/O Controller Provider API.
 *
 * The DM Agent responds to I/O Unit requests on all IB fabric ports
 * in the system, setting each ports "isDeviceManagementSupported" bit.
 *
 * I/O Controllers must register their IOC profile and associated
 * services with the DM Agent.  The DM Agent will assign a
 * I/O Unit slot to the I/O Controller at that time.
 */
typedef void*  ibdma_hdl_t;

/*
 * Register an IOC.
 *
 * Returns a handle used to un-register or update the IOC
 * profile/services information.
 */
ibdma_hdl_t  ibdma_ioc_register(ib_guid_t ioc_guid,
	ib_dm_ioc_ctrl_profile_t *profile, ib_dm_srv_t *services);

/*
 * Un-Register an IOC.
 */
ibdma_status_t ibdma_ioc_unregister(ibdma_hdl_t hdl);

/*
 * Update a previously register IOC profile/services.
 */
ibdma_status_t ibdma_ioc_update(ibdma_hdl_t hdl,
	ib_dm_ioc_ctrl_profile_t *profile, ib_dm_srv_t *services);

#ifdef	__cplusplus
}
#endif

#endif /* _IBDMA_H */
