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

/*
 * SCSI device structure.
 *
 *	All SCSI target drivers will have one of these per target/lun/sfunc.
 *	It will be allocated and initialized by the SCSA HBA nexus code
 *	for each SCSI target dev_info_t node and stored as driver private data
 *	in that target device's dev_info_t (and thus can be retrieved by
 *	the function ddi_get_driver_private).
 */
#ifndef	_SYS_SCSI_CONF_DEVICE_H
#define	_SYS_SCSI_CONF_DEVICE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/scsi/scsi_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct scsi_device {
	/*
	 * Routing info for this device.  Contains a_hba_tran pointer to
	 * the transport and decoded addressing for SPI devices.
	 */
	struct scsi_address	sd_address;

	/*
	 * Cross-reference to target device's dev_info_t.
	 */
	dev_info_t		*sd_dev;

	/*
	 * Mutex for this device, initialized by
	 * parent prior to calling probe or attach
	 * routine.
	 */
	kmutex_t		sd_mutex;

	/*
	 * Reserved, do not use.
	 */
	void			*sd_reserved;


	/*
	 * If scsi_slave is used to probe out this device,
	 * a scsi_inquiry data structure will be allocated
	 * and an INQUIRY command will be run to fill it in.
	 *
	 * The allocation will be done via ddi_iopb_alloc,
	 * so any manual freeing may be done by ddi_iopb_free.
	 *
	 * The inquiry data is allocated/refreshed by
	 * scsi_probe/scsi_slave and freed by uninitchild (inquiry
	 * data is no longer freed by scsi_unprobe/scsi_unslave).
	 *
	 * Additional device identity information may be available
	 * as properties of sd_dev.
	 */
	struct scsi_inquiry	*sd_inq;

	/*
	 * Place to point to an extended request sense buffer.
	 * The target driver is responsible for managing this.
	 */
	struct scsi_extended_sense	*sd_sense;

	/*
	 * More detailed information is 'private' information. Typically a
	 * pointer to target driver private soft_state information for the
	 * device.  This soft_state is typically established in target driver
	 * attach(9E), and freed in the target driver detach(9E).
	 */
	caddr_t			sd_private;


	/*
	 * FMA capabilities of scsi_device.
	 */
	int			sd_fm_capable;

#ifdef	SCSI_SIZE_CLEAN_VERIFY
	/*
	 * Must be last: Building a driver with-and-without
	 * -DSCSI_SIZE_CLEAN_VERIFY, and checking driver modules for
	 * differences with a tools like 'wsdiff' allows a developer to verify
	 * that their driver has no dependencies on scsi*(9S) size.
	 */
	int			_pad[8];
#endif	/* SCSI_SIZE_CLEAN_VERIFY */
};

#ifdef	_KERNEL
int	scsi_slave(struct scsi_device *devp, int (*callback)(void));
int	scsi_probe(struct scsi_device *devp, int (*callback)(void));
void	scsi_unslave(struct scsi_device *devp);
void	scsi_unprobe(struct scsi_device *devp);
size_t	scsi_device_size();			/* private */
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_CONF_DEVICE_H */
