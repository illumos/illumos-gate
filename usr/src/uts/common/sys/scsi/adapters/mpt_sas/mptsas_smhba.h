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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * SM-HBA interfaces/definitions for MPT SAS driver.
 */

#ifndef _MPTSAS_SMHBA_H
#define	_MPTSAS_SMHBA_H
#ifdef	__cplusplus
extern "C" {
#endif

/* Leverage definition of data_type_t in nvpair.h */
#include <sys/nvpair.h>
#include <sys/scsi/adapters/mpt_sas/mptsas_var.h>

#define	MPTSAS_NUM_PHYS		"num-phys"
#define	MPTSAS_NUM_PHYS_HBA	"num-phys-hba"
#define	MPTSAS_SMHBA_SUPPORTED	"sm-hba-supported"
#define	MPTSAS_DRV_VERSION	"driver-version"
#define	MPTSAS_HWARE_VERSION	"hardware-version"
#define	MPTSAS_FWARE_VERSION	"firmware-version"
#define	MPTSAS_SUPPORTED_PROTOCOL	"supported-protocol"
#define	MPTSAS_VIRTUAL_PORT	"virtual-port"

#define	MPTSAS_MANUFACTURER	"Manufacturer"
#define	MPTSAS_SERIAL_NUMBER	"SerialNumber"
#define	MPTSAS_MODEL_NAME	"ModelName"
#define	MPTSAS_VARIANT		"variant"

#define	IS_ATAPI_DEVICE(x)	((x) & 0x2000)
#define	IS_SATA_DEVICE(x)	((x) & 0x80)
#define	DEVINFO_DIRECT_ATTACHED	0x0800

/*
 * Interfaces to add properties required for SM-HBA
 *
 * _add_xxx_prop() interfaces add only 1 prop that is specified in the args.
 * _set_xxx_props() interfaces add more than 1 prop for a set of phys/devices.
 */
int mptsas_smhba_setup(mptsas_t *);
void mptsas_smhba_show_phy_info(mptsas_t *);
void mptsas_smhba_set_all_phy_props(mptsas_t *mpt, dev_info_t *dip,
    uint8_t phy_nums, mptsas_phymask_t phy_mask, uint16_t *attached_devhdl);
void mptsas_smhba_set_one_phy_props(mptsas_t *mpt, dev_info_t *dip,
    uint8_t phy_id, uint16_t *attached_devhdl);
void mptsas_smhba_log_sysevent(mptsas_t *mpt, char *subclass, char *etype,
    smhba_info_t *phyp);
void
mptsas_create_phy_stats(mptsas_t *mpt, char *iport, dev_info_t *dip);
int mptsas_update_phy_stats(kstat_t *ks, int rw);
void mptsas_destroy_phy_stats(mptsas_t *mpt);
int mptsas_smhba_phy_init(mptsas_t *mpt);
int mptsas_smhba_phy_state_update(mptsas_t *mpt, uint8_t phy);
#ifdef	__cplusplus
}
#endif
#endif	/* _MPTSAS_SMHBA_H */
