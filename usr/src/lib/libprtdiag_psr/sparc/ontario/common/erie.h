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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Sun4v Platform header file.
 *
 * 	called when :
 *      machine_type ==  erie
 *
 */

#ifndef _ERIE_H
#define	_ERIE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	ERIE_PLATFORM			"SUNW,Sun-Fire-T1000"
#define	ERIE_PLATFORM2			"SUNW,SPARC-Enterprise-T1000"
#define	ERIE_PCIE_COMP			8
#define	ERIE_PCIX_COMP			20
#define	NO_SLOT 			-1
#define	NET_COMP_NUM			3
#define	IOBOARD				"IOBD"
#define	MOTHERBOARD			"MB"
#define	OPHIR				"GBE"
#define	NETWORK				"network"
#define	ERIE_NETWORK_0			"/pci@7c0/pci@0/network@4"
#define	ERIE_NETWORK_1			"/pci@7c0/pci@0/network@4,1"
#define	ERIE_NETWORK_2			"/pci@7c0/pci@0/pci@8/network@1"
#define	ERIE_NETWORK_3			"/pci@7c0/pci@0/pci@8/network@1,1"
#define	PCIX_BUS			"/pci@7c0/pci@0/pci@8"
#define	PCIE_PCIX			"/pci@7c0/pci@0/pci@8"
#define	PCIE_PCIE			"/pci@7c0/pci@0"
#define	ERIE_LSI_PATH			"/pci@7c0/pci@0/pci@8/scsi@2"
#define	FIRE0   			"/pci@780"
#define	FIRE1   			"/pci@7c0"
#define	IOBRIDGE			"IO-BRIDGE"
#define	PCI_BRIDGE			"PCI-BRIDGE"
#define	SAS_SATA_HBA			"SAS-SATA-HBA"



/*
 * Property names
 */
#define	OBP_PROP_REG			"reg"
#define	OBP_PROP_CLOCK_FREQ		"clock-frequency"
#define	OBP_PROP_BOARD_NUM		"board#"
#define	OBP_PROP_REVISION_ID		"revision-id"
#define	OBP_PROP_VERSION_NUM		"version#"
#define	OBP_PROP_BOARD_TYPE		"board_type"
#define	OBP_PROP_ECACHE_SIZE		"ecache-size"
#define	OBP_PROP_IMPLEMENTATION		"implementation#"
#define	OBP_PROP_MASK			"mask#"
#define	OBP_PROP_COMPATIBLE		"compatible"
#define	OBP_PROP_BANNER_NAME		"banner-name"
#define	OBP_PROP_MODEL			"model"
#define	OBP_PROP_66MHZ_CAPABLE		"66mhz-capable"
#define	OBP_PROP_FBC_REG_ID		"fbc_reg_id"
#define	OBP_PROP_VERSION		"version"
#define	OBP_PROP_INSTANCE		"instance"

/*
 * Function Headers
 */


/* local functions */

int erie_pci_callback(picl_nodehdl_t pcih, void *args);
int erie_hw_rev_callback(picl_nodehdl_t pcih, void *args);
int erie_get_first_compatible_value(picl_nodehdl_t nodeh,
    char **outbuf);
int64_t erie_get_int_propval(picl_nodehdl_t modh, char *prop_name,
    int *ret);
void erie_get_bus_type(char path[], char bus_type[]);
void erie_get_nac(char bus_type[], char path[], int s,
    char name[],  char loc[], int size);
int erie_get_slot_number(char path[]);
int erie_get_network_instance(char path[]);
int erie_get_name(picl_nodehdl_t nodeh, char name[], int size);
int erie_get_model(picl_nodehdl_t nodeh, char model[], int size);
int erie_get_path(picl_nodehdl_t nodeh, char path[], int size);
int erie_get_class(picl_nodehdl_t nodeh, char piclclass[], int size);
#ifdef __cplusplus
}
#endif

#endif /* _ERIE_H */
