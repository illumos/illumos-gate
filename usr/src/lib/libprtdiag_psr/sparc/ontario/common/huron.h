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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Sun4v Platform header file.
 *
 * 	called when :
 *      machine_type ==  huron
 *
 */

#ifndef _HURON_H
#define	_HURON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	HURON_2U_PLATFORM	"SUNW,SPARC-Enterprise-T5220"
#define	HURON_1U_PLATFORM	"SUNW,SPARC-Enterprise-T5120"
#define	HURON_PCIE_COMP		30
#define	HURON_XAUI_COMP		17
#define	NO_SLOT 		-1
#define	NET_COMP_NUM		3
#define	MOTHERBOARD		"MB"
#define	HURON_SWITCH_A		"PCI-SWITCH0"
#define	HURON_SWITCH_B		"PCI-SWITCH1"
#define	HURON_SWITCH_C		"PCI-SWITCH2"
#define	SOUTHBRIDGE		"southbridge"
#define	OPHIR			"GBE"
#define	NETWORK			"network"
#define	PCIE			"/PCIE"
#define	HURON_NIU		"/niu@80"
#define	HURON_SWITCH_A_PATH	"/pci@0/pci@0"
#define	HURON_SWITCH_B_PATH	"/pci@0/pci@0/pci@8/pci@0"
#define	HURON_SWITCH_C_PATH	"/pci@0/pci@0/pci@1/pci@0"
#define	HURON_NETWORK_0		"/pci@0/pci@0/pci@1/pci@0/pci@2/network@0"
#define	HURON_NETWORK_1		"/pci@0/pci@0/pci@1/pci@0/pci@2/network@0,1"
#define	HURON_NETWORK_2		"/pci@0/pci@0/pci@1/pci@0/pci@3/network@0"
#define	HURON_NETWORK_3		"/pci@0/pci@0/pci@1/pci@0/pci@3/network@0,1"
#define	HURON_PCIE_SLOT0	"/pci@0/pci@0/pci@8/pci@0/pci@9"
#define	HURON_PCIE_SLOT1	"/pci@0/pci@0/pci@8/pci@0/pci@1"
#define	HURON_PCIE_SLOT2	"/pci@0/pci@0/pci@9"
#define	HURON_PCIE_SLOT3	"/pci@0/pci@0/pci@8/pci@0/pci@a"
#define	HURON_PCIE_SLOT4	"/pci@0/pci@0/pci@8/pci@0/pci@2"
#define	HURON_PCIE_SLOT5	"/pci@0/pci@0/pci@8/pci@0/pci@8"
#define	HURON_LSI_PATH		"/pci@0/pci@0/pci@2/scsi@0"
#define	HURON_N2_XAUI0		"/niu@80/network@1"
#define	HURON_N2_XAUI1		"/niu@80/network@0"
#define	SAS_SATA_HBA		"SAS-SATA-HBA"

/*
 * Property names
 */
#define	OBP_PROP_REG		"reg"
#define	OBP_PROP_CLOCK_FREQ	"clock-frequency"
#define	OBP_PROP_BOARD_NUM	"board#"
#define	OBP_PROP_REVISION_ID	"revision-id"
#define	OBP_PROP_VERSION_NUM	"version#"
#define	OBP_PROP_BOARD_TYPE	"board_type"
#define	OBP_PROP_ECACHE_SIZE	"ecache-size"
#define	OBP_PROP_IMPLEMENTATION	"implementation#"
#define	OBP_PROP_MASK		"mask#"
#define	OBP_PROP_COMPATIBLE	"compatible"
#define	OBP_PROP_BANNER_NAME	"banner-name"
#define	OBP_PROP_MODEL		"model"
#define	OBP_PROP_66MHZ_CAPABLE	"66mhz-capable"
#define	OBP_PROP_FBC_REG_ID	"fbc_reg_id"
#define	OBP_PROP_VERSION	"version"
#define	OBP_PROP_INSTANCE	"instance"

/*
 * Function Headers
 */


/* local functions */

int huron_pci_callback(picl_nodehdl_t pcih, void *args);
int huron_hw_rev_callback(picl_nodehdl_t pcih, void *args);
int huron_get_first_compatible_value(picl_nodehdl_t nodeh,
    char **outbuf);
int64_t huron_get_int_propval(picl_nodehdl_t modh, char *prop_name,
    int *ret);
void huron_get_nac(char bus_type[], char path[], int s,
    char name[],  char loc[], int size);
int huron_get_name(picl_nodehdl_t nodeh, char name[], int size);
int huron_get_model(picl_nodehdl_t nodeh, char model[], int size);
int huron_get_path(picl_nodehdl_t nodeh, char path[], int size);
int huron_get_class(picl_nodehdl_t nodeh, char piclclass[], int size);
#ifdef __cplusplus
}
#endif

#endif /* _HURON_H */
