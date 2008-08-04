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

#ifndef _SYS_ACPICA_H
#define	_SYS_ACPICA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	dev_info_t		*dip;
	kmutex_t		mutex;
	ddi_iblock_cookie_t	iblock_cookie;
} AcpiCA;

/* acpi-user-options options property */
extern unsigned int acpi_options_prop;
#define	ACPI_OUSER_MASK		0x0003
#define	ACPI_OUSER_DFLT		0x0000
#define	ACPI_OUSER_ON		0x0001
#define	ACPI_OUSER_OFF		0x0002
#define	ACPI_OUSER_MADT		0x0004
#define	ACPI_OUSER_LEGACY	0x0008


/*
 * Initialization state of the ACPI CA subsystem
 */
#define	ACPICA_NOT_INITIALIZED	(0)
#define	ACPICA_INITIALIZED	(1)

extern int acpica_init(void);
extern void acpica_ec_init(void);

/*
 * acpi_status property values
 */
#define	ACPI_BOOT_INIT		0x00000001
#define	ACPI_BOOT_ENABLE	0x00000002
#define	ACPI_BOOT_BOOTCONF	0x00000010

#define	SCI_IPL	(LOCK_LEVEL-1)

/*
 * definitions of Bus Type
 */
#define	BUS_CBUS	1
#define	BUS_CBUSII	2
#define	BUS_EISA	3
#define	BUS_FUTURE	4
#define	BUS_INTERN	5
#define	BUS_ISA		6
#define	BUS_MBI		7
#define	BUS_MBII	8
#define	BUS_PCIE	9
#define	BUS_MPI		10
#define	BUS_MPSA	11
#define	BUS_NUBUS	12
#define	BUS_PCI		13
#define	BUS_PCMCIA	14
#define	BUS_TC		15
#define	BUS_VL		16
#define	BUS_VME		17
#define	BUS_XPRESS	18


/*
 * intr_po - polarity definitions
 */
#define	INTR_PO_CONFORM		0x00
#define	INTR_PO_ACTIVE_HIGH	0x01
#define	INTR_PO_RESERVED	0x02
#define	INTR_PO_ACTIVE_LOW	0x03

/*
 * intr_el edge or level definitions
 */
#define	INTR_EL_CONFORM		0x00
#define	INTR_EL_EDGE		0x01
#define	INTR_EL_RESERVED	0x02
#define	INTR_EL_LEVEL		0x03

/*
 * interrupt flags structure
 */
typedef struct iflag {
	uchar_t	intr_po: 2,
		intr_el: 2,
		bustype: 4;
} iflag_t;

/* _HID for PCI bus object */
#define	HID_PCI_BUS		0x30AD041
#define	HID_PCI_EXPRESS_BUS	0x080AD041

/*
 * Function prototypes
 */
extern ACPI_STATUS acpica_get_sci(int *, iflag_t *);
extern int acpica_get_bdf(dev_info_t *, int *, int *, int *);
extern ACPI_STATUS acpica_get_devinfo(ACPI_HANDLE, dev_info_t **);
extern ACPI_STATUS acpica_get_handle(dev_info_t *, ACPI_HANDLE *);
extern ACPI_STATUS acpica_eval_int(ACPI_HANDLE, char *, int *);
extern void acpica_map_cpu(processorid_t, UINT32);
extern void acpica_build_processor_map();
extern void acpica_ddi_save_resources(dev_info_t *);
extern void acpica_ddi_restore_resources(dev_info_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ACPICA_H */
