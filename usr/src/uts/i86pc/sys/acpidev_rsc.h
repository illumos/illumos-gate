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
/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#ifndef	_SYS_ACPIDEV_RSC_H
#define	_SYS_ACPIDEV_RSC_H
#include <sys/types.h>
#include <sys/obpdefs.h>
#include <sys/sunddi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ACPI bus range structure. */
typedef struct acpidev_bus_range {
	uint_t	bus_start;
	uint_t	bus_end;
} acpidev_bus_range_t;

/*
 * This structure is modeled after the 1275 "reg" property and
 * "assigned-addresses" property for PCI device nodes.
 * There's no standard definition available for ACPI devices.
 * This structure is used to store resources returned by the ACPI
 * _CRS method.
 *
 * The physical address format is:
 *         Bit#:      33222222 22221111 11111100 00000000
 *                    10987654 32109876 54321098 76543210
 * phys_hi cell:      xxxxxxxx xxxxxxxx xxxxxxxx TSxxxTTT
 * phys_hi(memory):   xxxxxxxx xxxxxxxx wxxxxxcc --xxx000
 * phys_hi(io):       xxxxxxxx xxxxxxxx sdxxxxaa --xxx001
 * phys_mid cell:     hhhhhhhh hhhhhhhh hhhhhhhh hhhhhhhh
 * phys_low cell:     llllllll llllllll llllllll llllllll
 *
 * TTT        is type of resource. Such as MEMORY, IO etc.
 * S          is 1 if address range is subtractive decoding
 * T          is 1 if resource type is different on primary and
 *	      secondary bus
 * cc         is memory coherence type
 * w          is 1 if memory is writable
 * aa         ranges of decoded ports, ISA only, non-ISA only or full.
 * d          is 1 if IO port decode 16 bit address, otherwise 10 bits.
 * s          is 1 if translation is sparse.
 * hh...hhh   is the 32-bit unsigned number
 * ll...lll   is the 32-bit unsigned number
 *
 * The physical size format is:
 *
 * size_hi cell:  hhhhhhhh hhhhhhhh hhhhhhhh hhhhhhhh
 * size_low cell: llllllll llllllll llllllll llllllll
 *
 * hh...hhh   is the 32-bit unsigned number
 * ll...lll   is the 32-bit unsigned number
 */
typedef struct acpidev_phys_spec {
	uint_t	phys_hi;		/* resource address, hi word */
	uint_t	phys_mid;		/* resource address, middle word */
	uint_t	phys_low;		/* resource address, low word */
	uint_t	size_hi;		/* high word of size field */
	uint_t	size_low;		/* low word of size field */
} acpidev_phys_spec_t;

typedef struct acpidev_phys_spec	acpidev_regspec_t;

#define	ACPIDEV_REG_TYPE_M		0x00000007
#define	ACPIDEV_REG_TYPE_MEMORY		0x00000000
#define	ACPIDEV_REG_TYPE_IO		0x00000001
#define	ACPIDEV_REG_SUB_DEC		0x00000040
#define	ACPIDEV_REG_TRANSLATED		0x00000080

#define	ACPIDEV_REG_MEM_COHERENT_M	0x00000300
#define	ACPIDEV_REG_MEM_COHERENT_NC	0x00000000	/* Non-cachable */
#define	ACPIDEV_REG_MEM_COHERENT_CA	0x00000100	/* Cachable */
#define	ACPIDEV_REG_MEM_COHERENT_WC	0x00000200	/* Write-combining */
#define	ACPIDEV_REG_MEM_COHERENT_PF	0x00000300	/* Prefectable */
#define	ACPIDEV_REG_MEM_WRITABLE	0x00008000	/* Writable */

#define	ACPIDEV_REG_IO_RANGE_M		0x00000300
#define	ACPIDEV_REG_IO_RANGE_NONISA	0x00000100
#define	ACPIDEV_REG_IO_RANGE_ISA	0x00000200
#define	ACPIDEV_REG_IO_RANGE_FULL	0x00000300
#define	ACPIDEV_REG_IO_DECODE16		0x00004000	/* Decode 16bit addr. */
#define	ACPIDEV_REG_IO_SPARSE		0x00008000 /* Sparse translation. */

typedef struct acpidev_ranges {
	uint_t	child_hi;		/* child's address, hi word */
	uint_t	child_mid;		/* child's address, middle word */
	uint_t	child_low;		/* child's address, low word */
	uint_t	parent_hi;		/* parent's address, hi word */
	uint_t	parent_mid;		/* parent's address, middle word */
	uint_t	parent_low;		/* parent's address, low word */
	uint_t	size_hi;		/* high word of size field */
	uint_t	size_low;		/* low word of size field */
} acpidev_ranges_t;

#ifdef	_KERNEL

/* Maximum possible number of IRQs. */
#define	ACPIDEV_RES_IRQ_MAX		16
/* Maximum possible number of DMAs. */
#define	ACPIDEV_RES_DMA_MAX		8

/* Forward declaration */
typedef	struct acpidev_resource_handle	*acpidev_resource_handle_t;

/*
 * Resource handler relative interfaces.
 * Return values of acpidev_resource_get_xxx interfaces:
 * AE_OK: succeed with resources stored in buffer and count updated.
 * AE_LIMIT: buffer is too small, count updated to number of resources.
 * AE_BAD_PARAMETER: invalid parameter
 */
extern acpidev_resource_handle_t acpidev_resource_handle_alloc(
    boolean_t consumer);
extern void acpidev_resource_handle_free(acpidev_resource_handle_t rhdl);

extern ACPI_STATUS acpidev_resource_insert_reg(acpidev_resource_handle_t rhdl,
    acpidev_regspec_t *regp);
extern ACPI_STATUS acpidev_resource_get_regs(acpidev_resource_handle_t rhdl,
    uint_t mask, uint_t value, acpidev_regspec_t *regp, uint_t *cntp);
extern uint_t acpidev_resource_get_reg_count(acpidev_resource_handle_t rhdl,
    uint_t mask, uint_t value);

extern ACPI_STATUS acpidev_resource_insert_range(acpidev_resource_handle_t rhdl,
    acpidev_ranges_t *rangep);
extern ACPI_STATUS acpidev_resource_get_ranges(acpidev_resource_handle_t rhdl,
    uint_t mask, uint_t value, acpidev_ranges_t *rangep, uint_t *cntp);
extern uint_t acpidev_resource_get_range_count(acpidev_resource_handle_t rhdl,
    uint_t mask, uint_t value);

extern ACPI_STATUS acpidev_resource_insert_bus(acpidev_resource_handle_t rhdl,
    acpidev_bus_range_t *busp);
extern ACPI_STATUS acpidev_resource_get_buses(acpidev_resource_handle_t rhdl,
    acpidev_bus_range_t *busp, uint_t *cntp);
extern uint_t acpidev_resource_get_bus_count(acpidev_resource_handle_t rhdl);

extern ACPI_STATUS acpidev_resource_insert_dma(acpidev_resource_handle_t rhdl,
    int dma);
extern ACPI_STATUS acpidev_resource_get_dmas(acpidev_resource_handle_t rhdl,
    uint_t *dmap, uint_t *cntp);
extern uint_t acpidev_resource_get_dma_count(acpidev_resource_handle_t rhdl);

extern ACPI_STATUS acpidev_resource_insert_irq(acpidev_resource_handle_t rhdl,
    int irq);
extern ACPI_STATUS acpidev_resource_get_irqs(acpidev_resource_handle_t rhdl,
    uint_t *irqp, uint_t *cntp);
extern uint_t acpidev_resource_get_irq_count(acpidev_resource_handle_t rhdl);

/*
 * Walk resources returned by 'method' and store parsed resources into rhdlp.
 * Caller needs to release rhdlp after using it.
 * Return AE_OK on success with resource handle stored in 'rhdlp'.
 */
extern ACPI_STATUS acpidev_resource_walk(ACPI_HANDLE hdl, char *method,
    boolean_t consumer, acpidev_resource_handle_t *rhdlp);

/*
 * Walk resources returned by the ACPI _CRS method and create device properties.
 * Create 'reg', 'assigned-addresses', 'dma-channels' and 'interrupts'
 * properties for resource consumer.
 * Create 'ranges' and 'bus-range' properties for resource producer.
 */
extern ACPI_STATUS acpidev_resource_process(acpidev_walk_info_t *infop,
    boolean_t consumer);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ACPIDEV_RSC_H */
