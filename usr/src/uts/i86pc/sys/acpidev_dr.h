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
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Interfaces to support System Board Dynamic Reconfiguration.
 */

#ifndef	_SYS_ACPIDEV_DR_H
#define	_SYS_ACPIDEV_DR_H
#include <sys/types.h>
#include <sys/obpdefs.h>
#include <sys/cpuvar.h>
#include <sys/memlist.h>
#include <sys/sunddi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_rsc.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/* Maximum number of DR capable system boards supported. */
#define	ACPIDEV_DR_MAX_BOARDS		0x40
#define	ACPIDEV_DR_SEGS_PER_MEM_DEV	0x10
#define	ACPIDEV_DR_MEMLISTS_PER_SEG	0x10
#define	ACPIDEV_DR_MAX_MEMLIST_ENTRIES	0x10000

#define	ACPIDEV_DR_PROP_PORTID		"portid"
#define	ACPIDEV_DR_PROP_BOARDNUM	OBP_BOARDNUM
#define	ACPIDEV_DR_PROP_DEVNAME		OBP_NAME

/*
 * Format strings for DR capable system boards.
 * They will be used as attachment point names.
 */
#define	ACPIDEV_DR_CPU_BD_FMT		"CPU%u"
#define	ACPIDEV_DR_MEMORY_BD_FMT	"MEM%u"
#define	ACPIDEV_DR_IO_BD_FMT		"IO%u"
#define	ACPIDEV_DR_SYSTEM_BD_FMT	"SB%u"

typedef enum {
	ACPIDEV_INVALID_BOARD = 0,
	ACPIDEV_CPU_BOARD,
	ACPIDEV_MEMORY_BOARD,
	ACPIDEV_IO_BOARD,
	ACPIDEV_SYSTEM_BOARD
} acpidev_board_type_t;

/* Check whether the system is DR capable. */
extern int acpidev_dr_capable(void);

extern uint32_t acpidev_dr_max_boards(void);
extern uint32_t acpidev_dr_max_mem_units_per_board(void);
extern uint32_t acpidev_dr_max_io_units_per_board(void);
extern uint32_t acpidev_dr_max_cmp_units_per_board(void);
extern uint32_t acpidev_dr_max_cpu_units_per_cmp(void);
extern uint32_t acpidev_dr_max_segments_per_mem_device(void);
extern uint32_t acpidev_dr_max_memlists_per_segment(void);
extern ACPI_STATUS acpidev_dr_get_mem_alignment(ACPI_HANDLE hdl, uint64_t *ap);

/* Initialize support of DR operations. */
extern void acpidev_dr_init(void);

/* Scan for DR capable boards and setup environment for DR operations. */
extern void acpidev_dr_check(acpidev_walk_info_t *infop);

/*
 * Initialize DR interfaces to enable DR operations.
 */
extern ACPI_STATUS acpidev_dr_initialize(dev_info_t *pdip);

/* Get ACPI handle of the DR capable board. */
extern ACPI_STATUS acpidev_dr_get_board_handle(uint_t board,
    ACPI_HANDLE *hdlp);

/* Get board type of the DR capable board. */
extern acpidev_board_type_t acpidev_dr_get_board_type(ACPI_HANDLE hdl);

/* Get board number of the DR capable board. */
extern ACPI_STATUS acpidev_dr_get_board_number(ACPI_HANDLE hdl,
    uint32_t *bnump);

/* Get board name of the DR capable board. */
extern ACPI_STATUS acpidev_dr_get_board_name(ACPI_HANDLE hdl,
    char *buf, size_t len);

/* Get attachment point of the DR capable board. */
extern ACPI_STATUS acpidev_dr_get_attachment_point(ACPI_HANDLE hdl,
    char *buf, size_t len);

/*
 * Figure out device type of the object/device.
 * It only supports device types which may be involved in DR operations.
 */
extern acpidev_class_id_t acpidev_dr_device_get_class(ACPI_HANDLE hdl);

/* Get memory device index/id. */
extern ACPI_STATUS acpidev_dr_device_get_memory_index(ACPI_HANDLE hdl,
    uint32_t *idxp);

/* Check whether the device is a DR capable board or not. */
extern int acpidev_dr_device_is_board(ACPI_HANDLE hdl);

/* Check whether the device is present or not. */
extern int acpidev_dr_device_is_present(ACPI_HANDLE hdl);

/* Check whether the device is powered-on or not. */
extern int acpidev_dr_device_is_powered(ACPI_HANDLE hdl);

/* Check whether the device is DR capable. */
extern int acpidev_dr_device_hotplug_capable(ACPI_HANDLE hdl);

/* Check whether the device has an eject device list. */
extern int acpidev_dr_device_has_edl(ACPI_HANDLE hdl);

/*
 * Simulate OBP property interfaces to support drmach driver,
 * so we can keep drmach in consistency with SPARC version.
 * Return size of data copied to buf if it's big enough,
 * otherwise return size of buffer needed.
 */
extern int acpidev_dr_device_getprop(ACPI_HANDLE hdl, char *name,
    caddr_t buf, size_t len);

/*
 * Get "reg" or "assigned-address" property of the device.
 * Return "assigned-address" property if assigned is non-zero,
 * otherwise return "reg" property.
 * Caller needs to release returned resources by calling
 * acpidev_dr_device_free_regspec().
 */
extern ACPI_STATUS acpidev_dr_device_get_regspec(ACPI_HANDLE hdl,
    boolean_t assigned, acpidev_regspec_t **regpp, uint_t *cntp);

/* Free resources returned by acpidev_dr_device_get_regspec(). */
extern void acpidev_dr_device_free_regspec(acpidev_regspec_t *regp,
    uint_t count);

/* Walk devices in eject device list (ACPI _EDL method). */
extern ACPI_STATUS acpidev_dr_device_walk_edl(ACPI_HANDLE hdl,
    ACPI_WALK_CALLBACK cb, void *arg, void **retval);

/* Walk devices in eject dependency list (ACPI _EJD method). */
extern ACPI_STATUS acpidev_dr_device_walk_ejd(ACPI_HANDLE hdl,
    ACPI_WALK_CALLBACK cb, void *arg, void **retval);

/*
 * Walk child and dependent devices which may be involved in DR operations.
 * PCI host bridges embedded in physical processors may be presented in eject
 * device list instead of as children of processors.
 */
extern ACPI_STATUS acpidev_dr_device_walk_device(ACPI_HANDLE hdl,
    uint_t max_lvl, ACPI_WALK_CALLBACK cb, void *arg, void **retval);

/* Check whether the device is in working state without any error. */
extern ACPI_STATUS acpidev_dr_device_check_status(ACPI_HANDLE hdl);

/* Power on the device. */
extern ACPI_STATUS acpidev_dr_device_poweron(ACPI_HANDLE hdl);

/* Power off the device. */
extern ACPI_STATUS acpidev_dr_device_poweroff(ACPI_HANDLE hdl);

/*
 * Create device nodes for hot-added devices under hdl.
 * Return:
 * AE_OK: on success
 * AE_SUPPORT: if it's not capable of DR operation.
 * AE_ERROR: for other errors
 */
extern ACPI_STATUS acpidev_dr_device_insert(ACPI_HANDLE hdl);

/*
 * Destroy device nodes to be removed under hdl.
 * AE_OK: on success
 * AE_SUPPORT: if it's not capable of DR operation.
 * AE_ERROR: for other errors
 */
extern ACPI_STATUS acpidev_dr_device_remove(ACPI_HANDLE hdl);

/* Block dynamic reconfiguration operations. */
extern void acpidev_dr_lock_all(void);

/* Unblock dynamic reconfiguration operations. */
extern void acpidev_dr_unlock_all(void);

extern ACPI_STATUS acpidev_dr_allocate_cpuid(ACPI_HANDLE hdl,
    processorid_t *idp);
extern ACPI_STATUS acpidev_dr_free_cpuid(ACPI_HANDLE hdl);

/*
 * Query NUMA relative information for the CPU device.
 * It returns APIC id, Proximity id and latency information of the CPU device.
 * Latency information is retrieved from the ACPI _SLI method or the ACPI SLIT
 * table.
 */
extern int acpidev_dr_get_cpu_numa_info(cpu_t *cp, void **hdlpp,
    uint32_t *apicidp, uint32_t *pxmidp, uint32_t *slicntp, uchar_t **slipp);

/*
 * Release resources allocated by acpidev_dr_get_cpu_numa_info().
 */
extern void acpidev_dr_free_cpu_numa_info(void *hdlp);

/*
 * Query NUMA relative information for a memory device.
 * It returns proximity id and latency information of the memory device.
 * Latency information is obtained from the ACPI _SLI method or the ACPI
 * SLIT table.
 */
extern ACPI_STATUS acpidev_dr_get_mem_numa_info(ACPI_HANDLE hdl,
    struct memlist *ml, void **hdlpp, uint32_t *pxmidp,
    uint32_t *slicntp, uchar_t **slipp);

/*
 * Release resources allocated by acpidev_dr_get_mem_numa_info().
 */
extern void acpidev_dr_free_mem_numa_info(void *hdlp);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ACPIDEV_DR_H */
