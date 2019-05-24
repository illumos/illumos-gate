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
 * Copyright 2019 Peter Tribble.
 */

#ifndef	_SYS_PROM_PLAT_H
#define	_SYS_PROM_PLAT_H

#include <sys/feature_tests.h>
#include <sys/cpuvar.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_LONGLONG_TYPE)
#error "This header won't work without long long support"
#endif

/*
 * This file contains external platform-specific promif interface definitions.
 * There may be none.  This file is included by reference in <sys/promif.h>
 *
 * This version of the file is for the IEEE 1275-1994 compliant sun4u prom.
 */

/*
 * Memory allocation plus memory/mmu interfaces:
 *
 * Routines with fine-grained memory and MMU control are platform-dependent.
 *
 * MMU node virtualized "mode" arguments and results for Spitfire MMU:
 *
 * The default virtualized "mode" for client program mappings created
 * by the firmware is as follows:
 *
 * G (global)		Clear
 * L (locked)		Clear
 * W (write)		Set
 * R (read - soft)	Set (Prom is not required to implement soft bits)
 * X (exec - soft)	Set (Prom is not required to implement soft bits)
 * CV,CP (Cacheable)	Set if memory page, Clear if IO page
 * E (side effects)	Clear if memory page; Set if IO page
 * IE (Invert endian.)	Clear
 *
 * The following fields are initialized as follows in the TTE-data for any
 * mappings created by the firmware on behalf of the client program:
 *
 * P (Priviledged)	Set
 * V (Valid)		Set
 * NFO (No Fault Only)	Clear
 * Context		0
 * Soft bits		< private to the firmware implementation >
 *
 * Page size of Prom mappings are typically 8k, "modify" cannot change
 * page sizes. Mappings created by "map" are 8k pages.
 *
 * If the virtualized "mode" is -1, the defaults as shown above are used,
 * otherwise the virtualized "mode" is set (and returned) based on the
 * following virtualized "mode" abstractions. The mmu node "translations"
 * property contains the actual tte-data, not the virtualized "mode".
 *
 * Note that client programs may not create locked mappings by setting
 * the LOCKED bit. There are Spitfire specific client interfaces to create
 * and remove locked mappings. (SUNW,{i,d}tlb-load).
 * The LOCKED bit is defined here since it may be returned by the
 * "translate" method.
 *
 * The PROM is not required to implement the Read and eXecute soft bits,
 * and is not required to track them for the client program. They may be
 * set on calls to "map" and "modfify" and may be ignored by the firmware,
 * and are not necessarily returned from "translate".
 *
 * The TTE soft bits are private to the firmware.  No assumptions may
 * be made regarding the contents of the TTE soft bits.
 *
 * Changing a mapping from cacheable to non-cacheable implies a flush
 * or invalidate operation, if necessary.
 *
 * NB: The "map" MMU node method should NOT be used to create IO device
 * mappings. The correct way to do this is to call the device's parent
 * "map-in" method using the CALL-METHOD client interface service.
 */

#define	PROM_MMU_MODE_DEFAULT	((int)-1)	/* Default "mode", see above */

/*
 * NB: These are not implemented in PROM version P1.0 ...
 */
#define	PROM_MMU_MODE_WRITE	0x0001	/* Translation is Writable */
#define	PROM_MMU_MODE_READ	0x0002	/* Soft: Readable, See above */
#define	PROM_MMU_MODE_EXEC	0x0004	/* Soft: eXecutable, See above */
#define	PROM_MMU_MODE_RWX_MASK	0x0007	/* Mask for R-W-X bits */

#define	PROM_MMU_MODE_LOCKED	0x0010	/* Read-only: Locked; see above */
#define	PROM_MMU_MODE_CACHED	0x0020	/* Set means both CV,CP bits */
#define	PROM_MMU_MODE_EFFECTS	0x0040	/* side Effects bit in MMU */
#define	PROM_MMU_MODE_GLOBAL	0x0080	/* Global bit */
#define	PROM_MMU_MODE_INVERT	0x0100	/* Invert Endianness */

/*
 * resource allocation group: OBP only. (mapping functions are platform
 * dependent because they use physical address arguments.)
 */
extern	caddr_t		prom_map(caddr_t virthint,
			    unsigned long long physaddr, uint_t size);

/*
 * prom_alloc is platform dependent and has historical semantics
 * associated with the align argument and the return value.
 * prom_malloc is the generic memory allocator.
 */
extern	caddr_t		prom_malloc(caddr_t virt, size_t size, uint_t align);

extern	caddr_t		prom_allocate_virt(uint_t align, size_t size);
extern	caddr_t		prom_claim_virt(size_t size, caddr_t virt);
extern	void		prom_free_virt(size_t size, caddr_t virt);

extern	int		prom_allocate_phys(size_t size, uint_t align,
			    unsigned long long *physaddr);
extern	int		prom_claim_phys(size_t size,
			    unsigned long long physaddr);
extern	void		prom_free_phys(size_t size,
			    unsigned long long physaddr);

extern	int		prom_map_phys(int mode, size_t size, caddr_t virt,
			    unsigned long long physaddr);
extern	void		prom_unmap_phys(size_t size, caddr_t virt);
extern	void		prom_unmap_virt(size_t size, caddr_t virt);

extern	int		prom_phys_installed_len(void);
extern	int		prom_phys_avail_len(void);
extern	int		prom_virt_avail_len(void);

extern	int		prom_phys_installed(caddr_t);
extern	int		prom_phys_avail(caddr_t);
extern	int		prom_virt_avail(caddr_t);

/*
 * prom_retain allocates or returns retained physical memory
 * identified by the arguments of name string "id", "size" and "align".
 */
extern	int		prom_retain(char *id, size_t size, uint_t align,
			    unsigned long long *physaddr);

/*
 * prom_translate_virt returns the physical address and virtualized "mode"
 * for the given virtual address. After the call, if *valid is non-zero,
 * a mapping to 'virt' exists and the physical address and virtualized
 * "mode" were returned to the caller.
 */
extern	int		prom_translate_virt(caddr_t virt, int *valid,
			    unsigned long long *physaddr, int *mode);

/*
 * prom_modify_mapping changes the "mode" of an existing mapping or
 * repeated mappings. virt is the virtual address whose "mode" is to
 * be changed; size is some multiple of the fundamental pagesize.
 * This method cannot be used to change the pagesize of an MMU mapping,
 * nor can it be used to Lock a translation into the i or d tlb.
 */
extern	int	prom_modify_mapping(caddr_t virt, size_t size, int mode);

/*
 * Client interfaces for managing the {i,d}tlb handoff to client programs.
 */
extern	int		prom_itlb_load(int index,
			    unsigned long long tte_data, caddr_t virt);

extern	int		prom_dtlb_load(int index,
			    unsigned long long tte_data, caddr_t virt);

/*
 * Administrative group: OBP only and SMCC platform specific.
 * XXX: IDPROM related stuff should be replaced with specific data-oriented
 * XXX: functions.
 */

extern	int		prom_heartbeat(int msecs);
extern	int		prom_get_unum(int syn_code, unsigned long long physaddr,
				char *buf, uint_t buflen, int *ustrlen);
extern	int		prom_serengeti_get_ecacheunum(int cpuid,
				unsigned long long physaddr, char *buf,
				uint_t buflen, int *ustrlen);

extern	int		prom_getidprom(caddr_t addr, int size);
extern	int		prom_getmacaddr(ihandle_t hd, caddr_t ea);

/*
 * CPU Control Group: MP's only.
 */
extern	int		prom_startcpu(pnode_t node, caddr_t pc, int arg);
extern	int		prom_startcpu_bycpuid(int cpuid, caddr_t pc, int arg);
extern	int		prom_stopcpu_bycpuid(int);
extern	int		prom_sunfire_cpu_off(void);	/* SunFire only */
extern	int		prom_wakeupcpu(pnode_t node);
extern	int		prom_serengeti_wakeupcpu(pnode_t node);
extern	int		prom_hotaddcpu(int cpuid);
extern	int		prom_hotremovecpu(int cpuid);
extern	void		promsafe_pause_cpus(void);
extern	void		promsafe_xc_attention(cpuset_t cpuset);
extern	int		prom_serengeti_cpu_off(pnode_t node);

/*
 * Set trap table
 */
extern	void		prom_set_traptable(void *tba_addr);

/*
 * Power-off
 */
extern	void		prom_power_off(void);

/*
 * sunfire attach/detach
 */
extern	int		prom_sunfire_attach_board(uint_t board);
extern	int		prom_sunfire_detach_board(uint_t board);

/*
 * Serengeti console switch
 */
extern	char		*prom_serengeti_set_console_input(char *new_value);

/*
 * Serengeti attach/detach
 */
extern	int		prom_serengeti_attach_board(uint_t node, uint_t board);
extern	int		prom_serengeti_detach_board(uint_t node, uint_t board);
extern	int		prom_serengeti_tunnel_switch(uint_t node, uint_t board);

/*
 * OPL-specific routines
 */
extern	void		prom_opl_get_tod(time_t *time, int64_t *stickval);
extern	void		prom_opl_set_diff(int64_t diff);
extern	int		prom_attach_notice(int bn);
extern	int		prom_detach_notice(int bn);
extern	int		prom_opl_switch_console(int bn);

/*
 * The client program implementation is required to provide a wrapper
 * to the client handler, for the 32 bit client program to 64 bit cell-sized
 * client interface handler (switch stack, etc.).  This function is not
 * to be used externally!
 */

extern	int		client_handler(void *cif_handler, void *arg_array);

/*
 * The 'format' of the "translations" property in the 'mmu' node ...
 */

struct translation {
	uint32_t virt_hi;	/* upper 32 bits of vaddr */
	uint32_t virt_lo;	/* lower 32 bits of vaddr */
	uint32_t size_hi;	/* upper 32 bits of size in bytes */
	uint32_t size_lo;	/* lower 32 bits of size in bytes */
	uint32_t tte_hi;	/* higher 32 bites of tte */
	uint32_t tte_lo;	/* lower 32 bits of tte */
};

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PROM_PLAT_H */
