/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _I40E_OSDEP_H
#define	_I40E_OSDEP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci_cap.h>
#include <sys/sysmacros.h>

/*
 * For the moment, we use this to basically deal with a few custom changes
 * particularly around the use of sprintf() in the common code. The DDI defines
 * sprintf() in a rather different way than the rest of the world expects it.
 * This is currently necessary to indicate that we should use an alternate
 * behavior.
 */
#define	I40E_ILLUMOS 1

#define	DEBUGOUT(S)				i40e_debug(NULL, 0, S)
#define	DEBUGOUT1(S, A)				i40e_debug(NULL, 0, S, A)
#define	DEBUGOUT2(S, A, B)			i40e_debug(NULL, 0, S, A, B)
#define	DEBUGOUT3(S, A, B, C)			i40e_debug(NULL, 0, S, A, B, C)
#define	DEBUGOUT4(S, A, B, C, D)		\
	i40e_debug(NULL, 0, S, A, B, C, D)
#define	DEBUGOUT5(S, A, B, C, D, E)		\
	i40e_debug(NULL, 0, S, A, B, C, D, E)
#define	DEBUGOUT6(S, A, B, C, D, E, F)		\
	i40e_debug(NULL, 0, S, A, B, C, D, E, F)
#define	DEBUGOUT7(S, A, B, C, D, E, F, G)	\
	i40e_debug(NULL, 0, S, A, B, C, D, E, F, G)
#define	DEBUGFUNC(F)				DEBUGOUT(F);


#define	UNREFERENCED_PARAMETER(x)		_NOTE(ARGUNUSED(x))
#define	UNREFERENCED_1PARAMETER(_p)		UNREFERENCED_PARAMETER(_p)
#define	UNREFERENCED_2PARAMETER(_p, _q)		_NOTE(ARGUNUSED(_p, _q))
#define	UNREFERENCED_3PARAMETER(_p, _q, _r)	_NOTE(ARGUNUSED(_p, _q, _r))
#define	UNREFERENCED_4PARAMETER(_p, _q, _r, _s)	_NOTE(ARGUNUSED(_p, _q, _r, _s))

#define	INLINE  inline

/*
 * The mdb dmod needs to use this code as well, but mdb already defines TRUE and
 * FALSE in the module API. Thus we don't define these if we're building the
 * dmod, as indicated by _I40E_MDB_DMOD. However, if we don't define these, then
 * the shared code will be upset.
 */
#ifndef _I40E_MDB_DMOD
#define	FALSE	B_FALSE
#define	false	B_FALSE
#define	TRUE	B_TRUE
#define	true	B_TRUE
#endif /* _I40E_MDB_DMOD */


#define	CPU_TO_LE16(o)	LE_16(o)
#define	CPU_TO_LE32(s)	LE_32(s)
#define	CPU_TO_LE64(h)	LE_64(h)
#define	LE16_TO_CPU(a)	LE_16(a)
#define	LE32_TO_CPU(c)	LE_32(c)
#define	LE64_TO_CPU(k)	LE_64(k)

#define	I40E_NTOHS(a)	ntohs(a)
#define	I40E_NTOHL(a)	ntohl(a)
#define	I40E_HTONS(a)	htons(a)
#define	I40E_HTONL(a)	htonl(a)

#define	i40e_memset(a, b, c, d)  memset((a), (b), (c))
#define	i40e_memcpy(a, b, c, d)  bcopy((b), (a), (c))

#define	i40e_usec_delay(x) drv_usecwait(x)
#define	i40e_msec_delay(x) drv_usecwait(1000 * (x))

#define	FIELD_SIZEOF(x, y) (sizeof (((x*)0)->y))

#define	BIT(a) 		(1UL << (a))
#define	BIT_ULL(a) 	(1ULL << (a))

typedef boolean_t	bool;

typedef uint8_t		u8;
typedef int8_t		s8;
typedef uint16_t	u16;
typedef int16_t		s16;
typedef uint32_t	u32;
typedef int32_t		s32;
typedef uint64_t	u64;

/* long string relief */
typedef enum i40e_status_code i40e_status;

#define	__le16  u16
#define	__le32  u32
#define	__le64  u64
#define	__be16  u16
#define	__be32  u32
#define	__be64  u64

/*
 * Most other systems use spin locks for interrupts. However, illumos always
 * uses a single kmutex_t for both and we decide what to do based on IPL (hint:
 * it's not going to be a true spin lock, we'll use an adaptive mutex).
 */
struct i40e_spinlock {
	kmutex_t ispl_mutex;
};

/*
 * Note, while prefetch is strictly not present on all architectures, (it's an
 * SSE extension on i386), it is expected that the platforms provide it.
 */
#define	prefetch(x) prefetch_read_many(x)

struct i40e_osdep {
	off_t			ios_reg_size;
	ddi_acc_handle_t 	ios_reg_handle;
	ddi_acc_handle_t 	ios_cfg_handle;
	struct i40e		*ios_i40e;
};

/*
 * This structure and its members are defined by the common code. This means we
 * cannot structure prefix it, even if we want to.
 */
struct i40e_virt_mem {
	void 	*va;
	u32	size;
};

/*
 * The first three members of this structure are defined by the common code.
 * This means we cannot structure prefix them, even if we wanted to.
 */
struct i40e_dma_mem {
	void			*va;	/* Virtual address. */
	u64			pa;	/* Physical (DMA/Hardware) address. */
	size_t			size;	/* Buffer size. */

	/* illumos-private members */
	ddi_acc_handle_t	idm_acc_handle;	/* Data access handle */
	ddi_dma_handle_t	idm_dma_handle;	/* DMA handle */
	uint32_t		idm_alignment;	/* Requested alignment */
};

struct i40e_hw; /* forward decl */

#define	OS_DEP(hw) ((struct i40e_osdep *)((hw)->back))
#define	i40e_read_pci_cfg(hw, reg) \
	(pci_config_get16(OS_DEP(hw)->ios_cfg_handle, (reg)))
#define	i40e_write_pci_cfg(hw, reg, value) \
	(pci_config_put16(OS_DEP(hw)->ios_cfg_handle, (reg), (value)))

/*
 * Intel expects that the symbol wr32 and rd32 be defined to something which can
 * read and write the 32-bit register in PCI space.
 *
 * To make it easier for readers and satisfy the general agreement that macros
 * should be in all capitals, we use our own versions of these macros.
 */
#define	wr32(hw, reg, value) \
	ddi_put32(OS_DEP(hw)->ios_reg_handle, \
	    (uint32_t *)((uintptr_t)(hw)->hw_addr + (reg)), (value))
#define	rd32(hw, reg) \
	ddi_get32(OS_DEP(hw)->ios_reg_handle, \
	    (uint32_t *)((uintptr_t)(hw)->hw_addr + (reg)))
#define	I40E_WRITE_REG	wr32
#define	I40E_READ_REG	rd32

/*
 * The use of GLGEN_STAT presumes that we're only using this file for a PF
 * driver. If we end up doing a VF driver, then we'll want to logically change
 * this.
 */
#define	i40e_flush(hw) (void) rd32(hw, I40E_GLGEN_STAT)

extern void i40e_debug(void *, u32, char *, ...);
extern boolean_t i40e_set_hw_bus_info(struct i40e_hw *);

#ifdef __cplusplus
}
#endif

#endif /* _I40E_OSDEP_H */
