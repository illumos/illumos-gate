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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DDI_ISA_H
#define	_SYS_DDI_ISA_H

#include <sys/isa_defs.h>
#include <sys/ndifm.h>
#include <sys/dditypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * These are the data access functions which the platform
 * can choose to define as functions or macro's.
 */

/*
 * DDI interfaces defined as macro's
 */

/*
 * DDI interfaces defined as functions
 */

/*
 * The implementation specific ddi access handle is the same for
 * all sparc v7 platforms.
 */

typedef struct ddi_acc_impl {
	ddi_acc_hdl_t	ahi_common;
	uint8_t
		(*ahi_get8)(struct ddi_acc_impl *handle, uint8_t *addr);
	uint16_t
		(*ahi_get16)(struct ddi_acc_impl *handle, uint16_t *addr);
	uint32_t
		(*ahi_get32)(struct ddi_acc_impl *handle, uint32_t *addr);
	uint64_t
		(*ahi_get64)(struct ddi_acc_impl *handle, uint64_t *addr);
	void	(*ahi_put8)(struct ddi_acc_impl *handle, uint8_t *addr,
			uint8_t value);
	void	(*ahi_put16)(struct ddi_acc_impl *handle, uint16_t *addr,
			uint16_t value);
	void	(*ahi_put32)(struct ddi_acc_impl *handle, uint32_t *addr,
			uint32_t value);
	void	(*ahi_put64)(struct ddi_acc_impl *handle, uint64_t *addr,
			uint64_t value);

	void	(*ahi_rep_get8)(struct ddi_acc_impl *handle,
			uint8_t *host_addr, uint8_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_get16)(struct ddi_acc_impl *handle,
			uint16_t *host_addr, uint16_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_get32)(struct ddi_acc_impl *handle,
			uint32_t *host_addr, uint32_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_get64)(struct ddi_acc_impl *handle,
			uint64_t *host_addr, uint64_t *dev_addr,
			size_t repcount, uint_t flags);

	void	(*ahi_rep_put8)(struct ddi_acc_impl *handle,
			uint8_t *host_addr, uint8_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_put16)(struct ddi_acc_impl *handle,
			uint16_t *host_addr, uint16_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_put32)(struct ddi_acc_impl *handle,
			uint32_t *host_addr, uint32_t *dev_addr,
			size_t repcount, uint_t flags);
	void	(*ahi_rep_put64)(struct ddi_acc_impl *handle,
			uint64_t *host_addr, uint64_t *dev_addr,
			size_t repcount, uint_t flags);

	int	(*ahi_fault_check)(struct ddi_acc_impl *handle);
	void	(*ahi_fault_notify)(struct ddi_acc_impl *handle);
	uint32_t	ahi_fault;
	ndi_err_t *ahi_err;	/* Access error data */
} ddi_acc_impl_t;

/*
 * Input functions to memory mapped IO
 */
uint8_t
i_ddi_get8(ddi_acc_impl_t *hdlp, uint8_t *addr);

uint16_t
i_ddi_get16(ddi_acc_impl_t *hdlp, uint16_t *addr);

uint32_t
i_ddi_get32(ddi_acc_impl_t *hdlp, uint32_t *addr);

uint64_t
i_ddi_get64(ddi_acc_impl_t *hdlp, uint64_t *addr);

uint16_t
i_ddi_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr);

uint32_t
i_ddi_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr);

uint64_t
i_ddi_swap_get64(ddi_acc_impl_t *hdlp, uint64_t *addr);

/*
 * Output functions to memory mapped IO
 */
void
i_ddi_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value);

void
i_ddi_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value);

void
i_ddi_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value);

void
i_ddi_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value);

void
i_ddi_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value);

void
i_ddi_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value);

void
i_ddi_swap_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value);

/*
 * Repeated input functions for memory mapped IO
 */
void
i_ddi_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags);

void
i_ddi_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr, uint16_t *dev_addr,
    size_t repcount, uint_t flags);

void
i_ddi_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr, uint32_t *dev_addr,
    size_t repcount, uint_t flags);

void
i_ddi_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr, uint64_t *dev_addr,
    size_t repcount, uint_t flags);

void
i_ddi_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);

void
i_ddi_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);

void
i_ddi_swap_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

/*
 * Repeated output functions for memory mapped IO
 */
void
i_ddi_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr, uint8_t *dev_addr,
    size_t repcount, uint_t flags);

void
i_ddi_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr, uint16_t *dev_addr,
    size_t repcount, uint_t flags);

void
i_ddi_rep_put32(ddi_acc_impl_t *hdl, uint32_t *host_addr, uint32_t *dev_addr,
    size_t repcount, uint_t flags);

void
i_ddi_rep_put64(ddi_acc_impl_t *hdl, uint64_t *host_addr, uint64_t *dev_addr,
    size_t repcount, uint_t flags);

void
i_ddi_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);

void
i_ddi_swap_rep_put32(ddi_acc_impl_t *hdl, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);

void
i_ddi_swap_rep_put64(ddi_acc_impl_t *hdl, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

/*
 * Default fault-checking and notification functions
 */
int
i_ddi_acc_fault_check(ddi_acc_impl_t *hdlp);

void
i_ddi_acc_fault_notify(ddi_acc_impl_t *hdlp);

/* DDI Fault Services functions */

void i_ddi_caut_get(size_t size, void *addr, void *val);

uint8_t i_ddi_prot_get8(ddi_acc_impl_t *hdlp, uint8_t *addr);
uint16_t i_ddi_prot_get16(ddi_acc_impl_t *hdlp, uint16_t *addr);
uint32_t i_ddi_prot_get32(ddi_acc_impl_t *hdlp, uint32_t *addr);
uint64_t i_ddi_prot_get64(ddi_acc_impl_t *hdlp, uint64_t *addr);

void i_ddi_prot_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value);
void i_ddi_prot_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value);
void i_ddi_prot_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value);
void i_ddi_prot_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value);

void i_ddi_prot_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_prot_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_prot_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_prot_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

void i_ddi_prot_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_prot_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_prot_rep_put32(ddi_acc_impl_t *hdl, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_prot_rep_put64(ddi_acc_impl_t *hdl, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

uint8_t i_ddi_caut_get8(ddi_acc_impl_t *hdlp, uint8_t *addr);
uint16_t i_ddi_caut_get16(ddi_acc_impl_t *hdlp, uint16_t *addr);
uint32_t i_ddi_caut_get32(ddi_acc_impl_t *hdlp, uint32_t *addr);
uint64_t i_ddi_caut_get64(ddi_acc_impl_t *hdlp, uint64_t *addr);

void i_ddi_caut_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value);
void i_ddi_caut_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value);
void i_ddi_caut_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value);
void i_ddi_caut_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value);

void i_ddi_caut_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

void i_ddi_caut_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_put32(ddi_acc_impl_t *hdl, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags);
void i_ddi_caut_rep_put64(ddi_acc_impl_t *hdl, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_ISA_H */
