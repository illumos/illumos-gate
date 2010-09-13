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

#ifndef _NPI_VIR_H
#define	_NPI_VIR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>
#include <nxge_hw.h>

/*
 * Virtualization and Logical devices NPI error codes
 */
#define	FUNCID_INVALID		PORT_INVALID
#define	VIR_ERR_ST		(VIR_BLK_ID << NPI_BLOCK_ID_SHIFT)
#define	VIR_ID_SHIFT(n)		(n << NPI_PORT_CHAN_SHIFT)

#define	VIR_HW_BUSY		(NPI_BK_HW_ERROR_START | 0x1)

#define	VIR_TAS_BUSY		(NPI_BK_ERROR_START | 0x1)
#define	VIR_TAS_NOTREAD	(NPI_BK_ERROR_START | 0x2)

#define	VIR_SR_RESET		(NPI_BK_ERROR_START | 0x3)
#define	VIR_SR_FREE		(NPI_BK_ERROR_START | 0x4)
#define	VIR_SR_BUSY		(NPI_BK_ERROR_START | 0x5)
#define	VIR_SR_INVALID		(NPI_BK_ERROR_START | 0x6)
#define	VIR_SR_NOTOWNER	(NPI_BK_ERROR_START | 0x7)
#define	VIR_SR_INITIALIZED	(NPI_BK_ERROR_START | 0x8)

#define	VIR_MPC_DENY		(NPI_BK_ERROR_START | 0x10)

#define	VIR_BD_FUNC_INVALID	(NPI_BK_ERROR_START | 0x20)
#define	VIR_BD_REG_INVALID	(NPI_BK_ERROR_START | 0x21)
#define	VIR_BD_ID_INVALID	(NPI_BK_ERROR_START | 0x22)
#define	VIR_BD_TXDMA_INVALID	(NPI_BK_ERROR_START | 0x23)
#define	VIR_BD_RXDMA_INVALID	(NPI_BK_ERROR_START | 0x24)

#define	VIR_LD_INVALID		(NPI_BK_ERROR_START | 0x30)
#define	VIR_LDG_INVALID		(NPI_BK_ERROR_START | 0x31)
#define	VIR_LDSV_INVALID	(NPI_BK_ERROR_START | 0x32)

#define	VIR_INTM_TM_INVALID	(NPI_BK_ERROR_START | 0x33)
#define	VIR_TM_RES_INVALID	(NPI_BK_ERROR_START | 0x34)
#define	VIR_SID_VEC_INVALID	(NPI_BK_ERROR_START | 0x35)

#define	NPI_VIR_OCODE_INVALID(n) (VIR_ID_SHIFT(n) | VIR_ERR_ST | OPCODE_INVALID)
#define	NPI_VIR_FUNC_INVALID(n)	 (VIR_ID_SHIFT(n) | VIR_ERR_ST | FUNCID_INVALID)
#define	NPI_VIR_CN_INVALID(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | CHANNEL_INVALID)

/*
 * Errors codes of shared register functions.
 */
#define	NPI_VIR_TAS_BUSY(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_TAS_BUSY)
#define	NPI_VIR_TAS_NOTREAD(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_TAS_NOTREAD)
#define	NPI_VIR_SR_RESET(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_SR_RESET)
#define	NPI_VIR_SR_FREE(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_SR_FREE)
#define	NPI_VIR_SR_BUSY(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_SR_BUSY)
#define	NPI_VIR_SR_INVALID(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_SR_INVALID)
#define	NPI_VIR_SR_NOTOWNER(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_SR_NOTOWNER)
#define	NPI_VIR_SR_INITIALIZED(n) (VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_SR_INITIALIZED)

/*
 * Error codes of muti-partition control register functions.
 */
#define	NPI_VIR_MPC_DENY	(VIR_ERR_ST | VIR_MPU_DENY)

/*
 * Error codes of DMA binding functions.
 */
#define	NPI_VIR_BD_FUNC_INVALID(n)	(VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_BD_FUNC_INVALID)
#define	NPI_VIR_BD_REG_INVALID(n)	(VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_BD_REG_INVALID)
#define	NPI_VIR_BD_ID_INVALID(n)	(VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_BD_ID_INVALID)
#define	NPI_VIR_BD_TXDMA_INVALID(n)	(VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_BD_TXDMA_INVALID)
#define	NPI_VIR_BD_RXDMA_INVALID(n)	(VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_BD_RXDMA_INVALID)

/*
 * Error codes of logical devices and groups functions.
 */
#define	NPI_VIR_LD_INVALID(n) 	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_LD_INVALID)
#define	NPI_VIR_LDG_INVALID(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_LDG_INVALID)
#define	NPI_VIR_LDSV_INVALID(n) (VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_LDSV_INVALID)
#define	NPI_VIR_INTM_TM_INVALID(n)	(VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_INTM_TM_INVALID)
#define	NPI_VIR_TM_RES_INVALID		(VIR_ERR_ST | VIR_TM_RES_INVALID)
#define	NPI_VIR_SID_VEC_INVALID(n)	(VIR_ID_SHIFT(n) | \
						VIR_ERR_ST | VIR_TM_RES_INVALID)

/*
 * Bit definition ([15:0] of the shared register
 * used by the driver as locking mechanism.
 *	[1:0]		lock state (RESET, FREE, BUSY)
 *	[3:2]		function ID (owner)
 *	[11:4]		Implementation specific states
 *	[15:12]  	Individual function state
 */
#define	NPI_DEV_SR_LOCK_ST_RESET	0
#define	NPI_DEV_SR_LOCK_ST_FREE		1
#define	NPI_DEV_SR_LOCK_ST_BUSY		2

#define	NPI_DEV_SR_LOCK_ST_SHIFT	0
#define	NPI_DEV_SR_LOCK_ST_MASK		0x03
#define	NPI_DEV_SR_LOCK_FID_SHIFT	2
#define	NPI_DEV_SR_LOCK_FID_MASK	0x0C

#define	NPI_DEV_SR_IMPL_ST_SHIFT	4
#define	NPI_DEV_SR_IMPL_ST_MASK	0xfff0

#define	NPI_GET_LOCK_OWNER(sr)		((sr & NPI_DEV_SR_LOCK_FID_MASK) \
						>> NPI_DEV_SR_LOCK_FID_SHIFT)
#define	NPI_GET_LOCK_ST(sr)		(sr & NPI_DEV_SR_LOCK_ST_MASK)
#define	NPI_GET_LOCK_IMPL_ST(sr)	((sr & NPI_DEV_SR_IMPL_ST_MASK) \
						>> NPI_DEV_SR_IMPL_ST_SHIFT)

/*
 * DMA channel binding definitions.
 */
#define	DMA_BIND_VADDR_VALIDATE(fn, rn, id, status)			\
{									\
	status = NPI_SUCCESS;						\
	if (!TXDMA_FUNC_VALID(fn)) {					\
		status = (NPI_FAILURE | NPI_VIR_BD_FUNC_INVALID(fn));	\
	} else if (!SUBREGION_VALID(rn)) {				\
		status = (NPI_FAILURE | NPI_VIR_BD_REG_INVALID(rn));	\
	} else if (!VIR_PAGE_INDEX_VALID(id)) {				\
		status = (NPI_FAILURE | NPI_VIR_BD_ID_INVALID(id));	\
	}								\
}

#define	DMA_BIND_TX_VALIDATE(n, status)					\
{									\
	status = NPI_SUCCESS;						\
	if (!TXDMA_CHANNEL_VALID(n)) {					\
		status = (NPI_FAILURE | NPI_VIR_BD_TXDMA_INVALID(n));	\
	}								\
}

#define	DMA_BIND_RX_VALIDATE(n, status)					\
{									\
	status = NPI_SUCCESS;						\
	if (!VRXDMA_CHANNEL_VALID(n)) {					\
		status = (NPI_FAILURE | NPI_VIR_BD_RXDMA_INVALID(n));	\
	}								\
}

#define	DMA_BIND_STEP			8
#define	DMA_BIND_REG_OFFSET(fn, rn, id)	(DMA_BIND_STEP * \
					(fn * 2 * VIR_PAGE_INDEX_MAX + \
					rn * VIR_PAGE_INDEX_MAX) + id)

/*
 * NPI defined data structure to program the DMA binding register.
 */
typedef struct _fzc_dma_bind {
	uint8_t		function_id;	/* 0 to 3 */
	uint8_t		sub_vir_region;	/* 0 or 1 */
	uint8_t		vir_index;	/* 0 to 7 */
	boolean_t	tx_bind;	/* set 1 to bind */
	uint8_t		tx_channel;	/* hardware channel number (0 - 23) */
	boolean_t	rx_bind;	/* set 1 to bind */
	uint8_t		rx_channel;	/* hardware channel number (0 - 15) */
} fzc_dma_bind_t, *p_fzc_dma_bind;

/*
 * Logical device definitions.
 */
#define	LD_NUM_STEP		8
#define	LD_NUM_OFFSET(ld)	(ld * LDG_NUM_STEP)
#define	LDG_NUM_STEP		8
#define	LDG_NUM_OFFSET(ldg)	(ldg * LDG_NUM_STEP)
#define	LDGNUM_OFFSET(ldg)	(ldg * LDG_NUM_STEP)
#define	LDSV_STEP		8192
#define	LDSVG_OFFSET(ldg)	(ldg * LDSV_STEP)
#define	LDSV_OFFSET(ldv)	(ldv * LDSV_STEP)

#define	LDSV_OFFSET_MASK(ld)			\
	(((ld < NXGE_MAC_LD_START) ?		\
	(LD_IM0_REG + LDSV_OFFSET(ld)) :	\
	(LD_IM1_REG + LDSV_OFFSET((ld - NXGE_MAC_LD_START))))); \

#define	LDG_SID_STEP		8
#define	LDG_SID_OFFSET(ldg)	(ldg * LDG_SID_STEP)

typedef enum {
	LDF0,
	LDF1
} ldf_type_t;

typedef enum {
	VECTOR0,
	VECTOR1,
	VECTOR2
} ldsv_type_t;

/*
 * Definitions for the system interrupt data.
 */
typedef struct _fzc_sid {
	boolean_t	niu;
	uint8_t		ldg;
	uint8_t		func;
	uint8_t		vector;
} fzc_sid_t, *p_fzc_sid_t;

/*
 * Virtualization and Interrupt Prototypes.
 */
/*
 * npi_dev_func_sr_init():
 *	This function is called to initialize the device function
 *	shared register (set the software implementation lock
 *	state to FREE).
 * Parameters:
 *	handle		- NPI handle
 * Return:
 *	NPI_SUCCESS	- If initialization is complete successfully.
 *			  (set sr bits to free).
 *	Error:
 *	NPI_FAILURE
 *		VIR_TAS_BUSY
 */
npi_status_t npi_dev_func_sr_init(npi_handle_t);

/*
 * npi_dev_func_sr_lock_enter():
 *	This function is called to lock the function shared register
 *	by setting the lock state to busy.
 * Parameters:
 *	handle		- NPI handle
 * Return:
 *	NPI_SUCCESS	- If the function id can own the lock.
 *
 *	Error:
 *	NPI_FAILURE
 *		VIR_SR_RESET
 *		VIR_SR_BUSY
 *		VIR_SR_INVALID
 *		VIR_TAS_BUSY
 */
npi_status_t npi_dev_func_sr_lock_enter(npi_handle_t);

/*
 * npi_dev_func_sr_lock_free():
 *	This function is called to free the function shared register
 *	by setting the lock state to free.
 * Parameters:
 *	handle		- NPI handle
 * Return:
 *	NPI_SUCCESS	- If the function id can free the lock.
 *
 *	Error:
 *	NPI_FAILURE
 *		VIR_SR_NOTOWNER
 *		VIR_TAS_NOTREAD
 */
npi_status_t npi_dev_func_sr_lock_free(npi_handle_t);

/*
 * npi_dev_func_sr_funcid_get():
 *	This function is called to get the caller's function ID.
 *	(based on address bits [25:26] on read access.
 *	(After read, the TAS bit is always set to 1. Software needs
 *	to write 0 to clear.) This function will write 0 to clear
 *	the TAS bit if we own it.
 * Parameters:
 *	handle		- NPI handle
 *	funcid_p	- pointer to store the function id.
 * Return:
 *	NPI_SUCCESS	- If get function id is complete successfully.
 *
 *	Error:
 */
npi_status_t npi_dev_func_sr_funcid_get(npi_handle_t, uint8_t *);

/*
 * npi_dev_func_sr_sr_raw_get():
 *	This function is called to get the shared register value.
 *	(After read, the TAS bit is always set to 1. Software needs
 *	to write 0 to clear if we own it.)
 *
 * Parameters:
 *	handle		- NPI handle
 *	sr_p		- pointer to store the shared value of this register.
 *
 * Return:
 *	NPI_SUCCESS		- If shared value get is complete successfully.
 *
 *	Error:
 */
npi_status_t npi_dev_func_sr_sr_raw_get(npi_handle_t, uint16_t *);

/*
 * npi_dev_func_sr_sr_get():
 *	This function is called to get the shared register value.
 *	(After read, the TAS bit is always set to 1. Software needs
 *	to write 0 to clear if we own it.)
 *
 * Parameters:
 *	handle		- NPI handle
 *	sr_p		- pointer to store the shared value of this register.
 *		    . this will get only non-lock, non-function id portion
 *              . of the register
 *
 *
 * Return:
 *	NPI_SUCCESS		- If shared value get is complete successfully.
 *
 *	Error:
 */

npi_status_t npi_dev_func_sr_sr_get(npi_handle_t, uint16_t *);

/*
 * npi_dev_func_sr_sr_get_set_clear():
 *	This function is called to set the shared register value.
 *	(Shared register must be read first. If tas bit is 0, then
 *	it implies that the software can proceed to set). After
 *	setting, tas bit will be cleared.
 * Parameters:
 *	handle		- NPI handle
 *	impl_sr		- shared value to set (only the 8 bit
 *			  implementation specific state info).
 *
 * Return:
 *	NPI_SUCCESS		- If shared value is set successfully.
 *
 *	Error:
 *	NPI_FAILURE
 *		VIR_TAS_BUSY
 */
npi_status_t npi_dev_func_sr_sr_get_set_clear(npi_handle_t,
					    uint16_t);

/*
 * npi_dev_func_sr_sr_set_only():
 *	This function is called to only set the shared register value.
 * Parameters:
 *	handle		- NPI handle
 *	impl_sr		- shared value to set.
 *
 * Return:
 *	NPI_SUCCESS		- If shared value is set successfully.
 *
 *	Error:
 *	NPI_FAILURE
 *		VIR_TAS_BUSY
 */
npi_status_t npi_dev_func_sr_sr_set_only(npi_handle_t, uint16_t);

/*
 * npi_dev_func_sr_busy():
 *	This function is called to see if we can own the device.
 *	It will not reset the tas bit.
 * Parameters:
 *	handle		- NPI handle
 *	busy_p		- pointer to store busy flag.
 *				(B_TRUE: device is in use, B_FALSE: free).
 * Return:
 *	NPI_SUCCESS		- If tas bit is read successfully.
 *	Error:
 */
npi_status_t npi_dev_func_sr_busy(npi_handle_t, boolean_t *);

/*
 * npi_dev_func_sr_tas_get():
 *	This function is called to get the tas bit
 *	(after read, this bit is always set to 1, software write 0
 *	 to clear it).
 *
 * Parameters:
 *	handle		- NPI handle
 *	tas_p		- pointer to store the tas value
 *
 * Return:
 *	NPI_SUCCESS		- If tas value get is complete successfully.
 *	Error:
 */
npi_status_t npi_dev_func_sr_tas_get(npi_handle_t, uint8_t *);

/*
 * npi_fzc_mpc_set():
 *	This function is called to enable the write access
 *	to FZC region to function zero.
 * Parameters:
 *	handle		- NPI handle
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 */
npi_status_t npi_fzc_mpc_set(npi_handle_t, boolean_t);

/*
 * npi_fzc_mpc_get():
 *	This function is called to get the access mode.
 * Parameters:
 *	handle		- NPI handle
 * Return:
 *	NPI_SUCCESS	-
 *
 */
npi_status_t npi_fzc_mpc_get(npi_handle_t, boolean_t *);

/*
 * npi_fzc_dma_bind_set():
 *	This function is called to set DMA binding register.
 * Parameters:
 *	handle		- NPI handle
 *	dma_bind	- NPI defined data structure that
 *			  contains the tx/rx channel binding info.
 *			  to set.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 *
 */
npi_status_t npi_fzc_dma_bind_set(npi_handle_t, fzc_dma_bind_t);

/*
 * npi_fzc_dma_bind_get():
 *	This function is called to get a DMA binding register.
 * Parameters:
 *	handle		- NPI handle
 *	dma_bind	- NPI defined data structure that
 *			  contains the tx/rx channel binding info.
 *	value		- Where to put the register value.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 *
 */
npi_status_t npi_fzc_dma_bind_get(npi_handle_t, fzc_dma_bind_t, uint64_t *);

/*
 * npi_fzc_ldg_num_set():
 *	This function is called to set up a logical group number that
 *	a logical device belongs to.
 * Parameters:
 *	handle		- NPI handle
 *	ld		- logical device number (0 - 68)
 *	ldg		- logical device group number (0 - 63)
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 *
 */
npi_status_t npi_fzc_ldg_num_set(npi_handle_t, uint8_t, uint8_t);

/*
 * npi_fzc_ldg_num_get():
 *	This function is called to get the logical device group that
 *	a logical device belongs to.
 * Parameters:
 *	handle		- NPI handle
 *	ld		- logical device number (0 - 68)
 *	*ldg_p		- pointer to store its group number.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_fzc_ldg_num_get(npi_handle_t, uint8_t,
		uint8_t *);

npi_status_t npi_ldsv_ldfs_get(npi_handle_t, uint8_t,
		uint64_t *, uint64_t *, uint64_t *);
/*
 * npi_ldsv_get():
 *	This function is called to get device state vectors.
 * Parameters:
 *	handle		- NPI handle
 *	ldg		- logical device group (0 - 63)
 *	ldf_type	- either LDF0 (0) or LDF1 (1)
 *	vector		- vector type (0, 1 or 2)
 *	*ldf_p		- pointer to store its flag bits.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_ldsv_get(npi_handle_t, uint8_t, ldsv_type_t,
		uint64_t *);

/*
 * npi_ldsv_ld_get():
 *	This function is called to get the flag bit value of a device.
 * Parameters:
 *	handle		- NPI handle
 *	ldg		- logical device group (0 - 63)
 *	ld		- logical device (0 - 68)
 *	ldf_type	- either LDF0 (0) or LDF1 (1)
 *	vector		- vector type (0, 1 or 2)
 *	*ldf_p		- pointer to store its flag bits.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_ldsv_ld_get(npi_handle_t, uint8_t, uint8_t,
		ldsv_type_t, ldf_type_t, boolean_t *);
/*
 * npi_ldsv_ld_ldf0_get():
 *	This function is called to get the ldf0 bit value of a device.
 * Parameters:
 *	handle		- NPI handle
 *	ldg		- logical device group (0 - 63)
 *	ld		- logical device (0 - 68)
 *	*ldf_p		- pointer to store its flag bits.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_ldsv_ld_ldf0_get(npi_handle_t, uint8_t, uint8_t,
		boolean_t *);

/*
 * npi_ldsv_ld_ldf1_get():
 *	This function is called to get the ldf1 bit value of a device.
 * Parameters:
 *	handle		- NPI handle
 *	ldg		- logical device group (0 - 63)
 *	ld		- logical device (0 - 68)
 *	*ldf_p		- pointer to store its flag bits.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_ldsv_ld_ldf1_get(npi_handle_t, uint8_t, uint8_t,
		boolean_t *);
/*
 * npi_intr_mask_set():
 *	This function is called to select the mask bits for both ldf0 and ldf1.
 * Parameters:
 *	handle		- NPI handle
 *	ld		- logical device (0 - 68)
 *	ldf_mask	- mask value to set (both ldf0 and ldf1).
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_intr_mask_set(npi_handle_t, uint8_t,
			uint8_t);

/*
 * npi_intr_mask_get():
 *	This function is called to get the mask bits.
 * Parameters:
 *	handle		- NPI handle
 *	ld		- logical device (0 - 68)
 *	ldf_mask	- pointer to store mask bits info.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_intr_mask_get(npi_handle_t, uint8_t,
			uint8_t *);

/*
 * npi_intr_ldg_mgmt_set():
 *	This function is called to set interrupt timer and arm bit.
 * Parameters:
 *	handle		- NPI handle
 *	ldg		- logical device group (0 - 63)
 *	arm		- B_TRUE (arm) B_FALSE (disable)
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_intr_ldg_mgmt_set(npi_handle_t, uint8_t,
			boolean_t, uint8_t);


/*
 * npi_intr_ldg_mgmt_timer_get():
 *	This function is called to get the timer counter
 * Parameters:
 *	handle		- NPI handle
 *	ldg		- logical device group (0 - 63)
 *	timer_p		- pointer to store the timer counter.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_intr_ldg_mgmt_timer_get(npi_handle_t, uint8_t,
		uint8_t *);

/*
 * npi_intr_ldg_mgmt_arm():
 *	This function is called to arm the group.
 * Parameters:
 *	handle		- NPI handle
 *	ldg		- logical device group (0 - 63)
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_intr_ldg_mgmt_arm(npi_handle_t, uint8_t);

/*
 * npi_fzc_ldg_timer_res_set():
 *	This function is called to set the timer resolution.
 * Parameters:
 *	handle		- NPI handle
 *	res		- timer resolution (# of system clocks)
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_fzc_ldg_timer_res_set(npi_handle_t, uint32_t);

/*
 * npi_fzc_ldg_timer_res_get():
 *	This function is called to get the timer resolution.
 * Parameters:
 *	handle		- NPI handle
 *	res_p		- pointer to store the timer resolution.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_fzc_ldg_timer_res_get(npi_handle_t, uint8_t *);

/*
 * npi_fzc_sid_set():
 *	This function is called to set the system interrupt data.
 * Parameters:
 *	handle		- NPI handle
 *	ldg		- logical group (0 - 63)
 *	sid		- NPI defined data to set
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_fzc_sid_set(npi_handle_t, fzc_sid_t);

/*
 * npi_fzc_sid_get():
 *	This function is called to get the system interrupt data.
 * Parameters:
 *	handle		- NPI handle
 *	ldg		- logical group (0 - 63)
 *	sid_p		- NPI defined data to get
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */
npi_status_t npi_fzc_sid_get(npi_handle_t, p_fzc_sid_t);
npi_status_t npi_fzc_sys_err_mask_set(npi_handle_t, uint64_t);
npi_status_t npi_fzc_sys_err_stat_get(npi_handle_t,
						p_sys_err_stat_t);
npi_status_t npi_vir_dump_pio_fzc_regs_one(npi_handle_t);
npi_status_t npi_vir_dump_ldgnum(npi_handle_t);
npi_status_t npi_vir_dump_ldsv(npi_handle_t);
npi_status_t npi_vir_dump_imask0(npi_handle_t);
npi_status_t npi_vir_dump_sid(npi_handle_t);
#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_VIR_H */
