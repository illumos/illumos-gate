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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <npi_vir.h>

/* One register only */
uint64_t pio_offset[] = {
	DEV_FUNC_SR_REG
};

const char *pio_name[] = {
	"DEV_FUNC_SR_REG",
};

/* One register only */
uint64_t fzc_pio_offset[] = {
	MULTI_PART_CTL_REG,
	LDGITMRES_REG
};

const char *fzc_pio_name[] = {
	"MULTI_PART_CTL_REG",
	"LDGITMRES_REG"
};

/* 64 sets */
uint64_t fzc_pio_dma_bind_offset[] = {
	DMA_BIND_REG
};

const char *fzc_pio_dma_bind_name[] = {
	"DMA_BIND_REG",
};

/* 69 logical devices */
uint64_t fzc_pio_ldgnum_offset[] = {
	LDG_NUM_REG
};

const char *fzc_pio_ldgnum_name[] = {
	"LDG_NUM_REG",
};

/* PIO_LDSV, 64 sets by 8192 bytes */
uint64_t pio_ldsv_offset[] = {
	LDSV0_REG,
	LDSV1_REG,
	LDSV2_REG,
	LDGIMGN_REG
};
const char *pio_ldsv_name[] = {
	"LDSV0_REG",
	"LDSV1_REG",
	"LDSV2_REG",
	"LDGIMGN_REG"
};

/* PIO_IMASK0: 64 by 8192 */
uint64_t pio_imask0_offset[] = {
	LD_IM0_REG,
};

const char *pio_imask0_name[] = {
	"LD_IM0_REG",
};

/* PIO_IMASK1: 5 by 8192 */
uint64_t pio_imask1_offset[] = {
	LD_IM1_REG
};

const char *pio_imask1_name[] = {
	"LD_IM1_REG"
};

/* SID: 64 by 8 */
uint64_t fzc_pio_sid_offset[] = {
	SID_REG
};

const char *fzc_pio_sid_name[] = {
	"SID_REG"
};

npi_status_t
npi_vir_dump_pio_fzc_regs_one(npi_handle_t handle)
{
	uint64_t value;
	int num_regs, i;

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nPIO FZC Common Register Dump\n"));

	num_regs = sizeof (pio_offset) / sizeof (uint64_t);
	for (i = 0; i < num_regs; i++) {
		value = 0;
		NXGE_REG_RD64(handle, pio_offset[i], &value);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL, "0x%08llx "
		    "%s\t 0x%08llx \n",
		    pio_offset[i],
		    pio_name[i], value));
	}

	num_regs = sizeof (fzc_pio_offset) / sizeof (uint64_t);
	for (i = 0; i < num_regs; i++) {
		NXGE_REG_RD64(handle, fzc_pio_offset[i], &value);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL, "0x%08llx "
		    "%s\t 0x%08llx \n",
		    fzc_pio_offset[i],
		    fzc_pio_name[i], value));
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n PIO FZC Register Dump Done \n"));
	return (NPI_SUCCESS);
}

npi_status_t
npi_vir_dump_ldgnum(npi_handle_t handle)
{
	uint64_t value = 0, offset = 0;
	int num_regs, i, ldv;

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nFZC PIO LDG Number Register Dump\n"));

	num_regs = sizeof (fzc_pio_ldgnum_offset) / sizeof (uint64_t);
	for (ldv = 0; ldv < NXGE_INT_MAX_LDS; ldv++) {
		for (i = 0; i < num_regs; i++) {
			value = 0;
			offset = fzc_pio_ldgnum_offset[i] + 8 * ldv;
			NXGE_REG_RD64(handle, offset, &value);
			NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
			    "Logical Device %d: 0x%08llx "
			    "%s\t %d\n",
			    ldv, offset,
			    fzc_pio_ldgnum_name[i], value));
		}
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n FZC PIO LDG Register Dump Done \n"));

	return (NPI_SUCCESS);
}

npi_status_t
npi_vir_dump_ldsv(npi_handle_t handle)
{
	uint64_t value, offset;
	int num_regs, i, ldg;

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nLD Device State Vector Register Dump\n"));

	num_regs = sizeof (pio_ldsv_offset) / sizeof (uint64_t);
	for (ldg = 0; ldg < NXGE_INT_MAX_LDGS; ldg++) {
		for (i = 0; i < num_regs; i++) {
			value = 0;
			offset = pio_ldsv_offset[i] + 8192 * ldg;
			NXGE_REG_RD64(handle, offset, &value);
			NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
			    "LDG State: group %d: 0x%08llx "
			    "%s\t 0x%08llx \n",
			    ldg, offset,
			    pio_ldsv_name[i], value));
		}
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n FZC PIO LDG Register Dump Done \n"));

	return (NPI_SUCCESS);
}

npi_status_t
npi_vir_dump_imask0(npi_handle_t handle)
{
	uint64_t value, offset;
	int num_regs, i, ldv;

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nLD Interrupt Mask Register Dump\n"));

	num_regs = sizeof (pio_imask0_offset) / sizeof (uint64_t);
	for (ldv = 0; ldv < 64; ldv++) {
		for (i = 0; i < num_regs; i++) {
			value = 0;
			offset = pio_imask0_offset[i] + 8192 * ldv;
			NXGE_REG_RD64(handle, offset,
			    &value);
			NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
			    "LD Interrupt Mask %d: 0x%08llx "
			    "%s\t 0x%08llx \n",
			    ldv, offset,
			    pio_imask0_name[i], value));
		}
	}
	num_regs = sizeof (pio_imask1_offset) / sizeof (uint64_t);
	for (ldv = 64; ldv < 69; ldv++) {
		for (i = 0; i < num_regs; i++) {
			value = 0;
			offset = pio_imask1_offset[i] + 8192 * (ldv - 64);
			NXGE_REG_RD64(handle, offset,
			    &value);
			NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
			    "LD Interrupt Mask %d: 0x%08llx "
			    "%s\t 0x%08llx \n",
			    ldv, offset,
			    pio_imask1_name[i], value));
		}
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n FZC PIO Logical Device Group Register Dump Done \n"));

	return (NPI_SUCCESS);
}

npi_status_t
npi_vir_dump_sid(npi_handle_t handle)
{
	uint64_t value, offset;
	int num_regs, i, ldg;

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nSystem Interrupt Data Register Dump\n"));

	num_regs = sizeof (fzc_pio_sid_offset) / sizeof (uint64_t);
	for (ldg = 0; ldg < NXGE_INT_MAX_LDGS; ldg++) {
		for (i = 0; i < num_regs; i++) {
			value = 0;
			offset = fzc_pio_sid_offset[i] + 8 * ldg;
			NXGE_REG_RD64(handle, offset,
			    &value);
			NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
			    "SID for group %d: 0x%08llx "
			    "%s\t 0x%08llx \n",
			    ldg, offset,
			    fzc_pio_sid_name[i], value));
		}
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n FZC PIO SID Register Dump Done \n"));

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_dev_func_sr_init(npi_handle_t handle)
{
	dev_func_sr_t		sr;
	int			status = NPI_SUCCESS;

	NXGE_REG_RD64(handle, DEV_FUNC_SR_REG, &sr.value);
	if (!sr.bits.ldw.tas) {
		/*
		 * After read, this bit is set to 1 by hardware.
		 * We own it if tas bit read as 0.
		 * Set the lock state to free if it is in reset state.
		 */
		if (!sr.bits.ldw.sr) {
			/* reset state */
			sr.bits.ldw.sr |= NPI_DEV_SR_LOCK_ST_FREE;
			NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);
			sr.bits.ldw.tas = 0;
			NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);
		}

		NPI_DEBUG_MSG((handle.function, NPI_VIR_CTL,
		    " npi_dev_func_sr_init"
		    " sr <0x%x>",
		    sr.bits.ldw.sr));
	} else {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_dev_func_sr_init"
		    " tas busy <0x%x>",
		    sr.bits.ldw));
		status = NPI_VIR_TAS_BUSY(sr.bits.ldw.funcid);
	}

	return (status);
}

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

npi_status_t
npi_dev_func_sr_lock_enter(npi_handle_t handle)
{
	dev_func_sr_t		sr;
	int			status = NPI_SUCCESS;
	uint32_t		state;

	NXGE_REG_RD64(handle, DEV_FUNC_SR_REG, &sr.value);
	if (!sr.bits.ldw.tas) {
		/*
		 * tas bit will be set to 1 by hardware.
		 * reset tas bit when we unlock the sr.
		 */
		state = sr.bits.ldw.sr & NPI_DEV_SR_LOCK_ST_MASK;
		switch (state) {
		case NPI_DEV_SR_LOCK_ST_FREE:
			/*
			 * set it to busy and our function id.
			 */
			sr.bits.ldw.sr |= (NPI_DEV_SR_LOCK_ST_BUSY |
			    (sr.bits.ldw.funcid <<
			    NPI_DEV_SR_LOCK_FID_SHIFT));
			NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);
			break;

		case NPI_DEV_SR_LOCK_ST_RESET:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_dev_func_sr_lock_enter"
			    " reset state <0x%x>",
			    sr.bits.ldw.sr));
			status = NPI_VIR_SR_RESET(sr.bits.ldw.funcid);
			break;

		case NPI_DEV_SR_LOCK_ST_BUSY:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_dev_func_sr_lock_enter"
			    " busy <0x%x>",
			    sr.bits.ldw.sr));
			status = NPI_VIR_SR_BUSY(sr.bits.ldw.funcid);
			break;

		default:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_dev_func_sr_lock_enter",
			    " invalid state",
			    sr.bits.ldw.sr));
			status = NPI_VIR_SR_INVALID(sr.bits.ldw.funcid);
			break;
		}
	} else {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_dev_func_sr_lock_enter",
		    " tas busy", sr.bits.ldw));
		status = NPI_VIR_TAS_BUSY(sr.bits.ldw.funcid);
	}

	return (status);
}

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

npi_status_t
npi_dev_func_sr_lock_free(npi_handle_t handle)
{
	dev_func_sr_t		sr;
	int			status = NPI_SUCCESS;

	NXGE_REG_RD64(handle, DEV_FUNC_SR_REG, &sr.value);
	if (sr.bits.ldw.tas) {
		if (sr.bits.ldw.funcid == NPI_GET_LOCK_OWNER(sr.bits.ldw.sr)) {
			sr.bits.ldw.sr &= NPI_DEV_SR_IMPL_ST_MASK;
			sr.bits.ldw.sr |= NPI_DEV_SR_LOCK_ST_FREE;
			sr.bits.ldw.tas = 0;
			NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);
		} else {
			NPI_DEBUG_MSG((handle.function, NPI_VIR_CTL,
			    " npi_dev_func_sr_lock_free"
			    " not owner <0x%x>",
			    sr.bits.ldw.sr));
			status = NPI_VIR_SR_NOTOWNER(sr.bits.ldw.funcid);
		}
	} else {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_dev_func_sr_lock_free",
		    " invalid tas state <0x%x>",
		    sr.bits.ldw.tas));
		status = NPI_VIR_TAS_NOTREAD(sr.bits.ldw.funcid);
	}

	return (status);
}

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

npi_status_t
npi_dev_func_sr_funcid_get(npi_handle_t handle, uint8_t *funcid_p)
{
	dev_func_sr_t		sr;

	NXGE_REG_RD64(handle, DEV_FUNC_SR_REG, &sr.value);
	*funcid_p = NXGE_VAL(DEV_FUNC_SR_FUNCID, sr.value);
	if (!sr.bits.ldw.tas) {
		/*
		 * After read, this bit is set to 1 by hardware.
		 * We own it if tas bit read as 0.
		 */
		sr.bits.ldw.tas = 0;
		NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);
	}

	return (NPI_SUCCESS);
}

/*
 * npi_dev_func_sr_sr_get():
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
npi_status_t
npi_dev_func_sr_sr_raw_get(npi_handle_t handle, uint16_t *sr_p)
{
	dev_func_sr_t		sr;

	NXGE_REG_RD64(handle, DEV_FUNC_SR_REG, &sr.value);
	*sr_p = NXGE_VAL(DEV_FUNC_SR_FUNCID, sr.value);
	if (!sr.bits.ldw.tas) {
		/*
		 * After read, this bit is set to 1 by hardware.
		 * We own it if tas bit read as 0.
		 */
		sr.bits.ldw.tas = 0;
		NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);
	}

	return (NPI_SUCCESS);
}

/*
 * npi_dev_func_sr_sr_get():
 *	This function is called to get the shared register value.
 *	(After read, the TAS bit is always set to 1. Software needs
 *	to write 0 to clear if we own it.)
 *
 * Parameters:
 *	handle	- NPI handle
 *	sr_p	- pointer to store the shared value of this register.
 *		. this will get only non-lock, non-function id portion
 *              . of the register
 *
 *
 * Return:
 *	NPI_SUCCESS		- If shared value get is complete successfully.
 *
 *	Error:
 */

npi_status_t
npi_dev_func_sr_sr_get(npi_handle_t handle, uint16_t *sr_p)
{
	dev_func_sr_t		sr;
	uint16_t sr_impl = 0;

	NXGE_REG_RD64(handle, DEV_FUNC_SR_REG, &sr.value);
	sr_impl = NXGE_VAL(DEV_FUNC_SR_FUNCID, sr.value);
	*sr_p =  (sr_impl << NPI_DEV_SR_IMPL_ST_SHIFT);
	if (!sr.bits.ldw.tas) {
		/*
		 * After read, this bit is set to 1 by hardware.
		 * We own it if tas bit read as 0.
		 */
		sr.bits.ldw.tas = 0;
		NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);
	}

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_dev_func_sr_sr_get_set_clear(npi_handle_t handle, uint16_t impl_sr)
{
	dev_func_sr_t		sr;
	int			status;

	status = npi_dev_func_sr_lock_enter(handle);
	if (status != NPI_SUCCESS) {
		NPI_DEBUG_MSG((handle.function, NPI_VIR_CTL,
		    " npi_dev_func_sr_src_get_set_clear"
		    " unable to acquire lock:"
		    " status <0x%x>", status));
		return (status);
	}

	NXGE_REG_RD64(handle, DEV_FUNC_SR_REG, &sr.value);
	sr.bits.ldw.sr |= (impl_sr << NPI_DEV_SR_IMPL_ST_SHIFT);
	NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);

	return (npi_dev_func_sr_lock_free(handle));
}

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

npi_status_t
npi_dev_func_sr_sr_set_only(npi_handle_t handle, uint16_t impl_sr)
{
	int		status = NPI_SUCCESS;
	dev_func_sr_t	sr;

	NXGE_REG_RD64(handle, DEV_FUNC_SR_REG, &sr.value);
	/* must be the owner */
	if (sr.bits.ldw.funcid == NPI_GET_LOCK_OWNER(sr.bits.ldw.sr)) {
		sr.bits.ldw.sr |= (impl_sr << NPI_DEV_SR_IMPL_ST_SHIFT);
		NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);
	} else {
		NPI_DEBUG_MSG((handle.function, NPI_VIR_CTL,
		    " npi_dev_func_sr_sr_set_only"
		    " not owner <0x%x>",
		    sr.bits.ldw.sr));
		status = NPI_VIR_SR_NOTOWNER(sr.bits.ldw.funcid);
	}

	return (status);
}

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

npi_status_t
npi_dev_func_sr_busy(npi_handle_t handle, boolean_t *busy_p)
{
	dev_func_sr_t	sr;

	NXGE_REG_RD64(handle, DEV_FUNC_SR_REG, &sr.value);
	if (!sr.bits.ldw.tas) {
		sr.bits.ldw.tas = 0;
		NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);
		*busy_p = B_FALSE;
	} else {
		/* Other function already owns it */
		*busy_p = B_TRUE;
	}

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_dev_func_sr_tas_get(npi_handle_t handle, uint8_t *tas_p)
{
	dev_func_sr_t		sr;

	NXGE_REG_RD64(handle, DEV_FUNC_SR_REG, &sr.value);
	*tas_p = sr.bits.ldw.tas;
	if (!sr.bits.ldw.tas) {
		sr.bits.ldw.tas = 0;
		NXGE_REG_WR64(handle, DEV_FUNC_SR_REG, sr.value);

	}

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_fzc_mpc_set(npi_handle_t handle, boolean_t mpc)
{
	multi_part_ctl_t	mp;

	mp.value = 0;
	if (mpc) {
		mp.bits.ldw.mpc = 1;
	}
	NXGE_REG_WR64(handle, MULTI_PART_CTL_REG, mp.value);

	return (NPI_SUCCESS);
}

/*
 * npi_fzc_mpc_get():
 *	This function is called to get the access mode.
 * Parameters:
 *	handle		- NPI handle
 * Return:
 *	NPI_SUCCESS	-
 *
 */

npi_status_t
npi_fzc_mpc_get(npi_handle_t handle, boolean_t *mpc_p)
{
	multi_part_ctl_t	mpc;

	mpc.value = 0;
	NXGE_REG_RD64(handle, MULTI_PART_CTL_REG, &mpc.value);
	*mpc_p = mpc.bits.ldw.mpc;

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_fzc_dma_bind_set(npi_handle_t handle, fzc_dma_bind_t dma_bind)
{
	dma_bind_t	bind;
	int		status;
	uint8_t		fn, region, id, tn, rn;

	fn = dma_bind.function_id;
	region = dma_bind.sub_vir_region;
	id = dma_bind.vir_index;
	tn = dma_bind.tx_channel;
	rn = dma_bind.rx_channel;

	DMA_BIND_VADDR_VALIDATE(fn, region, id, status);
	if (status) {
		return (status);
	}

	if (dma_bind.tx_bind) {
		DMA_BIND_TX_VALIDATE(tn, status);
		if (status) {
			return (status);
		}
	}

	if (dma_bind.rx_bind) {
		DMA_BIND_RX_VALIDATE(rn, status);
		if (status) {
			return (status);
		}
	}

	bind.value = 0;
	if (dma_bind.tx_bind) {
		bind.bits.ldw.tx_bind = 1;
		bind.bits.ldw.tx = tn;
	}
	if (dma_bind.rx_bind) {
		bind.bits.ldw.rx_bind = 1;
		bind.bits.ldw.rx = rn;
	}

	NXGE_REG_WR64(handle, DMA_BIND_REG +
	    DMA_BIND_REG_OFFSET(fn, region, id), bind.value);

	return (status);
}

npi_status_t
npi_fzc_dma_bind_get(
	npi_handle_t handle,
	fzc_dma_bind_t dma_bind,
	uint64_t *pValue)
{
	uint8_t		function, region, slot;
	int		offset;
	int		status;

	function = dma_bind.function_id;
	region = dma_bind.sub_vir_region;
	slot = dma_bind.vir_index;

	DMA_BIND_VADDR_VALIDATE(function, region, slot, status);
	if (status) {
		return (status);
	}

	offset = DMA_BIND_REG_OFFSET(function, region, slot);
	NXGE_REG_RD64(handle, DMA_BIND_REG + offset, pValue);

	return (status);
}

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

npi_status_t
npi_fzc_ldg_num_set(npi_handle_t handle, uint8_t ld, uint8_t ldg)
{
	ldg_num_t	gnum;

	ASSERT(LD_VALID(ld));
	if (!LD_VALID(ld)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fzc_ldg_num_set"
		    "ld <0x%x>", ld));
		return (NPI_FAILURE | NPI_VIR_LD_INVALID(ld));
	}

	ASSERT(LDG_VALID(ldg));
	if (!LDG_VALID(ldg)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fzc_ldg_num_set"
		    " ldg <0x%x>", ldg));
		return (NPI_FAILURE | NPI_VIR_LDG_INVALID(ld));
	}

	gnum.value = 0;
	gnum.bits.ldw.num = ldg;

	NXGE_REG_WR64(handle, LDG_NUM_REG + LD_NUM_OFFSET(ld),
	    gnum.value);

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_fzc_ldg_num_get(npi_handle_t handle, uint8_t ld, uint8_t *ldg_p)
{
	uint64_t val;

	ASSERT(LD_VALID(ld));
	if (!LD_VALID(ld)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fzc_ldg_num_get"
		    " Invalid Input:",
		    " ld <0x%x>", ld));
		return (NPI_FAILURE | NPI_VIR_LD_INVALID(ld));
	}

	NXGE_REG_RD64(handle, LDG_NUM_REG + LD_NUM_OFFSET(ld), &val);

	*ldg_p = (uint8_t)(val & LDG_NUM_NUM_MASK);

	return (NPI_SUCCESS);
}

/*
 * npi_ldsv_ldfs_get():
 *	This function is called to get device state vectors.
 * Parameters:
 *	handle		- NPI handle
 *	ldg		- logical device group (0 - 63)
 *	*ldf_p		- pointer to store ldf0 and ldf1 flag bits.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */

npi_status_t
npi_ldsv_ldfs_get(npi_handle_t handle, uint8_t ldg, uint64_t *vector0_p,
	uint64_t *vector1_p, uint64_t *vector2_p)
{
	int	status;

	if ((status = npi_ldsv_get(handle, ldg, VECTOR0, vector0_p))) {
		return (status);
	}
	if ((status = npi_ldsv_get(handle, ldg, VECTOR1, vector1_p))) {
		return (status);
	}
	if ((status = npi_ldsv_get(handle, ldg, VECTOR2, vector2_p))) {
		return (status);
	}

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_ldsv_get(npi_handle_t handle, uint8_t ldg, ldsv_type_t vector,
	uint64_t *ldf_p)
{
	uint64_t		offset;

	ASSERT(LDG_VALID(ldg));
	if (!LDG_VALID(ldg)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ldsv_get"
		    " Invalid Input "
		    " ldg <0x%x>", ldg));
		return (NPI_FAILURE | NPI_VIR_LDG_INVALID(ldg));
	}

	switch (vector) {
	case VECTOR0:
		offset = LDSV0_REG + LDSV_OFFSET(ldg);
		break;

	case VECTOR1:
		offset = LDSV1_REG + LDSV_OFFSET(ldg);
		break;

	case VECTOR2:
		offset = LDSV2_REG + LDSV_OFFSET(ldg);
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ldsv_get"
		    " Invalid Input: "
		    " ldsv type <0x%x>", vector));
		return (NPI_FAILURE | NPI_VIR_LDSV_INVALID(vector));
	}

	NXGE_REG_RD64(handle, offset, ldf_p);

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_ldsv_ld_get(npi_handle_t handle, uint8_t ldg, uint8_t ld,
	ldsv_type_t vector, ldf_type_t ldf_type, boolean_t *flag_p)
{
	uint64_t		sv;
	uint64_t		offset;

	ASSERT(LDG_VALID(ldg));
	if (!LDG_VALID(ldg)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ldsv_ld_get"
		    " Invalid Input: "
		    " ldg <0x%x>", ldg));
		return (NPI_FAILURE | NPI_VIR_LDG_INVALID(ldg));
	}
	ASSERT((LD_VALID(ld)) &&	\
	    ((vector != VECTOR2) || (ld >= NXGE_MAC_LD_START)));
	if (!LD_VALID(ld)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ldsv_ld_get Invalid Input: "
		    " ld <9x%x>", ld));
		return (NPI_FAILURE | NPI_VIR_LD_INVALID(ld));
	} else if (vector == VECTOR2 && ld < NXGE_MAC_LD_START) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_ldsv_ld_get Invalid Input:"
		    " ld-vector2 <0x%x>", ld));
		return (NPI_FAILURE | NPI_VIR_LD_INVALID(ld));
	}

	switch (vector) {
	case VECTOR0:
		offset = LDSV0_REG + LDSV_OFFSET(ldg);
		break;

	case VECTOR1:
		offset = LDSV1_REG + LDSV_OFFSET(ldg);
		break;

	case VECTOR2:
		offset = LDSV2_REG + LDSV_OFFSET(ldg);

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL, "npi_ldsv_get"
		    "ldsv", vector));
		return (NPI_FAILURE | NPI_VIR_LDSV_INVALID(vector));
	}

	NXGE_REG_RD64(handle, offset, &sv);
	if (vector != VECTOR2) {
		*flag_p = ((sv >> ld) & LDSV_MASK_ALL);
	} else {
		if (ldf_type) {
			*flag_p = (((sv >> LDSV2_LDF1_SHIFT) >>
			    (ld - NXGE_MAC_LD_START)) & LDSV_MASK_ALL);
		} else {
			*flag_p = (((sv >> LDSV2_LDF0_SHIFT) >>
			    (ld - NXGE_MAC_LD_START)) & LDSV_MASK_ALL);
		}
	}

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_ldsv_ld_ldf0_get(npi_handle_t handle, uint8_t ldg, uint8_t ld,
	boolean_t *flag_p)
{
	ldsv_type_t vector;

	if (ld >= NXGE_MAC_LD_START) {
		vector = VECTOR2;
	}

	return (npi_ldsv_ld_get(handle, ldg, ld, vector, LDF0, flag_p));
}

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

npi_status_t
npi_ldsv_ld_ldf1_get(npi_handle_t handle, uint8_t ldg, uint8_t ld,
		boolean_t *flag_p)
{
	ldsv_type_t vector;

	if (ld >= NXGE_MAC_LD_START) {
		vector = VECTOR2;
	}

	return (npi_ldsv_ld_get(handle, ldg, ld, vector, LDF1, flag_p));
}

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

npi_status_t
npi_intr_mask_set(npi_handle_t handle, uint8_t ld, uint8_t ldf_mask)
{
	uint64_t		offset;

	ASSERT(LD_VALID(ld));
	if (!LD_VALID(ld)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_intr_mask_set ld", ld));
		return (NPI_FAILURE | NPI_VIR_LD_INVALID(ld));
	}

	ldf_mask &= LD_IM0_MASK;
	offset = LDSV_OFFSET_MASK(ld);

	NPI_DEBUG_MSG((handle.function, NPI_VIR_CTL,
	    "npi_intr_mask_set: ld %d "
	    " offset 0x%0llx "
	    " mask 0x%x",
	    ld, offset, ldf_mask));

	NXGE_REG_WR64(handle, offset, (uint64_t)ldf_mask);

	return (NPI_SUCCESS);
}

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
npi_status_t
npi_intr_mask_get(npi_handle_t handle, uint8_t ld, uint8_t *ldf_mask_p)
{
	uint64_t		offset;
	uint64_t		val;

	ASSERT(LD_VALID(ld));
	if (!LD_VALID(ld)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_intr_mask_get ld", ld));
		return (NPI_FAILURE | NPI_VIR_LD_INVALID(ld));
	}

	offset = LDSV_OFFSET_MASK(ld);

	NXGE_REG_RD64(handle, offset, &val);

	*ldf_mask_p = (uint8_t)(val & LD_IM_MASK);

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_intr_ldg_mgmt_set(npi_handle_t handle, uint8_t ldg, boolean_t arm,
			uint8_t timer)
{
	ldgimgm_t		mgm;
	uint64_t		val;

	ASSERT((LDG_VALID(ldg)) && (LD_INTTIMER_VALID(timer)));
	if (!LDG_VALID(ldg)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_intr_ldg_mgmt_set"
		    " Invalid Input: "
		    " ldg <0x%x>", ldg));
		return (NPI_FAILURE | NPI_VIR_LDG_INVALID(ldg));
	}
	if (!LD_INTTIMER_VALID(timer)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_intr_ldg_mgmt_set Invalid Input"
		    " timer <0x%x>", timer));
		return (NPI_FAILURE | NPI_VIR_INTM_TM_INVALID(ldg));
	}

	if (arm) {
		mgm.bits.ldw.arm = 1;
	} else {
		NXGE_REG_RD64(handle, LDGIMGN_REG + LDSV_OFFSET(ldg), &val);
		mgm.value = val & LDGIMGM_ARM_MASK;
	}

	mgm.bits.ldw.timer = timer;
	NXGE_REG_WR64(handle, LDGIMGN_REG + LDSV_OFFSET(ldg),
	    mgm.value);

	NPI_DEBUG_MSG((handle.function, NPI_VIR_CTL,
	    " npi_intr_ldg_mgmt_set: ldg %d"
	    " reg offset 0x%x",
	    ldg, LDGIMGN_REG + LDSV_OFFSET(ldg)));

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_intr_ldg_mgmt_timer_get(npi_handle_t handle, uint8_t ldg, uint8_t *timer_p)
{
	uint64_t val;

	ASSERT(LDG_VALID(ldg));
	if (!LDG_VALID(ldg)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_intr_ldg_mgmt_timer_get"
		    " Invalid Input: ldg <0x%x>", ldg));
		return (NPI_FAILURE | NPI_VIR_LDG_INVALID(ldg));
	}

	NXGE_REG_RD64(handle, LDGIMGN_REG + LDSV_OFFSET(ldg), &val);

	*timer_p = (uint8_t)(val & LDGIMGM_TIMER_MASK);

	NPI_DEBUG_MSG((handle.function, NPI_VIR_CTL,
	    " npi_intr_ldg_mgmt_timer_get: ldg %d"
	    " reg offset 0x%x",
	    ldg, LDGIMGN_REG + LDSV_OFFSET(ldg)));

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_intr_ldg_mgmt_arm(npi_handle_t handle, uint8_t ldg)
{
	ldgimgm_t		mgm;

	ASSERT(LDG_VALID(ldg));
	if (!LDG_VALID(ldg)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_intr_ldg_mgmt_arm"
		    " Invalid Input: ldg <0x%x>",
		    ldg));
		return (NPI_FAILURE | NPI_VIR_LDG_INVALID(ldg));
	}

	NXGE_REG_RD64(handle, (LDGIMGN_REG + LDSV_OFFSET(ldg)), &mgm.value);
	mgm.bits.ldw.arm = 1;

	NXGE_REG_WR64(handle, LDGIMGN_REG + LDSV_OFFSET(ldg),
	    mgm.value);
	NPI_DEBUG_MSG((handle.function, NPI_VIR_CTL,
	    " npi_intr_ldg_mgmt_arm: ldg %d"
	    " reg offset 0x%x",
	    ldg, LDGIMGN_REG + LDSV_OFFSET(ldg)));

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_fzc_ldg_timer_res_set(npi_handle_t handle, uint32_t res)
{
	ASSERT(res <= LDGTITMRES_RES_MASK);
	if (res > LDGTITMRES_RES_MASK) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fzc_ldg_timer_res_set"
		    " Invalid Input: res <0x%x>",
		    res));
		return (NPI_FAILURE | NPI_VIR_TM_RES_INVALID);
	}

	NXGE_REG_WR64(handle, LDGITMRES_REG, (res & LDGTITMRES_RES_MASK));

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_fzc_ldg_timer_res_get(npi_handle_t handle, uint8_t *res_p)
{
	uint64_t val;

	NXGE_REG_RD64(handle, LDGITMRES_REG, &val);

	*res_p = (uint8_t)(val & LDGIMGM_TIMER_MASK);

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_fzc_sid_set(npi_handle_t handle, fzc_sid_t sid)
{
	sid_t		sd;

	ASSERT(LDG_VALID(sid.ldg));
	if (!LDG_VALID(sid.ldg)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fzc_sid_set"
		    " Invalid Input: ldg <0x%x>",
		    sid.ldg));
		return (NPI_FAILURE | NPI_VIR_LDG_INVALID(sid.ldg));
	}
	if (!sid.niu) {
		ASSERT(FUNC_VALID(sid.func));
		if (!FUNC_VALID(sid.func)) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_fzc_sid_set"
			    " Invalid Input: func <0x%x>",
			    sid.func));
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    "invalid FUNC: npi_fzc_sid_set(%d)", sid.func));
			return (NPI_FAILURE | NPI_VIR_FUNC_INVALID(sid.func));
		}

		ASSERT(SID_VECTOR_VALID(sid.vector));
		if (!SID_VECTOR_VALID(sid.vector)) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_fzc_sid_set"
			    " Invalid Input: vector <0x%x>",
			    sid.vector));
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " invalid VECTOR: npi_fzc_sid_set(%d)",
			    sid.vector));
			return (NPI_FAILURE |
			    NPI_VIR_SID_VEC_INVALID(sid.vector));
		}
	}
	sd.value = 0;
	if (!sid.niu) {
		sd.bits.ldw.data = ((sid.func << SID_DATA_FUNCNUM_SHIFT) |
		    (sid.vector & SID_DATA_INTNUM_MASK));
	}

	NPI_DEBUG_MSG((handle.function, NPI_VIR_CTL,
	    " npi_fzc_sid_set: group %d 0x%llx", sid.ldg, sd.value));

	NXGE_REG_WR64(handle,  SID_REG + LDG_SID_OFFSET(sid.ldg), sd.value);

	return (NPI_SUCCESS);
}

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

npi_status_t
npi_fzc_sid_get(npi_handle_t handle, p_fzc_sid_t sid_p)
{
	sid_t		sd;

	ASSERT(LDG_VALID(sid_p->ldg));
	if (!LDG_VALID(sid_p->ldg)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_fzc_sid_get"
		    " Invalid Input: ldg <0x%x>",
		    sid_p->ldg));
		return (NPI_FAILURE | NPI_VIR_LDG_INVALID(sid_p->ldg));
	}
	NXGE_REG_RD64(handle, (SID_REG + LDG_SID_OFFSET(sid_p->ldg)),
	    &sd.value);
	if (!sid_p->niu) {
		sid_p->func = ((sd.bits.ldw.data & SID_DATA_FUNCNUM_MASK) >>
		    SID_DATA_FUNCNUM_SHIFT);
		sid_p->vector = ((sd.bits.ldw.data & SID_DATA_INTNUM_MASK) >>
		    SID_DATA_INTNUM_SHIFT);
	} else {
		sid_p->vector = (sd.value & SID_DATA_MASK);
	}

	return (NPI_SUCCESS);
}

/*
 * npi_fzc_sys_err_mask_set():
 *	This function is called to mask/unmask the device error mask bits.
 *
 * Parameters:
 *	handle		- NPI handle
 *	mask		- set bit mapped mask
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */

npi_status_t
npi_fzc_sys_err_mask_set(npi_handle_t handle, uint64_t mask)
{
	NXGE_REG_WR64(handle,  SYS_ERR_MASK_REG, mask);
	return (NPI_SUCCESS);
}

/*
 * npi_fzc_sys_err_stat_get():
 *	This function is called to get the system error stats.
 *
 * Parameters:
 *	handle		- NPI handle
 *	err_stat	- sys_err_stat structure to hold stats.
 * Return:
 *	NPI_SUCCESS	-
 *	Error:
 *	NPI_FAILURE
 */

npi_status_t
npi_fzc_sys_err_stat_get(npi_handle_t handle, p_sys_err_stat_t statp)
{
	NXGE_REG_RD64(handle,  SYS_ERR_STAT_REG, &statp->value);
	return (NPI_SUCCESS);
}

npi_status_t
npi_fzc_rst_ctl_get(npi_handle_t handle, p_rst_ctl_t rstp)
{
	NXGE_REG_RD64(handle, RST_CTL_REG, &rstp->value);

	return (NPI_SUCCESS);
}

/*
 * npi_fzc_mpc_get():
 *	This function is called to get the access mode.
 * Parameters:
 *	handle		- NPI handle
 * Return:
 *	NPI_SUCCESS	-
 *
 */

npi_status_t
npi_fzc_rst_ctl_reset_mac(npi_handle_t handle, uint8_t port)
{
	rst_ctl_t 		rst;

	rst.value = 0;
	NXGE_REG_RD64(handle, RST_CTL_REG, &rst.value);
	rst.value |= (1 << (RST_CTL_MAC_RST0_SHIFT + port));
	NXGE_REG_WR64(handle, RST_CTL_REG, rst.value);

	return (NPI_SUCCESS);
}
