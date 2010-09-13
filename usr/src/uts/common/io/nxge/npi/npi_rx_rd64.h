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

#ifndef _NPI_RX_RD64_H
#define	_NPI_RX_RD64_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>

/*
 * RXDMA_REG_READ64
 *
 *	Read a 64-bit value from a DMC register.
 *
 * This is the old, rather convoluted,  macro:
 *
 * #define RXDMA_REG_READ64(handle, reg, channel, data_p) {	\
 *	NXGE_REG_RD64(handle, (NXGE_RXDMA_OFFSET(reg, \
 *	handle.is_vraddr, channel)), (data_p))
 *
 * There are 4 versions of NXGE_REG_RD64:
 * -------------------------------------------------------------
 * #if defined(REG_TRACE)
 * #define	NXGE_REG_RD64(handle, offset, val_p) {	\
 * 	*(val_p) = NXGE_NPI_PIO_READ64(handle, offset);			\
 * 	npi_rtrace_update(handle, B_FALSE, &npi_rtracebuf, (uint32_t)offset, \
 * 			(uint64_t)(*(val_p)));				\
 * }
 * #elif defined(REG_SHOW)
 * #define	NXGE_REG_RD64(handle, offset, val_p) {\
 * 	*(val_p) = NXGE_NPI_PIO_READ64(handle, offset);\
 * 	rt_show_reg(0xbadbad, B_FALSE, (uint32_t)offset, (uint64_t)(*(val_p)));\
 * }
 * #elif defined(AXIS_DEBUG) && !defined(LEGION)
 * #define	NXGE_REG_RD64(handle, offset, val_p) {\
 * 	int	n;				\
 * 	for (n = 0; n < AXIS_WAIT_LOOP; n++) {	\
 * 		*(val_p) = 0;		\
 * 		*(val_p) = NXGE_NPI_PIO_READ64(handle, offset);\
 * 		if (*(val_p) != (~0)) { \
 * 			break; \
 * 		}	\
 * 		drv_usecwait(AXIS_WAIT_PER_LOOP); \
 * 		if (n < 20) { \
 * 			cmn_err(CE_WARN, "NXGE_REG_RD64: loop %d " \
 * 			"REG 0x%x(0x%llx)", \
 * 			n, offset, *val_p);\
 * 		}	\
 * 	} \
 * 	if (n >= AXIS_WAIT_LOOP) {	\
 * 		cmn_err(CE_WARN, "(FATAL)NXGE_REG_RD64 on offset 0x%x " \
 * 			"with -1!!!", offset); \
 * 	}	\
 * }
 * #else
 * #define	NXGE_REG_RD64(handle, offset, val_p) {\
 * 	*(val_p) = NXGE_NPI_PIO_READ64(handle, offset);\
 * }
 * #endif
 *
 * There are 2 versions of NXGE_NPI_PIO_READ64:
 * -------------------------------------------------------------
 * #if defined(__i386)
 * #define	NXGE_NPI_PIO_READ64(npi_handle, offset)		\
 * 	(ddi_get64(NPI_REGH(npi_handle),		\
 * 	(uint64_t *)(NPI_REGP(npi_handle) + (uint32_t)offset)))
 * #else
 * #define	NXGE_NPI_PIO_READ64(npi_handle, offset)		\
 * 	(ddi_get64(NPI_REGH(npi_handle),		\
 * 	(uint64_t *)(NPI_REGP(npi_handle) + offset)))
 * #endif
 *
 * -------------------------------------------------------------
 * #define	NPI_REGH(npi_handle)		(npi_handle.regh)
 * #define	NPI_REGP(npi_handle)		(npi_handle.regp)
 *
 * Now let's tackle NXGE_RXDMA_OFFSET
 * -------------------------------------------------------------
 * #define	NXGE_RXDMA_OFFSET(x, v, channel) (x + \
 * 		(!v ? DMC_OFFSET(channel) : \
 *			RDMC_PIOVADDR_OFFSET(channel)))
 *
 * -------------------------------------------------------------
 * #define	DMC_OFFSET(channel)	(DMA_CSR_SIZE * channel)
 *
 * #define	TDMC_PIOVADDR_OFFSET(channel)	(2 * DMA_CSR_SIZE * channel)
 * -------------------------------------------------------------
 * #define	RDMC_PIOVADDR_OFFSET(channel) \
 *			(TDMC_OFFSET(channel) + DMA_CSR_SIZE)
 * -------------------------------------------------------------
 * #define	DMA_CSR_SIZE		512
 *
 * #define TDMC_OFFSET(channel)	(TX_RNG_CFIG + DMA_CSR_SIZE * channel)
 * #define TX_RNG_CFIG		(DMC + 0x40000)
 * -------------------------------------------------------------
 * This definition is clearly wrong!  I think this was intended:
 *
 * #define	RDMC_PIOVADDR_OFFSET(channel) \
 *			(TDMC_PIOVADDR__OFFSET(channel) + DMA_CSR_SIZE)
 * -------------------------------------------------------------
 *
 * Finally, we have the full macro:
 * -------------------------------------------------------------
 * #define RXDMA_REG_READ64(handle, reg, channel, data_p) {	\
 *	NXGE_REG_RD64(handle, (NXGE_RXDMA_OFFSET(reg, \
 *	handle.is_vraddr, channel)), (data_p))
 *
 * *data_p = ddi_get64(handle.regh, (uint64_t*)(handle.regp +
 *		((0x600000+0x00000) +
 *		(!handle.is_vraddr ?
 *			(512 * channel) :
 *			0x600000 + 0x40000 + (512 * channel) + 512)));
 */

static void RXDMA_REG_READ64(npi_handle_t, uint64_t, int, uint64_t *);
#pragma inline(RXDMA_REG_READ64)

/*
 * RXDMA_REG_READ64
 *
 *	Read a 64-bit value from a DMC register.
 *
 * Arguments:
 * 	handle	The NPI handle to use.
 * 	offset	The offset into the DMA CSR (the register).
 * 	channel	The channel, which is used as a multiplicand.
 * 	value	Where to put the 64-bit value to be read.
 *
 * Notes:
 *	If handle.regp is a virtual address (the address of a VR),
 *	we have to subtract the value DMC right off the bat.  DMC
 *	is defined as 0x600000, which works in a non-virtual address
 *	space, but not in a VR.  In a VR, a DMA CSR's space begins
 *	at zero (0).  So, since every call to RXMDA_REG_READ64 uses
 *	a register macro which adds in DMC, we have to subtract it.
 *
 *	The rest of it is pretty straighforward.  In a VR, a channel is
 *	logical, not absolute; and every DMA CSR is 512 bytes big;
 *	furthermore, a subpage of a VR is always ordered with the
 *	transmit CSRs first, followed by the receive CSRs.  That is,
 *	a 512 byte space of Tx CSRs, followed by a 512 byte space of
 *	Rx CSRs.  Hence this calculation:
 *
 *	offset += ((channel << 1) + 1) << DMA_CSR_SLL;
 *
 *	Here's an example:
 *
 *	RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel, value);
 *	Let's say channel is 3
 *	#define	RX_DMA_CTL_STAT_REG	(DMC + 0x00070)
 *	offset = 0x600070
 *	offset &= 0xff = 0x70
 *	offset += ((3 << 1) + 1) << 9
 *	3 << 1 = 6
 *	6 + 1 = 7
 *	7 << 9 = 0xe00
 *	offset += 0xe00 = 0xe70
 *
 *	Therefore, our register's (virtual) PIO address is 0xe70.
 *
 *	cf. Table 10-6 on page 181 of the Neptune PRM, v 1.4:
 *
 *	E00 - FFF CSRs for bound logical receive DMA channel 3.
 *
 *	In a non-virtual environment, you simply multiply the absolute
 *	channel number by 512 bytes, and get the correct offset to
 *	the register you're looking for.  That is, the RX_DMA_CTL_STAT CSR,
 *	is, as are all of these registers, in a table where each channel
 *	is offset 512 bytes from the previous channel (count 16 step 512).
 *
 *	offset += (channel << DMA_CSR_SLL);	// channel<<9 = channel*512
 *
 *	Here's an example:
 *
 *	RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel, value);
 *	Let's say channel is 3
 *	#define	RX_DMA_CTL_STAT_REG	(DMC + 0x00070)
 *	offset = 0x600070
 *	offset += (3 << 9)
 *	3 << 9 = 0x600
 *	offset += 0x600 = 0x600670
 *
 *	Therefore, our register's PIO address is 0x600670.
 *
 *	cf. Table 12-42 on page 234 of the Neptune PRM, v 1.4:
 *	RX_DMA_CTL_STAT (DMC + [0x]00070) (count 16 step [0x]200)
 *
 * Context:
 *	Guest domain
 *
 */
extern const char *nxge_rx2str(int);

void
RXDMA_REG_READ64(
	npi_handle_t handle,
	uint64_t offset,
	int channel,
	uint64_t *value)
{
#if defined(NPI_REG_TRACE)
	const char *name = nxge_rx2str((int)offset);
#endif
	if (handle.is_vraddr) {
		offset &= DMA_CSR_MASK;
		offset += (((channel << 1) + 1) << DMA_CSR_SLL);
	} else {
		offset += (channel << DMA_CSR_SLL);
	}

#if defined(__i386)
	*value = ddi_get64(handle.regh,
	    (uint64_t *)(handle.regp + (uint32_t)offset));
#else
	*value = ddi_get64(handle.regh, (uint64_t *)(handle.regp + offset));
#endif

#if defined(NPI_REG_TRACE)
	npi_trace_update(handle, B_FALSE, &npi_rtracebuf,
	    name, (uint32_t)offset, *value);
#elif defined(REG_SHOW)
	/*
	 * Since we don't have a valid RTBUF index to show, send 0xBADBAD.
	 */
	rt_show_reg(0xbadbad, B_FALSE, (uint32_t)offset, *value);
#endif
}

#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_RX_RD64_H */
