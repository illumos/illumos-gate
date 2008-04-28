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

#ifndef _NPI_TX_RD64_H
#define	_NPI_TX_RD64_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>

static void TXDMA_REG_READ64(npi_handle_t, uint64_t, int, uint64_t *);
#pragma inline(TXDMA_REG_READ64)

/*
 * TXDMA_REG_READ64
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
 *	For reference, here is the old macro:
 *
 *	#define	TXDMA_REG_READ64(handle, reg, channel, val_p)	\
 *			NXGE_REG_RD64(handle,			\
 *		(NXGE_TXDMA_OFFSET(reg, handle.is_vraddr, channel)), val_p)
 *
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
 *	offset += ((channel << 1) << DMA_CSR_SLL);
 *
 *	Here's an example:
 *
 *	TXDMA_REG_READ64(handle, TX_CS_REG, channel, &value);
 *	Let's say channel is 3
 *	#define	TX_CS_REG		(DMC + 0x40028)
 *	offset = 0x640028
 *	offset &= 0xff = 0x28
 *	offset += ((3 << 1) << 9)
 *	3 << 1 = 6
 *	6 << 9 = 0xc00
 *	offset += 0xc00 = 0xc28
 *
 *	Therefore, our register's (virtual) PIO address is 0xc28.
 *
 *	cf. Table 10-6 on page 181 of the Neptune PRM, v 1.4:
 *
 *	C00 - dFF CSRs for bound logical transmit DMA channel 3.
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
 *	TXDMA_REG_READ64(handle, TX_CS_REG, channel, &value);
 *	Let's say channel is 3
 *	#define	TX_CS_REG		(DMC + 0x40028)
 *	offset = 0x640028
 *	offset += (3 << 9)
 *	3 << 9 = 0x600
 *	offset += 0x600 = 0x640628
 *
 *	Therefore, our register's PIO address is 0x640628.
 *
 *	cf. Table 13-15 on page 265 of the Neptune PRM, v 1.4:
 *	TX_CS (DMC + 4002816) (count 24 step 0x200)
 *
 * Context:
 *	Any domain
 *
 */
extern const char *nxge_tx2str(int);

void
TXDMA_REG_READ64(
	npi_handle_t handle,
	uint64_t offset,
	int channel,
	uint64_t *value)
{
#if defined(NPI_REG_TRACE)
	const char *name = nxge_tx2str((int)offset);
#endif
	if (handle.is_vraddr) {
		offset &= DMA_CSR_MASK;
		offset += ((channel << 1) << DMA_CSR_SLL);
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

#endif	/* _NPI_TX_RD64_H */
