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

#ifndef _NPI_RX_RD32_H
#define	_NPI_RX_RD32_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>

static uint32_t RXDMA_REG_READ32(npi_handle_t, uint32_t, int);
#pragma inline(RXDMA_REG_READ32)

/*
 * RXDMA_REG_READ32
 *
 *	Read a 32-bit value from a DMC register.
 *
 * Arguments:
 * 	handle	The NPI handle to use.
 * 	offset	The offset into the DMA CSR (the register).
 * 	channel	The channel, which is used as a multiplicand.
 *
 * Notes:
 *	If handle.regp is a virtual address (the address of a VR),
 *	we have to subtract the value DMC right off the bat.  DMC
 *	is defined as 0x600000, which works in a non-virtual address
 *	space, but not in a VR.  In a VR, a DMA CSR's space begins
 *	at zero (0).  So, since every call to RXMDA_REG_READ32 uses
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
 *	RXDMA_REG_READ32(handle, RX_DMA_CTL_STAT_REG, channel);
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
 *	RXDMA_REG_READ32(handle, RX_DMA_CTL_STAT_REG, channel);
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
uint32_t
RXDMA_REG_READ32(
	npi_handle_t handle,
	uint32_t offset,
	int channel)
{
	if (handle.is_vraddr) {
		offset &= DMA_CSR_MASK;
		offset += (((channel << 1) + 1) << DMA_CSR_SLL);
	} else {
		offset += (channel << DMA_CSR_SLL);
	}

	return (ddi_get32(handle.regh, (uint32_t *)(handle.regp + offset)));
}

#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_RX_RD32_H */
