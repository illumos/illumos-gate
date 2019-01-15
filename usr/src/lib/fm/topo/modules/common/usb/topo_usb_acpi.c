/*
 * Copyright (C) 2000 - 2016, Intel Corp.
 * Copyright (c) 2018, Joyent, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    substantially similar to the "NO WARRANTY" disclaimer below
 *    ("Disclaimer") and any redistribution must be conditioned upon
 *    including a substantially similar Disclaimer requirement for further
 *    binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 */

/*
 * This allows us to embed the decoding of the _PLD data structure method. While
 * this is normally part of the broader ACPI code dump, it has been pulled out
 * to simplify the management and required set of ACPI tools. The _PLD is the
 * physical location of the device. It is a series of fields that is
 * theoretically supposed to tell you information about where a given device is,
 * its shape, color, etc. This data is only as good as the firwmare that
 * provides it. This is defined in the ACPI specification in section 6.1.8 (ACPI
 * 6.2).
 */

#include <strings.h>
#include "topo_usb_int.h"

boolean_t
usbtopo_decode_pld(uint8_t *buf, size_t len, ACPI_PLD_INFO *infop)
{
	uint32_t *buf32p;
	size_t i;

	if (buf == NULL || len < ACPI_PLD_REV1_BUFFER_SIZE)
		return (B_FALSE);

	/*
	 * Look through the array of bytes that we have. We've found some cases
	 * where we have buffers that are basically all zeros aside from the
	 * revision, which is revision one.
	 */
	for (i = 1; i < len; i++) {
		if (buf[i] != 0)
			break;
	}
	if (i == len && buf[0] == 0x01)
		return (B_FALSE);

	buf32p = (uint32_t *)buf;
	bzero(infop, sizeof (*infop));

	/* First 32-bit DWord */
	infop->Revision = ACPI_PLD_GET_REVISION(&buf32p[0]);
	infop->IgnoreColor = ACPI_PLD_GET_IGNORE_COLOR(&buf32p[0]);
	infop->Red = ACPI_PLD_GET_RED(&buf32p[0]);
	infop->Green = ACPI_PLD_GET_GREEN(&buf32p[0]);
	infop->Blue = ACPI_PLD_GET_BLUE(&buf32p[0]);

	/* Second 32-bit DWord */
	infop->Width = ACPI_PLD_GET_WIDTH(&buf32p[1]);
	infop->Height = ACPI_PLD_GET_HEIGHT(&buf32p[1]);

	/* Third 32-bit DWord */
	infop->UserVisible = ACPI_PLD_GET_USER_VISIBLE(&buf32p[2]);
	infop->Dock = ACPI_PLD_GET_DOCK(&buf32p[2]);
	infop->Lid = ACPI_PLD_GET_LID(&buf32p[2]);
	infop->Panel = ACPI_PLD_GET_PANEL(&buf32p[2]);
	infop->VerticalPosition = ACPI_PLD_GET_VERTICAL(&buf32p[2]);
	infop->HorizontalPosition = ACPI_PLD_GET_HORIZONTAL(&buf32p[2]);
	infop->Shape = ACPI_PLD_GET_SHAPE(&buf32p[2]);
	infop->GroupOrientation = ACPI_PLD_GET_ORIENTATION(&buf32p[2]);
	infop->GroupToken = ACPI_PLD_GET_TOKEN(&buf32p[2]);
	infop->GroupPosition = ACPI_PLD_GET_POSITION(&buf32p[2]);
	infop->Bay = ACPI_PLD_GET_BAY(&buf32p[2]);

	/* Fourth 32-bit DWord */
	infop->Ejectable = ACPI_PLD_GET_EJECTABLE(&buf32p[3]);
	infop->OspmEjectRequired = ACPI_PLD_GET_OSPM_EJECT(&buf32p[3]);
	infop->CabinetNumber = ACPI_PLD_GET_CABINET(&buf32p[3]);
	infop->CardCageNumber = ACPI_PLD_GET_CARD_CAGE(&buf32p[3]);
	infop->Reference = ACPI_PLD_GET_REFERENCE(&buf32p[3]);
	infop->Rotation = ACPI_PLD_GET_ROTATION(&buf32p[3]);
	infop->Order = ACPI_PLD_GET_ORDER(&buf32p[3]);

	if (len >= ACPI_PLD_REV2_BUFFER_SIZE && infop->Revision >= 2) {
		/* Fifth 32-bit DWord (Revision 2 of _PLD) */

		infop->VerticalOffset = ACPI_PLD_GET_VERT_OFFSET(&buf32p[4]);
		infop->HorizontalOffset = ACPI_PLD_GET_HORIZ_OFFSET(&buf32p[4]);
	}

	return (B_TRUE);
}
