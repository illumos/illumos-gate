/*-
 * Copyright (c) 2001 Michael Smith <msmith@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <stand.h>
#include <machine/stdarg.h>
#include <bootstrap.h>
#include <btxv86.h>
#include "libi386.h"

#include "platform/acfreebsd.h"
#include "acconfig.h"
#define ACPI_SYSTEM_XFACE
#include "actypes.h"
#include "actbl.h"
#include "actbl3.h"

/*
 * Detect ACPI and export information about the ACPI BIOS into the
 * environment.
 */

ACPI_TABLE_RSDP	*rsdp;
static ACPI_TABLE_RSDP	*biosacpi_find_rsdp(void);
static ACPI_TABLE_RSDP	*biosacpi_search_rsdp(char *base, int length);

#define RSDP_CHECKSUM_LENGTH 20

static ACPI_TABLE_SPCR *
find_spcr(ACPI_TABLE_RSDP *rsdp)
{
	unsigned count, i;
	ACPI_TABLE_XSDT *xsdt;
	ACPI_TABLE_RSDT *rsdt;
	void *ptr;

	if (rsdp->Revision >= 2 && rsdp->XsdtPhysicalAddress != 0) {
		xsdt = (ACPI_TABLE_XSDT *)
		    PTOV((uintptr_t)rsdp->XsdtPhysicalAddress);

		count = xsdt->Header.Length - sizeof (ACPI_TABLE_HEADER);
		count /= sizeof (xsdt->TableOffsetEntry[0]);
		for (i = 0; i < count; i++) {
			ptr = PTOV((uintptr_t)xsdt->TableOffsetEntry[i]);
			if (memcmp(ptr, ACPI_SIG_SPCR,
			    sizeof (ACPI_SIG_SPCR) - 1) == 0) {
				return (ptr);
			}
		}
	}
	if (rsdp->RsdtPhysicalAddress != 0) {
		rsdt = (ACPI_TABLE_RSDT *)PTOV(rsdp->RsdtPhysicalAddress);

		count = rsdt->Header.Length - sizeof (ACPI_TABLE_HEADER);
		count /= sizeof (rsdt->TableOffsetEntry[0]);
		for (i = 0; i < count; i++) {
			ptr = PTOV(rsdt->TableOffsetEntry[i]);
			if (memcmp(ptr, ACPI_SIG_SPCR,
			    sizeof (ACPI_SIG_SPCR) - 1) == 0) {
				return (ptr);
			}
		}
	}
	return (NULL);
}

/*
 * Find and parse SPCR table to set up serial console.
 */
static void
biosacpi_setup_spcr(ACPI_TABLE_SPCR *spcr)
{
	unsigned baudrate;
	const char *port;
	char *name, *value;

	if (spcr == NULL)
		return;

	switch (spcr->BaudRate) {
	case 0:
		/* Use current port setting. */
		baudrate = 0;
		break;
	case 3:
		baudrate = 9600;
		break;
	case 4:
		baudrate = 19200;
		break;
	case 6:
		baudrate = 57600;
		break;
	case 7:
		baudrate = 115200;
		break;
	default:
		return;
	}

	port = NULL;
	name = NULL;
	value = NULL;

	switch (spcr->SerialPort.SpaceId) {
	case ACPI_ADR_SPACE_SYSTEM_IO:
		if (baudrate == 0)
			baudrate = comc_getspeed(spcr->SerialPort.Address);

		if (asprintf(&value, "%u,8,N,1,-", baudrate) < 0)
			return;

		switch (spcr->SerialPort.Address) {
		case 0x3F8:
			port = "ttya";
			break;
		case 0x2F8:
			port = "ttyb";
			break;
		case 0x3E8:
			port = "ttyc";
			break;
		case 0x2E8:
			port = "ttyd";
			break;
		default:
			break;
		}
		break;
	default:
		/* XXX not implemented. */
		break;
	}

	/*
	 * We want to set console according to SPCR. Also
	 * we need to store the SPCR reference value.
	 */
	if (port != NULL) {
		if (asprintf(&name, "%s,text", port) > 0) {
			setenv("console", name, 1);
			free(name);
		}
		if (asprintf(&name, "%s-mode", port) > 0) {
			setenv(name, value, 1);
			free(name);
		}
		if (asprintf(&name, "%s-spcr-mode", port) > 0) {
			setenv(name, value, 1);
			free(name);
		}
	}
	free(value);
}

void
biosacpi_detect(void)
{
	char	buf[24];
	int	revision;

	/* locate and validate the RSDP */
	if ((rsdp = biosacpi_find_rsdp()) == NULL)
		return;

	/* export values from the RSDP */
	sprintf(buf, "0x%08x", (unsigned int)VTOP(rsdp));
	setenv("acpi.rsdp", buf, 1);
	revision = rsdp->Revision;
	if (revision == 0)
		revision = 1;
	snprintf(buf, sizeof (buf), "%d", revision);
	setenv("acpi.revision", buf, 1);
	strncpy(buf, rsdp->OemId, sizeof(rsdp->OemId));
	buf[sizeof (rsdp->OemId)] = '\0';
	setenv("acpi.oem", buf, 1);
	snprintf(buf, sizeof (buf), "0x%08x", rsdp->RsdtPhysicalAddress);
	setenv("acpi.rsdt", buf, 1);
	if (revision >= 2) {
		/* XXX extended checksum? */
		snprintf(buf, sizeof (buf), "0x%016llx",
		    (unsigned long long)rsdp->XsdtPhysicalAddress);
		setenv("acpi.xsdt", buf, 1);
		sprintf(buf, "%d", rsdp->Length);
		setenv("acpi.xsdt_length", buf, 1);
	}
	biosacpi_setup_spcr(find_spcr(rsdp));
}

/*
 * Find the RSDP in low memory.  See section 5.2.2 of the ACPI spec.
 */
static ACPI_TABLE_RSDP *
biosacpi_find_rsdp(void)
{
    ACPI_TABLE_RSDP	*rsdp;
    uint16_t		*addr;

    /* EBDA is the 1 KB addressed by the 16 bit pointer at 0x40E. */
    addr = (uint16_t *)PTOV(0x40E);
    rsdp = biosacpi_search_rsdp((char *)(intptr_t)(*addr << 4), 0x400);
    if (rsdp != NULL)
	return (rsdp);

    /* Check the upper memory BIOS space, 0xe0000 - 0xfffff. */
    if ((rsdp = biosacpi_search_rsdp((char *)0xe0000, 0x20000)) != NULL)
	return (rsdp);

    return (NULL);
}

static ACPI_TABLE_RSDP *
biosacpi_search_rsdp(char *base, int length)
{
    ACPI_TABLE_RSDP	*rsdp;
    u_int8_t		*cp, sum;
    int			ofs, idx;

    /* search on 16-byte boundaries */
    for (ofs = 0; ofs < length; ofs += 16) {
	rsdp = (ACPI_TABLE_RSDP *)PTOV(base + ofs);

	/* compare signature, validate checksum */
	if (!strncmp(rsdp->Signature, ACPI_SIG_RSDP, strlen(ACPI_SIG_RSDP))) {
	    cp = (u_int8_t *)rsdp;
	    sum = 0;
	    for (idx = 0; idx < RSDP_CHECKSUM_LENGTH; idx++)
		sum += *(cp + idx);
	    if (sum != 0)
		continue;
	    return(rsdp);
	}
    }
    return(NULL);
}
