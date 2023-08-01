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
 * Copyright 2016 Tooams Soome <tsoome@me.com>
 */

#include <sys/cdefs.h>

#include <stand.h>
#include <machine/stdarg.h>
#include <bootstrap.h>
#include <efi.h>
#include <efilib.h>
#include <Guid/Acpi.h>

#include "platform/acfreebsd.h"
#include "acconfig.h"
#define	ACPI_SYSTEM_XFACE
#include "actypes.h"
#include "actbl.h"

ACPI_TABLE_RSDP	*rsdp;
EFI_GUID gEfiAcpiTableGuid = ACPI_TABLE_GUID;
EFI_GUID gEfiAcpi20TableGuid = EFI_ACPI_TABLE_GUID;

void
acpi_detect(void)
{
	char		buf[24];
	int		revision;

	if ((rsdp = efi_get_table(&gEfiAcpi20TableGuid)) == NULL)
		rsdp = efi_get_table(&gEfiAcpiTableGuid);

	if (rsdp == NULL)
		return;

	/* export values from the RSDP */
#ifdef _LP64
	snprintf(buf, sizeof (buf), "0x%016llx", (unsigned long long)rsdp);
#else
	snprintf(buf, sizeof (buf), "0x%08x", (unsigned int)rsdp);
#endif
	setenv("acpi.rsdp", buf, 1);
	revision = rsdp->Revision;
	if (revision == 0)
		revision = 1;
	snprintf(buf, sizeof (buf), "%d", revision);
	setenv("acpi.revision", buf, 1);
	strncpy(buf, rsdp->OemId, sizeof (rsdp->OemId));
	buf[sizeof (rsdp->OemId)] = '\0';
	setenv("acpi.oem", buf, 1);
#ifdef _LP64
	snprintf(buf, sizeof (buf), "0x%016llx",
	    (unsigned long long)rsdp->RsdtPhysicalAddress);
#else
	snprintf(buf, sizeof (buf), "0x%08x", rsdp->RsdtPhysicalAddress);
#endif
	setenv("acpi.rsdt", buf, 1);
	if (revision >= 2) {
		snprintf(buf, sizeof (buf), "0x%016llx",
		    (unsigned long long)rsdp->XsdtPhysicalAddress);
		setenv("acpi.xsdt", buf, 1);
		snprintf(buf, sizeof (buf), "%d", rsdp->Length);
		setenv("acpi.xsdt_length", buf, 1);
	}
}
