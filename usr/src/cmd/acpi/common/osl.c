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
 * Copyright 2016 Joyent, Inc.
 */

#include <stdio.h>
#include <stdarg.h>
#include "acpi.h"
#include "accommon.h"

ACPI_STATUS
AcpiOsInitialize(void)
{
	return (AE_OK);
}

/*
 * The locking functions are no-ops because the application tools that use
 * these are all single threaded. However, due to the common code base that we
 * pull in from Intel, these functions are also called when the software is
 * compiled into the kernel, where it does need to do locking.
 */
ACPI_CPU_FLAGS
AcpiOsAcquireLock(ACPI_HANDLE Handle)
{
	return (AE_OK);
}

void
AcpiOsReleaseLock(ACPI_HANDLE Handle, ACPI_CPU_FLAGS Flags)
{
}

void
AcpiOsVprintf(const char *Format, va_list Args)
{
	vprintf(Format, Args);
}

void ACPI_INTERNAL_VAR_XFACE
AcpiOsPrintf(const char *Format, ...)
{
	va_list ap;

	va_start(ap, Format);
	AcpiOsVprintf(Format, ap);
	va_end(ap);
}

int
AcpiOsWriteFile(ACPI_FILE File, void *Buffer, ACPI_SIZE Size, ACPI_SIZE Count)
{
	return (fwrite(Buffer, Size, Count, File));
}
