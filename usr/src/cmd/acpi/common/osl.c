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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "acpi.h"
#include "accommon.h"

UINT32
CmGetFileSize(ACPI_FILE File)
{
	int fd;
	struct stat sb;

	fd = fileno(File);
	if (fstat(fd, &sb) != 0)
		return (ACPI_UINT32_MAX);
	return ((UINT32)sb.st_size);
}

int
AcpiOsWriteFile(ACPI_FILE File, void *Buffer, ACPI_SIZE Size, ACPI_SIZE Count)
{
	return (fwrite(Buffer, Size, Count, File));
}

ACPI_FILE
AcpiOsOpenFile(const char *Path, UINT8 Modes)
{
	char mode[3];

	bzero(mode, sizeof (mode));
	if ((Modes & ACPI_FILE_READING) != 0)
		(void) strlcat(mode, "r", sizeof (mode));

	if ((Modes & ACPI_FILE_WRITING) != 0)
		(void) strlcat(mode, "w", sizeof (mode));

	return (fopen(Path, mode));
}

void
AcpiOsCloseFile(ACPI_FILE File)
{
	fclose(File);
}

int
AcpiOsReadFile(ACPI_FILE File, void *Buffer, ACPI_SIZE Size, ACPI_SIZE Count)
{
	return (fread(Buffer, Size, Count, File));
}
