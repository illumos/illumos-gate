/*
 *
 * Module Name: osillumostbl - illumos OSL for obtaining ACPI tables
 * This file is derived from the Intel oslinuxtbl source file.
 *
 */

/*
 * Copyright (C) 2000 - 2016, Intel Corp.
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
 * Copyright 2016 Joyent, Inc.
 */

#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "acpidump.h"

#define	_COMPONENT	ACPI_OS_SERVICES
    ACPI_MODULE_NAME("osillumostbl")

/* List of information about obtained ACPI tables */

typedef struct osl_table_info
{
	struct osl_table_info	*Next;
	UINT32			Instance;
	char			Signature[ACPI_NAME_SIZE];
} OSL_TABLE_INFO;

/* Local prototypes */
static ACPI_STATUS
OslTableInitialize(void);
static ACPI_STATUS OslTableNameFromFile(char *, char *, UINT32 *);
static ACPI_STATUS OslAddTableToList(char *);
static ACPI_STATUS OslMapTable(ACPI_SIZE, char *, ACPI_TABLE_HEADER **);
static void OslUnmapTable(ACPI_TABLE_HEADER *);
static ACPI_STATUS OslLoadRsdp(void);
static ACPI_STATUS OslListBiosTables(void);
static ACPI_STATUS OslGetBiosTable(char *, UINT32, ACPI_TABLE_HEADER **,
    ACPI_PHYSICAL_ADDRESS *);
static ACPI_STATUS OslGetLastStatus(ACPI_STATUS);

static int pagesize;

/* Initialization flags */
UINT8			Gbl_TableListInitialized = FALSE;

/* Local copies of main ACPI tables */
ACPI_TABLE_RSDP		Gbl_Rsdp;
ACPI_TABLE_FADT		*Gbl_Fadt = NULL;
ACPI_TABLE_RSDT		*Gbl_Rsdt = NULL;
ACPI_TABLE_XSDT		*Gbl_Xsdt = NULL;

/* Table addresses */
ACPI_PHYSICAL_ADDRESS	Gbl_FadtAddress = 0;
ACPI_PHYSICAL_ADDRESS	Gbl_RsdpAddress = 0;

/* Revision of RSD PTR */
UINT8			Gbl_Revision = 0;

OSL_TABLE_INFO		*Gbl_TableListHead = NULL;
UINT32			Gbl_TableCount = 0;

/*
 *
 * FUNCTION:    OslGetLastStatus
 *
 * PARAMETERS:  DefaultStatus   - Default error status to return
 *
 * RETURN:      Status; Converted from errno.
 *
 * DESCRIPTION: Get last errno and conver it to ACPI_STATUS.
 *
 */
static ACPI_STATUS
OslGetLastStatus(ACPI_STATUS DefaultStatus)
{
	switch (errno) {
	case EACCES:
	case EPERM:
		return (AE_ACCESS);

	case ENOENT:
		return (AE_NOT_FOUND);

	case ENOMEM:
		return (AE_NO_MEMORY);

	default:
		return (DefaultStatus);
	}
}

/*
 *
 * FUNCTION:    AcpiOsGetTableByAddress
 *
 * PARAMETERS:  Address         - Physical address of the ACPI table
 *              Table           - Where a pointer to the table is returned
 *
 * RETURN:      Status; Table buffer is returned if AE_OK.
 *              AE_NOT_FOUND: A valid table was not found at the address
 *
 * DESCRIPTION: Get an ACPI table via a physical memory address.
 *
 */
ACPI_STATUS
AcpiOsGetTableByAddress(ACPI_PHYSICAL_ADDRESS Address,
    ACPI_TABLE_HEADER **Table)
{
	UINT32			TableLength;
	ACPI_TABLE_HEADER	*MappedTable;
	ACPI_TABLE_HEADER	*LocalTable = NULL;
	ACPI_STATUS		Status = AE_OK;

	/*
	 * Get main ACPI tables from memory on first invocation of this
	 * function
	 */
	Status = OslTableInitialize();
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	/* Map the table and validate it */

	Status = OslMapTable(Address, NULL, &MappedTable);
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	/* Copy table to local buffer and return it */

	TableLength = ApGetTableLength(MappedTable);
	if (TableLength == 0) {
		Status = AE_BAD_HEADER;
		goto Exit;
	}

	LocalTable = calloc(1, TableLength);
	if (!LocalTable) {
		Status = AE_NO_MEMORY;
		goto Exit;
	}

	memcpy(LocalTable, MappedTable, TableLength);

Exit:
	OslUnmapTable(MappedTable);
	*Table = LocalTable;
	return (Status);
}

/*
 *
 * FUNCTION:    AcpiOsGetTableByName
 *
 * PARAMETERS:  Signature       - ACPI Signature for desired table. Must be
 *                                a null terminated 4-character string.
 *              Instance        - Multiple table support for SSDT/UEFI (0...n)
 *                                Must be 0 for other tables.
 *              Table           - Where a pointer to the table is returned
 *              Address         - Where the table physical address is returned
 *
 * RETURN:      Status; Table buffer and physical address returned if AE_OK.
 *              AE_LIMIT: Instance is beyond valid limit
 *              AE_NOT_FOUND: A table with the signature was not found
 *
 * NOTE:        Assumes the input signature is uppercase.
 *
 */
ACPI_STATUS
AcpiOsGetTableByName(char *Signature, UINT32 Instance,
    ACPI_TABLE_HEADER **Table, ACPI_PHYSICAL_ADDRESS *Address)
{
	ACPI_STATUS	Status;

	/*
	 * Get main ACPI tables from memory on first invocation of this
	 * function
	 */
	Status = OslTableInitialize();
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	/* attempt to extract it from the RSDT/XSDT */
	Status = OslGetBiosTable(Signature, Instance, Table, Address);

	return (Status);
}

/*
 *
 * FUNCTION:    OslAddTableToList
 *
 * PARAMETERS:  Signature       - Table signature
 *
 * RETURN:      Status; Successfully added if AE_OK.
 *              AE_NO_MEMORY: Memory allocation error
 *
 * DESCRIPTION: Insert a table structure into OSL table list.
 *
 */
static ACPI_STATUS
OslAddTableToList(char *Signature)
{
	OSL_TABLE_INFO	*NewInfo;
	OSL_TABLE_INFO	*Next;
	UINT32		NextInstance = 0;
	UINT32		Instance = 0;
	BOOLEAN		Found = FALSE;

	NewInfo = calloc(1, sizeof (OSL_TABLE_INFO));
	if (NewInfo == NULL) {
		return (AE_NO_MEMORY);
	}

	ACPI_MOVE_NAME(NewInfo->Signature, Signature);

	if (!Gbl_TableListHead) {
		Gbl_TableListHead = NewInfo;
	} else {
		Next = Gbl_TableListHead;

		while (1) {
			if (ACPI_COMPARE_NAME(Next->Signature, Signature)) {
				if (Next->Instance == 0) {
					Found = TRUE;
				}
				if (Next->Instance >= NextInstance) {
					NextInstance = Next->Instance + 1;
				}
			}

			if (!Next->Next) {
				break;
			}
			Next = Next->Next;
		}
		Next->Next = NewInfo;
	}

	if (Found) {
		Instance = NextInstance;
	}

	NewInfo->Instance = Instance;
	Gbl_TableCount++;

	return (AE_OK);
}

/*
 *
 * FUNCTION:    AcpiOsGetTableByIndex
 *
 * PARAMETERS:  Index           - Which table to get
 *              Table           - Where a pointer to the table is returned
 *              Instance        - Where a pointer to the table instance no. is
 *                                returned
 *              Address         - Where the table physical address is returned
 *
 * RETURN:      Status; Table buffer and physical address returned if AE_OK.
 *              AE_LIMIT: Index is beyond valid limit
 *
 * DESCRIPTION: Get an ACPI table via an index value (0 through n). Returns
 *              AE_LIMIT when an invalid index is reached. Index is not
 *              necessarily an index into the RSDT/XSDT.
 *
 */
ACPI_STATUS
AcpiOsGetTableByIndex(UINT32 Index, ACPI_TABLE_HEADER **Table,
    UINT32 *Instance, ACPI_PHYSICAL_ADDRESS *Address)
{
	OSL_TABLE_INFO	*Info;
	ACPI_STATUS	Status;
	UINT32		i;

	/*
	 * Get main ACPI tables from memory on first invocation of this
	 * function.
	 */

	Status = OslTableInitialize();
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	/* Validate Index */

	if (Index >= Gbl_TableCount) {
		return (AE_LIMIT);
	}

	/* Point to the table list entry specified by the Index argument */

	Info = Gbl_TableListHead;
	for (i = 0; i < Index; i++) {
		Info = Info->Next;
	}

	/* Now we can just get the table via the signature */

	Status = AcpiOsGetTableByName(Info->Signature, Info->Instance,
	    Table, Address);

	if (ACPI_SUCCESS(Status)) {
		*Instance = Info->Instance;
	}
	return (Status);
}

/*
 *
 * FUNCTION:    OslLoadRsdp
 *
 * PARAMETERS:  None
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Scan and load RSDP.
 * See the find_rsdp() function in usr/src/uts/i86pc/os/fakebop.c, which is how
 * the kernel finds the RSDP. That algorithm matches AcpiFindRootPointer().
 * The code here is derived from AcpiFindRootPointer, except that we will try
 * the BIOS if the EBDA fails, and we will copy the table if found.
 */
static ACPI_STATUS
OslLoadRsdp(void)
{
	UINT8			*mapp;
	ACPI_TABLE_HEADER	*tblp;
	ACPI_SIZE		mapsize;
	ACPI_PHYSICAL_ADDRESS	physaddr;

	/* 1a) Get the location of the Extended BIOS Data Area (EBDA) */
	mapp = AcpiOsMapMemory((ACPI_PHYSICAL_ADDRESS)ACPI_EBDA_PTR_LOCATION,
	    ACPI_EBDA_PTR_LENGTH);
	if (mapp == NULL)
		goto try_bios;

	ACPI_MOVE_16_TO_32(&physaddr, mapp);

	/* Convert segment part to physical address */
	physaddr <<= 4;
	AcpiOsUnmapMemory(mapp, ACPI_EBDA_PTR_LENGTH);

	/* EBDA present? */
	if (physaddr <= 0x400)
		goto try_bios;

	/*
	 * 1b) Search EBDA paragraphs (EBDA is required to be a minimum of 1K
	 * length)
	 */
	mapp = AcpiOsMapMemory(physaddr, ACPI_EBDA_WINDOW_SIZE);
	if (mapp == NULL) {
		(void) fprintf(stderr, "EBDA (0x%p) found, but is not "
		    "mappable\n", physaddr);
		goto try_bios;
	}

	tblp = ACPI_CAST_PTR(ACPI_TABLE_HEADER,
	    AcpiTbScanMemoryForRsdp(mapp, ACPI_EBDA_WINDOW_SIZE));
	if (tblp != NULL) {
		physaddr += (ACPI_PHYSICAL_ADDRESS) ACPI_PTR_DIFF(tblp, mapp);
		Gbl_RsdpAddress = physaddr;
		memcpy(&Gbl_Rsdp, tblp, sizeof (ACPI_TABLE_RSDP));
		AcpiOsUnmapMemory(mapp, ACPI_EBDA_WINDOW_SIZE);

		return (AE_OK);
	}
	AcpiOsUnmapMemory(mapp, ACPI_EBDA_WINDOW_SIZE);

try_bios:
	/* Try to get RSDP from BIOS memory */
	if (Gbl_RsdpBase != NULL) {
		physaddr = Gbl_RsdpBase;
		mapsize = sizeof (ACPI_TABLE_RSDP);
	} else {
		physaddr = ACPI_HI_RSDP_WINDOW_BASE;
		mapsize = ACPI_HI_RSDP_WINDOW_SIZE;
	}

	mapp = AcpiOsMapMemory(physaddr, mapsize);
	if (mapp == NULL)
		return (OslGetLastStatus(AE_BAD_ADDRESS));

	/* Search low memory for the RSDP */
	tblp = ACPI_CAST_PTR(ACPI_TABLE_HEADER,
	    AcpiTbScanMemoryForRsdp(mapp, mapsize));
	if (tblp == NULL) {
		AcpiOsUnmapMemory(mapp, mapsize);
		return (AE_NOT_FOUND);
	}

	physaddr += (ACPI_PHYSICAL_ADDRESS) ACPI_PTR_DIFF(tblp, mapp);
	Gbl_RsdpAddress = physaddr;
	memcpy(&Gbl_Rsdp, tblp, sizeof (ACPI_TABLE_RSDP));
	AcpiOsUnmapMemory(mapp, mapsize);

	return (AE_OK);
}

/*
 *
 * FUNCTION:    OslCanUseXsdt
 *
 * PARAMETERS:  None
 *
 * RETURN:      TRUE if XSDT is allowed to be used.
 *
 * DESCRIPTION: This function collects logic that can be used to determine if
 *              XSDT should be used instead of RSDT.
 *
 */
static BOOLEAN
OslCanUseXsdt(void)
{
	if (Gbl_Revision && !AcpiGbl_DoNotUseXsdt) {
		return (TRUE);
	} else {
		return (FALSE);
	}
}

/*
 *
 * FUNCTION:    OslTableInitialize
 *
 * PARAMETERS:  None
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Initialize ACPI table data. Get and store main ACPI tables to
 *              local variables. Main ACPI tables include RSDT, FADT, RSDT,
 *              and/or XSDT.
 *
 */
static ACPI_STATUS
OslTableInitialize(void)
{
	ACPI_STATUS		Status;
	ACPI_PHYSICAL_ADDRESS	Address;

	if (Gbl_TableListInitialized) {
		return (AE_OK);
	}

	/* Get RSDP from memory */

	Status = OslLoadRsdp();
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	/* Get XSDT from memory */

	if (Gbl_Rsdp.Revision && !Gbl_DoNotDumpXsdt) {
		if (Gbl_Xsdt) {
			free(Gbl_Xsdt);
			Gbl_Xsdt = NULL;
		}

		Gbl_Revision = 2;
		Status = OslGetBiosTable(ACPI_SIG_XSDT, 0,
		    ACPI_CAST_PTR(ACPI_TABLE_HEADER *, &Gbl_Xsdt), &Address);
		if (ACPI_FAILURE(Status)) {
			return (Status);
		}
	}

	/* Get RSDT from memory */

	if (Gbl_Rsdp.RsdtPhysicalAddress) {
		if (Gbl_Rsdt) {
			free(Gbl_Rsdt);
			Gbl_Rsdt = NULL;
		}

		Status = OslGetBiosTable(ACPI_SIG_RSDT, 0,
		    ACPI_CAST_PTR(ACPI_TABLE_HEADER *, &Gbl_Rsdt), &Address);
		if (ACPI_FAILURE(Status)) {
			return (Status);
		}
	}

	/* Get FADT from memory */

	if (Gbl_Fadt) {
		free(Gbl_Fadt);
		Gbl_Fadt = NULL;
	}

	Status = OslGetBiosTable(ACPI_SIG_FADT, 0,
	    ACPI_CAST_PTR(ACPI_TABLE_HEADER *, &Gbl_Fadt), &Gbl_FadtAddress);
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	/* Add mandatory tables to global table list first */

	Status = OslAddTableToList(ACPI_RSDP_NAME);
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	Status = OslAddTableToList(ACPI_SIG_RSDT);
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	if (Gbl_Revision == 2) {
		Status = OslAddTableToList(ACPI_SIG_XSDT);
		if (ACPI_FAILURE(Status)) {
			return (Status);
		}
	}

	Status = OslAddTableToList(ACPI_SIG_DSDT);
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	Status = OslAddTableToList(ACPI_SIG_FACS);
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	/* Add all tables found in the memory */

	Status = OslListBiosTables();
	if (ACPI_FAILURE(Status)) {
		return (Status);
	}

	Gbl_TableListInitialized = TRUE;
	return (AE_OK);
}


/*
 *
 * FUNCTION:    OslListBiosTables
 *
 * PARAMETERS:  None
 *
 * RETURN:      Status; Table list is initialized if AE_OK.
 *
 * DESCRIPTION: Add ACPI tables to the table list from memory.
 */
static ACPI_STATUS
OslListBiosTables(void)
{
	ACPI_TABLE_HEADER	*MappedTable = NULL;
	UINT8			*TableData;
	UINT32			NumberOfTables;
	UINT8			ItemSize;
	ACPI_PHYSICAL_ADDRESS	TableAddress = 0;
	ACPI_STATUS		Status = AE_OK;
	UINT32			i;

	if (OslCanUseXsdt()) {
		ItemSize = sizeof (UINT64);
		TableData = ACPI_CAST8(Gbl_Xsdt) + sizeof (ACPI_TABLE_HEADER);
		NumberOfTables = (UINT32)
		    ((Gbl_Xsdt->Header.Length - sizeof (ACPI_TABLE_HEADER))
		    / ItemSize);

	} else {
		/* Use RSDT if XSDT is not available */
		ItemSize = sizeof (UINT32);
		TableData = ACPI_CAST8(Gbl_Rsdt) + sizeof (ACPI_TABLE_HEADER);
		NumberOfTables = (UINT32)
		    ((Gbl_Rsdt->Header.Length - sizeof (ACPI_TABLE_HEADER))
		    / ItemSize);
	}

	/* Search RSDT/XSDT for the requested table */

	for (i = 0; i < NumberOfTables; ++i, TableData += ItemSize) {
		if (OslCanUseXsdt()) {
			TableAddress =
			    (ACPI_PHYSICAL_ADDRESS) (*ACPI_CAST64(TableData));
		} else {
			TableAddress =
			    (ACPI_PHYSICAL_ADDRESS) (*ACPI_CAST32(TableData));
		}

		/* Skip NULL entries in RSDT/XSDT */
		if (TableAddress == NULL) {
			continue;
		}

		Status = OslMapTable(TableAddress, NULL, &MappedTable);
		if (ACPI_FAILURE(Status)) {
			return (Status);
		}

		OslAddTableToList(MappedTable->Signature);
		OslUnmapTable(MappedTable);
	}

	return (AE_OK);
}

/*
 *
 * FUNCTION:    OslGetBiosTable
 *
 * PARAMETERS:  Signature       - ACPI Signature for common table. Must be
 *                                a null terminated 4-character string.
 *              Instance        - Multiple table support for SSDT/UEFI (0...n)
 *                                Must be 0 for other tables.
 *              Table           - Where a pointer to the table is returned
 *              Address         - Where the table physical address is returned
 *
 * RETURN:      Status; Table buffer and physical address returned if AE_OK.
 *              AE_LIMIT: Instance is beyond valid limit
 *              AE_NOT_FOUND: A table with the signature was not found
 *
 * DESCRIPTION: Get a BIOS provided ACPI table
 *
 * NOTE:        Assumes the input signature is uppercase.
 *
 */
static ACPI_STATUS
OslGetBiosTable(char *Signature, UINT32 Instance, ACPI_TABLE_HEADER **Table,
    ACPI_PHYSICAL_ADDRESS *Address)
{
	ACPI_TABLE_HEADER	*LocalTable = NULL;
	ACPI_TABLE_HEADER	*MappedTable = NULL;
	UINT8			*TableData;
	UINT8			NumberOfTables;
	UINT8			ItemSize;
	UINT32			CurrentInstance = 0;
	ACPI_PHYSICAL_ADDRESS	TableAddress = 0;
	UINT32			TableLength = 0;
	ACPI_STATUS		Status = AE_OK;
	UINT32			i;

	/* Handle special tables whose addresses are not in RSDT/XSDT */

	if (ACPI_COMPARE_NAME(Signature, ACPI_RSDP_NAME) ||
	    ACPI_COMPARE_NAME(Signature, ACPI_SIG_RSDT) ||
	    ACPI_COMPARE_NAME(Signature, ACPI_SIG_XSDT) ||
	    ACPI_COMPARE_NAME(Signature, ACPI_SIG_DSDT) ||
	    ACPI_COMPARE_NAME(Signature, ACPI_SIG_FACS)) {
		if (Instance > 0) {
			return (AE_LIMIT);
		}

		/*
		 * Get the appropriate address, either 32-bit or 64-bit. Be very
		 * careful about the FADT length and validate table addresses.
		 * Note: The 64-bit addresses have priority.
		 */
		if (ACPI_COMPARE_NAME(Signature, ACPI_SIG_DSDT)) {
			if ((Gbl_Fadt->Header.Length >= MIN_FADT_FOR_XDSDT) &&
			    Gbl_Fadt->XDsdt) {
				TableAddress =
				    (ACPI_PHYSICAL_ADDRESS) Gbl_Fadt->XDsdt;

			} else if (Gbl_Fadt->Header.Length >=
			    MIN_FADT_FOR_DSDT && Gbl_Fadt->Dsdt) {
				TableAddress =
				    (ACPI_PHYSICAL_ADDRESS) Gbl_Fadt->Dsdt;
			}

		} else if (ACPI_COMPARE_NAME(Signature, ACPI_SIG_FACS)) {
			if ((Gbl_Fadt->Header.Length >= MIN_FADT_FOR_XFACS) &&
			    Gbl_Fadt->XFacs) {
				TableAddress =
				    (ACPI_PHYSICAL_ADDRESS) Gbl_Fadt->XFacs;

			} else if (Gbl_Fadt->Header.Length >=
			    MIN_FADT_FOR_FACS && Gbl_Fadt->Facs) {
				TableAddress =
				    (ACPI_PHYSICAL_ADDRESS) Gbl_Fadt->Facs;
			}

		} else if (ACPI_COMPARE_NAME(Signature, ACPI_SIG_XSDT)) {
			if (!Gbl_Revision) {
				return (AE_BAD_SIGNATURE);
			}
			TableAddress = (ACPI_PHYSICAL_ADDRESS)
			    Gbl_Rsdp.XsdtPhysicalAddress;

		} else if (ACPI_COMPARE_NAME(Signature, ACPI_SIG_RSDT)) {
			TableAddress = (ACPI_PHYSICAL_ADDRESS)
			    Gbl_Rsdp.RsdtPhysicalAddress;

		} else {
			TableAddress = (ACPI_PHYSICAL_ADDRESS) Gbl_RsdpAddress;
			Signature = ACPI_SIG_RSDP;
		}

		/* Now we can get the requested special table */

		Status = OslMapTable(TableAddress, Signature, &MappedTable);
		if (ACPI_FAILURE(Status)) {
			return (Status);
		}

		TableLength = ApGetTableLength(MappedTable);

	} else {
		/* Case for a normal ACPI table */
		if (OslCanUseXsdt()) {
			ItemSize = sizeof (UINT64);
			TableData = ACPI_CAST8(Gbl_Xsdt) +
			    sizeof (ACPI_TABLE_HEADER);
			NumberOfTables = (UINT8) ((Gbl_Xsdt->Header.Length -
			    sizeof (ACPI_TABLE_HEADER))
			    / ItemSize);

		} else {
			/* Use RSDT if XSDT is not available */
			ItemSize = sizeof (UINT32);
			TableData = ACPI_CAST8(Gbl_Rsdt) +
			    sizeof (ACPI_TABLE_HEADER);
			NumberOfTables = (UINT8) ((Gbl_Rsdt->Header.Length -
			    sizeof (ACPI_TABLE_HEADER))
			    / ItemSize);
		}

		/* Search RSDT/XSDT for the requested table */

		for (i = 0; i < NumberOfTables; ++i, TableData += ItemSize) {
			if (OslCanUseXsdt()) {
				TableAddress = (ACPI_PHYSICAL_ADDRESS)
				    (*ACPI_CAST64(TableData));
			} else {
				TableAddress = (ACPI_PHYSICAL_ADDRESS)
				    (*ACPI_CAST32(TableData));
			}

			/* Skip NULL entries in RSDT/XSDT */

			if (TableAddress == NULL) {
				continue;
			}

			Status = OslMapTable(TableAddress, NULL, &MappedTable);
			if (ACPI_FAILURE(Status)) {
				return (Status);
			}
			TableLength = MappedTable->Length;

			/* Does this table match the requested signature? */

			if (!ACPI_COMPARE_NAME(MappedTable->Signature,
			    Signature)) {
				OslUnmapTable(MappedTable);
				MappedTable = NULL;
				continue;
			}

			/* Match table instance (for SSDT/UEFI tables) */

			if (CurrentInstance != Instance) {
				OslUnmapTable(MappedTable);
				MappedTable = NULL;
				CurrentInstance++;
				continue;
			}

			break;
		}
	}

	if (MappedTable == NULL) {
		return (AE_LIMIT);
	}

	if (TableLength == 0) {
		Status = AE_BAD_HEADER;
		goto Exit;
	}

	/* Copy table to local buffer and return it */

	LocalTable = calloc(1, TableLength);
	if (LocalTable == NULL) {
		Status = AE_NO_MEMORY;
		goto Exit;
	}

	memcpy(LocalTable, MappedTable, TableLength);
	*Address = TableAddress;
	*Table = LocalTable;

Exit:
	OslUnmapTable(MappedTable);
	return (Status);
}

/*
 *
 * FUNCTION:    OslMapTable
 *
 * PARAMETERS:  Address             - Address of the table in memory
 *              Signature           - Optional ACPI Signature for desired table.
 *                                    Null terminated 4-character string.
 *              Table               - Where a pointer to the mapped table is
 *                                    returned
 *
 * RETURN:      Status; Mapped table is returned if AE_OK.
 *              AE_NOT_FOUND: A valid table was not found at the address
 *
 * DESCRIPTION: Map entire ACPI table into caller's address space.
 *
 */
static ACPI_STATUS
OslMapTable(ACPI_SIZE Address, char *Signature, ACPI_TABLE_HEADER **Table)
{
	ACPI_TABLE_HEADER	*MappedTable;
	UINT32			Length;

	if (Address == NULL) {
		return (AE_BAD_ADDRESS);
	}

	/*
	 * Map the header so we can get the table length.
	 * Use sizeof (ACPI_TABLE_HEADER) as:
	 * 1. it is bigger than 24 to include RSDP->Length
	 * 2. it is smaller than sizeof (ACPI_TABLE_RSDP)
	 */
	MappedTable = AcpiOsMapMemory(Address, sizeof (ACPI_TABLE_HEADER));
	if (MappedTable == NULL) {
		(void) fprintf(stderr, "Could not map table header at "
		    "0x%8.8X%8.8X\n", ACPI_FORMAT_UINT64(Address));
		return (OslGetLastStatus(AE_BAD_ADDRESS));
	}

	/* If specified, signature must match */

	if (Signature != NULL) {
		if (ACPI_VALIDATE_RSDP_SIG(Signature)) {
			if (!ACPI_VALIDATE_RSDP_SIG(MappedTable->Signature)) {
				AcpiOsUnmapMemory(MappedTable,
				    sizeof (ACPI_TABLE_HEADER));
				return (AE_BAD_SIGNATURE);
			}
		} else if (!ACPI_COMPARE_NAME(Signature,
		    MappedTable->Signature)) {
			AcpiOsUnmapMemory(MappedTable,
			    sizeof (ACPI_TABLE_HEADER));
			return (AE_BAD_SIGNATURE);
		}
	}

	/* Map the entire table */

	Length = ApGetTableLength(MappedTable);
	AcpiOsUnmapMemory(MappedTable, sizeof (ACPI_TABLE_HEADER));
	if (Length == 0) {
		return (AE_BAD_HEADER);
	}

	MappedTable = AcpiOsMapMemory(Address, Length);
	if (MappedTable == NULL) {
		(void) fprintf(stderr, "Could not map table at 0x%8.8X%8.8X "
		    "length %8.8X\n", ACPI_FORMAT_UINT64(Address), Length);
		return (OslGetLastStatus(AE_INVALID_TABLE_LENGTH));
	}

	(void) ApIsValidChecksum(MappedTable);

	*Table = MappedTable;
	return (AE_OK);
}


/*
 *
 * FUNCTION:    OslUnmapTable
 *
 * PARAMETERS:  Table               - A pointer to the mapped table
 *
 * RETURN:      None
 *
 * DESCRIPTION: Unmap entire ACPI table.
 *
 */
static void
OslUnmapTable(ACPI_TABLE_HEADER *Table)
{
	if (Table != NULL) {
		AcpiOsUnmapMemory(Table, ApGetTableLength(Table));
	}
}

/*
 *
 * FUNCTION:    OslTableNameFromFile
 *
 * PARAMETERS:  Filename            - File that contains the desired table
 *              Signature           - Pointer to 4-character buffer to store
 *                                    extracted table signature.
 *              Instance            - Pointer to integer to store extracted
 *                                    table instance number.
 *
 * RETURN:      Status; Table name is extracted if AE_OK.
 *
 * DESCRIPTION: Extract table signature and instance number from a table file
 *              name.
 *
 */
static ACPI_STATUS
OslTableNameFromFile(char *Filename, char *Signature, UINT32 *Instance)
{
	/* Ignore meaningless files */

	if (strlen(Filename) < ACPI_NAME_SIZE) {
		return (AE_BAD_SIGNATURE);
	}

	/* Extract instance number */

	if (isdigit((int)Filename[ACPI_NAME_SIZE])) {
		sscanf(&Filename[ACPI_NAME_SIZE], "%u", Instance);
	} else if (strlen(Filename) != ACPI_NAME_SIZE) {
		return (AE_BAD_SIGNATURE);
	} else {
		*Instance = 0;
	}

	/* Extract signature */

	ACPI_MOVE_NAME(Signature, Filename);
	return (AE_OK);
}

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

void *
AcpiOsAllocateZeroed(ACPI_SIZE Size)
{
	return (calloc(1, Size));
}

void
AcpiOsFree(void *p)
{
	free(p);
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

void *
AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS Where, ACPI_SIZE Length)
{
	int fd;
	void *p;
	ulong_t offset;

	if ((fd = open("/dev/xsvc", O_RDONLY)) < 0)
		return (NULL);

	if (pagesize == 0) {
		pagesize = getpagesize();
	}

	offset = Where % pagesize;
	p = mmap(NULL, Length + offset, PROT_READ, MAP_SHARED | MAP_NORESERVE,
	    fd, Where - offset);

	(void) close(fd);

	if (p == MAP_FAILED)
		return (NULL);
	p = (char *)p + offset;
	return (p);
}

void
AcpiOsUnmapMemory(void *LogicalAddress, ACPI_SIZE Size)
{
	ulong_t offset;
	void *p;

	offset = (ulong_t)LogicalAddress % pagesize;
	p = (void *)((char *)LogicalAddress - offset);

	(void) munmap(p, Size + offset);
}
