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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

/*
 * Build smap like memory map from efi memmap.
 */

#include <stand.h>
#include <inttypes.h>
#include <efi.h>
#include <efilib.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/queue.h>
#include <sys/stddef.h>
#include <machine/metadata.h>
#include <machine/pc/bios.h>
#include "bootstrap.h"

struct smap_buf {
	struct bios_smap	sb_smap;
	STAILQ_ENTRY(smap_buf)	sb_bufs;
};

static struct bios_smap *smapbase;
static int smaplen;

/*
 * See ACPI 6.1 Table 15-330 UEFI Memory Types and mapping to ACPI address
 * range types.
 */
static int
smap_type(int type)
{
	switch (type) {
	case EfiLoaderCode:
	case EfiLoaderData:
	case EfiBootServicesCode:
	case EfiBootServicesData:
	case EfiConventionalMemory:
		return (SMAP_TYPE_MEMORY);
	case EfiReservedMemoryType:
	case EfiRuntimeServicesCode:
	case EfiRuntimeServicesData:
	case EfiMemoryMappedIO:
	case EfiMemoryMappedIOPortSpace:
	case EfiPalCode:
	case EfiUnusableMemory:
		return (SMAP_TYPE_RESERVED);
	case EfiACPIReclaimMemory:
		return (SMAP_TYPE_ACPI_RECLAIM);
	case EfiACPIMemoryNVS:
		return (SMAP_TYPE_ACPI_NVS);
	}
	return (SMAP_TYPE_RESERVED);
}

void
efi_getsmap(void)
{
	UINTN size, desc_size, key;
	EFI_MEMORY_DESCRIPTOR *efi_mmap, *p;
	EFI_PHYSICAL_ADDRESS addr;
	EFI_STATUS status;
	STAILQ_HEAD(smap_head, smap_buf) head =
	    STAILQ_HEAD_INITIALIZER(head);
	struct smap_buf *cur, *next;
	int i, n, ndesc;
	int type = -1;

	size = 0;
	status = BS->GetMemoryMap(&size, efi_mmap, &key, &desc_size, NULL);
	efi_mmap = malloc(size);
	status = BS->GetMemoryMap(&size, efi_mmap, &key, &desc_size, NULL);
	if (EFI_ERROR(status)) {
		printf("GetMemoryMap: error %lu\n", EFI_ERROR_CODE(status));
		free(efi_mmap);
		return;
	}

	STAILQ_INIT(&head);
	n = 0;
	i = 0;
	p = efi_mmap;
	next = NULL;
	ndesc = size / desc_size;
	while (i < ndesc) {
		if (next == NULL) {
			next = malloc(sizeof(*next));
			if (next == NULL)
				break;

			next->sb_smap.base = p->PhysicalStart;
			next->sb_smap.length =
			    p->NumberOfPages << EFI_PAGE_SHIFT;
			/*
			 * ACPI 6.1 tells the lower memory should be
			 * reported as normal memory, so we enforce
			 * page 0 type even as vmware maps it as
			 * acpi reclaimable.
			 */
			if (next->sb_smap.base == 0)
				type = SMAP_TYPE_MEMORY;
			else
				type = smap_type(p->Type);
			next->sb_smap.type = type;

			STAILQ_INSERT_TAIL(&head, next, sb_bufs);
			n++;
			p = NextMemoryDescriptor(p, desc_size);
			i++;
			continue;
		}
		addr = next->sb_smap.base + next->sb_smap.length;
		if ((smap_type(p->Type) == type) &&
		    (p->PhysicalStart == addr)) {
			next->sb_smap.length +=
			    (p->NumberOfPages << EFI_PAGE_SHIFT);
			p = NextMemoryDescriptor(p, desc_size);
			i++;
		} else
			next = NULL;
	}
	smaplen = n;
	if (smaplen > 0) {
		smapbase = malloc(smaplen * sizeof(*smapbase));
		if (smapbase != NULL) {
			n = 0;
			STAILQ_FOREACH(cur, &head, sb_bufs)
				smapbase[n++] = cur->sb_smap;
		}
		cur = STAILQ_FIRST(&head);
		while (cur != NULL) {
			next = STAILQ_NEXT(cur, sb_bufs);
			free(cur);
			cur = next;
		}
	}
	free(efi_mmap);
}

void
efi_addsmapdata(struct preloaded_file *kfp)
{
	size_t size;

	if (smapbase == NULL || smaplen == 0)
		return;
	size = smaplen * sizeof(*smapbase);
	file_addmetadata(kfp, MODINFOMD_SMAP, size, smapbase);
}

COMMAND_SET(smap, "smap", "show BIOS SMAP", command_smap);

static int
command_smap(int argc, char *argv[])
{
	u_int i;

	if (smapbase == NULL || smaplen == 0)
		return (CMD_ERROR);

	for (i = 0; i < smaplen; i++)
		printf("SMAP type=%02" PRIx32 " base=%016" PRIx64
		    " len=%016" PRIx64 "\n", smapbase[i].type,
		    smapbase[i].base, smapbase[i].length);
	return (CMD_OK);
}
