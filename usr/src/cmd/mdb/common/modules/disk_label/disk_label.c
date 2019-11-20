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
 * Copyright (c) 2019, Joyent, Inc.
 */

/*
 * The on-disk elements here are all little-endian, and this code doesn't make
 * any attempt to adjust for running on a big-endian system.
 */

#include <sys/types.h>
#include <sys/crc32.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/dktp/fdisk.h>
#include <sys/efi_partition.h>
#include <sys/vtoc.h>

#include <assert.h>
#include <ctype.h>
#include <uuid/uuid.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_debug.h>

#include "installboot.h"

#ifdef _BIG_ENDIAN
#error needs porting for big-endian system
#endif

/* See usr/src/grub/grub-0.97/stage1/stage1.h */
#define	GRUB_VERSION_OFF (0x3e)
#define	GRUB_COMPAT_VERSION_MAJOR 3
#define	GRUB_COMPAT_VERSION_MINOR 2
#define	GRUB_VERSION (2 << 8 | 3) /* 3.2 */

#define	LOADER_VERSION (1)
#define	LOADER_JOYENT_VERSION (2)

typedef enum {
	MBR_TYPE_UNKNOWN,
	MBR_TYPE_GRUB1,
	MBR_TYPE_LOADER,
	MBR_TYPE_LOADER_JOYENT,
} mbr_type_t;

typedef struct stringval {
	const char	*sv_text;
	int		sv_value;
} stringval_t;

stringval_t ptag_array[] = {
	{ "unassigned",		V_UNASSIGNED	},
	{ "boot",		V_BOOT		},
	{ "root",		V_ROOT		},
	{ "swap",		V_SWAP		},
	{ "usr",		V_USR		},
	{ "backup",		V_BACKUP	},
	{ "stand",		V_STAND		},
	{ "var",		V_VAR		},
	{ "home",		V_HOME		},
	{ "alternates",		V_ALTSCTR	},
	{ "reserved",		V_RESERVED	},
	{ "system",		V_SYSTEM	},
	{ "BIOS_boot",		V_BIOS_BOOT	},
	{ "FreeBSD boot",	V_FREEBSD_BOOT	},
	{ "FreeBSD swap",	V_FREEBSD_SWAP	},
	{ "FreeBSD UFS",	V_FREEBSD_UFS	},
	{ "FreeBSD ZFS",	V_FREEBSD_ZFS	},
	{ "FreeBSD NANDFS",	V_FREEBSD_NANDFS },

	{ NULL }
};

stringval_t pflag_array[] = {
	{ "wm", 0			},
	{ "wu", V_UNMNT			},
	{ "rm", V_RONLY			},
	{ "ru", V_RONLY | V_UNMNT	},
	{ NULL }
};

size_t sector_size = SECTOR_SIZE;

static const char *
array_find_string(stringval_t *array, int match_value)
{
	for (; array->sv_text != NULL; array++) {
		if (array->sv_value == match_value) {
			return (array->sv_text);
		}
	}

	return (NULL);
}

static int
array_widest_str(stringval_t *array)
{
	int	i;
	int	width;

	width = 0;
	for (; array->sv_text != NULL; array++) {
		if ((i = strlen(array->sv_text)) > width)
			width = i;
	}

	return (width);
}

static void
print_fdisk_part(struct ipart *ip, size_t nr)
{
	char typestr[128];
	char begchs[128];
	char endchs[128];
	char *c = NULL;

	if (ip->systid == UNUSED) {
		mdb_printf("%-4llu %s:%#lx\n", nr, "UNUSED", ip->systid);
		return;
	}

	switch (ip->systid) {
	case DOSOS12: c = "DOSOS12"; break;
	case PCIXOS: c = "PCIXOS"; break;
	case DOSOS16: c = "DOSOS16"; break;
	case EXTDOS: c = "EXTDOS"; break;
	case DOSHUGE: c = "DOSHUGE"; break;
	case FDISK_IFS: c = "FDISK_IFS"; break;
	case FDISK_AIXBOOT: c = "FDISK_AIXBOOT"; break;
	case FDISK_AIXDATA: c = "FDISK_AIXDATA"; break;
	case FDISK_OS2BOOT: c = "FDISK_OS2BOOT"; break;
	case FDISK_WINDOWS: c = "FDISK_WINDOWS"; break;
	case FDISK_EXT_WIN: c = "FDISK_EXT_WIN"; break;
	case FDISK_FAT95: c = "FDISK_FAT95"; break;
	case FDISK_EXTLBA: c = "FDISK_EXTLBA"; break;
	case DIAGPART: c = "DIAGPART"; break;
	case FDISK_LINUX: c = "FDISK_LINUX"; break;
	case FDISK_LINUXDSWAP: c = "FDISK_LINUXDSWAP"; break;
	case FDISK_LINUXDNAT: c = "FDISK_LINUXDNAT"; break;
	case FDISK_CPM: c = "FDISK_CPM"; break;
	case DOSDATA: c = "DOSDATA"; break;
	case OTHEROS: c = "OTHEROS"; break;
	case UNIXOS: c = "UNIXOS"; break;
	case FDISK_NOVELL2: c = "FDISK_NOVELL2"; break;
	case FDISK_NOVELL3: c = "FDISK_NOVELL3"; break;
	case FDISK_QNX4: c = "FDISK_QNX4"; break;
	case FDISK_QNX42: c = "FDISK_QNX42"; break;
	case FDISK_QNX43: c = "FDISK_QNX43"; break;
	case SUNIXOS: c = "SUNIXOS"; break;
	case FDISK_LINUXNAT: c = "FDISK_LINUXNAT"; break;
	case FDISK_NTFSVOL1: c = "FDISK_NTFSVOL1"; break;
	case FDISK_NTFSVOL2: c = "FDISK_NTFSVOL2"; break;
	case FDISK_BSD: c = "FDISK_BSD"; break;
	case FDISK_NEXTSTEP: c = "FDISK_NEXTSTEP"; break;
	case FDISK_BSDIFS: c = "FDISK_BSDIFS"; break;
	case FDISK_BSDISWAP: c = "FDISK_BSDISWAP"; break;
	case X86BOOT: c = "X86BOOT"; break;
	case SUNIXOS2: c = "SUNIXOS2"; break;
	case EFI_PMBR: c = "EFI_PMBR"; break;
	case EFI_FS: c = "EFI_FS"; break;
	default: c = NULL; break;
	}

	if (c != NULL) {
		mdb_snprintf(typestr, sizeof (typestr), "%s:%#lx",
		    c, ip->systid);
	} else {
		mdb_snprintf(typestr, sizeof (typestr), "%#lx", ip->systid);
	}

	mdb_snprintf(begchs, sizeof (begchs), "%hu/%hu/%hu",
	    (uint16_t)ip->begcyl | (uint16_t)(ip->begsect & ~0x3f) << 2,
	    (uint16_t)ip->beghead, (uint16_t)ip->begsect & 0x3f);
	mdb_snprintf(endchs, sizeof (endchs), "%hu/%hu/%hu",
	    (uint16_t)ip->endcyl | (uint16_t)(ip->endsect & ~0x3f) << 2,
	    (uint16_t)ip->endhead, (uint16_t)ip->endsect & 0x3f);

	mdb_printf("%-4llu %-21s %#-7x %-11s %-11s %-10u %-9u\n",
	    nr, typestr, ip->bootid, begchs, endchs, ip->relsect, ip->numsect);
}

static mbr_type_t
mbr_info(struct mboot *mbr)
{
	mbr_type_t type = MBR_TYPE_UNKNOWN;

	if (*((uint16_t *)&mbr->bootinst[GRUB_VERSION_OFF]) == GRUB_VERSION) {
		type = MBR_TYPE_GRUB1;
	} else if (mbr->bootinst[STAGE1_MBR_VERSION] == LOADER_VERSION) {
		type = MBR_TYPE_LOADER;
	} else if (mbr->bootinst[STAGE1_MBR_VERSION] == LOADER_JOYENT_VERSION) {
		type = MBR_TYPE_LOADER_JOYENT;
	}

	switch (type) {
	case MBR_TYPE_UNKNOWN:
		mdb_printf("Format: unknown\n");
		break;
	case MBR_TYPE_GRUB1:
		mdb_printf("Format: grub1\n");
		break;
	case MBR_TYPE_LOADER:
		mdb_printf("Format: loader (illumos)\n");
		break;
	case MBR_TYPE_LOADER_JOYENT:
		mdb_printf("Format: loader (joyent)\n");
		break;
	}

	mdb_printf("Signature: 0x%hx (%s)\n", mbr->signature,
	    mbr->signature == MBB_MAGIC ? "valid" : "invalid");

	mdb_printf("UniqueMBRDiskSignature: %#lx\n",
	    *(uint32_t *)&mbr->bootinst[STAGE1_SIG]);

	if (type == MBR_TYPE_LOADER || type == MBR_TYPE_LOADER_JOYENT) {
		char uuid[UUID_PRINTABLE_STRING_LENGTH];

		mdb_printf("Loader STAGE1_STAGE2_LBA: %llu\n",
		    *(uint64_t *)&mbr->bootinst[STAGE1_STAGE2_LBA]);

		mdb_printf("Loader STAGE1_STAGE2_SIZE: %hu\n",
		    *(uint16_t *)&mbr->bootinst[STAGE1_STAGE2_SIZE]);

		uuid_unparse((uchar_t *)&mbr->bootinst[STAGE1_STAGE2_UUID],
		    uuid);

		mdb_printf("Loader STAGE1_STAGE2_UUID: %s\n", uuid);
	}

	return (type);
}

static int
cmd_mbr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv __unused)
{
	struct mboot *mbr;
	mbr_type_t type;

	CTASSERT(sizeof (*mbr) == SECTOR_SIZE);

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC))
		addr = 0;

	mbr = mdb_zalloc(sector_size, UM_SLEEP | UM_GC);

	if (mdb_vread(mbr, sector_size, addr) == -1) {
		mdb_warn("failed to read MBR");
		return (DCMD_ERR);
	}

	type = mbr_info(mbr);

	/* If the magic is wrong, stop here. */
	if (mbr->signature != MBB_MAGIC)
		return (DCMD_ERR);

	/* Also print volume boot record */
	switch (type) {
	case MBR_TYPE_LOADER:
	case MBR_TYPE_LOADER_JOYENT:
		if (*(uint16_t *)&mbr->bootinst[STAGE1_STAGE2_SIZE] == 1) {
			struct mboot vbr;
			uintptr_t vbrp;

			vbrp = *(uint64_t *)&mbr->bootinst[STAGE1_STAGE2_LBA];
			vbrp *= sector_size;
			vbrp += addr;
			if (mdb_vread(&vbr, sizeof (vbr), vbrp) == -1) {
				mdb_warn("failed to read VBR");
			} else {
				mdb_printf("\nSTAGE1 in VBR:\n");
				(void) mbr_info(&vbr);
			}
		}
		break;
	default:
		break;
	}

	mdb_printf("\n%<u>%-4s %-21s %-7s %-11s %-11s %-10s %-9s%</u>\n",
	    "PART", "TYPE", "ACTIVE", "STARTCHS", "ENDCHS",
	    "SECTOR", "NUMSECT");

	for (size_t i = 0; i < FD_NUMPART; i++) {
		struct ipart *ip = (struct ipart *)
		    (mbr->parts + (sizeof (struct ipart) * i));
		print_fdisk_part(ip, i);
	}

	return (DCMD_OK);
}

static unsigned int crc32_tab[] = { CRC32_TABLE };

static unsigned int
efi_crc32(const unsigned char *s, unsigned int len)
{
	unsigned int crc32val;

	CRC32(crc32val, s, len, -1U, crc32_tab);

	return (crc32val ^ -1U);
}

typedef struct {
	struct uuid eg_uuid;
	const char *eg_name;
} efi_guid_t;

static efi_guid_t efi_guids[] = {
	{ EFI_UNUSED, "EFI_UNUSED" },
	{ EFI_RESV1, "EFI_RESV1" },
	{ EFI_BOOT, "EFI_BOOT" },
	{ EFI_ROOT, "EFI_ROOT" },
	{ EFI_SWAP, "EFI_SWAP" },
	{ EFI_USR, "EFI_USR" },
	{ EFI_BACKUP, "EFI_BACKUP" },
	{ EFI_RESV2, "EFI_RESV2" },
	{ EFI_VAR, "EFI_VAR" },
	{ EFI_HOME, "EFI_HOME" },
	{ EFI_ALTSCTR, "EFI_ALTSCTR" },
	{ EFI_RESERVED, "EFI_RESERVED" },
	{ EFI_SYSTEM, "EFI_SYSTEM" },
	{ EFI_LEGACY_MBR, "EFI_LEGACY_MBR" },
	{ EFI_SYMC_PUB, "EFI_SYMC_PUB" },
	{ EFI_SYMC_CDS, "EFI_SYMC_CDS" },
	{ EFI_MSFT_RESV, "EFI_MSFT_RESV" },
	{ EFI_DELL_BASIC, "EFI_DELL_BASIC" },
	{ EFI_DELL_RAID, "EFI_DELL_RAID" },
	{ EFI_DELL_SWAP, "EFI_DELL_SWAP" },
	{ EFI_DELL_LVM, "EFI_DELL_LVM" },
	{ EFI_DELL_RESV, "EFI_DELL_RESV" },
	{ EFI_AAPL_BOOT, "EFI_AAPL_BOOT" },
	{ EFI_AAPL_HFS, "EFI_AAPL_HFS" },
	{ EFI_AAPL_UFS, "EFI_AAPL_UFS" },
	{ EFI_AAPL_ZFS, "EFI_AAPL_ZFS" },
	{ EFI_AAPL_APFS, "EFI_AAPL_APFS" },
	{ EFI_FREEBSD_BOOT, "EFI_FREEBSD_BOOT" },
	{ EFI_FREEBSD_NANDFS, "EFI_FREEBSD_NANDFS" },
	{ EFI_FREEBSD_SWAP, "EFI_FREEBSD_SWAP" },
	{ EFI_FREEBSD_UFS, "EFI_FREEBSD_UFS" },
	{ EFI_FREEBSD_VINUM, "EFI_FREEBSD_VINUM" },
	{ EFI_FREEBSD_ZFS, "EFI_FREEBSD_ZFS" },
	{ EFI_BIOS_BOOT, "EFI_BIOS_BOOT" },
};

static void
print_gpe(efi_gpe_t *gpe, size_t nr, int show_guid)
{
	const char *type = "unknown";

	for (size_t i = 0; i < ARRAY_SIZE(efi_guids); i++) {
		if (memcmp((void *)&efi_guids[i].eg_uuid,
		    (void *)&gpe->efi_gpe_PartitionTypeGUID,
		    sizeof (efi_guids[i].eg_uuid)) == 0) {
			type = efi_guids[i].eg_name;
			break;
		}
	}

	if (strcmp(type, "EFI_UNUSED") == 0) {
		mdb_printf("%-4u %-19s\n", nr, type);
		return;
	}

	if (show_guid) {
		char guid[UUID_PRINTABLE_STRING_LENGTH];

		uuid_unparse((uchar_t *)&gpe->efi_gpe_UniquePartitionGUID,
		    guid);

		mdb_printf("%-4u %-19s %s\n", nr, type, guid);
	} else {
		char name[EFI_PART_NAME_LEN + 1] = "";

		/*
		 * Hopefully, ASCII is sufficient for any naming we care about.
		 */
		for (size_t i = 0; i < sizeof (name); i++) {
			ushort_t wchar = gpe->efi_gpe_PartitionName[i];

			name[i] = (char)(isascii(wchar) ? wchar : '?');
		}

		mdb_printf("%-4u %-19s %-13llu %-13llu %#-8llx %s\n",
		    nr, type, gpe->efi_gpe_StartingLBA, gpe->efi_gpe_EndingLBA,
		    gpe->efi_gpe_Attributes, name);
	}
}

static int
cmd_gpt(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv __unused)
{
	char uuid[UUID_PRINTABLE_STRING_LENGTH];
	int show_alternate = B_FALSE;
	int show_guid = B_FALSE;
	efi_gpt_t *altheader;
	size_t table_size;
	efi_gpt_t *header;
	efi_gpe_t *gpet;
	uint_t orig_crc;
	uint_t crc;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, TRUE, &show_alternate,
	    'g', MDB_OPT_SETBITS, TRUE, &show_guid,
	    NULL) != argc)
		return (DCMD_USAGE);

	/* Primary header is at LBA 1. */
	if (!(flags & DCMD_ADDRSPEC))
		addr = sector_size;

	header = mdb_zalloc(sector_size, UM_SLEEP | UM_GC);
	if (mdb_vread(header, sector_size, addr) == -1) {
		mdb_warn("failed to read GPT header");
		return (DCMD_ERR);
	}

	if (show_alternate) {
		addr = header->efi_gpt_AlternateLBA * sector_size;

		if (mdb_vread(header, sector_size, addr) == -1) {
			mdb_warn("failed to read GPT header");
			return (DCMD_ERR);
		}
	}

	mdb_printf("Signature: %s (%s)\n", (char *)&header->efi_gpt_Signature,
	    strncmp((char *)&header->efi_gpt_Signature, "EFI PART", 8) == 0 ?
	    "valid" : "invalid");

	mdb_printf("Revision: %hu.%hu\n", header->efi_gpt_Revision >> 16,
	    header->efi_gpt_Revision);

	mdb_printf("HeaderSize: %u bytes\n", header->efi_gpt_HeaderSize);

	if (header->efi_gpt_HeaderSize > SECTOR_SIZE) {
		mdb_warn("invalid header size: skipping CRC\n");
	} else {
		orig_crc = header->efi_gpt_HeaderCRC32;

		header->efi_gpt_HeaderCRC32 = 0;

		crc = efi_crc32((unsigned char *)header,
		    header->efi_gpt_HeaderSize);

		mdb_printf("HeaderCRC32: %#x (should be %#x)\n", orig_crc, crc);
	}

	mdb_printf("Reserved1: %#x (should be 0x0)\n",
	    header->efi_gpt_Reserved1);

	mdb_printf("MyLBA: %llu (should be %llu)\n",
	    header->efi_gpt_MyLBA, addr / sector_size);

	mdb_printf("AlternateLBA: %llu\n", header->efi_gpt_AlternateLBA);
	mdb_printf("FirstUsableLBA: %llu\n", header->efi_gpt_FirstUsableLBA);
	mdb_printf("LastUsableLBA: %llu\n", header->efi_gpt_LastUsableLBA);

	if (header->efi_gpt_MyLBA >= header->efi_gpt_FirstUsableLBA &&
	    header->efi_gpt_MyLBA <= header->efi_gpt_LastUsableLBA) {
		mdb_warn("MyLBA is within usable LBA range\n");
	}

	if (header->efi_gpt_AlternateLBA >= header->efi_gpt_FirstUsableLBA &&
	    header->efi_gpt_AlternateLBA <= header->efi_gpt_LastUsableLBA) {
		mdb_warn("AlternateLBA is within usable LBA range\n");
	}

	altheader = mdb_zalloc(sector_size, UM_SLEEP | UM_GC);
	if (mdb_vread(altheader, sector_size,
	    header->efi_gpt_AlternateLBA * sector_size) == -1) {
		mdb_warn("failed to read alternate GPT header");
	} else {
		if (strncmp((char *)&altheader->efi_gpt_Signature,
		    "EFI PART", 8) != 0) {
			mdb_warn("found invalid alternate GPT header with "
			    "Signature: %s\n",
			    (char *)&altheader->efi_gpt_Signature);
		}

		if (altheader->efi_gpt_MyLBA != header->efi_gpt_AlternateLBA) {
			mdb_warn("alternate GPT header at offset %#llx has "
			    "invalid MyLBA %llu\n",
			    header->efi_gpt_AlternateLBA * sector_size,
			    altheader->efi_gpt_MyLBA);
		}

		if (altheader->efi_gpt_AlternateLBA != header->efi_gpt_MyLBA) {
			mdb_warn("alternate GPT header at offset %#llx has "
			    "invalid AlternateLBA %llu\n",
			    header->efi_gpt_AlternateLBA * sector_size,
			    altheader->efi_gpt_AlternateLBA);
		}

		/*
		 * We could go ahead and verify all the alternate checksums,
		 * etc. here too...
		 */
	}

	uuid_unparse((uchar_t *)&header->efi_gpt_DiskGUID, uuid);
	mdb_printf("DiskGUID: %s\n", uuid);

	mdb_printf("PartitionEntryLBA: %llu\n",
	    header->efi_gpt_PartitionEntryLBA);

	mdb_printf("NumberOfPartitionEntries: %u\n",
	    header->efi_gpt_NumberOfPartitionEntries);

	/*
	 * While the spec allows a different size, in practice the table
	 * is always packed.
	 */
	if (header->efi_gpt_SizeOfPartitionEntry != sizeof (efi_gpe_t)) {
		mdb_warn("SizeOfPartitionEntry: %#x bytes "
		    "(expected %#x bytes)\n",
		    header->efi_gpt_SizeOfPartitionEntry, sizeof (efi_gpe_t));
		return (DCMD_ERR);
	}

	mdb_printf("SizeOfPartitionEntry: %#x bytes\n",
	    header->efi_gpt_SizeOfPartitionEntry);

	table_size = header->efi_gpt_SizeOfPartitionEntry *
	    header->efi_gpt_NumberOfPartitionEntries;

	/*
	 * While this is a minimum reservation, it serves us ably as a
	 * maximum value to reasonably expect.
	 */
	if (table_size > EFI_MIN_ARRAY_SIZE) {
		mdb_warn("Skipping GPT array of %#lx bytes.\n", table_size);
		return (DCMD_ERR);
	}

	table_size = P2ROUNDUP(table_size, sector_size);
	gpet = mdb_alloc(table_size, UM_SLEEP | UM_GC);

	if (mdb_vread(gpet, table_size,
	    header->efi_gpt_PartitionEntryLBA * sector_size) == -1) {
		mdb_warn("couldn't read GPT array");
		return (DCMD_ERR);
	}

	crc = efi_crc32((unsigned char *)gpet,
	    header->efi_gpt_SizeOfPartitionEntry *
	    header->efi_gpt_NumberOfPartitionEntries);

	mdb_printf("PartitionEntryArrayCRC32: %#x (should be %#x)\n",
	    header->efi_gpt_PartitionEntryArrayCRC32, crc);

	if (show_guid) {
		mdb_printf("\n%<u>%-4s %-19s %-37s%</u>\n",
		    "PART", "TYPE", "GUID");
	} else {
		mdb_printf("\n%<u>%-4s %-19s %-13s %-13s %-8s %s%</u>\n",
		    "PART", "TYPE", "STARTLBA", "ENDLBA", "ATTR", "NAME");
	}

	for (size_t i = 0; i < header->efi_gpt_NumberOfPartitionEntries; i++)
		print_gpe(&gpet[i], i, show_guid);

	return (DCMD_OK);
}

void
gpt_help(void)
{
	mdb_printf("Display an EFI GUID Partition Table.\n\n"
	    "-a Display the alternate GPT\n"
	    "-g Show unique GUID for each table entry\n");
}

static int
cmd_vtoc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint8_t *buf;
	struct dk_label *dl;
	struct dk_vtoc *dv;
	uintptr_t vaddr;
	int i, tag_width, cyl_width;
	int show_absolute = B_TRUE;
	int show_sectors = B_TRUE;
	uint32_t cyl;

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_CLRBITS, TRUE, &show_sectors,
	    'r', MDB_OPT_CLRBITS, TRUE, &show_absolute,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC))
		addr = 0;
	else
		addr *= sector_size;

	buf = mdb_zalloc(sector_size, UM_SLEEP | UM_GC);

#if defined(_SUNOS_VTOC_16)
	if (mdb_vread(buf, sector_size, addr) == -1) {
		mdb_warn("failed to read VBR");
		return (DCMD_ERR);
	}

	mdb_printf("VBR info:\n");
	(void) mbr_info((struct mboot *)buf);
#endif

	vaddr = addr + DK_LABEL_LOC * sector_size;

	if (mdb_vread(buf, sector_size, vaddr) == -1) {
		mdb_warn("failed to read VTOC");
		return (DCMD_ERR);
	}

	dl = (struct dk_label *)buf;
	dv = (struct dk_vtoc *)&dl->dkl_vtoc;

	mdb_printf("Label magic: 0x%hx (%s)\n", dl->dkl_magic,
	    dl->dkl_magic == DKL_MAGIC ? "valid" : "invalid");
	if (dl->dkl_magic != DKL_MAGIC)
		return (DCMD_ERR);
	mdb_printf("Label %s sane\n", dv->v_sanity == VTOC_SANE ?
	    "is" : "is not");

	mdb_printf("Label version: %#x\n", dv->v_version);
	mdb_printf("Volume name = <%s>\n", dv->v_volume);
	mdb_printf("ASCII name  = <%s>\n", dv->v_asciilabel);
	mdb_printf("pcyl        = %4d\n", dl->dkl_pcyl);
	mdb_printf("ncyl        = %4d\n", dl->dkl_ncyl);
	mdb_printf("acyl        = %4d\n", dl->dkl_acyl);

#if defined(_SUNOS_VTOC_16)
	mdb_printf("bcyl        = %4d\n", dl->dkl_bcyl);
#endif /* defined(_SUNOS_VTOC_16) */

	mdb_printf("nhead       = %4d\n", dl->dkl_nhead);
	mdb_printf("nsect       = %4d\n", dl->dkl_nsect);


	if (!show_absolute)
		addr = 0;
	cyl = dl->dkl_nhead * dl->dkl_nsect;
	if (show_sectors)
		cyl = 1;
	else
		addr /= (cyl * sector_size);

	tag_width = array_widest_str(ptag_array);

	cyl_width = sizeof ("CYLINDERS");
	for (i = 0; i < dv->v_nparts; i++) {
		uint32_t start, end, size;
		int w;

#if defined(_SUNOS_VTOC_16)
		start = addr + (dv->v_part[i].p_start / cyl);
		size = dv->v_part[i].p_size;
#elif defined(_SUNOS_VTOC_8)
		start = dl->dkl_map[i].dkl_cylno;
		start *= dl->dkl_nhead * dl->dkl_nsect; /* compute bytes */
		start /= cyl;
		start += addr;
		size = dl->dkl_map[i].dkl_nblk;
#else
#error "No VTOC format defined."
#endif
		if (size == 0)
			end = start = 0;
		else
			end = start + size / cyl - 1;

		w = mdb_snprintf(NULL, 0, "%u - %u", start, end);
		if (w > cyl_width)
			cyl_width = w;
	}

	if (show_sectors == B_TRUE) {
		mdb_printf("\n%<u>%-4s %-*s %-7s %-11s %-11s %-*s "
		    "%-10s%</u>\n", "PART", tag_width, "TAG", "FLAG",
		    "STARTLBA", "ENDLBA", MDB_NICENUM_BUFLEN, "SIZE", "BLOCKS");
	} else {
		mdb_printf("\n%<u>%-4s %-*s %-7s %-*s %-*s %-10s%</u>\n",
		    "PART", tag_width, "TAG", "FLAG", cyl_width, "CYLINDERS",
		    MDB_NICENUM_BUFLEN, "SIZE", "BLOCKS");
	}

	for (i = 0; i < dv->v_nparts; i++) {
		uint16_t tag, flag;
		uint32_t start, end, size;
		const char *stag, *sflag;
		char nnum[MDB_NICENUM_BUFLEN];

#if defined(_SUNOS_VTOC_16)
		tag = dv->v_part[i].p_tag;
		flag = dv->v_part[i].p_flag;
		start = addr + (dv->v_part[i].p_start / cyl);
		size = dv->v_part[i].p_size;
#elif defined(_SUNOS_VTOC_8)
		tag = dv->v_part[i].p_tag;
		flag = dv->v_part[i].p_flag;
		start = dl->dkl_map[i].dkl_cylno;
		start *= dl->dkl_nhead * dl->dkl_nsect; /* compute bytes */
		start /= cyl;
		start += addr;
		size = dl->dkl_map[i].dkl_nblk;
#else
#error "No VTOC format defined."
#endif
		if (size == 0)
			end = start = 0;
		else
			end = start + size / cyl - 1;

		stag = array_find_string(ptag_array, tag);
		if (stag == NULL)
			stag = "?";
		sflag = array_find_string(pflag_array, flag);
		if (sflag == NULL)
			sflag = "?";

		mdb_printf("%-4d %-*s %-7s ", i, tag_width, stag, sflag);
		mdb_nicenum(size * sector_size, nnum);
		if (show_sectors) {
			mdb_printf("%-11u %-11u %-*s %-10u\n", start, end,
			    MDB_NICENUM_BUFLEN, nnum, size);
		} else {
			char cyls[10 * 2 + 4];

			if (size == 0) {
				mdb_snprintf(cyls, sizeof (cyls), "%-*u",
				    cyl_width, size);
			} else {
				mdb_snprintf(cyls, sizeof (cyls), "%u - %u",
				    start, end);
			}
			mdb_printf("%-*s %-*s %-10u\n", cyl_width, cyls,
			    MDB_NICENUM_BUFLEN, nnum, size);
		}
	}

	return (DCMD_OK);
}

void
vtoc_help(void)
{
	mdb_printf("Display a Virtual Table of Content (VTOC).\n\n"
	    "-r Display relative addresses\n"
	    "-c Use cylinder based addressing\n");
	mdb_printf("\nThe addr is in %u-byte disk blocks.\n", sector_size);
}

static int
cmd_sect(uintptr_t addr __unused, uint_t flags __unused, int argc,
    const mdb_arg_t *argv)
{
	uint64_t size = SECTOR_SIZE;

	if (argc < 1) {
		mdb_printf("Current sector size is %u (%#x)\n", sector_size,
		    sector_size);
		return (DCMD_OK);
	}

	if (argc != 1)
		return (DCMD_USAGE);

	switch (argv[0].a_type) {
	case MDB_TYPE_STRING:
		size = mdb_strtoull(argv[0].a_un.a_str);
		break;
	case MDB_TYPE_IMMEDIATE:
		size = argv[0].a_un.a_val;
		break;
	default:
		return (DCMD_USAGE);
	}

	if (!ISP2(size)) {
		mdb_printf("sector size must be power of 2\n");
		return (DCMD_USAGE);
	}
	sector_size = size;
	return (DCMD_OK);
}

void
sect_help(void)
{
	mdb_printf("Show or set sector size.\n");
}

static const mdb_dcmd_t dcmds[] = {
	{ "mbr", NULL, "dump Master Boot Record information", cmd_mbr },
	{ "gpt", "?[-ag]", "dump an EFI GPT", cmd_gpt, gpt_help },
	{ "vtoc", "?[-cr]", "dump VTOC information", cmd_vtoc, vtoc_help },
	{ "sectorsize", NULL, "set or show sector size", cmd_sect, sect_help },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
