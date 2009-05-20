/*
    libparted - a library for manipulating disk partitions

    original version by Matt Domsch <Matt_Domsch@dell.com>
    Disclaimed into the Public Domain

    Portions Copyright (C) 2001, 2002, 2003, 2005, 2006, 2007
        Free Software Foundation, Inc.

    EFI GUID Partition Table handling
    Per Intel EFI Specification v1.02
    http://developer.intel.com/technology/efi/efi.htm

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <config.h>

#include <parted/parted.h>
#include <parted/debug.h>
#include <parted/endian.h>
#include <parted/crc32.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>

#if ENABLE_NLS
#  include <libintl.h>
#  define _(String) gettext (String)
#else
#  define _(String) (String)
#endif				/* ENABLE_NLS */

#define EFI_PMBR_OSTYPE_EFI 0xEE
#define MSDOS_MBR_SIGNATURE 0xaa55

#define GPT_HEADER_SIGNATURE 0x5452415020494645LL

/* NOTE: the document that describes revision 1.00 is labelled "version 1.02",
 * so some implementors got confused...
 */
#define GPT_HEADER_REVISION_V1_02 0x00010200
#define GPT_HEADER_REVISION_V1_00 0x00010000
#define GPT_HEADER_REVISION_V0_99 0x00009900

#ifdef __sun
#define __attribute__(X)	/*nothing*/
#endif /* __sun */

typedef uint16_t efi_char16_t;	/* UNICODE character */
typedef struct _GuidPartitionTableHeader_t GuidPartitionTableHeader_t;
typedef struct _GuidPartitionEntryAttributes_t GuidPartitionEntryAttributes_t;
typedef struct _GuidPartitionEntry_t GuidPartitionEntry_t;
typedef struct _PartitionRecord_t PartitionRecord_t;
typedef struct _LegacyMBR_t LegacyMBR_t;
typedef struct _GPTDiskData GPTDiskData;
typedef struct {
        uint32_t time_low;
        uint16_t time_mid;
        uint16_t time_hi_and_version;
        uint8_t  clock_seq_hi_and_reserved;
        uint8_t  clock_seq_low;
        uint8_t  node[6];
} /* __attribute__ ((packed)) */ efi_guid_t;
/* commented out "__attribute__ ((packed))" to work around gcc bug (fixed
 * in gcc3.1): __attribute__ ((packed)) breaks addressing on initialized
 * data.  It turns out we don't need it in this case, so it doesn't break
 * anything :)
 */

#define UNUSED_ENTRY_GUID    \
    ((efi_guid_t) { 0x00000000, 0x0000, 0x0000, 0x00, 0x00, \
    		    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }})
#define PARTITION_SYSTEM_GUID \
    ((efi_guid_t) { PED_CPU_TO_LE32 (0xC12A7328), PED_CPU_TO_LE16 (0xF81F), \
    		    PED_CPU_TO_LE16 (0x11d2), 0xBA, 0x4B, \
		    { 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B }})
#define LEGACY_MBR_PARTITION_GUID \
    ((efi_guid_t) { PED_CPU_TO_LE32 (0x024DEE41), PED_CPU_TO_LE16 (0x33E7), \
		    PED_CPU_TO_LE16 (0x11d3, 0x9D, 0x69, \
		    { 0x00, 0x08, 0xC7, 0x81, 0xF3, 0x9F }})
#define PARTITION_MSFT_RESERVED_GUID \
    ((efi_guid_t) { PED_CPU_TO_LE32 (0xE3C9E316), PED_CPU_TO_LE16 (0x0B5C), \
    		    PED_CPU_TO_LE16 (0x4DB8), 0x81, 0x7D, \
		    { 0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE }})
#define PARTITION_BASIC_DATA_GUID \
    ((efi_guid_t) { PED_CPU_TO_LE32 (0xEBD0A0A2), PED_CPU_TO_LE16 (0xB9E5), \
    		    PED_CPU_TO_LE16 (0x4433), 0x87, 0xC0, \
		    { 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7 }})
#define PARTITION_RAID_GUID \
    ((efi_guid_t) { PED_CPU_TO_LE32 (0xa19d880f), PED_CPU_TO_LE16 (0x05fc), \
    		    PED_CPU_TO_LE16 (0x4d3b), 0xa0, 0x06, \
		    { 0x74, 0x3f, 0x0f, 0x84, 0x91, 0x1e }})
#define PARTITION_SWAP_GUID \
    ((efi_guid_t) { PED_CPU_TO_LE32 (0x0657fd6d), PED_CPU_TO_LE16 (0xa4ab), \
    		    PED_CPU_TO_LE16 (0x43c4), 0x84, 0xe5, \
		    { 0x09, 0x33, 0xc8, 0x4b, 0x4f, 0x4f }})
#define PARTITION_LVM_GUID \
    ((efi_guid_t) { PED_CPU_TO_LE32 (0xe6d6d379), PED_CPU_TO_LE16 (0xf507), \
    		    PED_CPU_TO_LE16 (0x44c2), 0xa2, 0x3c, \
		    { 0x23, 0x8f, 0x2a, 0x3d, 0xf9, 0x28 }})
#define PARTITION_RESERVED_GUID \
    ((efi_guid_t) { PED_CPU_TO_LE32 (0x8da63339), PED_CPU_TO_LE16 (0x0007), \
    		    PED_CPU_TO_LE16 (0x60c0), 0xc4, 0x36, \
		    { 0x08, 0x3a, 0xc8, 0x23, 0x09, 0x08 }})
#define PARTITION_HPSERVICE_GUID \
    ((efi_guid_t) { PED_CPU_TO_LE32 (0xe2a1e728), PED_CPU_TO_LE16 (0x32e3), \
		    PED_CPU_TO_LE16 (0x11d6), 0xa6, 0x82, \
		    { 0x7b, 0x03, 0xa0, 0x00, 0x00, 0x00 }})
#define PARTITION_APPLE_HFS_GUID \
    ((efi_guid_t) { PED_CPU_TO_LE32 (0x48465300), PED_CPU_TO_LE16 (0x0000), \
		    PED_CPU_TO_LE16 (0x11AA), 0xaa, 0x11, \
		    { 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC }})

#ifdef __sun
#pragma pack(1)
#endif
struct __attribute__ ((packed)) _GuidPartitionTableHeader_t {
	uint64_t Signature;
	uint32_t Revision;
	uint32_t HeaderSize;
	uint32_t HeaderCRC32;
	uint32_t Reserved1;
	uint64_t MyLBA;
	uint64_t AlternateLBA;
	uint64_t FirstUsableLBA;
	uint64_t LastUsableLBA;
	efi_guid_t DiskGUID;
	uint64_t PartitionEntryLBA;
	uint32_t NumberOfPartitionEntries;
	uint32_t SizeOfPartitionEntry;
	uint32_t PartitionEntryArrayCRC32;
	uint8_t* Reserved2;
};

struct __attribute__ ((packed)) _GuidPartitionEntryAttributes_t {
#if defined(__GNUC__) || defined(__sun) /* XXX narrow this down to !TinyCC */
	uint64_t RequiredToFunction:1;
	uint64_t Reserved:47;
        uint64_t GuidSpecific:16;
#else
	uint32_t RequiredToFunction:1;
	uint32_t Reserved:32;
	uint32_t LOST:5;
        uint32_t GuidSpecific:16;
#endif
};

struct __attribute__ ((packed)) _GuidPartitionEntry_t {
	efi_guid_t PartitionTypeGuid;
	efi_guid_t UniquePartitionGuid;
	uint64_t StartingLBA;
	uint64_t EndingLBA;
	GuidPartitionEntryAttributes_t Attributes;
	efi_char16_t PartitionName[72 / sizeof(efi_char16_t)];
};
#ifdef __sun
#pragma pack()
#endif

#define GPT_PMBR_LBA 0
#define GPT_PMBR_SECTORS 1
#define GPT_PRIMARY_HEADER_LBA 1
#define GPT_HEADER_SECTORS 1
#define GPT_PRIMARY_PART_TABLE_LBA 2 

/* 
   These values are only defaults.  The actual on-disk structures
   may define different sizes, so use those unless creating a new GPT disk!
*/

#define GPT_DEFAULT_PARTITION_ENTRY_ARRAY_SIZE 16384

/* Number of actual partition entries should be calculated as: */
#define GPT_DEFAULT_PARTITION_ENTRIES \
        (GPT_DEFAULT_PARTITION_ENTRY_ARRAY_SIZE / \
         sizeof(GuidPartitionEntry_t))


#ifdef __sun
#pragma pack(1)
#endif
struct __attribute__ ((packed)) _PartitionRecord_t {
	/* Not used by EFI firmware. Set to 0x80 to indicate that this
	   is the bootable legacy partition. */
	uint8_t BootIndicator;

	/* Start of partition in CHS address, not used by EFI firmware. */
	uint8_t StartHead;

	/* Start of partition in CHS address, not used by EFI firmware. */
	uint8_t StartSector;

	/* Start of partition in CHS address, not used by EFI firmware. */
	uint8_t StartTrack;

	/* OS type. A value of 0xEF defines an EFI system partition.
	   Other values are reserved for legacy operating systems, and
	   allocated independently of the EFI specification. */
	uint8_t OSType;

	/* End of partition in CHS address, not used by EFI firmware. */
	uint8_t EndHead;

	/* End of partition in CHS address, not used by EFI firmware. */
	uint8_t EndSector;

	/* End of partition in CHS address, not used by EFI firmware. */
	uint8_t EndTrack;

	/* Starting LBA address of the partition on the disk. Used by
	   EFI firmware to define the start of the partition. */
	uint32_t StartingLBA;

	/* Size of partition in LBA. Used by EFI firmware to determine
	   the size of the partition. */
	uint32_t SizeInLBA;
};

/* Protected Master Boot Record  & Legacy MBR share same structure */
/* Needs to be packed because the u16s force misalignment. */
struct __attribute__ ((packed)) _LegacyMBR_t {
	uint8_t BootCode[440];
	uint32_t UniqueMBRSignature;
	uint16_t Unknown;
	PartitionRecord_t PartitionRecord[4];
	uint16_t Signature;
};

/* uses libparted's disk_specific field in PedDisk, to store our info */
struct __attribute__ ((packed)) _GPTDiskData {
	PedGeometry	data_area;
	int		entry_count;
	efi_guid_t	uuid;
};
#ifdef __sun
#pragma pack()
#endif

/* uses libparted's disk_specific field in PedPartition, to store our info */
typedef struct _GPTPartitionData {
	efi_guid_t	type;
	efi_guid_t	uuid;
	char		name[37];
	int		lvm;
	int		raid;
	int		boot;
	int		hp_service;
        int             hidden;
        int             msftres;
} GPTPartitionData;

static PedDiskType gpt_disk_type;


static inline uint32_t
pth_get_size (const PedDevice* dev)
{
        return GPT_HEADER_SECTORS * dev->sector_size;
}


static inline uint32_t
pth_get_size_static (const PedDevice* dev)
{
        return sizeof (GuidPartitionTableHeader_t) - sizeof (uint8_t*);
}


static inline uint32_t
pth_get_size_rsv2 (const PedDevice* dev)
{
        return pth_get_size(dev) - pth_get_size_static(dev);
}


static GuidPartitionTableHeader_t*
pth_new (const PedDevice* dev)
{
        GuidPartitionTableHeader_t* pth = ped_malloc (
                        sizeof (GuidPartitionTableHeader_t)
                        + sizeof (uint8_t));
        
        pth->Reserved2 = ped_malloc ( pth_get_size_rsv2 (dev) );

        return pth;
}


static GuidPartitionTableHeader_t*
pth_new_zeroed (const PedDevice* dev)
{
        GuidPartitionTableHeader_t* pth = pth_new (dev);
        
        memset (pth, 0, pth_get_size_static (dev));
        memset (pth->Reserved2, 0, pth_get_size_rsv2 (dev));        
        
        return (pth);
}
                        

static GuidPartitionTableHeader_t*
pth_new_from_raw (const PedDevice* dev, const uint8_t* pth_raw)
{
        GuidPartitionTableHeader_t* pth = pth_new (dev); 

        PED_ASSERT (pth_raw != NULL, return 0);
        
        memcpy (pth, pth_raw, pth_get_size_static (dev));
        memcpy (pth->Reserved2, pth_raw + pth_get_size_static (dev),
                        pth_get_size_rsv2 (dev));
        
        return pth;
}

static void
pth_free (GuidPartitionTableHeader_t* pth)
{
	PED_ASSERT (pth != NULL, return);
	PED_ASSERT (pth->Reserved2 != NULL, return);

	ped_free (pth->Reserved2);
	ped_free (pth);
}

static uint8_t*
pth_get_raw (const PedDevice* dev, const GuidPartitionTableHeader_t* pth)
{
        uint8_t* pth_raw = ped_malloc (pth_get_size (dev));
        int size_static = pth_get_size_static (dev);
        
        PED_ASSERT (pth != NULL, return 0);
        PED_ASSERT (pth->Reserved2 != NULL, return 0);
       
        memcpy (pth_raw, pth, size_static);
        memcpy (pth_raw + size_static, pth->Reserved2, pth_get_size_rsv2 (dev));
        
        return pth_raw;
}


/**
 * swap_uuid_and_efi_guid() - converts between uuid formats
 * @uuid - uuid_t in either format (converts it to the other)
 *
 * There are two different representations for Globally Unique Identifiers
 * (GUIDs or UUIDs).
 * 
 * The RFC specifies a UUID as a string of 16 bytes, essentially
 * a big-endian array of char.
 * Intel, in their EFI Specification, references the same RFC, but
 * then defines a GUID as a structure of little-endian fields.
 * Coincidentally, both structures have the same format when unparsed.
 *
 * When read from disk, EFI GUIDs are in struct of little endian format,
 * and need to be converted to be treated as uuid_t in memory.
 *
 * When writing to disk, uuid_ts need to be converted into EFI GUIDs.
 *
 * Blame Intel.
 */
static void
swap_uuid_and_efi_guid(uuid_t uuid)
{
	efi_guid_t *guid = (efi_guid_t *)uuid;

	PED_ASSERT(uuid != NULL, return);
	guid->time_low            = PED_SWAP32(guid->time_low);
	guid->time_mid            = PED_SWAP16(guid->time_mid);
	guid->time_hi_and_version = PED_SWAP16(guid->time_hi_and_version);
}

/* returns the EFI-style CRC32 value for buf
 *	This function uses the crc32 function by Gary S. Brown,
 * but seeds the function with ~0, and xor's with ~0 at the end.
 */
static inline uint32_t
efi_crc32(const void *buf, unsigned long len)
{
	return (__efi_crc32(buf, len, ~0L) ^ ~0L);
}

static inline uint32_t
pth_crc32(const PedDevice* dev, const GuidPartitionTableHeader_t* pth)
{
        uint8_t* pth_raw = pth_get_raw (dev, pth);
        uint32_t crc32 = 0;
       
        PED_ASSERT (dev != NULL, return 0);
        PED_ASSERT (pth != NULL, return 0);
       
        crc32 = efi_crc32 (pth_raw, PED_LE32_TO_CPU (pth->HeaderSize));

        ped_free (pth_raw);
      
        return crc32;
}

static inline int
guid_cmp (efi_guid_t left, efi_guid_t right)
{
	return memcmp(&left, &right, sizeof(efi_guid_t));
}

/* checks if 'mbr' is a protective MBR partition table */
static inline int
_pmbr_is_valid (const LegacyMBR_t* mbr)
{
	int i;

	PED_ASSERT(mbr != NULL, return 0);

	if (mbr->Signature != PED_CPU_TO_LE16(MSDOS_MBR_SIGNATURE))
		return 0;
	for (i = 0; i < 4; i++) {
		if (mbr->PartitionRecord[i].OSType == EFI_PMBR_OSTYPE_EFI)
			return 1;
	}
	return 0;
}

static int
gpt_probe (const PedDevice * dev)
{
	GuidPartitionTableHeader_t* gpt = NULL;
        uint8_t* pth_raw = ped_malloc (pth_get_size (dev));
	LegacyMBR_t legacy_mbr;
	int gpt_sig_found = 0;

	PED_ASSERT (dev != NULL, return 0);
	PED_ASSERT (pth_raw != NULL, return 0);

	if (ped_device_read(dev, pth_raw, 1, GPT_HEADER_SECTORS)
	|| ped_device_read(dev, pth_raw, dev->length - 1, GPT_HEADER_SECTORS)) {
		gpt = pth_new_from_raw (dev, pth_raw);
		if (gpt->Signature == PED_CPU_TO_LE64(GPT_HEADER_SIGNATURE))
			gpt_sig_found = 1;
	}
	
        ped_free (pth_raw);

        if (gpt)
	        pth_free (gpt);

        
	if (!gpt_sig_found)
		return 0;

	if (ped_device_read(dev, &legacy_mbr, 0, GPT_HEADER_SECTORS)) {
		if (!_pmbr_is_valid (&legacy_mbr)) {
			int ex_status = ped_exception_throw (
				PED_EXCEPTION_WARNING,
				PED_EXCEPTION_YES_NO,
			_("%s contains GPT signatures, indicating that it has "
			  "a GPT table.  However, it does not have a valid "
			  "fake msdos partition table, as it should.  Perhaps "
			  "it was corrupted -- possibly by a program that "
			  "doesn't understand GPT partition tables.  Or "
			  "perhaps you deleted the GPT table, and are now "
			  "using an msdos partition table.  Is this a GPT "
			  "partition table?"),
				dev->path);
			if (ex_status == PED_EXCEPTION_NO)
				return 0;
		}
	}

	return 1;
}

#ifndef DISCOVER_ONLY
/* writes zeros to the PMBR and the primary and alternate GPTHs and PTEs */
static int
gpt_clobber(PedDevice * dev)
{
	LegacyMBR_t pmbr;
        uint8_t* zeroed_pth_raw = ped_malloc (pth_get_size (dev));
        uint8_t* pth_raw = ped_malloc (pth_get_size (dev));
	GuidPartitionTableHeader_t* gpt;

	PED_ASSERT (dev != NULL, return 0);

	memset(&pmbr, 0, sizeof(pmbr));
	memset(zeroed_pth_raw, 0, pth_get_size (dev));
	
        /*
         * TO DISCUSS: check whether checksum is correct?
         * If not, we might get a wrong AlternateLBA field and destroy
         * one sector of random data.
         */
	if (!ped_device_read(dev, pth_raw,
			     GPT_PRIMARY_HEADER_LBA, GPT_HEADER_SECTORS))
                goto error_free;

        gpt = pth_new_from_raw (dev, pth_raw);
        
	if (!ped_device_write(dev, &pmbr, GPT_PMBR_LBA, GPT_PMBR_SECTORS))
                goto error_free_with_gpt;
	if (!ped_device_write(dev, &zeroed_pth_raw,
			      GPT_PRIMARY_HEADER_LBA, GPT_HEADER_SECTORS))
                goto error_free_with_gpt;
	if (!ped_device_write(dev, &zeroed_pth_raw, dev->length - GPT_HEADER_SECTORS,
			      GPT_HEADER_SECTORS))
                goto error_free_with_gpt;

	if ((PedSector) PED_LE64_TO_CPU (gpt->AlternateLBA) < dev->length - 1) {
		if (!ped_device_write(dev, gpt,
				      PED_LE64_TO_CPU (gpt->AlternateLBA),
				      GPT_HEADER_SECTORS))
			return 0;
	}
        
	pth_free (gpt);

        return 1;
        
error_free_with_gpt:
        pth_free (gpt);
error_free:
        ped_free (pth_raw);
        ped_free (zeroed_pth_raw);
	return 0;
}
#endif /* !DISCOVER_ONLY */

static PedDisk *
gpt_alloc (const PedDevice * dev)
{
	PedDisk* disk;
	GPTDiskData *gpt_disk_data;
	PedSector data_start, data_end;

	disk = _ped_disk_alloc ((PedDevice*)dev, &gpt_disk_type);
	if (!disk)
		goto error;
	disk->disk_specific = gpt_disk_data = ped_malloc (sizeof (GPTDiskData));
	if (!disk->disk_specific)
		goto error_free_disk;

	data_start = 2 + GPT_DEFAULT_PARTITION_ENTRY_ARRAY_SIZE / dev->sector_size;
	data_end = dev->length - 2
		   - GPT_DEFAULT_PARTITION_ENTRY_ARRAY_SIZE / dev->sector_size;
	ped_geometry_init (&gpt_disk_data->data_area, dev, data_start,
			   data_end - data_start + 1);
	gpt_disk_data->entry_count = GPT_DEFAULT_PARTITION_ENTRIES;
	uuid_generate ((unsigned char*) &gpt_disk_data->uuid);
	swap_uuid_and_efi_guid((unsigned char*)(&gpt_disk_data->uuid));
	return disk;

error_free_disk:
	ped_free (disk);
error:
	return NULL;
}

static PedDisk*
gpt_duplicate (const PedDisk* disk)
{
	PedDisk* new_disk;
	GPTDiskData* new_disk_data;
	GPTDiskData* old_disk_data;

	new_disk = ped_disk_new_fresh (disk->dev, &gpt_disk_type);
	if (!new_disk)
		return NULL;

	old_disk_data = disk->disk_specific;
	new_disk_data = new_disk->disk_specific;

	ped_geometry_init (&new_disk_data->data_area, disk->dev,
			   old_disk_data->data_area.start,
			   old_disk_data->data_area.length);
	new_disk_data->entry_count = old_disk_data->entry_count;
	new_disk_data->uuid = old_disk_data->uuid;
	return new_disk;
}

static void
gpt_free(PedDisk * disk)
{
	ped_disk_delete_all (disk);
	ped_free (disk->disk_specific);
	_ped_disk_free (disk);
}

static int
_header_is_valid (const PedDevice* dev, GuidPartitionTableHeader_t* gpt)
{
	uint32_t crc, origcrc;

	if (PED_LE64_TO_CPU (gpt->Signature) != GPT_HEADER_SIGNATURE)
		return 0;
	/*
	 * "While the GUID Partition Table Header's size may increase
	 * in the future it cannot span more than one block on the
	 * device."  EFI Specification, version 1.10, 11.2.2.1
	 */
	if (PED_LE32_TO_CPU (gpt->HeaderSize) < pth_get_size_static (dev)
	    || PED_LE32_TO_CPU (gpt->HeaderSize) > dev->sector_size)
		return 0;

	origcrc = gpt->HeaderCRC32;
	gpt->HeaderCRC32 = 0;
	crc = pth_crc32 (dev, gpt);
	gpt->HeaderCRC32 = origcrc;

	return crc == PED_LE32_TO_CPU (origcrc);
}

static int
_read_header (const PedDevice* dev, GuidPartitionTableHeader_t** gpt,
              PedSector where)
{
        uint8_t* pth_raw = ped_malloc (pth_get_size (dev));

	PED_ASSERT (dev != NULL, return 0);

	if (!ped_device_read (dev, pth_raw, where, GPT_HEADER_SECTORS)) {
                ped_free (pth_raw); 
		return 0;
        }
 
        *gpt = pth_new_from_raw (dev, pth_raw);
        
        ped_free (pth_raw);

        if (_header_is_valid (dev, *gpt))
                return 1;

        pth_free (*gpt);
        return 0;
}

static int
_parse_header (PedDisk* disk, GuidPartitionTableHeader_t* gpt, 
	       int *update_needed)
{ 
	GPTDiskData* gpt_disk_data = disk->disk_specific;
	PedSector first_usable;
	PedSector last_usable;
	PedSector last_usable_if_grown, last_usable_min_default;
	static int asked_already;

	PED_ASSERT (_header_is_valid (disk->dev, gpt), return 0);

#ifndef DISCOVER_ONLY
	if (PED_LE32_TO_CPU (gpt->Revision) > GPT_HEADER_REVISION_V1_02) {
		if (ped_exception_throw (
			PED_EXCEPTION_WARNING,
			PED_EXCEPTION_IGNORE_CANCEL,
			_("The format of the GPT partition table is version "
			  "%x, which is newer than what Parted can "
			  "recognise.  Please tell us!  bug-parted@gnu.org"),
			PED_LE32_TO_CPU (gpt->Revision))
				!= PED_EXCEPTION_IGNORE)
			return 0;
	}
#endif

	first_usable = PED_LE64_TO_CPU (gpt->FirstUsableLBA);
	last_usable = PED_LE64_TO_CPU (gpt->LastUsableLBA);


/*
   Need to check whether the volume has grown, the LastUsableLBA is
   normally set to disk->dev->length - 2 - ptes_size (at least for parted
   created volumes), where ptes_size is the number of entries * 
   size of each entry / sector size or 16k / sector size, whatever the greater.
   If the volume has grown, offer the user the chance to use the new
   space or continue with the current usable area.  Only ask once per 
   parted invocation.
*/
   
	last_usable_if_grown 
		= PED_CPU_TO_LE64 (disk->dev->length - 2 - 
		((PedSector)(PED_LE32_TO_CPU(gpt->NumberOfPartitionEntries)) * 
		(PedSector)(PED_LE32_TO_CPU(gpt->SizeOfPartitionEntry)) / 
		disk->dev->sector_size));

	last_usable_min_default = disk->dev->length - 2 - 
		GPT_DEFAULT_PARTITION_ENTRY_ARRAY_SIZE / disk->dev->sector_size;

	if ( last_usable_if_grown > last_usable_min_default ) {

		last_usable_if_grown = last_usable_min_default;
	}


	PED_ASSERT (last_usable > first_usable, return 0);
	PED_ASSERT (last_usable <= disk->dev->length, return 0);

	PED_ASSERT (last_usable_if_grown > first_usable, return 0);
	PED_ASSERT (last_usable_if_grown <= disk->dev->length, return 0);

	if ( !asked_already && last_usable < last_usable_if_grown ) {

		PedExceptionOption q;

		q = ped_exception_throw (PED_EXCEPTION_WARNING,
			PED_EXCEPTION_FIX | PED_EXCEPTION_IGNORE,
			_("Not all of the space available to %s appears "
			"to be used, you can fix the GPT to use all of the "
			"space (an extra %llu blocks) or continue with the "
			"current setting? "), disk->dev->path, 
			(uint64_t)(last_usable_if_grown - last_usable));


		if (q == PED_EXCEPTION_FIX) {

			last_usable = last_usable_if_grown;
			*update_needed = 1;

		}
		else if (q != PED_EXCEPTION_UNHANDLED ) {

			asked_already = 1;
		}
	}

	ped_geometry_init (&gpt_disk_data->data_area, disk->dev,
			   first_usable, last_usable - first_usable + 1);


	gpt_disk_data->entry_count
		= PED_LE32_TO_CPU (gpt->NumberOfPartitionEntries);
	PED_ASSERT (gpt_disk_data->entry_count > 0, return 0);
	PED_ASSERT (gpt_disk_data->entry_count <= 8192, return 0);

	gpt_disk_data->uuid = gpt->DiskGUID;

	return 1;
}

static PedPartition*
_parse_part_entry (PedDisk* disk, GuidPartitionEntry_t* pte)
{
	PedPartition* part;
	GPTPartitionData* gpt_part_data;
	unsigned int i;

	part = ped_partition_new (disk, 0, NULL,
			PED_LE64_TO_CPU(pte->StartingLBA),
			PED_LE64_TO_CPU(pte->EndingLBA));
	if (!part)
		return NULL;

	gpt_part_data = part->disk_specific;
	gpt_part_data->type = pte->PartitionTypeGuid;
	gpt_part_data->uuid = pte->UniquePartitionGuid;
	for (i = 0; i < 72 / sizeof (efi_char16_t); i++)
		gpt_part_data->name[i] = (efi_char16_t) PED_LE16_TO_CPU(
					   (uint16_t) pte->PartitionName[i]);
	gpt_part_data->name[i] = 0;
        
        gpt_part_data->lvm = gpt_part_data->raid 
                = gpt_part_data->boot = gpt_part_data->hp_service
                = gpt_part_data->hidden = gpt_part_data->msftres = 0;

        if (pte->Attributes.RequiredToFunction & 0x1)
                gpt_part_data->hidden = 1;
       
	if (!guid_cmp (gpt_part_data->type, PARTITION_SYSTEM_GUID))
		gpt_part_data->boot = 1;
	else if (!guid_cmp (gpt_part_data->type, PARTITION_RAID_GUID))
		gpt_part_data->raid = 1;
	else if (!guid_cmp (gpt_part_data->type, PARTITION_LVM_GUID))
		gpt_part_data->lvm = 1;
	else if (!guid_cmp (gpt_part_data->type, PARTITION_HPSERVICE_GUID))
		gpt_part_data->hp_service = 1;
        else if (!guid_cmp (gpt_part_data->type, PARTITION_MSFT_RESERVED_GUID))
                gpt_part_data->msftres = 1;
        
	return part;
}

/************************************************************
 *  Intel is changing the EFI Spec. (after v1.02) to say that a
 *  disk is considered to have a GPT label only if the GPT
 *  structures are correct, and the MBR is actually a Protective
 *  MBR (has one 0xEE type partition).
 *  Problem occurs when a GPT-partitioned disk is then
 *  edited with a legacy (non-GPT-aware) application, such as
 *  fdisk (which doesn't generally erase the PGPT or AGPT).
 *  How should such a disk get handled?  As a GPT disk (throwing
 *  away the fdisk changes), or as an MSDOS disk (throwing away
 *  the GPT information).  Previously, I've taken the GPT-is-right,
 *  MBR is wrong, approach, to stay consistent with the EFI Spec.
 *  Intel disagrees, saying the disk should then be treated
 *  as having a msdos label, not a GPT label.  If this is true,
 *  then what's the point of having an AGPT, since if the PGPT
 *  is screwed up, likely the PMBR is too, and the PMBR becomes
 *  a single point of failure.
 *  So, in the Linux kernel, I'm going to test for PMBR, and
 *  warn if it's not there, and treat the disk as MSDOS, with a note
 *  for users to use Parted to "fix up" their disk if they
 *  really want it to be considered GPT.
 ************************************************************/
static int
gpt_read (PedDisk * disk)
{
	GPTDiskData *gpt_disk_data = disk->disk_specific;
	GuidPartitionTableHeader_t* gpt;
	GuidPartitionEntry_t* ptes;
	int ptes_size;
	int i;
#ifndef DISCOVER_ONLY
	int write_back = 0;
#endif

	ped_disk_delete_all (disk);

        /* 
         * motivation: let the user decide about the pmbr... during
         * ped_disk_probe(), they probably didn't get a choice...
         */
	if (!gpt_probe (disk->dev))
		goto error;

	if (_read_header (disk->dev, &gpt, 1)) {
		PED_ASSERT ((PedSector) PED_LE64_TO_CPU (gpt->AlternateLBA)
				<= disk->dev->length - 1, goto error_free_gpt);
		if ((PedSector) PED_LE64_TO_CPU (gpt->AlternateLBA)
				< disk->dev->length - 1) {
			char* zeros = ped_malloc (pth_get_size (disk->dev));

#ifndef DISCOVER_ONLY
			if (ped_exception_throw (
				PED_EXCEPTION_ERROR,
				PED_EXCEPTION_FIX | PED_EXCEPTION_CANCEL,
		_("The backup GPT table is not at the end of the disk, as it "
		  "should be.  This might mean that another operating system "
		  "believes the disk is smaller.  Fix, by moving the backup "
		  "to the end (and removing the old backup)?"))
					== PED_EXCEPTION_CANCEL)
				goto error_free_gpt;

			write_back = 1;
			memset (zeros, 0, disk->dev->sector_size);
			ped_device_write (disk->dev, zeros,
					  PED_LE64_TO_CPU (gpt->AlternateLBA),
					  1);
#endif /* !DISCOVER_ONLY */
		}
	} else { /* primary GPT *not* ok */
		int alternate_ok = 0;

#ifndef DISCOVER_ONLY
		write_back = 1;
#endif

		if ((PedSector) PED_LE64_TO_CPU (gpt->AlternateLBA)
				< disk->dev->length - 1) {
			alternate_ok = _read_header (disk->dev, &gpt,
					    PED_LE64_TO_CPU(gpt->AlternateLBA));
		}
		if (!alternate_ok) {
			alternate_ok = _read_header (disk->dev, &gpt,
						     disk->dev->length - 1);
		}

		if (alternate_ok) {
			if (ped_exception_throw (
				PED_EXCEPTION_ERROR,
				PED_EXCEPTION_OK_CANCEL,
				_("The primary GPT table is corrupt, but the "
				  "backup appears OK, so that will be used."))
				    == PED_EXCEPTION_CANCEL)
				goto error_free_gpt;
		} else {
			ped_exception_throw (
				PED_EXCEPTION_ERROR,
				PED_EXCEPTION_CANCEL,
				_("Both the primary and backup GPT tables "
				  "are corrupt.  Try making a fresh table, "
				  "and using Parted's rescue feature to "
				  "recover partitions."));
			goto error;
		}
	}

	if (!_parse_header (disk, gpt, &write_back))
		goto error_free_gpt;

	/*
	 * ptes_size is in bytes and must be a multiple of sector_size.
	 */
	ptes_size = ped_round_up_to(
		sizeof (GuidPartitionEntry_t) * gpt_disk_data->entry_count,
		disk->dev->sector_size);
	ptes = (GuidPartitionEntry_t*) ped_malloc (ptes_size);

	if (!ped_device_read (disk->dev, ptes,
			      PED_LE64_TO_CPU(gpt->PartitionEntryLBA),
			      ptes_size / disk->dev->sector_size))
		goto error_free_ptes;

	for (i = 0; i < gpt_disk_data->entry_count; i++) {
		PedPartition* part;
		PedConstraint* constraint_exact;

		if (!guid_cmp (ptes[i].PartitionTypeGuid, UNUSED_ENTRY_GUID))
			continue;

		part = _parse_part_entry (disk, &ptes[i]);
		if (!part)
			goto error_delete_all;

		part->fs_type = ped_file_system_probe (&part->geom);
		part->num = i + 1;

		constraint_exact = ped_constraint_exact (&part->geom);
		if (!ped_disk_add_partition(disk, part, constraint_exact)) {
			ped_partition_destroy (part);
			goto error_delete_all;
		}
		ped_constraint_destroy (constraint_exact);
	}
	ped_free (ptes);

#ifndef DISCOVER_ONLY
	if (write_back)
		ped_disk_commit_to_dev (disk);
#endif

	return 1;

error_delete_all:
	ped_disk_delete_all (disk);
error_free_ptes:
	ped_free (ptes);
error_free_gpt:
        pth_free (gpt);
error:
	return 0;
}

#ifndef DISCOVER_ONLY
/* Writes the protective MBR (to keep DOS happy) */
static int
_write_pmbr (PedDevice * dev)
{
	LegacyMBR_t pmbr;

	memset(&pmbr, 0, sizeof(pmbr));
	pmbr.Signature = PED_CPU_TO_LE16(MSDOS_MBR_SIGNATURE);
	pmbr.PartitionRecord[0].OSType      = EFI_PMBR_OSTYPE_EFI;
	pmbr.PartitionRecord[0].StartSector = 1;
	pmbr.PartitionRecord[0].EndHead     = 0xFE;
	pmbr.PartitionRecord[0].EndSector   = 0xFF;
	pmbr.PartitionRecord[0].EndTrack    = 0xFF;
	pmbr.PartitionRecord[0].StartingLBA = PED_CPU_TO_LE32(1);
	if ((dev->length - 1ULL) > 0xFFFFFFFFULL) 
		pmbr.PartitionRecord[0].SizeInLBA = PED_CPU_TO_LE32(0xFFFFFFFF);
	else
		pmbr.PartitionRecord[0].SizeInLBA = PED_CPU_TO_LE32(dev->length - 1UL);

	return ped_device_write (dev, &pmbr, GPT_PMBR_LBA, GPT_PMBR_SECTORS);
}

static void
_generate_header (const PedDisk* disk, int alternate, uint32_t ptes_crc,
		  GuidPartitionTableHeader_t** gpt_p)
{
	GPTDiskData* gpt_disk_data = disk->disk_specific;
        GuidPartitionTableHeader_t* gpt;

        *gpt_p = pth_new_zeroed (disk->dev);
        
        gpt = *gpt_p;
        
	gpt->Signature = PED_CPU_TO_LE64 (GPT_HEADER_SIGNATURE);
	gpt->Revision = PED_CPU_TO_LE32 (GPT_HEADER_REVISION_V1_00);

	/* per 1.00 spec */
	gpt->HeaderSize = PED_CPU_TO_LE32 (pth_get_size_static (disk->dev));
	gpt->HeaderCRC32 = 0;
	gpt->Reserved1 = 0;

	if (alternate) {
		/*
		 * ptes_size is in sectors
		 */
		PedSector ptes_size = ped_div_round_up(
			gpt_disk_data->entry_count *
			sizeof (GuidPartitionEntry_t),
			disk->dev->sector_size);

		gpt->MyLBA = PED_CPU_TO_LE64 (disk->dev->length - 1);
		gpt->AlternateLBA = PED_CPU_TO_LE64 (1);
		gpt->PartitionEntryLBA
			= PED_CPU_TO_LE64 (disk->dev->length - 1 - ptes_size);
	} else {
		gpt->MyLBA = PED_CPU_TO_LE64 (1);
		gpt->AlternateLBA = PED_CPU_TO_LE64 (disk->dev->length - 1);
		gpt->PartitionEntryLBA = PED_CPU_TO_LE64 (2);
	}

	gpt->FirstUsableLBA = PED_CPU_TO_LE64 (gpt_disk_data->data_area.start);
	gpt->LastUsableLBA = PED_CPU_TO_LE64 (gpt_disk_data->data_area.end);
	gpt->DiskGUID = gpt_disk_data->uuid;
	gpt->NumberOfPartitionEntries
		= PED_CPU_TO_LE32 (gpt_disk_data->entry_count);
	gpt->SizeOfPartitionEntry
		= PED_CPU_TO_LE32 (sizeof (GuidPartitionEntry_t));
	gpt->PartitionEntryArrayCRC32 = PED_CPU_TO_LE32 (ptes_crc);
	gpt->HeaderCRC32 = PED_CPU_TO_LE32 (pth_crc32 (disk->dev, gpt));
}

static void
_partition_generate_part_entry (PedPartition* part, GuidPartitionEntry_t* pte)
{
	GPTPartitionData* gpt_part_data = part->disk_specific;
	unsigned int i;

	PED_ASSERT (gpt_part_data != NULL, return);

	pte->PartitionTypeGuid = gpt_part_data->type;
	pte->UniquePartitionGuid = gpt_part_data->uuid;
	pte->StartingLBA = PED_CPU_TO_LE64(part->geom.start);
	pte->EndingLBA = PED_CPU_TO_LE64(part->geom.end);
	memset (&pte->Attributes, 0, sizeof (GuidPartitionEntryAttributes_t));

        if (gpt_part_data->hidden)
                pte->Attributes.RequiredToFunction = 1;
        
	for (i = 0; i < 72 / sizeof(efi_char16_t); i++)
		pte->PartitionName[i]
			= (efi_char16_t) PED_CPU_TO_LE16(
				(uint16_t) gpt_part_data->name[i]);
}

static int
gpt_write(const PedDisk * disk)
{
	GPTDiskData* gpt_disk_data;
	GuidPartitionEntry_t* ptes;
	uint32_t ptes_crc;
        uint8_t* pth_raw = ped_malloc (pth_get_size (disk->dev));
	GuidPartitionTableHeader_t* gpt;
	PedPartition* part;
	int ptes_size;

	PED_ASSERT (disk != NULL, goto error);
	PED_ASSERT (disk->dev != NULL, goto error);
	PED_ASSERT (disk->disk_specific != NULL, goto error);

	gpt_disk_data = disk->disk_specific;

	/*
	 * ptes_size is in bytes and must be a multiple of sector_size.
	 */
	ptes_size = ped_round_up_to(
		sizeof (GuidPartitionEntry_t) * gpt_disk_data->entry_count,
		disk->dev->sector_size);
	ptes = (GuidPartitionEntry_t*) ped_malloc (ptes_size);
	if (!ptes)
		goto error;
	memset (ptes, 0, ptes_size);
	for (part = ped_disk_next_partition (disk, NULL); part;
	     part = ped_disk_next_partition (disk, part)) {
		if (part->type != 0)
			continue;
		_partition_generate_part_entry (part, &ptes[part->num - 1]);
	}

	ptes_crc = efi_crc32 (ptes, ptes_size);

	/* Write protective MBR */
	if (!_write_pmbr (disk->dev))
		goto error_free_ptes;

	/* Write PTH and PTEs */
	_generate_header (disk, 0, ptes_crc, &gpt);
        pth_raw = pth_get_raw (disk->dev, gpt);
	if (!ped_device_write (disk->dev, pth_raw, 1, 1))
		goto error_free_ptes;
	if (!ped_device_write (disk->dev, ptes, 2, ptes_size / disk->dev->sector_size))
		goto error_free_ptes;

	/* Write Alternate PTH & PTEs */
	_generate_header (disk, 1, ptes_crc, &gpt);
        pth_raw = pth_get_raw (disk->dev, gpt);
	if (!ped_device_write (disk->dev, pth_raw, disk->dev->length - 1, 1))
		goto error_free_ptes;
	if (!ped_device_write (disk->dev, ptes,
			       disk->dev->length - 1 - ptes_size / disk->dev->sector_size,
			       ptes_size / disk->dev->sector_size))
		goto error_free_ptes;

	ped_free (ptes);
	return ped_device_sync (disk->dev);

error_free_ptes:
	ped_free (ptes);
error:
	return 0;
}
#endif /* !DISCOVER_ONLY */

static int
add_metadata_part(PedDisk * disk, PedSector start, PedSector length)
{
	PedPartition* part;
	PedConstraint* constraint_exact;
	PED_ASSERT(disk != NULL, return 0);

	part = ped_partition_new (disk, PED_PARTITION_METADATA, NULL,
				  start, start + length - 1);
	if (!part)
		goto error;

	constraint_exact = ped_constraint_exact (&part->geom);
	if (!ped_disk_add_partition (disk, part, constraint_exact))
		goto error_destroy_constraint;
	ped_constraint_destroy (constraint_exact);
	return 1;

error_destroy_constraint:
	ped_constraint_destroy (constraint_exact);
	ped_partition_destroy (part);
error:
	return 0;
}

static PedPartition*
gpt_partition_new (const PedDisk* disk,
		  PedPartitionType part_type, const PedFileSystemType* fs_type,
		  PedSector start, PedSector end)
{
	PedPartition* part;
	GPTPartitionData* gpt_part_data;

	part = _ped_partition_alloc (disk, part_type, fs_type, start, end);
	if (!part)
		goto error;

	if (part_type != 0)
		return part;

	gpt_part_data = part->disk_specific =
		ped_malloc (sizeof (GPTPartitionData));
	if (!gpt_part_data)
		goto error_free_part;

	gpt_part_data->type = PARTITION_BASIC_DATA_GUID;
	gpt_part_data->lvm = 0;
	gpt_part_data->raid = 0;
	gpt_part_data->boot = 0;
	gpt_part_data->hp_service = 0;
        gpt_part_data->hidden = 0;
        gpt_part_data->msftres = 0;
	uuid_generate ((unsigned char*) &gpt_part_data->uuid);
	swap_uuid_and_efi_guid((unsigned char*)(&gpt_part_data->uuid));
	strcpy (gpt_part_data->name, "");
	return part;

error_free_part:
	_ped_partition_free (part);
error:
	return NULL;
}

static PedPartition*
gpt_partition_duplicate (const PedPartition* part)
{
	PedPartition* result;
	GPTPartitionData* part_data = part->disk_specific;
	GPTPartitionData* result_data;

	result = _ped_partition_alloc (part->disk, part->type, part->fs_type,
				       part->geom.start, part->geom.end);
	if (!result)
		goto error;
	result->num = part->num;

	if (result->type != 0)
		return result;

	result_data = result->disk_specific =
		ped_malloc (sizeof (GPTPartitionData));
	if (!result_data)
		goto error_free_part;

	result_data->type = part_data->type;
	result_data->uuid = part_data->uuid;
	strcpy (result_data->name, part_data->name);
	return result;

error_free_part:
	_ped_partition_free (result);
error:
	return NULL;
}

static void
gpt_partition_destroy (PedPartition *part)
{
	if (part->type == 0) {
		PED_ASSERT (part->disk_specific != NULL, return);
		ped_free (part->disk_specific);
	}

	_ped_partition_free (part);
}

static int
gpt_partition_set_system (PedPartition* part, const PedFileSystemType* fs_type)
{
	GPTPartitionData* gpt_part_data = part->disk_specific;

	PED_ASSERT (gpt_part_data != NULL, return 0);

	part->fs_type = fs_type;

	if (gpt_part_data->lvm) {
		gpt_part_data->type = PARTITION_LVM_GUID;
		return 1;
	}
	if (gpt_part_data->raid) {
		gpt_part_data->type = PARTITION_RAID_GUID;
		return 1;
	}
	if (gpt_part_data->boot) {
		gpt_part_data->type = PARTITION_SYSTEM_GUID;
		return 1;
	}
	if (gpt_part_data->hp_service) {
		gpt_part_data->type = PARTITION_HPSERVICE_GUID;
		return 1;
	}
        if (gpt_part_data->msftres) {
                gpt_part_data->type = PARTITION_MSFT_RESERVED_GUID;
                return 1;
        }
        
	if (fs_type) {
		if (strncmp (fs_type->name, "fat", 3) == 0
		    || strcmp (fs_type->name, "ntfs") == 0) {
			gpt_part_data->type = PARTITION_MSFT_RESERVED_GUID;
			return 1;
		}
		if (strncmp (fs_type->name, "hfs", 3) == 0) {
			gpt_part_data->type = PARTITION_APPLE_HFS_GUID;
			return 1;
		}
		if (strstr (fs_type->name, "swap")) {
			gpt_part_data->type = PARTITION_SWAP_GUID;
			return 1;
		}
	}

	gpt_part_data->type = PARTITION_BASIC_DATA_GUID;
	return 1;
}

/* Allocate metadata partitions for the GPTH and PTES */
static int
gpt_alloc_metadata (PedDisk * disk)
{
	PedSector gptlength, pteslength = 0;
	GPTDiskData *gpt_disk_data;

	PED_ASSERT(disk != NULL, return 0);
	PED_ASSERT(disk->dev != NULL, return 0);
	PED_ASSERT(disk->disk_specific != NULL, return 0);
	gpt_disk_data = disk->disk_specific;

	gptlength = ped_div_round_up (sizeof (GuidPartitionTableHeader_t),
	                              disk->dev->sector_size);
	pteslength = ped_div_round_up (gpt_disk_data->entry_count
				       * sizeof (GuidPartitionEntry_t), disk->dev->sector_size);

	/* metadata at the start of the disk includes the MBR */
	if (!add_metadata_part(disk, GPT_PMBR_LBA,
			       GPT_PMBR_SECTORS + gptlength + pteslength))
		return 0;

	/* metadata at the end of the disk */
	if (!add_metadata_part(disk, disk->dev->length - gptlength - pteslength,
			       gptlength + pteslength))
		return 0;

	return 1;
}

/* Does nothing, as the read/new/destroy functions maintain part->num */
static int
gpt_partition_enumerate (PedPartition* part)
{
	GPTDiskData* gpt_disk_data = part->disk->disk_specific;
	int i;

	/* never change the partition numbers */
	if (part->num != -1)
		return 1;

	for (i = 1; i <= gpt_disk_data->entry_count; i++) {
		if (!ped_disk_get_partition (part->disk, i)) {
			part->num = i;
			return 1;
		}
	}

	PED_ASSERT (0, return 0);

	return 0; /* used if debug is disabled */
}

static int
gpt_partition_set_flag(PedPartition *part,
		       PedPartitionFlag flag,
		       int state)
{
	GPTPartitionData *gpt_part_data;
	PED_ASSERT(part != NULL, return 0);
	PED_ASSERT(part->disk_specific != NULL, return 0);
	gpt_part_data = part->disk_specific;

	switch (flag) {
	case PED_PARTITION_BOOT:
		gpt_part_data->boot = state;
		if (state)
                        gpt_part_data->raid 
                                = gpt_part_data->lvm
                                = gpt_part_data->hp_service
                                = gpt_part_data->msftres = 0;
		return gpt_partition_set_system (part, part->fs_type);
	case PED_PARTITION_RAID:
		gpt_part_data->raid = state;
		if (state)
                        gpt_part_data->boot
                                = gpt_part_data->lvm
                                = gpt_part_data->hp_service
                                = gpt_part_data->msftres = 0;
		return gpt_partition_set_system (part, part->fs_type);
	case PED_PARTITION_LVM:
		gpt_part_data->lvm = state;
		if (state)
                        gpt_part_data->boot
                                = gpt_part_data->raid
                                = gpt_part_data->hp_service
                                = gpt_part_data->msftres = 0;
		return gpt_partition_set_system (part, part->fs_type);
	case PED_PARTITION_HPSERVICE:
		gpt_part_data->hp_service = state;
		if (state)
                        gpt_part_data->boot
                                = gpt_part_data->raid
                                = gpt_part_data->lvm
                                = gpt_part_data->msftres = 0;
		return gpt_partition_set_system (part, part->fs_type);
        case PED_PARTITION_MSFT_RESERVED:
                gpt_part_data->msftres = state;
                if (state)
                        gpt_part_data->boot
                                = gpt_part_data->raid
                                = gpt_part_data->lvm
                                = gpt_part_data->hp_service = 0;
                return gpt_partition_set_system (part, part->fs_type);
        case PED_PARTITION_HIDDEN:
                gpt_part_data->hidden = state;
                return 1;
	case PED_PARTITION_SWAP:
	case PED_PARTITION_ROOT:
	case PED_PARTITION_LBA:
	default:
		return 0;
	}
	return 1;
}

static int
gpt_partition_get_flag(const PedPartition *part, PedPartitionFlag flag)
{
	GPTPartitionData *gpt_part_data;
	PED_ASSERT(part->disk_specific != NULL, return 0);
	gpt_part_data = part->disk_specific;

	switch (flag) {
	case PED_PARTITION_RAID:
		return gpt_part_data->raid;
	case PED_PARTITION_LVM:
		return gpt_part_data->lvm;
	case PED_PARTITION_BOOT:
		return gpt_part_data->boot;
	case PED_PARTITION_HPSERVICE:
		return gpt_part_data->hp_service;
        case PED_PARTITION_MSFT_RESERVED:
                return gpt_part_data->msftres;
        case PED_PARTITION_HIDDEN:
                       return gpt_part_data->hidden;
	case PED_PARTITION_SWAP:
	case PED_PARTITION_LBA:
	case PED_PARTITION_ROOT:
	default:
		return 0;
	}
	return 0;
}

static int
gpt_partition_is_flag_available(const PedPartition * part,
				PedPartitionFlag flag)
{
	switch (flag) {
	case PED_PARTITION_RAID:
	case PED_PARTITION_LVM:
	case PED_PARTITION_BOOT:
	case PED_PARTITION_HPSERVICE:
        case PED_PARTITION_MSFT_RESERVED:
        case PED_PARTITION_HIDDEN:        
		return 1;
	case PED_PARTITION_SWAP:
	case PED_PARTITION_ROOT:
	case PED_PARTITION_LBA:
	default:
		return 0;
	}
	return 0;
}

static void
gpt_partition_set_name (PedPartition *part, const char *name)
{
	GPTPartitionData *gpt_part_data = part->disk_specific;

	strncpy (gpt_part_data->name, name, 36);
	gpt_part_data->name [36] = 0;
}

static const char *
gpt_partition_get_name (const PedPartition * part)
{
	GPTPartitionData* gpt_part_data = part->disk_specific;
	return gpt_part_data->name;
}

static int
gpt_get_max_primary_partition_count (const PedDisk *disk)
{
	const GPTDiskData* gpt_disk_data = disk->disk_specific;
	return gpt_disk_data->entry_count;
}

static PedConstraint*
_non_metadata_constraint (const PedDisk* disk)
{
	GPTDiskData* gpt_disk_data = disk->disk_specific;

	return ped_constraint_new_from_max (&gpt_disk_data->data_area);
}

static int
gpt_partition_align (PedPartition* part, const PedConstraint* constraint)
{
	PED_ASSERT (part != NULL, return 0);

	if (_ped_partition_attempt_align (part, constraint,
			_non_metadata_constraint (part->disk)))
	       	return 1;

#ifndef DISCOVER_ONLY
	ped_exception_throw (
		PED_EXCEPTION_ERROR,
		PED_EXCEPTION_CANCEL,
		_("Unable to satisfy all constraints on the partition."));
#endif
	return 0;
}

static PedDiskOps gpt_disk_ops = {
	.probe =			gpt_probe,
#ifndef DISCOVER_ONLY
	.clobber =			gpt_clobber,
#else
	.clobber =			NULL,
#endif
	.alloc =			gpt_alloc,
	.duplicate =			gpt_duplicate,
	.free =				gpt_free,
	.read =				gpt_read,
#ifndef DISCOVER_ONLY
	.write =			gpt_write,
#else
	.write =			NULL,
#endif

	.partition_new =		gpt_partition_new,
	.partition_duplicate =		gpt_partition_duplicate,
	.partition_destroy =		gpt_partition_destroy,
	.partition_set_system =		gpt_partition_set_system,
	.partition_set_flag =		gpt_partition_set_flag,
	.partition_get_flag =		gpt_partition_get_flag,
	.partition_is_flag_available =	gpt_partition_is_flag_available,
	.partition_set_name =		gpt_partition_set_name,
	.partition_get_name =		gpt_partition_get_name,
	.partition_align =		gpt_partition_align,
	.partition_enumerate =		gpt_partition_enumerate,
	.alloc_metadata =		gpt_alloc_metadata,
	.get_max_primary_partition_count = gpt_get_max_primary_partition_count
};

static PedDiskType gpt_disk_type = {
	.next =		NULL,
	.name =		"gpt",
	.ops =		&gpt_disk_ops,
	.features =	PED_DISK_TYPE_PARTITION_NAME
};

void
ped_disk_gpt_init()
{
	PED_ASSERT (sizeof (GuidPartitionEntryAttributes_t) == 8, return);
	PED_ASSERT (sizeof (GuidPartitionEntry_t) == 128, return);

	ped_disk_type_register (&gpt_disk_type);
}

void
ped_disk_gpt_done()
{
	ped_disk_type_unregister (&gpt_disk_type);
}
