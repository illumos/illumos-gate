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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/crc32.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/dkio.h>
#include <sys/file.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/vtoc.h>

#include <sys/vdsk_common.h>

/*
 * Hooks for EFI support
 */

/*
 * This code provides generic functions to the vds and vdc drivers to read
 * EFI labels from the disk backend and to get the EFI GPT and GPE. This is
 * inspired from the libefi userland library and the cmlb driver. We will
 * certainly be able to remove that code if RFE 6213117 is ever implemented.
 */

#define	VD_EFI_DEBUG	if (vd_efi_debug) vd_efi_print

#ifdef DEBUG
static int vd_efi_debug = 1;
#else
static int vd_efi_debug = 0;
#endif

#define	VD_EFI_GPE_LEN(vdisk, nparts) \
	((((sizeof (efi_gpe_t) * (nparts) - 1) / (vdisk)->block_size) + 1) * \
	(vdisk)->block_size)

static void
vd_efi_print(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vcmn_err(CE_CONT, format, args);
	va_end(args);
}

/*
 * Return a 32-bit CRC of the contents of the buffer.
 *
 * The seed is 0xffffffff and the result is XORed with 0xffffffff
 * because this is what the Itanium firmware expects.
 */
unsigned int
vd_efi_crc32(const unsigned char *s, unsigned int len)
{
	unsigned int crc32val;

	CRC32(crc32val, s, len, -1U, crc32_table);

	return (crc32val ^ -1U);
}

static int
vd_efi_ioctl(vd_efi_dev_t *dev, int cmd, void *arg)
{
	int status;

	ASSERT(dev->vdisk_ioctl != NULL);
	ASSERT(dev->vdisk != NULL);
	status = (*dev->vdisk_ioctl)(dev->vdisk, cmd, (uintptr_t)arg);

	return (status);
}

/*
 * Swap GPT data to match with the system endianness.
 */
static void
vd_efi_swap_gpt(efi_gpt_t *gpt)
{
	gpt->efi_gpt_Signature = LE_64(gpt->efi_gpt_Signature);
	gpt->efi_gpt_Revision = LE_32(gpt->efi_gpt_Revision);
	gpt->efi_gpt_HeaderSize = LE_32(gpt->efi_gpt_HeaderSize);
	gpt->efi_gpt_HeaderCRC32 = LE_32(gpt->efi_gpt_HeaderCRC32);
	gpt->efi_gpt_MyLBA = LE_64(gpt->efi_gpt_MyLBA);
	gpt->efi_gpt_AlternateLBA = LE_64(gpt->efi_gpt_AlternateLBA);
	gpt->efi_gpt_FirstUsableLBA = LE_64(gpt->efi_gpt_FirstUsableLBA);
	gpt->efi_gpt_LastUsableLBA = LE_64(gpt->efi_gpt_LastUsableLBA);
	UUID_LE_CONVERT(gpt->efi_gpt_DiskGUID, gpt->efi_gpt_DiskGUID);
	gpt->efi_gpt_PartitionEntryLBA = LE_64(gpt->efi_gpt_PartitionEntryLBA);
	gpt->efi_gpt_NumberOfPartitionEntries =
	    LE_32(gpt->efi_gpt_NumberOfPartitionEntries);
	gpt->efi_gpt_SizeOfPartitionEntry =
	    LE_32(gpt->efi_gpt_SizeOfPartitionEntry);
	gpt->efi_gpt_PartitionEntryArrayCRC32 =
	    LE_32(gpt->efi_gpt_PartitionEntryArrayCRC32);
}

/*
 * Swap GPE data to match with the system endianness.
 */
static void
vd_efi_swap_gpe(efi_gpe_t *gpe, int nparts)
{
	int i, j;

	for (i = 0; i < nparts; i++) {
		UUID_LE_CONVERT(gpe[i].efi_gpe_PartitionTypeGUID,
		    gpe[i].efi_gpe_PartitionTypeGUID);
		UUID_LE_CONVERT(gpe[i].efi_gpe_UniquePartitionGUID,
		    gpe[i].efi_gpe_UniquePartitionGUID);
		gpe[i].efi_gpe_StartingLBA = LE_64(gpe[i].efi_gpe_StartingLBA);
		gpe[i].efi_gpe_EndingLBA = LE_64(gpe[i].efi_gpe_EndingLBA);
		gpe[i].efi_gpe_Attributes.PartitionAttrs =
		    LE_16(gpe[i].efi_gpe_Attributes.PartitionAttrs);
		for (j = 0; j < EFI_PART_NAME_LEN; j++) {
			gpe[i].efi_gpe_PartitionName[j] =
			    LE_16(gpe[i].efi_gpe_PartitionName[j]);
		}
	}
}

/*
 * Check that an EFI GPT is valid. This function should be called with a raw
 * EFI GPT i.e. GPT data should be in little endian format as indicated in the
 * EFI specification and they should not have been swapped to match with the
 * system endianness.
 */
static int
vd_efi_check_gpt(vd_efi_dev_t *dev, efi_gpt_t *gpt)
{
	uint_t crc_stored, crc_computed;

	if (gpt->efi_gpt_Signature != LE_64(EFI_SIGNATURE)) {
		VD_EFI_DEBUG("Bad EFI signature: 0x%llx != 0x%llx\n",
		    (long long)gpt->efi_gpt_Signature,
		    (long long)LE_64(EFI_SIGNATURE));
		return (EINVAL);
	}

	/*
	 * check CRC of the header; the size of the header should
	 * never be larger than one block
	 */
	if (LE_32(gpt->efi_gpt_HeaderSize) > dev->block_size) {
		VD_EFI_DEBUG("Header size (%u bytes) larger than one block"
		    "(%u bytes)\n", LE_32(gpt->efi_gpt_HeaderSize),
		    dev->block_size);
		return (EINVAL);
	}

	crc_stored = LE_32(gpt->efi_gpt_HeaderCRC32);
	gpt->efi_gpt_HeaderCRC32 = LE_32(0);
	crc_computed = vd_efi_crc32((unsigned char *)gpt,
	    LE_32(gpt->efi_gpt_HeaderSize));
	gpt->efi_gpt_HeaderCRC32 = LE_32(crc_stored);

	if (crc_stored != crc_computed) {
		VD_EFI_DEBUG("Bad EFI CRC: 0x%x != 0x%x\n",
		    crc_stored, crc_computed);
		return (EINVAL);
	}

	return (0);
}

/*
 * Allocate and read the EFI GPT and GPE from the disk backend. Note that the
 * on-disk GPT and GPE are stored in little endian format but this function
 * returns them using the endianness of the system so that any field in the
 * GPT/GPE structures can be directly accessible without any further conversion.
 * The caller is responsible for freeing the allocated structures by calling
 * vd_efi_free().
 */
int
vd_efi_alloc_and_read(vd_efi_dev_t *dev, efi_gpt_t **efi_gpt,
    efi_gpe_t **efi_gpe)
{
	dk_efi_t		dk_efi;
	efi_gpt_t		*gpt = NULL;
	efi_gpe_t		*gpe = NULL;
	size_t			gpt_len, gpe_len;
	int 			nparts, status;

	ASSERT(dev->block_size >= sizeof (efi_gpt_t));
	gpt_len = dev->block_size;
	gpt = kmem_zalloc(gpt_len, KM_SLEEP);

	/*
	 * Read the EFI GPT.
	 */
	dk_efi.dki_lba = 1;
	dk_efi.dki_data = gpt;
	dk_efi.dki_length = gpt_len;

	if ((status = vd_efi_ioctl(dev, DKIOCGETEFI, &dk_efi)) != 0) {
		VD_EFI_DEBUG("DKIOCGETEFI (GPT, LBA=1) error %d\n", status);
		goto errdone;
	}

	if ((status = vd_efi_check_gpt(dev, gpt)) != 0) {
		/*
		 * No valid label here; try the alternate. The alternate GPT is
		 * located in the last block of the disk.
		 */
		dk_efi.dki_lba = dev->disk_size - 1;
		dk_efi.dki_data = gpt;
		dk_efi.dki_length = gpt_len;

		if ((status = vd_efi_ioctl(dev, DKIOCGETEFI, &dk_efi)) != 0) {
			VD_EFI_DEBUG("DKIOCGETEFI (LBA=%lu) error %d\n",
			    dev->disk_size - 1, status);
			goto errdone;
		}

		if ((status = vd_efi_check_gpt(dev, gpt)) != 0)
			goto errdone;

		VD_EFI_DEBUG("efi_read: primary label corrupt; using backup\n");
	}

	/* swap GPT data after checking the GPT is valid */
	vd_efi_swap_gpt(gpt);

	/*
	 * Read the EFI GPE.
	 */
	nparts = gpt->efi_gpt_NumberOfPartitionEntries;

	if (nparts > NDKMAP + 1) {
		VD_EFI_DEBUG("Too many EFI partitions (%u)", nparts);
		status = EINVAL;
		goto errdone;
	}

	if (nparts == 0) {
		VD_EFI_DEBUG("No partition defined");
		status = EINVAL;
		goto errdone;
	}

	gpe_len = VD_EFI_GPE_LEN(dev, nparts);
	gpe = kmem_zalloc(gpe_len, KM_SLEEP);

	dk_efi.dki_lba = gpt->efi_gpt_PartitionEntryLBA;
	dk_efi.dki_data = (efi_gpt_t *)gpe;
	dk_efi.dki_length = gpe_len;

	if ((status = vd_efi_ioctl(dev, DKIOCGETEFI, &dk_efi)) != 0) {
		VD_EFI_DEBUG("DKIOCGETEFI (GPE, LBA=%lu) error %d\n",
		    gpt->efi_gpt_PartitionEntryLBA, status);
		goto errdone;
	}

	vd_efi_swap_gpe(gpe, nparts);

	*efi_gpt = gpt;
	*efi_gpe = gpe;

	return (0);

errdone:

	if (gpe != NULL)
		kmem_free(gpe, gpe_len);
	if (gpt != NULL)
		kmem_free(gpt, gpt_len);

	return (status);
}

/*
 * Free the EFI GPE and GPT structures returned by vd_efi_alloc_and_read().
 */
void
vd_efi_free(vd_efi_dev_t *dev, efi_gpt_t *gpt, efi_gpe_t *gpe)
{
	kmem_free(gpe, VD_EFI_GPE_LEN(dev,
	    gpt->efi_gpt_NumberOfPartitionEntries));
	kmem_free(gpt, dev->block_size);
}
