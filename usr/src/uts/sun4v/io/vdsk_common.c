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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
 * This code is a port of the functions efi_alloc_read() and efi_free() from
 * the libefi userland library to the kernel so that the vDisk drivers (vdc
 * and vds) can read EFI data. We will certaintly be able to remove that code
 * once RFE 6213117 is implemented.
 */

#define	VD_IOCTL_FLAGS  (FEXCL | FREAD | FWRITE | FKIOCTL)

#define	VD_EFI_DEBUG	if (vd_efi_debug) vd_efi_print

/*
 * The number of blocks the EFI label takes up (round up to nearest
 * block)
 */
#define	NBLOCKS(p, l)	(1 + ((((p) * (int)sizeof (efi_gpe_t))  + \
				((l) - 1)) / (l)))
/* number of partitions -- limited by what we can malloc */
#define	MAX_PARTS	((4294967295UL - sizeof (struct dk_gpt)) / \
			    sizeof (struct dk_part))

/*
 * The vd_efi_alloc_and_read() function will use some ioctls to get EFI data
 * but the way we issue ioctl is different depending if we are on the vDisk
 * server side (vds) or on the vDisk client side.
 *
 * On the server side (vds), we reference a layered device (ldi_handle_t) so we
 * will use the LDI interface to execute ioctls (ldi_ioctl()). On the client
 * side (vdc), we reference a vdc device (with a dev_t) so we directly invoke
 * the function of the vdc driver implementing ioctls (vd_process_ioctl()).
 */
#define	VD_EFI_CALLER_VDS	0
#define	VD_EFI_CALLER_VDC	1

typedef struct vd_efi_dev {
	int caller;
	union {
		ldi_handle_t vds;
		dev_t vdc;
	} ioctl_dev;
} vd_efi_dev_t;

static int (*vdc_ioctl_func)(dev_t dev, int cmd, caddr_t arg, int mode) = NULL;

static int vd_efi_debug = 1;

static struct uuid_to_ptag {
	struct uuid	uuid;
} conversion_array[] = {
	{ EFI_UNUSED },
	{ EFI_BOOT },
	{ EFI_ROOT },
	{ EFI_SWAP },
	{ EFI_USR },
	{ EFI_BACKUP },
	{ 0 },			/* STAND is never used */
	{ EFI_VAR },
	{ EFI_HOME },
	{ EFI_ALTSCTR },
	{ 0 },			/* CACHE (cachefs) is never used */
	{ EFI_RESERVED },
	{ EFI_SYSTEM },
	{ EFI_LEGACY_MBR },
	{ EFI_RESV3 },
	{ EFI_RESV4 },
	{ EFI_MSFT_RESV },
	{ EFI_DELL_BASIC },
	{ EFI_DELL_RAID },
	{ EFI_DELL_SWAP },
	{ EFI_DELL_LVM },
	{ EFI_DELL_RESV }
};

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
vd_ioctl(vd_efi_dev_t *dev, int cmd, void *arg, int flag,
    cred_t *cred, int *rvalp)
{
	int error;

	if (dev->caller == VD_EFI_CALLER_VDS) {
		error = ldi_ioctl(dev->ioctl_dev.vds, cmd,
		    (intptr_t)arg, flag, cred, rvalp);
	} else {
		ASSERT(vdc_ioctl_func != NULL);
		error = (*vdc_ioctl_func)(dev->ioctl_dev.vdc, cmd,
		    arg, flag);
	}

	return (error);
}

static int
vd_efi_ioctl(vd_efi_dev_t *dev, int cmd, dk_efi_t *dk_ioc)
{
	void *data = dk_ioc->dki_data;
	int error;

	dk_ioc->dki_data_64 = (uint64_t)(uintptr_t)data;
	error = vd_ioctl(dev, cmd, (caddr_t)dk_ioc, VD_IOCTL_FLAGS,
	    kcred, NULL);
	dk_ioc->dki_data = data;

	return (error);
}

static int
vd_efi_check_label(vd_efi_dev_t *dev, dk_efi_t *dk_ioc)
{
	efi_gpt_t *efi;
	uint_t crc;
	int status;

	if ((status = vd_efi_ioctl(dev, DKIOCGETEFI, dk_ioc)) != 0)
		return (status);

	efi = dk_ioc->dki_data;
	if (efi->efi_gpt_Signature != LE_64(EFI_SIGNATURE)) {
		VD_EFI_DEBUG("Bad EFI signature: 0x%llx != 0x%llx\n",
		    (long long)efi->efi_gpt_Signature,
		    (long long)LE_64(EFI_SIGNATURE));
		return (EINVAL);
	}

	/*
	 * check CRC of the header; the size of the header should
	 * never be larger than one block
	 */
	crc = efi->efi_gpt_HeaderCRC32;
	efi->efi_gpt_HeaderCRC32 = 0;

	if (((len_t)LE_32(efi->efi_gpt_HeaderSize) > dk_ioc->dki_length) ||
	    crc != LE_32(vd_efi_crc32((unsigned char *)efi,
	    LE_32(efi->efi_gpt_HeaderSize)))) {
		VD_EFI_DEBUG("Bad EFI CRC: 0x%x != 0x%x\n",
		    crc, LE_32(vd_efi_crc32((unsigned char *)efi,
		    sizeof (struct efi_gpt))));
		return (EINVAL);
	}

	return (0);
}

static int
vd_efi_read(vd_efi_dev_t *dev, struct dk_gpt *vtoc)
{
	int			i, j, status;
	int			label_len;
	int			md_flag = 0;
	struct dk_minfo		disk_info;
	dk_efi_t		dk_ioc;
	efi_gpt_t		*efi;
	efi_gpe_t		*efi_parts;
	struct dk_cinfo		dki_info;
	uint32_t		user_length;

	/*
	 * get the partition number for this file descriptor.
	 */
	if ((status = vd_ioctl(dev, DKIOCINFO, &dki_info, VD_IOCTL_FLAGS,
	    kcred, NULL)) != 0) {
		VD_EFI_DEBUG("DKIOCINFO error 0x%x\n", status);
		return (status);
	}
	if ((strncmp(dki_info.dki_cname, "pseudo", 7) == 0) &&
	    (strncmp(dki_info.dki_dname, "md", 3) == 0)) {
		md_flag++;
	}
	/* get the LBA size */
	if ((status = vd_ioctl(dev, DKIOCGMEDIAINFO, &disk_info, VD_IOCTL_FLAGS,
	    kcred, NULL)) != 0) {
		VD_EFI_DEBUG("assuming LBA 512 bytes %d\n", status);
		disk_info.dki_lbsize = DEV_BSIZE;
	}
	if (disk_info.dki_lbsize == 0) {
		VD_EFI_DEBUG("efi_read: assuming LBA 512 bytes\n");
		disk_info.dki_lbsize = DEV_BSIZE;
	}
	/*
	 * Read the EFI GPT to figure out how many partitions we need
	 * to deal with.
	 */
	dk_ioc.dki_lba = 1;
	if (NBLOCKS(vtoc->efi_nparts, disk_info.dki_lbsize) < 34) {
		label_len = EFI_MIN_ARRAY_SIZE + disk_info.dki_lbsize;
	} else {
		label_len = vtoc->efi_nparts * (int) sizeof (efi_gpe_t) +
				    disk_info.dki_lbsize;
		if (label_len % disk_info.dki_lbsize) {
			/* pad to physical sector size */
			label_len += disk_info.dki_lbsize;
			label_len &= ~(disk_info.dki_lbsize - 1);
		}
	}

	dk_ioc.dki_data = kmem_alloc(label_len, KM_SLEEP);
	dk_ioc.dki_length = label_len;
	user_length = vtoc->efi_nparts;
	efi = dk_ioc.dki_data;
	if (md_flag) {
		if ((status = vd_efi_ioctl(dev, DKIOCGETEFI, &dk_ioc)) != 0)
			return (status);
	} else if ((status = vd_efi_check_label(dev, &dk_ioc)) == EINVAL) {
		/* no valid label here; try the alternate */
		dk_ioc.dki_lba = disk_info.dki_capacity - 1;
		dk_ioc.dki_length = disk_info.dki_lbsize;
		if (vd_efi_check_label(dev, &dk_ioc) == 0) {
			VD_EFI_DEBUG("efi_read: primary label corrupt; "
			    "using backup\n");
			dk_ioc.dki_lba = LE_64(efi->efi_gpt_PartitionEntryLBA);
			vtoc->efi_flags |= EFI_GPT_PRIMARY_CORRUPT;
			vtoc->efi_nparts =
			    LE_32(efi->efi_gpt_NumberOfPartitionEntries);
			/*
			 * partitions are between last usable LBA and
			 * backup partition header
			 */
			dk_ioc.dki_data++;
			dk_ioc.dki_length = disk_info.dki_capacity -
						    dk_ioc.dki_lba - 1;
			dk_ioc.dki_length *= disk_info.dki_lbsize;
			if (dk_ioc.dki_length > (len_t)label_len) {
				status = EINVAL;
			} else {
				status = vd_efi_ioctl(dev, DKIOCGETEFI,
				    &dk_ioc);
			}
		}
	}
	if (status != 0) {
		kmem_free(efi, label_len);
		return (status);
	}

	/* partitions start in the next block */
	/* LINTED -- always longlong aligned */
	efi_parts = (efi_gpe_t *)(((char *)efi) + disk_info.dki_lbsize);

	/*
	 * Assemble this into a "dk_gpt" struct for easier
	 * digestibility by applications.
	 */
	vtoc->efi_version = LE_32(efi->efi_gpt_Revision);
	vtoc->efi_nparts = LE_32(efi->efi_gpt_NumberOfPartitionEntries);
	vtoc->efi_part_size = LE_32(efi->efi_gpt_SizeOfPartitionEntry);
	vtoc->efi_lbasize = disk_info.dki_lbsize;
	vtoc->efi_last_lba = disk_info.dki_capacity - 1;
	vtoc->efi_first_u_lba = LE_64(efi->efi_gpt_FirstUsableLBA);
	vtoc->efi_last_u_lba = LE_64(efi->efi_gpt_LastUsableLBA);
	UUID_LE_CONVERT(vtoc->efi_disk_uguid, efi->efi_gpt_DiskGUID);

	/*
	 * If the array the user passed in is too small, set the length
	 * to what it needs to be and return
	 */
	if (user_length < vtoc->efi_nparts) {
		kmem_free(efi, label_len);
		return (EINVAL);
	}

	for (i = 0; i < vtoc->efi_nparts; i++) {

	    UUID_LE_CONVERT(vtoc->efi_parts[i].p_guid,
		efi_parts[i].efi_gpe_PartitionTypeGUID);

	    for (j = 0;
		j < sizeof (conversion_array) / sizeof (struct uuid_to_ptag);
		j++) {

		    if (bcmp(&vtoc->efi_parts[i].p_guid,
			&conversion_array[j].uuid,
			sizeof (struct uuid)) == 0) {
			    vtoc->efi_parts[i].p_tag = j;
			    break;
		    }
	    }
	    if (vtoc->efi_parts[i].p_tag == V_UNASSIGNED)
		    continue;
	    vtoc->efi_parts[i].p_flag =
		LE_16(efi_parts[i].efi_gpe_Attributes.PartitionAttrs);
	    vtoc->efi_parts[i].p_start =
		LE_64(efi_parts[i].efi_gpe_StartingLBA);
	    vtoc->efi_parts[i].p_size =
		LE_64(efi_parts[i].efi_gpe_EndingLBA) -
		    vtoc->efi_parts[i].p_start + 1;
	    for (j = 0; j < EFI_PART_NAME_LEN; j++) {
		vtoc->efi_parts[i].p_name[j] =
		    (uchar_t)LE_16(efi_parts[i].efi_gpe_PartitionName[j]);
	    }

	    UUID_LE_CONVERT(vtoc->efi_parts[i].p_uguid,
		efi_parts[i].efi_gpe_UniquePartitionGUID);
	}
	kmem_free(efi, label_len);

	return (0);
}

/*
 * Read EFI - return 0 upon success.
 */
static int
vd_efi_alloc_and_read(vd_efi_dev_t *dev, struct dk_gpt **vtoc, size_t *vtoc_len)
{
	int status;
	uint32_t nparts;
	int length;

	/* figure out the number of entries that would fit into 16K */
	nparts = EFI_MIN_ARRAY_SIZE / sizeof (efi_gpe_t);
	length = (int) sizeof (struct dk_gpt) +
	    (int) sizeof (struct dk_part) * (nparts - 1);

	*vtoc = kmem_zalloc(length, KM_SLEEP);
	(*vtoc)->efi_nparts = nparts;
	status = vd_efi_read(dev, *vtoc);

	if ((status == EINVAL) && (*vtoc)->efi_nparts > nparts) {
		kmem_free(*vtoc, length);
		length = (int) sizeof (struct dk_gpt) +
				(int) sizeof (struct dk_part) *
				((*vtoc)->efi_nparts - 1);
		nparts = (*vtoc)->efi_nparts;
		*vtoc = kmem_alloc(length, KM_SLEEP);
		status = vd_efi_read(dev, *vtoc);
	}

	if (status != 0) {
		VD_EFI_DEBUG("read of EFI table failed with error=%d\n",
		    status);
		kmem_free(*vtoc, length);
		*vtoc = NULL;
		*vtoc_len = 0;
		return (status);
	}

	*vtoc_len = length;
	return (0);
}

int
vdc_efi_alloc_and_read(dev_t dev, struct dk_gpt **vtoc, size_t *vtoc_len)
{
	vd_efi_dev_t efi_dev;

	ASSERT(vdc_ioctl_func != NULL);

	efi_dev.caller = VD_EFI_CALLER_VDC;
	efi_dev.ioctl_dev.vdc = dev;

	return (vd_efi_alloc_and_read(&efi_dev, vtoc, vtoc_len));
}

int
vds_efi_alloc_and_read(ldi_handle_t dev, struct dk_gpt **vtoc, size_t *vtoc_len)
{
	vd_efi_dev_t efi_dev;

	efi_dev.caller = VD_EFI_CALLER_VDS;
	efi_dev.ioctl_dev.vds = dev;

	return (vd_efi_alloc_and_read(&efi_dev, vtoc, vtoc_len));
}

void
vd_efi_free(struct dk_gpt *ptr, size_t length)
{
	kmem_free(ptr, length);
}

void
vdc_efi_init(int (*func)(dev_t, int, caddr_t, int))
{
	vdc_ioctl_func = func;
}

void
vdc_efi_fini(void)
{
	vdc_ioctl_func = NULL;
}

/*
 * This function stores EFI data (as returned by efi_alloc_and_read()) into
 * a vtoc structure. The vDisk driver uses a vtoc structure to store generic
 * information about disk partitions.
 */
void
vd_efi_to_vtoc(struct dk_gpt *efi, struct vtoc *vtoc)
{
	int i, nparts;

	bzero(vtoc, sizeof (struct vtoc));

	vtoc->v_sanity = VTOC_SANE;

	nparts = efi->efi_nparts;
	for (i = 0; i < nparts; i++) {
		if (efi->efi_parts[i].p_tag != V_RESERVED)
			continue;
		bcopy(efi->efi_parts[i].p_name, vtoc->v_volume,
		    LEN_DKL_VVOL);
		bcopy(efi->efi_parts[i].p_name, vtoc->v_asciilabel,
		    EFI_PART_NAME_LEN);
		break;
	}

	vtoc->v_sectorsz = efi->efi_lbasize;
	vtoc->v_nparts = nparts;
	for (i = 0; i < nparts; i++) {
		/*
		 * EFI can have more than 8 partitions. However the current
		 * implementation of EFI on Solaris only support 7 partitions
		 * (s0 to s6). There is no partition s7 but the minor number
		 * corresponding to slice 7 is used to represent the whole
		 * disk which data are stored in the "Sun Reserved" partition.
		 * So we use the entry 7 of the vtoc structure to store
		 * information about the whole disk.
		 */
		if (efi->efi_parts[i].p_tag == V_RESERVED) {
			vtoc->v_part[VD_EFI_WD_SLICE].p_tag =
				efi->efi_parts[i].p_tag;
			vtoc->v_part[VD_EFI_WD_SLICE].p_flag =
				efi->efi_parts[i].p_flag;
			vtoc->v_part[VD_EFI_WD_SLICE].p_start =
				efi->efi_parts[i].p_start;
			vtoc->v_part[VD_EFI_WD_SLICE].p_size =
				efi->efi_parts[i].p_size;
			continue;
		}

		if (i >= VD_EFI_WD_SLICE) {
			continue;
		}

		vtoc->v_part[i].p_tag = efi->efi_parts[i].p_tag;
		if (efi->efi_parts[i].p_tag != V_UNASSIGNED) {
			vtoc->v_part[i].p_flag = efi->efi_parts[i].p_flag;
			vtoc->v_part[i].p_start = efi->efi_parts[i].p_start;
			vtoc->v_part[i].p_size = efi->efi_parts[i].p_size;
		}
	}
}
