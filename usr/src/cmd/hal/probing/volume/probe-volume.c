/***************************************************************************
 *
 * probe-volume.c : probe volumes
 *
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/dkio.h>
#include <sys/cdio.h>
#include <sys/fdio.h>
#include <libnvpair.h>
#include <libfstyp.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_isospec.h>
#include <priv.h>
#include <sys/u8_textprep.h>

#include <libhal.h>
#include <cdutils.h>
#include <fsutils.h>
#include <logger.h>

static void
my_dbus_error_free(DBusError *error)
{
	if (dbus_error_is_set(error)) {
		dbus_error_free(error);
	}
}

/*
 * Return a copy of a string without trailing spaces. If 'len' is non-zero,
 * it specifies max length, otherwise the string must be null-terminated.
 */
static char *
rtrim_copy(char *src, int len)
{
	char	*dst, *p;

	if (len == 0) {
		len = strlen(src);
	}
	if ((dst = calloc(1, len + 1)) != NULL) {
		strncpy(dst, src, len);
		p = dst + len - 1;
		while ((p >= dst) && (isspace(*p))) {
			*p-- = '\0';
		}
	}
	return (dst);
}

static void
set_fstyp_properties (LibHalContext *ctx, const char *udi, const char *fstype, nvlist_t *fsattr)
{
	char buf[256];
	DBusError error;
	char *uuid = NULL;
	char *label_orig = NULL;
	char *label = NULL;
	int  err;
	LibHalChangeSet *cs;

	dbus_error_init (&error);

	if ((cs = libhal_device_new_changeset (udi)) == NULL) {
		return;
	}

	libhal_changeset_set_property_string (cs, "volume.fsusage", "filesystem");
	libhal_changeset_set_property_string (cs, "volume.fstype", fstype);

	/* label */
	(void) nvlist_lookup_string(fsattr, "gen_volume_label", &label_orig);
	if (label_orig != NULL) {
		label = rtrim_copy(label_orig, 0);
	}
	/* Check if label is utf8 format */
	if ((label != NULL) && (label[0] != '\0') &&
	    (u8_validate(label, strlen(label), (char **)NULL,
	    U8_VALIDATE_ENTIRE, &err) != -1)) {
	        libhal_changeset_set_property_string (cs, "volume.label", label);
	        libhal_changeset_set_property_string (cs, "info.product", label);
	} else {
		libhal_changeset_set_property_string (cs, "volume.label", "");
		snprintf (buf, sizeof (buf), "Volume (%s)", fstype);
		libhal_changeset_set_property_string (cs, "info.product", buf);
	}
	free(label);

	/* uuid */
	if (nvlist_lookup_string(fsattr, "gen_uuid", &uuid) == 0) {
		libhal_changeset_set_property_string (cs, "volume.uuid", uuid);
	} else {
		libhal_changeset_set_property_string (cs, "volume.uuid", "");
	}

	libhal_device_commit_changeset (ctx, cs, &error);
	libhal_device_free_changeset (cs);

	my_dbus_error_free (&error);
}

/*
 * hsfs/iso9660 contents detection: Video DVD, Video CD, etc.
 */
static void
hsfs_contents(int fd, off_t probe_offset, LibHalContext *ctx, const char *udi)
{
	size_t	secsz = ISO_SECTOR_SIZE;
	uchar_t	buf[ISO_SECTOR_SIZE];
	int	ptbl_lbn, ptbl_size;
	int	off, reloff, readoff;
	uchar_t	*p;
	char	*name;
	int	name_len;
	int	ipe_len;
	DBusError error;

	/*
	 * find 1st Primary Volume Descriptor
	 */
	readoff = probe_offset + ISO_VOLDESC_SEC * secsz;
	if (pread (fd, buf, secsz, readoff) != secsz) {
		return;
	}
	while (ISO_DESC_TYPE (buf) != ISO_VD_PVD) {
		if (ISO_DESC_TYPE (buf) == ISO_VD_EOV) {
			return;
		}
		readoff += secsz;
		if (pread (fd, buf, secsz, readoff) != secsz) {
			return;
		}
	}

	/*
	 * PVD contains size and offset of the LSB/MSB path table
	 */
	ptbl_size = ISO_PTBL_SIZE (buf);
#if defined(_LITTLE_ENDIAN)
        ptbl_lbn = ISO_PTBL_MAN_LS (buf);
#else
        ptbl_lbn = ISO_PTBL_MAN_MS (buf);
#endif

	/*
	 * Look through path table entries
	 */
	readoff = probe_offset + ptbl_lbn * secsz;
	if (pread (fd, buf, secsz, readoff) != secsz) {
		return;
	}
	dbus_error_init (&error);

	for (off = reloff = 0;
	    off < ptbl_size;
	    off += ipe_len, reloff += ipe_len) {

		/* load sectors on demand */
		if (reloff >= secsz) {
			readoff += secsz;
			if (pread (fd, buf, secsz, readoff) != secsz) {
				break;
			}
			reloff -= secsz;
		}

		p = buf + reloff;
		name_len = IPE_NAME_LEN(p);
		ipe_len = IPE_FPESIZE + name_len + (name_len % 2);

		/* only interested in root directories */
		if (IPE_PARENT_NO (p) != 1) {
			continue;
		}
		if ((name_len < 2) || (name_len > IDE_MAX_NAME_LEN)) {
			continue;
		}

		name = (char *)IPE_NAME (p);
		if (strncasecmp (name, "VIDEO_TS", min (8, name_len)) == 0) {
			libhal_device_set_property_bool (ctx, udi,
			    "volume.disc.is_videodvd", TRUE, &error);
		} else if (strncasecmp (name, "VCD", min (3, name_len)) == 0) {
			libhal_device_set_property_bool (ctx, udi,
			    "volume.disc.is_vcd", TRUE, &error);
		} else if (strncasecmp (name, "SVCD", min (4, name_len)) == 0) {
			libhal_device_set_property_bool (ctx, udi,
			    "volume.disc.is_svcd", TRUE, &error);
		}
	}

	my_dbus_error_free (&error);
}

static dbus_bool_t
probe_disc (int fd, LibHalContext *ctx, const char *udi, dbus_bool_t *has_data,
    dbus_bool_t *has_audio)
{
	DBusError error;
	disc_info_t di;
	int profile;
	dbus_bool_t is_blank, is_appendable, is_rewritable;
	char *disc_type = "cd_rom";
	uint64_t capacity = 0;
	int i;
	LibHalChangeSet *cs;

	dbus_error_init (&error);

	if (get_disc_info (fd, &di)) {
		is_blank = (di.disc_status == 0);
		is_appendable = (di.disc_status == 1);
		is_rewritable = (di.erasable != 0);
	} else {
		is_blank = is_appendable = is_rewritable = FALSE;
	}

	if (get_current_profile (fd, &profile)) {
		switch (profile) {
		case 0x08: /* CD-ROM */
			disc_type = "cd_rom";
			break;
		case 0x09: /* CD-R */
			disc_type = "cd_r";
			break;
		case 0x0A: /* CD-RW */
			disc_type = "cd_rw";
			is_rewritable = TRUE;
			break;
		case 0x10: /* DVD-ROM */
			disc_type = "dvd_rom";
			break;
		case 0x11: /* DVD-R Sequential */
			disc_type = "dvd_r";
			break;
		case 0x12: /* DVD-RAM */
			disc_type = "dvd_ram";
			is_rewritable = TRUE;
			break;
		case 0x13: /* DVD-RW Restricted Overwrite */
			disc_type = "dvd_rw";
			is_rewritable = TRUE;
			break;
		case 0x14: /* DVD-RW Sequential */
			disc_type = "dvd_rw";
			is_rewritable = TRUE;
			break;
		case 0x1A: /* DVD+RW */
			disc_type = "dvd_plus_rw";
			is_rewritable = TRUE;
			break;
		case 0x1B: /* DVD+R */
			disc_type = "dvd_plus_r";
			break;
		case 0x2B: /* DVD+R Double Layer */
                        disc_type = "dvd_plus_r_dl";
			break;
		case 0x40: /* BD-ROM */
                        disc_type = "bd_rom";
			break;
		case 0x41: /* BD-R Sequential */
                        disc_type = "bd_r";
			break;
		case 0x42: /* BD-R Random */
                        disc_type = "bd_r";
			break;
		case 0x43: /* BD-RE */
                        disc_type = "bd_re";
			is_rewritable = TRUE;
			break;
		case 0x50: /* HD DVD-ROM */
                        disc_type = "hddvd_rom";
			break;
		case 0x51: /* HD DVD-R */
                        disc_type = "hddvd_r";
			break;
		case 0x52: /* HD DVD-Rewritable */
                        disc_type = "hddvd_rw";
			is_rewritable = TRUE;
			break;
		}

		(void) get_disc_capacity_for_profile(fd, profile, &capacity);
	}

	*has_audio = *has_data = FALSE;
	if (!is_blank) {
		uchar_t	smalltoc[12];
		size_t	toc_size;
		uchar_t	*toc, *p;

		/*
		 * XXX for some reason CDROMREADTOCENTRY fails on video DVDs,
		 * but extracting the toc directly works okay. And the toc
		 * data buffer length passed to read_toc() should be the same
		 * as the real buffer size.
		 */
		if (!read_toc(fd, 0, 1, 12, smalltoc)) {
                	HAL_DEBUG(("read_toc failed"));
			*has_data = B_TRUE; /* probe for fs anyway */
        	} else {
        		toc_size = smalltoc[0] * 256 + smalltoc[1] + 2;
        		toc = (uchar_t *)calloc(1, toc_size);
        		if (toc == NULL || !read_toc(fd, 0, 1, toc_size, toc)) {
                		HAL_DEBUG (("read_toc again failed"));
        		} else {
        			for (p = &toc[4]; p < (toc + toc_size); p += 8) {
					/* skip leadout */
                			if (p[2] == 0xAA) {
						continue;
					}
					if (p[1] & 4) {
						*has_data = B_TRUE;
					} else {
						*has_audio = B_TRUE;
					}
        			}
			}
			free(toc);
		}
	}

	if ((cs = libhal_device_new_changeset (udi)) == NULL) {
		return (FALSE);
	}
	libhal_changeset_set_property_string (cs, "volume.disc.type", disc_type);
	libhal_changeset_set_property_bool (cs, "volume.disc.is_blank", is_blank);
	libhal_changeset_set_property_bool (cs, "volume.disc.has_audio", *has_audio);
	libhal_changeset_set_property_bool (cs, "volume.disc.has_data", *has_data);
	libhal_changeset_set_property_bool (cs, "volume.disc.is_appendable", is_appendable);
	libhal_changeset_set_property_bool (cs, "volume.disc.is_rewritable", is_rewritable);
	libhal_changeset_set_property_uint64 (cs, "volume.disc.capacity", capacity);

	libhal_changeset_set_property_bool (cs, "volume.disc.is_videodvd", FALSE);
	libhal_changeset_set_property_bool (cs, "volume.disc.is_vcd", FALSE);
	libhal_changeset_set_property_bool (cs, "volume.disc.is_svcd", FALSE);

	libhal_device_commit_changeset (ctx, cs, &error);
	libhal_device_free_changeset (cs);

	my_dbus_error_free (&error);

	return (TRUE);
}

static void
drop_privileges ()
{
	priv_set_t *pPrivSet = NULL;
	priv_set_t *lPrivSet = NULL;

	/*
	 * Start with the 'basic' privilege set and then remove any
	 * of the 'basic' privileges that will not be needed.
	 */
	if ((pPrivSet = priv_str_to_set("basic", ",", NULL)) == NULL) {
		return;
	}

	/* Clear privileges we will not need from the 'basic' set */
	(void) priv_delset(pPrivSet, PRIV_FILE_LINK_ANY);
	(void) priv_delset(pPrivSet, PRIV_PROC_INFO);
	(void) priv_delset(pPrivSet, PRIV_PROC_SESSION);
	(void) priv_delset(pPrivSet, PRIV_PROC_EXEC);
	(void) priv_delset(pPrivSet, PRIV_PROC_FORK);

	/* for uscsi */
	(void) priv_addset(pPrivSet, PRIV_SYS_DEVICES);


	/* to open logindevperm'd devices */
	(void) priv_addset(pPrivSet, PRIV_FILE_DAC_READ);

	/* Set the permitted privilege set. */
	if (setppriv(PRIV_SET, PRIV_PERMITTED, pPrivSet) != 0) {
		return;
	}

	/* Clear the limit set. */
	if ((lPrivSet = priv_allocset()) == NULL) {
		return;
	}

	priv_emptyset(lPrivSet);

	if (setppriv(PRIV_SET, PRIV_LIMIT, lPrivSet) != 0) {
		return;
	}

	priv_freeset(lPrivSet);
}

int
main (int argc, char *argv[])
{
	int fd, rfd;
	int ret;
	char *udi;
	char *device_file, *raw_device_file;
	char *devpath, *rdevpath;
	boolean_t is_dos;
	int dos_num;
	LibHalContext *ctx = NULL;
	DBusError error;
	DBusConnection *conn;
	char *parent_udi;
	char *storage_device;
	char *is_disc_str;
	int fdc;
	dbus_bool_t is_disc = FALSE;
	dbus_bool_t is_floppy = FALSE;
	unsigned int block_size;
	dbus_uint64_t vol_size;
	dbus_bool_t has_data = TRUE;	/* probe for fs by default */
	dbus_bool_t has_audio = FALSE;
	char *partition_scheme = NULL;
	dbus_uint64_t partition_start = 0;
	int partition_number = 0;
	struct extvtoc vtoc;
	dk_gpt_t *gpt;
	struct dk_minfo mi;
	int i, dos_cnt;
	fstyp_handle_t fstyp_handle;
	off_t probe_offset = 0;
	int num_volumes;
	char **volumes;
	dbus_uint64_t v_start;
	const char *fstype;
	nvlist_t *fsattr;

	fd = rfd = -1;

	ret = 1;

	if ((udi = getenv ("UDI")) == NULL) {
		goto out;
	}
	if ((device_file = getenv ("HAL_PROP_BLOCK_DEVICE")) == NULL) {
		goto out;
	}
	if ((raw_device_file = getenv ("HAL_PROP_BLOCK_SOLARIS_RAW_DEVICE")) == NULL) {
		goto out;
	}
	if (!dos_to_dev(raw_device_file, &rdevpath, &dos_num)) {
		rdevpath = raw_device_file;
	}
	if (!(is_dos = dos_to_dev(device_file, &devpath, &dos_num))) {
		devpath = device_file;
	}
	if ((parent_udi = getenv ("HAL_PROP_INFO_PARENT")) == NULL) {
		goto out;
	}
	if ((storage_device = getenv ("HAL_PROP_BLOCK_STORAGE_DEVICE")) == NULL) {
		goto out;
	}

	is_disc_str = getenv ("HAL_PROP_VOLUME_IS_DISC");
	if (is_disc_str != NULL && strcmp (is_disc_str, "true") == 0) {
		is_disc = TRUE;
	} else {
		is_disc = FALSE;
	}

	drop_privileges ();

	setup_logger ();

	dbus_error_init (&error);
	if ((ctx = libhal_ctx_init_direct (&error)) == NULL)
		goto out;

	HAL_DEBUG (("Doing probe-volume for %s\n", device_file));

	fd = open (devpath, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		goto out;
	}
	rfd = open (rdevpath, O_RDONLY | O_NONBLOCK);
	if (rfd < 0) {
		goto out;
	}

	/* if it's a floppy with no media, bail out */
	if (ioctl(rfd, FDGETCHANGE, &fdc) == 0) {
		is_floppy = TRUE;
		if (fdc & FDGC_CURRENT) {
			goto out;
		}
	}

	/* block size and total size */
	if (ioctl(rfd, DKIOCGMEDIAINFO, &mi) != -1) {
		block_size = mi.dki_lbsize;
		vol_size = mi.dki_capacity * block_size;
	} else if (errno == ENXIO) {
		/* driver supports ioctl, but media is not available */
		goto out;
	} else {
		/* driver does not support ioctl, e.g. lofi */
		block_size = 512;
		vol_size = 0;
	}
	libhal_device_set_property_int (ctx, udi, "volume.block_size", block_size, &error);
	my_dbus_error_free (&error);
	libhal_device_set_property_uint64 (ctx, udi, "volume.size", vol_size, &error);
	my_dbus_error_free (&error);

	if (is_disc) {
		if (!probe_disc (rfd, ctx, udi, &has_data, &has_audio)) {
			HAL_DEBUG (("probe_disc failed, skipping fstyp"));
			goto out;
		}
		/* with audio present, create volume even if fs probing fails */
		if (has_audio) {
			ret = 0;
		}
	}

	if (!has_data) {
		goto skip_fs;
	}

	/* don't support partitioned floppy */
	if (is_floppy) {
		goto skip_part;
	}

	/*
	 * first get partitioning info
	 */
	if (is_dos) {
		/* for a dos drive find partition offset */
		if (!find_dos_drive(fd, dos_num, block_size, &probe_offset)) {
			goto out;
		}
		partition_scheme = "mbr";
		partition_start = (dbus_uint64_t)probe_offset;
		partition_number = dos_num;
	} else {
		if ((partition_number = read_extvtoc(rfd, &vtoc)) >= 0) {
			if (!vtoc_one_slice_entire_disk(&vtoc)) {
				partition_scheme = "smi";
				if (partition_number < vtoc.v_nparts) {
					if (vtoc.v_part[partition_number].p_size == 0) {
						HAL_DEBUG (("zero size partition"));
					}
					partition_start = vtoc.v_part[partition_number].p_start * block_size;
				}
			}
		} else if ((partition_number = efi_alloc_and_read(rfd, &gpt)) >= 0) {
			partition_scheme = "gpt";
			if (partition_number < gpt->efi_nparts) {
				if (gpt->efi_parts[partition_number].p_size == 0) {
					HAL_DEBUG (("zero size partition"));
				}
				partition_start = gpt->efi_parts[partition_number].p_start * block_size;
			}
			efi_free(gpt);
		}
		probe_offset = 0;
	}

	if (partition_scheme != NULL) {
		libhal_device_set_property_string (ctx, udi, "volume.partition.scheme", partition_scheme, &error);
		my_dbus_error_free (&error);
		libhal_device_set_property_int (ctx, udi, "volume.partition.number", partition_number, &error);
		my_dbus_error_free (&error);
		libhal_device_set_property_uint64 (ctx, udi, "volume.partition.start", partition_start, &error);
		my_dbus_error_free (&error);
		libhal_device_set_property_bool (ctx, udi, "volume.is_partition", TRUE, &error);
		my_dbus_error_free (&error);
	} else {
		libhal_device_set_property_bool (ctx, udi, "volume.is_partition", FALSE, &error);
		my_dbus_error_free (&error);
	}

	/*
	 * ignore duplicate partitions
	 */
	if ((volumes = libhal_manager_find_device_string_match (
	    ctx, "block.storage_device", storage_device, &num_volumes, &error)) != NULL) {
		my_dbus_error_free (&error);
		for (i = 0; i < num_volumes; i++) {
			if (strcmp (udi, volumes[i]) == 0) {
				continue; /* skip self */
			}
			v_start = libhal_device_get_property_uint64 (ctx, volumes[i], "volume.partition.start", &error);
			if (dbus_error_is_set(&error)) {
				dbus_error_free(&error);
				continue;
			}
			if (v_start == partition_start) {
				HAL_DEBUG (("duplicate partition"));
				goto out;
			}
		}
		libhal_free_string_array (volumes);
	}

skip_part:

	/*
	 * now determine fs type
	 *
	 * XXX We could get better performance from block device,
	 * but for now we use raw device because:
	 *
	 * - fstyp_udfs has a bug that it only works on raw
	 *
	 * - sd has a bug that causes extremely slow reads
	 *   and incorrect probing of hybrid audio/data media
	 */
	if (fstyp_init(rfd, probe_offset, NULL, &fstyp_handle) != 0) {
		HAL_DEBUG (("fstyp_init failed"));
		goto out;
	}
	if ((fstyp_ident(fstyp_handle, NULL, &fstype) != 0) ||
	    (fstyp_get_attr(fstyp_handle, &fsattr) != 0)) {
		HAL_DEBUG (("fstyp ident or get_attr failed"));
		fstyp_fini(fstyp_handle);
		goto out;
	}
	set_fstyp_properties (ctx, udi, fstype, fsattr);

	if (strcmp (fstype, "hsfs") == 0) {
		hsfs_contents (fd, probe_offset, ctx, udi);
	}

	fstyp_fini(fstyp_handle);

skip_fs:

	ret = 0;

out:
	if (fd >= 0)
		close (fd);
	if (rfd >= 0)
		close (rfd);

	if (ctx != NULL) {
		my_dbus_error_free (&error);
		libhal_ctx_shutdown (ctx, &error);
		libhal_ctx_free (ctx);
	}

	return ret;

}
