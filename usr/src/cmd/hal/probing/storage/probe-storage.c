/***************************************************************************
 *
 * probe-storage.c : Probe for storage devices
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mnttab.h>
#include <sys/fdio.h>
#include <sys/scsi/scsi.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include <priv.h>

#include <libhal.h>
#include <cdutils.h>
#include <fsutils.h>
#include <logger.h>

/** Check if a filesystem on a special device file is mounted
 *
 *  @param  device_file         Special device file, e.g. /dev/cdrom
 *  @return                     TRUE iff there is a filesystem system mounted
 *                              on the special device file
 */
static dbus_bool_t
is_mounted (const char *device_file)
{
	FILE *f;
	dbus_bool_t rc = FALSE;
	struct mnttab mp;
	struct mnttab mpref;

	if ((f = fopen ("/etc/mnttab", "r")) == NULL)
		return rc;

	bzero(&mp, sizeof (mp));
	bzero(&mpref, sizeof (mpref));
	mpref.mnt_special = (char *)device_file;
	if (getmntany(f, &mp, &mpref) == 0) {
		rc = TRUE;
	}

	fclose (f);
	return rc;
}

static int
get_cdrom_properties_walker (void *arg, int profile, boolean_t is_current)
{
	LibHalChangeSet	*cs = (LibHalChangeSet *)arg;

	switch (profile) {
	case 0x09:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.cdr", TRUE);
		break;
	case 0x0a:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.cdrw", TRUE);
		break;
	case 0x10:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.dvd", TRUE);
		break;
	case 0x11:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdr", TRUE);
		break;
	case 0x12:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdram", TRUE);
		break;
	case 0x13:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdrw", TRUE);
		break;
	case 0x14:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdrw", TRUE);
		break;
	case 0x1a:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdplusrw", TRUE);
		break;
	case 0x1b:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdplusr", TRUE);
		break;
	case 0x2b:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdplusrdl", TRUE);
		break;
	case 0x40:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.bd", TRUE);
		break;
	case 0x41:
	case 0x42:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.bdr", TRUE);
		break;
	case 0x43:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.bdre", TRUE);
		break;
	case 0x50:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.hddvd", TRUE);
		break;
	case 0x51:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.hddvdr", TRUE);
		break;
	case 0x52:
		libhal_changeset_set_property_bool (cs, "storage.cdrom.hddvdrw", TRUE);
		break;
	}

	return CDUTIL_WALK_CONTINUE;
}

#define	WSPLEN	64

static void
get_cdrom_properties (int fd, LibHalChangeSet *cs)
{
	DBusError error;
	int capabilities;
	int read_speed, write_speed;
	intlist_t *write_speeds, *write_speeds_mem, *sp;
	int n_wspeeds;
	char **wspeeds;
	char *wspeeds_mem;
	int i;

	libhal_changeset_set_property_bool (cs, "storage.cdrom.cdr", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.cdrw", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.dvd", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdr", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdrw", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdram", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdplusr", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdplusrw", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.dvdplusrdl", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.bd", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.bdr", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.bdre", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.hddvd", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.hddvdr", FALSE);
	libhal_changeset_set_property_bool (cs, "storage.cdrom.hddvdrw", FALSE);

	walk_profiles(fd, get_cdrom_properties_walker, cs);

	/* XXX */
	libhal_changeset_set_property_bool (cs, "storage.cdrom.support_media_changed", TRUE);

	get_read_write_speeds(fd, &read_speed, &write_speed, &write_speeds, &n_wspeeds, &write_speeds_mem);

	libhal_changeset_set_property_int (cs, "storage.cdrom.read_speed", read_speed);
	libhal_changeset_set_property_int (cs, "storage.cdrom.write_speed", write_speed);

	if (n_wspeeds <= 0) {
		wspeeds_mem = NULL;
		libhal_changeset_set_property_strlist (cs, "storage.cdrom.write_speeds", (const char **)&wspeeds_mem);
		return;
	}
	if ((wspeeds = (char **)calloc(n_wspeeds + 1, sizeof (char *))) == NULL) {
		free (write_speeds_mem);
		return;
	}
	if ((wspeeds_mem = (char *)calloc(n_wspeeds, WSPLEN)) == NULL) {
		free (wspeeds);
		free (write_speeds_mem);
		return;
	}
	for (i = 0; i < n_wspeeds; i++) {
		wspeeds[i] = &wspeeds_mem[i * WSPLEN];
	}

	for (sp = write_speeds, i = 0; sp != NULL; sp = sp->next, i++) {
		snprintf (wspeeds[i], WSPLEN, "%d", sp->val);
	}
	libhal_changeset_set_property_strlist (cs, "storage.cdrom.write_speeds", (const char **)wspeeds);

	free (wspeeds);
	free (wspeeds_mem);
	free (write_speeds_mem);
}

/*
 * Return a copy of a string without trailing spaces. If 'len' is non-zero,
 * it specifies max length, otherwise the string must be null-terminated.
 */
char *
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
get_disk_properties (int fd, LibHalChangeSet *cs)
{
	struct scsi_inquiry inq;
	struct uscsi_cmd ucmd;
	union scsi_cdb  cdb;
	int		status;
	char		*s;

	/* INQUIRY */
	(void) memset((void *) &inq, 0, sizeof (inq));
	(void) memset((void *) &ucmd, 0, sizeof (ucmd));
	(void) memset((void *) &cdb, 0, sizeof (union scsi_cdb));
	cdb.scc_cmd = SCMD_INQUIRY;
	FORMG0COUNT(&cdb, sizeof (inq));
	ucmd.uscsi_cdb = (caddr_t) & cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t) & inq;
	ucmd.uscsi_buflen = sizeof (inq);
	ucmd.uscsi_timeout = 30;
	ucmd.uscsi_flags = USCSI_READ;
	status = ioctl(fd, USCSICMD, &ucmd);
	if (status || ucmd.uscsi_status) {
		return;
	}

	if ((s = rtrim_copy(inq.inq_vid, sizeof (inq.inq_vid))) != NULL) {
		libhal_changeset_set_property_string (cs, "storage.vendor", s);
		free(s);
	}
	if ((s = rtrim_copy(inq.inq_pid, sizeof (inq.inq_pid))) != NULL) {
		libhal_changeset_set_property_string (cs, "storage.model", s);
		free(s);
	}
	if ((s = rtrim_copy(inq.inq_revision, sizeof (inq.inq_revision))) != NULL) {
		libhal_changeset_set_property_string (cs, "storage.firmware_revision", s);
		free(s);
	}
	if ((s = rtrim_copy(inq.inq_serial, sizeof (inq.inq_serial))) != NULL) {
		libhal_changeset_set_property_string (cs, "storage.serial", s);
		free(s);
	}
}

/*
 * returns TRUE if diskette is inserted.
 * also returns write protection status.
 */
static dbus_bool_t
check_floppy(int fd, dbus_bool_t *wprot)
{
	int	chg;

	if ((ioctl(fd, FDGETCHANGE, &chg) == 0) && !(chg & FDGC_CURRENT)) {
		*wprot = ((chg & FDGC_CURWPROT) != 0);
		return (TRUE);
	} else {
		return (FALSE);
	}
}

void
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
	int ret = 1;
	int fd = -1;
	int rfd = -1;
	char *udi;
	char *device_file;
	char *raw_device_file;
	LibHalContext *ctx = NULL;
	DBusError error;
	char *drive_type;
	dbus_bool_t is_cdrom;
	dbus_bool_t is_floppy;
	struct dk_minfo minfo;
	int rdonly;
	unsigned int block_size = 512;
	dbus_bool_t only_check_for_media;
	int got_media = FALSE;
	dbus_bool_t is_write_protected = FALSE;
	dbus_bool_t is_mbr = FALSE;
	dbus_bool_t is_smi = FALSE;
	dbus_bool_t is_gpt = FALSE;
	dbus_bool_t is_partitioned = FALSE;
	dbus_bool_t vtoc_slices = FALSE;
	int dos_cnt = 0;
	const char *scheme = "";
	struct extvtoc vtoc;
	dk_gpt_t *gpt;
	LibHalChangeSet *cs = NULL;

	if ((udi = getenv ("UDI")) == NULL)
		goto out;
	if ((device_file = getenv ("HAL_PROP_BLOCK_DEVICE")) == NULL)
		goto out;
	if ((raw_device_file = getenv ("HAL_PROP_BLOCK_SOLARIS_RAW_DEVICE")) == NULL)
		goto out;
	if ((drive_type = getenv ("HAL_PROP_STORAGE_DRIVE_TYPE")) == NULL)
		goto out;

	drop_privileges ();

	setup_logger ();

	if (argc == 2 && strcmp (argv[1], "--only-check-for-media") == 0)
		only_check_for_media = TRUE;
	else
		only_check_for_media = FALSE;

	is_cdrom = (strcmp (drive_type, "cdrom") == 0);
	is_floppy = (strcmp (drive_type, "floppy") == 0);

	dbus_error_init (&error);
	if ((ctx = libhal_ctx_init_direct (&error)) == NULL)
		goto out;

	if ((cs = libhal_device_new_changeset (udi)) == NULL) {
		HAL_DEBUG (("Cannot allocate changeset"));
		goto out;
	}

	HAL_DEBUG (("Doing probe-storage for %s (drive_type %s) (udi=%s) (--only-check-for-media==%d)",
	     device_file, drive_type, udi, only_check_for_media));

	if ((rfd = open (raw_device_file, O_RDONLY | O_NONBLOCK)) < 0) {
		HAL_DEBUG (("Cannot open %s: %s", raw_device_file, strerror (errno)));
		goto out;
	}

	if (!only_check_for_media) {
		if (strcmp (drive_type, "cdrom") == 0) {
			get_cdrom_properties (rfd, cs);
		} else if (strcmp (drive_type, "disk") == 0) {
			get_disk_properties (rfd, cs);
		}
	}

	ret = 0;

	if (is_cdrom) {
		HAL_DEBUG (("Checking for optical disc on %s", raw_device_file));
		got_media = get_media_info(rfd, &minfo);
		if (!got_media) {
			goto out_cs;
		}
		block_size = minfo.dki_lbsize;
		/* XXX */
		is_write_protected = TRUE;
	} else if (is_floppy) {
		HAL_DEBUG (("Checking for floppy on %s", raw_device_file));
		if (check_floppy(rfd, &is_write_protected)) {
			got_media = TRUE;
		}
		/* don't look for partitions on floppy */
		goto out_cs;
	} else {
		got_media = get_media_info(rfd, &minfo);
		if (!got_media) {
			goto out_cs;
		}
		block_size = minfo.dki_lbsize;
		if ((ioctl(rfd, DKIOCREADONLY, &rdonly) == 0) && rdonly) {
			is_write_protected = TRUE;
		}
	}

	HAL_DEBUG (("Checking for partitions on %s", device_file));

	if ((fd = open (device_file, O_RDONLY | O_NONBLOCK)) < 0) {
		HAL_DEBUG (("Cannot open %s: %s", device_file, strerror (errno)));
		goto out_cs;
	}

	dos_cnt = get_num_dos_drives(fd, block_size);
	is_mbr = (dos_cnt > 0);
	if (is_mbr) {
		scheme = "mbr";
	}
	if (read_extvtoc(rfd, &vtoc) >= 0) {
		if (!vtoc_one_slice_entire_disk(&vtoc)) {
			is_smi = TRUE;
			if (!is_mbr) {
				/* smi within mbr partition is okay */
				scheme = "smi";
			}
			vtoc_slices = TRUE;
		}
	} else if (!is_cdrom && (efi_alloc_and_read(rfd, &gpt) >= 0)) {
		/*
		 * Note: for some reason efi_read takes very long on cdroms.
		 * Needs more investigation, skip gpt on cdrom for now.
		 */
		is_gpt = TRUE;
		scheme = "gpt";
		efi_free(gpt);
	}

out_cs:
	is_partitioned = is_mbr || is_smi || is_gpt;
	libhal_changeset_set_property_bool (cs, "storage.no_partitions_hint", !is_partitioned);
	libhal_changeset_set_property_bool (cs, "block.no_partitions", !is_partitioned);
	libhal_changeset_set_property_string (cs, "storage.partitioning_scheme", scheme);
	libhal_changeset_set_property_bool (cs, "storage.solaris.vtoc_slices", vtoc_slices);
	libhal_changeset_set_property_int (cs, "storage.solaris.num_dos_partitions", dos_cnt);
	/* XXX should only set for removable drives */
	libhal_changeset_set_property_bool (cs, "storage.removable.media_available", got_media);
	libhal_changeset_set_property_bool (cs, "storage.removable.solaris.read_only", is_write_protected);

	libhal_device_commit_changeset (ctx, cs, &error);

out:
	if (cs != NULL) {
		libhal_device_free_changeset (cs);
	}
	if (fd >= 0) {
		close (fd);
	}
	if (rfd >= 0) {
		close (rfd);
	}
	if (ctx != NULL) {
		if (dbus_error_is_set(&error)) {
			dbus_error_free (&error);
		}
		libhal_ctx_shutdown (ctx, &error);
		libhal_ctx_free (ctx);
	}

	return ret;
}
