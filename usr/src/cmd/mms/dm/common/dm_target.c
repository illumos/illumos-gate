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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <limits.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/file.h>
#include <pthread.h>
#include <synch.h>
#include <ctype.h>
#include <signal.h>
#include <pwd.h>
#include <auth_attr.h>
#include <secdb.h>
#include <ucred.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>
#include <dirent.h>
#include <errno.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <dmd_impl.h>
#include <dm_impl.h>
#include <dm_drive.h>
#include <mms_sym.h>
#include <dm_msg.h>
#include <mms_trace.h>
#include <mms_dmd.h>
#include <dm_proto.h>
#include <mms_strapp.h>



static	char *_SrcFile = __FILE__;


/*
 * Minor device number of the ST driver.
 *
 * Change device to bn device - turn BSD and norewind bits
 *
 * The minor device byte structure is (from mtio(7I)):
 *
 * 15-7     6          5          4         3          2       1   0
 * ___________________________________________________________________
 * Unit #  BSD	Reserved   Density   Density   No rewind    Unit #
 *         behavior		Select    Select    on Close    Bits 0-1
 *
 */

minor_t
dm_get_targ(minor_t minor)
{
	minor &= ~0x18;			/* turn off density select */
	minor |= 0x44;			/* BSD, norewind */

	return (minor);
}

minor_t
dm_hdl_minor(void)
{
	minor_t		minor = 0;

	minor = (((wka->dm_counter % 255) + 1) << 8) | wka->dm_drm_minor;
	return (minor);
}

int
dm_get_target_base(void)
{
	if (drv->drv_serial_num[0] == '\0') {
		/*
		 * Serial number unknown. Have to use specified path
		 */
		return (dm_get_target_pathname());
	} else {
		/*
		 * Have serial number, look in /dev/rmt (tape devices)
		 * for device matching serial number.
		 */
		return (dm_get_target_by_serial_num());
	}
}

int
dm_get_target_pathname(void)
{
	char		*show_cmd;
	char		*task;
	mms_par_node_t	*root;
	dm_command_t	*cmd;
	char		*val;

	TRACE((MMS_DEVP, "Getting target base"));
	task = dm_bld_task("show-target-base");
	show_cmd = mms_strapp(NULL,
	    "show task['%s'] reportmode[namevalue] "
	    "match[streq(DM.'DMName' '%s')] "
	    "report[ DM.'DMTargetPath']" ";", task, DMNAME);
	cmd = dm_send_cmd(show_cmd, dm_cmd_response, task);
	free(show_cmd);
	free(task);
	if (cmd == NULL || cmd->cmd_rc != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to get DM.'DMTargetPath'"));
		if (cmd) {
			dm_destroy_cmd(cmd);
		}
		return (-1);
	}
	root = cmd->cmd_root;
	/*
	 * Save tape path
	 */
	val = dm_get_attr_value(root, "DM", "DMTargetPath");
	if (val == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "No TargetPath"));
		dm_destroy_cmd(cmd);
		return (-1);
	}
	if (dm_verify_target_dev(val) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "invalid device pathname \"%s\"", val));
		dm_destroy_cmd(cmd);
		return (-1);
	}
	wka->dm_target_base = strdup(val);
	TRACE((MMS_OPER, "dm_get_target_base: Target base is %s",
	    wka->dm_target_base));
	dm_destroy_cmd(cmd);
	return (0);
}

int
dm_get_target_by_serial_num(void)
{
	char	**dirtab;
	int	i;
	int	rc = -1;

	/*
	 * Search in the default dir
	 */
	if (dm_probe_dir(drv->drv_dev_dir) == 0) {
		/* Found it */
		return (0);
	}

	/*
	 * Build a dir table from *.so
	 */
	dirtab = dm_bld_dir_tab();
	if (dirtab == NULL) {
		return (-1);
	}

	/*
	 * Search each entry in dir table
	 */
	rc = -1;				/* assume not found */
	for (i = 0; dirtab[i] != NULL; i++) {
		if (dm_probe_dir(dirtab[i]) == 0) {
			/* Found it */
			rc = 0;
			break;
		}
	}

	/*
	 * Can't find a device that matches the serial number
	 */
	for (i = 0; dirtab[i] != NULL; i++) {
		free(dirtab[i]);
	}
	free(dirtab);

	return (rc);
}

int
dm_probe_dir(char *dirname)
{
	DIR	*dir;
	struct	dirent	*dirent;
	int	len;
	char	sernum[MMS_SER_NUM_LEN + 1];
	int	fd;
	int	rc = -1;
	struct	ent	{
		ino_t	ino;
		char	*name;
	};
	struct	ent	ptab[64];
	int	nument = 0;
	int	probe = 1;
	drm_probe_dev_t	dev;
	int	i;
	int	err;
	int	zero = 0;


	if ((dir = opendir(dirname)) == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to open directory %s: %s",
		    dirname, strerror(errno)));
		return (-1);
	}

	while ((dirent = readdir(dir)) != NULL) {
		/*
		 * Read the serial number of this device
		 */
		len = strlen(dirent->d_name);
		if (strcmp(dirname, DRV_TAPE_DIR) == 0) {
			if (len < 2) {
				/* Device name must be >= 2 chars */
				continue;
			}
			/* If tape device, look at only norewind devices */
			if (dirent->d_name[len - 1] != 'n' ||
			    !isdigit(dirent->d_name[len - 2])) {
				continue;
			}
		}
		ptab[nument].name = mms_strapp(NULL,
		    "%s/%s", dirname, dirent->d_name);
		ptab[nument].ino = dirent->d_ino;
		nument++;
	}
	closedir(dir);

	while (probe) {
		/*
		 * Continue to probe until all devices are probed.
		 */
		probe = 0;
		for (i = 0; i < nument; i++) {
			/*
			 * Set the ino in dmd. If EBUSY, then skip for now
			 */
			if (ptab[i].name == NULL) {
				/* Already checked */
				continue;
			}

			/*
			 * Tell DMD probing this device
			 */
			dev.drm_dev = 0;
			ioctl(drv->drv_fd, DRM_PROBE_DEV, &dev);
			dev.drm_dev = ptab[i].ino;
			if (ioctl(drv->drv_fd, DRM_PROBE_DEV, &dev) < 0) {
				err = errno;
				if (err == EBUSY) {
					TRACE((MMS_DEBUG, "Busy: %s",
					    ptab[i].name));
					continue;
				}
				DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
				    "unable to probe device: %s",
				    strerror(err)));
				errno = err;
				rc = -1;
				goto done;
			}

			/*
			 * Check serial number of this device
			 */
			probe = 1;
			do {
				TRACE((MMS_DEBUG, "Looking at: %s",
				    ptab[i].name));
				fd = open(ptab[i].name, O_NDELAY | O_RDWR);
				if (fd < 0) {
					/*
					 * If can't open this device,
					 * then skip it
					 */
					TRACE((MMS_DEBUG, "probe open error: "
					    "%s: %s",
					    ptab[i].name, strerror(errno)));
					break;
				}

				/* Read the serial number */
				drv->drv_fd = fd;
						/* drv_*() uses drv->drv_fd */
				if (DRV_CALL(drv_get_serial_num,
				    (sernum)) != 0) {
					TRACE((MMS_DEBUG, "probe get "
					    "serial num  error: %s: %s",
					    ptab[i].name, strerror(errno)));
					close(fd);
					drv->drv_fd = wka->dm_drm_fd;
					/* restoredrv->drv_fd */
					break;
				}
				close(fd);
				drv->drv_fd = wka->dm_drm_fd;
				/* restoredrv->drv_fd */

				TRACE((MMS_DEBUG, "path %s, serial num %s",
				    ptab[i].name, sernum));

				/*
				 * Compare serial numbers
				 */
				if (strcmp(sernum, drv->drv_serial_num) == 0) {
					/* Found device matching serial num */
					wka->dm_target_base =
					    strdup(ptab[i].name);
					/* Drop the "n" from pathname */
					wka->dm_target_base[
					    strlen(wka->dm_target_base) - 1] =
					    '\0';
					TRACE((MMS_OPER, "dm_probe_dir: "
					    "Target base is %s",
					    wka->dm_target_base));
					rc = 0;
					probe = 0;	/* probe done */
				}
			} while (zero);

			free(ptab[i].name);
			ptab[i].name = NULL;
			/*
			 * Unlock this dev
			 */
			dev.drm_dev = 0;
			ioctl(drv->drv_fd, DRM_PROBE_DEV, &dev);

			if (probe == 0) {
				break;
			}
		}
		if (nument == i) {
			DM_MSG_PREPEND(("dm_probe_dir: "
			    "cannot find a matching drive "
			    "with serial num %s in \"%s\": ",
			    drv->drv_serial_num, dirname));
		}
	}

done:
	for (i = 0; i < nument; i++) {
		if (ptab[i].name != NULL) {
			free(ptab[i].name);
		}
	}

	return (rc);
}

char **
dm_bld_dir_tab(void)
{
	char		**dirtab;
	char		**newtab;
	int		taboff = 0;
	int		size = DRV_DIR_TAB_SIZE;
	char		*libpath;
	char		*libname;
	int		len;
	void		*dlhdl;
	char		*devdir;
	DIR		*dir;
	dirent_t	*dirent;
	int		i;

	dirtab = (char **)malloc(size * sizeof (char *));
	if (dirtab == NULL) {
		DM_MSG_ADD((MMS_EXIST, MMS_DM_E_INTERNAL,
		    "out of memory"));
		return (NULL);
	}
	memset(dirtab, 0, size);

	dir = opendir(DM_DEV_LIB_DIR);
	if (dir == NULL) {
		DM_MSG_ADD((MMS_EXIST, MMS_DM_E_INTERNAL,
		    "unable to open %s", DM_DEV_LIB_DIR));
		free(dirtab);
		return (NULL);
	}

	while (dirent = readdir(dir)) {
		libname = dirent->d_name;
		len = strlen(libname);
		if (strncmp(libname, "lib", 3) ||
		    strncmp(libname + len - 3, ".so", 3)) {
			/* Not lib*.so */
			continue;
		}

		TRACE((MMS_DEBUG, "looking at lib %s", libname));
		libpath = mms_strapp(NULL,
		    "%s/%s", DM_DEV_LIB_DIR, libname);
		dlhdl = dlopen(libpath, RTLD_LAZY);
		if (dlhdl == NULL) {
			DM_MSG_ADD((MMS_EXIST, MMS_DM_E_INTERNAL,
			    "unable to open %s", libpath));
			free(libpath);
			continue;
		}
		free(libpath);

		devdir = dlsym(dlhdl, "drv_dev_dir");
		if (devdir != NULL) {
			if (devdir[0] == '\0') {
				/* dev dir not specified */
				dlclose(dlhdl);
				continue;
			}

			if (strcmp(devdir, DRV_TAPE_DIR) == 0) {
				/* Already probed DRV_TAPE_DIR */
				dlclose(dlhdl);
				continue;
			}

			/*
			 * Add to dirtab if not in it already
			 */
			for (i = 0; i < taboff && dirtab[i] != NULL; i++) {
				if (strcmp(devdir, dirtab[i]) == 0) {
					/* dir name already in dirtab */
					dlclose(dlhdl);
					continue;
				}
			}
			/* Not in table yet */
			TRACE((MMS_DEBUG, "adding to dirtab: %s", devdir));
			dirtab[taboff] = strdup(devdir);
			taboff++;
			if (taboff == size) {
				size += DRV_DIR_TAB_SIZE;
				newtab = (char **)
				    realloc(dirtab, size * sizeof (char *));
				if (newtab == NULL) {
					DM_MSG_ADD((MMS_EXIST,
					    MMS_DM_E_INTERNAL,
					    "out of memory"));
					return (NULL);
				}
				dirtab = newtab;
			}

		}
	}

	/*
	 * Done
	 */
	return (dirtab);
}

/*
 * Verify target device name
 */
int
dm_verify_target_dev(char *devname)
{
	int		i;

	if (devname[0] == '\0') {
		return (-1);
	}

	if (strncmp(devname, DRV_TAPE_DIR "/", 9) != 0) {
		/* If not a tape dev, ignore */
		return (0);
	}

	if (!isdigit(devname[9])) {
		return (-1);
	}

	/*
	 * strip device attribute from devname
	 */

	for (i = 9; devname[i] != '\0'; i++) {
		if (!isdigit(devname[i])) {
			devname[i] = '\0';
			return (0);
		}
	}
	return (0);
}

int
dm_stat_targ_base(void)
{
	struct		stat buf;
	int		fd;

	if (wka->dm_target_base == NULL || wka->dm_target_base[0] == '\0') {
		DM_MSG_ADD((MMS_EXIST, MMS_DM_E_INTERNAL,
		    "target base device not available"));
		return (-1);
	}

	if ((fd = open(wka->dm_target_base, O_RDWR | O_NDELAY)) < 0 ||
	    fstat(fd, &buf)) {
		DM_MSG_ADD((MMS_EXIST, MMS_DM_E_INTERNAL,
		    "stat '%s' error: %s",
		    wka->dm_target_base, strerror(errno)));
		if (fd >= 0) {
			close(fd);
		}
		return (-1);
	}

	wka->dm_targ_base_major = major(buf.st_rdev);
	wka->dm_targ_base_minor = minor(buf.st_rdev);
	TRACE((MMS_DEVP, "dm_stat_targ_base: %s - (%d:%d)",
	    wka->dm_target_base, wka->dm_targ_base_major,
	    wka->dm_targ_base_minor));
	close(fd);
	return (0);
}

int
dm_reserve_target(void)
{
	int		rc = 0;

	if (wka->dm_flags & DM_USE_PRSV) {
		for (;;) {
			rc = dm_reserve_target_prsv();
			if (rc == 0) {	/* drive reserved */
				break;
			} else if (rc > 0) {
				/* error other than reservation conflict */
				DM_MSG_ADD_HEAD((MMS_INTERNAL,
				    MMS_DM_E_INTERNAL,
				    "unable to reserve drive: "
				    "I/O error"));
				return (-1);
			}
			/*
			 * If already have MMS reservation, just preempt it.
			 * Otherwise see if we have to ask.
			 */
			rc = DM_REP_YES;	/* assume preempt */
			if (!dm_have_mms_rsv()) {	/* no mms rsv */
				if (wka->dm_flags & DM_ASK_PREEMPT_RSV) {
					rc = dm_ask_preempt();
				}
				if (rc == DM_REP_ERROR) {
					/* Ask got an error, assume "no" */
					rc = DM_REP_NO;
				}
				if (rc == DM_REP_NO) {
					DM_MSG_ADD_HEAD((MMS_INTERNAL,
					    MMS_DM_E_INTERNAL,
					    "drive reservation "
					    "denied by operator"));
					return (-1);
				} else if (rc == DM_REP_RETRY) {
					sleep(1);
					continue;
				}
			}
			if (rc == DM_REP_YES) {
				TRACE((MMS_DEBUG, "Preempting reservation"));
				if (dm_preempt_rsv()) {
					return (-1);
				}
				rc = 0;
				break;
			}


		}
	} else {
		rc = dm_reserve_target_rsv();
	}

	TRACE((MMS_DEBUG, "Drive reserved successfully"));

	return (rc);
}


int
dm_reserve_target_prsv(void)
{
	int		status = 0;
	uint64_t	key;

	TRACE((MMS_DEVP, "dm_reserve_target_prsv: Using PRSV"));

	/*
	 * Register key
	 */

	if (DRV_CALL(drv_prsv_register, ())) {
		status = serr->se_dsreg;
		char_to_uint64((uchar_t *)DRV_PRSV_KEY, 8, &key);
		TRACE((MMS_DEVP, "Can't register PRSV "
		    "reservation key: \"%16.16llx\": %s",
		    key, mms_scsi_status(status)));
		if (status == STATUS_RESERVATION_CONFLICT) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "unable to register key, "
			    "reservation conflict"));
			return (-1);
		} else {
			/* other error */
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "registration error: %s", strerror(errno)));
			return (EIO);
		}
	}

	/*
	 * Do an exclusive persistent reservation
	 */
	if (DRV_CALL(drv_prsv_reserve, ()) != 0) {
		status = serr->se_dsreg;
		TRACE((MMS_ERR, "Unable to reserve drive"));
		if (status == STATUS_RESERVATION_CONFLICT) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "unable to reserve drive: "
			    "reservation conflict"));
			return (-1);
		} else {
			/* other error */
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "reservation error: %s", strerror(errno)));
			return (EIO);
		}
	}

	/*
	 * Now, get rid of all the attentions
	 */
	TRACE((MMS_DEVP, "dm_reserve_target_prsv: Clear attentions"));
	while (DRV_CALL(drv_tur, ()) != 0 &&
	    serr->se_senkey == KEY_UNIT_ATTENTION) {
		;
	}

	TRACE((MMS_DEVP, "dm_reserve_target_prsv: Drive %s reserved",
	    DRVNAME));

	return (0);
}

int
dm_reserve_target_rsv(void)
{
	int		rc = 0;

	/*
	 * Since the target is opened (via ldi_open()) with O_NDELAY,
	 * the st drive will not do reserve/release on open/close.
	 * until an I/O is done. A TUR will be done after binding
	 * the target. This causes the st driver to reserve the drive.
	 */
	while (DRV_CALL(drv_tur, ()) != 0 && errno == EACCES) {
		TRACE((MMS_INFO, "TUR error: %s", strerror(errno)));
		/*
		 * Drive is reserved, find out if it is assigned to
		 * another DM
		 */
		if (dm_drv_assigned() != 0) {
			/*
			 * No, not assigned. This means that the drive
			 * is being used by a non MMS client.
			 */
			if ((wka->dm_flags & DM_PREEMPT_RSV) == 0) {
				/* Do not preempt */
				return (-1);
			}

			rc = DM_REP_YES;	/* assume freserve */
			if (wka->dm_flags & DM_ASK_PREEMPT_RSV) {
				rc = dm_ask_freserve();
			}
			if (rc == DM_REP_ERROR) {
				/* Ask got an error, assume "no" */
				rc = DM_REP_NO;
			}
			if (rc == DM_REP_YES) {
				TRACE((MMS_DEBUG, "Doing forcereserve"));
				if (ioctl(wka->dm_drm_fd, MTIOCFORCERESERVE)) {
					return (-1);
				}
			} else if (rc == DM_REP_NO) {
				return (-1);
			} else if (rc == DM_REP_RETRY) {
				continue;
			}
		} else {
			/*
			 * If drive is assigned to another DM, then
			 * silently wait for it to be unassigned.
			 */
			TRACE((MMS_ERR, "Drive %s is reserved by "
			    "another DM. "
			    "Will keep trying reserve until "
			    "successful", wka->dm_target_base));
		}
	}

	/*
	 * Release the reservation made by the ST driver and tell it
	 * not to do reserve/release at open/close.
	 * Then do my own reservations
	 */
	ioctl(drv->drv_fd, MTIOCRESERVE);
	DRV_CALL(drv_release, ());
	if (DRV_CALL(drv_reserve, ()) != 0) {
		ioctl(drv->drv_fd, MTIOCRELEASE);
		return (-1);
	}
	drv->drv_flags |= DRV_RESERVED;
	return (0);
}

int
dm_release_target(void)
{
	if ((wka->dm_flags & DM_USE_PRSV) == 0) {
		/* Using reserve/release */
		DRV_CALL(drv_release, ());
		return (0);
	}

	/*
	 * Using persistent reserve out
	 */
	DRV_CALL(drv_prsv_register, ());
	DRV_CALL(drv_prsv_release, ());
	return (0);
}

int
dm_force_release(void)
{
	if (ioctl(wka->dm_drm_fd, MTIOCFORCERESERVE)) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Can't do FORCERESERVE: %s", strerror(errno)));
		return (-1);
	}
	TRACE((MMS_DEBUG, "FORCERESERVE successful"));

	if (DRV_CALL(drv_release, ()) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "release error: %s", strerror(errno)));
		return (-1);
	}
	TRACE((MMS_DEBUG, "RELEASE successful"));

	return (0);
}

int
dm_preempt_rsv(void)
{
	char		buf[24];
	uint32_t	num;

	if (DRV_CALL(drv_prsv_register, ()) != 0 ||
	    DRV_CALL(drv_prsv_read_rsv, (buf, sizeof (buf))) != 0) {
		if (serr->se_dsreg == STATUS_RESERVATION_CONFLICT) {
			/* Try force reserve and release */
			if (dm_force_release() != 0) {
				/* Can't force release */
				return (-1);
			}
			if (DRV_CALL(drv_prsv_register, ()) != 0 ||
			    DRV_CALL(drv_prsv_reserve, ())) {
				DM_MSG_ADD_HEAD((MMS_INTERNAL,
				    MMS_DM_E_INTERNAL,
				    "persistent reservation " "error"));
				return (-1);
			}
			return (0);
		} else {
			/* Other error */
			DM_MSG_ADD_HEAD((MMS_INTERNAL,
			    MMS_DM_E_INTERNAL,
			    "reservation error", strerror(errno)));
			return (-1);
		}
	}

	char_to_uint32((uchar_t *)buf + 4, 4, &num);
	if (num == 0) {			/* no reservation */
		if (DRV_CALL(drv_prsv_register, ()) != 0 ||
		    DRV_CALL(drv_prsv_reserve, ()) != 0) {
			DM_MSG_ADD_HEAD((MMS_INTERNAL,
			    MMS_DM_E_INTERNAL,
			    "persistent reservation " "error"));
			return (-1);
		}
	} else {
		/* Preempt the current reservation */
		if (DRV_CALL(drv_prsv_preempt, (buf + 8)) != 0) {
			DM_MSG_ADD_HEAD((MMS_INTERNAL,
			    MMS_DM_E_INTERNAL,
			    "persistent reservation preempt" "error"));
			return (-1);
		}
	}

	return (0);
}

int
dm_have_mms_rsv(void)
{
	char		buf[24];
	uint32_t	num;

	if (DRV_CALL(drv_prsv_register, ()) != 0 ||
	    DRV_CALL(drv_prsv_read_rsv, (buf, sizeof (buf))) != 0) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "unable to read reservation"));
		/* Can't read reservation */
		return (0);
	}

	char_to_uint32((uchar_t *)buf + 4, 4, &num);
	if (num == 0) {			/* no reservation */
		return (0);
	}

	if (memcmp(buf + 8, DRV_PRSV_KEY_PFX, 4) != 0) {
		return (0);
	}

	/*
	 * Have MMS reservation
	 */
	return (1);
}

int
dm_rebind_target(void)
{
	drm_target_t	targ;

	wka->dm_targ_base_minor = dm_get_targ(wka->dm_targ_base_minor);
	memset(&targ, 0, sizeof (targ));
	targ.drm_targ_oflags |= FREAD | FWRITE | FNDELAY;
	targ.drm_targ_major = wka->dm_targ_base_major;
	targ.drm_targ_minor = wka->dm_targ_base_minor;
	if (ioctl(wka->dm_drm_fd, DRM_REBIND_DEV, &targ)) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "Rebind base device error: %s",
		    strerror(errno)));
		return (-1);
	}
	TRACE((MMS_DEBUG, "Target rebound to (%d:%d)",
	    wka->dm_targ_base_major, wka->dm_targ_base_minor));
	return (0);
}

int
dm_open_dm_device(void)
{
	int	fd;

	/*
	 * Open the drive manager device
	 */
	fd = open(wka->dm_drm_path, O_RDWR | O_NDELAY);
	if (fd < 0) {
		DM_MSG_ADD((MMS_EXIST, MMS_DM_E_INTERNAL,
		    "open '%s' error: %s",
		    wka->dm_drm_path, strerror(errno)));
		return (-1);
	}
	wka->dm_drm_fd = fd;
	drv->drv_fd = fd;

	return (0);
}

int
dm_bind_target(void)
{
	struct		stat statbuf;

	/*
	 * Get the major and minor of the DRM device
	 */
	fstat(wka->dm_drm_fd, &statbuf);
	wka->dm_drm_major = major(statbuf.st_rdev);
	wka->dm_drm_minor = minor(statbuf.st_rdev);

	/*
	 * Bind the drive manager to the target device.
	 * Since the target is opened (via ldi_open()) with O_NDELAY,
	 * the st drive will not do reserve/release on open/close.
	 * until an I/O is done. A TUR will be done after binding
	 * the target. This causes the st driver to reserve the drive.
	 */
	if (dm_bind_target_base() != 0) {
		return (-1);
	}

	return (0);
}

/*
 * Bind manager drive to target
 */
int
dm_bind_target_base(void)
{
	drm_target_t	targ;
	int		err;
	uint32_t	buf;
	char		pid[20];

	targ.drm_targ_major = wka->dm_targ_base_major;
	targ.drm_targ_minor = wka->dm_targ_base_minor;

	targ.drm_targ_oflags = FWRITE | FNDELAY;

	pthread_mutex_lock(&wka->dm_tdv_close_mutex);
	while (ioctl(wka->dm_drm_fd, DRM_BIND_DEV, &targ)) {
		err = errno;
		if (err == EMFILE) {
			/* drive is still opened. wait for close */
			ioctl(wka->dm_drm_fd, DRM_TDV_PID, &buf);
			snprintf(pid, sizeof (pid), "%d", buf);
			TRACE((MMS_DEBUG,
			    "Waiting for App to close target device, pid %s",
			    pid));
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "waiting for close"));
			DM_MSG_SEND((DM_ADM_ERR, DM_6521_MSG,
			    "drive", drv->drv_drvname, "pid", pid, NULL));
			pthread_cond_wait(&wka->dm_tdv_close_cv,
			    &wka->dm_tdv_close_mutex);
			TRACE((MMS_DEBUG, "Waken up by tdv close"));
		} else {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "unable to bind target device: %s", strerror(err)));
			pthread_mutex_unlock(&wka->dm_tdv_close_mutex);
			return (-1);
		}
	}
	pthread_mutex_unlock(&wka->dm_tdv_close_mutex);
	TRACE((MMS_OPER, "Device %s (%lld, %lld) bound to %s",
	    wka->dm_target_base, targ.drm_targ_major, targ.drm_targ_minor,
	    wka->dm_drm_path));

	return (0);
}

int
dm_bind_raw_dev(int oflag)
{
	int		err;
	char		*path;
	char		*den = "";
	char		*bsd = "";
	char		*rew = "";
	struct		stat statbuf;
	drm_target_t	targ;

	if (mnt->mnt_flags & MNT_LOW) {
		den = "l";
	} else if (mnt->mnt_flags & MNT_MEDIUM) {
		den = "m";
	} else if (mnt->mnt_flags & MNT_HIGH) {
		den = "h";
	} else if (mnt->mnt_flags & (MNT_ULTRA | MNT_COMPRESSION)) {
		den = "c";
	}
	if (mnt->mnt_flags & (MNT_MMS | MNT_MMS_TM | MNT_BSD)) {
		/* MMS mode always use "b" */
		bsd = "b";
	}
	if (mnt->mnt_flags & (MNT_MMS | MNT_NOREWIND)) {
		/* MMS mode always use "n" */
		rew = "n";
	}

	path = mms_strapp(NULL,
	    "%s%s%s%s", wka->dm_target_base, den, bsd, rew);
	TRACE((MMS_DEBUG, "Device path chosen = %s", path));

	if (stat(path, &statbuf) != 0) {
		err = errno;
		TRACE((MMS_ERR, "Can't stat %s: %s", path, strerror(err)));
		return (err);
	}
	free(path);
	targ.drm_targ_oflags = oflag;
	targ.drm_targ_major = major(statbuf.st_rdev);
	targ.drm_targ_minor = minor(statbuf.st_rdev);
	if (ioctl(wka->dm_drm_fd, DRM_REBIND_DEV, &targ)) {
		err = errno;
		TRACE((MMS_ERR, "Rebind raw device error: %s",
		    strerror(err)));
		return (err);
	}

	dm_clear_dev();

	return (0);
}

void
dm_init_sense_buf(void)
{
	struct	scsi_extended_sense	*es;

	if (DRV_CALL(drv_req_sense, (sizeof (struct scsi_extended_sense)))) {
		/* Can't read sense data */
		drv->drv_mtee_stat_len = sizeof (struct scsi_extended_sense);
		TRACE((MMS_DEBUG, "drv_req_sense error: Sense buf size set "
		    "to %d", sizeof (struct scsi_extended_sense)));
		return;
	}
	es = (struct scsi_extended_sense *)drv->drv_iobuf;
	drv->drv_num_sen_bytes =
	    es->es_add_len + ((char *)&es->es_add_len - (char *)es) + 1;
	drv->drv_mtee_stat_len =
	    sizeof (struct scsi_arq_status) -
	    sizeof (struct scsi_extended_sense) + drv->drv_num_sen_bytes;
	if (drv->drv_mtee_stat_len < sizeof (struct scsi_arq_status)) {
		drv->drv_mtee_stat_len = sizeof (struct scsi_arq_status);
	}
	if (drv->drv_mtee_stat_len > DRV_SENSE_LEN) {
		drv->drv_mtee_stat_len = DRV_SENSE_LEN;
	}
	TRACE((MMS_DEBUG, "add sense length = %d, num of sen bytes = %d",
	    es->es_add_len, drv->drv_num_sen_bytes));
	TRACE((MMS_DEBUG, "Sense buf size set = %d", drv->drv_mtee_stat_len));
}

char *
dm_get_user(pid_t pid)
{
	/*
	 * Given the pid, return the user login name
	 */
	struct	passwd	pwd;
	struct	passwd	*pwent;
	ucred_t		*ucred;
	uid_t		uid;

	ucred = ucred_get(pid);
	uid = ucred_getruid(ucred);

	setpwent();
	pwent = getpwuid_r(uid, &pwd, wka->dm_pwbuf, wka->dm_pwbuf_size);
	if (pwent == NULL) {
		endpwent();
		ucred_free(ucred);
		return (NULL);
	}
	TRACE((MMS_DEBUG, "pid %ld, uid %ld, user %s",
	    (long)pid, (long)uid, pwent->pw_name));
	endpwent();
	ucred_free(ucred);
	return (strdup(pwent->pw_name));
}

int
dm_chk_dev_auth(char *user)
{
	/*
	 * Check to see if the user is authorized to use MMS
	 */
	setauthattr();
	if (!chkauthattr(MMS_AUTHNAME, user)) {
		endauthattr();
		return (-1);
	}
	endauthattr();
	return (0);
}
