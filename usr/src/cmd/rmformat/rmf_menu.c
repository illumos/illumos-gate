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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * rmf_menu.c :
 *	Command line options to rmformat are processed in this file.
 */

#include "rmformat.h"
#include <sys/smedia.h>
#include <priv_utils.h>

extern int32_t D_flag;
extern int32_t e_flag;
extern int32_t H_flag;
extern int32_t U_flag;
extern int32_t V_flag;
extern int32_t b_flag;
extern int32_t w_flag;
extern int32_t W_flag;
extern int32_t s_flag;
extern int32_t c_flag;
extern int32_t F_flag;
extern int32_t R_flag;
extern int32_t p_flag;
extern int32_t l_flag;

extern char *myname;
extern char *slice_file;
extern diskaddr_t repair_blk_no;
extern int32_t quick_format;
extern int32_t long_format;
extern int32_t force_format;
extern int32_t rw_protect_enable;
extern int32_t rw_protect_disable;
extern int32_t wp_enable_passwd;
extern int32_t wp_disable_passwd;
extern int32_t wp_enable;
extern int32_t wp_disable;
extern int32_t verify_write;
extern char *dev_name;
extern char *label;
extern int total_devices_found;
extern int removable_found;
char *global_intr_msg;
smmedium_prop_t med_info;
int vol_running;

extern void check_invalid_combinations();
extern void check_invalid_combinations_again(int32_t);
extern void process_options();
extern void get_passwd(struct smwp_state *wp, int32_t confirm);
extern int32_t valid_slice_file(smedia_handle_t, int32_t, char *,
	struct extvtoc *);
extern void trap_SIGINT();
extern void release_SIGINT();
extern int32_t verify(smedia_handle_t handle, int32_t fd,
	diskaddr_t start_sector, uint32_t nblocks,
	char *buf, int32_t flag, int32_t blocksize, int32_t no_raw_rw);
extern void my_perror(char *err_string);
extern void write_default_label(smedia_handle_t, int32_t fd);
extern int find_device(int defer, char *tmpstr);

void overwrite_metadata(int32_t fd, smedia_handle_t handle);

int32_t write_sunos_label(int32_t fd, int32_t media_type);

int32_t my_open(char *device_name, int32_t flags);
int32_t check_and_unmount_vold(char *device_name, int32_t flag);
int32_t check_and_unmount_scsi(char *device_name, int32_t flag);

int32_t check_and_unmount_floppy(int32_t fd, int32_t flag);
int32_t get_confirmation(void);


static void	process_F_flag(smedia_handle_t handle, int32_t fd);
static void	process_w_flag(smedia_handle_t handle);
static void	process_W_flag(smedia_handle_t handle);
static void	process_R_flag(smedia_handle_t handle);
void		process_p_flag(smedia_handle_t handle, int32_t fd);
static void	process_c_flag(smedia_handle_t handle);
static void	process_V_flag(smedia_handle_t handle, int32_t fd);
static void	process_s_flag(smedia_handle_t, int32_t fd);
static void	process_e_flag(smedia_handle_t handle);
static void	process_H_flag(smedia_handle_t handle, int32_t fd);
static void	process_D_flag(smedia_handle_t handle, int32_t fd);
static void	process_b_flag(int32_t fd);
static void	process_l_flag(void);

void
process_options()
{
	int32_t fd;
	smedia_handle_t handle;
	int32_t m_scsi_umount = 0;
	int32_t m_flp_umount = 0;
	int32_t v_device_umount = 0;
	int32_t umount_required = 0;
	int32_t removable;
	int32_t umount_failed = 0;
	struct dk_minfo media;

	check_invalid_combinations();

	if (l_flag && !dev_name) {
		process_l_flag();
		return;
	}

	if (U_flag) {
		if (!(F_flag || H_flag || D_flag)) {
			F_flag = 1;
			long_format = 1;
		}
	}

	if (F_flag || w_flag || W_flag || R_flag || D_flag || H_flag ||
	    V_flag || c_flag || b_flag || s_flag || e_flag) {
		umount_required = 1;
	}

	fd = my_open(dev_name, O_RDONLY|O_NDELAY);
	if (fd < 0)  {
		PERROR("Could not open device");
		(void) close(fd);
		exit(1);
	}

	if (ioctl(fd, DKIOCREMOVABLE, &removable) < 0) {
		PERROR("DKIOCREMOVABLE ioctl failed");
		(void) close(fd);
		exit(1);
	}
	if (!removable) {
		(void) fprintf(stderr,
		    gettext("Not a removable media device\n"));
		(void) close(fd);
		exit(1);
	}

	if (ioctl(fd, DKIOCGMEDIAINFO, &media) < 0) {
		(void) fprintf(stderr,
		    gettext("No media in specified device\n"));
		(void) close(fd);
		exit(1);
	}

	/* Check if volume manager has mounted this */
	if (umount_required) {
		v_device_umount = check_and_unmount_vold(dev_name, U_flag);
		if (v_device_umount != 1) {
			m_scsi_umount = check_and_unmount_scsi(dev_name,
			    U_flag);
			if (m_scsi_umount != 1) {
				m_flp_umount = check_and_unmount_floppy(fd,
				    U_flag);
				if (m_flp_umount != 1) {
					umount_failed = 1;
				}
			}
		}
	}

	if (umount_required && U_flag && umount_failed) {
		if (v_device_umount || m_scsi_umount || m_flp_umount) {
			(void) fprintf(stderr,
			    gettext("Could not unmount device.\n"));
			(void) close(fd);
			exit(1);
		}
	}

	if (umount_required && !U_flag) {
		if (v_device_umount || m_scsi_umount || m_flp_umount) {
			(void) fprintf(stderr, gettext("Device mounted.\n"));
			(void) fprintf(stderr,
			    gettext("Requested operation can not be \
performed on a mounted device.\n"));
			(void) close(fd);
			exit(1);
		}
	}
	/* register the fd with the libsmedia */
	handle = smedia_get_handle(fd);
	if (handle == NULL) {
		(void) fprintf(stderr,
		    gettext("Failed to get libsmedia handle.\n"));
		(void) close(fd);
		exit(1);
	}

	if (smedia_get_medium_property(handle, &med_info) < 0) {
		(void) fprintf(stderr,
		    gettext("Get medium property failed \n"));
		(void) smedia_release_handle(handle);
		(void) close(fd);
		exit(1);
	}

	DPRINTF1("media type %x\n", med_info.sm_media_type);
	DPRINTF1("media block size %x\n", med_info.sm_blocksize);
	DPRINTF1("media capacity %u\n", (uint32_t)med_info.sm_capacity);
	DPRINTF3("media cyl %d head %d sect %d\n",
	    med_info.sm_pcyl, med_info.sm_nhead, med_info.sm_nsect);
	check_invalid_combinations_again(med_info.sm_media_type);

	/*
	 * Special handling for pcmcia, sometimes open the file in
	 * read-write mode.
	 */

	if (med_info.sm_media_type == SM_PCMCIA_MEM) {
		if (F_flag || H_flag || D_flag || (V_flag && verify_write)) {
			(void) close(fd);
			DPRINTF("Reopening device\n");
			fd = my_open(dev_name, O_RDWR|O_NDELAY);
			if (fd < 0)  {
				PERROR("Could not open device");
				(void) smedia_release_handle(handle);
				(void) close(fd);
				exit(1);
			}
		}
	}

	if (med_info.sm_media_type == SM_PCMCIA_ATA) {
		if (V_flag || c_flag) {
			(void) fprintf(stderr,
			    gettext("Option not supported on PC ATA cards\n"));
			(void) smedia_release_handle(handle);
			(void) close(fd);
			exit(1);
		}
		if (F_flag) {
			/* same text as used by the format command */
			(void) fprintf(stderr,
			    gettext("Cannot format this drive. Please use your \
Manufacturer supplied formatting utility.\n"));
			(void) smedia_release_handle(handle);
			(void) close(fd);
			exit(1);
		}
	}

	if (F_flag)
		process_F_flag(handle, fd);
	if (w_flag)
		process_w_flag(handle);
	if (W_flag)
		process_W_flag(handle);
	if (R_flag)
		process_R_flag(handle);
	if (p_flag)
		process_p_flag(handle, fd);
	if (D_flag)
		process_D_flag(handle, fd);
	if (H_flag)
		process_H_flag(handle, fd);
	if (V_flag)
		process_V_flag(handle, fd);
	if (c_flag)
		process_c_flag(handle);
	if (b_flag)
		process_b_flag(fd);
	if (s_flag)
		process_s_flag(handle, fd);
	if (e_flag)
		process_e_flag(handle);
	if (l_flag) {
		process_l_flag();
	}

	(void) smedia_release_handle(handle);
	(void) close(fd);
}

/*
 * This routine handles the F_flag.
 * This options should not be used for floppy. However,
 * if this option is used for floppy, the option will
 * be forced to SM_FORMAT_HD and smedia_format is called.
 * Note that smedia_format is a blocked mode format and it
 * returns only after the complete formatting is over.
 */

static void
process_F_flag(smedia_handle_t handle, int32_t fd)
{
	uint32_t format_flag;
	int32_t old_per = 0;
	int32_t new_per, ret_val;

	if (force_format) {
		(void) fprintf(stderr,
		    gettext("Formatting disk.\n"));
	} else {
		(void) fprintf(stderr,
		    gettext("Formatting will erase all the data on disk.\n"));
		if (!get_confirmation())
			return;
	}

	if (quick_format)
		format_flag = SM_FORMAT_QUICK;
	else if (long_format)
		format_flag = SM_FORMAT_LONG;
	else if (force_format)
		format_flag = SM_FORMAT_FORCE;

	if (med_info.sm_media_type == SM_FLOPPY)
		format_flag = SM_FORMAT_HD;

	if ((med_info.sm_media_type != SM_FLOPPY) &&
	    (med_info.sm_media_type != SM_PCMCIA_MEM) &&
	    (med_info.sm_media_type != SM_SCSI_FLOPPY)) {
		global_intr_msg = "Interrupting format may render the \
medium useless";
	} else {
		global_intr_msg = "";
	}
		trap_SIGINT();

	if (smedia_format(handle, format_flag, SM_FORMAT_IMMEDIATE) != 0) {
		if (errno == EINVAL) {
			(void) fprintf(stderr, gettext("Format failed.\n"));
			(void) fprintf(stderr, gettext("The medium may not \
be compatible for format operation.\n"));
			(void) fprintf(stderr, gettext("read/write surface \
scan may be used to get the effect of formatting.\n"));
		} else {
			PERROR("Format failed");
		}
		(void) smedia_release_handle(handle);
		(void) close(fd);
		exit(1);
	}

	/* CONSTCOND */
	while (1) {
		ret_val = smedia_check_format_status(handle);
		if (ret_val == -1) {
			if (errno != ENOTSUP) {
				PERROR("Format failed");
				(void) smedia_release_handle(handle);
				(void) close(fd);
				exit(1);
			} else {
				/* Background formatting is not supported */
				break;
			}
		}
		if (ret_val == 100) {
			(void) printf("\n");
			(void) fflush(stdout);
			break;
		}
		new_per = (ret_val * 80)/100;
		while (new_per >= old_per) {
			(void) printf(".");
			(void) fflush(stdout);
			old_per++;
		}
		(void) sleep(6);
	}

	if ((med_info.sm_media_type == SM_FLOPPY) ||
	    (med_info.sm_media_type == SM_PCMCIA_MEM) ||
	    (med_info.sm_media_type == SM_SCSI_FLOPPY)) {
		(void) write_sunos_label(fd, med_info.sm_media_type);
	} else {

		/*
		 * Iomega drives don't destroy the data in quick format.
		 * Do a best effort write to first 1024 sectors.
		 */

		if (quick_format)
			overwrite_metadata(fd, handle);

		(void) write_default_label(handle, fd);
	}

	release_SIGINT();
}

/*
 * List removable devices.
 */
static void
process_l_flag()
{
	int retry;
	int removable;
	int total_devices_found_last_time;
	int defer = 0;
	char *tmpstr;

#define	MAX_RETRIES_FOR_SCANNING 3

	vol_running = volmgt_running();
	if (vol_running)
		defer = 1;
	(void) printf(gettext("Looking for devices...\n"));
	total_devices_found_last_time = 0;

	/*
	 * Strip out any leading path.  For example, /dev/rdsk/c3t0d0s2
	 * will result in tmpstr = c3t0d0s2.  dev_name is given as input
	 * argument.
	 */
	if (dev_name) {
		if ((tmpstr = strrchr(dev_name, '/')) != NULL) {
			tmpstr += sizeof (char);
		} else {
			tmpstr = dev_name;
		}
	}

	for (retry = 0; retry < MAX_RETRIES_FOR_SCANNING; retry++) {
		removable = find_device(defer, tmpstr);
		if (removable == -1)
			break;

		/*
		 * We'll do a small sleep and retry the command if volume
		 * manager is running and no removable devices are found.
		 * This is because the device may be busy.
		 */
		if (defer || (vol_running && (removable == 0))) {
			if ((total_devices_found == 0) ||
			    (total_devices_found !=
			    total_devices_found_last_time)) {
				total_devices_found_last_time =
				    total_devices_found;
				(void) sleep(2);
			} else {
				/* Do the printing this time */
				defer = 0;
				removable_found = 0;
			}

		} else
			break;
	}
	if (removable_found == 0)
		(void) printf(gettext("No removables found.\n"));
}

/*
 * The following three routines handle the write protect
 * options. These options are mostly Iomega ZIP/Jaz centric.
 * The following options are allowed :
 *  No write protect <=> write protect without passwd : use -w flag
 *  from any state to WP with passwd : use -W flag
 *  from WP with passwd to no write protect : use -W flag
 *  from any state to RWP with passwd : use -R flag
 *  from RWP with passwd to no write protect : use -R flag
 *
 * The following transitions is not allowed
 * WP with passwd or RWP to WP without passwd.
 */

static void
process_w_flag(smedia_handle_t handle)
{
	int32_t rval;
	int32_t med_status;
	struct smwp_state wps;

	if ((rval = smedia_get_protection_status((handle), &wps)) < 0) {
		(void) fprintf(stderr,
		    gettext("Could not get medium status \n"));
		return;
	}
	med_status = wps.sm_new_state;

	wps.sm_version = SMWP_STATE_V_1;

	if (wp_enable) {	/* Enable write protect no password */

		switch (med_status) {
			case SM_WRITE_PROTECT_DISABLE  :
				wps.sm_new_state =
				    SM_WRITE_PROTECT_NOPASSWD;
				wps.sm_passwd_len = 0;
				rval = smedia_set_protection_status(handle,
				    &wps);
				if (rval == -1)
					PERROR(WP_ERROR);
				break;
			case SM_WRITE_PROTECT_NOPASSWD :
				(void) fprintf(stderr, gettext(WP_MSG_0));
				break;
			case SM_WRITE_PROTECT_PASSWD :
				(void) fprintf(stderr, gettext(WP_MSG_1));
				break;
			case SM_READ_WRITE_PROTECT :
				(void) fprintf(stderr, gettext(WP_MSG_2));
				break;
			case SM_STATUS_UNKNOWN :
				default :
				(void) fprintf(stderr, gettext(WP_UNKNOWN));
				break;
		}
	} else if (wp_disable) {
		switch (med_status) {
			case SM_WRITE_PROTECT_NOPASSWD :
				wps.sm_new_state =
				    SM_WRITE_PROTECT_DISABLE;
				wps.sm_passwd_len = 0;
				rval = smedia_set_protection_status(handle,
				    &wps);
				if (rval == -1)
					PERROR(WP_ERROR);
				break;
			case SM_WRITE_PROTECT_DISABLE  :
				(void) fprintf(stderr, gettext(WP_MSG_3));
				break;
			case SM_WRITE_PROTECT_PASSWD :
				(void) fprintf(stderr, gettext(WP_MSG_1));
				break;
			case SM_READ_WRITE_PROTECT :
				(void) fprintf(stderr, gettext(WP_MSG_2));
				break;
			case SM_STATUS_UNKNOWN :
				default :
				(void) fprintf(stderr, gettext(WP_UNKNOWN));
				break;
		}
	}
}

static void
process_W_flag(smedia_handle_t handle)
{
	int32_t rval;
	int32_t med_status;
	struct smwp_state wps;

	DPRINTF("Write protect with password\n");

	if ((rval = smedia_get_protection_status((handle), &wps)) < 0) {
		(void) fprintf(stderr,
		    gettext("Could not get medium status \n"));
		return;
	}
	med_status = wps.sm_new_state;

	wps.sm_version = SMWP_STATE_V_1;

	if (wp_enable_passwd) {	/* Enable write protect  */
		switch (med_status) {
			case SM_WRITE_PROTECT_DISABLE  :
			case SM_WRITE_PROTECT_NOPASSWD :
				DPRINTF("Getting passwd\n");
				get_passwd(&wps, 1);
				wps.sm_new_state =
				    SM_WRITE_PROTECT_PASSWD;
				rval = smedia_set_protection_status(handle,
				    &wps);
				if (rval == -1) {
					PERROR(WP_ERROR);
				}
				break;
			case SM_READ_WRITE_PROTECT :
				(void) fprintf(stderr, gettext(WP_MSG_4));
				(void) fprintf(stderr, gettext(WP_MSG_5));
				get_passwd(&wps, 0);
				wps.sm_new_state =
				    SM_WRITE_PROTECT_PASSWD;
				rval = smedia_set_protection_status(handle,
				    &wps);
				if (rval == -1) {
					if (errno == EACCES) {
						(void) fprintf(stderr,
						    gettext(WP_MSG_10));
					} else {
						PERROR(WP_ERROR);
					}
				}
				break;
			case SM_WRITE_PROTECT_PASSWD :
				(void) fprintf(stderr, gettext(WP_MSG_6));
				break;
			case SM_STATUS_UNKNOWN :
				default :
				(void) fprintf(stderr,
				    gettext(WP_UNKNOWN));
				break;
		}
	} else if (wp_disable_passwd) {
		switch (med_status) {
			case SM_WRITE_PROTECT_PASSWD :
				get_passwd(&wps, 0);
				wps.sm_new_state =
				    SM_WRITE_PROTECT_DISABLE;
				rval = smedia_set_protection_status(handle,
				    &wps);
				if (rval == -1) {
					if (errno == EACCES) {
						(void) fprintf(stderr,
						    gettext(WP_MSG_10));
					} else {
						PERROR(WP_ERROR);
					}
				}
				break;
			case SM_READ_WRITE_PROTECT :
				(void) fprintf(stderr, gettext(WP_MSG_2));
				break;
			case SM_WRITE_PROTECT_NOPASSWD :
				(void) fprintf(stderr, gettext(WP_MSG_7));
				break;
			case SM_WRITE_PROTECT_DISABLE  :
				(void) fprintf(stderr, gettext(WP_MSG_3));
				break;
			case SM_STATUS_UNKNOWN :
				default :
				(void) fprintf(stderr, gettext(WP_UNKNOWN));
				break;
		}
	}
}

static void
process_R_flag(smedia_handle_t handle)
{
	int32_t rval;
	int32_t med_status;
	struct smwp_state wps;

	DPRINTF("Read Write protect \n");

	if ((rval = smedia_get_protection_status((handle), &wps)) < 0) {
		(void) fprintf(stderr,
		    gettext("Could not get medium status \n"));
		return;
	}
	med_status = wps.sm_new_state;

	wps.sm_version = SMWP_STATE_V_1;

	if (rw_protect_enable) {	/* Enable write protect  */
		switch (med_status) {
			case SM_WRITE_PROTECT_DISABLE  :
			case SM_WRITE_PROTECT_NOPASSWD :
				DPRINTF("Getting passwd\n");
				get_passwd(&wps, 1);
				wps.sm_new_state =
				    SM_READ_WRITE_PROTECT;
				rval = smedia_set_protection_status(handle,
				    &wps);
				if (rval == -1)
					PERROR(WP_ERROR);
				break;
			case SM_WRITE_PROTECT_PASSWD :
				(void) fprintf(stderr, gettext(WP_MSG_8));
				(void) fprintf(stderr, gettext(WP_MSG_9));
				get_passwd(&wps, 0);
				wps.sm_new_state =
				    SM_READ_WRITE_PROTECT;
				rval = smedia_set_protection_status(handle,
				    &wps);
				if (rval == -1) {
					if (errno == EACCES) {
						(void) fprintf(stderr,
						    gettext(WP_MSG_10));
					} else {
						PERROR(WP_ERROR);
					}
				}
				break;
			case SM_READ_WRITE_PROTECT :
				(void) fprintf(stderr, gettext(WP_MSG_4));
				break;
			case SM_STATUS_UNKNOWN :
				default :
				(void) fprintf(stderr, gettext(WP_UNKNOWN));
				break;
		}
	} else if (rw_protect_disable) {
		switch (med_status) {
			case SM_READ_WRITE_PROTECT :
			case SM_STATUS_UNKNOWN :
				get_passwd(&wps, 0);
				wps.sm_new_state =
				    SM_WRITE_PROTECT_DISABLE;
				rval = smedia_set_protection_status(handle,
				    &wps);
				if (rval == -1) {
					if (errno == EACCES) {
						(void) fprintf(stderr,
						    gettext(WP_MSG_10));
					} else {
						PERROR(WP_ERROR);
					}
				}
				break;
			case SM_WRITE_PROTECT_PASSWD :
				(void) fprintf(stderr, gettext(WP_MSG_1));
					break;
			case SM_WRITE_PROTECT_NOPASSWD :
				(void) fprintf(stderr, gettext(WP_MSG_7));
				break;
			case SM_WRITE_PROTECT_DISABLE  :
				(void) fprintf(stderr, gettext(WP_MSG_3));
				break;
			default :
				(void) fprintf(stderr, gettext(WP_UNKNOWN));
				break;
		}
	}
}

void
process_p_flag(smedia_handle_t handle, int32_t fd)
{
	int32_t med_status;
	smwp_state_t	wps;

	med_status = smedia_get_protection_status((handle), &wps);
	DPRINTF("Could not get medium status \n");

	/*
	 * Workaround in case mode sense fails.
	 *
	 * Also, special handling for PCMCIA. PCMCIA does not have any
	 * ioctl to find out the write protect status. So, open the
	 * device with O_RDWR. If it passes, it is not write protected,
	 * otherwise it is write protected.
	 * If it fails, reopen with O_RDONLY, may be some other
	 * operation can go through.
	 */
	if ((med_status < 0) || (med_info.sm_media_type == SM_PCMCIA_MEM) ||
	    (med_info.sm_media_type == SM_PCMCIA_ATA)) {
		(void) close(fd);
		DPRINTF("Reopening device for -p option\n");
		fd = my_open(dev_name, O_RDONLY|O_NDELAY);
		if (fd < 0)  {
			if (p_flag)  {
				PERROR("Could not open device");
				(void) smedia_release_handle(handle);
				(void) close(fd);
				exit(1);
			} else {
				(void) fprintf(stdout,
				    gettext("<Unknown>\n"));
				(void) smedia_release_handle(handle);
				(void) close(fd);
				return;
			}
			fd = my_open(dev_name, O_RDWR|O_NDELAY);
			if (fd < 0)  {
				(void) fprintf(stdout,
				gettext("Medium is write protected.\n"));
			}
		} else { /* Open succeeded */
			(void) fprintf(stdout,
			    gettext("Medium is not write protected.\n"));
		}
		return;
	}
	med_status = wps.sm_new_state;
	switch (med_status) {

		case SM_READ_WRITE_PROTECT :
			(void) fprintf(stdout,
			gettext("Medium is read-write protected.\n"));
			break;
		case SM_WRITE_PROTECT_PASSWD :
			(void) fprintf(stdout,
			gettext("Medium is write protected with password.\n"));
			break;
		case SM_WRITE_PROTECT_NOPASSWD :
			(void) fprintf(stdout,
			gettext("Medium is write protected.\n"));
			break;
		case SM_WRITE_PROTECT_DISABLE  :
			(void) fprintf(stdout,
			gettext("Medium is not write protected.\n"));
			break;
		case SM_STATUS_UNKNOWN :
			default:
			(void) fprintf(stdout,
			    gettext("Unknown write protect status.\n"));
			break;
	}
}

static void
process_c_flag(smedia_handle_t handle)
{
	char error_string[256];

	if (smedia_reassign_block(handle, repair_blk_no) != 0) {
		(void) snprintf(error_string, 255,
		    gettext("Could not repair block no %llu"), repair_blk_no);
		PERROR(error_string);
		return;
	}
}

/*
 * This routine handles the -V (verify) option.
 * There can be devices without rw_read option. If the raw_read
 * and raw_write are not supported by the interface, then read and
 * write system calls are used. It is assumed that either both
 * raw_read and raw_write are supported or both are unsupported.
 */

static void
process_V_flag(smedia_handle_t handle, int32_t fd)
{
	int32_t ret;
	uint32_t j;
	diskaddr_t bn;
	char *read_buf, *write_buf;
	int32_t old_per = 0;
	int32_t new_per;
	int32_t no_raw_rw = 0;
	int32_t verify_size;
	diskaddr_t capacity;
	int32_t blocksize;

	DPRINTF("ANALYSE MEDIA \n");

	ret = smedia_get_medium_property(handle, &med_info);
	if (ret == -1) {
		DPRINTF("get_media_info failed\n");
		return;
	}

	DPRINTF1("media_type %d\n", med_info.sm_media_type);
	DPRINTF1("sector_size %d\n", med_info.sm_blocksize);
	DPRINTF1("num_sectors %u\n", (uint32_t)med_info.sm_capacity);
	DPRINTF1("nsect	 %d\n", med_info.sm_nsect);

	blocksize = med_info.sm_blocksize;

	capacity = (uint32_t)med_info.sm_capacity;
	verify_size = (med_info.sm_nsect > 64) ? 64 : med_info.sm_nsect;
	read_buf = (char *)malloc(blocksize * verify_size);
	if (read_buf == NULL) {
		DPRINTF("Could not allocate memory\n");
		return;
	}
	write_buf = (char *)malloc(blocksize * verify_size);
	if (write_buf == NULL) {
		DPRINTF("Could not allocate memory\n");
		free(read_buf);
		return;
	}

	if (!verify_write) {
		DPRINTF("Non-destructive verify \n");
		for (bn = 0; bn < (uint32_t)med_info.sm_capacity;
		    bn += verify_size) {
			new_per = (bn * 80)/(uint32_t)med_info.sm_capacity;
			if (new_per >= old_per) {
				(void) printf(".");
				(void) fflush(stdout);
				old_per++;
			}
			DPRINTF2("Reading %d blks starting at %llu\n",
			    verify_size, bn);
			ret = verify(handle, fd, bn, verify_size, read_buf,
			    VERIFY_READ, blocksize, no_raw_rw);
			if ((ret == -1) && (errno == ENOTSUP)) {
				no_raw_rw = 1;
				ret = verify(handle, fd, bn, verify_size,
				    read_buf,
				    VERIFY_READ, blocksize, no_raw_rw);
				capacity = (diskaddr_t)med_info.sm_pcyl *
				    med_info.sm_nhead * med_info.sm_nsect;
			}

			if (ret != 0) {
				for (j = 0; j < verify_size; j++) {
					if ((bn + j) >= capacity)
							return;
					DPRINTF2(
					    "Reading %d blks starting "
					    "at %llu\n", 1, bn + j);
					ret = verify(handle, fd, bn + j, 1,
					    read_buf,
					    VERIFY_READ, blocksize,
					    no_raw_rw);
					if (ret == -1) {
						(void) printf(
						    "Bad block %llu\n",
						    bn + j);
					}
				}
			}
		}
	} else {

		DPRINTF("Destrutive verify \n");
		for (bn = 0; bn < (uint32_t)med_info.sm_capacity;
		    bn += verify_size) {
			new_per = (bn * 80)/(uint32_t)med_info.sm_capacity;
			if (new_per >= old_per) {
				(void) printf(".");

				(void) fflush(stdout);
				old_per++;
			}

			for (j = 0; j < blocksize * verify_size; j++) {
				write_buf[j] = (bn | j) & 0xFF;
			}
			DPRINTF2("Writing %d blks starting at %llu\n",
			    verify_size, bn);
			ret = verify(handle, fd, bn, verify_size, write_buf,
			    VERIFY_WRITE, blocksize, no_raw_rw);

			if (ret != 0) {
				for (j = 0; j < verify_size; j++) {
					if ((bn + j) >= capacity)
							break;
					DPRINTF2(
					    "Writing %d blks starting "
					    "at %llu\n", 1, bn + j);
					ret = verify(handle, fd, bn + j, 1,
					    write_buf,
					    VERIFY_WRITE, blocksize,
					    no_raw_rw);
					if (ret == -1) {
						(void) printf(
						    "Bad block %llu\n", bn + j);
					}
				}
			}
			DPRINTF2("Read after write  %d blks starting at %llu\n",
			    verify_size, bn);
			ret = verify(handle, fd, bn, verify_size,
			    read_buf, VERIFY_READ, blocksize, no_raw_rw);

			if (ret != 0) {
				for (j = 0; j < verify_size; j++) {
					if ((bn + j) >= capacity)
							return;
					DPRINTF2(
					    "Read after write  %d blks "
					    "starting at %llu\n", 1, bn + j);
					ret = verify(handle, fd, bn + j, 1,
					    read_buf, VERIFY_READ,
					    blocksize, no_raw_rw);
					if (ret == -1) {
						(void) printf(
						    "Bad block %llu\n", bn + j);
					}
				}
			}


		}
	}
}

static void
process_s_flag(smedia_handle_t handle, int32_t fd)
{
	int32_t i, ret;
	struct extvtoc v_toc, t_vtoc;
	if (valid_slice_file(handle, fd, slice_file, &v_toc)) {
			(void) smedia_release_handle(handle);
			(void) close(fd);
			exit(1);
	}

	(void) memset(&t_vtoc, 0, sizeof (t_vtoc));


	t_vtoc.v_nparts = V_NUMPAR;
	t_vtoc.v_sanity = VTOC_SANE;
	t_vtoc.v_version = V_VERSION;
	t_vtoc.v_sectorsz = DEV_BSIZE;

	/* Get existing Vtoc, don't bother if it fails. */

	/* Turn on privileges. */
	(void) __priv_bracket(PRIV_ON);

	(void) read_extvtoc(fd, &t_vtoc);

	/* Turn off privileges. */
	(void) __priv_bracket(PRIV_OFF);

	for (i = 0; i < V_NUMPAR; i++) {
		t_vtoc.v_part[i].p_start = v_toc.v_part[i].p_start;
		t_vtoc.v_part[i].p_size = v_toc.v_part[i].p_size;
		t_vtoc.v_part[i].p_tag	= v_toc.v_part[i].p_tag;
		t_vtoc.v_part[i].p_flag = v_toc.v_part[i].p_flag;
	}

	errno = 0;


	/* Turn on privileges. */
	(void) __priv_bracket(PRIV_ON);

	ret = write_extvtoc(fd, &t_vtoc);

	/* Turn off privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (ret < 0)  {
#ifdef sparc
		PERROR("write VTOC failed");
		DPRINTF1("Errno = %d\n", errno);
#else /* i386 */
		if (errno == EIO) {
			PERROR("No Solaris partition, eject & retry");
			DPRINTF1("Errno = %d\n", errno);
		} else {
			PERROR("write VTOC failed");
			DPRINTF1("Errno = %d\n", errno);
		}
#endif
	}
}
static void
process_e_flag(smedia_handle_t handle)
{
	if (smedia_eject(handle) < 0) {
		PERROR("Eject failed");
	}
}
static void
process_H_flag(smedia_handle_t handle, int32_t fd)
{
	uint32_t cyl, head;
	int32_t old_per = 0;
	int32_t new_per;

	(void) fprintf(stderr,
	    gettext("Formatting will erase all the data on disk.\n"));
	if (!get_confirmation())
		return;

	for (cyl = 0; cyl < med_info.sm_pcyl; cyl++) {
		for (head = 0; head < med_info.sm_nhead; head++) {
			if (smedia_format_track(handle, cyl, head, SM_FORMAT_HD)
			    < 0) {
					PERROR("Format failed");
					return;
			}
		}
		new_per = (cyl * 80)/med_info.sm_pcyl;
		while (new_per >= old_per) {
			(void) printf(".");
			(void) fflush(stdout);
			old_per++;
		}
	}

	(void) write_sunos_label(fd, med_info.sm_media_type);
}

static void
process_D_flag(smedia_handle_t handle, int32_t fd)
{
	uint32_t cyl, head;
	int32_t old_per = 0;
	int32_t new_per;

	(void) fprintf(stderr,
	    gettext("Formatting will erase all the data on disk.\n"));
	if (!get_confirmation())
		return;
	for (cyl = 0; cyl < med_info.sm_pcyl; cyl++) {
		for (head = 0; head < med_info.sm_nhead; head++) {
			if (smedia_format_track(handle, cyl, head, SM_FORMAT_DD)
			    < 0) {
					PERROR("Format failed");
					return;
			}
		}
		new_per = (cyl * 80)/med_info.sm_pcyl;
		while (new_per >= old_per) {
			(void) printf(".");
			(void) fflush(stdout);
			old_per++;
		}
	}
	(void) write_sunos_label(fd, med_info.sm_media_type);
}

/*
 * This routine handles the -b (label) option.
 * Please note that, this will fail if there is no valid vtoc is
 * there on the medium and the vtoc is not faked.
 */

static void
process_b_flag(int32_t fd)
{
	int32_t ret, nparts;
	struct extvtoc v_toc;
	struct dk_gpt *vtoc64;

	/* For EFI disks. */
	if (efi_type(fd)) {
		if (efi_alloc_and_read(fd, &vtoc64) < 0) {
			/*
			 * If reading the vtoc failed, try to
			 * auto-sense the disk configuration.
			 */
			if (efi_auto_sense(fd, &vtoc64) < 0) {
				(void) fprintf(stderr,
				    gettext("Could not write label.\n"));
				return;
			}
		}
		for (nparts = 0; nparts < vtoc64->efi_nparts;
		    nparts++) {
			if (vtoc64->efi_parts[nparts].p_tag ==
			    V_RESERVED) {
				(void) strncpy(
				    vtoc64->efi_parts[nparts].p_name, label,
				    EFI_PART_NAME_LEN);
				break;
			}
		}
		if (efi_write(fd, vtoc64) != 0) {
			(void) efi_err_check(vtoc64);
			(void) fprintf(stderr,
			    gettext("Could not write label.\n"));
		}
		return;
	}

	/* Get existing Vtoc */

	/* Turn on privileges. */
	(void) __priv_bracket(PRIV_ON);

	ret = read_extvtoc(fd, &v_toc);

	/* Turn off privileges */
	(void) __priv_bracket(PRIV_OFF);

	if (ret < 0) {
#ifdef sparc
		PERROR("read VTOC failed");
		DPRINTF1("Errno = %d\n", errno);
#else /* i386 */
		if (errno == EIO) {
			PERROR("No Solaris partition, eject & retry");
			DPRINTF1("Errno = %d\n", errno);
		} else {
			PERROR("read VTOC failed");
			DPRINTF1("Errno = %d\n", errno);
		}
#endif
		return;
	}

	(void) strncpy(v_toc.v_volume, label, LEN_DKL_VVOL);


	/* Turn on the privileges. */
	(void) __priv_bracket(PRIV_ON);

	ret = write_extvtoc(fd, &v_toc);

	/* Turn off the privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (ret < 0) {
#ifdef sparc
		PERROR("write VTOC failed");
		DPRINTF1("Errno = %d\n", errno);
#else /* i386 */
		if (errno == EIO) {
			PERROR("No Solaris partition, eject & retry");
			DPRINTF1("Errno = %d\n", errno);
		} else {
			PERROR("write VTOC failed");
			DPRINTF1("Errno = %d\n", errno);
		}
#endif
	}
}
