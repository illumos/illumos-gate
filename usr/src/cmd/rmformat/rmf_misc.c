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
 * rmf_misc.c :
 *	Miscelleneous routines for rmformat.
 */

#include <sys/types.h>
#include <stdio.h>
#include <sys/mnttab.h>
#include <volmgt.h>
#include <sys/dkio.h>
#include <sys/fdio.h>
#include <sys/vtoc.h>
#include <sys/termios.h>
#include <sys/mount.h>
#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include <priv_utils.h>
#include <stdarg.h>
#include "rmformat.h"

/*
 * Definitions.
 */
#define	SENSE_KEY(rqbuf)	(rqbuf[2] & 0xf) /* scsi error category */
#define	ASC(rqbuf)		(rqbuf[12])	/* additional sense code */
#define	ASCQ(rqbuf)		(rqbuf[13])	/* ASC qualifier */

#define	DEFAULT_SCSI_TIMEOUT	60
#define	INQUIRY_CMD		0x12
#define	RQBUFLEN		32
#define	CD_RW			1		/* CD_RW/CD-R	*/
#define	WRITE_10_CMD		0x2A
#define	READ_INFO_CMD		0x51
#define	SYNC_CACHE_CMD		0x35
#define	CLOSE_TRACK_CMD		0x5B
#define	MODE_SENSE_10_CMD	0x5A
#define	DEVFS_PREFIX		"/devices"

int		uscsi_error;		 /* used for debugging failed uscsi */
char		rqbuf[RQBUFLEN];
static uint_t	total_retries;
static struct	uscsi_cmd uscmd;
static char	ucdb[16];
uchar_t		uscsi_status, rqstatus, rqresid;
int		total_devices_found = 0;
int		removable_found = 0;

extern char	*global_intr_msg;
extern int	vol_running;
extern char	*dev_name;
extern int32_t	m_flag;

/*
 * ON-private functions from libvolmgt
 */
int	_dev_mounted(char *path);

/*
 * Function prototypes.
 */
static int		my_umount(char *mountp);
static int		my_volrmmount(char *real_name);
static int		vol_name_to_dev_node(char *vname, char *found);
static int		vol_lookup(char *supplied, char *found);
static device_t		*get_device(char *user_supplied, char *node);
static char		*get_physical_name(char *path);
static int		lookup_device(char *supplied, char *found);
static void		fini_device(device_t *dev);
static int		is_cd(char *node);
void			*my_zalloc(size_t size);
void			err_msg(char *fmt, ...);
int			inquiry(int fd, uchar_t *inq);
struct uscsi_cmd	*get_uscsi_cmd(void);
int			uscsi(int fd, struct uscsi_cmd *scmd);
int			get_mode_page(int fd, int page_no, int pc, int buf_len,
			    uchar_t *buffer);
int			mode_sense(int fd, uchar_t pc, int dbd, int page_len,
			    uchar_t *buffer);
uint16_t		read_scsi16(void *addr);
int			check_device(device_t *dev, int cond);
static void		get_media_info(device_t *t_dev, char *sdev,
			    char *pname, char *sn);

extern void		process_p_flag(smedia_handle_t handle, int32_t fd);

void
my_perror(char *err_string)
{

	int error_no;
	if (errno == 0)
		return;

	error_no = errno;
	(void) fprintf(stderr, "%s", err_string);
	(void) fprintf(stderr, gettext(" : "));
	errno = error_no;
	perror("");
}

int32_t
get_confirmation()
{
	char c;

	(void) fprintf(stderr, gettext("Do you want to continue? (y/n)"));
	c = getchar();
	if (c == 'y' || c == 'Y')
		return (1);
	else if (c == 'n' || c == 'N')
		return (0);
	else {
		(void) fprintf(stderr, gettext("Invalid choice\n"));
		return (0);
	}
}


void
get_passwd(struct smwp_state *wp, int32_t confirm)
{
	char passwd[256], re_passwd[256];
	int32_t len;
	struct termios tio;
	int32_t echo_off = 0;
	FILE *in, *out;
	char *buf;


	in = fopen("/dev/tty", "r+");
	if (in == NULL) {
		in = stdin;
		out = stderr;
	} else {
		out = in;
	}

	/* Turn echoing off if it is on now.  */

	if (tcgetattr(fileno(in), &tio) < 0) {
		PERROR("Echo off ioctl failed");
		exit(1);
	}
	if (tio.c_lflag & ECHO) {
		tio.c_lflag &= ~ECHO;
		/* echo_off = tcsetattr(fileno(in), TCSAFLUSH, &tio) == 0; */
		echo_off = tcsetattr(fileno(in), TCSAFLUSH, &tio) == 0;
		tio.c_lflag |= ECHO;
	}

	/* CONSTCOND */
	while (1) {
		(void) fputs(
		    gettext("Please enter password (32 chars maximum):"),
		    out);
		(void) fflush(out);
		buf = fgets(passwd, (size_t)256, in);
		rewind(in);
		if (buf == NULL) {
			PERROR("Error reading password");
			continue;
		}
		len = strlen(passwd);
		(void) fputc('\n', out);
		len--;	/* To offset the \n */
		if ((len <= 0) || (len > 32)) {
			(void) fprintf(stderr,
			    gettext("Invalid length of password \n"));
			(void) fputs("Try again\n", out);
			continue;
		}

		if (!confirm)
			break;

		(void) fputs("Please reenter password:", out);
		(void) fflush(out);
		buf = fgets(re_passwd, (size_t)256, in);
		rewind(in);
		(void) fputc('\n', out);
		if ((buf == NULL) || strcmp(passwd, re_passwd)) {
			(void) fputs("passwords did not match\n", out);
			(void) fputs("Try again\n", out);
		} else {
			break;
		}
	}
	wp->sm_passwd_len = len;
	(void) strncpy(wp->sm_passwd, passwd, wp->sm_passwd_len);
	wp->sm_version = SMWP_STATE_V_1;

	/* Restore echoing.  */
	if (echo_off)
		(void) tcsetattr(fileno(in), TCSAFLUSH, &tio);

}

int32_t
check_and_unmount_vold(char *device_name, int32_t flag)
{
	char *real_name;
	char *nm;
	char tmp_path_name[PATH_MAX];
	struct stat stat_buf;
	int32_t ret_val = 0;
	struct	mnttab	*mntp;
	FILE	*fp;
	int nl;

	DPRINTF1("Device name %s\n", device_name);

	if (volmgt_running() == 0) {
		DPRINTF("Vold not running\n");
		return (0);
	}
	if ((nm = volmgt_symname(device_name)) == NULL) {
		DPRINTF("path not managed\n");
		real_name = media_findname(device_name);
	} else {
		DPRINTF1("path managed as %s\n", nm);
		real_name = media_findname(nm);
		DPRINTF1("real name %s\n", real_name);
	}

	if (real_name == NULL)
		return (-1);

	/*
	 * To find out whether the device has been mounted by
	 * volume manager...
	 *
	 * Convert the real name to a block device address.
	 * Do a partial match with the mnttab entries.
	 * Make sure the match is in the beginning to avoid if
	 * anybody puts a label similiar to volume manager path names.
	 * Then use "volrmmount -e <dev_name>" if -U flag is set.
	 */

	nl = strlen("/vol/dev/");

	if (strncmp(real_name, "/vol/dev/", nl) != 0)
			return (0);
	if (real_name[nl] == 'r') {
		(void) snprintf(tmp_path_name, PATH_MAX, "%s%s", "/vol/dev/",
		    &real_name[nl + 1]);
	} else {
		(void) snprintf(tmp_path_name, PATH_MAX, "%s", real_name);
	}
	DPRINTF1("%s \n", tmp_path_name);
	ret_val = stat(tmp_path_name, &stat_buf);
	if (ret_val < 0) {
		PERROR("Could not stat");
		return (-1);
	}

	fp = fopen("/etc/mnttab", "r");

	if (fp == NULL) {
		PERROR("Could not open /etc/mnttab");
		return (-1);
	}

	mntp = (struct mnttab *)malloc(sizeof (struct mnttab));
	if (mntp == NULL) {
		PERROR("malloc failed");
		(void) fclose(fp);
		return (-1);
	}
	errno = 0;
	while (getmntent(fp, mntp) == 0) {
		if (errno != 0) {
			PERROR("Error with mnttab");
			(void) fclose(fp);
			return (-1);
		}
		/* Is it a probable entry? */
		DPRINTF1(" %s \n", mntp->mnt_special);
		if (strstr(mntp->mnt_special, tmp_path_name) !=
		    mntp->mnt_special) {
			/* Skip to next entry */
			continue;
		} else {
			DPRINTF1("Found!! %s\n", mntp->mnt_special);
			ret_val = 1;
			break;
		}
	}

	if (ret_val == 1) {
		if (flag) {
			if (my_volrmmount(real_name) < 0) {
				ret_val = -1;
			}
		} else {
			ret_val = -1;
		}
	}
	(void) fclose(fp);
	free(mntp);
	return (ret_val);
}

/*
 * This routine checks if a device has mounted partitions. The
 * device name is assumed to be /dev/rdsk/cNtNdNsN. So, this can
 * be used for SCSI and PCMCIA cards.
 * Returns
 *	 0 : if not mounted
 *	 1 : if successfully unmounted
 *	-1 : Any error or umount failed
 */

int32_t
check_and_unmount_scsi(char *device_name, int32_t flag)
{

	struct	mnttab	*mntrefp;
	struct	mnttab	*mntp;
	FILE	*fp;
	char block_dev_name[PATH_MAX];
	char tmp_name[PATH_MAX];
	int32_t  i, j;
	int32_t unmounted = 0;

	/*
	 * If the device name is not a character special, anyway we
	 * can not progress further
	 */

	if (strncmp(device_name, "/dev/rdsk/c", strlen("/dev/rdsk/c")) != 0)
		return (0);

	(void) snprintf(block_dev_name, PATH_MAX, "/dev/%s",
	    &device_name[strlen("/dev/r")]);
	fp = fopen("/etc/mnttab", "r");

	if (fp == NULL) {
		PERROR("Could not open /etc/mnttab");
		return (-1);
	}

	mntrefp = (struct mnttab *)malloc(sizeof (struct mnttab));
	if (mntrefp == NULL) {
		PERROR("malloc failed");
		(void) fclose(fp);
		return (-1);
	}

	mntp = (struct mnttab *)malloc(sizeof (struct mnttab));
	if (mntp == NULL) {
		PERROR("malloc failed");
		(void) fclose(fp);
		free(mntrefp);
		return (-1);
	}

	/* Try all the partitions */

	(void) snprintf(tmp_name, PATH_MAX, "/dev/%s",
	    &device_name[strlen("/dev/r")]);

	tmp_name[strlen("/dev/dsk/c0t0d0s")] = '\0';

	errno = 0;
	while (getmntent(fp, mntp) == 0) {
		if (errno != 0) {
			PERROR("Error with mnttab");
			(void) fclose(fp);
			return (-1);
		}
		/* Is it a probable entry? */
		if (strncmp(mntp->mnt_special, tmp_name, strlen(tmp_name))) {
			/* Skip to next entry */
			continue;
		}
		for (i = 0; i < NDKMAP; i++) {
			/* Check for ufs style mount devices */
			(void) snprintf(block_dev_name, PATH_MAX,
			    "%s%d", tmp_name, i);

			if (strcmp(mntp->mnt_special, block_dev_name) == 0) {
				if (flag) {
					if (my_umount(mntp->mnt_mountp) < 0) {
						(void) fclose(fp);
						return (-1);
					}
					unmounted = 1;
				} else {
					(void) fclose(fp);
					return (-1);
				}
				/* Skip to next entry */
				continue;
			}

			/* Try for :1 -> :24 for pcfs */

			for (j = 1; j < 24; j++) {
				(void) snprintf(block_dev_name, PATH_MAX,
				    "%s%d:%d", tmp_name, i, j);

				if (strcmp(mntp->mnt_special,
				    block_dev_name) == 0) {
					if (flag) {
						if (my_umount(mntp->mnt_mountp)
						    < 0) {
							(void) fclose(fp);
							return (-1);
						}
						unmounted = 1;
					} else {
						(void) fclose(fp);
						return (-1);
					}
					/* Skip to next entry */
					continue;
				}
				(void) snprintf(block_dev_name, PATH_MAX,
				    "%s%d:%c", tmp_name, i, 'b' + j);

				if (strcmp(mntp->mnt_special,
				    block_dev_name) == 0) {
					if (flag) {
						if (my_umount(mntp->mnt_mountp)
						    < 0) {
							(void) fclose(fp);
							return (-1);
						}
						unmounted = 1;
					} else {
						(void) fclose(fp);
						return (-1);
					}
					/* Skip to next entry */
					continue;
				}
			}
		}

	}

	if (unmounted)
		return (1);
	return (0);
}

/*
 * This routine checks if a device has mounted partitions. The
 * device name is assumed to be /dev/rdiskette. So, this can
 * be used for Floppy controllers
 * Returns
 *	 0 : if not mounted
 *	 1 : if successfully unmounted
 *	-1 : Any error or unmount failed
 */

int32_t
check_and_unmount_floppy(int32_t fd, int32_t flag)
{
	FILE	*fp = NULL;
	int32_t	mfd;
	struct dk_cinfo dkinfo, dkinfo_tmp;
	struct mnttab	mnt_record;
	struct mnttab	*mp = &mnt_record;
	struct stat	stbuf;
	char	raw_device[PATH_MAX];
	int32_t	found = 0;


	if (ioctl(fd, DKIOCINFO, &dkinfo) < 0) {
		return (-1);
	}

	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		PERROR("Could not open /etc/mnttab");
		(void) close(fd);
		exit(3);
	}

	while (getmntent(fp, mp) == 0) {
		if (strstr(mp->mnt_special, "/dev/fd") == NULL &&
		    strstr(mp->mnt_special, "/dev/disket") == NULL &&
		    strstr(mp->mnt_special, "/dev/c") == NULL) {
			continue;
		}

		(void) strcpy(raw_device, "/dev/r");
		(void) strcat(raw_device, mp->mnt_special + strlen("/dev/"));


		/*
		 * Attempt to open the device.	If it fails, skip it.
		 */

		/* Turn on the privileges. */
		(void) __priv_bracket(PRIV_ON);

		mfd = open(raw_device, O_RDWR | O_NDELAY);

		/* Turn off the privileges. */
		(void) __priv_bracket(PRIV_OFF);

		if (mfd < 0) {
			continue;
		}

		/*
		 * Must be a character device
		 */
		if (fstat(mfd, &stbuf) < 0 || !S_ISCHR(stbuf.st_mode)) {
			(void) close(mfd);
			continue;
		}
		/*
		 * Attempt to read the configuration info on the disk.
		 */
		if (ioctl(mfd, DKIOCINFO, &dkinfo_tmp) < 0) {
			(void) close(mfd);
			continue;
		}
		/*
		 * Finished with the opened device
		 */
		(void) close(mfd);

		/*
		 * If it's not the disk we're interested in, it doesn't apply.
		 */
		if (dkinfo.dki_ctype != dkinfo_tmp.dki_ctype ||
		    dkinfo.dki_cnum != dkinfo_tmp.dki_cnum ||
		    dkinfo.dki_unit != dkinfo_tmp.dki_unit) {
				continue;
		}
		/*
		 * It's a mount on the disk we're checking.  If we are
		 * checking whole disk, then we found trouble.	We can
		 * quit searching.
		 */

		if (flag) {
			if (my_umount(mp->mnt_mountp) < 0) {
				return (-1);
			}
			found = 1;
		} else {
			return (-1);
		}
	}
	return (found);
}


int32_t
my_open(char *device_name, int32_t flags)
{
	char *real_name;
	char *nm;
	char tmp_path_name[PATH_MAX];
	struct stat stat_buf;
	int32_t ret_val;
	int32_t fd;
	int32_t have_read_priv = 0;
	DIR *dirp;
	struct dirent *dp;

	DPRINTF1("Device name %s\n", device_name);

	if ((nm = volmgt_symname(device_name)) == NULL) {
		DPRINTF("path not managed\n");
		real_name = media_findname(device_name);
	} else {
		DPRINTF1("path managed as %s\n", nm);
		real_name = media_findname(nm);
		DPRINTF1("real name %s\n", real_name);
	}

	if (real_name == NULL)
		return (-1);

	(void) strcpy(tmp_path_name, real_name);
	ret_val = stat(tmp_path_name, &stat_buf);
	if (ret_val < 0) {
		PERROR("Could not stat");
		return (-1);
	}
	if (S_ISDIR(stat_buf.st_mode)) {

		/*
		 * Open the directory and look for the
		 * first non '.' entry.
		 * Since raw_read and raw_writes are used, we don't
		 * need to access the backup slice.
		 * For PCMCIA Memory cards, raw_read and raw_writes are
		 * not supported, but that is not a problem as, only slice2
		 * is allowed on PCMCIA memory cards.
		 */

		/*
		 * First make sure we are operating with a /vol/....
		 * Otherwise it can dangerous,
		 * e.g. rmformat -s /dev/rdsk
		 * We should not look into the directory contents here.
		 */
		if (strncmp(tmp_path_name, "/vol/dev/", strlen("/vol/dev/"))
		    != 0) {
			(void) fprintf(stderr, gettext("The specified device \
is not a raw device.\n"));
			exit(1);
		}

		/* Turn on the privileges. */
		(void) __priv_bracket(PRIV_ON);

		dirp = opendir(tmp_path_name);

		/* Turn off the privileges. */
		(void) __priv_bracket(PRIV_OFF);

		if (dirp == NULL) {
			return (-1);
		}

		/* Turn on the privileges. */
		(void) __priv_bracket(PRIV_ON);
		have_read_priv = 1;

		while ((dp = readdir(dirp)) != NULL) {

			/* Turn off the privileges. */
			(void) __priv_bracket(PRIV_OFF);
			have_read_priv = 0;

			DPRINTF1("Found %s\n", dp->d_name);
			if ((strcmp(dp->d_name, ".") != 0) &&
			    (strcmp(dp->d_name, "..") != 0)) {
				size_t len = strlen(tmp_path_name);

				(void) snprintf(tmp_path_name + len,
				    PATH_MAX - len, "/%s", dp->d_name);

				DPRINTF1("tmp_pathname is %s\n", tmp_path_name);
				break;
			}

			/* Turn on the privileges. */
			(void) __priv_bracket(PRIV_ON);
			have_read_priv = 1;
		}

		if (have_read_priv) {
			/* drop the file_dac_read privilege */
			(void) __priv_bracket(PRIV_OFF);
			have_read_priv = 0;
		}

		(void) closedir(dirp);
	}


	if (volmgt_running() == 0) {
		/* Turn on privileges. */
		(void) __priv_bracket(PRIV_ON);
		have_read_priv = 1;
	}

	fd = open(tmp_path_name, flags);

	if (have_read_priv) {
		/* Turn off privileges. */
		(void) __priv_bracket(PRIV_OFF);
		have_read_priv = 0;
	}

	DPRINTF1("path opened %s\n", tmp_path_name);

	return (fd);
}

uint64_t
my_atoll(char *ptr)
{
	char *tmp_ptr = ptr;
	int32_t base = 10;
	uint64_t ret_val;

	while (*tmp_ptr) {
		if (isdigit(*tmp_ptr))
			tmp_ptr++;
		else {
			base = 16;
			break;
		}
	}
	tmp_ptr = ptr;
	if (base == 16) {
		if (strlen(tmp_ptr) < 3) {
			return (-1);
		}
		if (*tmp_ptr++ != '0' || (*tmp_ptr != 'x' && *tmp_ptr != 'X')) {
			return (-1);
		}
		tmp_ptr++;
		while (*tmp_ptr) {
			if (isxdigit(*tmp_ptr))
				tmp_ptr++;
			else {
				return (-1);
			}
		}
	}
	ret_val = (uint64_t)strtoull(ptr, (char **)NULL, 0);
	return (ret_val);
}

int32_t
write_sunos_label(int32_t fd, int32_t media_type)
{

	struct extvtoc v_toc;
	int32_t ret;

	(void) memset(&v_toc, 0, sizeof (struct extvtoc));

	/* Initialize the vtoc information */

	if (media_type == SM_FLOPPY) {
		struct fd_char fdchar;
		int32_t mult_factor;

		if (ioctl(fd, FDIOGCHAR, &fdchar) < 0) {
			PERROR("FDIOGCHAR failed");
			return (-1);
		}

		/* SPARC and x86 fd drivers use fdc_medium differently */
#if defined(__sparc)
		mult_factor = (fdchar.fdc_medium) ? 2 : 1;
#elif defined(__x86)
		mult_factor = (fdchar.fdc_medium == 5) ? 2 : 1;
#else
#error  No Platform defined
#endif /* defined(__sparc) */

		/* initialize the vtoc structure */
		v_toc.v_nparts = 3;

		v_toc.v_part[0].p_start = 0;
		v_toc.v_part[0].p_size = (fdchar.fdc_ncyl - 1) * 2 *
		    fdchar.fdc_secptrack * mult_factor;
		v_toc.v_part[1].p_start = (fdchar.fdc_ncyl - 1) * 2 *
		    fdchar.fdc_secptrack * mult_factor;
		v_toc.v_part[1].p_size = 2 * fdchar.fdc_secptrack * mult_factor;

		v_toc.v_part[2].p_start = 0;
		v_toc.v_part[2].p_size = fdchar.fdc_ncyl * 2 *
		    fdchar.fdc_secptrack * mult_factor;

	} else if (media_type == SM_SCSI_FLOPPY) {

		smedia_handle_t handle;
		smmedium_prop_t med_info;
		struct dk_geom dkgeom;


		/*
		 * call smedia_get_medium_property to get the
		 * correct media information, since DKIOCGMEDIAINFO
		 * may fail for unformatted media.
		 */

		handle = smedia_get_handle(fd);
		if (handle == NULL) {
			(void) fprintf(stderr,
			gettext("Failed to get libsmedia handle.\n"));

			(void) close(fd);
			return (-1);
		}


		if (smedia_get_medium_property(handle, &med_info) < 0) {
			(void) fprintf(stderr,
			    gettext("Get medium property failed \n"));

			(void) smedia_release_handle(handle);
			(void) close(fd);
			return (-1);
		}

		/* Fill in our own geometry information */

		dkgeom.dkg_pcyl = med_info.sm_pcyl;
		dkgeom.dkg_ncyl = med_info.sm_pcyl;
		dkgeom.dkg_nhead = med_info.sm_nhead;
		dkgeom.dkg_nsect = med_info.sm_nsect;
		dkgeom.dkg_acyl = 0;
		dkgeom.dkg_bcyl = 0;
		dkgeom.dkg_intrlv = 0;
		dkgeom.dkg_apc = 0;

		/*
		 * Try to set vtoc, if not successful we will
		 * continue to use the faked geometry information.
		 */

		(void) ioctl(fd, DKIOCSGEOM, &dkgeom);

		(void) smedia_release_handle(handle);

		/* we want the same partitioning as used for normal floppies */

		v_toc.v_part[0].p_start = 0;
		v_toc.v_part[0].p_size =  (diskaddr_t)(dkgeom.dkg_ncyl - 1) *
		    dkgeom.dkg_nhead * dkgeom.dkg_nsect;

		v_toc.v_part[1].p_start = (diskaddr_t)(dkgeom.dkg_ncyl - 1) *
		    dkgeom.dkg_nhead * dkgeom.dkg_nsect;
		v_toc.v_part[1].p_size =  dkgeom.dkg_nhead * dkgeom.dkg_nsect;

		v_toc.v_part[2].p_start = 0;
		v_toc.v_part[2].p_size = (diskaddr_t)dkgeom.dkg_ncyl *
		    dkgeom.dkg_nhead * dkgeom.dkg_nsect;

		/* both write_vtoc and DKIOCSVTOC require V_NUMPAR partitions */
		v_toc.v_nparts = V_NUMPAR;

	} else {

		return (0);
	}

	v_toc.v_sanity = VTOC_SANE;
	v_toc.v_version = V_VERSION;

	/*
	 * The label structure is set up for DEV_BSIZE(512 byte) blocks,
	 * even though a medium density diskette has 1024 byte blocks
	 * See dklabel.h for more details.
	 */
	v_toc.v_sectorsz = DEV_BSIZE;

	/* let the fd driver finish constructing the label and writing it. */


	/* Turn on the privileges. */
	(void) __priv_bracket(PRIV_ON);

	ret = write_extvtoc(fd, &v_toc);

	/* Turn off the privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (ret < 0) {
		PERROR("Write vtoc");
		DPRINTF1("Write vtoc failed errno:%d\n", errno);
		return (-1);
	}

	return (0);
}

static void
intr_sig_handler()
{
	char c;

	(void) fprintf(stderr, gettext(global_intr_msg));
	(void) fprintf(stderr,
	    gettext("\nDo you want to stop formatting?(y/n)"));
	(void) fflush(stdout);
	rewind(stdin);
	while ((c = getchar()) == -1)
		;
	if (c == 'y' || c == 'Y') {
		(void) fprintf(stderr, gettext("Format interrupted\n"));
		exit(1);
	} else if (c == 'n' || c == 'N')
		return;
	else {
		(void) fprintf(stderr, gettext("Did not interrupt\n"));
		return;
	}
}

static struct sigaction act, oact;
void
trap_SIGINT(void)
{

	act.sa_handler = intr_sig_handler;
	(void) memset(&act.sa_mask, 0, sizeof (sigset_t));
	act.sa_flags = SA_RESTART; /* | SA_NODEFER; */
	if (sigaction(SIGINT, &act, &oact) < 0) {
		DPRINTF("sigset failed\n");
		return;
	}
}

void
release_SIGINT(void)
{
	if (sigaction(SIGINT, &oact, (struct sigaction *)NULL) < 0) {
		DPRINTF("sigunset failed\n");
		return;
	}
}

int32_t
verify(smedia_handle_t handle, int32_t fd, diskaddr_t start_sector,
    uint32_t nblocks, char *buf,
    int32_t flag, int32_t blocksize, int32_t no_raw_rw)
{
	uint64_t ret;

	DPRINTF("ANALYSE MEDIA \n");


	if ((flag == VERIFY_READ) && (!no_raw_rw)) {

		/* Turn on the privileges. */
		(void) __priv_bracket(PRIV_ON);

		ret = smedia_raw_read(handle, start_sector, buf, nblocks *
		    blocksize);

		/* Turn off the privileges. */
		(void) __priv_bracket(PRIV_OFF);

		if (ret != (nblocks * blocksize))
			return (-1);
		return (0);

	} else if ((flag == VERIFY_WRITE) && (!no_raw_rw)) {

		/* Turn on privileges. */
		(void) __priv_bracket(PRIV_ON);

		ret = smedia_raw_write(handle, start_sector, buf, nblocks *
		    blocksize);

		/* Turn off the privileges. */
		(void) __priv_bracket(PRIV_OFF);

		if (ret != (blocksize * nblocks))
			return (-1);
		return (0);

	} else if ((flag == VERIFY_READ) && (no_raw_rw)) {
		ret = llseek(fd, start_sector * blocksize, SEEK_SET);
		if (ret != start_sector * blocksize) {
			(void) fprintf(stderr, gettext("Seek failed\n"));
			return (-2);
		}

		/* Turn on the privileges. */
		(void) __priv_bracket(PRIV_ON);

		ret = read(fd, buf, nblocks * blocksize);

		/* Turn off the privileges. */
		(void) __priv_bracket(PRIV_OFF);

		if (ret != nblocks * blocksize) {
			return (-1);
		}
		return (0);
	} else if ((flag == VERIFY_WRITE) && (no_raw_rw)) {
		ret = llseek(fd, start_sector * blocksize, SEEK_SET);
		if (ret != start_sector * blocksize) {
			(void) fprintf(stderr, gettext("Seek failed\n"));
			return (-2);
		}

		/* Turn on the privileges. */
		(void) __priv_bracket(PRIV_ON);

		ret = write(fd, buf, nblocks * blocksize);

		/* Turn off the privileges. */
		(void) __priv_bracket(PRIV_OFF);

		if (ret != nblocks * blocksize) {
			return (-1);
		}
		return (0);
	} else {
		DPRINTF("Illegal parameter to verify_analysis!\n");
		return (-1);
	}
}

static int
my_umount(char *mountp)
{
	pid_t	pid;	/* forked proc's pid */
	int	rval;	/* proc's return value */


	/* create a child to unmount the path */

	/* Turn on the privileges */
	(void) __priv_bracket(PRIV_ON);

	pid = fork();

	/* Turn off the privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (pid < 0) {
		PERROR("fork failed");
		exit(0);
	}

	if (pid == 0) {
		/* the child */
		/* get rid of those nasty err messages */
		DPRINTF1("call_unmount_prog: calling %s \n", mountp);

		/* Turn on the priviliges. */
		(void) __priv_bracket(PRIV_ON);

		if (execl("/usr/sbin/umount", "/usr/sbin/umount", mountp,
		    NULL) < 0) {
			perror("exec failed");
			/* Turn off the privileges */
			(void) __priv_bracket(PRIV_OFF);
			exit(-1);
		}
	}

	/* wait for the umount command to exit */
	rval = 0;
	if (waitpid(pid, &rval, 0) == pid) {
		if (WIFEXITED(rval)) {
			if (WEXITSTATUS(rval) == 0) {
				DPRINTF("umount : Success\n");
				return (1);
			}
		}
	}
	return (-1);
}

static int
my_volrmmount(char *real_name)
{
	int pid, rval;

	/* Turn on the privileges. */
	(void) __priv_bracket(PRIV_ON);

	pid = fork();

	/* Turn off the privileges. */
	(void) __priv_bracket(PRIV_OFF);

	/* create a child to unmount the path */
	if (pid < 0) {
		PERROR("fork failed");
		exit(0);
	}

	if (pid == 0) {
		/* the child */
		/* get rid of those nasty err messages */
		DPRINTF1("call_unmount_prog: calling %s \n",
		    "/usr/bin/volrmmount");

		/* Turn on the privileges. */
		(void) __priv_bracket(PRIV_ON);
		if (execl("/usr/bin/volrmmount", "/usr/bin/volrmmount", "-e",
		    real_name, NULL) < 0) {
			PERROR("volrmmount exec failed");
			/* Turn off the privileges */
			(void) __priv_bracket(PRIV_OFF);
			exit(-1);
		}
	} else if (waitpid(pid, &rval, 0) == pid) {
		if (WIFEXITED(rval)) {
			if (WEXITSTATUS(rval) == 0) {
				DPRINTF("volrmmount: Success\n");
				return (1);
			}
		}
	}
	return (-1);
}

int
find_device(int defer, char *tmpstr)
{
	DIR *dir;
	struct dirent *dirent;
	char sdev[PATH_MAX], dev[PATH_MAX], *pname;
	device_t *t_dev;
	int removable = 0;
	int device_type = 0;
	int hotpluggable = 0;
	struct dk_minfo mediainfo;
	static int found = 0;

	dir = opendir("/dev/rdsk");
	if (dir == NULL)
		return (-1);

	total_devices_found = 0;
	while ((dirent = readdir(dir)) != NULL) {
		if (dirent->d_name[0] == '.') {
			continue;
		}
		(void) snprintf(sdev, PATH_MAX, "/dev/rdsk/%s",
		    dirent->d_name);
#ifdef sparc
		if (!strstr(sdev, "s2")) {
			continue;
		}
#else /* x86 */
		if (vol_running) {
			if (!(strstr(sdev, "s2") || strstr(sdev, "p0"))) {
				continue;
			}
		} else {
			if (!strstr(sdev, "p0")) {
				continue;
			}
		}
#endif
		if (!lookup_device(sdev, dev)) {
			continue;
		}
		if ((t_dev = get_device(NULL, dev)) == NULL) {
			continue;
		}
		total_devices_found++;

		if ((!defer) && !found) {
			char *sn, *tmpbuf;
			/*
			 * dev_name is an optional command line input.
			 */
			if (dev_name) {
				if (strstr(dirent->d_name, tmpstr)) {
					found = 1;
				} else if (!vol_running) {
					continue;
				}
			}
			/*
			 * volmgt_symname() returns NULL if the device
			 * is not managed by volmgt.
			 */
			sn = volmgt_symname(sdev);

			if (vol_running && (sn != NULL)) {
				if (strstr(sn, "dev") == NULL) {
					tmpbuf = (char *)my_zalloc(PATH_MAX);
					(void) strcpy(tmpbuf,
					    "/vol/dev/aliases/");
					(void) strcat(tmpbuf, sn);
					free(sn);
					sn = tmpbuf;
				}
				if (dev_name && !found) {
					if (!strstr(tmpbuf, tmpstr)) {
						continue;
					} else {
						found = 1;
					}
				}
			}

			/*
			 * Get device type information for CD/DVD devices.
			 */
			if (is_cd(dev)) {
				if (check_device(t_dev,
				    CHECK_DEVICE_IS_DVD_WRITABLE)) {
					device_type = DK_DVDR;
				} else if (check_device(t_dev,
				    CHECK_DEVICE_IS_DVD_READABLE)) {
					device_type = DK_DVDROM;
				} else if (check_device(t_dev,
				    CHECK_DEVICE_IS_CD_WRITABLE)) {
					device_type = DK_CDR;
				} else {
					device_type = DK_CDROM;
				}
			} else {
				device_type = ioctl(t_dev->d_fd,
				    DKIOCGMEDIAINFO, &mediainfo);
				if (device_type < 0)
					device_type = 0;
				else
					device_type = mediainfo.dki_media_type;
			}

			if (!ioctl(t_dev->d_fd, DKIOCREMOVABLE, &removable) &&
			    !ioctl(t_dev->d_fd, DKIOCHOTPLUGGABLE,
			    &hotpluggable)) {
				if (removable || hotpluggable) {
					removable_found++;
					pname = get_physical_name(sdev);
					if (sn) {
						(void) printf("  %4d. "
						    "Volmgt Node: %s\n",
						    removable_found, sn);
						(void) printf("        "
						    "Logical Node: %s\n", sdev);
						(void) printf("        "
						    "Physical Node: %s\n",
						    pname);
					} else {
						(void) printf("  %4d. "
						    "Logical Node: %s\n",
						    removable_found, sdev);
						(void) printf("        "
						    "Physical Node: %s\n",
						    pname);
					}
					(void) printf("        Connected "
					    "Device: %-8.8s %-16.16s "
					    "%-4.4s\n",
					    &t_dev->d_inq[8],
					    &t_dev->d_inq[16],
					    &t_dev->d_inq[32]);
					(void) printf("        Device "
					    "Type: ");
				} else
					continue;
			} else
				continue;

			switch (device_type) {
				case DK_CDROM:
					(void) printf("CD Reader\n");
					break;
				case DK_CDR:
				case DK_CDRW:
					(void) printf("CD Reader/Writer\n");
					break;
				case DK_DVDROM:
					(void) printf("DVD Reader\n");
					break;
				case DK_DVDR:
				case DK_DVDRAM:
					(void) printf("DVD Reader/Writer\n");
					break;
				case DK_FIXED_DISK:
					if (strstr((const char *)
					    &t_dev->d_inq[16], "FD") ||
					    strstr((const char *)
					    &t_dev->d_inq[16], "LS-120"))
						(void) printf("Floppy "
						    "drive\n");
					else
						(void) printf("Removable\n");
					break;
				case DK_FLOPPY:
					(void) printf("Floppy drive\n");
					break;
				case DK_ZIP:
					(void) printf("Zip drive\n");
					break;
				case DK_JAZ:
					(void) printf("Jaz drive\n");
					break;
				default:
					(void) printf("<Unknown>\n");
					DPRINTF1("\t   %d\n", device_type);
					break;
			}
			get_media_info(t_dev, sdev, pname, sn);
		}
		fini_device(t_dev);
	}

	(void) closedir(dir);
	return (removable_found);
}

/*
 * Returns a device_t handle for a node returned by lookup_device()
 * and takes the user supplied name and stores it inside the node.
 */
static device_t *
get_device(char *user_supplied, char *node)
{
	device_t *dev;
	int fd;
	char devnode[PATH_MAX];
	int size;

	/*
	 * we need to resolve any link paths to avoid fake files
	 * such as /dev/rdsk/../../export/file.
	 */
	size = resolvepath(node, devnode, PATH_MAX);
	if ((size <= 0) || (size >= (PATH_MAX - 1)))
		return (NULL);

	/* resolvepath may not return a null terminated string */
	devnode[size] = '\0';


	/* the device node must be in /devices/ or /vol/dev/rdsk */

	if ((strncmp(devnode, "/devices/", 9) != 0) &&
	    (strncmp(devnode, "/vol/dev/rdsk", 13) != 0))
		return (NULL);

	/* Turn on the privileges. */
	(void) __priv_bracket(PRIV_ON);

	/*
	 * Since we are currently running with the user euid it is
	 * safe to try to open the file without checking access.
	 */

	fd = open(devnode, O_RDONLY|O_NDELAY);

	/* Turn off the privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (fd < 0) {
		return (NULL);
	}

	dev = (device_t *)my_zalloc(sizeof (device_t));

	dev->d_node = (char *)my_zalloc(strlen(devnode) + 1);
	(void) strcpy(dev->d_node, devnode);

	dev->d_fd = fd;

	dev->d_inq = (uchar_t *)my_zalloc(INQUIRY_DATA_LENGTH);

	/* Turn on privileges. */
	(void) __priv_bracket(PRIV_ON);
	if (!inquiry(fd, dev->d_inq)) {
		DPRINTF1("USCSI ioctl failed %d\n",
		    uscsi_error);
		free(dev->d_inq);
		free(dev->d_node);
		(void) close(dev->d_fd);
		free(dev);
		/* Turn off privileges. */
		(void) __priv_bracket(PRIV_OFF);
		return (NULL);
	}
	/* Turn off privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (user_supplied) {
		dev->d_name = (char *)my_zalloc(strlen(user_supplied) + 1);
		(void) strcpy(dev->d_name, user_supplied);
	}
	return (dev);
}

/*
 * Check for device specific characteristics.
 */
int
check_device(device_t *dev, int cond)
{
	uchar_t page_code[4];

	/* Look at the capabilities page for this information */
	if (cond & CHECK_DEVICE_IS_CD_WRITABLE) {
		if (get_mode_page(dev->d_fd, 0x2a, 0, 4, page_code) &&
		    (page_code[3] & 1)) {
			return (1);
		}
	}

	if (cond & CHECK_DEVICE_IS_DVD_WRITABLE) {
		if (get_mode_page(dev->d_fd, 0x2a, 0, 4, page_code) &&
		    (page_code[3] & 0x10)) {
			return (1);
		}
	}

	if (cond & CHECK_DEVICE_IS_DVD_READABLE) {
		if (get_mode_page(dev->d_fd, 0x2a, 0, 4, page_code) &&
		    (page_code[2] & 0x8)) {
			return (1);
		}
	}

	return (0);
}

/*
 * Builds an open()able device path from a user supplied node which can be
 * of the * form of /dev/[r]dsk/cxtxdx[sx] or cxtxdx[sx] or volmgt-name like
 * cdrom[n].
 * Returns the path found in 'found' and returns 1. Otherwise returns 0.
 */
int
lookup_device(char *supplied, char *found)
{
	struct stat statbuf;
	int fd;
	char tmpstr[PATH_MAX];

	/* Turn on privileges */
	(void) __priv_bracket(PRIV_ON);

	/* If everything is fine and proper, no need to analyze */
	if ((stat(supplied, &statbuf) == 0) && S_ISCHR(statbuf.st_mode) &&
	    ((fd = open(supplied, O_RDONLY|O_NDELAY)) >= 0)) {
		(void) close(fd);
		(void) strlcpy(found, supplied, PATH_MAX);
		/* Turn off privilege */
		(void) __priv_bracket(PRIV_OFF);
		return (1);
	}

	/* Turn off privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (strncmp(supplied, "/dev/rdsk/", 10) == 0)
		return (vol_lookup(supplied, found));
	if (strncmp(supplied, "/dev/dsk/", 9) == 0) {
		(void) snprintf(tmpstr, PATH_MAX, "/dev/rdsk/%s",
		    (char *)strrchr(supplied, '/'));

		if ((fd = open(tmpstr, O_RDONLY|O_NDELAY)) >= 0) {
			(void) close(fd);
			(void) strlcpy(found, supplied, PATH_MAX);
			return (1);
		}
		if ((access(tmpstr, F_OK) == 0) && vol_running)
			return (vol_lookup(tmpstr, found));
		else
			return (0);
	}
	if ((strncmp(supplied, "cdrom", 5) != 0) &&
	    (strlen(supplied) < 32)) {
		(void) snprintf(tmpstr, sizeof (tmpstr), "/dev/rdsk/%s",
		    supplied);
		if (access(tmpstr, F_OK) < 0) {
			(void) strcat(tmpstr, "s2");
		}
		if ((fd = open(tmpstr, O_RDONLY|O_NDELAY)) >= 0) {
			(void) close(fd);
			(void) strlcpy(found, tmpstr, PATH_MAX);
			return (1);
		}
		if ((access(tmpstr, F_OK) == 0) && vol_running)
			return (vol_lookup(tmpstr, found));
	}
	return (vol_name_to_dev_node(supplied, found));
}

int
is_cd(char *node)
{
	int fd;
	struct dk_cinfo cinfo;

	fd = open(node, O_RDONLY|O_NDELAY);
	if (fd < 0)
		return (0);
	if (ioctl(fd, DKIOCINFO, &cinfo) < 0) {
		(void) close(fd);
		return (0);
	}
	if (cinfo.dki_ctype != DKC_CDROM)
		return (0);
	return (1);
}

void
print_header(void)
{
	/* l10n_NOTE : Column spacing should be kept same */
	(void) printf(gettext("    Node			       "
	    "Connected Device"));
	/* l10n_NOTE : Column spacing should be kept same */
	(void) printf(gettext("			Device type\n"));
	(void) printf(
	    "---------------------------+---------------------------");
	(void) printf("-----+----------------\n");
}

void
print_divider(void)
{
	(void) printf(
	    "---------------------------+---------------------------");
	(void) printf("-----+----------------\n");
}

static void
fini_device(device_t *dev)
{
	free(dev->d_inq);
	free(dev->d_node);
	(void) close(dev->d_fd);
	if (dev->d_name)
		free(dev->d_name);
	free(dev);
}

void *
my_zalloc(size_t size)
{
	void *ret;

	ret = malloc(size);
	if (ret == NULL) {

		/* Lets wait a sec. and try again */
		if (errno == EAGAIN) {
			(void) sleep(1);
			ret = malloc(size);
		}

		if (ret == NULL) {
			(void) err_msg("%s\n", gettext(strerror(errno)));
			(void) err_msg(gettext(
			    "Memory allocation failure, Exiting...\n"));
			exit(1);
		}
	}
	(void) memset(ret, 0, size);
	return (ret);
}

static int
vol_name_to_dev_node(char *vname, char *found)
{
	struct stat statbuf;
	char *p1;
	int i;

	if (vname == NULL)
		return (0);
	if (vol_running)
		(void) volmgt_check(vname);
	p1 = media_findname(vname);
	if (p1 == NULL)
		return (0);
	if (stat(p1, &statbuf) < 0) {
		free(p1);
		return (0);
	}
	if (S_ISDIR(statbuf.st_mode)) {
		for (i = 0; i < 16; i++) {
			(void) snprintf(found, PATH_MAX, "%s/s%d", p1, i);
			if (access(found, F_OK) >= 0)
				break;
		}
		if (i == 16) {
			free(p1);
			return (0);
		}
	} else {
		(void) strlcpy(found, p1, PATH_MAX);
	}
	free(p1);
	return (1);
}

/*
 * Searches for volume manager's equivalent char device for the
 * supplied pathname which is of the form of /dev/rdsk/cxtxdxsx
 */
static int
vol_lookup(char *supplied, char *found)
{
	char tmpstr[PATH_MAX], tmpstr1[PATH_MAX], *p;
	int i, ret;

	(void) strlcpy(tmpstr, supplied, PATH_MAX);
	if ((p = volmgt_symname(tmpstr)) == NULL) {
		if (strstr(tmpstr, "s2") != NULL) {
			*((char *)(strrchr(tmpstr, 's') + 1)) = 0;
			for (i = 0; i < 16; i++) {
				(void) snprintf(tmpstr1, PATH_MAX, "%s%d",
				    tmpstr, i);
				if ((p = volmgt_symname(tmpstr1)) != NULL)
					break;
			}
		} else if (strstr(tmpstr, "p0") != NULL) {
			*((char *)(strrchr(tmpstr, 'p') + 1)) = 0;
			for (i = 0; i < 5; i++) {
				(void) snprintf(tmpstr1, PATH_MAX, "%s%d",
				    tmpstr, i);
				if ((p = volmgt_symname(tmpstr1)) != NULL)
					break;
			}
		} else
			return (0);
		if (p == NULL)
			return (0);
	}

	ret = vol_name_to_dev_node(p, found);
	free(p);
	return (ret);
}

/*PRINTFLIKE1*/
void
err_msg(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
}

int
inquiry(int fd, uchar_t *inq)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = INQUIRY_CMD;
	scmd->uscsi_cdb[4] = INQUIRY_DATA_LENGTH;
	scmd->uscsi_cdblen = 6;
	scmd->uscsi_bufaddr = (char *)inq;
	scmd->uscsi_buflen = INQUIRY_DATA_LENGTH;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

struct uscsi_cmd *
get_uscsi_cmd(void)
{
	(void) memset(&uscmd, 0, sizeof (uscmd));
	(void) memset(ucdb, 0, 16);
	uscmd.uscsi_cdb = ucdb;
	return (&uscmd);
}

int
uscsi(int fd, struct uscsi_cmd *scmd)
{
	int ret, global_rqsense;
	int retries, max_retries = 5;
	int i;

	/* set up for request sense extensions */
	if (!(scmd->uscsi_flags & USCSI_RQENABLE)) {
		scmd->uscsi_flags |= USCSI_RQENABLE;
		scmd->uscsi_rqlen = RQBUFLEN;
		scmd->uscsi_rqbuf = rqbuf;
		global_rqsense = 1;
	} else {
		global_rqsense = 0;
	}

	/*
	 * The device may be busy or slow and fail with a not ready status.
	 * we'll allow a limited number of retries to give the drive time
	 * to recover.
	 */
	for (retries = 0; retries < max_retries; retries++) {

		scmd->uscsi_status = 0;

		if (global_rqsense)
			(void) memset(rqbuf, 0, RQBUFLEN);

		DPRINTF("cmd:[");
		for (i = 0; i < scmd->uscsi_cdblen; i++)
			DPRINTF1("0x%02x ",
			    (uchar_t)scmd->uscsi_cdb[i]);
		DPRINTF("]\n");

		/*
		 * We need to have root privledges in order to use
		 * uscsi commands on the device.
		 */

		ret = ioctl(fd, USCSICMD, scmd);

		/* maintain consistency in case of sgen */
		if ((ret == 0) && (scmd->uscsi_status == 2)) {
			ret = -1;
			errno = EIO;
		}

		/* if error and extended request sense, retrieve errors */
		if (global_rqsense && (ret < 0) && (scmd->uscsi_status == 2)) {
			/*
			 * The drive is not ready to recieve commands but
			 * may be in the process of becoming ready.
			 * sleep for a short time then retry command.
			 * SENSE/ASC = 2/4 : not ready
			 * ASCQ = 0  Not Reportable.
			 * ASCQ = 1  Becoming ready.
			 */
			if ((SENSE_KEY(rqbuf) == 2) && (ASC(rqbuf) == 4) &&
			    ((ASCQ(rqbuf) == 0) || (ASCQ(rqbuf) == 1))) {
				total_retries++;
				(void) sleep(3);
				continue;
			}

			/*
			 * Device is not ready to transmit or a device reset
			 * has occurred. wait for a short period of time then
			 * retry the command.
			 */
			if ((SENSE_KEY(rqbuf) == 6) && ((ASC(rqbuf) == 0x28) ||
			    (ASC(rqbuf) == 0x29))) {
				(void) sleep(3);
				total_retries++;
				continue;
			}

			DPRINTF3("cmd: 0x%02x ret:%i status:%02x ",
			    (uchar_t)scmd->uscsi_cdb[0], ret,
			    scmd->uscsi_status);
			DPRINTF3(" sense: %02x ASC: %02x ASCQ:%02x\n",
			    (uchar_t)SENSE_KEY(rqbuf),
			    (uchar_t)ASC(rqbuf), (uchar_t)ASCQ(rqbuf));
		}

		/* no errors we'll return */
		break;
	}

	/* store the error status for later debug printing */
	if ((ret < 0) && (global_rqsense)) {
		uscsi_status = scmd->uscsi_status;
		rqstatus = scmd->uscsi_rqstatus;
		rqresid = scmd->uscsi_rqresid;

	}

	DPRINTF1("total retries: %d\n", total_retries);

	return (ret);
}

/*
 * will get the mode page only i.e. will strip off the header.
 */
int
get_mode_page(int fd, int page_no, int pc, int buf_len, uchar_t *buffer)
{
	int ret;
	uchar_t byte2, *buf;
	uint_t header_len, page_len, copy_cnt;

	byte2 = (uchar_t)(((pc << 6) & 0xC0) | (page_no & 0x3f));
	buf = (uchar_t *)my_zalloc(256);

	/* Ask 254 bytes only to make our IDE driver happy */
	ret = mode_sense(fd, byte2, 1, 254, buf);
	if (ret == 0) {
		free(buf);
		return (0);
	}

	header_len = 8 + read_scsi16(&buf[6]);
	page_len = buf[header_len + 1] + 2;

	copy_cnt = (page_len > buf_len) ? buf_len : page_len;
	(void) memcpy(buffer, &buf[header_len], copy_cnt);
	free(buf);

	return (1);
}

int
mode_sense(int fd, uchar_t pc, int dbd, int page_len, uchar_t *buffer)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_buflen = page_len;
	scmd->uscsi_bufaddr = (char *)buffer;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 0xa;
	scmd->uscsi_cdb[0] = MODE_SENSE_10_CMD;
	if (dbd) {
		/* don't return any block descriptors */
		scmd->uscsi_cdb[1] = 0x8;
	}
	/* the page code we want */
	scmd->uscsi_cdb[2] = pc;
	/* allocation length */
	scmd->uscsi_cdb[7] = (page_len >> 8) & 0xff;
	scmd->uscsi_cdb[8] = page_len & 0xff;

	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

uint16_t
read_scsi16(void *addr)
{
	uchar_t *ad = (uchar_t *)addr;
	uint16_t ret;

	ret = ((((uint16_t)ad[0]) << 8) | ad[1]);
	return (ret);
}

/*
 * Allocate space for and return a pointer to a string
 * on the stack.  If the string is null, create
 * an empty string.
 * Use destroy_data() to free when no longer used.
 */
char *
alloc_string(char *s)
{
	char    *ns;

	if (s == (char *)NULL) {
		ns = (char *)my_zalloc(1);
	} else {
		ns = (char *)my_zalloc(strlen(s) + 1);
		(void) strcpy(ns, s);
	}
	return (ns);
}

/*
 * Follow symbolic links from the logical device name to
 * the /devfs physical device name.  To be complete, we
 * handle the case of multiple links.  This function
 * either returns NULL (no links, or some other error),
 * or the physical device name, alloc'ed on the heap.
 *
 * Note that the standard /devices prefix is stripped from
 * the final pathname, if present.  The trailing options
 * are also removed (":c, raw").
 */
static char *
get_physical_name(char *path)
{
	struct stat	stbuf;
	int		i;
	int		level;
	char		*p;
	char		s[MAXPATHLEN];
	char		buf[MAXPATHLEN];
	char		dir[MAXPATHLEN];
	char		savedir[MAXPATHLEN];
	char		*result = NULL;

	if (getcwd(savedir, sizeof (savedir)) == NULL) {
		DPRINTF1("getcwd() failed - %s\n", strerror(errno));
		return (NULL);
	}

	(void) strcpy(s, path);
	if ((p = strrchr(s, '/')) != NULL) {
		*p = 0;
	}
	if (s[0] == 0) {
		(void) strcpy(s, "/");
	}
	if (chdir(s) == -1) {
		DPRINTF2("cannot chdir() to %s - %s\n",
		    s, strerror(errno));
		goto exit;
	}

	level = 0;
	(void) strcpy(s, path);
	for (;;) {
		/*
		 * See if there's a real file out there.  If not,
		 * we have a dangling link and we ignore it.
		 */
		if (stat(s, &stbuf) == -1) {
			goto exit;
		}
		if (lstat(s, &stbuf) == -1) {
			DPRINTF2("%s: lstat() failed - %s\n",
			    s, strerror(errno));
			goto exit;
		}
		/*
		 * If the file is not a link, we're done one
		 * way or the other.  If there were links,
		 * return the full pathname of the resulting
		 * file.
		 */
		if (!S_ISLNK(stbuf.st_mode)) {
			if (level > 0) {
				/*
				 * Strip trailing options from the
				 * physical device name
				 */
				if ((p = strrchr(s, ':')) != NULL) {
					*p = 0;
				}
				/*
				 * Get the current directory, and
				 * glue the pieces together.
				 */
				if (getcwd(dir, sizeof (dir)) == NULL) {
					DPRINTF1("getcwd() failed - %s\n",
					    strerror(errno));
					goto exit;
				}
				(void) strcat(dir, "/");
				(void) strcat(dir, s);
				/*
				 * If we have the standard fixed
				 * /devices prefix, remove it.
				 */
				p = (strstr(dir, DEVFS_PREFIX) == dir) ?
				    dir+strlen(DEVFS_PREFIX) : dir;
				result = alloc_string(p);
			}
			goto exit;
		}
		i = readlink(s, buf, sizeof (buf));
		if (i == -1) {
			DPRINTF2("%s: readlink() failed - %s\n",
			    s, strerror(errno));
			goto exit;
		}
		level++;
		buf[i] = 0;

		/*
		 * Break up the pathname into the directory
		 * reference, if applicable and simple filename.
		 * chdir()'ing to the directory allows us to
		 * handle links with relative pathnames correctly.
		 */
		(void) strcpy(dir, buf);
		if ((p = strrchr(dir, '/')) != NULL) {
			*p = 0;
			if (chdir(dir) == -1) {
				DPRINTF2("cannot chdir() to %s - %s\n",
				    dir, strerror(errno));
				goto exit;
			}
			(void) strcpy(s, p+1);
		} else {
			(void) strcpy(s, buf);
		}
	}

exit:
	if (chdir(savedir) == -1) {
		(void) printf("cannot chdir() to %s - %s\n",
		    savedir, strerror(errno));
	}

	return (result);
}

static void
get_media_info(device_t *t_dev, char *sdev, char *pname, char *sn)
{
	struct dk_cinfo cinfo;
	struct extvtoc vtocinfo;
	float size;
	int32_t fd;
	smedia_handle_t handle;
	struct dk_minfo mediainfo;
	int device_type;

	device_type = ioctl(t_dev->d_fd, DKIOCGMEDIAINFO, &mediainfo);

	/*
	 * Determine bus type.
	 */
	if (!ioctl(t_dev->d_fd, DKIOCINFO, &cinfo)) {
		if (strstr(cinfo.dki_cname, "usb") || strstr(pname, "usb")) {
			(void) printf("\tBus: USB\n");
		} else if (strstr(cinfo.dki_cname, "firewire") ||
		    strstr(pname, "firewire")) {
			(void) printf("\tBus: Firewire\n");
		} else if (strstr(cinfo.dki_cname, "ide") ||
		    strstr(pname, "ide")) {
			(void) printf("\tBus: IDE\n");
		} else if (strstr(cinfo.dki_cname, "scsi") ||
		    strstr(pname, "scsi")) {
			(void) printf("\tBus: SCSI\n");
		} else {
			(void) printf("\tBus: <Unknown>\n");
		}
	} else {
		(void) printf("\tBus: <Unknown>\n");
	}

	/*
	 * Calculate size of media.
	 */
	if (!device_type &&
	    (!ioctl(t_dev->d_fd, DKIOCGMEDIAINFO, &mediainfo))) {
		size = (mediainfo.dki_lbsize*
		    mediainfo.dki_capacity)/(1024.0*1024.0);
		if (size < 1000) {
			(void) printf("\tSize: %.1f MB\n", size);
		} else {
			size = size/1000;
			(void) printf("\tSize: %.1f GB\n", size);
		}
	} else {
		(void) printf("\tSize: <Unknown>\n");
	}

	/*
	 * Print label.
	 */
	if (!device_type && (read_extvtoc(t_dev->d_fd,  &vtocinfo) >= 0)) {
		if (*vtocinfo.v_volume) {
			(void) printf("\tLabel: %s\n", vtocinfo.v_volume);
		} else {
			(void) printf("\tLabel: <None>\n");
		}
	} else {
		(void) printf("\tLabel: <Unknown>\n");
	}

	/*
	 * Acess permissions.
	 */
	if (device_type) {
		(void) printf("\tAccess permissions: <Unknown>\n");
		return;
	}

	(void) fprintf(stdout, gettext("\tAccess permissions: "));
	if (sn) {
		/*
		 * Set dev_name for process_p_flag().
		 */
		dev_name = sn;
		fd = my_open(sn, O_RDONLY|O_NDELAY);
	} else {
		dev_name = sdev;
		fd = my_open(sdev, O_RDONLY|O_NDELAY);
	}
	if (fd < 0)  {
		(void) printf("<Unknown>\n");
		DPRINTF("Could not open device.\n");
		(void) close(fd);
	} else {
		/* register the fd with the libsmedia */
		handle = smedia_get_handle(fd);
		if (handle == NULL) {
			(void) printf("<Unknown>\n");
			DPRINTF("Failed to get libsmedia handle.\n");
			(void) close(fd);
		} else {
			process_p_flag(handle, fd);
		}
	}
	/* Clear dev_name */
	dev_name = NULL;
}
