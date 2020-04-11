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
 * I18N message number ranges
 *  This file: 21000 - 21499
 *  Shared common messages: 1 - 1999
 */

/*
 * Functions to support the download of FCode to PCI HBAs
 * Qlogic ISP21XX/22XX boards: FC100/P single port, ISP2200 dual port
 * and Emulex cards
 */
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <limits.h>
#include <signal.h>
#include <dirent.h>
#include <nl_types.h>
#include <utmpx.h>
#include <sys/mnttab.h>
#include <sys/file.h>
#include <sys/mtio.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/fibre-channel/fcio.h>
#include <stgcom.h>
#include <sys/scsi/adapters/ifpio.h>
#include <libdevinfo.h>
#include "luxadm.h"

/* Error codes - used by the fcode_load_file routine */
#define	FCODE_SUCCESS	    0	/* successful completion */
#define	FCODE_LOAD_FAILURE  1	/* general failure */
#define	FCODE_IOCTL_FAILURE 2	/* FCODE ioctl download failure */

#define	HBA_MAX	128
#define	FCODE_HDR 200
#define	MAX_RETRIES	3
#define	MAX_WAIT_TIME	30

/*
 * EMULEX Fcode attributes
 */
#define	EMULEX_FCODE_VERSION_LENGTH	16
#define	EMULEX_READ_BUFFER_SIZE		128

/* Emulex specific error codes */
#define	EMLX_ERRNO_START	0x100

/* Diagnostic error codes */
#define	EMLX_TEST_FAILED	(EMLX_ERRNO_START + 0)

/* Download image contains bad data */
#define	EMLX_IMAGE_BAD		(EMLX_ERRNO_START + 1)
/* Download image not compatible with current hardware */
#define	EMLX_IMAGE_INCOMPATIBLE	(EMLX_ERRNO_START + 2)
/* Unable to take adapter offline */
#define	EMLX_IMAGE_FAILED	(EMLX_ERRNO_START + 3)
/* Image download failed */
#define	EMLX_OFFLINE_FAILED	(EMLX_ERRNO_START + 4)




/*
 * This is just a random value chosen to identify Sbus Fcodes. Sbus FCode
 * for Ivory is based on a 2200 chip but this value does not reflect that.
 */
#define	SBUS_CHIP_ID	0x1969
#define	IVORY_BUS	"/sbus@"
#define	IVORY_DRVR	"/SUNW,qlc@"

/*	Global variables	*/
static char	fc_trans[] = "SUNW,ifp";	/* fibre channel transport */
static char	fp_trans[] = "SUNW,qlc";	/* fca layer driver	   */
static char	fp_trans_id[] = "fp@";		/* transport layer id	   */
static char	qlgc2100[] = "FC100/P";		/* product name for 2100   */
static char	qlgc2200[] = "ISP2200";		/* product name for 2200   */
static char	qlgc2300[] = "ISP2300";		/* product name for 2300   */
static char	qlgc2312[] = "ISP2312";		/* product name for 2312   */
/*
 * The variable qlgc2200Sbus represents the string which is always the
 * starting string of the version information in an ISP2200 Sbus Fcode.
 */
static char	qlgc2200Sbus[] = "ISP2200 Sbus FC-AL Host Adapter Driver";
static char	pcibus_list[HBA_MAX][PATH_MAX];
/*	Internal functions	*/
static int	q_load_file(int, char *);
static int	q_getbootdev(uchar_t *);
static int	q_getdevctlpath(char *, int *);
static int	q_warn(int);
static int	q_findversion(int, int, uchar_t *, uint16_t *);
static int	q_findfileversion(char *, uchar_t *, uint16_t *, int, int *);
static int	q_findSbusfile(int, int *);
static int	memstrstr(char *, char *, int, int);
static int	fcode_load_file(int, char *, int *);

/*
 * Functions to support Fcode download for Emulex HBAs
 */
static int	emulex_fcodeversion(di_node_t, uchar_t *);
static void	handle_emulex_error(int, char *);

/*
 * Searches for and updates the cards.	This is the "main" function
 * and will give the output to the user by calling the subfunctions.
 * args: FCode file; if NULL only the current FCode version is printed
 */
int
q_qlgc_update(unsigned int verbose, char *file)
/*ARGSUSED*/
{
	int fd, fcode_fd = -1, errnum = 0, devcnt = 0, retval = 0, isSbus = 0;
	int sbus_off;
	uint_t i, fflag = 0;
	uint16_t chip_id = 0, file_id = 0;
	uchar_t fcode_buf[FCODE_HDR];
	static uchar_t	bootpath[PATH_MAX];
	static uchar_t	version[MAXNAMELEN], version_file[MAXNAMELEN];
	char devpath[PATH_MAX], tmppath[PATH_MAX];
	void	(*sigint)(); /* to store default SIGTERM setting */
	static struct	utmpx *utmpp = NULL; /* pointer for getutxent() */
	char *ptr1, *ptr2;
	char phys_path[PATH_MAX];
	/*
	 * The variables port1 and port2 are used to store the bus id
	 * e.g. the bus id for this path:
	 * /devices/sbus@12,0/SUNW,qlc@2,30000/fp@0,0:devctl
	 * is "sbus@12". They are initialized to a random value and are
	 * set such that they are not equal initially.
	 */
	static char port1[MAXNAMELEN] = { 0 };
	static char port2[MAXNAMELEN] = { 0 };

	if (file) {
		fflag++;

		/* check for a valid file */
		if ((fcode_fd = open(file, O_RDONLY)) < 0) {
			(void) fprintf(stderr,
			    MSGSTR(21000, "Error: Could not open %s\n"), file);
			return (1);
		}
		if (read(fcode_fd, fcode_buf, FCODE_HDR) != FCODE_HDR) {
			perror(MSGSTR(21001, "read"));
			(void) close(fcode_fd);
			return (1);
		}

		/*
		 * Check if it's SBUS FCode by calling q_findSbusfile
		 * if it is then isSbus will be 1, if not it will be 0
		 * in case of an error, it will be -1
		 */
		isSbus = q_findSbusfile(fcode_fd, &sbus_off);
		if (isSbus == -1) {
			(void) close(fcode_fd);
			return (1);
		}

		/*
		 * FCode header check - make sure it's PCI FCode
		 * Structure of FCode header (byte# refers to byte numbering
		 * in FCode spec, not the byte# of our fcode_buf buffer):
		 * header	byte 00	   0x55	 prom signature byte one
		 *		byte 01	   0xaa	 prom signature byte two
		 * data		byte 00-03 P C I R
		 * OR
		 * header	byte 32	   0x55
		 *		byte 33	   0xaa
		 * data		byte 60-63 P C I R
		 * The second format with an offset of 32 is used for ifp prom
		 */
		if (!(((fcode_buf[0x00] == 0x55) &&
		    (fcode_buf[0x01] == 0xaa) &&
		    (fcode_buf[0x1c] == 'P') &&
		    (fcode_buf[0x1d] == 'C') &&
		    (fcode_buf[0x1e] == 'I') &&
		    (fcode_buf[0x1f] == 'R')) ||

		    ((fcode_buf[0x20] == 0x55) &&
		    (fcode_buf[0x21] == 0xaa) &&
		    (fcode_buf[0x3c] == 'P') &&
		    (fcode_buf[0x3d] == 'C') &&
		    (fcode_buf[0x3e] == 'I') &&
		    (fcode_buf[0x3f] == 'R')) ||

		    (isSbus))) {
			(void) fprintf(stderr, MSGSTR(21002,
			    "Error: %s is not a valid FC100/P, "
			    "ISP2200, ISP23xx FCode file.\n"),
			    file);
			(void) close(fcode_fd);
			return (1);
		}

		/* check for single user mode */
		while ((utmpp = getutxent()) != NULL) {
			if (strstr(utmpp->ut_line, "run-level") &&
			    (strcmp(utmpp->ut_line, "run-level S") &&
				strcmp(utmpp->ut_line, "run-level 1"))) {
				if (q_warn(1)) {
					(void) endutxent();
					(void) close(fcode_fd);
					return (1);
				}
				break;
			}
		}
		(void) endutxent();

		/* get bootpath */
		if (!q_getbootdev((uchar_t *)&bootpath[0]) &&
		    getenv("_LUX_D_DEBUG") != NULL) {
			(void) fprintf(stdout, "  Bootpath: %s\n", bootpath);
		}
	}
	/*
	 * Get count of, and names of PCI slots with ifp device control
	 * (devctl) nodes.  Search /devices.
	 */
	(void) strcpy(devpath, "/devices");
	if (q_getdevctlpath(devpath, (int *)&devcnt) == 0) {
		(void) fprintf(stdout, MSGSTR(21003,
		"\n  Found Path to %d FC100/P, ISP2200, ISP23xx Devices\n"),
			devcnt);
	} else {
		(void) fprintf(stderr, MSGSTR(21004,
		"Error: Could not get /devices path to FC100/P,"
		"ISP2200, ISP23xx Cards.\n"));
		retval++;
	}

	for (i = 0; i < devcnt; i++) {

		(void) strncpy((char *)phys_path, &pcibus_list[i][0],
				strlen(&pcibus_list[i][0]));
		if (fflag && (strstr((char *)bootpath,
		    strtok((char *)phys_path, ":")) != NULL)) {
			(void) fprintf(stderr,
			    MSGSTR(21005, "Ignoring %s (bootpath)\n"),
			    &pcibus_list[i][0]);
			continue;
		}

		(void) fprintf(stdout,
		MSGSTR(21006, "\n  Opening Device: %s\n"), &pcibus_list[i][0]);
		/* Check if the device is valid */
		if ((fd = open(&pcibus_list[i][0], O_RDWR)) < 0) {
			(void) fprintf(stderr,
			    MSGSTR(21000, "Error: Could not open %s\n"),
			    &pcibus_list[i][0]);
			retval++;
			continue;
		}
		(void) close(fd);
		/*
		 * Check FCode version present on the adapter (at last boot)
		 */
		if (q_findversion(verbose, i, (uchar_t *)&version[0],
		    &chip_id) == 0) {
			if (strlen((char *)version) == 0) {
				(void) fprintf(stdout, MSGSTR(21007,
	"  Detected FCode Version:\tNo version available for this FCode\n"));
			} else {
			(void) fprintf(stdout, MSGSTR(21008,
			    "  Detected FCode Version:\t%s\n"), version);
			}
		} else {
			chip_id = 0x0;
		}

		if (fflag) {
			/*
			 * For ISP2200, Sbus HBA, do just 1 download
			 * for both the ports (dual port HBA)
			 * Here it is assumed that readdir() always
			 * returns the paths in pcibus_list[] in the
			 * sorted order.
			 */
			(void) strcpy(tmppath, pcibus_list[i]);
			if (ptr1 = strstr(tmppath, IVORY_BUS)) {
				if (ptr2 = strstr(ptr1, IVORY_DRVR)) {
					ptr2 = strchr(ptr2, ',');
					if (ptr2 = strchr(++ptr2, ',')) {
						*ptr2 = '\0';
					}
				}
				(void) strcpy(port2, ptr1);
				if (strcmp(port1, port2) == 0) {
				    (void) fprintf(stdout, MSGSTR(21037,
				    "/n New FCode has already been downloaded "
				    "to this ISP2200 SBus HBA Card.\n"
				    "It is sufficient to download to one "
				    "port of the ISP2200 SBus HBA Card. "
				    "Moving on...\n"));
					continue;
				}
			}
			/*
			 * Check version of the supplied FCode file (once)
			 */
			if ((file_id != 0 && version_file != NULL) ||
			    (q_findfileversion((char *)
			    &fcode_buf[0], (uchar_t *)&version_file[0],
			    &file_id, isSbus, &sbus_off) == 0)) {
				(void) fprintf(stdout, MSGSTR(21009,
				    "  New FCode Version:\t\t%s\n"),
				    version_file);
			} else {
				(void) close(fcode_fd);
				return (1);
			}

			/*
			 * Load the New FCode
			 * Give warning if file doesn't appear to be correct
			 *
			 */
			if (chip_id == 0) {
				errnum = 2; /* can't get chip_id */
				retval++;
			} else if (chip_id - file_id != 0) {
				errnum = 3; /* file/card mismatch */
				retval++;
			} else {
				errnum = 0; /* everything is ok */
			}

			if (!q_warn(errnum)) {
				/* Disable user-interrupt Control-C */
				sigint =
				    (void (*)(int)) signal(SIGINT, SIG_IGN);

				/* Load FCode */
				(void) fprintf(stdout, MSGSTR(21010,
				    "  Loading FCode: %s\n"), file);

				if (q_load_file(fcode_fd,
				    &pcibus_list[i][0]) == 0) {
					(void) fprintf(stdout, MSGSTR(21011,
					"  Successful FCode download: %s\n"),
					    &pcibus_list[i][0]);
					(void) strcpy(port1, port2);
				} else {
					(void) fprintf(stderr, MSGSTR(21012,
					"Error: FCode download failed: %s\n"),
							&pcibus_list[i][0]);
					retval++;
				}
				/* Restore SIGINT (user interrupt) setting */
				(void) signal(SIGINT, sigint);
			}
		}
	}
	(void) fprintf(stdout, "  ");
	(void) fprintf(stdout, MSGSTR(125, "Complete\n"));
	if (fcode_fd != -1)
		(void) close(fcode_fd);
	return (retval);
}


/*
 * Retrieve the version banner from the card
 *    uses ioctl: FCIO_FCODE_MCODE_VERSION	FCode revision
 */
static int
q_findversion(int verbose, int index, uchar_t *version, uint16_t *chip_id)
/*ARGSUSED*/
{
	int fd, ntries;
	struct	ifp_fm_version *version_buffer = NULL;
	char	prom_ver[100] = { 0 };
	char	mcode_ver[100] = { 0 };
	fcio_t	fcio;

	if (strstr(&pcibus_list[index][0], fc_trans)) {

	if ((fd = open(&pcibus_list[index][0], O_RDWR)) < 0) {
		(void) fprintf(stderr,
		    MSGSTR(21000, "Error: Could not open %s\n"),
		    &pcibus_list[index][0]);
		return (1);
	}

	if ((version_buffer = (struct ifp_fm_version *)malloc(
		sizeof (struct ifp_fm_version))) == NULL) {
		(void) fprintf(stderr,
		    MSGSTR(21013, "Error: Memory allocation failed\n"));
		(void) close(fd);
		return (1);
	}

	version_buffer->fcode_ver = (char *)version;
	version_buffer->mcode_ver = mcode_ver;
	version_buffer->prom_ver = prom_ver;
	version_buffer->fcode_ver_len = MAXNAMELEN - 1;
	version_buffer->mcode_ver_len = 100;
	version_buffer->prom_ver_len = 100;

	if (ioctl(fd, FCIO_FCODE_MCODE_VERSION, version_buffer) < 0) {
		(void) fprintf(stderr, MSGSTR(21014,
		"Error: Driver interface FCIO_FCODE_MCODE_VERSION failed\n"));
		free(version_buffer);
		(void) close(fd);
		return (1);
	}
	version[version_buffer->fcode_ver_len] = '\0';

	/* Need a way to get card MCODE (firmware) to track certain HW bugs */
	if (getenv("_LUX_D_DEBUG") != NULL) {
		(void) fprintf(stdout, "  Device %i: QLGC chip_id %x\n",
		    index+1, *chip_id);
		(void) fprintf(stdout, "  FCode:%s\n  MCODE:%s\n  PROM:%s\n",
		    (char *)version, mcode_ver, prom_ver);
	}
	free(version_buffer);

	} else if (strstr(&pcibus_list[index][0], fp_trans)) {
		/*
		 * Get the fcode and prom's fw version
		 * using the fp ioctls. Currently, we pass
		 * only the fcode version to the calling function
		 * and ignore the FW version (using the existing
		 * implementation).
		 */

		if ((fd = open(&pcibus_list[index][0], O_RDWR)) < 0) {
			(void) fprintf(stderr,
			    MSGSTR(4511, "Could not open %s\n"),
			    &pcibus_list[index][0]);
			(void) close(fd);
			return (1);
		}
		/* Get the fcode version */
		bzero(version, sizeof (version));
		fcio.fcio_cmd = FCIO_GET_FCODE_REV;
		/* Information read operation */
		fcio.fcio_xfer = FCIO_XFER_READ;
		fcio.fcio_obuf = (caddr_t)version;
		fcio.fcio_olen = MAXNAMELEN;

		for (ntries = 0; ntries < MAX_RETRIES; ntries++) {
			if (ioctl(fd, FCIO_CMD, &fcio) != 0) {
				if ((errno == EAGAIN) &&
				    (ntries+1 < MAX_RETRIES)) {
					/* wait 30 secs */
					(void) sleep(MAX_WAIT_TIME);
					continue;
				}
				(void) close(fd);
				return (L_FCIO_GET_FCODE_REV_FAIL);
			}
			break;
		}
		version[MAXNAMELEN-1] = '\0';
	}

	/* Get type of card from product name in FCode version banner */
	if (strstr((char *)version, qlgc2100)) {
		*chip_id = 0x2100;
	} else if (strstr((char *)version, qlgc2200)) {
		*chip_id = 0x2200;
		if (strstr((char *)version, "Sbus")) {
			*chip_id = SBUS_CHIP_ID;
		}
	} else if (strstr((char *)version, qlgc2300)) {
		*chip_id = 0x2300;
	} else if (strstr((char *)version, qlgc2312)) {
		*chip_id = 0x2312;
	} else {
		*chip_id = 0x0;
	}

	(void) close(fd);
	return (0);
}

/*
 * Retrieve the version banner and file type (2100 or 2200) from the file
 */
static int
q_findfileversion(char *dl_fcode, uchar_t *version_file, uint16_t *file_id,
		    int isSbus, int *sbus_offset)
{
	int mark;
	int qlc_offset = 0;
	char temp[4] = { 0 };


	/*
	 * Get file version from FCode for 2100 or 2202
	 */
	if (isSbus) {
		*file_id = SBUS_CHIP_ID;
	} else {
		if ((dl_fcode[0x23] == 0x22) ||
		    (dl_fcode[0x23] == 0x23)) {
			*file_id = dl_fcode[0x22] & 0xff;
			*file_id |= (dl_fcode[0x23] << 8) & 0xff00;
		} else {
			*file_id = dl_fcode[0x42] & 0xff;
			*file_id |= (dl_fcode[0x43] << 8) & 0xff00;
		}
	}

	/*
	 * Ok, we're just checking for 2200 here. If it is we need
	 * to offset to find the banner.
	 */
	if ((*file_id == 0x2200) ||
	    (*file_id == 0x2300) ||
	    (*file_id == 0x2312)) {
		qlc_offset = -32;
	}

	/*
	 * If this is an ISP2200 Sbus Fcode file, then search for the string
	 * "ISP2200 FC-AL Host Adapter Driver" in the whole fcode file
	 */
	if (isSbus) {
		*file_id = SBUS_CHIP_ID;
		qlc_offset = *sbus_offset;
		/* Subtract 111 from the offset we add below for PCI Fcodes */
		qlc_offset -= 111;
	}

	/* Banner length varies; grab banner to end of date marker yr/mo/da */
	version_file[0] = '\0';
	for (mark = (111 + qlc_offset); mark < (191 + qlc_offset); mark++) {
		(void) strncpy(temp, (char *)&dl_fcode[mark], 4);
		if ((strncmp(&temp[0], "/", 1) == 0) &&
		    (strncmp(&temp[3], "/", 1) == 0)) {
			(void) strncat((char *)version_file,
			    (char *)&dl_fcode[mark], 6);
			break;
		}
		(void) strncat((char *)version_file, temp, 1);
	}
	return (0);
}

/*
 * Find if the FCode file is a ISP2200 SBUS Fcode file
 */
static int
q_findSbusfile(int fd, int *sbus_offset)
{
	static int file_size;
	char *sbus_info;
	struct stat statinfo;

	if (lseek(fd, 0, SEEK_SET) == -1) {
		perror(MSGSTR(21022, "seek"));
		return (-1);
	}
	if (fstat(fd, &statinfo)) {
		perror(MSGSTR(21023, "fstat"));
		return (-1);
	}
	file_size = statinfo.st_size;

	if ((sbus_info = (char *)malloc(file_size)) == NULL) {
		(void) fprintf(stderr,
		    MSGSTR(21013, "Error: Memory allocation failed\n"));
		return (-1);
	}

	if (read(fd, sbus_info, file_size) < 0) {
		perror(MSGSTR(21001, "read"));
		free(sbus_info);
		return (-1);
	}

	/*
	 * Search for the version string in the whole file
	 */
	if ((*sbus_offset = memstrstr((char *)sbus_info, qlgc2200Sbus,
			    file_size, strlen(qlgc2200Sbus))) != -1) {
		free(sbus_info);
		return (1);
	} else {
		free(sbus_info);
		return (0);
	}
}


/*
 * Build a list of all the devctl entries for all the 2100/2200 based adapters
 */
static int
q_getdevctlpath(char *devpath, int *devcnt)
{
	struct stat	statbuf;
	struct dirent	*dirp = NULL;
	DIR		*dp = NULL;
	char		*ptr = NULL;
	int		err = 0;
	int		testopen;

	if (lstat(devpath, &statbuf) < 0) {
		(void) fprintf(stderr,
		    MSGSTR(21016, "Error: %s lstat() error\n"), devpath);
		return (1);
	}

	if ((strstr(devpath, fc_trans) ||
	    (strstr(devpath, fp_trans_id) && strstr(devpath, fp_trans))) &&
	    strstr(devpath, "devctl")) {
		/* Verify the path is valid */
		if ((testopen = open(devpath, O_RDONLY)) >= 0) {
			(void) close(testopen);
			(void) strcpy(pcibus_list[*devcnt], devpath);
			*devcnt += 1;
			return (0);
		}
	}

	if (S_ISDIR(statbuf.st_mode) == 0) {
		/*
		 * not a directory so
		 * we don't care about it - return
		 */
		return (0);
	}

	/*
	 * It's a directory. Call ourself to
	 * traverse the path(s)
	 */
	ptr = devpath + strlen(devpath);
	*ptr++ = '/';
	*ptr = 0;

	/* Forget the /devices/pseudo/ directory */
	if (strcmp(devpath, "/devices/pseudo/") == 0) {
		return (0);
	}

	if ((dp = opendir(devpath)) == NULL) {
		(void) fprintf(stderr,
		    MSGSTR(21017, "Error: %s Can't read directory\n"), devpath);
		return (1);
	}

	while ((dirp = readdir(dp)) != NULL) {

		if (strcmp(dirp->d_name, ".") == 0 ||
		    strcmp(dirp->d_name, "..") == 0) {
			continue;
		}
		(void) strcpy(ptr, dirp->d_name); /* append name */
		err = q_getdevctlpath(devpath, devcnt);
	}

	if (closedir(dp) < 0) {
		(void) fprintf(stderr,
		MSGSTR(21018, "Error: Can't close directory %s\n"), devpath);
		return (1);
	}
	return (err);
}

/*
 * Get the boot device.	 Cannot load FCode to current boot device.
 * Boot devices under volume management will prompt a warning.
 */
static int
q_getbootdev(uchar_t *bootpath)
{
	struct mnttab mp;
	struct mnttab mpref;
	FILE *fp = NULL;
	static char buf[BUFSIZ];
	char *p = NULL, *p1 = NULL;  /* p = full device, p1 = chunk to rm */
	char *slot = ":devctl";
	char *root = "/";

	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		(void) fprintf(stderr,
		    MSGSTR(21000, "Error: Could not open %s\n"), MNTTAB);
		return (1);
	}

	mntnull(&mpref);
	mpref.mnt_mountp = (char *)root;

	if (getmntany(fp, &mp, &mpref) != 0 ||
	    mpref.mnt_mountp == NULL) {
		(void) fprintf(stderr, MSGSTR(21019,
		    "Error: Cannot get boot device, check %s.\n"), MNTTAB);
		(void) fclose(fp);
		return (1);
	}
	(void) fclose(fp);

	/*
	 * If we can't get a link, we may be dealing with a volume mgr
	 * so give a warning.  If a colon is present, we likely have a
	 * non-local disk or cd-rom, so no warning is necessary.
	 * e.g. /devices/pci@1f,4000/scsi@3/sd@6,0:b (cdrom, no link) or
	 *	storage-e4:/blah/blah remote boot server
	 */
	if (readlink(mp.mnt_special, buf, BUFSIZ) < 0) {
		if (strstr(mp.mnt_special, ":") == NULL) {
			(void) fprintf(stderr, MSGSTR(21020,
	"\nWarning: Cannot read boot device link, check %s.\n"), MNTTAB);
			(void) fprintf(stderr, MSGSTR(21021,
	"Do not upgrade FCode on adapters controlling the boot device.\n"));
		}
		return (1);
	}
	/*
	 * Copy boot device path to bootpath.  First remove leading
	 * path junk (../../..) then if it's an ifp device, chop off
	 * the disk and add the devctl to the end of the path.
	 */
	if (p = strstr(buf, "/devices")) {
		if (strstr(buf, fc_trans) != NULL) {
			p1 = strrchr(p, '/');
			*p1 = '\0';
		}
	}
	(void) strcpy((char *)bootpath, (char *)p);
	if (p1) {
		(void) strcat((char *)bootpath, slot);
	}
	return (0);
}

/*
 * Load FCode to card.
 *    uses ioctl: IFPIO_FCODE_DOWNLOAD
 */
static int
q_load_file(int fcode_fd, char *device)
{
	static int	dev_fd, fcode_size;
	struct stat	stat;
	ifp_download_t	*download_p = NULL;
	fcio_t		fcio;
	uint16_t	file_id = 0;
	uchar_t		*bin;

	if (lseek(fcode_fd, 0, SEEK_SET) == -1) {
		perror(MSGSTR(21022, "seek"));
		(void) close(fcode_fd);
		return (1);
	}
	if (fstat(fcode_fd, &stat) == -1) {
		perror(MSGSTR(21023, "fstat"));
		(void) close(fcode_fd);
		return (1);
	}

	fcode_size = stat.st_size;

	if (strstr(device, fc_trans)) {
		if ((download_p = (ifp_download_t *)malloc(
			sizeof (ifp_download_t) + fcode_size)) == NULL) {
			(void) fprintf(stderr,
			    MSGSTR(21013, "Error: Memory allocation failed\n"));
			(void) close(fcode_fd);
			return (1);
		}
	} else {
		if ((bin = (uchar_t *)malloc(fcode_size)) == NULL) {
			(void) fprintf(stderr,
			    MSGSTR(21013, "Error: Memory allocation failed\n"));
			(void) close(fcode_fd);
			return (1);
		}
	}

	if (strstr(device, fc_trans)) {
		if (read(fcode_fd, download_p->dl_fcode, fcode_size)
		    != fcode_size) {
			perror(MSGSTR(21001, "read"));
			free(download_p);
			(void) close(fcode_fd);
			return (1);
		}
	} else {
		if (read(fcode_fd, bin, fcode_size)
		    != fcode_size) {
			perror(MSGSTR(21001, "read"));
			free(bin);
			(void) close(fcode_fd);
			return (1);
		}
	}


	if ((dev_fd = open(device, O_RDWR|O_EXCL)) < 0) {
		(void) fprintf(stderr,
		    MSGSTR(21000, "Error: Could not open %s\n"), device);
		free(download_p);
		return (1);
	}
	if (strstr(device, fc_trans)) {
		download_p->dl_fcode_len = fcode_size;
		file_id = download_p->dl_fcode[0x42] & 0xff;
		file_id |= (download_p->dl_fcode[0x43] << 8) & 0xff00;
		download_p->dl_chip_id = file_id;
		if (ioctl(dev_fd, IFPIO_FCODE_DOWNLOAD, download_p) < 0) {
			(void) fprintf(stderr, MSGSTR(21024,
		    "Error: Driver interface IFPIO_FCODE_DOWNLOAD failed\n"));
			free(download_p);
			(void) close(dev_fd);
			return (1);
		}
		free(download_p);
	} else if (strstr(device, fp_trans)) {
		fcio.fcio_cmd = FCIO_DOWNLOAD_FCODE;
		/* Information read operation */
		fcio.fcio_xfer = FCIO_XFER_WRITE;
		fcio.fcio_ibuf = (caddr_t)bin;
		fcio.fcio_ilen = fcode_size;

		if (ioctl(dev_fd, FCIO_CMD, &fcio) != 0) {
			(void) fprintf(stderr, MSGSTR(21036,
		    "Error: Driver interface FCIO_DOWNLOAD_FCODE failed\n"));
			free(download_p);
			(void) close(dev_fd);
			return (1);
		}
		free(bin);
	}
	(void) close(dev_fd);
	return (0);
}

/*
 * Issue warning strings and loop for Yes/No user interaction
 *    err# 0 -- we're ok, warn for pending FCode load
 *	   1 -- not in single user mode
 *	   2 -- can't get chip_id
 *	   3 -- card and file do not have same type (2100/2200)
 */
static int
q_warn(int errnum)
{
	char input[1024];
	input[0] = '\0';

	if (errnum == 1) {
		(void) fprintf(stderr, MSGSTR(21025,
		    "\nWarning: System is not in single-user mode.\n"));
		(void) fprintf(stderr, MSGSTR(21026,
	"Loading FCode will reset the adapter and terminate I/O activity\n"));
	} else {
		if (errnum == 2) {
			(void) fprintf(stderr, MSGSTR(21027,
			"  Warning: FCode is missing or existing FCode has"
			" unrecognized version.\n"));
			return (1);
		} else if (errnum == 3) {
			(void) fprintf(stderr, MSGSTR(21028,
			"  Warning: New FCode file version does not match this"
			" board type. Skipping...\n"));
			return (1);
		}
		(void) fprintf(stderr, MSGSTR(21029,
		"\nWARNING!! This program will update the FCode in this"
		" FC100/PCI, ISP2200/PCI, ISP23xx/PCI "
		" and Emulex devices.\n"));
		(void) fprintf(stderr, MSGSTR(21030,
		"This may take a few (5) minutes. Please be patient.\n"));
	}

loop1:
	(void) fprintf(stderr, MSGSTR(21031,
		"Do you wish to continue ? (y/n) "));

	(void) gets(input);

	if ((strcmp(input, MSGSTR(21032, "y")) == 0) ||
			(strcmp(input, MSGSTR(40, "yes")) == 0)) {
		return (0);
	} else if ((strcmp(input, MSGSTR(21033, "n")) == 0) ||
			(strcmp(input, MSGSTR(45, "no")) == 0)) {
		(void) fprintf(stderr,
		    MSGSTR(21034, "Not Downloading FCode\n"));
		return (1);
	} else {
		(void) fprintf(stderr, MSGSTR(21035, "Invalid input\n"));
		goto loop1;
	}
}

/*
 * Name	   : memstrstr
 * Input   : pointer to buf1, pointer to buf2, size of buf1, size of buf2
 * Returns :
 *	Offset of the start of contents-of-buf2 in buf1 if it is found
 *	-1 if buf1 does not contain contents of buf2
 * Synopsis:
 * This function works similar to strstr(). The difference is that null
 * characters in the buffer are treated like any other character. So, buf1
 * and buf2 can have embedded null characters in them.
 */
static int
memstrstr(char *s1, char *s2, int size1, int size2)
{
	int count1, count2;
	char *s1_ptr, *s2_ptr;

	count1 = size1; count2 = size2;
	s1_ptr = s1; s2_ptr = s2;

	if ((size2 == 0)||(size1 == 0))
		return (-1);

	for (count1 = 0; count1 < (size1 - size2 + 1); count1++) {
		if (*s1_ptr++ == *s2_ptr++) {
			if (--count2 == 0) {
				return (count1 - size2 + 1);
			}
			continue;
		}
		count2 = size2;
		s2_ptr = s2;
	}

	return (-1);
}

/*
 * generic fcode load file routine.  given a file descriptor to a fcode file
 * this routine will issue the FCIO_DOWNLOAD_FCODE ioctl to the given
 * device.  Any ioctl errors will be returned in fcio_errno
 *
 * Arguments:
 *	fcode_fd    file descriptor to a fcode file
 *	device	    path to the device we will be downloading the fcode onto
 *	fcio_errno  pointer to an int that will be used to return any errors
 *			back to the caller
 * Retrurn Values:
 *	0	    successful download
 *	>0	    otherwise
 */
static int
fcode_load_file(int fcode_fd, char *device, int *fcio_errno)
{

	fcio_t		fcio;
	static int	dev_fd, fcode_size;
	uchar_t		*bin;
	struct stat	stat;

	if (device == NULL || fcio_errno == NULL) {
		return (FCODE_LOAD_FAILURE);
	}

	*fcio_errno = 0;
	if (lseek(fcode_fd, 0, SEEK_SET) == -1) {
		perror(MSGSTR(21022, "seek"));
		return (FCODE_LOAD_FAILURE);
	}

	if (fstat(fcode_fd, &stat) == -1) {
		perror(MSGSTR(21023, "fstat"));
		return (FCODE_LOAD_FAILURE);
	}

	fcode_size = stat.st_size;

	if ((bin = (uchar_t *)malloc(fcode_size)) == NULL) {
		(void) fprintf(stderr,
		    MSGSTR(21013, "Error: Memory allocation failed\n"));
		return (FCODE_LOAD_FAILURE);
	}

	if (read(fcode_fd, bin, fcode_size)
	    != fcode_size) {
		perror(MSGSTR(21001, "read"));
		free(bin);
		return (FCODE_LOAD_FAILURE);
	}

	if ((dev_fd = open(device, O_RDWR|O_EXCL)) < 0) {
		(void) fprintf(stderr,
		    MSGSTR(21122, "Error: Could not open %s, failed "
			    "with errno %d\n"), device, errno);
		free(bin);
		return (FCODE_LOAD_FAILURE);
	}

	fcio.fcio_cmd = FCIO_DOWNLOAD_FCODE;
	fcio.fcio_xfer = FCIO_XFER_WRITE;
	fcio.fcio_ibuf = (caddr_t)bin;
	fcio.fcio_ilen = fcode_size;

	if (ioctl(dev_fd, FCIO_CMD, &fcio) != 0) {
		(void) close(dev_fd);
		*fcio_errno = fcio.fcio_errno;
		free(bin);
		return (FCODE_IOCTL_FAILURE);
	}

	free(bin);
	(void) close(dev_fd);
	return (FCODE_SUCCESS);
}

/*
 * Searches for and updates the fcode for Emulex HBA cards
 * args: FCode file; if NULL only the current FCode
 * version is printed
 */

int
emulex_update(char *file)
{

	int		fd, retval = 0;
	int		devcnt = 0;
	uint_t		state = 0, fflag = 0;
	static uchar_t	bootpath[PATH_MAX];
	int		fcode_fd = -1;
	static struct	utmpx *utmpp = NULL;
	di_node_t	root;
	di_node_t	node, sib_node, count_node;
	di_minor_t	minor_node;
	char		phys_path[PATH_MAX], *path;
	int		errnum = 0, fcio_errno = 0;
	static uchar_t	prom_ver_data[MAXNAMELEN];
	static char	ver_file[EMULEX_FCODE_VERSION_LENGTH];
	void		(*sigint)();
	int		prop_entries = -1;
	int		*port_data = NULL;

	if (file) {
		/* set the fcode download flag */
		fflag++;

		/* check for a valid file */
		if ((fcode_fd = open(file, O_RDONLY)) < 0) {
			(void) fprintf(stderr,
			    MSGSTR(21118, "Error: Could not open %s, failed "
				    "with errno %d\n"), file, errno);
			return (1);
		}

		/* check for single user mode */
		while ((utmpp = getutxent()) != NULL) {
			if (strstr(utmpp->ut_line, "run-level") &&
				(strcmp(utmpp->ut_line, "run-level S") &&
				strcmp(utmpp->ut_line, "run-level 1"))) {
				if (q_warn(1)) {
					(void) endutxent();
					(void) close(fcode_fd);
					return (1);
				}
				break;
			}
		}
		(void) endutxent();

		/* get bootpath */
		if (!q_getbootdev((uchar_t *)&bootpath[0]) &&
		    getenv("_LUX_D_DEBUG") != NULL) {
			(void) fprintf(stdout, "  Bootpath: %s\n", bootpath);
		}
	}

	/*
	 * Download the Fcode to all the emulex cards found
	 */

	/* Create a snapshot of the kernel device tree */
	if ((root = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		(void) fprintf(stderr, MSGSTR(21114,
		"Error: Could not get /devices path to "
		"Emulex Devices.\n"));
		retval++;
	}

	/* point to first node which matches emulex driver */
	node = di_drv_first_node("emlxs", root);

	if (node == DI_NODE_NIL) {
		/*
		 * Could not find any emulex cards
		 */
		(void) di_fini(root);
		(void) fprintf(stderr, MSGSTR(21115,
		"\n  Found Path to %d Emulex Devices.\n"), devcnt);
		retval++;
	} else {
		count_node = node;
		while (count_node != DI_NODE_NIL) {
			state = di_state(count_node);
			if ((state & DI_DRIVER_DETACHED)
			    != DI_DRIVER_DETACHED) {
				sib_node = di_child_node(count_node);
				while (sib_node != DI_NODE_NIL) {
					state = di_state(sib_node);
					if ((state & DI_DRIVER_DETACHED) !=
					    DI_DRIVER_DETACHED) {
						/* Found an attached node */
						prop_entries =
						    di_prop_lookup_ints(
						    DDI_DEV_T_ANY, sib_node,
						    "port", &port_data);
						if (prop_entries != -1) {
							devcnt++;
							break;
						}
					}

					sib_node = di_sibling_node(sib_node);
				}
			}
			count_node = di_drv_next_node(count_node);
		}
		(void) fprintf(stdout, MSGSTR(21116,
		"\n  Found Path to %d Emulex Devices.\n"), devcnt);
	}


	/*
	 * Traverse device tree to find all emulex cards
	 */
	while (node != DI_NODE_NIL) {

		state = di_state(node);
		if ((state & DI_DRIVER_DETACHED) == DI_DRIVER_DETACHED) {
			node = di_drv_next_node(node);
			continue;
		}

		sib_node = di_child_node(node);
		while (sib_node != DI_NODE_NIL) {
			state = di_state(sib_node);
			if ((state & DI_DRIVER_DETACHED) !=
			    DI_DRIVER_DETACHED) {

				/* Found an attached node */
				prop_entries = di_prop_lookup_ints(
				    DDI_DEV_T_ANY, sib_node,
				    "port", &port_data);
				if (prop_entries != -1) {

					/* Found a node with "port" property */
					minor_node = di_minor_next(sib_node,
					    DI_MINOR_NIL);
					break;
				}
			}
			sib_node = di_sibling_node(sib_node);
		}

		if (sib_node == DI_NODE_NIL) {
			goto try_next;
		}

		path = di_devfs_path(sib_node);
		(void) strcpy(phys_path, "/devices");
		(void) strncat(phys_path, path, strlen(path));
		di_devfs_path_free(path);

		if (fflag && (strstr((char *)bootpath,
		    (char *)phys_path) != NULL)) {
			(void) fprintf(stderr,
			    MSGSTR(21117, "Ignoring %s (bootpath)\n"),
			    phys_path);
			node = di_drv_next_node(node);
			continue;
		}

		if (minor_node) {
			(void) strncat(phys_path, ":", 1);
			(void) strncat(phys_path,
				di_minor_name(minor_node),
				strlen(di_minor_name(minor_node)));
		}

		(void) fprintf(stdout,
				MSGSTR(21107, "\n  Opening Device: %s\n"),
				phys_path);

		/* Check if the device is valid */
		if ((fd = open(phys_path, O_RDWR)) < 0) {
			(void) fprintf(stderr,
			    MSGSTR(21121, "Error: Could not open %s, failed "
				    "with errno %d\n"), phys_path, errno);
			retval++;
			node = di_drv_next_node(node);
			continue;
		}

		(void) close(fd);

		/*
		 * Check FCode version present on the adapter
		 * (at last boot)
		 */
		memset(prom_ver_data, 0, sizeof (prom_ver_data));
		if (emulex_fcodeversion(node, (uchar_t *)&prom_ver_data[0])
		    == 0) {
			errnum = 0;
			if (strlen((char *)prom_ver_data) == 0) {
				(void) fprintf(stdout, MSGSTR(21108,
	"  Detected FCode Version:\tNo version available for this FCode\n"));
			} else {
				(void) fprintf(stdout, MSGSTR(21109,
				    "  Detected FCode Version:\t%s\n"),
				    prom_ver_data);
			}
		} else {
			errnum = 2; /* can't get prom properties */
			retval++;
		}

		if (fflag) {

			memset(ver_file, 0, sizeof (ver_file));
			if (emulex_fcode_reader(fcode_fd, "fcode-version",
				    ver_file, sizeof (ver_file)) == 0) {
				(void) fprintf(stdout, MSGSTR(21110,
					    "  New FCode Version:\t\t%s\n"),
					    ver_file);
			} else {
				di_fini(root);
				(void) close(fcode_fd);
				return (1);
			}

			/*
			 * Load the New FCode
			 * Give warning if file doesn't appear to be correct
			 */
			if (!q_warn(errnum)) {
				/* Disable user-interrupt Control-C */
				sigint =
				    (void (*)(int)) signal(SIGINT, SIG_IGN);
				/* Load FCode */
				(void) fprintf(stdout, MSGSTR(21111,
					"  Loading FCode: %s\n"), file);
				if (fcode_load_file(fcode_fd, phys_path,
					    &fcio_errno) == FCODE_SUCCESS) {
					(void) fprintf(stdout, MSGSTR(21112,
					"  Successful FCode download: %s\n"),
					phys_path);
				} else {
					handle_emulex_error(fcio_errno,
					    phys_path);
					retval++;
				}

				/* Restore SIGINT (user interrupt) setting */
				(void) signal(SIGINT, sigint);
			}
		}

	try_next:
		node = di_drv_next_node(node);
	}

	di_fini(root);
	(void) fprintf(stdout, "  ");
	(void) fprintf(stdout, MSGSTR(125, "Complete\n"));
	if (fcode_fd != -1)
		(void) close(fcode_fd);
	return (retval);

}

/*
 * Retrieve the version from the card.
 *    uses PROM properties
 */
static int
emulex_fcodeversion(di_node_t node, uchar_t *ver) {
	di_prom_prop_t	    promprop;
	di_prom_handle_t    ph;
	char		    *promname;
	uchar_t		    *ver_data = NULL;
	int		    size, found = 0;

	/* check to make sure ver is not NULL */
	if (ver == NULL) {
		return (1);
	}

	if ((ph = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		return (1);
	}

	for (promprop = di_prom_prop_next(ph, node,
		DI_PROM_PROP_NIL);
		promprop != DI_PROM_PROP_NIL;
		promprop = di_prom_prop_next(ph, node, promprop)) {
		if (((promname = di_prom_prop_name(
			promprop)) != NULL) &&
			(strcmp(promname, "fcode-version") == 0)) {
			size = di_prom_prop_data(promprop, &ver_data);
			(void) memset(ver, 0, size);
			(void) memcpy(ver, ver_data, size);
			found = 1;
		}
	}

	if (found) {
		return (0);
	} else {
		return (1);
	}
}

/*
 * Retrieves information from the Emulex fcode
 *
 * Given a pattern, this routine will look for this pattern in the fcode
 * file and if found will return the pattern value
 *
 * possible patterns are manufacturer and fcode-version
 */
int
emulex_fcode_reader(int fcode_fd, char *pattern, char *pattern_value,
    uint32_t pattern_value_size) {
	int32_t i = 0;
	uint32_t n = 0;
	uint32_t b = 0;
	char byte1;
	char byte2;
	char byte3;
	char byte4;
	char buffer1[EMULEX_READ_BUFFER_SIZE];
	char buffer2[EMULEX_READ_BUFFER_SIZE];
	uint32_t plen, image_size;
	struct stat	stat;
	uchar_t		*image;

	/* Check the arguments */
	if (!fcode_fd || !pattern_value || pattern_value_size < 8) {
		return (1);
	}

	if (fstat(fcode_fd, &stat) == -1) {
		perror(MSGSTR(21023, "fstat"));
		return (1);
	}
	image_size = stat.st_size;
	if (image_size < 2) {
		return (1);
	}
	if ((image = (uchar_t *)calloc(image_size, 1)) == NULL) {
		(void) fprintf(stderr,
		    MSGSTR(21013, "Error: Memory allocation failed\n"));
		return (1);
	}

	/* Read the fcode image file */
	lseek(fcode_fd, 0, SEEK_SET);
	read(fcode_fd, image, image_size);

	/* Initialize */
	bzero(buffer1, sizeof (buffer1));
	bzero(buffer2, sizeof (buffer2));
	/* Default pattern_value string */
	strcpy((char *)pattern_value, "<unknown>");
	plen = strlen(pattern);
	n = 0;
	b = 0;
	i = 0;

	/* Search entire image for pattern string */
	while (i <= (image_size - 2)) {
		/* Read next two bytes */
		byte1 = image[i++];
		byte2 = image[i++];

		/* Check second byte first due to endianness */

		/* Save byte in circular buffer */
		buffer1[b++] = byte2;
		if (b == sizeof (buffer1)) {
			b = 0;
		}

		/* Check byte for pattern match */
		if (pattern[n++] != byte2) {
			/* If no match, then reset pattern */
			n = 0;
		} else {
			/*
			 * If complete pattern has been matched then
			 * exit loop
			 */
			if (n == plen) {
				goto found;
			}
		}


		/* Check first byte second due to endianness */
		/* Save byte in circular buffer */
		buffer1[b++] = byte1;
		if (b == sizeof (buffer1)) {
			b = 0;
		}
		/* Check byte for pattern match */
		if (pattern[n++] != byte1) {
			/* If no match, then reset pattern */
			n = 0;
		} else {
			/*
			 * If complete pattern has been matched
			 * then exit loop
			 */
			if (n == plen) {
				goto found;
			}
		}
	}

	/* Not found.  Try again with different endianess */

	/* Initialize */
	bzero(buffer1, sizeof (buffer1));
	bzero(buffer2, sizeof (buffer2));
	n = 0;
	b = 0;
	i = 0;

	/* Search entire 32bit endian image for pattern string */
	while (i <= (image_size - 4)) {
		/* Read next four bytes */
		byte1 = image[i++];
		byte2 = image[i++];
		byte3 = image[i++];
		byte4 = image[i++];

		/* Save byte in circular buffer */
		buffer1[b++] = byte4;
		if (b == sizeof (buffer1)) {
			b = 0;
		}

		/* Check byte for pattern match */
		if (pattern[n++] != byte4) {
			/* If no match, then reset pattern */
			n = 0;
		} else {
			/*
			 * If complete pattern has been matched then exit loop
			 */
			if (n == plen) {
				goto found;
			}
		}

		/* Save byte in circular buffer */
		buffer1[b++] = byte3;
		if (b == sizeof (buffer1)) {
			b = 0;
		}

		/* Check byte for pattern match */
		if (pattern[n++] != byte3) {
			/* If no match, then reset pattern */
			n = 0;
		} else {
			/*
			 * If complete pattern has been matched then exit loop
			 */
			if (n == plen) {
				goto found;
			}
		}

		/* Save byte in circular buffer */
		buffer1[b++] = byte2;
		if (b == sizeof (buffer1)) {
			b = 0;
		}

		/* Check byte for pattern match */
		if (pattern[n++] != byte2) {
			/* If no match, then reset pattern */
			n = 0;
		} else {
			/*
			 * If complete pattern has been matched then exit loop
			 */
			if (n == plen) {
				goto found;
			}
		}

		/* Save byte in circular buffer */
		buffer1[b++] = byte1;
		if (b == sizeof (buffer1)) {
			b = 0;
		}

		/* Check byte for pattern match */
		if (pattern[n++] != byte1) {
			/* If no match, then reset pattern */
			n = 0;
		} else {
			/*
			 * If complete pattern has been matched then exit loop
			 */
			if (n == plen) {
				goto found;
			}
		}
	}

	free(image);
	return (1);

found:
	free(image);

	/* Align buffer and eliminate non-printable characters */
	for (i = 0; i < (sizeof (buffer1)-plen); i++) {
		byte1 = buffer1[b++];
		if (b == sizeof (buffer1)) {
			b = 0;
		}
		/* Zero any non-printable characters */
		if (byte1 >= 33 && byte1 <= 126) {
			buffer2[i] = byte1;
		} else {
			buffer2[i] = 0;
		}
	}

	/*
	 *  Scan backwards for first non-zero string. This will be the
	 *  version string
	 */
	for (i = sizeof (buffer1)-plen-1; i >= 0; i--) {
		if (buffer2[i] != 0) {
			for (; i >= 0; i--) {
				if (buffer2[i] == 0) {
					i++;
					strncpy((char *)pattern_value,
					    &buffer2[i], pattern_value_size);
					break;
				}
			}
			break;
		}
	}
	return (0);
}

/*
 * error handling routine to handle emulex error conditions
 */
static void
handle_emulex_error(int fcio_errno, char *phys_path) {
	if (fcio_errno == EMLX_IMAGE_BAD) {
		fprintf(stderr, MSGSTR(21119,
			    "Error: Fcode download failed.  "
			    "Bad fcode image.\n"));
	} else if (fcio_errno == EMLX_IMAGE_INCOMPATIBLE) {
		fprintf(stderr, MSGSTR(21120,
			    "Error: Fcode download failed.  Fcode is not "
			    "compatible with card.\n"));
	} else {
		(void) fprintf(stderr, MSGSTR(21036,
		    "Error: Driver interface FCIO_DOWNLOAD_FCODE failed\n"));
		(void) fprintf(stderr,
			MSGSTR(21113,
				"Error: FCode download failed: %s\n"),
				phys_path);
	}
}
