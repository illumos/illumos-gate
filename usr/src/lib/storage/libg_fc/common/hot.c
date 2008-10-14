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


/*LINTLIBRARY*/


/*
 *	This module is part of fibre channel interface library.
 */

/*
 * I18N message number ranges
 *  This file: 11000 - 11499
 *  Shared common messages: 1 - 1999
 */

/* #define		_POSIX_SOURCE 1 */

/*	Includes	*/
#include	<stdlib.h>
#include	<stdio.h>
#include	<sys/file.h>
#include	<sys/errno.h>
#include	<sys/types.h>
#include	<sys/param.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<strings.h>
#include	<sys/sunddi.h>
#include	<sys/scsi/scsi.h>
#include	<nl_types.h>
#include	<l_common.h>
#include	<stgcom.h>
#include	<l_error.h>
#include	<g_state.h>

/* Forward declarations */
static int issue_lip(char *, int);


/*	Global variables	*/
extern	uchar_t		g_switch_to_alpa[];
extern	uchar_t		g_sf_alpa_to_switch[];

/*
 * starts a device.
 *
 * RETURNS:
 *	0	 if O.K.
 *	non-zero otherwise
 */
int
g_dev_start(char *drv_path, int verbose)
{
int status;

	if ((drv_path != NULL) && (*drv_path != '\0')) {
		if (status = g_start(drv_path)) {
			return (status);
		}
	}
	return (L_INVALID_PATH);
}



/*
 * stops a device. If the device was
 * reserved by a host, it gets multiple
 * paths to the device and try to stop the
 * device using a different path.
 *
 * Returns:
 *	0 if OK
 *	-1 otherwise
 */

int
g_dev_stop(char *drv_path, struct wwn_list_struct *wwn_list,
						int verbose)
{
int		status, err;
char		*phys_path;
struct dlist	*ml = NULL;


	/* stop the device */
	/* Make the stop NOT immediate, so we wait. */
	if ((drv_path == NULL) || (*drv_path == '\0')) {
		return (L_INVALID_PATH);
	}
	if ((status = g_stop(drv_path, 0)) != 0) {
		/*
		 * In case of reservation conflict,
		 * get the multiple paths and try to
		 * stop the device through the path
		 * which held the reservations.
		 */
		if ((status & ~L_SCSI_ERROR) == STATUS_RESERVATION_CONFLICT) {
			if ((phys_path = g_get_physical_name(drv_path))
								== NULL) {
				return (L_INVALID_PATH);
			}
			if ((err = g_get_multipath(phys_path, &ml,
						wwn_list, verbose)) != 0) {
				return (err);
			}
			while (ml != NULL) {
				if (g_stop(ml->logical_path, 0) == 0) {
					(void) g_free_multipath(ml);
					goto done;
				}
				ml = ml->next;
			}
			(void) g_free_multipath(ml);
		}
		return (status);
	}
done:
	return (0);
}

/*
 * This function is for Leadville devices only
 * It takes as input the actual path on which to issue the LIP and issues it
 *
 * INPUT :
 * Path to the FCA devctl node.
 *
 * For example,
 * /devices/pci@6,2000/pci@2/SUNW,qlc@4/fp@0,0:devctl
 *
 * No SCSI_VHCI paths will work. No checks are done and we'll let the ioctl
 * handle any failures if it is passed in.
 *
 * RETURNS:
 * 0 on Success
 * non-zero otherwise
 */
static int
issue_lip(char *fp_path, int verbose)
{
	int		fp_fd;
	la_wwn_t	wwn;
	fcio_t		fcio;

	/*
	 * open fp path with exclusive path, otherwise,
	 * FCIO_RESET_LINK ioctl will fail with permission
	 * denied error.
	 */
	if ((fp_fd = g_object_open(fp_path, O_RDONLY | O_EXCL)) < 0) {
		return (L_OPEN_PATH_FAIL);
	}

	if (verbose) {
		(void) fprintf(stdout, MSGSTR(11001,
			" Reinitializing the loop at:  %s\n"), fp_path);
	}

	fcio.fcio_cmd = FCIO_RESET_LINK;
	fcio.fcio_xfer = FCIO_XFER_WRITE;
	/*
	 * Reset the local loop here (fcio_ibuf = 0).
	 * Reset a remote loop on the Fabric by
	 * passing its node wwn (fcio_len = sizeof(nwwn)
	 * and fcio_ibuf = (caddr_t)&nwwn) to the port driver.
	 */
	(void) bzero((caddr_t)&wwn, sizeof (wwn));
	fcio.fcio_ilen = sizeof (wwn);
	fcio.fcio_ibuf = (caddr_t)&wwn;
	if (g_issue_fcio_ioctl(fp_fd, &fcio, verbose) != 0) {
		I_DPRINTF(" issue_lip: FCIO_RESET_LINK"
			" ioctl failed: %s\n", fp_path);
		(void) close(fp_fd);
		return (L_FCIO_RESET_LINK_FAIL);
	}
	(void) close(fp_fd);
	return (0);
}

/*
 * Issues the LIP (Loop Intialization Protocol)
 * on a nexus path (in case of socal) or on an
 * fp path (in case of fabric).
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
g_force_lip(char *path_phys, int verbose)
{
int		fd, err = 0, i = 0, pathcnt = 0;
char		nexus_path[MAXPATHLEN], *nexus_path_ptr;
char		*charPtr, fp_path[MAXPATHLEN];
struct stat	stbuf;
uint_t		dev_type;
mp_pathlist_t	pathlist;
mp_pathinfo_t	*pinfop;

	/* return invalid path if path_phys NULL */
	if (path_phys == NULL) {
		return (L_INVALID_PATH);
	}

	/* Make a copy of the arg passed in ... we'll need it down */
	(void) strcpy(fp_path, path_phys);

	if (strstr(path_phys, SCSI_VHCI) != NULL) {

		/*
		 * Its an MPXIO device path
		 *
		 * First, Get a list of all the pHCI for the given vHCI
		 * Then issue a LIP on all the pHCI FCAs that are in the
		 * MDI_PATHINFO_STATE_ONLINE or MDI_PATHINFO_STATE_STANDBY
		 * states.
		 */
		if (g_get_pathlist(fp_path, &pathlist)) {
			return (L_INVALID_PATH);
		}
		for (i = 0; i < pathlist.path_count; i++) {
			pinfop = &pathlist.path_info[i];
			if ((pinfop->path_state ==
				MDI_PATHINFO_STATE_ONLINE) ||
				    (pinfop->path_state ==
					MDI_PATHINFO_STATE_STANDBY)) {
				pathcnt++;
				sprintf(fp_path, "%s%s",
						pinfop->path_hba, FC_CTLR);
				if (issue_lip(fp_path, verbose) != 0) {
					err++;
				}
			}
		}
		free(pathlist.path_info);
		if (err == 0)
			return (0);
		if (err == pathcnt)
			return (L_FCIO_FORCE_LIP_FAIL);
		return (L_FCIO_FORCE_LIP_PARTIAL_FAIL);
	}

	/* Non-MPXIO case */

	if ((dev_type = g_get_path_type(fp_path)) == 0) {
		return (L_INVALID_PATH);
	}

	if (dev_type & FC_FCA_MASK) {
		if (strstr(fp_path, DRV_NAME_SSD) ||
			strstr(fp_path, SES_NAME) ||
			strstr(fp_path, DRV_NAME_ST)) {
			if ((charPtr = strrchr(fp_path, '/')) == NULL) {
				return (L_INVALID_PATH);
			}
			*charPtr = '\0';
			/* append devctl to the path */
			(void) strcat(fp_path, FC_CTLR);
		} else {
			/* should have fp transport node to continue. */
			if (!(dev_type & FC_XPORT_MASK)) {
				return (L_INVALID_PATH_TYPE);
			}
			if (stat(fp_path, &stbuf) < 0) {
				return (L_LSTAT_ERROR);
			}
			if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
				/* append devctl to the path */
				(void) strcat(fp_path, FC_CTLR);
			}
		}
		return (issue_lip(fp_path, verbose));

	} else {	/* for fc4 devices */
		if ((err = g_get_nexus_path(path_phys,
					&nexus_path_ptr)) != 0)
			return (err);

		(void) strcpy(nexus_path, nexus_path_ptr);
		(void) g_destroy_data(nexus_path_ptr);
		P_DPRINTF("  g_force_lip: Force lip on:"
			" Path %s\n", nexus_path);

		/* open driver */
		if ((fd = g_object_open(nexus_path,
				O_NDELAY | O_RDONLY)) == -1)
			return (L_OPEN_PATH_FAIL);

		if (verbose) {
			(void) fprintf(stdout,
					MSGSTR(11000,
					"  Forcing lip (Loop Initialization "
					"Protocol)"
					"\n  on loop at: %s\n"), nexus_path);
		}
		if (ioctl(fd, FCIO_FORCE_LIP) != 0) {
			I_DPRINTF("  FCIO_FORCE_LIP ioctl failed.\n");
			(void) close(fd);
			return (L_FCIO_FORCE_LIP_FAIL);
		}
		(void) close(fd);
	}
	return (0);
}



/*
 * Takes one or more drives offline.
 * If the force flag is supplied then: (1) don't pass the exclusive flag
 * to the acquire routine and (2) allow the offline to fail
 * If any acquire fails, print an error message and continue.
 *
 * RETURNS:
 *	0		iff each offline succeeds
 *	non-zero	otherwise
 */
int
g_offline_drive(struct dlist *dl, int force_flag)
{
devctl_hdl_t		devhdl;


	/* for each drive attempt to take it offline */
	for (; dl != NULL; dl = dl->next) {

		/* attempt to acquire the device */
		if ((devhdl = devctl_device_acquire(dl->dev_path,
				force_flag ? 0 : DC_EXCL)) == NULL) {
			if (errno != EBUSY) {
				P_DPRINTF("%s: Could not acquire"
					" the device: %s\n\n",
					strerror(errno), dl->dev_path);
				continue;
			}
		}
		/* attempt to offline the drive */
		if ((devctl_device_offline(devhdl) != 0) && !force_flag) {
			(void) devctl_release(devhdl);
			return (L_DEV_BUSY);
		}

		/* offline succeeded -- release handle acquired above */
		(void) devctl_release(devhdl);
	}

	return (0);
}



/*
 * Brings one or more drives online.
 * If the force flag is supplied then: (1) don't pass the exclusive
 * flag to the acquire routine and (2) allow the offline to fail
 * If any acquire fails, continue with the next device.
 *
 * RETURNS:
 *	None.
 */
void
g_online_drive(struct dlist *dl, int force_flag)
{
devctl_hdl_t		devhdl;


	while (dl != NULL) {
		if ((devhdl = devctl_device_acquire(dl->dev_path,
					force_flag ? 0 : DC_EXCL)) != NULL) {
			(void) devctl_device_online(devhdl);
			(void) devctl_release(devhdl);
		}
		dl = dl->next;
	}
}



void
g_ll_to_str(uchar_t *wwn_ll, char	*wwn_str)
{
int	j, k, fnib, snib;
uchar_t	c;

	for (j = 0, k = 0; j < 8; j++) {
		c = wwn_ll[j];
		fnib = ((int)(c & 0xf0) >> 4);
		snib = (c & 0x0f);
		if (fnib >= 0 && fnib <= 9)
			wwn_str[k++] = '0' + fnib;
		else if (fnib >= 10 && fnib <= 15)
			wwn_str[k++] = 'a' + fnib - 10;
		if (snib >= 0 && snib <= 9)
			wwn_str[k++] = '0' + snib;
		else if (snib >= 10 && snib <= 15)
			wwn_str[k++] = 'a' + snib - 10;
	}
	wwn_str[k] = '\0';
}



/*
 * Creates a list of nexus paths for each
 * hotpluggable device and sends the list to g_force_lip(),
 * which forces the LIP on each nexus path in the list.
 *
 * RETURNS:
 *	None.
 */
int
g_forcelip_all(struct hotplug_disk_list *disk_list)
{
char		*p;
int		len, ndevs = 0, err = 0;
struct	dlist	*dl;
struct loop_list {	/* adp_name holds full dev path for MPXIO devices */
		char adp_name[MAXPATHLEN];
		struct loop_list *next;
		struct loop_list *prev;
	} *llist_head, *llist_tail, *llist, *llist1;

	llist_head = llist_tail = NULL;

	while (disk_list) {
		if (disk_list->dev_location == SENA) {
			dl = disk_list->seslist;
		} else {
			dl = disk_list->dlhead;
		}
		while (dl != NULL) {
			if (strstr(dl->dev_path, SCSI_VHCI) == NULL) {
				/* non-MPXIO device path */
				if (disk_list->dev_location == SENA) {
				    p = strstr(dl->dev_path, SLASH_SES);
				} else {
				    p = strstr(dl->dev_path, SLSH_DRV_NAME_SSD);
				    if (p == NULL) {
					p = strstr(dl->dev_path,
							SLSH_DRV_NAME_ST);
				    }
				}
				if (p == NULL) {
					P_DPRINTF(
					"  g_forcelip_all: Not able to do"
					" LIP on this path because path "
					"invalid.\n  Path: %s\n", dl->dev_path);
					dl = dl->next;
					continue;
				}
				len = strlen(dl->dev_path) - strlen(p);
			} else {
				/* MPXIO path */
				len = strlen(dl->dev_path);
			}

			/*
			 * Avoid issuing forcelip
			 * on the same HA more than once
			 */
			if (llist_head != NULL) {
				for (llist1 = llist_head; llist1 != NULL;
						llist1 = llist1->next) {
					if (strncmp(llist1->adp_name,
						dl->dev_path, len) == 0) {
						break;
					}
				}
				if (llist1 != NULL) {
					dl = dl->next;
					continue;
				}
			}
			if ((llist = (struct loop_list *)
				g_zalloc(sizeof (struct loop_list))) == NULL)
				return (L_MALLOC_FAILED);
			(void) strncpy(llist->adp_name, dl->dev_path, len);
			llist->adp_name[len] = '\0';
			ndevs++;

			if (llist_head == NULL) {
				llist_head = llist_tail = llist;
			} else {
				llist->prev = llist_tail;
				llist_tail = llist_tail->next = llist;
			}
			dl = dl->next;
		}
		disk_list = disk_list->next;
	}

	while (llist_head) {
		if ((err = g_force_lip(llist_head->adp_name, 0)) != 0) {
			(void) g_destroy_data(llist);
			(void) g_destroy_data(llist_head);
			return (err);
		}
		llist = llist_head;
		llist_head = llist_head->next;
		(void) g_destroy_data((char *)llist);
	}
	(void) sleep(ndevs*10);
	return (0);
}
