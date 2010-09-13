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
 * I18N message number ranges
 *  This file: (not defined yet)
 *  Shared common messages: 1 - 1999
 */

/*
 *	This module is part of the Fibre Channel Interface library.
 */

/* #define		_POSIX_SOURCE 1 */


/*	Includes	*/
#include	<stdlib.h>
#include	<stdio.h>
#include	<sys/file.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/mkdev.h>
#include	<sys/param.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<string.h>
#include	<sys/scsi/scsi.h>
#include	<dirent.h>		/* for DIR */
#include	<sys/vtoc.h>
#include	<nl_types.h>
#include	<strings.h>
#include	<sys/ddi.h>		/* for max */
#include	<fnmatch.h>
#include	<l_common.h>
#include	<stgcom.h>
#include	<l_error.h>
#include	<g_state.h>
#include	<sys/fibre-channel/ulp/fcp_util.h>
#include	<sys/fibre-channel/impl/fc_error.h>
#include	<sys/fibre-channel/impl/fcph.h>
#include	<sys/socalio.h>
#include	<libdevinfo.h>
#include	<libnvpair.h>
#include	<sys/scsi/adapters/scsi_vhci.h>
#include	<errno.h>

/* Some forward declarations of static functions */
static void g_free_pi_list(sv_path_info_t *, uint_t num_paths);
static int get_pathlist(char *, sv_iocdata_t *, int *);
static int stms_path_enable_disable(char *, char *, int);
static int stms_path_enable_disable_all(char *, int);

/*
 * To get lun number of a given device pathname using driver ioctl.
 * This interface is called directly by g_get_lun_number
 *
 * inputs;
 * outputs:
 * returns:
 *    0 - success
 *   !0 - failure
 */
int
g_get_lun_str(char *dev_path, char lunstr[], int path_num)
{
	char		*char_ptr, *charptr1;
	int		fd = 0;
	sv_iocdata_t	ioc;
	char		phci_path[MAXPATHLEN];
	char		client_path[MAXPATHLEN];
	char		paddr[MAXNAMELEN];
	uint_t		num_elem = 0, i;
	sv_path_info_t	*pi = NULL;
	int		retval = 0;
	uint_t		num_paths;

	if (strstr(dev_path, "/devices") == NULL) {
		return (-1);
	}

	num_paths = path_num + 1;
	(void) strcpy(client_path, dev_path + DEV_PREFIX_LEN-1);
	if ((char_ptr = strrchr(client_path, ':')) != NULL) {
		*char_ptr = '\0';
	}

	ioc.client	= client_path;
	ioc.phci	= phci_path;
	ioc.addr	= paddr;
	ioc.buf_elem	= 0;
	ioc.ret_buf	= NULL;
	ioc.ret_elem	= &num_elem;

	if ((fd = g_object_open(VHCI_NODE, O_RDWR)) < 0) {
		return (L_OPEN_PATH_FAIL);
	}

	/* Allocate memory for path info structs */
	pi = (sv_path_info_t *)calloc((size_t)num_paths,
		sizeof (sv_path_info_t));
	ioc.buf_elem = num_paths;
	ioc.ret_buf  = pi;

	/* Allocate memory for getting per path info properties */

	for (i = 0; i < num_paths; i++) {
		pi[i].ret_prop.buf_size = SV_PROP_MAX_BUF_SIZE;
		if (((pi[i].ret_prop.buf =
			malloc(SV_PROP_MAX_BUF_SIZE)) == NULL) ||
			((pi[i].ret_prop.ret_buf_size =
				malloc(sizeof (*pi[i].ret_prop.ret_buf_size)))
				    == NULL)) {
			/* Free memory for per path info properties */
			g_free_pi_list(pi, num_paths);
			(void) close(fd);
			return (-1);
		}
	}

	retval = ioctl(fd, SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO, &ioc);
	if (retval != 0) {
		/* Free memory for per path info properties */
		g_free_pi_list(pi, num_paths);
		(void) close(fd);
		return (retval);
	}

	if (path_num < ioc.buf_elem) {
		charptr1 = strchr(pi[path_num].ret_addr, ',');
		retval = 0;
	} else {
		charptr1 = strchr(pi[0].ret_addr, ',');
		retval = -1;
	}

	if (charptr1 != NULL) {
		charptr1++;
		if (charptr1 != NULL) {
			(void) strcpy(lunstr, charptr1);
		}
	}

	/* Free memory for per path info properties */
	g_free_pi_list(pi, num_paths);
	(void) close(fd);
	return (retval);
}

/*
 * To give the lun number of a given device pathname
 *
 * inputs: physical pathname beginning with /devices
 * outputs: none
 * returns: lun number (if available) or -1 (if not available or
 *          failure)
 */
int
g_get_lun_number(char *path_phys)
{
	char		path0[MAXPATHLEN], lunarr[MAXPATHLEN];
	char		*charptr1, *charptr2, *charptr3;
	int		lunval = 0;

	if ((strstr(path_phys, "/devices")) == NULL) {
		return (-1);
	}

	if (((charptr3 = strstr(path_phys, SLSH_DRV_NAME_SSD)) == NULL) &&
		((charptr3 = strstr(path_phys, SLSH_DRV_NAME_ST)) == NULL)) {
		return (-1);
	}

	(void) strcpy(path0, charptr3);

	if ((charptr2 = strrchr(path0, ':')) != NULL) {
		*charptr2 = '\0';
	}

	if ((charptr1 = strchr(path0, ',')) != NULL) {
		charptr1++;
		if (*charptr1 != '0') {
			(void) strcpy(lunarr, charptr1);
		} else {
			return (0);
		}
	} else if (strstr(path_phys, SCSI_VHCI) != NULL) {
		/* for the time being */
		if (g_get_lun_str(path_phys, lunarr, 0) != 0) {
			return (-1);
		}
	} else {
		return (-1);
	}

	lunval = (int)strtol(lunarr, NULL, 16);

	return (lunval);
}

/*
 * Input - Space for client_path, phci_path and paddr fields of ioc structure
 * need to be allocated by the caller of this routine.
 */
static int
get_pathlist(char *dev_path, sv_iocdata_t *ioc, int *num_paths_to_copy)
{
	char	*physical_path, *physical_path_s;
	int	retval;
	int	fd;
	int	initial_path_count;
	int	current_path_count;
	int 	i;
	char	*delimiter;
	int	malloc_error = 0;
	int 	prop_buf_size;
	int	pathlist_retry_count = 0;

	if (strncmp(dev_path, SCSI_VHCI,
			strlen(SCSI_VHCI)) != NULL) {
		if ((physical_path = g_get_physical_name(dev_path)) == NULL) {
			return (L_INVALID_PATH);
		}
		if (strncmp(physical_path, SCSI_VHCI,
				strlen(SCSI_VHCI)) != NULL) {
			free(physical_path);
			return (L_INVALID_PATH);
		}
	} else {
		if ((physical_path = calloc(1, MAXPATHLEN)) == NULL) {
			return (L_MALLOC_FAILED);
		}
		(void) strcpy(physical_path, dev_path);
	}
	physical_path_s = physical_path;

	/* move beyond "/devices" prefix */
	physical_path += DEV_PREFIX_LEN-1;
	/* remove  :c,raw suffix */
	delimiter = strrchr(physical_path, ':');
	/* if we didn't find the ':' fine, else truncate */
	if (delimiter != NULL) {
		*delimiter = NULL;
	}

	/*
	 * We'll call ioctl SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO
	 * at least twice.  The first time will get the path count
	 * and the size of the ioctl propoerty buffer.  The second
	 * time will get the path_info for each path.
	 *
	 * It's possible that additional paths are added while this
	 * code is running.  If the path count increases between the
	 * 2 ioctl's above, then we'll retry (and assume all is well).
	 */
	(void) strcpy(ioc->client, physical_path);
	ioc->buf_elem = 1;
	ioc->ret_elem = (uint_t *)&(initial_path_count);
	ioc->ret_buf = NULL;

	/* free physical path */
	free(physical_path_s);

	/* 0 buf_size asks driver to return actual size needed */
	/* open the ioctl file descriptor */
	if ((fd = g_object_open(VHCI_NODE, O_RDWR)) < 0) {
		return (L_OPEN_PATH_FAIL);
	}

	retval = ioctl(fd, SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO, ioc);
	if (retval != 0) {
		close(fd);
		return (L_SCSI_VHCI_ERROR);
	}
	prop_buf_size = SV_PROP_MAX_BUF_SIZE;


	while (pathlist_retry_count <= RETRY_PATHLIST) {
		ioc->buf_elem = initial_path_count;
		/* Make driver put actual # paths in variable */
		ioc->ret_elem = (uint_t *)&(current_path_count);

		/*
		 * Allocate space for array of path_info structures.
		 * Allocate enough space for # paths from get_pathcount
		 */
		ioc->ret_buf = (sv_path_info_t *)
				calloc(initial_path_count,
					sizeof (sv_path_info_t));
		if (ioc->ret_buf == NULL) {
			close(fd);
			return (L_MALLOC_FAILED);
		}

		/*
		 * Allocate space for path properties returned by driver
		 */
		malloc_error = 0;
		for (i = 0; i < initial_path_count; i++) {
			ioc->ret_buf[i].ret_prop.buf_size = prop_buf_size;
			if ((ioc->ret_buf[i].ret_prop.buf =
			    (caddr_t)malloc(prop_buf_size)) == NULL) {
				malloc_error = 1;
				break;
			}
			if ((ioc->ret_buf[i].ret_prop.ret_buf_size =
				(uint_t *)malloc(sizeof (uint_t))) == NULL) {
				malloc_error = 1;
				break;
			}
		}
		if (malloc_error == 1) {
			for (i = 0; i < initial_path_count; i++) {
				free(ioc->ret_buf[i].ret_prop.buf);
				free(ioc->ret_buf[i].ret_prop.ret_buf_size);
			}
			free(ioc->ret_buf);
			close(fd);
			return (L_MALLOC_FAILED);
		}

		retval = ioctl(fd, SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO, ioc);
		if (retval != 0) {
			for (i = 0; i < initial_path_count; i++) {
				free(ioc->ret_buf[i].ret_prop.buf);
				free(ioc->ret_buf[i].ret_prop.ret_buf_size);
			}
			free(ioc->ret_buf);
			close(fd);
			return (L_SCSI_VHCI_ERROR);
		}
		if (initial_path_count < current_path_count) {
			/* then a new path was added */
			pathlist_retry_count++;
			initial_path_count = current_path_count;
		} else {
			break;
		}
	}
	/* we are done with ioctl's, lose the fd */
	close(fd);

	/*
	 * Compare the length num elements from the ioctl response
	 *   and the caller's request - use smaller value.
	 *
	 * pathlist_p->path_count now has count returned from ioctl.
	 * ioc.buf_elem has the value the caller provided.
	 */
	if (initial_path_count < current_path_count) {
		/* More paths exist than we allocated space for */
		*num_paths_to_copy = initial_path_count;
	} else {
		*num_paths_to_copy = current_path_count;
	}
return (0);
}

/*
 * To obtain pathlist of a given target device
 *
 * inputs:
 *	dev_path client device path
 *	example: /devices/scsi_vhci/ssd@g280000602200416d6257333030303261:c,raw
 * outputs:
 * 	pathlist_p pathlist structure containing pathinfo node data
 * returns:
 *   0 - success
 *  !0 - failure
 */
int
g_get_pathlist(char *dev_path, struct mp_pathlist *pathlist_p)
{

	sv_iocdata_t	ioc;
	int	retval, caller_ret = 0;
	int	num_paths_to_copy;
	int 	i;
	int 	prop_buf_size;
	char	*path_class_val = NULL;
	char	*temp_addr;
	char	phci_path[MAXPATHLEN];
	char	client_path[MAXPATHLEN];
	char	paddr[MAXNAMELEN];


	ioc.client = client_path;
	ioc.phci = phci_path;
	ioc.addr = paddr;

	if ((caller_ret = get_pathlist(dev_path, &ioc, &num_paths_to_copy))
		!= 0) {
		return (caller_ret);
	}

	pathlist_p->path_count = num_paths_to_copy;
	pathlist_p->path_info = calloc(num_paths_to_copy,
					sizeof (mp_pathinfo_t));

	prop_buf_size = SV_PROP_MAX_BUF_SIZE;

	if (pathlist_p->path_info == NULL) {
		caller_ret = L_MALLOC_FAILED;
		/* force the loop to not run so we free buffers and exit */
		num_paths_to_copy = 0;
	}

	/* get ioctl reponse fields and copy them to caller's buffer */
	for (i = 0; i < num_paths_to_copy; i++) {
		nvlist_t *nvl;

		pathlist_p->path_info[i].path_state =
			ioc.ret_buf[i].ret_state;
		(void) strncpy(pathlist_p->path_info[i].path_hba, DEV_PREFIX,
			DEV_PREFIX_LEN - 1);
		(void) strcat(pathlist_p->path_info[i].path_hba,
			ioc.ret_buf[i].device.ret_phci);
		(void) strcpy(pathlist_p->path_info[i].path_dev,
			ioc.client);

		/*
		 * Check for leading 'w'. The mpxio framework was
		 * incorrectly implemented to skip 'w' in mdi_pi_get_addr().
		 * Since the leading 'w' is fibre-channel specific, we
		 * do it here to remove fibre-channel specific behavior
		 * from the mpxio framework.
		 */
		temp_addr = ioc.ret_buf[i].ret_addr;
		if (*temp_addr == 'w') {
			temp_addr++;
		}
		(void) strcpy(pathlist_p->path_info[i].path_addr, temp_addr);

		/* use nvlist_ calls to extract properties from retbuf */
		retval = nvlist_unpack(ioc.ret_buf[i].ret_prop.buf,
					prop_buf_size, &nvl, 0);
		if (retval != 0) { /* ??? same retcode */
			(void) strcpy(pathlist_p->path_info[i].path_class,
				"UNKNOWN PROB");
		} else {
			retval = nvlist_lookup_string(nvl, "path-class",
				&path_class_val);
			if (retval != 0) {
			(void) strcpy(pathlist_p->path_info[i].path_class,
				"UNKNOWN");
			} else {
				(void) strcpy(pathlist_p->path_info[i].
					path_class,
					path_class_val);
			}
			nvlist_free(nvl);
		}
	}

	/* free everything we alloced */
	for (i = 0; i < ioc.buf_elem; i++) {
		free(ioc.ret_buf[i].ret_prop.buf);
		free(ioc.ret_buf[i].ret_prop.ret_buf_size);
	}
	free(ioc.ret_buf);
return (caller_ret);
}

/*
 * To get the number of paths to a given device pathname using
 * driver ioctl.
 *
 * inputs:
 *   dev path you would like to recieve mp count on
 * outputs:
 * returns:
 *   0  - success
 *   -1 - bad device path
 *   -2 - open failure
 *   -3 - ioctl failure
 */
int
g_get_pathcount(char *dev_path)
{
	char		*char_ptr;
	int		fd = -1;
	sv_iocdata_t	ioc;
	char		phci_path[MAXPATHLEN];
	char		client_path[MAXPATHLEN];
	char		paddr[MAXNAMELEN];
	uint_t		num_elem = 0;
	int		retval = 0;
	char		*physical_path;

	/* translate device path to physical path */
	physical_path = g_get_physical_name(dev_path);
	/* ensure physical path is not NULL, or strcpy will core */
	if (physical_path == NULL) {
		return (-1);
	}
	/* copy physical path without /devices/ prefix */
	(void) strcpy(client_path, physical_path + DEV_PREFIX_LEN-1);
	free(physical_path);

	if ((char_ptr = strrchr(client_path, ':')) != NULL) {
		*char_ptr = '\0';
	}

	/* prepare sv_iocdata_t structure */
	ioc.client	= client_path;
	ioc.phci	= phci_path;
	ioc.addr	= paddr;
	ioc.buf_elem	= 0;
	ioc.ret_buf	= NULL;
	ioc.ret_elem	= &num_elem;

	strcpy(ioc.phci, client_path);

	/* Get file descr. for "/devices/scsi_vhci:devctl" */
	if ((fd = g_object_open(VHCI_NODE, O_RDWR)) < 0) {
		return (-2);
	}

	/* Issue open to device to get multipath_info (ie. count) */
	retval = ioctl(fd, SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO, &ioc);
	close(fd);

	/* Check icotl status */
	if (retval == 0) {
		/* success */
		return (*ioc.ret_elem);
	} else {
		/* failure */
		return (-3);
	}

}


/*
 * Call driver to effect failover for a given pathclass
 *
 * inputs:
 * outputs:
 * returns:
 *   0  - success
 *   !0 - failure
 */
int
g_failover(char *dev_path, char *path_class)
{
int		fd = 0, ret = 0;
char		client_path[MAXPATHLEN];
char		class[MAXNAMELEN];
sv_switch_to_cntlr_iocdata_t	iocsc;

char		*char_ptr_start, *char_ptr_end;


	if (strstr(dev_path, SCSI_VHCI) == NULL) {
		return (L_INVALID_PATH);
	}

	char_ptr_start = dev_path + strlen("/devices");
	if ((char_ptr_end = strrchr(char_ptr_start, ':')) != NULL) {
		*char_ptr_end = '\0';
	}

	if ((fd = g_object_open(VHCI_NODE, O_RDWR)) < 0) {
		return (L_OPEN_PATH_FAIL);
	}

	iocsc.client = client_path;
	iocsc.class = class;

	strcpy(iocsc.client, char_ptr_start);
	strcpy(iocsc.class, path_class);

	if (ioctl(fd, SCSI_VHCI_SWITCH_TO_CNTLR, &iocsc) != 0) {
		switch (errno) {
			case EALREADY:
				ret = L_SCSI_VHCI_ALREADY_ACTIVE;
				break;
			case ENXIO:
				ret = L_INVALID_PATH;
				break;
			case EIO:
				ret = L_SCSI_VHCI_NO_STANDBY;
				break;
			case ENOTSUP:
				ret = L_SCSI_VHCI_FAILOVER_NOTSUP;
				break;
			case EBUSY:
				ret = L_SCSI_VHCI_FAILOVER_BUSY;
				break;
			case EFAULT:
			default:
				ret = L_SCSI_VHCI_ERROR;
		}
	}

	close(fd);
	return (ret);
}

static void
g_free_pi_list(sv_path_info_t *pi, uint_t num_paths)
{
sv_path_info_t *pi_h = pi;
int i = 0;

	while (i++ < num_paths && pi != NULL) {
		free(pi->ret_prop.buf);
		free(pi->ret_prop.ret_buf_size);
		pi++;
	}
	free(pi_h);
}


/*
 * Name: stms_path_enable_disable
 *
 * inputs:
 *
 * client_path	client device path
 *	example: /devices/scsi_vhci/ssd@g280000602200416d6257333030303261:c,raw
 *
 * phci		Controller device path
 *	example: /devices/pci@4,4000/SUNW,qlc@4/fp@0,0
 *
 * request should be set to one of the following:
 *	SCSI_VHCI_PATH_DISABLE
 *	SCSI_VHCI_PATH_ENABLE
 *
 * returns:
 *	0 for success
 *	non-zero otherwise
 */
static int
stms_path_enable_disable(char *client_path, char *phci, int request)
{
	char *ioc_phci;
	char *char_ptr_end;
	char *client_physical_path, *client_path_ptr;
	int fd;
	sv_iocdata_t	ioc;

	if (!client_path || !phci) {
		return (EINVAL);
	}

	if ((fd = g_object_open(VHCI_NODE, O_RDWR)) < 0) {
		return (L_OPEN_PATH_FAIL);
	}

	/*
	 * translate device path to physical path
	 * Save off the ptr for use by free
	 */
	client_path_ptr = client_physical_path =
		g_get_physical_name(client_path);

	/* ensure physical path is not NULL, or strcpy will core */
	if (client_physical_path == NULL) {
		return (EINVAL);
	}

	/*
	 * Must be a scsi_vhci path
	 */
	if (strstr(client_physical_path, SCSI_VHCI) == NULL) {
		free(client_path_ptr);
		return (L_INVALID_PATH);
	}

	/* physical path without /devices/ prefix */
	client_physical_path += DEV_PREFIX_LEN - 1;

	if ((char_ptr_end = strrchr(client_physical_path, ':')) != NULL) {
		*char_ptr_end = '\0';
	}

	/*
	 * If there is a '/devices', strip it, if not
	 * assume it is complete and correct
	 */
	if (strncmp(phci, DEV_PREFIX, DEV_PREFIX_LEN) == 0) {
		ioc_phci = phci + DEV_PREFIX_LEN - 1;
	} else {
		ioc_phci = phci;
	}

	memset(&ioc, 0, sizeof (ioc));

	ioc.client = client_physical_path;
	ioc.phci = ioc_phci;

	/*
	 * Issue requested operation
	 */
	if (ioctl(fd, request, &ioc) != 0) {
		free(client_path_ptr);
		return (errno);
	}
	free(client_path_ptr);
	return (0);
}

int
g_stms_path_disable(char *client_path, char *phci)
{
	return (stms_path_enable_disable(client_path, phci,
		SCSI_VHCI_PATH_DISABLE));
}

int
g_stms_path_enable(char *client_path, char *phci)
{
	return (stms_path_enable_disable(client_path, phci,
		SCSI_VHCI_PATH_ENABLE));
}

/*
 * Name: stms_path_enable_disable_all
 *
 * inputs:
 *
 * phci		Controller device path
 *	example: /devices/pci@4,4000/SUNW,qlc@4/fp@0,0
 *
 * request should be set to one of the following:
 *	SCSI_VHCI_PATH_DISABLE
 *	SCSI_VHCI_PATH_ENABLE
 *
 * returns:
 *	0 for success
 *	non-zero otherwise
 */

static int
stms_path_enable_disable_all(char *phci, int request)
{
	int fd;
	char *ioc_phci;
	sv_iocdata_t ioc;

	if (!phci) {
		return (EINVAL);
	}

	if ((fd = g_object_open(VHCI_NODE, O_RDWR)) < 0) {
		return (L_OPEN_PATH_FAIL);
	}

	memset(&ioc, 0, sizeof (ioc));

	/*
	 * If there is a '/devices', strip it, if not
	 * assume it is complete and correct
	 */
	if (strncmp(phci, DEV_PREFIX, DEV_PREFIX_LEN) == 0) {
		ioc_phci = phci + DEV_PREFIX_LEN - 1;
	} else {
		ioc_phci = phci;
	}

	ioc.client = "/scsi_vhci";
	ioc.phci = ioc_phci;

	/*
	 * Issue requested operation
	 */
	if (ioctl(fd, request, &ioc) != 0) {
		return (errno);
	}
	return (0);
}

int
g_stms_path_disable_all(char *phci)
{
	/*
	 * issue disable on all clients for a phci
	 */
	return (stms_path_enable_disable_all(phci, SCSI_VHCI_PATH_DISABLE));
}

int
g_stms_path_enable_all(char *phci)
{
	/*
	 * issue enable on all clients for a phci
	 */
	return (stms_path_enable_disable_all(phci, SCSI_VHCI_PATH_ENABLE));
}

/*
 * Name: stms_get_path_state
 *
 * inputs:
 *
 * client_path	client device path
 *	example: /devices/scsi_vhci/ssd@g280000602200416d6257333030303261:c,raw
 *
 * phci		Controller device path
 *	example: /devices/pci@4,4000/SUNW,qlc@4/fp@0,0
 *
 * outputs:
 * state set to one of enum mdi_pathinfo_state_t in sunmdi.h
 *	MDI_PATHINFO_STATE_*
 *
 * ext_state set to one or more of the bits defined in mdi_impldefs.h
 *	MDI_PATHINFO_STATE_*
 *
 *
 * returns:
 *	0 for success
 *	non-zero otherwise
 */
int
g_stms_get_path_state(char *client_path, char *phci, int *state, int *ext_state)
{
	sv_iocdata_t ioc;
	int num_paths;
	char *ioc_phci;
	int i;
	int found = 0;
	int err;
	char	phci_path[MAXPATHLEN];
	char	cpath[MAXPATHLEN];
	char	paddr[MAXNAMELEN];


	if (!client_path || !phci) {
		return (EINVAL);
	}

	ioc.client = cpath;
	ioc.phci = phci_path;
	ioc.addr = paddr;

	/*
	 * Get all the paths for this client
	 */
	if ((err = get_pathlist(client_path, &ioc, &num_paths))
		!= 0) {
		return (err);
	}

	/*
	 * If there is a '/devices', strip it, if not
	 * assume it is complete and correct
	 */
	if (strncmp(phci, DEV_PREFIX, DEV_PREFIX_LEN) == 0) {
		ioc_phci = phci + DEV_PREFIX_LEN - 1;
	} else {
		ioc_phci = phci;
	}

	/*
	 * get ioctl response states
	 * for the requested client and phci
	 * and copy them to caller's buffers
	 */
	for (i = 0; i < num_paths; i++) {
		if (strncmp(ioc_phci, ioc.ret_buf[i].device.ret_phci,
			strlen(ioc_phci)) == 0) {
			found++;
			*state = ioc.ret_buf[i].ret_state;
			*ext_state = ioc.ret_buf[i].ret_ext_state;
			break;
		}
	}

	/* free everything we alloced */
	for (i = 0; i < ioc.buf_elem; i++) {
		free(ioc.ret_buf[i].ret_prop.buf);
		free(ioc.ret_buf[i].ret_prop.ret_buf_size);
	}
	free(ioc.ret_buf);

	if (found) {
		return (0);
	} else {
		/* Requested path not found */
		return (ENXIO);
	}
}
