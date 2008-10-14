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


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <hbaapi.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/fibre-channel/fcio.h>
#include <sys/fibre-channel/impl/fc_error.h>
#include <sys/scsi/adapters/scsi_vhci.h>
#include "common.h"
#include "errorcodes.h"
#include <locale.h>

/* The i18n catalog */
nl_catd l_catd;

void
i18n_catopen() {
	static int fileopen = 0;

	if (setlocale(LC_ALL, "") == NULL) {
		(void) fprintf(stderr,
		"Cannot operate in the locale requested. "
		"Continuing in the default C locale\n");
	}
	if (!fileopen) {
		l_catd = catopen("a5k_g_fc_i18n_cat", NL_CAT_LOCALE);
		if (l_catd == (nl_catd)-1) {
			return;
		}
		fileopen = 1;
	}
	return;

}

/*
 * Given an error number, this functions
 * calls the get_errString() to print a
 * corresponding error message to the stderr.
 * get_errString() always returns an error
 * message, even in case of undefined error number.
 * So, there is no need to check for a NULL pointer
 * while printing the error message to the stdout.
 *
 * RETURNS: N/A
 *
 */
void
print_errString(int errnum, char *devpath)
{

char	*errStr;

	errStr = get_errString(errnum);

	if (devpath == NULL) {
		(void) fprintf(stderr,
				"%s \n\n", errStr);
	} else {
		(void) fprintf(stderr,
				"%s - %s.\n\n", errStr, devpath);
	}

	/* free the allocated memory for error string */
	if (errStr != NULL)
		(void) free(errStr);
}

static void terminate() {
	fprintf(stdout, MSGSTR(2506, "Unsupported"));
	fprintf(stdout, "\n");
	exit(1);
}

/*ARGSUSED*/
int adm_display_config(char **a) {
	terminate();
	return (1);
}

/*ARGSUSED*/
void adm_download(char **a, char *b) {
	terminate();
}

/*ARGSUSED*/
void up_encl_name(char **a, int b) {
	terminate();
}

void adm_failover(char **argv) {
	int		path_index = 0, err = 0, fd;
	char		path_class[MAXNAMELEN];
	char		client_path[MAXPATHLEN];
	char		*path_phys = NULL, *trailingMinor;
	sv_switch_to_cntlr_iocdata_t	iocsc;

	(void) memset(path_class, 0, sizeof (path_class));
	(void) strcpy(path_class, argv[path_index++]);
	if ((strcmp(path_class, "primary") != 0) &&
		(strcmp(path_class, "secondary") != 0)) {
			(void) fprintf(stderr,
			MSGSTR(2300, "Incorrect pathclass\n"));
			exit(-1);
	}

	if ((fd = open("/devices/scsi_vhci:devctl", O_RDWR)) < 0) {
	    print_errString(L_OPEN_PATH_FAIL, "/devices/scsi_vhci:devctl");
	    exit(-1);
	}

	iocsc.client = client_path;
	iocsc.class = path_class;

	while (argv[path_index] != NULL) {
		path_phys =
		    get_slash_devices_from_osDevName(argv[path_index++],
			STANDARD_DEVNAME_HANDLING);
		if ((path_phys == NULL) ||
			(strstr(path_phys, "/devices/scsi_vhci") == NULL)) {
				(void) fprintf(stderr,
				MSGSTR(2301, "Incorrect pathname\n"));
				close(fd);
				exit(-1);
		}

		strcpy(iocsc.client, path_phys + strlen("/devices"));

		/* Now chop off the trailing ":xxx" portion if present */
		if ((trailingMinor = strrchr(iocsc.client, ':')) != NULL) {
			trailingMinor[0] = '\0';
		}

		if (ioctl(fd, SCSI_VHCI_SWITCH_TO_CNTLR, &iocsc) != 0) {
		    switch (errno) {
			case EALREADY:
				err = L_SCSI_VHCI_ALREADY_ACTIVE;
				break;
			case ENXIO:
				err = L_INVALID_PATH;
				break;
			case EIO:
				err = L_SCSI_VHCI_NO_STANDBY;
				break;
			case ENOTSUP:
				err = L_SCSI_VHCI_FAILOVER_NOTSUP;
				break;
			case EBUSY:
				err = L_SCSI_VHCI_FAILOVER_BUSY;
				break;
			case EFAULT:
			default:
				err = L_SCSI_VHCI_ERROR;
		    }
		}

		if (err != 0) {
		    close(fd);
		    print_errString(err, path_phys);
		    exit(-1);
		}
	}

	close(fd);
}

/*ARGSUSED*/
int adm_inquiry(char **a) {
	terminate();
	return (1);
}

/*ARGSUSED*/
void pho_probe() {
	terminate();
}

/*ARGSUSED*/
void non_encl_probe() {
	terminate();
}

/*ARGSUSED*/
void adm_led(char **a, int b) {
	terminate();
}

/*ARGSUSED*/
void up_password(char **a) {
	terminate();
}

/*ARGSUSED*/
int adm_reserve(char *path) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int adm_release(char *path) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int adm_start(char **a) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int adm_stop(char **a) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int adm_power_off(char **a, int b) {
	terminate();
	return (1);
}

int
adm_forcelip(char **argv)
{
	int		path_index = 0, fd;
	uint64_t	wwn;
	fcio_t		fcio;
	HBA_HANDLE handle;
	HBA_ADAPTERATTRIBUTES hbaAttrs;
	HBA_PORTATTRIBUTES portAttrs;
	HBA_FCPTARGETMAPPINGV2    *map;
	HBA_STATUS status;
	int count, adapterIndex, portIndex, mapIndex;
	char name[256];
	int		matched, ret = 0, wwnCompare = 0, ntries;
	char	    *physical = NULL, *slash_OSDeviceName = NULL;

	if ((status = loadLibrary())) {
	    /* loadLibrary print out error msg */
	    return (ret++);
	}
	for (path_index = 0; argv[path_index] != NULL; path_index++) {

	    if (is_wwn(argv[path_index])) {
		(void) sscanf(argv[path_index], "%016llx", &wwn);
		wwnCompare = 1;
	    } else if (!is_path(argv[path_index])) {
		print_errString(L_INVALID_PATH, argv[path_index]);
		ret++;
		continue;
	    }
	    if (!wwnCompare) {
		/* Convert the paths to phsyical paths */
		physical = get_slash_devices_from_osDevName(argv[path_index],
			STANDARD_DEVNAME_HANDLING);
		if (!physical) {
		    print_errString(L_INVALID_PATH, argv[path_index]);
		    ret++;
		    continue;
		}
	    }

	    count = getNumberOfAdapters();

	    matched = 0;
	    for (adapterIndex = 0; adapterIndex < count; adapterIndex ++) {
		status = HBA_GetAdapterName(adapterIndex, (char *)&name);
		if (status != HBA_STATUS_OK) {
		    /* May have been DR'd */
		    continue;
		}
		handle = HBA_OpenAdapter(name);
		if (handle == 0) {
		    /* May have been DR'd */
		    continue;
		}

		if (getAdapterAttrs(handle, name, &hbaAttrs)) {
		    /* Should never happen */
		    HBA_CloseAdapter(handle);
		    continue;
		}

		/* Loop over all HBA Ports */
		for (portIndex = 0; portIndex < hbaAttrs.NumberOfPorts;
			portIndex++) {
		    if (getAdapterPortAttrs(handle, name, portIndex,
			    &portAttrs)) {
			continue;
		    }

		    matched = 0;
		    if (is_wwn(argv[path_index])) {
			if (wwn == wwnConversion(
				portAttrs.NodeWWN.wwn) ||
				wwn == wwnConversion(
				portAttrs.PortWWN.wwn)) {
			    matched = 1;
			}
		    } else {
			slash_OSDeviceName = get_slash_devices_from_osDevName(
			    portAttrs.OSDeviceName, STANDARD_DEVNAME_HANDLING);
			if (!slash_OSDeviceName) {
			    continue;
			} else {
			    if (strncmp(physical, slash_OSDeviceName,
				    strlen(slash_OSDeviceName) -
				    strlen(strrchr(slash_OSDeviceName, ':')))
				== 0) {
				matched = 1;
			    }
			    free(slash_OSDeviceName);
			}
		    }

		    if (!matched) {
			if (!fetch_mappings(handle, portAttrs.PortWWN, &map)) {
				/*
				 * matchr_mapping checks the arg
				 * so we pass argv here.
				 */
			    mapIndex = match_mappings(argv[path_index], map);
			    if (mapIndex >= 0) {
				matched = 1;
			    }
			} else {
			    continue;
			}
		    }

		    if (matched) {
			if ((fd = open(portAttrs.OSDeviceName,
				O_RDONLY | O_EXCL)) == -1) {
			    print_errString(L_OPEN_PATH_FAIL,
				    portAttrs.OSDeviceName);
			    return (ret++);
			}

			fcio.fcio_cmd = FCIO_RESET_LINK;
			fcio.fcio_xfer = FCIO_XFER_WRITE;
			/*
			 * Reset the local loop here (fcio_ibuf = 0).
			 * Reset a remote loop on the Fabric by
			 * passing its node wwn (fcio_len = sizeof(nwwn)
			 * and fcio_ibuf = (caddr_t)&nwwn) to the port driver.
			 */
			(void) memset(&wwn, 0, sizeof (wwn));
			fcio.fcio_ilen = sizeof (wwn);
			fcio.fcio_ibuf = (caddr_t)&wwn;

			for (ntries = 0; ntries < RETRY_FCIO_IOCTL; ntries++) {
			    errno = 0;
			    if (ioctl(fd, FCIO_CMD, &fcio) != 0) {
				/*
				 * When port is offlined, qlc
				 * returns the FC_OFFLINE error and errno
				 * is set to EIO.
				 * We do want to ignore this error,
				 * especially when an enclosure is
				 * removed from the loop.
				 */
				if (fcio.fcio_errno == FC_OFFLINE)
				    break;
				if ((errno == EAGAIN) &&
				    (ntries+1 < RETRY_FCIO_IOCTL)) {
				    /* wait WAIT_FCIO_IOCTL */
				    (void) usleep(WAIT_FCIO_IOCTL);
				    continue;
				}
				I_DPRINTF("FCIO ioctl failed.\n"
				    "Error: %s. fc_error = %d (0x%x)\n",
				strerror(errno), fcio.fcio_errno,
				    fcio.fcio_errno);
				close(fd);
				print_errString(L_FCIO_FORCE_LIP_FAIL,
				    portAttrs.OSDeviceName);
				return (ret++);
			    } else {
				break; /* ioctl succeeds. */
			    }
			}
			close(fd);
			if (ntries == RETRY_FCIO_IOCTL) {
			    print_errString(L_FCIO_FORCE_LIP_FAIL,
			    portAttrs.OSDeviceName);
			    return (ret++);
			}
		    }
		    if (matched)
			break; /* for HBA port for loop */
		}
		if (matched) /* HBA adapter for loop */
		    break;
	    }

	    if (!matched) {
		print_errString(L_INVALID_PATH, argv[path_index]);
		ret++;
	    }
	}
	HBA_FreeLibrary();
	return (ret);
}

/*ARGSUSED*/
void adm_bypass_enable(char **argv, int bypass_flag) {
	terminate();
}

/*ARGSUSED*/
int adm_port_offline_online(char **a, int b) {
	terminate();
	return (1);
}

/*ARGSUSED*/
void display_link_status(char **a) {
	terminate();
}

/*ARGSUSED*/
void dump_map(char **argv) {
	terminate();
}

/*ARGSUSED*/
int adm_display_port(int a) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int adm_port_loopback(char *a, int b) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int hotplug_e(int todo, char **argv, int verbose_flag, int force_flag) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int
setboot(unsigned int yes, unsigned int verbose, char *fname)
{
	terminate();
	return (1);
}

/*ARGSUSED*/
int hotplug(int todo, char **argv, int verbose_flag, int force_flag) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int adm_check_file(char **argv, int flag) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int sysdump(int verbose) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int fcal_update(unsigned int verbose, char *file) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int q_qlgc_update(unsigned int verbose, char *file) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int emulex_update(char *file) {
	terminate();
	return (1);
}

/*ARGSUSED*/
int emulex_fcode_reader(int fcode_fd, char *pattern, char *pattern_value,
    uint32_t pattern_value_size) {
	terminate();
	return (1);
}

/*ARGSUSED*/
void dump(char **argv) {
	terminate();
}

/*ARGSUSED*/
int h_insertSena_fcdev() {
	terminate();
	return (1);
}
