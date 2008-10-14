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



#include	<hbaapi.h>
#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<sys/param.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<string.h>
#include	<strings.h>
#include	<ctype.h>
#include	<sys/scsi/generic/sense.h>
#include	<sys/scsi/generic/mode.h>
#include	<sys/scsi/generic/inquiry.h>
#include	<errno.h>
#include	<libdevice.h>
#include	<config_admin.h>
#include	<sys/byteorder.h>
#include	<sys/fibre-channel/fcio.h>
#include	"common.h"
#include	"sun_fc_version.h"

#define	DEFAULT_LUN_COUNT	1024
#define	LUN_SIZE		8
#define	LUN_HEADER_SIZE		8
#define	DEFAULT_LUN_LENGTH	DEFAULT_LUN_COUNT   *	\
				LUN_SIZE	    +	\
				LUN_HEADER_SIZE
struct lun_val {
	uchar_t val[8];
};
struct rep_luns_rsp {
	uint32_t    length;
	uint32_t    rsrvd;
	struct lun_val  lun[1];
};

/* Extracted from the old scsi.h file */
struct  capacity_data_struct {
	uint_t  last_block_addr;
	uint_t  block_size;
};


/* Structure to handle the inq. page 0x80 serial number */
struct page80 {
	uchar_t inq_dtype;
	uchar_t inq_page_code;
	uchar_t reserved;
	uchar_t inq_page_len;
	uchar_t inq_serial[251];
};

extern char		*dtype[];
extern int		Options;
extern const int	OPTION_P;

int skip_hba(int i);
int find_supported_inq_page(HBA_HANDLE handle, HBA_WWN hwwn, HBA_WWN pwwn,
    uint64_t lun, int page_num);
/*
 * The routines within this file operate against the T11
 * HBA API interface.  In some cases, proprietary Sun driver
 * interface are also called to add additional information
 * above what the standard library supports.
 */

uint64_t
wwnConversion(uchar_t *wwn) {
	uint64_t tmp;
	(void) memcpy(&tmp, wwn, sizeof (uint64_t));
	return (ntohll(tmp));
}

void printStatus(HBA_STATUS status) {
	switch (status) {
	case HBA_STATUS_OK:
	    printf(MSGSTR(2410, "OK"));
	    return;
	case HBA_STATUS_ERROR:
	    printf(MSGSTR(2411, "ERROR"));
	    return;
	case HBA_STATUS_ERROR_NOT_SUPPORTED:
	    printf(MSGSTR(2412, "NOT SUPPORTED"));
	    return;
	case HBA_STATUS_ERROR_INVALID_HANDLE:
	    printf(MSGSTR(2413, "INVALID HANDLE"));
	    return;
	case HBA_STATUS_ERROR_ARG:
	    printf(MSGSTR(2414, "ERROR ARG"));
	    return;
	case HBA_STATUS_ERROR_ILLEGAL_WWN:
	    printf(MSGSTR(2415, "ILLEGAL WWN"));
	    return;
	case HBA_STATUS_ERROR_ILLEGAL_INDEX:
	    printf(MSGSTR(2416, "ILLEGAL INDEX"));
	    return;
	case HBA_STATUS_ERROR_MORE_DATA:
	    printf(MSGSTR(2417, "MORE DATA"));
	    return;
	case HBA_STATUS_ERROR_STALE_DATA:
	    printf(MSGSTR(2418, "STALE DATA"));
	    return;
	case HBA_STATUS_SCSI_CHECK_CONDITION:
	    printf(MSGSTR(2419, "SCSI CHECK CONDITION"));
	    return;
	case HBA_STATUS_ERROR_BUSY:
	    printf(MSGSTR(2420, "BUSY"));
	    return;
	case HBA_STATUS_ERROR_TRY_AGAIN:
	    printf(MSGSTR(2421, "TRY AGAIN"));
	    return;
	case HBA_STATUS_ERROR_UNAVAILABLE:
	    printf(MSGSTR(2422, "UNAVAILABLE"));
	    return;
	default:
	    printf(MSGSTR(2423, "UNKNOWN ERROR TYPE %d"), status);
	    return;
	    }
}

uint32_t
getNumberOfAdapters() {
	uint32_t count = HBA_GetNumberOfAdapters();
	if (count == 0) {
		fprintf(stderr, MSGSTR(2405,
			"\nERROR: No Fibre Channel Adapters found.\n"));
	}
	return (count);
}

#define	MAX_RETRIES	10

/*
 * Returns non-zero on failure (aka, HBA_STATUS_ERROR_*
 * Will handle retries if applicable.
 */
int
getAdapterAttrs(HBA_HANDLE handle, char *name, HBA_ADAPTERATTRIBUTES *attrs) {
	int count = 0;
	HBA_STATUS status = HBA_STATUS_ERROR_TRY_AGAIN; /* force first pass */

	/* Loop as long as we have a retryable error */
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
		status == HBA_STATUS_ERROR_BUSY) && count++ < MAX_RETRIES) {
		status = HBA_GetAdapterAttributes(handle, attrs);
		if (status == HBA_STATUS_OK) {
			break;
		}
		(void) sleep(1);
	}
	if (status != HBA_STATUS_OK) {
		/* We encountered a non-retryable error */
		fprintf(stderr, MSGSTR(2501,
		"\nERROR: Unable to retrieve adapter port details (%s)"),
		name);
		printStatus(status);
		fprintf(stderr, "\n");
	}
	return (status);
}

/*
 * Returns non-zero on failure (aka, HBA_STATUS_ERROR_*
 * Will handle retries if applicable.
 */
int
getAdapterPortAttrs(HBA_HANDLE handle, char *name, int portIndex,
	    HBA_PORTATTRIBUTES *attrs) {
	int count = 0;
	HBA_STATUS status = HBA_STATUS_ERROR_TRY_AGAIN; /* force first pass */

	/* Loop as long as we have a retryable error */
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
		status == HBA_STATUS_ERROR_BUSY) && count++ < MAX_RETRIES) {
		status = HBA_GetAdapterPortAttributes(handle, portIndex, attrs);
		if (status == HBA_STATUS_OK) {
			break;
		}

		/* The odds of this occuring are very slim, but possible. */
		if (status == HBA_STATUS_ERROR_STALE_DATA) {
			/*
			 * If we hit a stale data scenario,
			 * we'll just tell the user to try again.
			 */
			status = HBA_STATUS_ERROR_TRY_AGAIN;
			break;
		}
		sleep(1);
	}
	if (status != HBA_STATUS_OK) {
		/* We encountered a non-retryable error */
		fprintf(stderr, MSGSTR(2501,
		"\nERROR: Unable to retrieve adapter port details (%s)"),
		name);
		printStatus(status);
		fprintf(stderr, "\n");
	}
	return (status);
}

/*
 * Returns non-zero on failure (aka, HBA_STATUS_ERROR_*
 * Will handle retries if applicable.
 */
int
getDiscPortAttrs(HBA_HANDLE handle, char *name, int portIndex, int discIndex,
	    HBA_PORTATTRIBUTES *attrs) {
	int count = 0;
	HBA_STATUS status = HBA_STATUS_ERROR_TRY_AGAIN; /* force first pass */

	/* Loop as long as we have a retryable error */
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
		status == HBA_STATUS_ERROR_BUSY) && count++ < MAX_RETRIES) {
		status = HBA_GetDiscoveredPortAttributes(handle, portIndex,
				discIndex, attrs);
		if (status == HBA_STATUS_OK) {
			break;
		}

		/* The odds of this occuring are very slim, but possible. */
		if (status == HBA_STATUS_ERROR_STALE_DATA) {
			/*
			 * If we hit a stale data scenario, we'll just tell the
			 * user to try again.
			 */
			status = HBA_STATUS_ERROR_TRY_AGAIN;
			break;
		}
		sleep(1);
	}
	if (status != HBA_STATUS_OK) {
		/* We encountered a non-retryable error */
		fprintf(stderr, MSGSTR(2504,
		"\nERROR: Unable to retrieve target port details (%s)"),
		name);
		printStatus(status);
		fprintf(stderr, "\n");
	}
	return (status);
}


/*ARGSUSED*/
int
fchba_display_port(int verbose)
{
	int retval = 0;
	HBA_HANDLE handle;
	HBA_ADAPTERATTRIBUTES hbaAttrs;
	HBA_PORTATTRIBUTES portAttrs;
	HBA_STATUS status;
	int count, adapterIndex, portIndex;
	char name[256];
	char *physical = NULL;
	char path[MAXPATHLEN];

	if ((retval = loadLibrary())) {
	    return (retval);
	}

	count = getNumberOfAdapters();

	for (adapterIndex = 0; adapterIndex < count; adapterIndex ++) {
	    if (skip_hba(adapterIndex)) {
		continue;
	    }
	    status = HBA_GetAdapterName(adapterIndex, (char *)&name);
	    if (status != HBA_STATUS_OK) {
		/* Just skip it, maybe it was DR'd */
		continue;
	    }
	    handle = HBA_OpenAdapter(name);
	    if (handle == 0) {
		/* Just skip it, maybe it was DR'd */
		continue;
	    }

	    if (getAdapterAttrs(handle, name, &hbaAttrs)) {
		/* This should never happen, we'll just skip the adapter */
		HBA_CloseAdapter(handle);
		continue;
	    }

	    for (portIndex = 0; portIndex < hbaAttrs.NumberOfPorts;
		    portIndex++) {
		if (getAdapterPortAttrs(handle, name, portIndex,
			&portAttrs)) {
		    continue;
		}
		physical = get_slash_devices_from_osDevName(
				portAttrs.OSDeviceName,
				STANDARD_DEVNAME_HANDLING);
		if (physical) {
			char *tmp = strstr(physical, ":fc");
			if (tmp) {
				*tmp = '\0';
				(void) snprintf(path, MAXPATHLEN, "%s:devctl",
					physical);
			} else {
				(void) snprintf(path, MAXPATHLEN, "%s",
					physical);
			}
			free(physical);
			physical = NULL;
			(void) printf("%-65s  ", path);
		} else {
			(void) printf("%-65s  ", portAttrs.OSDeviceName);
		}
		if (portAttrs.NumberofDiscoveredPorts > 0) {
		    printf(MSGSTR(2233, "CONNECTED\n"));
		} else {
		    printf(MSGSTR(2234, "NOT CONNECTED\n"));
		}
	    }
	}
	(void) HBA_FreeLibrary();
	return (retval);
}

/*
 * Internal routines/structure to deal with a path list
 * so we can ensure uniqueness
 */
struct path_entry {
	char path[MAXPATHLEN];
	HBA_UINT8 wwn[8];
	uchar_t dtype;
	struct path_entry *next;
};
void add_path(struct path_entry *head, struct path_entry *cur) {
	struct path_entry *tmp;
	for (tmp = head; tmp->next != NULL; tmp = tmp->next) { }
		tmp->next = cur;
}
struct path_entry *is_duplicate_path(struct path_entry *head, char *path) {
	struct path_entry *tmp;
	for (tmp = head; tmp != NULL; tmp = tmp->next) {
		if (strncmp(tmp->path, path, sizeof (tmp->path)) == 0) {
			return (tmp);
		}
	}
	return (NULL);
}
void free_path_list(struct path_entry *head) {
	struct path_entry *tmp;
	struct path_entry *tmp2;
	for (tmp = head; tmp != NULL; ) {
		tmp2 = tmp->next;
		free(tmp);
		tmp = tmp2;
	}
}


int
is_wwn(char *arg) {
	int i;
	if (strlen(arg) == 16) {
		for (i = 0; i < 16; i++) {
			if (!isxdigit(arg[i])) {
				return (0);
			}
		}
		return (1);
	}
	return (0);
}

int
is_path(char *arg) {
	struct stat buf;
	if (stat(arg, &buf)) {
		return (0);
	}
	return (1);
}

/* We take a wild guess for our first get target mappings call */
#define	MAP_GUESS	50

HBA_STATUS
fetch_mappings(HBA_HANDLE handle, HBA_WWN pwwn, HBA_FCPTARGETMAPPINGV2 **map) {
	int loop = 0;
	int count = 0;
	HBA_STATUS status = HBA_STATUS_ERROR_TRY_AGAIN; /* force first pass */
	*map = (HBA_FCPTARGETMAPPINGV2 *) calloc(1,
		(sizeof (HBA_FCPSCSIENTRYV2)* (MAP_GUESS-1)) +
		sizeof (HBA_FCPTARGETMAPPINGV2));

	/* Loop as long as we have a retryable error */
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
		status == HBA_STATUS_ERROR_BUSY ||
		status == HBA_STATUS_ERROR_MORE_DATA) && loop++ < MAX_RETRIES) {
	    status = HBA_GetFcpTargetMappingV2(handle, pwwn, *map);
	    if (status == HBA_STATUS_OK) {
		break;
	    } else if (status == HBA_STATUS_ERROR_MORE_DATA) {
		count = (*map)->NumberOfEntries;
		free(*map);
		*map = (HBA_FCPTARGETMAPPINGV2 *) calloc(1,
		    (sizeof (HBA_FCPSCSIENTRYV2)* (count-1)) +
		    sizeof (HBA_FCPTARGETMAPPINGV2));
		(*map)->NumberOfEntries = count;
		continue;
	    }
	    sleep(1);
	}
	if (status != HBA_STATUS_OK) {
	    /* We encountered a non-retryable error */
	    fprintf(stderr, MSGSTR(2502,
		    "\nERROR: Unable to retrieve SCSI device paths "
		    "(HBA Port WWN %016llx)"),
		    wwnConversion(pwwn.wwn));
	    printStatus(status);
	    fprintf(stderr, "\n");
	}
	return (status);
}

/*
 * Returns the index of the first match, or -1 if no match
 */
int
match_mappings(char *compare, HBA_FCPTARGETMAPPINGV2 *map) {
	int		mapIndex;
	char	*physical = NULL;
	char	*tmp;
	int		wwnCompare = 0;
	uint64_t	wwn;

	if (map == NULL || compare == NULL) {
	    return (-1);
	}

	if (is_wwn(compare)) {
	    wwnCompare = 1;
	    (void) sscanf(compare, "%016llx", &wwn);
	} else {
	    /* Convert the paths to phsyical paths */
	    physical = get_slash_devices_from_osDevName(compare,
			STANDARD_DEVNAME_HANDLING);
	}

	for (mapIndex = 0; mapIndex < map->NumberOfEntries; mapIndex ++) {
	    if (wwnCompare) {
		if (wwn == wwnConversion(
			map->entry[mapIndex].FcpId.NodeWWN.wwn) ||
			wwn == wwnConversion(
			map->entry[mapIndex].FcpId.PortWWN.wwn)) {
		    return (mapIndex);
		}
	    } else {
		if (physical != NULL) {
		    tmp = get_slash_devices_from_osDevName(
			map->entry[mapIndex].ScsiId.OSDeviceName,
			STANDARD_DEVNAME_HANDLING);
		    if ((tmp != NULL) &&
			strncmp(physical, tmp, MAXPATHLEN) == 0) {
			free(physical);
			return (mapIndex);
		    }
		}
	    }
	}
	if (physical) {
	    free(physical);
	}
	return (-1);
}


/*
 * returns non-zero on failure (aka HBA_STATUS_ERROR_*
 */
int
loadLibrary() {
	int status = HBA_LoadLibrary();
	if (status != HBA_STATUS_OK) {
		fprintf(stderr, MSGSTR(2505,
			"ERROR: Unable to load HBA API library: "));
		printStatus(status);
		fprintf(stderr, "\n");
	}
	return (status);
}

int
fchba_non_encl_probe() {
	HBA_HANDLE handle;
	HBA_ADAPTERATTRIBUTES hbaAttrs;
	HBA_PORTATTRIBUTES portAttrs;
	HBA_FCPTARGETMAPPINGV2    *map;
	HBA_STATUS status;
	int count, adapterIndex, portIndex, mapIndex;
	char name[256];
	struct path_entry *head = NULL;
	uint64_t	lun = 0;
	L_inquiry	inq;
	struct scsi_extended_sense sense;
	HBA_UINT8	scsiStatus;
	uint32_t	inquirySize = sizeof (inq), senseSize = sizeof (sense);

	if (loadLibrary()) {
	    return (-1);
	}

	count = getNumberOfAdapters();

	/* Loop over all HBAs */
	for (adapterIndex = 0; adapterIndex < count; adapterIndex ++) {
	    if (skip_hba(adapterIndex)) {
		continue;
	    }
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
		/* Should not happen, just skip it */
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

		if (fetch_mappings(handle, portAttrs.PortWWN, &map)) {
		    continue;
		}

		/* Loop over all target Mapping entries */
		for (mapIndex = 0; mapIndex < map->NumberOfEntries;
		    mapIndex ++) {
			struct path_entry *tmpPath = NULL;
			int doInquiry = 0;
			if (!head) {
			head = (struct path_entry *)calloc(1,
				sizeof (struct path_entry));
			tmpPath = head;
			strncpy(head->path,
			    map->entry[mapIndex].ScsiId.OSDeviceName,
			    sizeof (map->entry[mapIndex].ScsiId.OSDeviceName));
			(void) memcpy(tmpPath->wwn,
			    map->entry[mapIndex].FcpId.NodeWWN.wwn,
			    sizeof (HBA_UINT8) * 8);
			doInquiry = 1;
			} else if (tmpPath = is_duplicate_path(head,
				map->entry[mapIndex].ScsiId.OSDeviceName)) {
				if (tmpPath->dtype != 0x1f) {
					doInquiry = 0;
				} else {
					doInquiry = 1;
				}
			} else {
			tmpPath = (struct path_entry *)
				calloc(1, sizeof (struct path_entry));
			strncpy(tmpPath->path,
			    map->entry[mapIndex].ScsiId.OSDeviceName,
			    sizeof (map->entry[mapIndex].ScsiId.OSDeviceName));
			(void) memcpy(tmpPath->wwn,
			    map->entry[mapIndex].FcpId.NodeWWN.wwn,
			    sizeof (HBA_UINT8) * 8);
			add_path(head, tmpPath);
			doInquiry = 1;
			}

			if (doInquiry) {
				lun = map->entry[mapIndex].FcpId.FcpLun;
				memset(&inq, 0, sizeof (inq));
				memset(&sense, 0, sizeof (sense));
				status = HBA_ScsiInquiryV2(handle,
				    portAttrs.PortWWN,
				    map->entry[mapIndex].FcpId.PortWWN,
				    lun, 0, 0,
				    &inq, &inquirySize,
				    &scsiStatus,
				    &sense, &senseSize);
				if (status != HBA_STATUS_OK) {
					inq.inq_dtype = 0x1f;
				}
				tmpPath->dtype = inq.inq_dtype;
			}
		}
	}
	}
	if (head) {
		struct path_entry *tmp;
		printf(MSGSTR(2098, "\nFound Fibre Channel device(s):\n"));
		for (tmp = head; tmp != NULL; tmp = tmp->next) {
			printf("  ");
			printf(MSGSTR(90, "Node WWN:"));
			printf("%016llx  ", wwnConversion(tmp->wwn));
			fprintf(stdout, MSGSTR(35, "Device Type:"));
			(void) fflush(stdout);

			if ((tmp->dtype & DTYPE_MASK) < 0x10) {
				fprintf(stdout, "%s",
				    dtype[tmp->dtype & DTYPE_MASK]);
			} else if ((tmp->dtype & DTYPE_MASK) < 0x1f) {
				fprintf(stdout, MSGSTR(2406,
				    "Reserved"));
			} else {
				fprintf(stdout, MSGSTR(2407,
				    "Unknown"));
			}

			printf("\n    ");
			printf(MSGSTR(31, "Logical Path:%s"), tmp->path);
			printf("\n");

		/* We probably shouldn't be using a g_fc interface here */
			if (Options & OPTION_P) {
				char *phys_path =
				get_slash_devices_from_osDevName(
				    tmp->path,
				    STANDARD_DEVNAME_HANDLING);
				if (phys_path != NULL) {
				fprintf(stdout, "    ");
				fprintf(stdout, MSGSTR(5, "Physical Path:"));
				fprintf(stdout, "\n     %s\n", phys_path);
				free(phys_path);
				}
			}
		}
		free_path_list(head);
	}
	HBA_FreeLibrary();
	return (0);
}


int
fchba_inquiry(char **argv)
{
	int		path_index = 0, found = 0;
	uint64_t	wwn;
	uint64_t	lun = 0;
	HBA_HANDLE handle;
	HBA_ADAPTERATTRIBUTES hbaAttrs;
	HBA_PORTATTRIBUTES portAttrs;
	HBA_FCPTARGETMAPPINGV2    *map;
	HBA_STATUS status;
	int count, adapterIndex, portIndex, mapIndex;
	char name[256];
	L_inquiry	inq;
	struct page80	serial;
	uint32_t	serialSize = sizeof (serial);
	struct scsi_extended_sense sense;
	HBA_UINT8	scsiStatus;
	uint32_t	inquirySize = sizeof (inq), senseSize = sizeof (sense);
	boolean_t	goodPath = B_FALSE;
	int		matched = 0, wwnCompare = 0;
	char		*tmp, *physical = NULL;
	int		ret = 0;

	if (loadLibrary()) {
	    return (-1);
	}
	for (path_index = 0; argv[path_index] != NULL; path_index++) {
	    goodPath = B_FALSE;
	    found = 0;

	    if (is_wwn(argv[path_index])) {
		(void) sscanf(argv[path_index], "%016llx", &wwn);
		wwnCompare = 1;
	    } else if (!is_path(argv[path_index])) {
		fprintf(stderr, MSGSTR(112, "Error: Invalid pathname (%s)"),
			argv[path_index]);
		fprintf(stderr, "\n");
		ret = -1;
		continue;
	    }
	    if (!wwnCompare) {
		/* Convert the paths to phsyical paths */
		physical = get_slash_devices_from_osDevName(argv[path_index],
			STANDARD_DEVNAME_HANDLING);
		if (!physical) {
		    fprintf(stderr, MSGSTR(112,
			"Error: Invalid pathname (%s)"),
			argv[path_index]);
		    fprintf(stderr, "\n");
		    ret = -1;
		    continue;
		}
	    }

	    count = getNumberOfAdapters();

	    /* Loop over all HBAs */
	    for (adapterIndex = 0; adapterIndex < count; adapterIndex ++) {
		if (skip_hba(adapterIndex)) {
		    continue;
		}
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

		    if (fetch_mappings(handle, portAttrs.PortWWN, &map)) {
			continue;
		    }

		    for (mapIndex = 0; mapIndex < map->NumberOfEntries;
			    mapIndex ++) {
			matched = 0;
			if (wwnCompare) {
			    if (wwn == wwnConversion(
				    map->entry[mapIndex].FcpId.NodeWWN.wwn) ||
				    wwn == wwnConversion(
				    map->entry[mapIndex].FcpId.PortWWN.wwn)) {
				lun = map->entry[mapIndex].FcpId.FcpLun;
				matched = 1;
			    }
			} else {
			    tmp = get_slash_devices_from_osDevName(
				    map->entry[mapIndex].ScsiId.OSDeviceName,
				    STANDARD_DEVNAME_HANDLING);
			    if ((tmp != NULL) && (strncmp(physical, tmp,
				    MAXPATHLEN) == 0)) {
				lun = map->entry[mapIndex].FcpId.FcpLun;
				matched = 1;
				free(tmp);
			    }
			}

			if (matched) {
			    memset(&inq, 0, sizeof (inq));
			    memset(&sense, 0, sizeof (sense));
			    status = HBA_ScsiInquiryV2(handle,
				portAttrs.PortWWN,
				map->entry[mapIndex].FcpId.PortWWN,
				lun, 0, 0,
				&inq, &inquirySize,
				&scsiStatus,
				&sense, &senseSize);
			    if (status == HBA_STATUS_OK) {
				goodPath = B_TRUE;
				/*
				 * Call the inquiry cmd on page 0x80 only if
				 * the vendor supports page 0x80
				 */
				memset(&serial, 0, sizeof (serial));
				if ((find_supported_inq_page(handle,
					    portAttrs.PortWWN,
					    map->entry[mapIndex].FcpId.PortWWN,
					    lun, 0x80))) {
					status = HBA_ScsiInquiryV2(handle,
					    portAttrs.PortWWN,
					    map->entry[mapIndex].FcpId.PortWWN,
					    lun, 1, 0x80,
					    &serial, &serialSize,
					    &scsiStatus,
					    &sense, &senseSize);
					if (status != HBA_STATUS_OK) {
						strncpy(
						    (char *)serial.inq_serial,
						    "Unavailable",
						    sizeof (serial.inq_serial));
					}
				} else {
					strncpy((char *)serial.inq_serial,
					    "Unsupported",
					    sizeof (serial.inq_serial));
				}
				/*
				 * we are adding serial number information
				 * from 0x80.  If length is less than 39,
				 * then we want to increase length to 52 to
				 * reflect the fact that we have serial number
				 * information
				 */
				if (inq.inq_len < 39) {
					inq.inq_len = 52;
				}
				print_inq_data(argv[path_index],
				    map->entry[mapIndex].ScsiId.OSDeviceName,
				    inq, serial.inq_serial,
				    sizeof (serial.inq_serial));
				if (! wwnCompare) {
					found = 1;
					break;
				}
			    } else {
				fprintf(stderr, MSGSTR(2430,
				"Error: I/O failure communicating with %s  "),
				map->entry[mapIndex].ScsiId.OSDeviceName);
				printStatus(status);
				fprintf(stderr, "\n");
			    }
			}
		    }
		    if (found == 1) {
			    break;
		    }
		}
		if (found == 1) {
			break;
		}
	    }

	    if (physical) {
		free(physical);
	    }

	    if (!goodPath) {
		fprintf(stderr, MSGSTR(112, "Error: Invalid pathname (%s)"),
			argv[path_index]);
		fprintf(stderr, "\n");
		ret = -1;
	    }
	}
	return (ret);
}



int
fchba_dump_map(char **argv)
{
	int		path_index = 0;
	uint64_t	wwn;
	uint64_t	lun = 0;
	HBA_HANDLE handle;
	HBA_ADAPTERATTRIBUTES hbaAttrs;
	HBA_PORTATTRIBUTES portAttrs;
	HBA_PORTATTRIBUTES discPortAttrs;
	HBA_FCPTARGETMAPPINGV2    *map;
	HBA_STATUS status;
	int count, adapterIndex, portIndex, mapIndex, discIndex;
	char name[256], *physical, *comp_phys;
	L_inquiry	inq;
	struct scsi_extended_sense sense;
	HBA_UINT8	scsiStatus;
	int		matched;
	int		done;
	uint32_t	inquirySize = sizeof (inq), senseSize = sizeof (sense);
	boolean_t	goodPath = B_FALSE;
	int		ret = 0;
	uint32_t	responseSize = DEFAULT_LUN_LENGTH;
	uchar_t		raw_luns[DEFAULT_LUN_LENGTH];
	struct rep_luns_rsp	*lun_resp;


	if (loadLibrary()) {
	    return (-1);
	}
	for (path_index = 0; argv[path_index] != NULL; path_index++) {
	    goodPath = B_FALSE;

	    if (is_wwn(argv[path_index])) {
		(void) sscanf(argv[path_index], "%016llx", &wwn);
	    } else if (!is_path(argv[path_index])) {
		fprintf(stderr, MSGSTR(112, "Error: Invalid pathname (%s)"),
			argv[path_index]);
		fprintf(stderr, "\n");
		ret = -1;
		continue;
	    }

	    count = getNumberOfAdapters();

	    done = 0;
	    /* Loop over all HBAs */
	    for (adapterIndex = 0; adapterIndex < count && !done;
		    adapterIndex ++) {
		if (skip_hba(adapterIndex)) {
		    continue;
		}
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
		for (portIndex = 0; portIndex < hbaAttrs.NumberOfPorts && !done;
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
			if (is_path(argv[path_index]) &&
			    ((physical = get_slash_devices_from_osDevName(
				argv[path_index],
				STANDARD_DEVNAME_HANDLING)) != NULL) &&
			    ((comp_phys = get_slash_devices_from_osDevName(
				portAttrs.OSDeviceName,
				STANDARD_DEVNAME_HANDLING)) != NULL)) {
			    char *tmp = strstr(physical, ":devctl");
			    if (tmp) {
				*tmp = '\0';
			    } else {
				tmp = strstr(physical, ":fc");
				if (tmp) {
					*tmp = '\0';
				}
			    }
			    if (strstr(comp_phys, physical)) {
				matched = 1;
			    }
			}
			if (physical) {
			    free(physical);
			    physical = NULL;
			}
			if (comp_phys) {
			    free(comp_phys);
			    comp_phys = NULL;
			}
		    }

		    if (!fetch_mappings(handle, portAttrs.PortWWN, &map)) {
			mapIndex = match_mappings(argv[path_index], map);
			if (mapIndex >= 0) {
			    matched = 1;
			}
		    } else {
			continue;
		    }

		    if (matched) {
			goodPath = B_TRUE;
			printf(MSGSTR(2095,
				"Pos  Port_ID Hard_Addr Port WWN"
				"         Node WWN         Type\n"));
			for (discIndex = 0;
				discIndex < portAttrs.NumberofDiscoveredPorts;
				discIndex++) {
			    if (getDiscPortAttrs(handle, name, portIndex,
				    discIndex, &discPortAttrs)) {
				/* Move on to the next target */
				continue;
			    }

			    printf("%-4d %-6x  %-6x   %016llx %016llx",
				    discIndex,
				    discPortAttrs.PortFcId, 0,
				    wwnConversion(discPortAttrs.PortWWN.wwn),
				    wwnConversion(discPortAttrs.NodeWWN.wwn));

				/*
				 * devices are not all required to respond to
				 * Scsi Inquiry calls sent to LUN 0.  We must
				 * fisrt issue a ReportLUN and then send the
				 * SCSI Inquiry call to the first LUN Returned
				 * from the ReportLUN call
				 */
			    memset(&sense, 0, sizeof (sense));
			    status = HBA_ScsiReportLUNsV2(handle,
				portAttrs.PortWWN,
				discPortAttrs.PortWWN,
				(void *)raw_luns, &responseSize, &scsiStatus,
				(void *)&sense, &senseSize);
			    if (status == HBA_STATUS_OK) {
				    lun_resp =
					(struct rep_luns_rsp *)
					(unsigned long)raw_luns;
				    lun = ntohll(
					wwnConversion(lun_resp->lun[0].val));
			    } else {
				/*
				 * in case we are unable to retrieve report
				 * LUN data, we will blindly try sending the
				 * INQUIRY to lun 0.
				 */
				lun = 0;
			    }
			    memset(&sense, 0, sizeof (sense));
			    status = HBA_ScsiInquiryV2(handle,
				    portAttrs.PortWWN,
				    discPortAttrs.PortWWN,
				    lun, 0, 0,
				    &inq, &inquirySize,
				    &scsiStatus,
				    &sense, &senseSize);
			    if (status != HBA_STATUS_OK) {
				inq.inq_dtype = 0x1f;
			    }
			    print_fabric_dtype_prop(portAttrs.PortWWN.wwn,
				map->entry[mapIndex].FcpId.PortWWN.wwn,
				inq.inq_dtype);
			}
			/* Now dump this HBA's stats */
			printf("%-4d %-6x  %-6x   %016llx %016llx",
			    discIndex,
			    portAttrs.PortFcId, 0,
			    wwnConversion(portAttrs.PortWWN.wwn),
			    wwnConversion(portAttrs.NodeWWN.wwn));
			print_fabric_dtype_prop(portAttrs.PortWWN.wwn,
			    portAttrs.PortWWN.wwn, 0x1f);
			done = 1;
		    }
		}
	    }
	    if (!goodPath) {
		fprintf(stderr, MSGSTR(112, "Error: Invalid pathname (%s)"),
			argv[path_index]);
		fprintf(stderr, "\n");
		ret = -1;
	    }
	}
	return (ret);
}

int
fchba_display_link_status(char **argv)
{
	int		path_index = 0;
	uint64_t	wwn;
	HBA_HANDLE handle;
	HBA_ADAPTERATTRIBUTES hbaAttrs;
	HBA_PORTATTRIBUTES portAttrs;
	HBA_PORTATTRIBUTES discPortAttrs;
	HBA_FCPTARGETMAPPINGV2    *map;
	HBA_STATUS status;
	int count, adapterIndex, portIndex, discIndex;
	char name[256], *physical, *comp_phys;
	int		matched;
	struct fc_rls_acc_params	rls;
	uint32_t	rls_size = sizeof (rls);
	boolean_t	goodPath = B_FALSE;
	int		ret = 0;

	if (loadLibrary()) {
	    return (-1);
	}
	for (path_index = 0; argv[path_index] != NULL; path_index++) {
	    goodPath = B_FALSE;

	    if (is_wwn(argv[path_index])) {
		(void) sscanf(argv[path_index], "%016llx", &wwn);
	    } else if (!is_path(argv[path_index])) {
		fprintf(stderr, MSGSTR(112, "Error: Invalid pathname (%s)"),
			argv[path_index]);
		fprintf(stderr, "\n");
		ret = -1;
		continue;
	    }

	    count = getNumberOfAdapters();

	    /* Loop over all HBAs */
	    for (adapterIndex = 0; adapterIndex < count; adapterIndex ++) {
		if (skip_hba(adapterIndex)) {
		    continue;
		}
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
			if (is_path(argv[path_index]) &&
			    ((physical = get_slash_devices_from_osDevName(
				argv[path_index],
				STANDARD_DEVNAME_HANDLING)) != NULL) &&
			    ((comp_phys = get_slash_devices_from_osDevName(
				portAttrs.OSDeviceName,
				STANDARD_DEVNAME_HANDLING)) != NULL)) {
			    char *tmp = strstr(physical, ":devctl");
			    if (tmp) {
				*tmp = '\0';
			    } else {
				tmp = strstr(physical, ":fc");
				if (tmp) {
					*tmp = '\0';
				}
			    }
			    if (strstr(comp_phys, physical)) {
				matched = 1;
			    }
			}
			if (physical) {
			    free(physical);
			    physical = NULL;
			}
			if (comp_phys) {
			    free(comp_phys);
			    comp_phys = NULL;
			}
		    }

		    if (!matched) {
			if (fetch_mappings(handle, portAttrs.PortWWN, &map)) {
			    continue;
			}
		    }

		    if (matched || match_mappings(argv[path_index], map) >= 0) {
			goodPath = B_TRUE;
			fprintf(stdout,
				MSGSTR(2007, "\nLink Error Status "
				"information for loop:%s\n"), argv[path_index]);
			fprintf(stdout, MSGSTR(2008, "al_pa   lnk fail "
				"   sync loss   signal loss   sequence err"
				"   invalid word   CRC\n"));

			for (discIndex = 0;
				discIndex < portAttrs.NumberofDiscoveredPorts;
				discIndex++) {


			    if (getDiscPortAttrs(handle, name, portIndex,
				    discIndex, &discPortAttrs)) {
				continue;
			    }

			    status = HBA_SendRLS(handle, portAttrs.PortWWN,
					discPortAttrs.PortWWN,
					&rls, &rls_size);
			    if (status != HBA_STATUS_OK) {
				memset(&rls, 0xff, sizeof (rls));
			    }

			    if ((rls.rls_link_fail == 0xffffffff) &&
				(rls.rls_sync_loss == 0xffffffff) &&
				(rls.rls_sig_loss == 0xffffffff) &&
				(rls.rls_prim_seq_err == 0xffffffff) &&
				(rls.rls_invalid_word == 0xffffffff) &&
				(rls.rls_invalid_crc == 0xffffffff)) {
				    fprintf(stdout,
					"%x\t%-12d%-12d%-14d%-15d%-15d%-12d\n",
					    discPortAttrs.PortFcId,
					    rls.rls_link_fail,
					    rls.rls_sync_loss,
					    rls.rls_sig_loss,
					    rls.rls_prim_seq_err,
					    rls.rls_invalid_word,
					    rls.rls_invalid_crc);
			    } else {
				    fprintf(stdout,
					"%x\t%-12u%-12u%-14u%-15u%-15u%-12u\n",
					    discPortAttrs.PortFcId,
					    rls.rls_link_fail,
					    rls.rls_sync_loss,
					    rls.rls_sig_loss,
					    rls.rls_prim_seq_err,
					    rls.rls_invalid_word,
					    rls.rls_invalid_crc);
			    }


			}
			/* Now dump this HBA's stats */
			status = HBA_SendRLS(handle, portAttrs.PortWWN,
				portAttrs.PortWWN,
				&rls, &rls_size);
			if (status != HBA_STATUS_OK) {
			    memset(&rls, 0xff, sizeof (rls));
			}

			if ((rls.rls_link_fail == 0xffffffff) &&
				(rls.rls_sync_loss == 0xffffffff) &&
				(rls.rls_sig_loss == 0xffffffff) &&
				(rls.rls_prim_seq_err == 0xffffffff) &&
				(rls.rls_invalid_word == 0xffffffff) &&
				(rls.rls_invalid_crc == 0xffffffff)) {
			    fprintf(stdout,
				    "%x\t%-12d%-12d%-14d%-15d%-15d%-12d\n",
				    portAttrs.PortFcId,
				    rls.rls_link_fail,
				    rls.rls_sync_loss,
				    rls.rls_sig_loss,
				    rls.rls_prim_seq_err,
				    rls.rls_invalid_word,
				    rls.rls_invalid_crc);
			} else {
			    fprintf(stdout,
				    "%x\t%-12u%-12u%-14u%-15u%-15u%-12u\n",
				    portAttrs.PortFcId,
				    rls.rls_link_fail,
				    rls.rls_sync_loss,
				    rls.rls_sig_loss,
				    rls.rls_prim_seq_err,
				    rls.rls_invalid_word,
				    rls.rls_invalid_crc);
			}
		    }
		}
	    }
	    if (!goodPath) {
		fprintf(stderr, MSGSTR(112, "Error: Invalid pathname (%s)"),
			argv[path_index]);
		fprintf(stderr, "\n");
		ret = -1;
	    }
	}
	(void) fprintf(stdout,
		MSGSTR(2009, "NOTE: These LESB counts are not"
		" cleared by a reset, only power cycles.\n"
		"These counts must be compared"
		" to previously read counts.\n"));
	return (ret);
}

typedef struct _PathInformation {
	char	pathClass[MAXPATHLEN];
	char	pathState[MAXPATHLEN];
	int32_t	pathInfoState;
	int32_t	pathInfoExternalState;
} PathInformation;

struct lun_tracking {
	HBA_FCPSCSIENTRYV2  map;
	HBA_WWN	hba_pwwn;
	char	hba_path[MAXPATHLEN];
	PathInformation info;

	/* Points to another lun_tracking instance with the same map->LUID */
	struct lun_tracking	*next_path;

	/* Points to next lun_tracking with a different map->LUID */
	struct lun_tracking *next_lun;
};


static const char VHCI_COMPONENT[] = "scsi_vhci";
static void
scsi_vhci_details(struct lun_tracking *lun)
{
	HBA_FCPSCSIENTRYV2 entry = lun->map;
	int		retval = 0;
	int		pathcnt, i, count, found = 0;
	char		temppath[MAXPATHLEN];
	char		buf[MAXPATHLEN];
	char	*path_state[5];

	char	*phys_path = get_slash_devices_from_osDevName(
				entry.ScsiId.OSDeviceName,
				STANDARD_DEVNAME_HANDLING);
	char	*devPath = NULL;
	char	*trailingCruft = NULL;
	char	devaddr[MAXPATHLEN];
	sv_iocdata_t	ioc;
	int	prop_buf_size = SV_PROP_MAX_BUF_SIZE;
	char	*path_class_val = NULL;
	char	client_path[MAXPATHLEN];
	char	phci_path[MAXPATHLEN];

	/* Only proceed if we are an mpxio path */
	if (phys_path == NULL || strstr(phys_path, VHCI_COMPONENT) == NULL) {
	    return;
	}

	path_state[0] = MSGSTR(2400, "INIT");
	path_state[1] = MSGSTR(2401, "ONLINE");
	path_state[2] = MSGSTR(2402, "STANDBY");
	path_state[3] = MSGSTR(2403, "FAULT");
	path_state[4] = MSGSTR(2404, "OFFLINE");

	sprintf(devaddr, "%016llx,%x", wwnConversion(
		entry.FcpId.PortWWN.wwn),
		entry.ScsiId.ScsiOSLun);

	/* First get the controller path */
	sprintf(temppath, "/dev/cfg/c%d", entry.ScsiId.ScsiBusNumber);
	if ((count = readlink(temppath, buf, sizeof (buf)))) {
	    buf[count] = '\0';
	    /* Now skip over the leading "../.." */
	    devPath = strstr(buf, "/devices/");
	    if (devPath == NULL) {
		strcpy(lun->info.pathClass, "Unavailable");
		strcpy(lun->info.pathState, "Unavailable");
		free(phys_path);
		return;
	    }

	    /* Now chop off the trailing ":xxx" portion if present */
	    trailingCruft = strrchr(buf, ':');
	    if (trailingCruft) {
		trailingCruft[0] = '\0';
	    }
	} else {
	    strcpy(lun->info.pathClass, "Unavailable");
	    strcpy(lun->info.pathState, "Unavailable");
	    free(phys_path);
	    return;
	}

	ioc.client = client_path;
	ioc.phci = phci_path;

	retval = get_scsi_vhci_pathinfo(phys_path, &ioc, &pathcnt);
	if (retval != 0) {
	    print_errString(retval, NULL);
	    exit(-1);
	}

	for (i = 0; i < pathcnt; i++) {
	    nvlist_t *nvl;
	    if (strstr(devPath, ioc.ret_buf[i].device.ret_phci)) {
		/* This could break someday if MPxIO changes devaddr */
		if (strstr(ioc.ret_buf[i].ret_addr, devaddr)) {
		    retval = nvlist_unpack(ioc.ret_buf[i].ret_prop.buf,
			prop_buf_size, &nvl, 0);
		    if (retval != 0) {
			strcpy(lun->info.pathClass,
			    "UNKNOWN PROB");
		    } else {
			strcpy(lun->info.pathState,
			    path_state[ioc.ret_buf[i].ret_state]);
			lun->info.pathInfoState = ioc.ret_buf[i].ret_state;
			lun->info.pathInfoExternalState =
			    ioc.ret_buf[i].ret_ext_state;
			if (nvlist_lookup_string(nvl, "path-class",
				&path_class_val) == 0) {
			    strcpy(lun->info.pathClass, path_class_val);
			} else {
			    strcpy(lun->info.pathClass, "UNKNOWN");
			}
		    }
		    nvlist_free(nvl);
		    found++;
		    break;
		}
	    }

	}

	if (!found) {
	    strcpy(lun->info.pathClass, "Unavailable");
	    strcpy(lun->info.pathState, "Unavailable");
	}
	free(phys_path);

	/* free everything we alloced */
	for (i = 0; i < ioc.buf_elem; i++) {
		free(ioc.ret_buf[i].ret_prop.buf);
		free(ioc.ret_buf[i].ret_prop.ret_buf_size);
	}
	free(ioc.ret_buf);

}

/* Utility routine to add new entries to the list (ignores dups) */
static void
add_lun_path(struct lun_tracking *head, HBA_FCPSCSIENTRYV2  *map,
	    HBA_WWN pwwn, char *path)
{
	struct lun_tracking *tmp = NULL, *cmp = NULL;

	for (tmp = head; tmp != NULL; tmp = tmp->next_lun) {
	    if (memcmp(&tmp->map.LUID, &map->LUID,
		    sizeof (HBA_LUID)) == 0) {

		/* Ensure this isn't a duplicate */
		for (cmp = tmp; cmp->next_path != NULL;
			    cmp = cmp->next_path) {
		    if (memcmp(&cmp->map, map, sizeof (cmp->map)) == 0) {
			return;
		    }
		}
		if (memcmp(&cmp->map, map, sizeof (cmp->map)) == 0) {
		    return;
		}

		/* We have a new entry to add */
		cmp->next_path = (struct lun_tracking *)calloc(1,
		    sizeof (struct lun_tracking));
		cmp = cmp->next_path;
		(void) memcpy(&cmp->map, map,
		    sizeof (cmp->map));
		(void) memcpy(&cmp->hba_pwwn, &pwwn,
			sizeof (cmp->hba_pwwn));
		(void) snprintf(cmp->hba_path, MAXPATHLEN,
		    path);
		scsi_vhci_details(cmp);
		return;
	    }
	}
	/* Append a new LUN at the end of the list */
	for (tmp = head; tmp->next_lun != NULL; tmp = tmp->next_lun) {}
	tmp->next_lun = (struct lun_tracking *)calloc(1,
		sizeof (struct lun_tracking));
	tmp = tmp->next_lun;
	(void) memcpy(&tmp->map, map,
		sizeof (tmp->map));
	(void) memcpy(&tmp->hba_pwwn, &pwwn,
		sizeof (tmp->hba_pwwn));
	(void) snprintf(tmp->hba_path, MAXPATHLEN,
		path);
	scsi_vhci_details(tmp);
}

/*ARGSUSED*/
int
fchba_display_config(char **argv, int option_t_input, int argc)
{
	int		path_index = 0;
	uint64_t	wwn;
	uint64_t	lun = 0;
	HBA_HANDLE handle;
	HBA_ADAPTERATTRIBUTES hbaAttrs;
	HBA_PORTATTRIBUTES portAttrs;
	HBA_FCPTARGETMAPPINGV2    *map;
	HBA_STATUS status;
	int count, adapterIndex, portIndex;
	char name[256];
	L_inquiry	inq;
	struct scsi_extended_sense sense;
	struct page80	serial;
	HBA_UINT8	scsiStatus;
	uint32_t	inquirySize = sizeof (inq), senseSize = sizeof (sense);
	uint32_t	serialSize = sizeof (serial);
	struct mode_page	*pg_hdr;
	uchar_t		*pg_buf;
	float		lunMbytes;
	struct capacity_data_struct cap_data;
	uint32_t	    cap_data_size = sizeof (cap_data);
	struct mode_header_g1	*mode_header_ptr;
	int		offset;
	char *phys_path = NULL;
	int		mpxio = 0;
	int		wwnCompare = 0;
	char	    *physical = NULL;
	struct lun_tracking	*head = NULL;
	boolean_t	goodPath = B_FALSE;
	int		ret = 0;



	if ((status = loadLibrary())) {
	    return (-1);
	}
	for (path_index = 0; argv[path_index] != NULL; path_index++) {
	    goodPath = B_FALSE;

	    if (is_wwn(argv[path_index])) {
		(void) sscanf(argv[path_index], "%016llx", &wwn);
		wwnCompare = 1;
	    } else if (!is_path(argv[path_index])) {
		fprintf(stderr, MSGSTR(112, "Error: Invalid pathname (%s)"),
			argv[path_index]);
		fprintf(stderr, "\n");
		ret = -1;
		continue;
	    }
	    if (!wwnCompare) {
		/* Convert the paths to phsyical paths */
		physical = get_slash_devices_from_osDevName(argv[path_index],
			STANDARD_DEVNAME_HANDLING);
		if (!physical) {
		    fprintf(stderr, MSGSTR(112,
			"Error: Invalid pathname (%s)"),
			argv[path_index]);
		    fprintf(stderr, "\n");
		    ret = -1;
		    continue;
		}
	    }

	    count = getNumberOfAdapters();


		/*
		 * We have to loop twice to ensure we don't miss any
		 * extra paths for other targets in a multi-target device
		 */

	    /* First check WWN/path comparisons */
	    for (adapterIndex = 0; adapterIndex < count; adapterIndex ++) {
		if (skip_hba(adapterIndex)) {
		    continue;
		}
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
		    int	    matched = 0;
		    int	    mapIndex;
		    char	    *tmp;
		    if (getAdapterPortAttrs(handle, name, portIndex,
			    &portAttrs)) {
			continue;
		    }

		    if (fetch_mappings(handle, portAttrs.PortWWN, &map)) {
			continue;
		    }



		    for (mapIndex = 0; mapIndex < map->NumberOfEntries;
			    mapIndex ++) {
			matched = 0;
			if (wwnCompare) {
			    if (wwn == wwnConversion(
				    map->entry[mapIndex].FcpId.NodeWWN.wwn) ||
				    wwn == wwnConversion(
				    map->entry[mapIndex].FcpId.PortWWN.wwn)) {
				matched = 1;
			    }
			} else {
			    tmp = get_slash_devices_from_osDevName(
				    map->entry[mapIndex].ScsiId.OSDeviceName,
				    STANDARD_DEVNAME_HANDLING);
			    if ((tmp != NULL) && (strncmp(physical, tmp,
				    MAXPATHLEN) == 0)) {
				matched = 1;
				free(tmp);
			    }
			}
			if (matched && head == NULL) {
			    goodPath = B_TRUE;
			    head  = (struct lun_tracking *)calloc(1,
				    sizeof (struct lun_tracking));
			    (void) memcpy(&head->map, &map->entry[mapIndex],
				    sizeof (head->map));
			    (void) memcpy(&head->hba_pwwn, &portAttrs.PortWWN,
				    sizeof (head->hba_pwwn));
			    (void) snprintf(head->hba_path, MAXPATHLEN,
				portAttrs.OSDeviceName);
			    scsi_vhci_details(head);
			} else if (matched) {
			    goodPath = B_TRUE;
			    add_lun_path(head, &map->entry[mapIndex],
				portAttrs.PortWWN, portAttrs.OSDeviceName);
			}
		    }
		}
	    }

	    if (physical) {
		free(physical);
	    }

	    /* Now do it again and look for matching LUIDs (aka GUIDs) */
	    for (adapterIndex = 0; adapterIndex < count; adapterIndex ++) {
		if (skip_hba(adapterIndex)) {
		    continue;
		}
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
		    int	    matched = 0;
		    int	    mapIndex;
		    if (getAdapterPortAttrs(handle, name, portIndex,
			    &portAttrs)) {
			continue;
		    }

		    if (fetch_mappings(handle, portAttrs.PortWWN, &map)) {
			continue;
		    }


		    for (mapIndex = 0; mapIndex < map->NumberOfEntries;
			    mapIndex ++) {
			struct lun_tracking *outer;
			matched = 0;
			for (outer = head; outer != NULL;
				    outer = outer->next_lun) {
			    struct lun_tracking *inner;
			    for (inner = outer; inner != NULL;
				    inner = inner->next_path) {
				if (memcmp(&inner->map.LUID,
					&map->entry[mapIndex].LUID,
					sizeof (HBA_LUID)) == 0) {
				    matched = 1;
				    break;
				}
			    }
			    if (matched) {
				break;
			    }
			}
			if (matched && head == NULL) {
			    goodPath = B_TRUE;
			    head  = (struct lun_tracking *)calloc(1,
				    sizeof (struct lun_tracking));
			    (void) memcpy(&head->map, &map->entry[mapIndex],
				    sizeof (head->map));
			    (void) memcpy(&head->hba_pwwn, &portAttrs.PortWWN,
				    sizeof (head->hba_pwwn));
			    (void) snprintf(head->hba_path, MAXPATHLEN,
				portAttrs.OSDeviceName);
			    scsi_vhci_details(head);
			} else if (matched) {
			    goodPath = B_TRUE;
			    add_lun_path(head, &map->entry[mapIndex],
				portAttrs.PortWWN, portAttrs.OSDeviceName);
			}
		    }
		}
	    }
	    if (!goodPath) {
		fprintf(stderr, MSGSTR(112, "Error: Invalid pathname (%s)"),
			argv[path_index]);
		fprintf(stderr, "\n");
		ret = -1;
		/* Just bomb out instead of going on */
		return (ret);
	    }
	}

	/* Now display all the LUNs that we found that matched */
	{
	    struct lun_tracking *first_time;
	    struct lun_tracking *tmp_path;
	    for (first_time = head; first_time != NULL;
		    first_time = first_time->next_lun) {
		struct lun_tracking *path;
		phys_path = get_slash_devices_from_osDevName(
		    first_time->map.ScsiId.OSDeviceName,
		    STANDARD_DEVNAME_HANDLING);
		/* Change behavior if this is an MPxIO device */
		if (phys_path != NULL) {
		    if (strstr(phys_path, VHCI_COMPONENT) != NULL) {
			mpxio = 1;
		    }
		}

		for (tmp_path = first_time; tmp_path != NULL;
			tmp_path = tmp_path->next_path) {
			if (mpxio && (strncmp(tmp_path->info.pathState,
			    "ONLINE", strlen(tmp_path->info.pathState)))) {
				/* continue to next online path */
				continue;
			}
			status = HBA_OpenAdapterByWWN(&handle,
			    tmp_path->hba_pwwn);
			if (status != HBA_STATUS_OK) {
				fprintf(stderr, MSGSTR(2431,
				    "Error: Failed to get handle for %s  "),
				    tmp_path->hba_path);
				printStatus(status);
				fprintf(stderr, "\n");
				/* continue to next path */
				continue;
			}

			lun = tmp_path->map.FcpId.FcpLun;
			memset(&inq, 0, sizeof (inq));
			memset(&sense, 0, sizeof (sense));

			status = HBA_ScsiInquiryV2(handle,
				tmp_path->hba_pwwn,
				tmp_path->map.FcpId.PortWWN,
				lun, 0, 0,
				&inq, &inquirySize,
				&scsiStatus,
				&sense, &senseSize);

			if (status == HBA_STATUS_OK) {
				break;
			}
			HBA_CloseAdapter(handle);
		}

		if (tmp_path == NULL) {
			fprintf(stderr, MSGSTR(2430,
			    "Error: I/O failure communicating with %s  "),
			    first_time->map.ScsiId.OSDeviceName);
			printStatus(status);
			fprintf(stderr, "\n");
			continue;
		}

		switch ((inq.inq_dtype & DTYPE_MASK)) {
		case DTYPE_DIRECT:
		    fprintf(stdout, MSGSTR(121,
			    "DEVICE PROPERTIES for disk: %s\n"),
			    first_time->map.ScsiId.OSDeviceName);
		    break;
		case DTYPE_SEQUENTIAL: /* Tape */
		    fprintf(stdout, MSGSTR(2249,
			    "DEVICE PROPERTIES for tape: %s\n"),
			    first_time->map.ScsiId.OSDeviceName);
		    break;
		default:
		    fprintf(stdout, MSGSTR(2250,
			    "DEVICE PROPERTIES for: %s\n"),
			    first_time->map.ScsiId.OSDeviceName);
		    break;
		}
		fprintf(stdout, "  ");
		fprintf(stdout, MSGSTR(3, "Vendor:"));
		fprintf(stdout, "\t\t");
		print_chars(inq.inq_vid, sizeof (inq.inq_vid), 0);
		fprintf(stdout, MSGSTR(2115, "\n  Product ID:\t\t"));
		print_chars(inq.inq_pid, sizeof (inq.inq_pid), 0);

		fprintf(stdout, "\n  ");
		fprintf(stdout, MSGSTR(2119, "Revision:"));
		fprintf(stdout, "\t\t");
		print_chars(inq.inq_revision, sizeof (inq.inq_revision), 0);

		fprintf(stdout, "\n  ");
		fprintf(stdout, MSGSTR(17, "Serial Num:"));
		fprintf(stdout, "\t\t");
		(void) fflush(stdout);
		/*
		 * Call the inquiry cmd on page 0x80 only if the vendor
		 * supports page 0x80.
		 */
		if ((find_supported_inq_page(handle, first_time->hba_pwwn,
		    first_time->map.FcpId.PortWWN, lun, 0x80))) {
			memset(&serial, 0, sizeof (serial));
			status = HBA_ScsiInquiryV2(handle,
			    first_time->hba_pwwn,
			    first_time->map.FcpId.PortWWN,
			    lun, 1, 0x80,
			    &serial, &serialSize,
			    &scsiStatus,
			    &sense, &senseSize);
			if (status == HBA_STATUS_OK) {
				print_chars(serial.inq_serial,
				    sizeof (serial.inq_serial), 0);
			} else {
				fprintf(stdout, MSGSTR(2506, "Unsupported"));
			}
		} else {
			fprintf(stdout, MSGSTR(2506, "Unsupported"));
		}
		HBA_CloseAdapter(handle);
		if ((inq.inq_dtype & DTYPE_MASK) == DTYPE_DIRECT) {
		/* Read capacity wont work on standby paths, so try till OK */
		    for (tmp_path = first_time; tmp_path != NULL;
			tmp_path = tmp_path->next_path) {
			if (mpxio && (strncmp(tmp_path->info.pathState,
			    "ONLINE", strlen(tmp_path->info.pathState)))) {
			    /* continue to next online path */
			    continue;
			}
			status = HBA_OpenAdapterByWWN(&handle,
						tmp_path->hba_pwwn);
			if (status != HBA_STATUS_OK) {
			    /* continue to next path */
			    continue;
			}

			status = HBA_ScsiReadCapacityV2(handle,
			    tmp_path->hba_pwwn,
			    tmp_path->map.FcpId.PortWWN,
			    tmp_path->map.FcpId.FcpLun,
			    &cap_data, &cap_data_size,
			    &scsiStatus,
			    &sense, &senseSize);
			if (status == HBA_STATUS_OK) {
			    break;
			} else if (status == HBA_STATUS_SCSI_CHECK_CONDITION &&
			    sense.es_key == KEY_UNIT_ATTENTION) {
			/*
			 * retry for check-condition state when unit attention
			 * condition has been established
			 */
			    status =  HBA_ScsiReadCapacityV2(handle,
				tmp_path->hba_pwwn,
				tmp_path->map.FcpId.PortWWN,
				tmp_path->map.FcpId.FcpLun,
				&cap_data, &cap_data_size,
				&scsiStatus,
				&sense, &senseSize);
			    if (status == HBA_STATUS_OK) {
				break;
			    }
			}
			HBA_CloseAdapter(handle);
		    }
		}
		if (handle != HBA_HANDLE_INVALID) {
			HBA_CloseAdapter(handle);
		}
		if (status != HBA_STATUS_OK) {
		    /* Make sure we don't display garbage */
		    cap_data.block_size = 0;
		    cap_data.last_block_addr = 0;
		}

		if (cap_data.block_size > 0 &&
			cap_data.last_block_addr > 0) {
		    lunMbytes = ntohl(cap_data.last_block_addr) + 1;
		    lunMbytes *= ntohl(cap_data.block_size);
		    lunMbytes /= (float)(1024*1024);
		    fprintf(stdout, "\n  ");
		    fprintf(stdout, MSGSTR(60,
			    "Unformatted capacity:\t%6.3f MBytes"), lunMbytes);
		}
		fprintf(stdout, "\n");

		/*
		 * get mode page information for FC device.
		 * do not do mode sense if this is a tape device.
		 * mode sense will rewind the tape
		 */
		if ((inq.inq_dtype & DTYPE_MASK) != DTYPE_SEQUENTIAL) {
		    if (get_mode_page(first_time->map.ScsiId.OSDeviceName,
			&pg_buf) == 0) {
			mode_header_ptr = (struct mode_header_g1 *)
				(void *)pg_buf;
			offset = sizeof (struct mode_header_g1) +
			    ntohs(mode_header_ptr->bdesc_length);
			pg_hdr = (struct mode_page *)&pg_buf[offset];

			while (offset < (ntohs(mode_header_ptr->length) +
			    sizeof (mode_header_ptr->length))) {
			    if (pg_hdr->code == MODEPAGE_CACHING) {
				struct	mode_caching	*pg8_buf;
				pg8_buf = (struct mode_caching *)
				    (void *)pg_hdr;
				if (pg8_buf->wce) {
				    fprintf(stdout, MSGSTR(2122,
					"  Write Cache:\t\t"
					"Enabled\n"));
				}
				if (pg8_buf->rcd == 0) {
				    fprintf(stdout, MSGSTR(2123,
					"  Read Cache:\t\t"
					"Enabled\n"));
				    fprintf(stdout, MSGSTR(2509,
					"    Minimum prefetch:\t0x%x\n"
					"    Maximum prefetch:\t0x%x\n"),
					pg8_buf->min_prefetch,
					pg8_buf->max_prefetch);
				}
				break;
			    }
			    offset += pg_hdr->length +
				sizeof (struct mode_page);
			    pg_hdr = (struct mode_page *)&pg_buf[offset];
			}
		    }
		}

		fprintf(stdout, "  %s\t\t", MSGSTR(35, "Device Type:"));
		if ((inq.inq_dtype & DTYPE_MASK) < 0x10) {
			fprintf(stdout, "%s\n",
			    dtype[inq.inq_dtype & DTYPE_MASK]);
		} else if ((inq.inq_dtype & DTYPE_MASK) < 0x1f) {
			fprintf(stdout, MSGSTR(2432, "Reserved"));
		} else {
			/* dtype of 0x1f is returned */
			fprintf(stdout, MSGSTR(2433, "Unknown"));
		}

		fprintf(stdout, MSGSTR(2128, "  Path(s):\n"));
		fprintf(stdout, "\n");
		fprintf(stdout, "  %s\n",
		    first_time->map.ScsiId.OSDeviceName);
		if (phys_path != NULL) {
		    fprintf(stdout, "  %s\n", phys_path);
		}

		/* Now display all paths to this LUN */
		for (path = first_time; path != NULL;
		    path = path->next_path) {
		    /* Display the controller information */
		    fprintf(stdout, MSGSTR(2303, "   Controller      \t%s\n"),
			    path->hba_path);

		    fprintf(stdout, MSGSTR(2507,
			    "    Device Address\t\t%016llx,%x\n"),
			    wwnConversion(
			    path->map.FcpId.PortWWN.wwn),
			    path->map.ScsiId.ScsiOSLun);

		    fprintf(stdout, MSGSTR(2508,
			    "    Host controller port WWN\t%016llx\n"),
			    wwnConversion(path->hba_pwwn.wwn));

		    if (mpxio) {
			fprintf(stdout, MSGSTR(2305,
				"    Class\t\t\t%s\n"), path->info.pathClass);
			fprintf(stdout, MSGSTR(2306,
				"    State\t\t\t%s\n"), path->info.pathState);
		    }
		    if (phys_path != NULL) {
			free(phys_path);
			phys_path = NULL;
		    }
		}
		printf("\n");
	    }
	}
	return (ret);
}

/*
 * handle expert-mode hotplug commands
 *
 * return 0 iff all is okay
 */
int
fchba_hotplug_e(int todo, char **argv, int verbose_flag, int force_flag)
{
char		*path_phys = NULL;
int		exit_code;
devctl_hdl_t	dcp;

	if (todo != DEV_ONLINE &&
	    todo != DEV_OFFLINE) {
	    fprintf(stderr, "%s\n", strerror(ENOTSUP));
	    return (-1);
	}

	/* Convert the paths to phsyical paths */
	path_phys = get_slash_devices_from_osDevName(argv[0],
		NOT_IGNORE_DANGLING_LINK);
	if (!path_phys) {
	    fprintf(stderr, MSGSTR(112,
		"Error: Invalid pathname (%s)"),
		argv[0]);
	    fprintf(stderr, "\n");
	    return (-1);
	}
	if (verbose_flag) {
		(void) fprintf(stdout,
				MSGSTR(5516,
				"phys path = \"%s\"\n"),
				path_phys);
	}
	/* acquire rights to hack on device */
	if ((dcp = devctl_device_acquire(path_phys,
		force_flag ? 0 : DC_EXCL)) == NULL) {

		(void) fprintf(stderr, MSGSTR(5517,
		    "Error: can't acquire \"%s\": %s\n"),
		    path_phys, strerror(errno));
		return (1);
	}

	switch (todo) {
	case DEV_ONLINE:
		exit_code = devctl_device_online(dcp);
		break;
	case DEV_OFFLINE:
		exit_code = devctl_device_offline(dcp);
		break;
	}

	if (exit_code != 0) {
		perror(MSGSTR(5518, "devctl"));
	}

	/* all done now -- release device */
	devctl_release(dcp);

	if (path_phys) {
	    free(path_phys);
	}

	return (exit_code);
}

/*
 * Returns non zero if we should use FC-HBA.
 * For x86, luxadm uses FC-HBA.
 */
int
use_fchba()
{

#ifdef __x86
	return (1);
#else
	return (0);
#endif

}

/*
 * Returns non-zero if we should skip the HBA at index "i"
 */
int
skip_hba(int i) {
	HBA_LIBRARYATTRIBUTES lib_attrs;
	(void) HBA_GetVendorLibraryAttributes(i, &lib_attrs);
	if (strncmp(lib_attrs.VName, VSL_NAME,
		sizeof (lib_attrs.VName)) == 0) {
	    return (0);
	}
	return (1);
}

/*
 * Function to determine if the given page is supported by vendor.
 */
int
find_supported_inq_page(HBA_HANDLE handle, HBA_WWN hwwn, HBA_WWN pwwn,
    uint64_t lun, int page_num)
{
	struct	scsi_extended_sense	sense;
	L_inquiry00			inq00;
	uchar_t				*data;
	HBA_STATUS			status = HBA_STATUS_ERROR;
	int				index;
	HBA_UINT8			scsiStatus;
	uint32_t			inqSize = sizeof (inq00);
	uint32_t			senseSize = sizeof (sense);

	status = HBA_ScsiInquiryV2(handle, hwwn, pwwn, lun, 1, 0x00,
	    &inq00, &inqSize, &scsiStatus, &sense, &senseSize);

	if (status == HBA_STATUS_OK) {
		data = (uchar_t *)&inq00;
		for (index = 4; (index <= inq00.len+3)&&
		    (data[index] <= page_num); index ++) {
			if (data[index] == page_num) {
				return (1);
			}
		}
	}
	return (0);
}
