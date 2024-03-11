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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <libipmi.h>
#include <stdio.h>
#include <string.h>

static const char *pname;
static const char optstr[] = "h:p:u:t:";

static void
usage()
{
	(void) fprintf(stderr,
	    "Usage: %s [-t <bmc|lan>] [-h hostname] [-u username] "
	    "[-p password]\n", pname);
}

/*ARGSUSED*/
static int
sdr_print(ipmi_handle_t *ihp, ipmi_entity_t *ep, const char *name,
    ipmi_sdr_t *sdrp, void *data)
{
	int indentation = (uintptr_t)data;
	ipmi_sdr_compact_sensor_t *csp;
	ipmi_sdr_full_sensor_t *fsp;
	uint8_t sensor_number, sensor_type, reading_type;
	boolean_t get_reading = B_FALSE;
	ipmi_sensor_reading_t *srp;
	char sensor_name[128];
	char reading_name[128];

	if (name == NULL)
		return (0);

	switch (sdrp->is_type) {
	case IPMI_SDR_TYPE_COMPACT_SENSOR:
		csp = (ipmi_sdr_compact_sensor_t *)sdrp->is_record;
		sensor_number = csp->is_cs_number;
		sensor_type = csp->is_cs_type;
		reading_type = csp->is_cs_reading_type;
		get_reading = B_TRUE;
		break;

	case IPMI_SDR_TYPE_FULL_SENSOR:
		fsp = (ipmi_sdr_full_sensor_t *)sdrp->is_record;
		sensor_number = fsp->is_fs_number;
		sensor_type = fsp->is_fs_type;
		reading_type = fsp->is_fs_reading_type;
		get_reading = B_TRUE;
		break;
	}

	(void) printf("%*s%-*s", indentation, "",
	    36 - indentation, name);

	if (get_reading) {
		ipmi_sensor_type_name(sensor_type, sensor_name,
		    sizeof (sensor_name));
		ipmi_sensor_reading_name(sensor_type, reading_type,
		    reading_name, sizeof (reading_name));
		(void) printf("%12s  %12s", sensor_name, reading_name);
		if ((srp = ipmi_get_sensor_reading(ihp,
		    sensor_number)) == NULL) {
			if (ipmi_errno(ihp) == EIPMI_NOT_PRESENT) {
				(void) printf("      -\n");
			} else {
				(void) printf("\n");
				return (-1);
			}
		} else {
			(void) printf("   %04x\n", srp->isr_state);
		}
	} else {
		(void) printf("\n");
	}

	return (0);
}

static int
entity_print(ipmi_handle_t *ihp, ipmi_entity_t *ep, void *data)
{
	int indentation = (uintptr_t)data;
	char name[128];
	boolean_t present;

	ipmi_entity_name(ep->ie_type, name, sizeof (name));
	(void) snprintf(name + strlen(name), sizeof (name) - strlen(name),
	    " %d", ep->ie_instance);

	if (ipmi_entity_present(ihp, ep, &present) != 0) {
		(void) printf("%*s%-*s  %s (%s)\n", indentation, "",
		    24 - indentation, name, "unknown", ipmi_errmsg(ihp));
	} else {
		(void) printf("%*s%-*s  %s\n", indentation, "",
		    24 - indentation, name, present ? "present" : "absent");
	}
	(void) ipmi_entity_iter_sdr(ihp, ep, sdr_print,
	    (void *)(indentation + 2));

	if (ep->ie_children != 0)
		(void) ipmi_entity_iter_children(ihp, ep, entity_print,
		    (void *)(indentation + 2));
	return (0);
}

int
main(int argc, char **argv)
{
	ipmi_handle_t *ihp;
	char *errmsg;
	uint_t xport_type;
	char *host = NULL, *user = NULL, *passwd = NULL;
	int c, err;
	nvlist_t *params = NULL;

	pname = argv[0];
	while (optind < argc) {
		while ((c = getopt(argc, argv, optstr)) != -1)
			switch (c) {
			case 'h':
				host = optarg;
				break;
			case 'p':
				passwd = optarg;
				break;
			case 't':
				if (strcmp(optarg, "bmc") == 0)
					xport_type = IPMI_TRANSPORT_BMC;
				else if (strcmp(optarg, "lan") == 0)
					xport_type = IPMI_TRANSPORT_LAN;
				else {
					(void) fprintf(stderr,
					    "ABORT: Invalid transport type\n");
					usage();
				}
				break;
			case 'u':
				user = optarg;
				break;
			default:
				usage();
				return (1);
			}
	}

	if (xport_type == IPMI_TRANSPORT_LAN &&
	    (host == NULL || passwd == NULL || user == NULL)) {
		(void) fprintf(stderr, "-h/-u/-p must all be specified for "
		    "transport type \"lan\"\n");
		usage();
		return (1);
	}
	if (xport_type == IPMI_TRANSPORT_LAN) {
		if (nvlist_alloc(&params, NV_UNIQUE_NAME, 0) ||
		    nvlist_add_string(params, IPMI_LAN_HOST, host) ||
		    nvlist_add_string(params, IPMI_LAN_USER, user) ||
		    nvlist_add_string(params, IPMI_LAN_PASSWD, passwd)) {
			(void) fprintf(stderr,
			    "ABORT: nvlist construction failed\n");
			return (1);
		}
	}
	if ((ihp = ipmi_open(&err, &errmsg, xport_type, params)) == NULL) {
		(void) fprintf(stderr, "failed to open libipmi: %s\n",
		    errmsg);
		return (1);
	}

	(void) printf("%-24s  %-8s  %12s  %12s  %5s\n",
	    "ENTITY/SENSOR", "PRESENT", "SENSOR", "READING", "STATE");
	(void) printf("-----------------------  --------  -------------  "
	    "------------  -----\n");
	if (ipmi_entity_iter(ihp, entity_print, NULL) != 0) {
		(void) fprintf(stderr, "failed to iterate entities: %s\n",
		    ipmi_errmsg(ihp));
		return (1);
	}

	ipmi_close(ihp);

	return (0);
}
