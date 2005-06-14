/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Display WRSM kstat data.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <kstat.h>
#include <libintl.h>
#include <values.h>
#include <locale.h>
#include <sys/rsm/rsmpi.h>
#include <sys/wrsm.h>
#include <sys/wci_common.h>
#ifndef lint
#include <sys/wci_cmmu.h>
#else
typedef union {
	struct {
		uint64_t count_enable;
	} bit;
	uint64_t val;
} wci_sram_array_as_cmmu_0_u;
#endif /* lint */

#define	ERR_NO_ERR	0
#define	ERR_UNKNOWN	1
#define	ERR_USAGE	2
#define	ERR_KSOPEN	3
#define	ERR_KSLOOKUP	4
#define	ERR_KSREAD	5

#define	MAX_CMMU_ENTRIES (0x200000) /* 2 million entries max */

/* Error messages */
#define	MSG_WRONG_ARGUMENT  gettext("wrsmstat: wrong argument\n")
#define	MSG_ERROR_ARGUMENTS gettext("wrsmatat: error reading arguments\n")
#define	MSG_KSTAT_OPEN_FAIL gettext("wrsmstat: kstat not found\n")
#define	MSG_KSTAT_NO_DATA   gettext("wrsmstat: no data in kstat\n")
#define	MSG_WRSM_FAIL	    gettext("wrsmstat: wrsm instance not found\n")
#define	MSG_ROUTE_FAIL	    gettext("wrsmstat: route not found\n")
#define	MSG_CONTROLLER_FAIL gettext("wrsmstat: controller not found\n")
#define	MSG_SUB_NOT_IMPL    gettext("wrsmstat: subcommand not implemented\n")
#define	MSG_BAD_SUB	    gettext("wrsmstat: bad subcommand: %s\n")
/* WCI kstat messages */
#define	MSG_WCI_INSTANCE    gettext("WCI instance: %d\n")
#define	MSG_PORT_ID	    gettext("Port ID:                       %d\n")
#define	MSG_CTLR_ID	    gettext("Controller ID:                 %d")
#define	MSG_WCI_NOT_BELONG  gettext(" (WCI does not belong to a controller)\n")
#define	MSG_WCI_IN_LOOPBACK gettext(" (WCI is in loopback test mode)\n")
#define	MSG_CONFIG_VERSION  gettext("Config Version:                %llu\n")
#define	MSG_ERROR_LIMIT	    gettext("Link Error Shutdown Trigger:   %d\n")
#define	MSG_LINK_NOT_PRES   gettext("Link %d is not present.\n")
#define	MSG_LINK_ID	    gettext("Link %d\n")
#define	MSG_LINK_STATE	    gettext("\tLink State:             ")
#define	MSG_STATE_UP	    gettext("up\n")
#define	MSG_STATE_DOWN	    gettext("down\n")
#define	MSG_STATE_NO_PAROLI gettext("no PAROLI\n")
#define	MSG_STATE_WAIT_DOWN gettext("wait (down)\n")
#define	MSG_STATE_WAIT_UP   gettext("wait (up)\n")
#define	MSG_STATE_ERR_DOWN  gettext("wait (error down)\n")
#define	MSG_UNKNOWN	    gettext("unknown\n")
#define	MSG_PHYS_STATE	    gettext("\tPhysical Link State:    ")
#define	MSG_STATE_OFF	    gettext("off\n")
#define	MSG_STATE_FAILOVER  gettext("failover\n")
#define	MSG_STATE_SEEK	    gettext("seek\n")
#define	MSG_STATE_IN_USE    gettext("in use\n")
#define	MSG_LASER_ENABLED   gettext("\tLaser Enabled:          %s\n")
#define	MSG_TX_ENABLED	    gettext("\tTransmit Enabled:       %s\n")
#define	MSG_REMOTE_CNODE    gettext("\tRemote RSM HW addr:     %d\n")
#define	MSG_REMOTE_WNODE    gettext("\tRemote wnode ID:        %d\n")
#define	MSG_REMOTE_LINK	    gettext("\tRemote link num:        %d\n")
#define	MSG_REMOTE_WCI	    gettext("\tRemote WCI port ID:     %d\n")
#define	MSG_DIS_TAKEDOWNS   gettext("\tDisconnected takedowns: %d\n")
#define	MSG_ERR_TAKEDOWNS   gettext("\tError takedowns:        %d\n")
#define	MSG_CFG_TAKEDOWNS   gettext("\tBad Config takedowns:   %d\n")
#define	MSG_FAILED_BRINGUPS gettext("\tFailed bringups:        %d\n")
#define	MSG_LINK_ENABLED    gettext("\tLink enabled:           %s\n")
#define	MSG_TOT_LINK_ERRS   gettext("\tTotal link errors:      %d\n")
#define	MSG_MAX_LINK_ERRS   gettext("\tMaximum link errors:    %d\n")
#define	MSG_AVE_LINK_ERRS   gettext("\tAverage link errors:    %d\n")
#define	MSG_AUTO_SHUT_EN    gettext("\tAuto shutdown enabled:  %s\n")
#define	MSG_CLUSTER_ERR	    gettext("Cluster Error Count:           %lld\n")
#define	MSG_SRAM_ECC	    gettext("Uncorrectable SRAM ECC error:  %s\n")
#define	MSG_MAX_ECC	    gettext("Maximum SRAM ECC errors:       %ld\n")
#define	MSG_AVE_ECC	    gettext("Average SRAM ECC errors:       %ld\n")
/* Route kstat messages */
#define	MSG_ROUTE_CTLR	    gettext("\nController %d - Route to %s\n")
#define	MSG_FM_NODE_ID	    gettext("FM node id:                    0x%x\n")
#define	MSG_ROUTE_CNODE	    gettext("RSM hardware addr:             %d\n")
#define	MSG_ROUTE_CHANGES   gettext("Route Changes:                 %d\n")
#define	MSG_ROUTE_MH	gettext("Route Type:                    Multihop\n")
#define	MSG_ROUTE_PT	gettext("Route Type:                    Passthrough\n")
#define	MSG_NUM_WCIS	    gettext("Number of WCIs:                %d\n")
#define	MSG_STRIPES	    gettext("Stripes:                       %d\n")
#define	MSG_PORTID	    gettext("\tPort ID:               %d\n")
#define	MSG_INSTANCE	    gettext("\tInstance :             %d\n")
#define	MSG_NUM_HOPS	    gettext("\tNumber of hops:        %d\n")
#define	MSG_NUM_LINKS	    gettext("\tNumber of links:       %d\n")
#define	MSG_ROUTE_LINKID    gettext("\t\tLink #%d, ")
#define	MSG_ROUTE_NODEID    gettext("first hop RSM HW addr: 0x%x\n")
#define	MSG_ROUTE_SWITCH gettext("is a switch, leading to RSM HW addr: 0x%x\n")
/* Controller kstat messages */
#define	MSG_CONTROLLER	   gettext("\nController %d\n")
#define	MSG_CTLR_STATE	    gettext("Controller state:            ")
#define	MSG_CTLR_NOT_AVAIL  gettext("not available\n")
#define	MSG_CTLR_UP	    gettext("up\n")
#define	MSG_CTLR_DOWN	    gettext("down\n")
#define	MSG_CTLR_ADDR	    gettext("Local RSM Hardware Address:  0x%llx\n")
#define	MSG_EX_MEMSEGS	    gettext("Exported segments:           %d\n")
#define	MSG_EX_MEMSEGS_PUB  gettext("\tNum published:       %d\n")
#define	MSG_EX_MEMSEG_CON   gettext("\tNum connections:     %d\n")
#define	MSG_BYTES_BOUND	    gettext("\tTotal bound memory:  %lld\n")
#define	MSG_IM_MEMSEGS_CON  gettext("Imported segments:           %d\n")
#define	MSG_SENDQS	    gettext("Send Queues:                 %lld\n")
#define	MSG_HANDLERS	    gettext("Registered Handlers:         %ld\n")
#define	MSG_RSM_NUM_WCIS    gettext("Assigned WCIs:               %d\n")
#define	MSG_RSM_AVAIL_WCIS  gettext("Available WCIs:              %d\n")
#define	MSG_NUM_RECONFIGS   gettext("Number of reconfigs:         %d\n")
#define	MSG_FREE_CMMUS	    gettext("Number of free CMMU entries: %d\n")

static boolean_t msg_test = B_FALSE;

#define	NOT_FOUND	0xffffffff
#define	NOT_FOUND64	0xffffffffffffffff
static uint32_t find_named(kstat_t *ksp, char *name);
static uint64_t find_named64(kstat_t *ksp, char *name);
static char *find_named_char(kstat_t *ksp, char *name);

static void show_usage();

static int find_wrsm(int wci_id, boolean_t v, boolean_t private,
    kstat_ctl_t *kc);
static int fetch_wrsm(int instance, boolean_t v, kstat_ctl_t *kc);
static int fetch_route(int contid, char *fm_node_name, kstat_ctl_t *kc);
static int fetch_controller(int contid, boolean_t private, kstat_ctl_t *kc);
static int trace_cmmu(int wrsm_instance, int s, int e, kstat_ctl_t *kc);

#define	YESORNO(b) ((b) ? (gettext("yes")) : (gettext("no")))

int
main(int argc, char **argv)
{
	kstat_ctl_t *kc;
	kstat_t *chain;
	int c;
	int controller_id = -1;
	int wrsm_instance = -1;
	int wrsm_id = -1;
	int start;
	boolean_t got_start = B_FALSE;
	int end;
	boolean_t got_end = B_FALSE;
	char *set_argument = NULL;
	char *disp_kstat;
	char *nodename = NULL;
	int retval;
	boolean_t print_errors = B_FALSE;
	boolean_t private = B_FALSE;
	char *endptr;
	boolean_t check_endptr = B_FALSE;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 2) {
		/* Not enough arguments */
		show_usage();
		return (ERR_USAGE);
	}

	/* which kstat we are displaying */
	disp_kstat = argv[1];

	while ((c = getopt(argc-1, &argv[1], "c:i:h:ps:e:vw:x:"))
	    != EOF) {
		check_endptr = B_FALSE;
		switch (c) {
		case 'c':
			if ((strcmp(disp_kstat, "controller") == 0) ||
			    (strcmp(disp_kstat, "route") == 0)) {
				controller_id = strtol(optarg, &endptr, 0);
				check_endptr = B_TRUE;
			} else {
				set_argument = optarg;
			}
			break;
		case 'i':
			wrsm_instance = strtol(optarg, &endptr, 0);
			check_endptr = B_TRUE;
			break;
		case 'h':
			nodename = optarg;
			break;
		case 'v':
			print_errors = B_TRUE;
			break;
		case 's':
			start = strtol(optarg, &endptr, 0);
			got_start = B_TRUE;
			check_endptr = B_TRUE;
			break;
		case 'e':
			end = strtol(optarg, &endptr, 0);
			got_end = B_TRUE;
			check_endptr = B_TRUE;
			break;
		case 'w':
			wrsm_id = strtol(optarg, &endptr, 0);
			break;
		case 'p':
			private = B_TRUE;
			break;
		case 'x':
			if (optarg && strcmp(optarg, "msgtest") == 0) {
				msg_test = B_TRUE;
			}
			break;
		default:
			(void) fprintf(stderr, MSG_WRONG_ARGUMENT);
			show_usage();
			return (ERR_USAGE);
		}

		if (check_endptr) {
			if (strcmp(endptr, "\0")) {
				(void) fprintf(stderr, MSG_ERROR_ARGUMENTS);
				show_usage();
				return (ERR_USAGE);
			}
		}
	}

	/* initialize kstat control structure */
	if ((kc = kstat_open()) == NULL) {
		(void) fprintf(stderr, MSG_KSTAT_OPEN_FAIL);
		return (ERR_KSOPEN);
	}

	if (strcmp(disp_kstat, "controller") == 0) {
		if (controller_id != -1 || msg_test) {
			retval = fetch_controller(controller_id, private, kc);
		} else {
			chain = kc->kc_chain;
			/* unless we find something, return error */
			retval = ERR_KSLOOKUP;
			while (chain != NULL) {
				if ((strcmp(chain->ks_module, WRSM_KSTAT_WRSM)
				    == 0) && (strcmp(chain->ks_name,
				    RSM_KS_NAME) == 0)) {
					retval = fetch_controller(
					    chain->ks_instance, private, kc);
				}
				chain = chain->ks_next;
			}
		}
	} else if (strcmp(disp_kstat, "route") == 0) {
		boolean_t controller_found = B_FALSE;
		boolean_t route_found = B_FALSE;

		chain = kc->kc_chain;
		/* unless we find something, return error */
		retval = ERR_KSLOOKUP;
		if (msg_test) {
			controller_found = B_TRUE;
			route_found = B_TRUE;
			if (nodename == NULL) {
				nodename = "?";
			}
			retval = fetch_route(controller_id, nodename, kc);
		} else while (chain != NULL) {
			if (strcmp(chain->ks_module, WRSM_KSTAT_WRSM_ROUTE)
			    == 0) {
				if ((controller_id == -1) || (controller_id ==
				    chain->ks_instance)) {
					controller_found = B_TRUE;
					if ((nodename == NULL) || (strcmp(
					    nodename, chain->ks_name) == 0)) {
						route_found = B_TRUE;
						retval = fetch_route(
							    chain->ks_instance,
							    chain->ks_name,
							    kc);
					}
				}
			}
			chain = chain->ks_next;
		}
		if (controller_id != -1 && !controller_found) {
			(void) printf(MSG_CONTROLLER_FAIL);
		} else if (nodename != NULL && !route_found) {
			(void) printf(MSG_ROUTE_FAIL);
		}
	} else if (strcmp(disp_kstat, "wrsm") == 0) {
		if (wrsm_instance != -1 || msg_test) {
			retval = fetch_wrsm(wrsm_instance, print_errors, kc);
		} else if (wrsm_id != -1) {
			retval = find_wrsm(wrsm_id, print_errors, private, kc);
		} else {
			chain = kc->kc_chain;
			/* unless we find something, return error */
			retval = ERR_KSLOOKUP;
			while (chain != NULL) {
				if ((strcmp(chain->ks_module, WRSM_KSTAT_WRSM)
				    == 0) && (strcmp(chain->ks_name,
				    WRSM_KSTAT_STATUS) == 0)) {
					retval = fetch_wrsm(chain->ks_instance,
					    print_errors, kc);
				}
				chain = chain->ks_next;
			}
		}
	} else if (strcmp(disp_kstat, "set") == 0) {
		if (set_argument == NULL ||
		    strcmp(set_argument, "cmmu") != 0 ||
		    (!got_start) || (!got_end)) {
			show_usage();
			return (ERR_USAGE);
		}
		if (wrsm_instance != -1) {
			retval = trace_cmmu(wrsm_instance, start, end, kc);
		} else {
			chain = kc->kc_chain;
			/* unless we find something, return error */
			retval = ERR_KSLOOKUP;
			while (chain != NULL) {
				if ((strcmp(chain->ks_module, WRSM_KSTAT_WRSM)
				    == 0) && (strcmp(chain->ks_name,
				    WRSM_KSTAT_STATUS) == 0)) {
					retval = trace_cmmu(chain->ks_instance,
					    start, end, kc);
				}
				chain = chain->ks_next;
			}
		}
	} else if (strcmp(disp_kstat, "msgtest") == 0) {
		(void) printf(MSG_WRONG_ARGUMENT);
		(void) printf(MSG_ERROR_ARGUMENTS);
		(void) printf(MSG_KSTAT_OPEN_FAIL);
		(void) printf(MSG_KSTAT_NO_DATA);
		(void) printf(MSG_WRSM_FAIL);
		(void) printf(MSG_ROUTE_FAIL);
		(void) printf(MSG_CONTROLLER_FAIL);
		(void) printf(MSG_SUB_NOT_IMPL);
		(void) printf(MSG_BAD_SUB);
		return (0);
	} else {
		(void) fprintf(stderr, MSG_BAD_SUB, disp_kstat);
		show_usage();
		return (ERR_USAGE);
	}

	(void) kstat_close(kc);

	return (retval);
}


int
find_wrsm(int wci_id, boolean_t print_errors, boolean_t private,
    kstat_ctl_t *kc)
{
	kstat_t *chain;
	kstat_t *kstats;
	uint32_t value;

	chain = kc->kc_chain;

	while (chain != NULL) {
		if ((strcmp(chain->ks_module, WRSM_KSTAT_WRSM) == 0) &&
		    (strcmp(chain->ks_name, WRSM_KSTAT_STATUS) == 0)) {
			if ((kstats = kstat_lookup(kc, WRSM_KSTAT_WRSM,
			    chain->ks_instance, WRSM_KSTAT_STATUS)) == NULL) {
				chain = chain->ks_next;
				continue;
			}

			if (kstat_read(kc, kstats, NULL) == -1) {
				chain = chain->ks_next;
				continue;
			}

			value = find_named(kstats, WRSMKS_PORTID);
			if (value == wci_id) {
				if (private) {
					value = find_named(kstats,
					    WRSMKS_CONTROLLER_ID_NAMED);
					if (value != NOT_FOUND) {
						(void) printf("%d\n", value);
					}
					return (ERR_NO_ERR);
				} else {
					return (fetch_wrsm(chain->ks_instance,
					    print_errors, kc));
				}
			}
		}
		chain = chain->ks_next;
	}

	return (ERR_KSLOOKUP);
}

int
fetch_wrsm(int instance, boolean_t v, kstat_ctl_t *kc)
{
	int i;

	kstat_t *kstats;

	char ks_name[25];
	uint32_t value;
	uint64_t value64;
	boolean_t check_links = B_TRUE;

	if (msg_test) {
		(void) printf("\n");
		(void) printf(MSG_WCI_INSTANCE, 1023);
		(void) printf("-------------\n");
		(void) printf(MSG_PORT_ID, 1023);
		(void) printf(MSG_CTLR_ID, -1);
		(void) printf(MSG_WCI_NOT_BELONG);
		(void) printf(MSG_CTLR_ID, -2);
		(void) printf(MSG_WCI_IN_LOOPBACK);
		(void) printf(MSG_CTLR_ID, 32);
		(void) printf("\n");
		(void) printf(MSG_CONFIG_VERSION, MAXLONG);
		(void) printf(MSG_ERROR_LIMIT, MAXINT);
		(void) printf(MSG_LINK_NOT_PRES, 0);
		(void) printf(MSG_LINK_ID, 1);
		(void) printf(MSG_LINK_STATE);
		(void) printf(MSG_STATE_UP);
		(void) printf(MSG_LINK_STATE);
		(void) printf(MSG_STATE_DOWN);
		(void) printf(MSG_LINK_STATE);
		(void) printf(MSG_STATE_NO_PAROLI);
		(void) printf(MSG_LINK_STATE);
		(void) printf(MSG_STATE_WAIT_DOWN);
		(void) printf(MSG_LINK_STATE);
		(void) printf(MSG_STATE_WAIT_UP);
		(void) printf(MSG_LINK_STATE);
		(void) printf(MSG_STATE_ERR_DOWN);
		(void) printf(MSG_LINK_STATE);
		(void) printf(MSG_UNKNOWN);
		(void) printf(MSG_LINK_ENABLED, YESORNO(0));
		(void) printf(MSG_LINK_ENABLED, YESORNO(1));
		(void) printf(MSG_PHYS_STATE);
		(void) printf(MSG_STATE_OFF);
		(void) printf(MSG_PHYS_STATE);
		(void) printf(MSG_STATE_FAILOVER);
		(void) printf(MSG_PHYS_STATE);
		(void) printf(MSG_STATE_SEEK);
		(void) printf(MSG_PHYS_STATE);
		(void) printf(MSG_STATE_IN_USE);
		(void) printf(MSG_PHYS_STATE);
		(void) printf(MSG_UNKNOWN);
		(void) printf(MSG_LASER_ENABLED, YESORNO(0));
		(void) printf(MSG_TX_ENABLED, YESORNO(1));
		(void) printf(MSG_REMOTE_CNODE, 255);
		(void) printf(MSG_REMOTE_WNODE, 15);
		(void) printf(MSG_REMOTE_LINK, 2);
		(void) printf(MSG_REMOTE_WCI, 1023);
		(void) printf(MSG_ERR_TAKEDOWNS, MAXINT);
		(void) printf(MSG_DIS_TAKEDOWNS, MAXINT);
		(void) printf(MSG_CFG_TAKEDOWNS, MAXINT);
		(void) printf(MSG_FAILED_BRINGUPS, MAXINT);
		(void) printf(MSG_TOT_LINK_ERRS, MAXINT);
		(void) printf(MSG_MAX_LINK_ERRS, MAXINT);
		(void) printf(MSG_AVE_LINK_ERRS, MAXINT);
		(void) printf(MSG_AUTO_SHUT_EN, YESORNO(0));
		(void) printf(MSG_LINK_NOT_PRES, 2);
		(void) printf(MSG_CLUSTER_ERR, MAXLONG);
		(void) printf(MSG_SRAM_ECC, YESORNO(1));
		(void) printf(MSG_MAX_ECC, MAXLONG);
		(void) printf(MSG_AVE_ECC, MAXLONG);
		(void) printf("\n");

		return (0);
	}
	if ((kstats = kstat_lookup(kc, WRSM_KSTAT_WRSM, instance,
		WRSM_KSTAT_STATUS)) == NULL) {
			(void) fprintf(stderr, MSG_WRSM_FAIL);
			return (ERR_KSLOOKUP);
	}

	if (kstat_read(kc, kstats, NULL) == -1) {
		(void) fprintf(stderr, MSG_WRSM_FAIL);
		return (ERR_KSREAD);
	}

	(void) printf("\n");
	(void) printf(MSG_WCI_INSTANCE, instance);
	(void) printf("-------------\n");

	value = find_named(kstats, WRSMKS_PORTID);
	(void) printf(MSG_PORT_ID, value);

	value = find_named(kstats, WRSMKS_CONTROLLER_ID_NAMED);
	(void) printf(MSG_CTLR_ID, value);
	if (value == (uint32_t)WRSM_KSTAT_NO_CTRLR) {
		(void) printf(MSG_WCI_NOT_BELONG);
		check_links = B_FALSE;
	} else if (value == (uint32_t)-2) {
	    (void) printf(MSG_WCI_IN_LOOPBACK);
	    check_links = B_FALSE;
	} else {
	    (void) printf("\n");
	}

	if (check_links) {

		value64 = find_named64(kstats, WRSMKS_WCI_VERSION_NAMED);
		(void) printf(MSG_CONFIG_VERSION, value64);

		value = find_named(kstats, WRSMKS_ERROR_LIMIT);
		(void) printf(MSG_ERROR_LIMIT, value);

		for (i = 0; i < WCI_NUM_LINKS; i++) {

			(void) sprintf(ks_name, WRSMKS_VALID_LINK, i);
			value = find_named(kstats, ks_name);
			if (value == WRSMKS_LINK_NOT_PRESENT) {
				(void) printf(MSG_LINK_NOT_PRES, i);
				continue;
			}

			(void) printf(MSG_LINK_ID, i);

			(void) sprintf(ks_name, WRSMKS_LINK_ENABLED, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_LINK_ENABLED, YESORNO(value));

			(void) sprintf(ks_name, WRSMKS_LC_LINK_STATE, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_LINK_STATE);
			if (value == lc_up)
				(void) printf(MSG_STATE_UP);
			else if (value == lc_down)
				(void) printf(MSG_STATE_DOWN);
			else if (value == lc_not_there)
				(void) printf(MSG_STATE_NO_PAROLI);
			else if (value == sc_wait_down)
				(void) printf(MSG_STATE_WAIT_DOWN);
			else if (value == sc_wait_up)
				(void) printf(MSG_STATE_WAIT_UP);
			else if (value == sc_wait_errdown)
				(void) printf(MSG_STATE_ERR_DOWN);
			else
				(void) printf(MSG_UNKNOWN);

			(void) sprintf(ks_name, WRSMKS_PHYS_LINK_STATE, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_PHYS_STATE);
			if (value == phys_off)
				(void) printf(MSG_STATE_OFF);
			else if (value == phys_failover)
				(void) printf(MSG_STATE_FAILOVER);
			else if (value == phys_seek)
				(void) printf(MSG_STATE_SEEK);
			else if (value == phys_in_use)
				(void) printf(MSG_STATE_IN_USE);
			else
				(void) printf(MSG_UNKNOWN);

			(void) sprintf(ks_name, WRSMKS_PHYS_LASER_ENABLE, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_LASER_ENABLED, YESORNO(value));

			(void) sprintf(ks_name, WRSMKS_PHYS_XMIT_ENABLE, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_TX_ENABLED, YESORNO(value));

			(void) sprintf(ks_name, WRSMKS_REMOTE_CNODE_ID, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_REMOTE_CNODE, value);

			(void) sprintf(ks_name, WRSMKS_REMOTE_WNODE, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_REMOTE_WNODE, value);

			(void) sprintf(ks_name, WRSMKS_REMOTE_LINKNUM, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_REMOTE_LINK, value);

			(void) sprintf(ks_name, WRSMKS_REMOTE_WCI_PORTID, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_REMOTE_WCI, value);

			(void) sprintf(ks_name, WRSMKS_LINK_ERR_TAKEDOWNS, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_ERR_TAKEDOWNS, value);

			(void) sprintf(ks_name, WRSMKS_LINK_DISCON_TAKEDOWNS,
			    i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_DIS_TAKEDOWNS, value);

			(void) sprintf(ks_name, WRSMKS_LINK_CFG_TAKEDOWNS, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_CFG_TAKEDOWNS, value);

			(void) sprintf(ks_name, WRSMKS_LINK_FAILED_BRINGUPS,
			    i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_FAILED_BRINGUPS, value);

			(void) sprintf(ks_name, WRSMKS_LINK_ERRORS, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_TOT_LINK_ERRS, value);

			(void) sprintf(ks_name, WRSMKS_MAX_LINK_ERRORS, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_MAX_LINK_ERRS, value);

			(void) sprintf(ks_name, WRSMKS_AVG_LINK_ERRORS, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_AVE_LINK_ERRS, value);

			(void) sprintf(ks_name, WRSMKS_AUTO_SHUTDOWN_EN, i);
			value = find_named(kstats, ks_name);
			(void) printf(MSG_AUTO_SHUT_EN, YESORNO(value));
		}
	}

	if (v) {

		value64 = find_named64(kstats, WRSMKS_CLUSTER_ERROR_COUNT);
		(void) printf(MSG_CLUSTER_ERR, value64);

		value = find_named(kstats, WRSMKS_UC_SRAM_ECC_ERROR);
		(void) printf(MSG_SRAM_ECC, YESORNO(value));

		value = find_named(kstats, WRSMKS_MAX_SRAM_ECC_ERRORS);
		(void) printf(MSG_MAX_ECC, value);

		value = find_named(kstats, WRSMKS_AVG_SRAM_ECC_ERRORS);
		(void) printf(MSG_AVE_ECC, value);
	}

	(void) printf("\n");
	return (ERR_NO_ERR);
}

int
fetch_route(int contid, char *fm_node_name, kstat_ctl_t *kc)
{
	int i, j;

	kstat_t *kstats;

	char ks_name[25];
	uint32_t value, value1, value2, numwcis, numlinks;
	uint64_t value64;

	if (msg_test) {
		(void) printf(MSG_ROUTE_CTLR, 32, fm_node_name);
		(void) printf("------------------------\n");
		(void) printf(MSG_CONFIG_VERSION, MAXLONG);
		(void) printf(MSG_FM_NODE_ID, MAXINT);
		(void) printf(MSG_ROUTE_CNODE, 255);
		(void) printf(MSG_ROUTE_CHANGES, MAXINT);
		(void) printf(MSG_ROUTE_MH);
		(void) printf(MSG_ROUTE_PT);
		(void) printf(MSG_NUM_WCIS, MAXINT);
		(void) printf(MSG_STRIPES, 16);
		(void) printf("WCI #%d\n", 36);
		(void) printf(MSG_PORTID, 1023);
		(void) printf(MSG_INSTANCE, MAXINT);
		(void) printf(MSG_NUM_HOPS, MAXINT);
		(void) printf(MSG_NUM_LINKS, MAXINT);
		(void) printf(MSG_ROUTE_LINKID, 0);
		(void) printf(MSG_ROUTE_NODEID, 255);
		(void) printf(MSG_ROUTE_LINKID, 1);
		(void) printf(MSG_ROUTE_SWITCH, 255);
		(void) printf("\n");

		return (0);
	}
	if ((kstats =
	    kstat_lookup(kc, WRSM_KSTAT_WRSM_ROUTE, contid,
		fm_node_name)) == NULL) {
			(void) fprintf(stderr, MSG_ROUTE_FAIL);
			return (ERR_KSLOOKUP);
	}

	if (kstat_read(kc, kstats, NULL) == -1) {
		(void) fprintf(stderr, MSG_ROUTE_FAIL);
		return (ERR_KSREAD);
	}

	(void) printf(MSG_ROUTE_CTLR, contid, fm_node_name);
	(void) printf("------------------------\n");

	value64 = find_named64(kstats, WRSMKS_CONFIG_VERSION_NAMED);
	(void) printf(MSG_CONFIG_VERSION, value64);

	value = find_named(kstats, WRSMKS_FMNODEID);
	(void) printf(MSG_FM_NODE_ID, value);

	value = find_named(kstats, WRSMKS_CNODEID);
	(void) printf(MSG_ROUTE_CNODE, value);

	value = find_named(kstats, WRSMKS_NUMCHANGES);
	(void) printf(MSG_ROUTE_CHANGES, value);

	value = find_named(kstats, WRSMKS_ROUTE_TYPE_NAMED);
	if (value == 0) {
		(void) printf(MSG_ROUTE_MH);
	} else {
		(void) printf(MSG_ROUTE_PT);
	}

	value = find_named(kstats, WRSMKS_NUM_WCIS);
	numwcis = (value == NOT_FOUND) ? 0 : value;
	(void) printf(MSG_NUM_WCIS, value);

	value = find_named(kstats, WRSMKS_NUM_STRIPES);
	(void) printf(MSG_STRIPES, value);

	for (i = 0; i < numwcis; i++) {
		(void) printf("WCI #%d\n", i);

		(void) sprintf(ks_name, WRSMKS_ROUTE_PORTID, i);
		value = find_named(kstats, ks_name);
		(void) printf(MSG_PORTID, value);

		(void) sprintf(ks_name, WRSMKS_ROUTE_INSTANCE, i);
		value = find_named(kstats, ks_name);
		(void) printf(MSG_INSTANCE, value);

		(void) sprintf(ks_name, WRSMKS_ROUTE_NUMHOPS, i);
		value = find_named(kstats, ks_name);
		(void) printf(MSG_NUM_HOPS, value);

		(void) sprintf(ks_name, WRSMKS_ROUTE_NUMLINKS, i);
		value = find_named(kstats, ks_name);
		numlinks = (value == NOT_FOUND) ? 0 : value;
		(void) printf(MSG_NUM_LINKS, numlinks);

		for (j = 0; j < numlinks; j++) {

			(void) sprintf(ks_name, WRSMKS_ROUTE_LINKID, i, j);
			value = find_named(kstats, ks_name);

			(void) sprintf(ks_name, WRSMKS_ROUTE_NODEID, i, j);
			value1 = find_named(kstats, ks_name);

			(void) sprintf(ks_name, WRSMKS_ROUTE_GNID, i, j);
			value2 = find_named(kstats, ks_name);

			(void) printf(MSG_ROUTE_LINKID, value);
			if (value2 < 16) {
				(void) printf(MSG_ROUTE_NODEID, value1);
			} else {
				(void) printf(MSG_ROUTE_SWITCH, value1);
			}
		}
	}
	(void) printf("\n");
	return (ERR_NO_ERR);
}

int
fetch_controller(int contid, boolean_t private, kstat_ctl_t *kc)
{
	kstat_t *kstats;

	uint32_t value;
	uint64_t value64;
	char *value_char;

	if (msg_test) {
		(void) printf(MSG_CONTROLLER, contid);
		(void) printf("----------\n");
		(void) printf(MSG_CTLR_STATE);
		(void) printf(MSG_CTLR_NOT_AVAIL);
		(void) printf(MSG_CTLR_STATE);
		(void) printf(MSG_CTLR_UP);
		(void) printf(MSG_CTLR_STATE);
		(void) printf(MSG_CTLR_DOWN);
		(void) printf(MSG_CTLR_ADDR, MAXLONG);
		(void) printf(MSG_EX_MEMSEGS, MAXINT);
		(void) printf(MSG_EX_MEMSEGS_PUB, MAXINT);
		(void) printf(MSG_EX_MEMSEG_CON, MAXINT);
		(void) printf(MSG_BYTES_BOUND, MAXLONG);
		(void) printf(MSG_IM_MEMSEGS_CON, MAXINT);
		(void) printf(MSG_SENDQS, MAXLONG);
		(void) printf(MSG_HANDLERS, MAXLONG);
		(void) printf(MSG_RSM_NUM_WCIS, MAXINT);
		(void) printf(MSG_RSM_AVAIL_WCIS, MAXINT);
		(void) printf(MSG_NUM_RECONFIGS, MAXINT);
		(void) printf(MSG_FREE_CMMUS, MAXINT);
		(void) printf("\n");

		return (0);
	}

	if ((kstats =
	    kstat_lookup(kc, WRSM_KSTAT_WRSM, contid, RSM_KS_NAME))
	    == NULL) {
		(void) fprintf(stderr, MSG_CONTROLLER_FAIL);
		    return (ERR_KSLOOKUP);
	}

	if (kstat_read(kc, kstats, NULL) == -1) {
		(void) fprintf(stderr, MSG_CONTROLLER_FAIL);
		return (ERR_KSREAD);
	}

	if (private) {
		value = find_named(kstats, WRSMKS_RSM_AVAIL_WCIS);
		(void) printf("%d\n", value);
		return (ERR_NO_ERR);
	}

	(void) printf(MSG_CONTROLLER, contid);
	(void) printf("----------\n");

	/* rsmpi components */

	/* not printing kstat, to ease translation for language localization */
	value_char = find_named_char(kstats, RSM_KS_CTLR_STATE);
	(void) printf(MSG_CTLR_STATE);
	if (value_char == NULL) {
		(void) printf(MSG_CTLR_NOT_AVAIL);
	} else if (strcmp(value_char, RSM_AE_CTLR_UP) == 0) {
		(void) printf(MSG_CTLR_UP);
	} else {
		(void) printf(MSG_CTLR_DOWN);
	}

	value64 = find_named64(kstats, RSM_KS_ADDR);
	(void) printf(MSG_CTLR_ADDR, value64);

	value = find_named(kstats, RSM_KS_EX_MEMSEGS);
	(void) printf(MSG_EX_MEMSEGS, value);

	value = find_named(kstats, RSM_KS_EX_MEMSEGS_PUB);
	(void) printf(MSG_EX_MEMSEGS_PUB, value);

	value = find_named(kstats, RSM_KS_EX_MEMSEGS_CON);
	(void) printf(MSG_EX_MEMSEG_CON, value);

	value64 = find_named64(kstats, RSM_KS_BYTES_BOUND);
	(void) printf(MSG_BYTES_BOUND, value64);

	value = find_named(kstats, RSM_KS_IM_MEMSEGS_CON);
	(void) printf(MSG_IM_MEMSEGS_CON, value);

	value64 = find_named64(kstats, RSM_KS_SENDQS);
	(void) printf(MSG_SENDQS, value64);

	value64 = find_named(kstats, RSM_KS_HANDLERS);
	(void) printf(MSG_HANDLERS, value64);

	/* wrsm specific components */
	value = find_named(kstats, WRSMKS_RSM_NUM_WCIS);
	(void) printf(MSG_RSM_NUM_WCIS, value);

	value = find_named(kstats, WRSMKS_RSM_AVAIL_WCIS);
	(void) printf(MSG_RSM_AVAIL_WCIS, value);

	value = find_named(kstats, WRSMKS_NUM_RECONFIGS);
	(void) printf(MSG_NUM_RECONFIGS, value);

	value = find_named(kstats, WRSMKS_FREE_CMMU_ENTRIES);
	(void) printf(MSG_FREE_CMMUS, value);

	(void) printf("\n");
	return (ERR_NO_ERR);
}

static uint32_t
find_named(kstat_t *ksp, char *name)
{
	kstat_named_t *kna;
	int counter;

	kna = (kstat_named_t *)ksp->ks_data;
	if (kna == NULL) {
		(void) fprintf(stderr, MSG_KSTAT_NO_DATA);
		return (NOT_FOUND);
	}

	for (counter = 0; counter < ksp->ks_ndata; counter++) {
		if (strcmp(kna->name, name) == 0)
			return (kna->value.ui32);
		kna++;
	}
	return (NOT_FOUND);
}

static uint64_t
find_named64(kstat_t *ksp, char *name)
{
	kstat_named_t *kna;
	int counter;

	kna = (kstat_named_t *)ksp->ks_data;
	if (kna == NULL) {
		(void) fprintf(stderr, MSG_KSTAT_NO_DATA);
		return (NOT_FOUND64);
	}

	for (counter = 0; counter < ksp->ks_ndata; counter++) {
		if (strcmp(kna->name, name) == 0)
			return (kna->value.ui64);
		kna++;
	}
	return (NOT_FOUND64);
}

static char *
find_named_char(kstat_t *ksp, char *name)
{
	kstat_named_t *kna;
	int counter;

	kna = (kstat_named_t *)ksp->ks_data;
	if (kna == NULL) {
		(void) fprintf(stderr, MSG_KSTAT_NO_DATA);
		return (NULL);
	}

	for (counter = 0; counter < ksp->ks_ndata; counter++) {
		if (strcmp(kna->name, name) == 0)
			return (kna->value.c);
		kna++;
	}
	return (NULL);
}

static void show_usage()
{
	char *controller_id = gettext("controller id");
	char *wrsm_instance_num = gettext("wrsm instance num");
	char *nodename = gettext("nodename");
	char *start = gettext("start");
	char *end = gettext("end");

	(void) fprintf(stderr, gettext("Usage:\n"));
	(void) fprintf(stderr, "\twrsmstat controller [ -c <%s> ]\n",
	    controller_id);
	(void) fprintf(stderr, "\twrsmstat wrsm [ -i <%s> ] [-v]\n",
	    wrsm_instance_num);
	(void) fprintf(stderr, "\twrsmstat route [ -c <%s> ] [ -h <%s> ]\n",
	    controller_id, nodename);
	(void) fprintf(stderr,
	    "\twrsmstat set [ -i <%s> ] -c cmmu -s <%s> -e <%s>\n",
	    wrsm_instance_num, start, end);
}

int
trace_cmmu(int instance, int start, int end, kstat_ctl_t *kc)
{
	int i;
	kstat_t *kstats;
	uint64_t args[4];
	wci_sram_array_as_cmmu_0_u word0;
	int retval;
	int fd;
	int port;
	char devname[32];

	if ((kstats = kstat_lookup(kc, WRSM_KSTAT_WRSM, instance,
		WRSM_KSTAT_STATUS)) == NULL) {
			(void) fprintf(stderr, MSG_WRSM_FAIL);
			return (ERR_KSLOOKUP);
	}

	if (kstat_read(kc, kstats, NULL) == -1) {
		(void) fprintf(stderr, MSG_WRSM_FAIL);
		return (ERR_KSREAD);
	}

	port = find_named(kstats, WRSMKS_PORTID);
	if (port == NOT_FOUND) {
		return (ERR_KSREAD);
	}

	(void) sprintf(devname, "/dev/wci%x", port);

	fd = open(devname, O_RDONLY);
	if (fd < 0) {
		perror("set");
		return (-1);
	}
	word0.val = 0;

	if (start == 0 && end == 0) {
		/* Enable all */
		word0.bit.count_enable = 1;
		start = 1;
		end = MAX_CMMU_ENTRIES;
	} else if (start == 0 && end == -1) {
		/* Disable all */
		word0.bit.count_enable = 0;
		start = 1;
		end = MAX_CMMU_ENTRIES;
	} else {
		/* Enable the specified range */
		if (end > MAX_CMMU_ENTRIES) {
			end = MAX_CMMU_ENTRIES;
		}
		if (start == 0) {
			/* Entry 0 is read-only */
			start = 1;
		}
		word0.bit.count_enable = 1;
	}

	args[0] = word0.val;
	args[1] = 0;
	args[3] = 0x100; /* Flag to change perf counter only */

	for (i = start; i <= end; i++) {
		args[2] = i;
		retval = ioctl(fd, WRSM_LC_UPDATECMMU, args);
		if (retval) {
			if (errno == EINVAL) {
				/*
				 * Walked off end of memory, CMMU might not be
				 * fully populated, and that's OK.
				 */
				return (ERR_NO_ERR);
			}
			perror("set");
			(void) close(fd);
			return (errno);
		}
	}
	(void) close(fd);
	return (ERR_NO_ERR);
}
