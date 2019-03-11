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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/modctl.h>
#include <sys/systeminfo.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <locale.h>
#include <libintl.h>
#include <libgen.h>
#include <nl_types.h>
#include <kstat.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#include "busstat.h"


/* Global defines */
static int		delta = TRUE;
static int		banner = TRUE;
static int		max_pic_num = 1;
static int		initial_read = TRUE;
static char		*pgmname;
static kstat_ctl_t	*kc;			/* libkstat cookie */
static dev_node_t	*dev_list_head	= NULL;
static dev_node_t	*dev_list_tail	= NULL;

/*
 * Global flags.
 */
static char	curr_dev_name[KSTAT_STRLEN];
static int	curr_inst_num;

static void print_evt(void);
static void print_dev(int, char *);
static void parse_cmd(int);
static void parse_dev_inst(char *);
static void parse_pic_evt(char *);
static void add_dev_node(char *, int);
static void add_all_dev_node(char *);
static void add_evt_node(dev_node_t *);
static void modify_evt_node(dev_node_t *, char *);
static void prune_evt_nodes(dev_node_t *);
static void setup_evts(void);
static void set_evt(dev_node_t *);
static void read_evts(void);
static void read_r_evt_node(dev_node_t *, int, kstat_named_t *);
static void read_w_evt_node(dev_node_t *, int, kstat_named_t *);
static void check_dr_ops(void);
static void remove_dev_node(dev_node_t *);
static dev_node_t *find_dev_node(char *, int, int);
static kstat_t *find_pic_kstat(char *, int, char *);
static int64_t is_num(char *);
static void print_banner(void);
static void print_timestamp(void);
static void usage(void);
static void *safe_malloc(size_t);
static void set_timer(int);
static void handle_sig(int);
static int strisnum(const char *);

int
main(int argc, char **argv)
{
	int		c, i;
	int		interval = 1;	/* Interval between displays */
	int		count = 0;	/* Number of times to sample */
	int		write_evts = FALSE;
	int		pos = 0;

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	/* For I18N */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	pgmname = basename(argv[0]);

	if ((kc = kstat_open()) == NULL) {
		(void) fprintf(stderr, gettext("%s: could not "
			"open /dev/kstat\n"), pgmname);
		exit(1);
	}

	while ((c = getopt(argc, argv, "e:w:r:ahln")) != EOF) {
		switch (c) {
		case 'a':
			delta = FALSE;
			break;
		case 'e':
			(void) print_evt();
			break;
		case 'h':
			usage();
			break;
		case 'l':
			(void) print_dev(argc, argv[argc-1]);
			break;
		case 'n':
			banner = FALSE;
			break;
		case 'r':
			(void) parse_cmd(READ_EVT);
			break;
		case 'w':
			(void) parse_cmd(WRITE_EVT);
			write_evts = TRUE;
			break;
		default:
			(void) fprintf(stderr, gettext("%s: invalid "
				"option\n"), pgmname);
			usage();
			break;
		}
	}

	if ((argc == 1) || (dev_list_head == NULL))
		usage();

	/*
	 * validate remaining operands are numeric.
	 */
	pos = optind;
	while (pos < argc) {
		if (strisnum(argv[pos]) == 0) {
			(void) fprintf(stderr,
				gettext("%s: syntax error\n"),
				pgmname);
			usage();
		}
		pos++;
	}

	if (optind < argc) {
		if ((interval = atoi(argv[optind])) == 0) {
			(void) fprintf(stderr, gettext("%s: invalid "
				"interval value\n"), pgmname);
			exit(1);
		}

		optind++;
		if (optind < argc)
			if ((count = atoi(argv[optind])) <= 0) {
				(void) fprintf(stderr, gettext("%s: "
					"invalid iteration value.\n"),
					    pgmname);
				exit(1);
			}
	}

	set_timer(interval);

	/*
	 * Set events for the first time.
	 */
	if (write_evts == TRUE)
		setup_evts();


	if (count > 0) {
		for (i = 0; i < count; i++) {
			if (banner)
				print_banner();

			check_dr_ops();
			read_evts();
			(void) fflush(stdout);
			(void) pause();
		}
	} else {
		for (;;) {
			if (banner)
				print_banner();

			check_dr_ops();
			read_evts();
			(void) fflush(stdout);
			(void) pause();
		}
	}

	read_evts();
	return (0);
}


/*
 * Display all the events that can be set on a device.
 */
void
print_evt()
{
	kstat_t		*cnt_ksp;
	kstat_t		*pic_ksp;
	kstat_named_t	*cnt_data;
	kstat_named_t	*pic_data;
	char		*device = NULL;
	char		*value;
	int		inst_num = -1;
	int		i = 0;
	int		j;

	value = optarg;

	/*
	 * Search through the value string for a numeric char which will
	 * be the device instance number, if the user specified one. If
	 * the user did not specify an instance then the return value from
	 * strscpn will be equal to the string length. In this case we
	 * use a default value of -1 for the kstat_lookup which causes
	 * the device number to be ignored during the search.
	 */
	if (((i = strcspn(value, "0123456789")) > 0) && (i != strlen(value))) {

		device = safe_malloc(sizeof (char) * i+1);
		device[i] = '\0';
		(void) strncpy(device, value, i);

		value = value + i;
		inst_num = atoi(value);
	}

	/*
	 * No instance specified.
	 */
	if (device == NULL)
		device = value;

	/*
	 * Get the "counters" kstat, so that we can get
	 * the names of the "picN" kstats, which hold the
	 * event names.
	 */
	if ((cnt_ksp = kstat_lookup(kc, device, inst_num, "counters"))
								== NULL) {
		(void) fprintf(stderr, gettext("%s: invalid device "
			"name or instance (%s)\n"), pgmname, device);
		exit(1);
	}

	if (kstat_read(kc, cnt_ksp, NULL) == FAIL) {
		(void) fprintf(stderr, gettext("%s: could not read "
			"kstat.\n"), pgmname);
		exit(1);
	}

	cnt_data = (kstat_named_t *)cnt_ksp->ks_data;

	/*
	 * Start at 1 as the first entry in the "counters"
	 * kstat is the pcr value/name. We are looking for the
	 * name of the "picN" kstats. For each one found store
	 * a pointer to it in pic_data[].
	 */
	if (cnt_ksp->ks_ndata <= 1) {
		(void) fprintf(stderr, gettext("%s: invalid kstat "
			"structure.\n"), pgmname);
		exit(1);
	}

	for (i = 1; i < cnt_ksp->ks_ndata; i++) {
		if ((pic_ksp = find_pic_kstat(device, inst_num,
			cnt_data[i].name)) == NULL) {

			(void) fprintf(stderr, gettext("%s: could not read "
				"pic kstat data structure for %s\n"),
				    pgmname, cnt_ksp->ks_module);

			exit(1);
		}

		if (kstat_read(kc, pic_ksp, NULL) == FAIL) {
			(void) fprintf(stderr, gettext("%s: could not read "
				"pic kstat.\n"), pgmname);

			exit(1);
		}

		pic_data = (kstat_named_t *)pic_ksp->ks_data;

		(void) printf(gettext("pic%-8d\n"), i-1);

		for (j = 0; j < pic_ksp->ks_ndata-1; j++) {
			(void) printf("%-30s\n", pic_data[j].name);
		}

		(void) printf("\n");
	}

	exit(0);
}


/*
 * Display the names and instances of the devices on the system
 * which can support performance monitoring.
 */
void
print_dev(int argc, char *str)
{
	kstat_t	*ksp;
	static int first_time = 1;

	if ((argc > 2) || (strcmp(str, "-l") != 0)) {
		(void) fprintf(stderr, gettext("%s: no arguments "
			"permitted with -l option.\n"),
			    pgmname);
		usage();
		exit(1);
	}

	/*
	 * For each device node, print the node name (device
	 * name) and the instance numbers.
	 */
	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if ((strcmp(ksp->ks_class, "bus") == 0) &&
			(strcmp(ksp->ks_name, "counters") == 0)) {
					if (first_time) {
						(void) printf(gettext("Busstat "
							"Device(s):\n"));
						first_time = 0;
					}
					(void) printf("%s%d ", ksp->ks_module,
						ksp->ks_instance);
		}
	}

	if (first_time)
		(void) fprintf(stderr, gettext("%s: No devices available "
			"in system."), pgmname);

	(void) printf("\n");

	exit(0);
}

/*
 * Parses the cmd line, checks all the values and
 * creates the appropiate data structures.
 */
void
parse_cmd(int mode)
{
	char		*options = optarg, *value;
	int		arg_num	= 0;

	while ((value = (char *)strtok(options, ",=")) != NULL) {
		/*
		 * First arg must be device name.
		 */
		if (!arg_num) {
			parse_dev_inst(value);
		} else {
			if (mode == READ_EVT) {
				(void) fprintf(stderr, gettext("%s: "
					"event names or pic values not "
					"permitted with -r option.\n"),
					    pgmname);
				usage();
				exit(1);
			}
			/*
			 * Now dealing with pic values.
			 */
			parse_pic_evt(value);
		}
		/*
		 * After first strtok call, must set first arg
		 * to null if wish to parse rest of string.
		 * See strtok man page.
		 */
		if (options != NULL)
			options = NULL;
		arg_num++;
	}
}


/*
 * Parse the device name/instance section of the
 * command line.
 */
void
parse_dev_inst(char *value)
{
	int		i;
	char		*device	= NULL;
	int		malloc_flag = FALSE;

	if (strlen(value) == 0) {
		(void) fprintf(stderr, gettext("%s: No device name given.\n"),
			pgmname);
		exit(1);
	}

	/*
	 * Break string into device name and
	 * instance number (if given).
	 */
	if ((i = strcspn(value, "0123456789")) > 0) {
		if (i != strlen(value)) {
			device = safe_malloc(sizeof (char) * i+1);
			device[i] = '\0';

			(void) strncpy(device, value, i);
			malloc_flag = TRUE;

			value = value + i;
		}
	}

	/*
	 * No instance was specified so we assume
	 * the user wants to use ALL instances.
	 */
	if (device == NULL) {
		if ((device = value) == NULL) {
			(void) fprintf(stderr, gettext("%s: no device "
				"specified\n"), pgmname);
			exit(1);
		}

		/*
		 * Set global flags.
		 */
		(void) strcpy(curr_dev_name, device);
		curr_inst_num = -1;

		add_all_dev_node(device);
		goto clean_up;
	}

	/*
	 * Set global flags.
	 */
	(void) strcpy(curr_dev_name, device);
	curr_inst_num = atoi(value);

	add_dev_node(device, curr_inst_num);

clean_up:
	if (malloc_flag) {
		free(device);
	}
}


/*
 * Adds new event nodes to existing ones, modifies existing ones, or
 * prunes existing ones.
 *
 * A specific instance call will overwrite an earlier all
 * instances call, but *not* vice-versa.
 *
 * All the state transitions are given below.
 *
 *
 *                       Call Type
 * STATE |  Specific Instance          All Instances.
 * ======================================================
 * INIT  | Change state to       | Change state to ALL,
 *       | INST, add events      | add events.
 *       |                       |
 * INST  | State unchanged,      | No change.
 *       | Add events.           |
 *       |                       |
 * ALL   | Change state to       | State unchanged,
 *       | INST, replace events. | add events.
 */
void
parse_pic_evt(char *value)
{
	dev_node_t	*dev_node;
	char		*evt_name;
	int		pic_num;

	if (strlen(value) <= PIC_STR_LEN) {
		(void) fprintf(stderr, gettext("%s: no pic number "
			"specified.\n"), pgmname);
		exit(1);
	}

	if (strncmp(value, "pic", PIC_STR_LEN) != 0) {
		(void) fprintf(stderr, gettext("%s: missing pic "
			"specifier\n"), pgmname);
		usage();
	}

	/*
	 * Step over the 'pic' part of the string to
	 * get the pic number.
	 */
	value = value + PIC_STR_LEN;
	pic_num = atoi(value);

	if ((pic_num == -1) || (pic_num > max_pic_num -1)) {
		(void) fprintf(stderr, gettext("%s: invalid pic "
			"number.\n"), pgmname);
		exit(1);
	}

	if ((evt_name = (char *)strtok(NULL, "=,")) == NULL) {
		(void) fprintf(stderr, gettext("%s: no event "
			"specified.\n"), pgmname);
		exit(1);
	}

	/*
	 * Dealing with a specific instance.
	 */
	if (curr_inst_num >= 0) {
		if ((dev_node = find_dev_node(curr_dev_name,
			curr_inst_num, pic_num)) == NULL) {
			(void) fprintf(stderr, gettext("%s: could not find "
				"data structures for %s\n"),
				    pgmname, curr_dev_name);
			exit(1);
		}

		if (dev_node->r_w == EVT_READ) {
			modify_evt_node(dev_node, evt_name);
			dev_node->r_w = EVT_WRITE;
			dev_node->state = STATE_INST;

		} else if ((dev_node->r_w == EVT_WRITE) &&
			(dev_node->state == STATE_ALL)) {

			prune_evt_nodes(dev_node);
			modify_evt_node(dev_node, evt_name);
			dev_node->state = STATE_INST;

		} else if ((dev_node->r_w == EVT_WRITE) &&
			(dev_node->state == STATE_INST)) {

			add_evt_node(dev_node);
			modify_evt_node(dev_node, evt_name);
		}

		return;
	}

	/*
	 * Dealing with all instances of a specific device.
	 */
	dev_node = dev_list_head;
	while (dev_node != NULL) {
		if ((strcmp(dev_node->name, curr_dev_name) == 0) &&
			(dev_node->pic_num == pic_num)) {

			if (dev_node->r_w == EVT_READ) {
				modify_evt_node(dev_node,
					evt_name);

				dev_node->r_w = EVT_WRITE;
				dev_node->state = STATE_ALL;

			} else if ((dev_node->r_w == EVT_WRITE) &&
				(dev_node->state == STATE_ALL)) {

				add_evt_node(dev_node);
				modify_evt_node(dev_node, evt_name);

			}
		}
		dev_node = dev_node->next;
	}
}


/*
 * Create a dev_node structure for this device if one does not
 * already exist.
 */
void
add_dev_node(char *dev_name, int inst_num)
{
	dev_node_t	*new_dev_node;
	kstat_named_t	*cnt_data;
	kstat_t		*cnt_ksp;
	kstat_t		*pic_ksp;
	int		pic_num;


	if ((cnt_ksp = kstat_lookup(kc, dev_name,
		inst_num, "counters")) == NULL) {
		(void) fprintf(stderr, gettext("%s: invalid device "
			"name or instance (%s%d)\n"), pgmname,
				dev_name, inst_num);
		exit(1);
	}

	if (kstat_read(kc, cnt_ksp, NULL) == FAIL) {
		(void) fprintf(stderr, gettext("%s : could not read counters "
			"kstat for device %s.\n"), pgmname, dev_name);
		exit(1);
	}

	cnt_data = (kstat_named_t *)cnt_ksp->ks_data;

	if (cnt_ksp->ks_ndata <= 1) {
		(void) fprintf(stderr, gettext("%s : invalid "
			"kstat structure.\n"), pgmname);
		exit(1);
	}

	/*
	 * max_pic_num used to format headers correctly
	 * for printing.
	 */
	if (cnt_ksp->ks_ndata-1 > max_pic_num)
		max_pic_num = cnt_ksp->ks_ndata-1;

	/* for each pic... */
	for (pic_num = 0; pic_num < cnt_ksp->ks_ndata-1; pic_num++) {
		if (find_dev_node(dev_name, inst_num, pic_num) != NULL) {
			/* Node already exists */
			continue;
		}

		new_dev_node = safe_malloc(sizeof (dev_node_t));
		bzero(new_dev_node, sizeof (dev_node_t));

		(void) strcpy(new_dev_node->name, dev_name);
		new_dev_node->dev_inst = inst_num;
		new_dev_node->pic_num = pic_num;

		new_dev_node->cnt_ksp = cnt_ksp;

		if ((pic_ksp = find_pic_kstat(dev_name, inst_num,
			cnt_data[pic_num+1].name)) == NULL) {

			(void) fprintf(stderr, gettext("%s: could not find "
				"pic kstat structure for %s.\n"),
				    pgmname, cnt_ksp->ks_module);
			exit(1);
		}

		new_dev_node->pic_ksp = pic_ksp;

		add_evt_node(new_dev_node);

		new_dev_node->state = STATE_INIT;
		new_dev_node->r_w = EVT_READ;

		if (dev_list_head == NULL) {
			dev_list_head = new_dev_node;
			dev_list_tail = new_dev_node;

		} else if (find_dev_node(dev_name, inst_num, pic_num) == NULL) {
			dev_list_tail->next = new_dev_node;
			dev_list_tail = new_dev_node;
		}
	}
}


/*
 * Add all possible instances of a device.
 */
void
add_all_dev_node(char *dev_name)
{
	kstat_t	*ksp;
	int	match = 0;

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if ((strcmp(ksp->ks_class, "bus") == 0) &&
			(strcmp(ksp->ks_name, "counters") == 0) &&
			(strcmp(ksp->ks_module, dev_name) == 0)) {
				match = 1;
				add_dev_node(dev_name, ksp->ks_instance);
		}
	}

	if (match == 0) {
		(void) fprintf(stderr,
			gettext("%s: invalid device name (%s)\n"),
			pgmname, dev_name);
		exit(1);
	}
}


/*
 * Add an event node to a specified device node.
 */
void
add_evt_node(dev_node_t *dev_node)
{
	evt_node_t	*new_evt_node;
	evt_node_t	*curr_evt_node;

	new_evt_node = safe_malloc(sizeof (evt_node_t));
	bzero(new_evt_node, sizeof (evt_node_t));

	(void) strcpy(new_evt_node->evt_name, "");

	if (dev_node->evt_node == NULL) {
		dev_node->evt_node = new_evt_node;
		new_evt_node->next = new_evt_node;
		return;
	} else {
		curr_evt_node = dev_node->evt_node;
		while (curr_evt_node->next != dev_node->evt_node)
			curr_evt_node = curr_evt_node->next;

		curr_evt_node->next = new_evt_node;
		new_evt_node->next = dev_node->evt_node;
	}
}


/*
 * Fill in or change the fields of an evt node.
 */
void
modify_evt_node(dev_node_t *dev_node, char *evt_name)
{
	evt_node_t	*evt_node;
	kstat_t		*pic_ksp;
	kstat_named_t	*pic_data;
	int64_t		evt_num = 0;
	int		evt_match = 0;
	int		i;

	evt_node = dev_node->evt_node;

	/*
	 * Find the last event node.
	 */
	if (evt_node->next != evt_node) {
		while (evt_node->next != dev_node->evt_node) {
			evt_node = evt_node->next;
		}
	}

	evt_node->prev_count = 0;
	evt_node->total = 0;

	pic_ksp = dev_node->pic_ksp;

	if (kstat_read(kc, pic_ksp, NULL) == FAIL) {
		(void) fprintf(stderr, gettext("%s: could not read "
			"pic kstat.\n"), pgmname);
		exit(1);
	}

	pic_data = (kstat_named_t *)dev_node->pic_ksp->ks_data;

	/*
	 * The event can either be given as a event name (string) or
	 * as a pcr mask. If given as pcr mask, we try to match it
	 * to an event name, and use that name. Otherwise we just use
	 * the pcr mask value.
	 */
	if ((evt_num = is_num(evt_name)) == EVT_STR) {
		(void) strcpy(evt_node->evt_name, evt_name);

		for (i = 0; i < dev_node->pic_ksp->ks_ndata; i++) {
			if (strcmp(evt_name, pic_data[i].name) == 0) {
				evt_node->evt_pcr_mask = pic_data[i].value.ui64;
				return;
			}
		}

		(void) fprintf(stderr,
			gettext("%s: %s is not a valid event name.\n"),
			pgmname, evt_name);
		exit(1);

	} else {
		/*
		 * See if the pcr mask given by the user matches that for any
		 * existing event.
		 */
		for (i = 0; i < dev_node->pic_ksp->ks_ndata; i++) {
			if (evt_num == pic_data[i].value.ui64) {
				(void) strcpy(evt_node->evt_name,
					pic_data[i].name);
				evt_match = 1;
				break;
			}
		}

		if (evt_match == 0)
			(void) sprintf(evt_node->evt_name, "%llx", evt_num);

		evt_node->evt_pcr_mask = evt_num;
	}
}


/*
 * Removes all bar one of the evt_nodes that are hanging off the
 * specified dev_node.
 */
void
prune_evt_nodes(dev_node_t *dev_node)
{
	evt_node_t	*next_evt_node;
	evt_node_t	*curr_evt_node;

	/*
	 * Only one evt node, nothing for us to do.
	 */
	if (dev_node->evt_node->next == dev_node->evt_node) {
		return;
	}

	curr_evt_node = dev_node->evt_node->next;
	dev_node->evt_node->next = dev_node->evt_node;

	while (curr_evt_node != dev_node->evt_node) {
		next_evt_node = curr_evt_node->next;
		free(curr_evt_node);
		curr_evt_node = next_evt_node;
	}
}


/*
 * Set the events for each pic on each device instance.
 */
void
setup_evts()
{
	dev_node_t	*dev_node;

	dev_node = dev_list_head;

	while (dev_node != NULL) {
		if (dev_node->r_w == EVT_WRITE)
			set_evt(dev_node);

		dev_node = dev_node->next;
	}
}


/*
 * Set the appropiate events. Only called for event nodes
 * that are marked EVT_WRITE.
 */
void
set_evt(dev_node_t *dev_node)
{
	kstat_named_t	*cnt_data;
	kstat_named_t	*pic_data;
	kstat_t		*cnt_ksp;
	kstat_t		*pic_ksp;
	evt_node_t	*evt_node;
	uint64_t	clear_pcr_mask;
	uint64_t	pcr;
	int		pic_num;

	cnt_ksp = dev_node->cnt_ksp;
	pic_ksp = dev_node->pic_ksp;
	pic_num = dev_node->pic_num;
	evt_node = dev_node->evt_node;

	/* Read the "counters" kstat */
	if (kstat_read(kc, cnt_ksp, NULL) == FAIL) {
		(void) fprintf(stderr, gettext("%s: could "
			"not set event's.\n"), pgmname);
		exit(1);
	}

	cnt_data = (kstat_named_t *)cnt_ksp->ks_data;

	if (kstat_read(kc, pic_ksp, NULL) == FAIL) {
		(void) fprintf(stderr, gettext("%s: could "
			"not set event's.\n"), pgmname);
		exit(1);
	}

	pic_data = (kstat_named_t *)pic_ksp->ks_data;
	clear_pcr_mask = pic_data[pic_ksp->ks_ndata-1].value.ui64;

	if ((pic_num < 0) || (pic_num > cnt_ksp->ks_ndata-1)) {
		(void) fprintf(stderr,
			gettext("%s: invalid pic #%d.\n"),
			pgmname, pic_num);
		exit(1);
	}

	/*
	 * Store the previous value that is on the pic
	 * so that we can calculate the delta value
	 * later.
	 */
	evt_node->prev_count = cnt_data[pic_num+1].value.ui64;


	/*
	 * Read the current pcr value from device.
	 */
	pcr = cnt_data[0].value.ui64;

	/*
	 * Clear the section of the pcr which corresponds to the
	 * pic we are setting events on. Also clear the pcr value
	 * which is stored in the instance node.
	 *
	 */
	pcr = pcr & clear_pcr_mask;

	/*
	 * Set the event.
	 */
	pcr = pcr | evt_node->evt_pcr_mask;
	cnt_data[0].value.ui64 = pcr;

	/*
	 * Write the value back to the kstat, to make it
	 * visible to the underlying driver.
	 */
	if (kstat_write(kc, cnt_ksp, NULL) == FAIL) {
		(void) fprintf(stderr, gettext("%s: could not set events "
					"(setting events requires root "
					    "permission).\n"), pgmname);
		exit(1);
	}
}


/*
 * Works through the list of device nodes, reading events
 * and where appropiate setting new events (multiplexing).
 */
void
read_evts()
{
	dev_node_t	*dev_node;
	kstat_t		*cnt_ksp;
	kstat_named_t	*cnt_data;
	char		tmp_str[30];
	int		iter = 0;

	dev_node = dev_list_head;

	while (dev_node != NULL) {
		if (iter == 0)
			print_timestamp();
		/*
		 * First read of all the counters is done
		 * to establish a baseline for the counts.
		 * This data is not printed.
		 */
		if ((!initial_read) && (iter == 0)) {
			(void) snprintf(tmp_str, sizeof (tmp_str), "%s%d",
				dev_node->name, dev_node->dev_inst);
			(void) printf("%-7s", tmp_str);
		}

		cnt_ksp = (kstat_t *)dev_node->cnt_ksp;

		if (kstat_read(kc, cnt_ksp, NULL) == FAIL) {
			(void) fprintf(stderr, gettext("%s: device %s%d "
				"(pic %d) no longer valid.\n"),
				    pgmname, dev_node->name,
				    dev_node->dev_inst,
				    dev_node->pic_num);
			remove_dev_node(dev_node);
			dev_node = dev_list_head;
			continue;
		}

		cnt_data = (kstat_named_t *)cnt_ksp->ks_data;

		if (dev_node->r_w == EVT_READ) {
			read_r_evt_node(dev_node, dev_node->pic_num, cnt_data);
			iter++;
		} else {
			read_w_evt_node(dev_node, dev_node->pic_num, cnt_data);
			iter++;
		}

		if ((!initial_read) && (iter == max_pic_num)) {
			iter = 0;
			(void) printf("\n");
		}

		/*
		 * If there is more than one event node
		 * per-pic then we are multiplexing.
		 */
		if ((dev_node->evt_node->next != dev_node->evt_node) &&
			(!initial_read)) {
				dev_node->evt_node = dev_node->evt_node->next;
				set_evt(dev_node);
		}
		dev_node = dev_node->next;
	}
	initial_read = FALSE;
}


/*
 * Read a node that is marked as EVT_READ
 */
void
read_r_evt_node(dev_node_t *dev_node, int pic_num, kstat_named_t *cnt_data)
{
	evt_node_t	*evt_node;
	kstat_t		*pic_ksp;
	kstat_named_t	*pic_data;
	uint64_t	pcr_read;
	uint64_t	clear_pcr_mask;
	uint64_t	delta_count;
	int		i;
	int		match = 0;
	int		evt_blank = 1;

	evt_node = dev_node->evt_node;

	pic_ksp = (kstat_t *)dev_node->pic_ksp;

	if (kstat_read(kc, pic_ksp, NULL) == FAIL) {
		(void) fprintf(stderr, gettext("%s: device %s%d "
			"(pic %d) no longer valid.\n"), pgmname,
			    dev_node->name, dev_node->dev_inst,
			    dev_node->pic_num);
		remove_dev_node(dev_node);
		return;
	}

	pic_data = (kstat_named_t *)pic_ksp->ks_data;
	clear_pcr_mask = pic_data[pic_ksp->ks_ndata-1].value.ui64;

	/*
	 * Get PCR value from device. We extract the portion
	 * of the PCR relating to the pic we are interested by
	 * AND'ing the inverse of the clear mask for this pic.
	 *
	 * The clear mask is usually used to clear the appropiate
	 * section of the PCR before we write events into it. So
	 * by using the inverse of the mask, we zero everything
	 * *but* the section we are interested in.
	 */
	pcr_read = cnt_data[0].value.ui64;
	pcr_read = pcr_read & ~(clear_pcr_mask);

	/*
	 * If the event name is blank this is the first time that
	 * this node has been accessed, so we read the pcr and
	 * from that we get the event name if it exists.
	 *
	 * If the pcr read from the device does not match that
	 * stored in the node, then it means that the event has
	 * changed from its previous value, so we need to re-read
	 * all the values.
	 */
	if ((strcmp(evt_node->evt_name, "") == 0) ||
		(pcr_read != evt_node->evt_pcr_mask)) {

		for (i = 0; i < pic_ksp->ks_ndata-1; i++) {
			if (pcr_read == pic_data[i].value.ui64) {
				match = TRUE;
				break;
			}
		}

		/*
		 * Able to resolve pcr value to a event name.
		 */
		if (match) {
			(void) strcpy(evt_node->evt_name, pic_data[i].name);
			evt_node->evt_pcr_mask = pcr_read;
			evt_node->total = 0;
			evt_node->prev_count =
				cnt_data[pic_num+1].value.ui64;

			if ((evt_blank) && (!initial_read)) {
				(void) printf("%s\t%-8d\t",
					evt_node->evt_name, 0);
				evt_blank = 0;
			}

		} else {
			(void) sprintf(evt_node->evt_name, "0x%llx", pcr_read);
			evt_node->evt_pcr_mask = pcr_read;
			evt_node->total = 0;
			evt_node->prev_count =
				cnt_data[pic_num+1].value.ui64;

			if ((evt_blank) && (!initial_read)) {
				(void) printf("%s\t%-8d\t",
					evt_node->evt_name, 0);
				evt_blank = 0;
			}

		}
	} else {
		/* Deal with wraparound of the counters */
		if (cnt_data[pic_num+1].value.ui64 < evt_node->prev_count) {

			delta_count = (UINT32_MAX-evt_node->prev_count) +
				cnt_data[pic_num+1].value.ui64;
		} else {
			/* Calcalate delta value */
			delta_count = cnt_data[pic_num+1].value.ui64
						- evt_node->prev_count;
		}


		/*
		 * Store value so that we can calculate delta next
		 * time through.
		 */
		evt_node->prev_count = cnt_data[pic_num+1].value.ui64;

		/* Update count total */
		evt_node->total += delta_count;

		if (delta) {
			(void) printf("%-20s %-9lld   ",
				evt_node->evt_name, delta_count);
		} else {

			(void) printf("%-20s %-9lld   ",
				evt_node->evt_name, evt_node->total);
		}
	}
}


/*
 * Read event nodes marked as EVT_WRITE
 */
void
read_w_evt_node(dev_node_t *dev_node, int pic_num, kstat_named_t *cnt_data)
{
	kstat_t		*pic_ksp;
	kstat_named_t	*pic_data;
	evt_node_t	*evt_node;
	uint64_t	delta_count;
	uint64_t	pcr_read;
	uint64_t	clear_pcr_mask;

	evt_node = dev_node->evt_node;

	pic_ksp = (kstat_t *)dev_node->pic_ksp;

	if (kstat_read(kc, pic_ksp, NULL) == FAIL) {
		(void) fprintf(stderr, gettext("%s: could not read "
			"%s%d\n"), pgmname, dev_node->name,
			    dev_node->dev_inst);
		remove_dev_node(dev_node);
		return;
	}

	pic_data = (kstat_named_t *)pic_ksp->ks_data;
	clear_pcr_mask = pic_data[pic_ksp->ks_ndata-1].value.ui64;

	/*
	 * Get PCR value from device. We extract the portion
	 * of the PCR relating to the pic we are interested by
	 * AND'ing the inverse of the clear mask for this pic.
	 *
	 * The clear mask is usually used to clear the appropiate
	 * section of the PCR before we write events into it. So
	 * by using the inverse of the mask, we zero everything
	 * *but* the section we are interested in.
	 */
	pcr_read = cnt_data[0].value.ui64;
	pcr_read = pcr_read & ~(clear_pcr_mask);

	/*
	 * If the pcr value from the device does not match the
	 * stored value, then the events on at least one of the
	 * pics must have been change by another busstat instance.
	 *
	 * Regard this as a fatal error.
	 */
	if (pcr_read != evt_node->evt_pcr_mask) {
		(void) fprintf(stderr, gettext("%s: events changed (possibly "
			"by another busstat).\n"), pgmname);
		exit(2);
	}

	/*
	 * Calculate delta, and then store value just read to allow us to
	 * calculate delta next time around.
	 */
	/* Deal with wraparound of the counters */
	if (cnt_data[pic_num+1].value.ui64 < evt_node->prev_count) {

		delta_count = (UINT32_MAX-evt_node->prev_count) +
			cnt_data[pic_num+1].value.ui64;
	} else {
		/* Calcalate delta value */
		delta_count = cnt_data[pic_num+1].value.ui64
			- evt_node->prev_count;
	}

	evt_node->prev_count = cnt_data[pic_num+1].value.ui64;

	if (initial_read) {
		evt_node->total = 0;

	} else {
		/* Update count total */
		evt_node->total += delta_count;

		if (delta) {
			(void) printf("%-20s %-9lld   ",
				evt_node->evt_name, delta_count);
		} else {
			(void) printf("%-20s %-9lld   ",
				evt_node->evt_name, evt_node->total);
		}
	}
}


/*
 * Check to see if any DR operations have occured, and deal with the
 * consequences.
 *
 * Use the Kstat chain ID to check for DR operations. If the ID has
 * changed then some kstats on system have been modified, we check
 * all the data structures to see are they still valid. If they are
 * not we remove them.
 */
void
check_dr_ops()
{
	dev_node_t	*dev_node;
	kid_t		new_id;
	kstat_t		*ksp;
	int		match = 0;

	if ((new_id = kstat_chain_update(kc)) < 0) {
		(void) fprintf(stderr, gettext("%s: could not get "
			"kstat chain id\n"), pgmname);
		exit(1);
	}

	if (new_id == 0) {
		/* Kstat chain has not changed. */
		return;
	}

	/*
	 * Scan the chain of device nodes, making sure that their associated
	 * kstats are still present. If not we remove the appropiate node.
	 */
	dev_node = dev_list_head;

	while (dev_node != NULL) {
		for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
			if ((strcmp("bus", ksp->ks_class) == 0) &&
				(strcmp("counters", ksp->ks_name) == 0) &&
				(strcmp(dev_node->name, ksp->ks_module) == 0) &&
				(ksp->ks_instance == dev_node->dev_inst)) {
					match = 1;
					break;
			}
		}
		if (match == 0) {
			(void) fprintf(stderr, gettext("%s: device %s%d"
				" (pic %d) no longer valid.\n"), pgmname,
				    dev_node->name, dev_node->dev_inst,
				    dev_node->pic_num);

			remove_dev_node(dev_node);
		}
		dev_node = dev_node->next;
	}
}



/*
 * Remove a device node and its associated event nodes.
 */
void
remove_dev_node(dev_node_t *dev_node)
{
	dev_node_t	*curr_node;
	dev_node_t	*prev_node;
	evt_node_t	*curr_evt_node;
	evt_node_t	*next_evt_node;
	evt_node_t	*start_pos;

	curr_node = dev_list_head;

	if (curr_node == dev_node) {
		dev_list_head = dev_node->next;

		if (dev_list_head == NULL) {
			(void) fprintf(stderr, gettext("%s: no "
				"devices left to monitor.\n"),
				    pgmname);
			exit(1);
		}

		/* Remove each event node first */
		start_pos = dev_node->evt_node;
		curr_evt_node = start_pos->next;

		while (curr_evt_node != start_pos) {
			next_evt_node = curr_evt_node->next;

			free(curr_evt_node);
			curr_evt_node = next_evt_node;
		}

		free(start_pos);
		free(dev_node);
		return;
	}

	/* Find the device node */
	prev_node = dev_list_head;
	curr_node = prev_node->next;

	while (curr_node != NULL) {
		if (curr_node == dev_node) {
			prev_node->next = curr_node->next;

			/* Remove each event node first */
			start_pos = dev_node->evt_node;
			curr_evt_node = start_pos->next;

			while (curr_evt_node != start_pos) {
				next_evt_node = curr_evt_node->next;

				free(curr_evt_node);
				curr_evt_node = next_evt_node;
			}
			free(start_pos);

			free(dev_node);
			return;
		}
		prev_node = curr_node;
		curr_node = curr_node->next;
	}
}


/*
 * Find a device node in the linked list of dev_nodes. Match
 * is done on device name, and instance number.
 */
dev_node_t *
find_dev_node(char *name, int inst_num, int pic_num)
{
	dev_node_t	*curr_node;

	curr_node = dev_list_head;

	while (curr_node != NULL) {
		if ((strcmp(curr_node->name, name) == 0) &&
			(curr_node->dev_inst == inst_num) &&
			(curr_node->pic_num == pic_num)) {
				return (curr_node);
		}

		curr_node = curr_node->next;
	}

	return (NULL);
}


/*
 * Determines whether the string represents a event name
 * or a numeric value. Numeric value can be dec, hex
 * or octal. All are converted to long int.
 */
int64_t
is_num(char *name)
{
	char	*remainder = NULL;
	int64_t	num;

	num = (int64_t)strtol(name, &remainder, 0);

	if (name == remainder) {
		return (EVT_STR);
	} else {
		return (num);
	}
}


/*
 * Find a pointer to the specified picN kstat. First
 * search for the specific kstat, and if that can't
 * be found search for any picN kstat belonging to this device.
 */
kstat_t *
find_pic_kstat(char *dev_name, int inst_num, char *pic)
{
	kstat_t	*ksp;
	kstat_t	*p_ksp;

	/* Look for specific picN kstat */
	if ((p_ksp = kstat_lookup(kc, dev_name, inst_num, pic)) == NULL) {

		for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
			if ((strcmp(ksp->ks_class, "bus") == 0) &&
				(strcmp(ksp->ks_name, pic) == 0) &&
				(strcmp(ksp->ks_module, dev_name) == 0)) {

						return (ksp);
			}
		}
	}
	return (p_ksp);
}


/*
 * Print column titles.
 * Can be turned off by -n option.
 */
void
print_banner()
{
	int		i;

	(void) printf("time dev    ");

	for (i = 0; i < max_pic_num; i++)
		(void) printf("event%d               "
			"pic%d        ", i, i);

	(void) printf("\n");

	banner = FALSE;
}


/*
 * Print the elapsed time in seconds, since the last call.
 */
void
print_timestamp()
{
	static hrtime_t	curr_time = 0;
	static hrtime_t total_elapsed = 0;
	hrtime_t	new_time = 0;
	hrtime_t	elapsed = 0;
	hrtime_t	rem = 0;

	if (initial_read)	{
		curr_time = (uint64_t)gethrtime();
		return;
	}

	new_time = gethrtime();

	elapsed = (new_time - curr_time)/NANO;

	/* Round up time value if necessary */
	rem = (new_time - curr_time)%NANO;
	if (rem >= NANO/2)
		elapsed += 1;

	total_elapsed += elapsed;

	(void) printf("%-4llu ", total_elapsed);

	curr_time = new_time;
}


void
usage()
{
	(void) printf(gettext("Usage : busstat [-a] [-h] [-l] [-n]\n"
		"                [-e device-inst]\n"
		"                [-w device-inst "
					"[,pic0=<event>] [,picN=<event>] ]\n"
		"                [-r device-inst]\n"
		"                [ interval [count] ]\n"));

	exit(2);
}


void *
safe_malloc(size_t size)
{
	void *a;

	if ((a = malloc(size)) == NULL) {
		(void) fprintf(stderr,
			gettext("%s: out of memory.\n"), pgmname);
		exit(1);
	}

	return (a);
}

/*
 * Create and arm the timer.
 */
void
set_timer(int interval)
{
	timer_t		t_id;		/* Timer id */
	itimerspec_t	time_struct;
	struct sigevent	sig_struct;
	struct sigaction act;

	bzero(&sig_struct, sizeof (struct sigevent));
	bzero(&act, sizeof (struct sigaction));

	/* Create timer */
	sig_struct.sigev_notify = SIGEV_SIGNAL;
	sig_struct.sigev_signo = SIGUSR1;
	sig_struct.sigev_value.sival_int = 0;

	if (timer_create(CLOCK_REALTIME, &sig_struct, &t_id) != 0) {
		(void) fprintf(stderr, gettext("%s: Timer creation failed.\n"),
			pgmname);
		exit(1);
	}

	act.sa_handler = handle_sig;

	if (sigaction(SIGUSR1, &act, NULL) != 0) {
		(void) fprintf(stderr, gettext("%s: could not setup signal "
			"handler"), pgmname);
		exit(1);
	}

	time_struct.it_value.tv_sec = interval;
	time_struct.it_value.tv_nsec = 0;
	time_struct.it_interval.tv_sec = interval;
	time_struct.it_interval.tv_nsec = 0;

	/* Arm timer */
	if ((timer_settime(t_id, 0, &time_struct, NULL)) != 0) {
		(void) fprintf(stderr, gettext("%s: Setting timer failed.\n"),
			pgmname);
		exit(1);
	}
}


/* ARGSUSED */
void
handle_sig(int x)
{
}

/*
 * return a boolean value indicating whether or not
 * a string consists solely of characters which are
 * digits 0..9
 */
int
strisnum(const char *s)
{
	for (; *s != '\0'; s++) {
		if (*s < '0' || *s > '9')
			return (0);
	}
	return (1);
}
