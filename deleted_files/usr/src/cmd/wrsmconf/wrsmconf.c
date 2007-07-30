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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  This file implments the RSM Proxy.
 *
 * The program is controlled by its command line arguments.
 * The first argument is always the name of the command to be
 * executed followed by some number of options with the
 * appropriate parameter values.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include <sys/int_fmtio.h>
#include <sys/systeminfo.h>
#include <sys/wrsmconf.h>
#include <stddef.h>
#include <errno.h>
#include "wrsmconf_msgs.h"

#define	DEVNAME		"/devices/wrsm@ffff,0:admin"
#define	CTLRDEVNAME	"/dev/wrsm%d"
#define	MAX_WCI_IDS 54

extern int ErrorCount;

struct dump_info {
	wrsm_fmnodeid_t fmnode_id;
	char host_name[WRSM_HOSTNAMELEN];
	uint32_t controller_id;
	unsigned char cnode_id;
};

static void init_usage(void);
static void print_usage(boolean_t private);
static void print_command_usage(char *command);
static int dump_config(char *fn, int controller_id);
static int getinfo(int controller_id);
static void free_controller_info(struct dump_info ***controller_info);
static int compare(const void *left, const void *right);
static void print_column_headers(FILE *fp);
static void print_member_info(FILE *fp, struct dump_info **info,
	int num_members);
static int topology(int cid);
static int check(int cid, char *hostname);
int mkconfig(char *input_file, char *output_file, int controller_id);

/* Private function in libwrsmconf */
extern void wrsm_print_controller(FILE *fp, wrsm_controller_t *cont);

static struct {
	char *name;
	char *usage;
} commands[6], private_commands[] = {
	{ "usage", "[<command>]" },
	{ "replace", "-f <in-filename> [-c <controller-id>] [-h <hostname>]" },
	{ "install", "[-c <controller-id>] [-w <wci-id>]" },
	{ "enable", "[-c <controller-id>] [-w <wci-id>]" },
	{ "info", "[-c <controller-id>]" },
	{ "read", "[-c <controller-id>] -f <in-filename> [-h <hostname>]" },
	{ "start", "[-c <controller-id>]" },
	{ "stop", "[-c <controller-id>]" },
	{ "link_disable", "-w <wci-id> -l <linkno>" },
	{ "link_enable", "-w <wci-id> -l <linkno>" },
	{ "check", "[-c <controller-id>] [-h <hostname>]" },
	{ "msgtest", "" },
	{ NULL, NULL },
};

static char *command_name;
extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

int
main(int argc, char **argv)
{
	char *file = NULL;
	int controller_id = -1;
	wrsm_safari_port_t wci_ids[MAX_WCI_IDS];
	size_t num_wcis = 0;
	boolean_t got_controller_id = B_FALSE;
	boolean_t got_hostname = B_FALSE;
	char hostname[WRSM_HOSTNAMELEN] = "";
	char c;
	char *command;
	wrsm_controller_t *cont = NULL;
	int wci_index = 0;
	int rc;
	int linkno = -1;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	command_name = argv[0];

	if (argc < 2) {
		print_usage(B_FALSE);
		return (2);
	}

	command = argv[1];

	while ((c = getopt(argc-1, &argv[1], "c:f:h:l:w:"))
	    != EOF) {
		switch (c) {
		case 'c':
			controller_id = atoi(optarg);
			got_controller_id = B_TRUE;
			break;
		case 'f':
			file = optarg;
			break;
		case 'w':
			wci_ids[wci_index++] =
				(wrsm_safari_port_t)
				strtol(optarg, NULL, 0);
			num_wcis++;
			break;
		case 'h':
			(void) strcpy(hostname, optarg);
			got_hostname = B_TRUE;
			break;
		case 'l':
			linkno = (int)atoi(optarg);
			break;
		default:
			print_command_usage(command);
			return (1);
		}
	}

	if (strcmp(command, "create") == 0) {
		if (!got_controller_id) {
			errno = EINVAL;
			perror(command);
			print_command_usage(command);
			return (1);
		}
		if (file == NULL) {
			errno = EINVAL;
			perror(command);
			print_command_usage(command);
			return (1);
		}
		rc = mkconfig(NULL, file, controller_id);

	} else if (strcmp(command, "initial") == 0) {
		if (file == NULL) {
			errno = EINVAL;
			perror(command);
			print_command_usage(command);
			return (1);
		}

		if (got_hostname)
			rc = wrsm_read_config_for_host(file, &cont, hostname);
		else
			rc = wrsm_read_config(file, &cont);
		if (rc != 0) {
			(void) fprintf(stderr, MSG_FILE, command, file);
			return (1);
		}
		if (got_controller_id &&
		    controller_id != cont->controller_id) {
			(void) fprintf(stderr, MSG_NOT_FOUND,
			    command, controller_id, file);
			return (1);
		}

		if ((rc = wrsm_initial_config(cont)) != 0) {
			perror(command);
			return (1);
		}

	} else if (strcmp(command, "start") == 0) {
		if (!got_controller_id) {
			rc = wrsm_start_all_configs();
			return (rc ? 1 : 0);
		} else if ((rc = wrsm_start_config(controller_id)) != 0) {
			perror(command);
			return (1);
		}

	} else if (strcmp(command, "stop") == 0) {
		if (!got_controller_id) {
			rc = wrsm_stop_all_configs();
			return (rc ? 1 : 0);
		} else if ((rc = wrsm_stop_config(controller_id)) != 0) {
			perror(command);
			return (1);
		}

	} else if (strcmp(command, "remove") == 0) {
		if (!got_controller_id) {
			rc = wrsm_remove_all_configs();
			return (rc ? 1 : 0);
		} else if ((rc = wrsm_remove_config(controller_id)) != 0) {
			perror(command);
			return (1);
		}

	} else if (strcmp(command, "replace") == 0) {
		if (file == NULL) {
			errno = EINVAL;
			perror(command);
			print_command_usage(command);
			return (1);
		}

		if (got_hostname)
			rc = wrsm_read_config_for_host(file, &cont, hostname);
		else
			rc = wrsm_read_config(file, &cont);

		if (rc != 0) {
			(void) fprintf(stderr, MSG_FILE, command, file);
			return (1);
		}
		if (got_controller_id &&
		    controller_id != cont->controller_id) {
			(void) fprintf(stderr, MSG_NOT_FOUND,
			    command, controller_id, file);
			return (1);
		}
		if ((rc = wrsm_replace_config(cont)) != 0) {
			perror(command);
			return (1);
		}

	} else if (strcmp(command, "install") == 0) {
		if (!got_controller_id) {
			controller_id = 0;
		}
		if ((rc = wrsm_install_config(controller_id, num_wcis,
		    wci_ids)) != 0) {
			perror(command);
			return (1);
		}

	} else if (strcmp(command, "enable") == 0) {
		if (!got_controller_id) {
			controller_id = 0;
		}
		if ((rc = wrsm_enable_config(controller_id, num_wcis,
		    wci_ids)) != 0) {
			perror(command);
			return (1);
		}

	} else if (strcmp(command, "dump") == 0) {
		if (!got_controller_id) {
			errno = EINVAL;
			perror(command);
			print_command_usage(command);
			return (1);
		}
		if (file == NULL) {
			errno = EINVAL;
			perror(command);
			print_command_usage(command);
			return (1);
		}
		return (dump_config(file, controller_id));

	} else if (strcmp(command, "info") == 0) {
		return (getinfo(controller_id));

	} else if (strcmp(command, "topology") == 0) {
		return (topology(controller_id));

	} else if (strcmp(command, "check") == 0) {
		return (check(controller_id, got_hostname ? hostname : NULL));

	} else if (strcmp(command, "usage") == 0) {
		if (argc == 3) {
			char *cmd = argv[2];
			if (strcmp(cmd, "private") == 0) {
				print_usage(B_TRUE);
			} else {
				print_command_usage(cmd);
			}
		} else {
			print_usage(B_FALSE);
		}

	} else if (strcmp(command, "read") == 0) {
		if (file == NULL) {
			errno = EINVAL;
			perror(command);
			print_command_usage(command);
			return (1);
		}

		if (got_hostname)
			rc = wrsm_read_config_for_host(file, &cont, hostname);
		else
			rc = wrsm_read_config(file, &cont);
		if (rc != 0) {
			(void) fprintf(stderr, MSG_FILE, command, file);
			return (1);
		}
		if (got_controller_id &&
		    controller_id != cont->controller_id) {
			(void) fprintf(stderr, MSG_NOT_FOUND,
			    command, controller_id, file);
			return (1);
		}
		wrsm_print_controller(stdout, cont);

	} else if (strcmp(command, "link_enable") == 0) {

		if ((num_wcis != 1) || (linkno == -1)) {
			errno = EINVAL;
			perror(command);
			print_command_usage(command);
			return (1);
		}
		rc = wrsm_link_enable(wci_ids[0], linkno);
		if (rc != 0) {
			perror(command);
			return (1);
		}

	} else if (strcmp(command, "link_disable") == 0) {

		if ((num_wcis != 1) || (linkno == -1)) {
			errno = EINVAL;
			perror(command);
			print_command_usage(command);
			return (1);
		}
		rc = wrsm_link_disable(wci_ids[0], linkno);
		if (rc != 0) {
			perror(command);
			return (1);
		}

	} else if (strcmp(command, "msgtest") == 0) {
		(void) printf(MSG_FILE, command, "filename");
		(void) printf(MSG_NOT_FOUND, command, 32, "filename");
		(void) printf(MSG_INPUT1);
		(void) printf(MSG_INPUT2);
		(void) printf(MSG_INPUT3);
		(void) printf(MSG_LINK_IN_USE, "create", "hostname", 1023, 2);
		(void) printf(MSG_INVALID, "create", "ncslice", 255);
		(void) printf(MSG_UNKNOWN, "create", "option");
		(void) printf(MSG_PARSE_ERR, "create", "unparsable line\n");
		(void) printf(MSG_LINK_RANGE, "create", "hostname.1023.3");
		(void) printf(MSG_NUM_HOSTS, "create", 10);
		(void) printf(MSG_NO_ROUTE, "create", "hostname1",
		    "hostname2");
	} else {
		errno = EINVAL;
		perror(command_name);
		print_usage(B_FALSE);
		return (1);
	}

	return (0);
}

void
init_usage()
{
	commands[0].name = "create";
	commands[0].usage =
		gettext("-c <controller id> -f <output file name>");
	commands[1].name = "initial";
	commands[1].usage =
		gettext("[-c <controller id>] -f <input file name>");
	commands[2].name = "remove";
	commands[2].usage = gettext("[-c <controller id>]");
	commands[3].name = "topology";
	commands[3].usage = gettext("[-c <controller id>]");
	commands[4].name = "dump";
	commands[4].usage =
		gettext("-c <controller id> -f <output file name>");
	commands[5].name = NULL;
	commands[5].usage = NULL;
}

void
print_usage(boolean_t private)
{
	int i;

	init_usage();
	(void) fprintf(stderr, gettext("usage: %s\n"), command_name);
	for (i = 0; commands[i].name; ++i)
		(void) printf("\t%s %s\n", commands[i].name,
		    commands[i].usage);
	if (private) {
		(void) printf("private commands:\n");
		for (i = 0; private_commands[i].name; i++) {
			(void) printf("\t%s %s\n", private_commands[i].name,
			    private_commands[i].usage);
		}
	}
}

static void
print_command_usage(char *command)
{
	int i;

	init_usage();
	(void) fprintf(stderr, gettext("usage: %s "), command_name);
	for (i = 0; commands[i].name; ++i) {
		if (strcmp(commands[i].name, command) == 0) {
			(void) printf("%s %s\n", commands[i].name,
			    commands[i].usage);
			break;
		}
	}
	if (commands[i].name == NULL) {
		print_usage(B_FALSE);
	}
}



/*
 * If dump_config is called with a controller id that is less than 0,
 * it scans all available controllers and prints the number of
 * those which are active.  If there is a valid controller-id
 * argument, it gets the config data from the kernel, unparses
 * it, and prints its contents.
 */
int
dump_config(char *file_name, int controller_id)
{
	wrsm_controller_t *config;
	FILE *fd;

	if (file_name) {
		fd = fopen(file_name, "w");
	} else {
		fd = stdout;
	}
	if (fd == NULL) {
		perror("dump");
	}
	if (wrsm_get_config(controller_id, &config) != 0) {
		return (1);
	}
	wrsm_print_controller(fd, config);
	wrsm_free_config(config);
	return (0);
}

/*
 * If getinfo is called with a controller id that is less than 0,
 * it prints info on all available controllers.
 */
int
getinfo(int controller_id)
{
	wrsm_controller_t *config;
	int i;

	if (controller_id < 0) {
		int n;

		if ((n = wrsm_get_num_controllers()) < 0) {
			perror("info");
			return (1);
		}
		for (i = 0; i < n; ++i)
			if (wrsm_get_config(i, &config) == 0) {
				(void) getinfo(i);
			}
		return (0);
	}

	if (wrsm_get_config(controller_id, &config) != 0) {
		perror("info");
		return (1);
	}
	(void) printf("controller %d cnodeid %d\n", config->controller_id,
	    config->cnodeid);
	for (i = 0; i < config->nmembers; i++) {
		int cnodeid = config->u_members.val.members[i]->cnodeid;
		(void) printf("   cnodeid %d %s\n", cnodeid,
		    config->u_members.val.members[i]->hostname);
	}
	free(config);
	return (0);
}


void
free_controller_info(struct dump_info ***controller_info)
{
	int controller_index = 0;
	int member_index;

	if (controller_info == NULL) {
		return;
	}

	while (controller_info[controller_index] != NULL) {
		member_index = 0;
		while (controller_info[controller_index][member_index]
		    != NULL) {
			free(controller_info[controller_index][member_index]);
			member_index++;
		}
		free(controller_info[controller_index]);
		controller_index++;
	}
	free(controller_info);
}

int
compare(const void *left, const void *right)
{
	struct dump_info *lt = *((struct dump_info **)left);
	struct dump_info *rt = *((struct dump_info **)right);

	if (lt->fmnode_id < rt->fmnode_id) {
		return (-1);
	} else if (lt->fmnode_id > rt->fmnode_id) {
		return (1);
	} else {
		if (lt->controller_id < rt->controller_id) {
			return (-1);
		} else if (lt->controller_id > rt->controller_id) {
			return (1);
		} else {
			return (0);
		}
	}
}

void
print_column_headers(FILE *fp)
{
	(void) fprintf(fp, "%-25s", "FM Node ID");
	(void) fprintf(fp, "%-25s", "Node Name");
	(void) fprintf(fp, "%-25s", "Wildcat Cont Instance");
	(void) fprintf(fp, "%-25s\n", "Wildcat Cont HW Addr");
}

void
print_member_info(FILE *fp, struct dump_info **info, int num_members)
{
	int i;

	print_column_headers(fp);
	for (i = 0; i < num_members; i++) {
		(void) fprintf(fp, "%-25llu", info[i]->fmnode_id);
		(void) fprintf(fp, "%-25s", info[i]->host_name);
		(void) fprintf(fp, "%-25u", info[i]->controller_id);
		(void) fprintf(fp, "%-25x\n", info[i]->cnode_id);
	}
}



int
topology(int cid)
{
	int num_conts;
	int controller_id;
	int i;
	struct dump_info ***controller_info;
	int cont_index = 0;
	int member_index;
	int total_num_members = 0;
	struct dump_info **member_info;
	int member_count;

	if (cid == -1) {

		/* get the number of controllers */
		if ((num_conts = wrsm_get_num_controllers()) < 0) {
			perror("topology");
			return (1);
		}

	} else {

		/* print the specific controller */
		num_conts = 1;
	}

	/* allocate num_controllers info records to hold the needed data */
	if ((controller_info = (struct dump_info ***)calloc(num_conts + 1,
	    sizeof (struct dump_info **))) == NULL) {
		perror("topology");
		return (1);
	}
	/* Set last pointer to NULL for easy structure traversal, redundant */
	controller_info[num_conts] = NULL;

	for (i = 0; i < num_conts; ++i) {

		wrsm_controller_t *unpacked;
		if (cid == -1)
			controller_id = i;
		else
			controller_id = cid;

		if (wrsm_get_config(controller_id, &unpacked) != 0) {
			continue;
		}
		/*
		 * allocate memory for the number of members in this
		 * controller
		 */
		if ((controller_info[cont_index] = (struct dump_info **)
		    calloc(unpacked->nmembers + 1,
			sizeof (struct dump_info *))) == NULL) {
			perror("toplogy");
			free_controller_info(controller_info);
			free(unpacked);
			return (1);
		}
		/*
		 * Set last pointer to NULL for easy structure
		 * traversal
		 */
		controller_info[cont_index][unpacked->nmembers] = NULL;

		/*
		 * Allocate each member record used to hold the info
		 * we are after and place the appropriate controller
		 * info in the new dump_info structs
		 */
		for (member_index = 0;
		    member_index < unpacked->nmembers;
		    member_index++) {
			if ((controller_info[cont_index][member_index] =
			    (struct dump_info *)
			    calloc(1, sizeof (struct dump_info)))
			    == NULL) {
				perror("toplogy");
				free_controller_info(controller_info);
				free(unpacked);
				return (1);
			}
			controller_info[cont_index][member_index]->fmnode_id =
				unpacked->u_members.val.members[member_index]
				->fmnodeid;
			(void) strcpy(controller_info[cont_index]
			    [member_index]->host_name,
			    unpacked->u_members.val.members[member_index]->
			    hostname);
			controller_info[cont_index][member_index]->
				controller_id = unpacked->controller_id;
			controller_info[cont_index][member_index]->
				    cnode_id = unpacked->
				    u_members.val.members[member_index]->
				    cnodeid;
		}

		total_num_members += unpacked->nmembers;
		cont_index++;
		free(unpacked);
	}

	/*
	 * All the member info is retrieved so now we allocate space for
	 * a flat array for sorting
	 */
	if ((member_info = (struct dump_info **)calloc(total_num_members,
			sizeof (struct dump_info *))) == NULL) {
		perror("toplogy");
		free_controller_info(controller_info);
		return (1);
	}

	/* copy the struct dump_info *'s to the one-dimensional array */
	cont_index = 0;
	member_count = 0;
	while (controller_info[cont_index] != NULL) {
		member_index = 0;
		while (controller_info[cont_index][member_index] != NULL) {
			member_info[member_count++] =
			    controller_info[cont_index][member_index];
			member_index++;
		}
		cont_index++;
	}

	qsort(member_info, total_num_members,
	    sizeof (struct dump_info *), compare);

	print_member_info(stdout, member_info, total_num_members);

	free(member_info);
	free_controller_info(controller_info);
	return (0);
}

static int
check_cnode(int controller_id, wrsm_cnodeid_t cnode, int *time_nsec)
{
	int fd;
	int rc;
	wrsm_ping_arg_t arg;
	char devname[BUFSIZ];
	const int count = 100;

	(void) sprintf(devname, CTLRDEVNAME, controller_id);
	fd = open(devname, O_RDONLY);
	if (fd == -1) {
		perror("open");
		return (1);
	}

	arg.ioctl_version = WRSM_CF_IOCTL_VERSION;
	arg.target = cnode;
	arg.count = count;
	rc = ioctl(fd, WRSM_CTLR_PING, &arg);
	(void) close(fd);
	*time_nsec = arg.time / count;

	return (rc);
}

static int
check(int controller_id, char *hostname)
{
	wrsm_controller_t *config;
	int retval = 0;
	boolean_t host_found = B_FALSE;
	int i;

	if (controller_id < 0) {
		int n;

		if ((n = wrsm_get_num_controllers()) < 0) {
			perror("info");
			return (1);
		}
		for (i = 0; i < n; ++i) {
			if (wrsm_get_config(i, &config) == 0) {
				if (check(i, hostname)) {
					retval = 1;
				}
			}
		}
		return (retval);
	}

	if (wrsm_get_config(controller_id, &config) != 0) {
		perror("check");
		return (1);
	}

	(void) printf("controller %d:\n", controller_id);

	for (i = 0; i < config->nmembers; i++) {
		wrsm_net_member_t *member = config->u_members.val.members[i];
		if (hostname == NULL ||
		    strcmp(member->hostname, hostname) == 0) {
			int ave_time;
			int rc;

			host_found = B_TRUE;
			rc = check_cnode(controller_id, member->cnodeid,
			    &ave_time);
			if (rc == 0) {
				(void) printf("  check of %s successful, "
				    "time = %d ns\n", member->hostname,
				    ave_time);
			} else {
				(void) printf("  check of %s failed\n",
				    member->hostname);
				retval = 1;
			}
		}
	}
	if (!host_found) {
		retval = 1;
	}
	return (retval);
}
