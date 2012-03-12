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
 * Copyright (c) 2012 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <zone.h>
#include <libgen.h>
#include <assert.h>

#include <sys/ipd.h>

static char *g_pname;
static char g_zonename[ZONENAME_MAX];
static zoneid_t	g_zid;

#define	E_SUCCESS	0
#define	E_ERROR		1
#define	E_USAGE		2

typedef int (*idc_cmd_func_t)(int, char *[]);
typedef struct ipdadm_cmd {
	const char	*idc_name;	/* subcommand name */
	idc_cmd_func_t	idc_func;	/* subcommand function */
	const char	*idc_usage;	/* subcommand help */
} ipdadm_cmd_t;

static int ipdadm_list(int, char *[]);
static int ipdadm_info(int, char *[]);
static int ipdadm_corrupt(int, char *[]);
static int ipdadm_delay(int, char *[]);
static int ipdadm_drop(int, char *[]);
static int ipdadm_remove(int, char *[]);

#define	IPDADM_NCMDS	6
static ipdadm_cmd_t ipdadm_cmds[] = {
	{ "list", ipdadm_list, "list" },
	{ "info", ipdadm_info, "info" },
	{ "corrupt", ipdadm_corrupt, "corrupt <percentage>" },
	{ "delay", ipdadm_delay, "delay <microseconds>" },
	{ "drop", ipdadm_drop, "drop <percentage>" },
	{ "remove", ipdadm_remove, "remove [corrupt|delay|drop]" }
};

static int
usage(FILE *fp)
{
	int ii;
	ipdadm_cmd_t *cmd;

	(void) fprintf(fp, "Usage: %s [-z zonename] subcommand "
	    "[subcommand opts]\n\n", g_pname);
	(void) fprintf(fp, "Subcommands:\n");
	for (ii = 0; ii < IPDADM_NCMDS; ii++) {
		cmd = &ipdadm_cmds[ii];
		(void) fprintf(fp, "\t%s\n", cmd->idc_usage);
	}

	return (E_USAGE);
}

static int
ipdadm_open(void)
{
	int fd;
	fd = open(IPD_DEV_PATH, O_RDWR);
	if (fd < 0) {
		(void) fprintf(stderr, "%s: failed to open %s: %s\n", g_pname,
		    IPD_DEV_PATH, strerror(errno));
		exit(E_ERROR);
	}
	return (fd);
}

/*ARGSUSED*/
static int
ipdadm_list(int argc, char *argv[])
{
	int fd, rval;
	unsigned int ii;
	ipd_ioc_list_t ipil;
	char zonename[ZONENAME_MAX];

	if (argc != 0)
		return (usage(stderr));

	fd = ipdadm_open();
	(void) memset(&ipil, '\0', sizeof (ipd_ioc_list_t));

	rval = ioctl(fd, IPDIOC_LIST, &ipil);
	if (rval != 0) {
		(void) fprintf(stderr, "%s: failed to get list info: %s\n",
		    g_pname, strerror(errno));
		return (E_ERROR);
	}

	ipil.ipil_list = malloc(sizeof (zoneid_t) * ipil.ipil_nzones);
	if (ipil.ipil_list == NULL) {
		(void) fprintf(stderr, "%s: failed to allocate memory: %s\n",
		    g_pname, strerror(errno));
		return (E_ERROR);
	}

	rval = ioctl(fd, IPDIOC_LIST, &ipil);
	if (rval != 0) {
		free(ipil.ipil_list);
		(void) fprintf(stderr, "%s: failed to get list info: %s\n",
		    g_pname, strerror(errno));
		return (E_ERROR);
	}

	for (ii = 0; ii < ipil.ipil_nzones; ii++) {
		if (getzonenamebyid(ipil.ipil_list[ii], zonename,
		    sizeof (zonename)) < 0) {
			(void) fprintf(stderr, "%s: failed to get zonename: "
			    "%s\n", g_pname, strerror(errno));
			return (E_ERROR);
		}
		(void) printf("%s\n", zonename);
	}

	return (E_SUCCESS);
}

/*ARGSUSED*/
static int
ipdadm_info(int argc, char *argv[])
{
	int rval, fd;
	ipd_ioc_info_t ipii;

	if (argc != 0)
		return (usage(stderr));

	ipii.ipii_zoneid = g_zid;
	fd = ipdadm_open();
	rval = ioctl(fd, IPDIOC_INFO, &ipii);
	(void) close(fd);
	if (rval != 0) {
		(void) fprintf(stderr, "%s: failed to get info: %s\n",
		    g_pname, strerror(errno));
		return (E_ERROR);
	}

	(void) printf("ipd information for zone %s:\n",
	    g_zonename);
	(void) printf("\tcorrupt:\t%d%% chance of packet corruption\n",
	    ipii.ipii_corrupt);
	(void) printf("\tdrop:\t\t%d%% chance of packet drop\n",
	    ipii.ipii_drop);
	(void) printf("\tdelay:\t\t%d microsecond delay per packet\n",
	    ipii.ipii_delay);

	return (E_SUCCESS);
}

static long
ipdadm_parse_long(const char *str, const char *name, long min, long max)
{
	long val;
	char *end;

	errno = 0;
	val = strtol(str, &end, 10);
	if (errno != 0) {
		(void) fprintf(stderr, "%s: invalid value for %s: %s\n",
		    g_pname, name, str);
		exit(E_ERROR);
	}

	/*
	 * We want to make sure that we got the whole string. If not that's an
	 * error. e.g. 23.42 should not be valid.
	 */
	if (*end != '\0') {
		(void) fprintf(stderr, "%s: %s value must be an integer\n",
		    g_pname, name);
		exit(E_ERROR);
	}

	if (val < min || val > max) {
		(void) fprintf(stderr, "%s: %s value must be between %ld and "
		    "%ld inclusive\n", g_pname, name, min, max);
		exit(E_ERROR);
	}

	return (val);
}

static int
ipdadm_corrupt(int argc, char *argv[])
{
	int rval, fd;
	long val;
	ipd_ioc_perturb_t ipip;

	if (argc != 1) {
		(void) fprintf(stderr, "%s: corrupt <percentage>\n",
		    g_pname);
		return (usage(stderr));
	}

	val = ipdadm_parse_long(argv[0], "corrupt", 0, 100);
	fd = ipdadm_open();
	ipip.ipip_zoneid = g_zid;
	ipip.ipip_arg = val;
	rval = ioctl(fd, IPDIOC_CORRUPT, &ipip);
	(void) close(fd);
	if (rval == -1) {
		(void) fprintf(stderr, "%s: failed to change corrupt "
		    "value: %s\n", g_pname, strerror(errno));
		return (E_ERROR);
	}

	return (E_SUCCESS);
}

static int
ipdadm_delay(int argc, char *argv[])
{
	long val;
	int fd, rval;
	ipd_ioc_perturb_t ipip;

	if (argc != 1) {
		(void) fprintf(stderr, "%s: delay <microseconds>\n",
		    g_pname);
		return (usage(stderr));
	}

	val = ipdadm_parse_long(argv[0], "delay", 0, IPD_MAX_DELAY);
	fd = ipdadm_open();
	ipip.ipip_zoneid = g_zid;
	ipip.ipip_arg = val;
	rval = ioctl(fd, IPDIOC_DELAY, &ipip);
	(void) close(fd);
	if (rval == -1) {
		(void) fprintf(stderr, "%s: failed to change delay value: %s\n",
		    g_pname, strerror(errno));
		return (E_ERROR);
	}

	return (E_SUCCESS);
}

static int
ipdadm_drop(int argc, char *argv[])
{
	long val;
	int fd, rval;
	ipd_ioc_perturb_t ipip;

	if (argc != 1) {
		(void) fprintf(stderr, "%s: drop <percentage>\n",
		    g_pname);
		return (usage(stderr));
	}

	val = ipdadm_parse_long(argv[0], "drop", 0, 100);
	fd = ipdadm_open();
	ipip.ipip_zoneid = g_zid;
	ipip.ipip_arg = val;
	rval = ioctl(fd, IPDIOC_DROP, &ipip);
	(void) close(fd);
	if (rval == -1) {
		(void) fprintf(stderr, "%s: failed to change drop value: %s\n",
		    g_pname, strerror(errno));
		return (E_ERROR);
	}

	return (E_SUCCESS);
}

static int
ipdadm_remove_valid(const char *str)
{
	if (strcmp(str, "corrupt") == 0) {
		return (IPD_CORRUPT);
	} else if (strcmp(str, "drop") == 0) {
		return (IPD_DROP);
	} else if (strcmp(str, "delay") == 0) {
		return (IPD_DELAY);
	}

	return (0);
}

static int
ipdadm_remove(int argc, char *argv[])
{
	ipd_ioc_perturb_t ipi;
	char *cur, *res;
	int rval, fd;

	if (argc < 1) {
		(void) fprintf(stderr, "%s: remove <arguments>\n",
		    g_pname);
		return (usage(stderr));
	}

	if (argc > 1) {
		(void) fprintf(stderr, "%s: remove's arguments must be "
		    "comma seperated\n", g_pname);
		return (E_ERROR);
	}

	ipi.ipip_zoneid = g_zid;
	ipi.ipip_arg = 0;

	cur = argv[0];
	while ((res = strchr(cur, ',')) != NULL) {
		*res = '\0';
		if ((rval = ipdadm_remove_valid(cur)) == 0) {
			(void) fprintf(stderr, "%s: unknown remove "
			    "argument: %s\n", g_pname, cur);
			return (E_ERROR);
		}
		ipi.ipip_arg |= rval;
		cur = res + 1;
	}

	if ((rval = ipdadm_remove_valid(cur)) == 0) {
		(void) fprintf(stderr, "%s: unknown remove argument: %s\n",
		    g_pname, cur);
		return (E_ERROR);
	}
	ipi.ipip_arg |= rval;

	fd = ipdadm_open();
	rval = ioctl(fd, IPDIOC_REMOVE, &ipi);
	(void) close(fd);
	if (rval == -1) {
		(void) fprintf(stderr, "%s: failed to remove instances: %s\n",
		    g_pname, strerror(errno));
		return (E_ERROR);
	}

	return (E_SUCCESS);
}


int
main(int argc, char *argv[])
{
	int ii;
	ipdadm_cmd_t *cmd;

	g_pname = basename(argv[0]);

	if (argc < 2)
		return (usage(stderr));
	argc--;
	argv++;

	g_zid = getzoneid();
	if (strcmp("-z", argv[0]) == 0) {
		argc--;
		argv++;
		if (argc < 1) {
			(void) fprintf(stderr, "%s: -z requires an argument\n",
			    g_pname);
			return (usage(stderr));
		}

		if (g_zid != GLOBAL_ZONEID) {
			(void) fprintf(stderr, "%s: -z option only permitted "
			    "in global zone\n", g_pname);
			return (usage(stderr));
		}

		g_zid = getzoneidbyname(argv[0]);
		if (g_zid == -1) {
			(void) fprintf(stderr, "%s: %s: invalid zone\n",
			    g_pname, argv[0]);
			return (E_ERROR);
		}
		argc--;
		argv++;
	}

	if (getzonenamebyid(g_zid, g_zonename, sizeof (g_zonename)) < 0) {
		(void) fprintf(stderr, "%s: failed to get zonename: %s\n",
		    g_pname, strerror(errno));
		return (E_ERROR);
	}

	if (argc < 1)
		return (usage(stderr));

	for (ii = 0; ii < IPDADM_NCMDS; ii++) {
		cmd = &ipdadm_cmds[ii];
		if (strcmp(argv[0], cmd->idc_name) == 0) {
			argv++;
			argc--;
			assert(cmd->idc_func != NULL);
			return (cmd->idc_func(argc, argv));
		}
	}

	(void) fprintf(stderr, "%s: %s: unknown command\n", g_pname, argv[0]);
	return (usage(stderr));
}
