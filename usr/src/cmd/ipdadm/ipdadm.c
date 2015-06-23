/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */


/*
 * Copyright (c) 2012 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <values.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <zone.h>
#include <libgen.h>
#include <assert.h>

#include <libipd.h>

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
	{ "list", ipdadm_list, "list [-v]" },
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

static void
ipdadm_list_one(zoneid_t z, const ipd_config_t *icp, void *arg)
{
	char zonename[ZONENAME_MAX];
	int opt_v = (int)(intptr_t)arg;

	if (getzonenamebyid(z, zonename, sizeof (zonename)) < 0)
		(void) printf("%ld", z);
	else
		(void) printf("%s", zonename);

	if (!opt_v) {
		(void) printf("\n");
		return;
	}

	(void) printf("\t%u\t%u\t%u\n", icp->ic_corrupt, icp->ic_drop,
	    icp->ic_delay);
}

static int
ipdadm_list(int argc, char *argv[])
{
	int opt_v = 0;
	int fd, rval;
	ipd_stathdl_t hdl;

	if (argc > 1)
		return (usage(stderr));

	if (argc == 1) {
		if (strcmp(argv[0], "-v") == 0)
			++opt_v;
		else
			return (usage(stderr));
	}

	fd = ipd_open(NULL);
	if (fd < 0) {
		(void) fprintf(stderr, "%s: failed to open ipd ctl node: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}
	rval = ipd_status_read(fd, &hdl);
	(void) ipd_close(fd);

	if (rval != 0) {
		(void) fprintf(stderr, "%s: failed to get list info: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}

	ipd_status_foreach_zone(hdl, ipdadm_list_one, (void *)(intptr_t)opt_v);
	ipd_status_free(hdl);

	return (E_SUCCESS);
}

/*ARGSUSED*/
static int
ipdadm_info(int argc, char *argv[])
{
	int rval, fd;
	ipd_stathdl_t hdl;
	ipd_config_t *icp;

	if (argc != 0)
		return (usage(stderr));

	fd = ipd_open(NULL);
	if (fd < 0) {
		(void) fprintf(stderr, "%s: failed to open ipd ctl node: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}
	rval = ipd_status_read(fd, &hdl);
	(void) ipd_close(fd);
	if (rval != 0) {
		(void) fprintf(stderr, "%s: failed to get info: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}

	if (ipd_status_get_config(hdl, g_zid, &icp) != 0) {
		if (ipd_errno == EIPD_ZC_NOENT) {
			(void) printf("zone %s does not exist or has no "
			    "ipd actions enabled\n", g_zonename);
			return (E_SUCCESS);
		}
		(void) fprintf(stderr, "%s: failed to get info: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}

	(void) printf("ipd information for zone %s:\n",
	    g_zonename);
	(void) printf("\tcorrupt:\t%u%% chance of packet corruption\n",
	    icp->ic_corrupt);
	(void) printf("\tdrop:\t\t%u%% chance of packet drop\n",
	    icp->ic_drop);
	(void) printf("\tdelay:\t\t%u microsecond delay per packet\n",
	    icp->ic_delay);

	ipd_status_free(hdl);

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
	ipd_config_t ic;

	if (argc != 1) {
		(void) fprintf(stderr, "%s: corrupt <percentage>\n",
		    g_pname);
		return (usage(stderr));
	}

	val = ipdadm_parse_long(argv[0], "corrupt", 0, 100);
	bzero(&ic, sizeof (ic));
	ic.ic_mask = IPDM_CORRUPT;
	ic.ic_corrupt = val;

	fd = ipd_open(NULL);
	if (fd < 0) {
		(void) fprintf(stderr, "%s: failed to open ipd ctl node: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}
	rval = ipd_ctl(fd, g_zid, &ic);
	(void) ipd_close(fd);

	if (rval != 0) {
		(void) fprintf(stderr, "%s: failed to change corrupt "
		    "value: %s\n", g_pname, ipd_errmsg);
		return (E_ERROR);
	}

	return (E_SUCCESS);
}

static int
ipdadm_delay(int argc, char *argv[])
{
	long val;
	int fd, rval;
	ipd_config_t ic;

	if (argc != 1) {
		(void) fprintf(stderr, "%s: delay <microseconds>\n",
		    g_pname);
		return (usage(stderr));
	}

	val = ipdadm_parse_long(argv[0], "delay", 0, MAXLONG);
	bzero(&ic, sizeof (ic));
	ic.ic_mask = IPDM_DELAY;
	ic.ic_delay = val;

	fd = ipd_open(NULL);
	if (fd < 0) {
		(void) fprintf(stderr, "%s: failed to open ipd ctl node: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}
	rval = ipd_ctl(fd, g_zid, &ic);
	(void) ipd_close(fd);

	if (rval != 0) {
		(void) fprintf(stderr, "%s: failed to change delay value: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}

	return (E_SUCCESS);
}

static int
ipdadm_drop(int argc, char *argv[])
{
	long val;
	int fd, rval;
	ipd_config_t ic;

	if (argc != 1) {
		(void) fprintf(stderr, "%s: drop <percentage>\n",
		    g_pname);
		return (usage(stderr));
	}

	val = ipdadm_parse_long(argv[0], "drop", 0, 100);
	bzero(&ic, sizeof (ic));
	ic.ic_mask = IPDM_DROP;
	ic.ic_drop = val;

	fd = ipd_open(NULL);
	if (fd < 0) {
		(void) fprintf(stderr, "%s: failed to open ipd ctl node: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}
	rval = ipd_ctl(fd, g_zid, &ic);
	(void) ipd_close(fd);

	if (rval != 0) {
		(void) fprintf(stderr, "%s: failed to change drop value: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}

	return (E_SUCCESS);
}

static int
ipdadm_remove_valid(const char *str)
{
	if (strcmp(str, "corrupt") == 0) {
		return (IPDM_CORRUPT);
	} else if (strcmp(str, "drop") == 0) {
		return (IPDM_DROP);
	} else if (strcmp(str, "delay") == 0) {
		return (IPDM_DELAY);
	}

	return (0);
}

static int
ipdadm_remove(int argc, char *argv[])
{
	ipd_config_t ic;
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

	bzero(&ic, sizeof (ic));

	cur = argv[0];
	while ((res = strchr(cur, ',')) != NULL) {
		*res = '\0';
		if ((rval = ipdadm_remove_valid(cur)) == 0) {
			(void) fprintf(stderr, "%s: unknown remove "
			    "argument: %s\n", g_pname, cur);
			return (E_ERROR);
		}
		ic.ic_mask |= rval;
		cur = res + 1;
	}

	if ((rval = ipdadm_remove_valid(cur)) == 0) {
		(void) fprintf(stderr, "%s: unknown remove argument: %s\n",
		    g_pname, cur);
		return (E_ERROR);
	}
	ic.ic_mask |= rval;

	fd = ipd_open(NULL);
	if (fd < 0) {
		(void) fprintf(stderr, "%s: failed to open ipd ctl node: %s\n",
		    g_pname, ipd_errmsg);
		return (E_ERROR);
	}
	rval = ipd_ctl(fd, g_zid, &ic);
	(void) ipd_close(fd);
	if (rval == -1) {
		(void) fprintf(stderr, "%s: failed to remove instances: %s\n",
		    g_pname, ipd_errmsg);
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
