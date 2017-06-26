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
 * Copyright 2016 Nexenta Systems, Inc.
 */

/*
 * nvmeadm -- NVMe administration utility
 *
 * nvmeadm [-v] [-d] [-h] <command> [<ctl>[/<ns>][,...]] [args]
 * commands:	list
 *		identify
 *		get-logpage <logpage name>
 *		get-features <feature>[,...]
 *		format ...
 *		secure-erase ...
 *		detach ...
 *		attach ...
 *		get-param ...
 *		set-param ...
 *		load-firmware ...
 *		activate-firmware ...
 *		write-uncorrectable ...
 *		compare ...
 *		compare-and-write ...
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <ctype.h>
#include <err.h>
#include <sys/sunddi.h>
#include <libdevinfo.h>

#include <sys/nvme.h>

#include "nvmeadm.h"

typedef struct nvme_process_arg nvme_process_arg_t;
typedef struct nvme_feature nvme_feature_t;
typedef struct nvmeadm_cmd nvmeadm_cmd_t;

struct nvme_process_arg {
	int npa_argc;
	char **npa_argv;
	char *npa_name;
	uint32_t npa_nsid;
	boolean_t npa_isns;
	const nvmeadm_cmd_t *npa_cmd;
	di_node_t npa_node;
	di_minor_t npa_minor;
	char *npa_path;
	char *npa_dsk;
	nvme_identify_ctrl_t *npa_idctl;
	nvme_identify_nsid_t *npa_idns;
	nvme_version_t *npa_version;
};

struct nvme_feature {
	char *f_name;
	char *f_short;
	uint8_t f_feature;
	size_t f_bufsize;
	uint_t f_getflags;
	int (*f_get)(int, const nvme_feature_t *, nvme_identify_ctrl_t *);
	void (*f_print)(uint64_t, void *, size_t, nvme_identify_ctrl_t *);
};

#define	NVMEADM_CTRL	1
#define	NVMEADM_NS	2
#define	NVMEADM_BOTH	(NVMEADM_CTRL | NVMEADM_NS)

struct nvmeadm_cmd {
	char *c_name;
	char *c_desc;
	char *c_flagdesc;
	int (*c_func)(int, const nvme_process_arg_t *);
	void (*c_usage)(const char *);
	boolean_t c_multi;
};


static void usage(const nvmeadm_cmd_t *);
static void nvme_walk(nvme_process_arg_t *, di_node_t);
static boolean_t nvme_match(nvme_process_arg_t *);

static int nvme_process(di_node_t, di_minor_t, void *);

static int do_list(int, const nvme_process_arg_t *);
static int do_identify(int, const nvme_process_arg_t *);
static int do_get_logpage_error(int, const nvme_process_arg_t *);
static int do_get_logpage_health(int, const nvme_process_arg_t *);
static int do_get_logpage_fwslot(int, const nvme_process_arg_t *);
static int do_get_logpage(int, const nvme_process_arg_t *);
static int do_get_feat_common(int, const nvme_feature_t *,
    nvme_identify_ctrl_t *);
static int do_get_feat_intr_vect(int, const nvme_feature_t *,
    nvme_identify_ctrl_t *);
static int do_get_features(int, const nvme_process_arg_t *);
static int do_format(int, const nvme_process_arg_t *);
static int do_secure_erase(int, const nvme_process_arg_t *);
static int do_attach_detach(int, const nvme_process_arg_t *);

static void usage_list(const char *);
static void usage_identify(const char *);
static void usage_get_logpage(const char *);
static void usage_get_features(const char *);
static void usage_format(const char *);
static void usage_secure_erase(const char *);
static void usage_attach_detach(const char *);

int verbose;
int debug;
int found;
static int exitcode;

static const nvmeadm_cmd_t nvmeadm_cmds[] = {
	{
		"list",
		"list controllers and namespaces",
		NULL,
		do_list, usage_list, B_TRUE
	},
	{
		"identify",
		"identify controllers and/or namespaces",
		NULL,
		do_identify, usage_identify, B_TRUE
	},
	{
		"get-logpage",
		"get a log page from controllers and/or namespaces",
		NULL,
		do_get_logpage, usage_get_logpage, B_TRUE
	},
	{
		"get-features",
		"get features from controllers and/or namespaces",
		NULL,
		do_get_features, usage_get_features, B_TRUE
	},
	{
		"format",
		"format namespace(s) of a controller",
		NULL,
		do_format, usage_format, B_FALSE
	},
	{
		"secure-erase",
		"secure erase namespace(s) of a controller",
		"  -c  Do a cryptographic erase.",
		do_secure_erase, usage_secure_erase, B_FALSE
	},
	{
		"detach",
		"detach blkdev(7d) from namespace(s) of a controller",
		NULL,
		do_attach_detach, usage_attach_detach, B_FALSE
	},
	{
		"attach",
		"attach blkdev(7d) to namespace(s) of a controller",
		NULL,
		do_attach_detach, usage_attach_detach, B_FALSE
	},
	{
		NULL, NULL, NULL,
		NULL, NULL, B_FALSE
	}
};

static const nvme_feature_t features[] = {
	{ "Arbitration", "",
	    NVME_FEAT_ARBITRATION, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_arbitration },
	{ "Power Management", "",
	    NVME_FEAT_POWER_MGMT, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_power_mgmt },
	{ "LBA Range Type", "range",
	    NVME_FEAT_LBA_RANGE, NVME_LBA_RANGE_BUFSIZE, NVMEADM_NS,
	    do_get_feat_common, nvme_print_feat_lba_range },
	{ "Temperature Threshold", "",
	    NVME_FEAT_TEMPERATURE, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_temperature },
	{ "Error Recovery", "",
	    NVME_FEAT_ERROR, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_error },
	{ "Volatile Write Cache", "cache",
	    NVME_FEAT_WRITE_CACHE, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_write_cache },
	{ "Number of Queues", "queues",
	    NVME_FEAT_NQUEUES, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_nqueues },
	{ "Interrupt Coalescing", "coalescing",
	    NVME_FEAT_INTR_COAL, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_intr_coal },
	{ "Interrupt Vector Configuration", "vector",
	    NVME_FEAT_INTR_VECT, 0, NVMEADM_CTRL,
	    do_get_feat_intr_vect, nvme_print_feat_intr_vect },
	{ "Write Atomicity", "atomicity",
	    NVME_FEAT_WRITE_ATOM, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_write_atom },
	{ "Asynchronous Event Configuration", "event",
	    NVME_FEAT_ASYNC_EVENT, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_async_event },
	{ "Autonomous Power State Transition", "",
	    NVME_FEAT_AUTO_PST, NVME_AUTO_PST_BUFSIZE, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_auto_pst },
	{ "Software Progress Marker", "progress",
	    NVME_FEAT_PROGRESS, 0, NVMEADM_CTRL,
	    do_get_feat_common, nvme_print_feat_progress },
	{ NULL, NULL, 0, 0, B_FALSE, NULL }
};


int
main(int argc, char **argv)
{
	int c;
	extern int optind;
	const nvmeadm_cmd_t *cmd;
	di_node_t node;
	nvme_process_arg_t npa = { 0 };
	int help = 0;
	char *tmp, *lasts = NULL;

	while ((c = getopt(argc, argv, "dhv")) != -1) {
		switch (c) {
		case 'd':
			debug++;
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
			help++;
			break;
		case '?':
			usage(NULL);
			exit(-1);
		}
	}

	if (optind == argc) {
		usage(NULL);
		if (help)
			exit(0);
		else
			exit(-1);
	}

	/* Look up the specified command in the command table. */
	for (cmd = &nvmeadm_cmds[0]; cmd->c_name != NULL; cmd++)
		if (strcmp(cmd->c_name, argv[optind]) == 0)
			break;

	if (cmd->c_name == NULL) {
		usage(NULL);
		exit(-1);
	}

	if (help) {
		usage(cmd);
		exit(0);
	}

	npa.npa_cmd = cmd;

	optind++;

	/*
	 * All commands but "list" require a ctl/ns argument.
	 */
	if ((optind == argc || (strncmp(argv[optind], "nvme", 4) != 0)) &&
	    cmd->c_func != do_list) {
		warnx("missing controller/namespace name");
		usage(cmd);
		exit(-1);
	}


	/* Store the remaining arguments for use by the command. */
	npa.npa_argc = argc - optind - 1;
	npa.npa_argv = &argv[optind + 1];

	/*
	 * Make sure we're not running commands on multiple controllers that
	 * aren't allowed to do that.
	 */
	if (argv[optind] != NULL && strchr(argv[optind], ',') != NULL &&
	    cmd->c_multi == B_FALSE) {
		warnx("%s not allowed on multiple controllers",
		    cmd->c_name);
		usage(cmd);
		exit(-1);
	}

	/*
	 * Get controller/namespace arguments and run command.
	 */
	npa.npa_name = strtok_r(argv[optind], ",", &lasts);
	do {
		if (npa.npa_name != NULL) {
			tmp = strchr(npa.npa_name, '/');
			if (tmp != NULL) {
				unsigned long nsid;
				*tmp++ = '\0';
				errno = 0;
				nsid = strtoul(tmp, NULL, 10);
				if (nsid >= UINT32_MAX || errno != 0) {
					warn("invalid namespace %s", tmp);
					exitcode--;
					continue;
				}
				if (nsid == 0) {
					warnx("invalid namespace %s", tmp);
					exitcode--;
					continue;
				}
				npa.npa_nsid = nsid;
				npa.npa_isns = B_TRUE;
			}
		}

		if ((node = di_init("/", DINFOSUBTREE | DINFOMINOR)) == NULL)
			err(-1, "failed to initialize libdevinfo");
		nvme_walk(&npa, node);
		di_fini(node);

		if (found == 0) {
			if (npa.npa_name != NULL) {
				warnx("%s%.*s%.*d: no such controller or "
				    "namespace", npa.npa_name,
				    npa.npa_nsid > 0 ? -1 : 0, "/",
				    npa.npa_nsid > 0 ? -1 : 0, npa.npa_nsid);
			} else {
				warnx("no controllers found");
			}
			exitcode--;
		}
		found = 0;
		npa.npa_name = strtok_r(NULL, ",", &lasts);
	} while (npa.npa_name != NULL);

	exit(exitcode);
}

static void
usage(const nvmeadm_cmd_t *cmd)
{
	(void) fprintf(stderr, "usage:\n");
	(void) fprintf(stderr, "  %s -h %s\n", getprogname(),
	    cmd != NULL ? cmd->c_name : "[<command>]");
	(void) fprintf(stderr, "  %s [-dv] ", getprogname());

	if (cmd != NULL) {
		cmd->c_usage(cmd->c_name);
	} else {
		(void) fprintf(stderr,
		    "<command> <ctl>[/<ns>][,...] [<args>]\n");
		(void) fprintf(stderr,
		    "\n  Manage NVMe controllers and namespaces.\n");
		(void) fprintf(stderr, "\ncommands:\n");

		for (cmd = &nvmeadm_cmds[0]; cmd->c_name != NULL; cmd++)
			(void) fprintf(stderr, "  %-15s - %s\n",
			    cmd->c_name, cmd->c_desc);
	}
	(void) fprintf(stderr, "\nflags:\n"
	    "  -h  print usage information\n"
	    "  -d  print information useful for debugging %s\n"
	    "  -v  print verbose information\n", getprogname());
	if (cmd != NULL && cmd->c_flagdesc != NULL)
		(void) fprintf(stderr, "%s\n", cmd->c_flagdesc);
}

static boolean_t
nvme_match(nvme_process_arg_t *npa)
{
	char *name;
	uint32_t nsid = 0;

	if (npa->npa_name == NULL)
		return (B_TRUE);

	if (asprintf(&name, "%s%d", di_driver_name(npa->npa_node),
	    di_instance(npa->npa_node)) < 0)
		err(-1, "nvme_match()");

	if (strcmp(name, npa->npa_name) != 0) {
		free(name);
		return (B_FALSE);
	}

	free(name);

	if (npa->npa_isns) {
		if (npa->npa_nsid == 0)
			return (B_TRUE);
		nsid = strtoul(di_minor_name(npa->npa_minor), NULL, 10);
	}

	if (npa->npa_isns && npa->npa_nsid != nsid)
		return (B_FALSE);

	return (B_TRUE);
}

char *
nvme_dskname(const nvme_process_arg_t *npa)
{
	char *path = NULL;
	di_node_t child;
	di_dim_t dim;
	char *addr;

	dim = di_dim_init();

	for (child = di_child_node(npa->npa_node);
	    child != DI_NODE_NIL;
	    child = di_sibling_node(child)) {
		addr = di_bus_addr(child);
		if (addr == NULL)
			continue;

		if (addr[0] == 'w')
			addr++;

		if (strncasecmp(addr, di_minor_name(npa->npa_minor),
		    strchrnul(addr, ',') - addr) != 0)
			continue;

		path = di_dim_path_dev(dim, di_driver_name(child),
		    di_instance(child), "c");

		if (path != NULL) {
			path[strlen(path) - 2] = '\0';
			path = strrchr(path, '/') + 1;
			if (path != NULL) {
				path = strdup(path);
				if (path == NULL)
					err(-1, "nvme_dskname");
			}
		}

		break;
	}

	di_dim_fini(dim);
	return (path);
}

static int
nvme_process(di_node_t node, di_minor_t minor, void *arg)
{
	nvme_process_arg_t *npa = arg;
	int fd;

	npa->npa_node = node;
	npa->npa_minor = minor;

	if (!nvme_match(npa))
		return (DI_WALK_CONTINUE);

	if ((fd = nvme_open(minor)) < 0)
		return (DI_WALK_CONTINUE);

	found++;

	npa->npa_path = di_devfs_path(node);
	if (npa->npa_path == NULL)
		goto out;

	npa->npa_version = nvme_version(fd);
	if (npa->npa_version == NULL)
		goto out;

	npa->npa_idctl = nvme_identify_ctrl(fd);
	if (npa->npa_idctl == NULL)
		goto out;

	npa->npa_idns = nvme_identify_nsid(fd);
	if (npa->npa_idns == NULL)
		goto out;

	if (npa->npa_isns)
		npa->npa_dsk = nvme_dskname(npa);

	exitcode += npa->npa_cmd->c_func(fd, npa);

out:
	di_devfs_path_free(npa->npa_path);
	free(npa->npa_dsk);
	free(npa->npa_version);
	free(npa->npa_idctl);
	free(npa->npa_idns);

	npa->npa_version = NULL;
	npa->npa_idctl = NULL;
	npa->npa_idns = NULL;

	nvme_close(fd);

	return (DI_WALK_CONTINUE);
}

static void
nvme_walk(nvme_process_arg_t *npa, di_node_t node)
{
	char *minor_nodetype = DDI_NT_NVME_NEXUS;

	if (npa->npa_isns)
		minor_nodetype = DDI_NT_NVME_ATTACHMENT_POINT;

	(void) di_walk_minor(node, minor_nodetype, 0, npa, nvme_process);
}

static void
usage_list(const char *c_name)
{
	(void) fprintf(stderr, "%s [<ctl>[/<ns>][,...]\n\n"
	    "  List NVMe controllers and their namespaces. If no "
	    "controllers and/or name-\n  spaces are specified, all "
	    "controllers and namespaces in the system will be\n  "
	    "listed.\n", c_name);
}

static int
do_list_nsid(int fd, const nvme_process_arg_t *npa)
{
	_NOTE(ARGUNUSED(fd));

	(void) printf("  %s/%s (%s): ", npa->npa_name,
	    di_minor_name(npa->npa_minor),
	    npa->npa_dsk != NULL ? npa->npa_dsk : "unattached");
	nvme_print_nsid_summary(npa->npa_idns);

	return (0);
}

static int
do_list(int fd, const nvme_process_arg_t *npa)
{
	_NOTE(ARGUNUSED(fd));

	nvme_process_arg_t ns_npa = { 0 };
	nvmeadm_cmd_t cmd = { 0 };
	char *name;

	if (asprintf(&name, "%s%d", di_driver_name(npa->npa_node),
	    di_instance(npa->npa_node)) < 0)
		err(-1, "do_list()");

	(void) printf("%s: ", name);
	nvme_print_ctrl_summary(npa->npa_idctl, npa->npa_version);

	ns_npa.npa_name = name;
	ns_npa.npa_isns = B_TRUE;
	ns_npa.npa_nsid = npa->npa_nsid;
	cmd = *(npa->npa_cmd);
	cmd.c_func = do_list_nsid;
	ns_npa.npa_cmd = &cmd;

	nvme_walk(&ns_npa, npa->npa_node);

	free(name);

	return (exitcode);
}

static void
usage_identify(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>[/<ns>][,...]\n\n"
	    "  Print detailed information about the specified NVMe "
	    "controllers and/or name-\n  spaces.\n", c_name);
}

static int
do_identify(int fd, const nvme_process_arg_t *npa)
{
	if (npa->npa_nsid == 0) {
		nvme_capabilities_t *cap;

		cap = nvme_capabilities(fd);
		if (cap == NULL)
			return (-1);

		(void) printf("%s: ", npa->npa_name);
		nvme_print_identify_ctrl(npa->npa_idctl, cap,
		    npa->npa_version);

		free(cap);
	} else {
		(void) printf("%s/%s: ", npa->npa_name,
		    di_minor_name(npa->npa_minor));
		nvme_print_identify_nsid(npa->npa_idns,
		    npa->npa_version);
	}

	return (0);
}

static void
usage_get_logpage(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>[/<ns>][,...] <logpage>\n\n"
	    "  Print the specified log page of the specified NVMe "
	    "controllers and/or name-\n  spaces. Supported log pages "
	    "are error, health, and firmware.\n", c_name);
}

static int
do_get_logpage_error(int fd, const nvme_process_arg_t *npa)
{
	int nlog = npa->npa_idctl->id_elpe + 1;
	size_t bufsize = sizeof (nvme_error_log_entry_t) * nlog;
	nvme_error_log_entry_t *elog;

	if (npa->npa_nsid != 0)
		errx(-1, "Error Log not available on a per-namespace basis");

	elog = nvme_get_logpage(fd, NVME_LOGPAGE_ERROR, &bufsize);

	if (elog == NULL)
		return (-1);

	nlog = bufsize / sizeof (nvme_error_log_entry_t);

	(void) printf("%s: ", npa->npa_name);
	nvme_print_error_log(nlog, elog);

	free(elog);

	return (0);
}

static int
do_get_logpage_health(int fd, const nvme_process_arg_t *npa)
{
	size_t bufsize = sizeof (nvme_health_log_t);
	nvme_health_log_t *hlog;

	if (npa->npa_nsid != 0) {
		if (npa->npa_idctl->id_lpa.lp_smart == 0)
			errx(-1, "SMART/Health information not available "
			    "on a per-namespace basis on this controller");
	}

	hlog = nvme_get_logpage(fd, NVME_LOGPAGE_HEALTH, &bufsize);

	if (hlog == NULL)
		return (-1);

	(void) printf("%s: ", npa->npa_name);
	nvme_print_health_log(hlog, npa->npa_idctl);

	free(hlog);

	return (0);
}

static int
do_get_logpage_fwslot(int fd, const nvme_process_arg_t *npa)
{
	size_t bufsize = sizeof (nvme_fwslot_log_t);
	nvme_fwslot_log_t *fwlog;

	if (npa->npa_nsid != 0)
		errx(-1, "Firmware Slot information not available on a "
		    "per-namespace basis");

	fwlog = nvme_get_logpage(fd, NVME_LOGPAGE_FWSLOT, &bufsize);

	if (fwlog == NULL)
		return (-1);

	(void) printf("%s: ", npa->npa_name);
	nvme_print_fwslot_log(fwlog);

	free(fwlog);

	return (0);
}

static int
do_get_logpage(int fd, const nvme_process_arg_t *npa)
{
	int ret = 0;
	int (*func)(int, const nvme_process_arg_t *);

	if (npa->npa_argc < 1) {
		warnx("missing logpage name");
		usage(npa->npa_cmd);
		exit(-1);
	}

	if (strcmp(npa->npa_argv[0], "error") == 0)
		func = do_get_logpage_error;
	else if (strcmp(npa->npa_argv[0], "health") == 0)
		func = do_get_logpage_health;
	else if (strcmp(npa->npa_argv[0], "firmware") == 0)
		func = do_get_logpage_fwslot;
	else
		errx(-1, "invalid log page: %s", npa->npa_argv[0]);

	ret = func(fd, npa);
	return (ret);
}

static void
usage_get_features(const char *c_name)
{
	const nvme_feature_t *feat;

	(void) fprintf(stderr, "%s <ctl>[/<ns>][,...] [<feature>[,...]]\n\n"
	    "  Print the specified features of the specified NVMe controllers "
	    "and/or\n  namespaces. Supported features are:\n\n", c_name);
	(void) fprintf(stderr, "    %-35s %-14s %s\n",
	    "FEATURE NAME", "SHORT NAME", "CONTROLLER/NAMESPACE");
	for (feat = &features[0]; feat->f_feature != 0; feat++) {
		char *type;

		if ((feat->f_getflags & NVMEADM_BOTH) == NVMEADM_BOTH)
			type = "both";
		else if ((feat->f_getflags & NVMEADM_CTRL) != 0)
			type = "controller only";
		else
			type = "namespace only";

		(void) fprintf(stderr, "    %-35s %-14s %s\n",
		    feat->f_name, feat->f_short, type);
	}

}

static int
do_get_feat_common(int fd, const nvme_feature_t *feat,
    nvme_identify_ctrl_t *idctl)
{
	void *buf = NULL;
	size_t bufsize = feat->f_bufsize;
	uint64_t res;

	if (nvme_get_feature(fd, feat->f_feature, 0, &res, &bufsize, &buf)
	    == B_FALSE)
		return (EINVAL);

	nvme_print(2, feat->f_name, -1, NULL);
	feat->f_print(res, buf, bufsize, idctl);
	free(buf);

	return (0);
}

static int
do_get_feat_intr_vect(int fd, const nvme_feature_t *feat,
    nvme_identify_ctrl_t *idctl)
{
	uint64_t res;
	uint64_t arg;
	int intr_cnt;

	intr_cnt = nvme_intr_cnt(fd);

	if (intr_cnt == -1)
		return (EINVAL);

	nvme_print(2, feat->f_name, -1, NULL);

	for (arg = 0; arg < intr_cnt; arg++) {
		if (nvme_get_feature(fd, feat->f_feature, arg, &res, NULL, NULL)
		    == B_FALSE)
			return (EINVAL);

		feat->f_print(res, NULL, 0, idctl);
	}

	return (0);
}

static int
do_get_features(int fd, const nvme_process_arg_t *npa)
{
	const nvme_feature_t *feat;
	char *f, *flist, *lasts;
	boolean_t header_printed = B_FALSE;

	if (npa->npa_argc > 1)
		errx(-1, "unexpected arguments");

	/*
	 * No feature list given, print all supported features.
	 */
	if (npa->npa_argc == 0) {
		(void) printf("%s: Get Features\n", npa->npa_name);
		for (feat = &features[0]; feat->f_feature != 0; feat++) {
			if ((npa->npa_nsid != 0 &&
			    (feat->f_getflags & NVMEADM_NS) == 0) ||
			    (npa->npa_nsid == 0 &&
			    (feat->f_getflags & NVMEADM_CTRL) == 0))
				continue;

			(void) feat->f_get(fd, feat, npa->npa_idctl);
		}

		return (0);
	}

	/*
	 * Process feature list.
	 */
	flist = strdup(npa->npa_argv[0]);
	if (flist == NULL)
		err(-1, "do_get_features");

	for (f = strtok_r(flist, ",", &lasts);
	    f != NULL;
	    f = strtok_r(NULL, ",", &lasts)) {
		while (isspace(*f))
			f++;

		for (feat = &features[0]; feat->f_feature != 0; feat++) {
			if (strncasecmp(feat->f_name, f, strlen(f)) == 0 ||
			    strncasecmp(feat->f_short, f, strlen(f)) == 0)
				break;
		}

		if (feat->f_feature == 0) {
			warnx("unknown feature %s", f);
			continue;
		}

		if ((npa->npa_nsid != 0 &&
		    (feat->f_getflags & NVMEADM_NS) == 0) ||
		    (npa->npa_nsid == 0 &&
		    (feat->f_getflags & NVMEADM_CTRL) == 0)) {
			warnx("feature %s %s supported for namespaces",
			    feat->f_name, (feat->f_getflags & NVMEADM_NS) != 0 ?
			    "only" : "not");
			continue;
		}

		if (!header_printed) {
			(void) printf("%s: Get Features\n", npa->npa_name);
			header_printed = B_TRUE;
		}

		if (feat->f_get(fd, feat, npa->npa_idctl) != 0) {
			warnx("unsupported feature: %s", feat->f_name);
			continue;
		}
	}

	free(flist);
	return (0);
}

static int
do_format_common(int fd, const nvme_process_arg_t *npa, unsigned long lbaf,
    unsigned long ses)
{
	nvme_process_arg_t ns_npa = { 0 };
	nvmeadm_cmd_t cmd = { 0 };

	cmd = *(npa->npa_cmd);
	cmd.c_func = do_attach_detach;
	cmd.c_name = "detach";
	ns_npa = *npa;
	ns_npa.npa_cmd = &cmd;

	if (do_attach_detach(fd, &ns_npa) != 0)
		return (exitcode);
	if (nvme_format_nvm(fd, lbaf, ses) == B_FALSE) {
		warn("%s failed", npa->npa_cmd->c_name);
		exitcode += -1;
	}
	cmd.c_name = "attach";
	exitcode += do_attach_detach(fd, &ns_npa);

	return (exitcode);
}

static void
usage_format(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>[/<ns>] [<lba-format>]\n\n"
	    "  Format one or all namespaces of the specified NVMe "
	    "controller. Supported LBA\n  formats can be queried with "
	    "the \"%s identify\" command on the namespace\n  to be "
	    "formatted.\n", c_name, getprogname());
}

static int
do_format(int fd, const nvme_process_arg_t *npa)
{
	unsigned long lbaf;

	if (npa->npa_idctl->id_oacs.oa_format == 0)
		errx(-1, "%s not supported", npa->npa_cmd->c_name);

	if (npa->npa_isns && npa->npa_idctl->id_fna.fn_format != 0)
		errx(-1, "%s not supported on individual namespace",
		    npa->npa_cmd->c_name);


	if (npa->npa_argc > 0) {
		errno = 0;
		lbaf = strtoul(npa->npa_argv[0], NULL, 10);

		if (errno != 0 || lbaf > NVME_FRMT_MAX_LBAF)
			errx(-1, "invalid LBA format %d", lbaf + 1);

		if (npa->npa_idns->id_lbaf[lbaf].lbaf_ms != 0)
			errx(-1, "LBA formats with metadata not supported");
	} else {
		lbaf = npa->npa_idns->id_flbas.lba_format;
	}

	return (do_format_common(fd, npa, lbaf, 0));
}

static void
usage_secure_erase(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>[/<ns>] [-c]\n\n"
	    "  Secure-Erase one or all namespaces of the specified "
	    "NVMe controller.\n", c_name);
}

static int
do_secure_erase(int fd, const nvme_process_arg_t *npa)
{
	unsigned long lbaf;
	uint8_t ses = NVME_FRMT_SES_USER;

	if (npa->npa_idctl->id_oacs.oa_format == 0)
		errx(-1, "%s not supported", npa->npa_cmd->c_name);

	if (npa->npa_isns && npa->npa_idctl->id_fna.fn_sec_erase != 0)
		errx(-1, "%s not supported on individual namespace",
		    npa->npa_cmd->c_name);

	if (npa->npa_argc > 0) {
		if (strcmp(npa->npa_argv[0], "-c") == 0)
			ses = NVME_FRMT_SES_CRYPTO;
		else
			usage(npa->npa_cmd);
	}

	if (ses == NVME_FRMT_SES_CRYPTO &&
	    npa->npa_idctl->id_fna.fn_crypt_erase == 0)
		errx(-1, "cryptographic %s not supported",
		    npa->npa_cmd->c_name);

	lbaf = npa->npa_idns->id_flbas.lba_format;

	return (do_format_common(fd, npa, lbaf, ses));
}

static void
usage_attach_detach(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>[/<ns>]\n\n"
	    "  %c%s blkdev(7d) %s one or all namespaces of the "
	    "specified NVMe controller.\n",
	    c_name, toupper(c_name[0]), &c_name[1],
	    c_name[0] == 'd' ? "from" : "to");
}

static int
do_attach_detach(int fd, const nvme_process_arg_t *npa)
{
	char *c_name = npa->npa_cmd->c_name;

	if (!npa->npa_isns) {
		nvme_process_arg_t ns_npa = { 0 };

		ns_npa.npa_name = npa->npa_name;
		ns_npa.npa_isns = B_TRUE;
		ns_npa.npa_cmd = npa->npa_cmd;

		nvme_walk(&ns_npa, npa->npa_node);

		return (exitcode);
	} else {
		if ((c_name[0] == 'd' ? nvme_detach : nvme_attach)(fd)
		    == B_FALSE) {
			warn("%s failed", c_name);
			return (-1);
		}
	}

	return (0);
}
