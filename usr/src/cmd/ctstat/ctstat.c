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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/ctfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <libuutil.h>
#include <sys/contract/process.h>
#include <limits.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <dirent.h>

#include <locale.h>
#include <langinfo.h>

static int opt_verbose = 0;
static int opt_showall = 0;

/*
 * usage
 *
 * Educate the user.
 */
static void
usage(void)
{
	(void) fprintf(stderr, gettext("Usage: %s [-a] [-i ctidlist] "
	    "[-t typelist] [-v] [interval [count]]\n"), uu_getpname());
	exit(UU_EXIT_USAGE);
}

/*
 * mystrtoul
 *
 * Convert a string into an int in [0, INT_MAX].  Exit if the argument
 * doen't fit this description.
 */
static int
mystrtoul(const char *arg)
{
	unsigned int result;

	if (uu_strtoint(arg, &result, sizeof (result), 10, 0, INT_MAX) == -1) {
		uu_warn(gettext("invalid numerical argument \"%s\"\n"), arg);
		usage();
	}

	return (result);
}

/*
 * int_compar
 *
 * A simple integer comparator.  Also used for id_ts, since they're the
 * same thing.
 */
static int
int_compar(const void *a1, const void *a2)
{
	int id1 = *(int *)a1;
	int id2 = *(int *)a2;

	if (id1 > id2)
		return (1);
	if (id2 > id1)
		return (-1);
	return (0);
}

typedef struct optvect {
	const char	*option;
	uint_t		bit;
} optvect_t;

static optvect_t option_params[] = {
	{ "inherit", CT_PR_INHERIT },
	{ "noorphan", CT_PR_NOORPHAN },
	{ "pgrponly", CT_PR_PGRPONLY },
	{ "regent", CT_PR_REGENT },
	{ NULL }
};

static optvect_t option_events[] = {
	{ "core", CT_PR_EV_CORE },
	{ "signal", CT_PR_EV_SIGNAL },
	{ "hwerr", CT_PR_EV_HWERR },
	{ "empty", CT_PR_EV_EMPTY },
	{ "fork", CT_PR_EV_FORK },
	{ "exit", CT_PR_EV_EXIT },
	{ NULL }
};

/*
 * print_bits
 *
 * Display a set whose membership is identified by a bitfield.
 */
static void
print_bits(uint_t bits, optvect_t *desc)
{
	int i, printed = 0;

	for (i = 0; desc[i].option; i++)
		if (desc[i].bit & bits) {
			if (printed)
				(void) putchar(' ');
			printed = 1;
			(void) fputs(desc[i].option, stdout);
		}
	if (printed)
		(void) putchar('\n');
	else
		(void) puts("none");
}

/*
 * print_ids
 *
 * Display a list of ids, sorted.
 */
static void
print_ids(id_t *ids, uint_t nids)
{
	int i;
	int first = 1;

	qsort(ids, nids, sizeof (int), int_compar);

	for (i = 0; i < nids; i++) {
		/*LINTED*/
		(void) printf(" %d" + first, ids[i]);
		first = 0;
	}
	if (first)
		(void) puts("none");
	else
		(void) putchar('\n');
}

typedef void printfunc_t(ct_stathdl_t);

/*
 * A structure defining a displayed field.  Includes a label to be
 * printed along side the field value, and a function which extracts
 * the data from a status structure, formats it, and displays it on
 * stdout.
 */
typedef struct verbout {
	const char	*label;	/* field label */
	printfunc_t	*func;	/* field display function */
} verbout_t;

/*
 * verb_cookie
 *
 * Used to display an error encountered when reading a contract status
 * field.
 */
static void
verb_error(int err)
{
	(void) printf("(error: %s)\n", strerror(err));
}

/*
 * verb_cookie
 *
 * Display the contract's cookie.
 */
static void
verb_cookie(ct_stathdl_t hdl)
{
	(void) printf("%#llx\n", ct_status_get_cookie(hdl));
}

/*
 * verb_info
 *
 * Display the parameters in the parameter set.
 */
static void
verb_param(ct_stathdl_t hdl)
{
	uint_t param;
	int err;

	if (err = ct_pr_status_get_param(hdl, &param))
		verb_error(err);
	else
		print_bits(param, option_params);
}

/*
 * verb_info
 *
 * Display the events in the informative event set.
 */
static void
verb_info(ct_stathdl_t hdl)
{
	print_bits(ct_status_get_informative(hdl), option_events);
}

/*
 * verb_crit
 *
 * Display the events in the critical event set.
 */
static void
verb_crit(ct_stathdl_t hdl)
{
	print_bits(ct_status_get_critical(hdl), option_events);
}

/*
 * verb_fatal
 *
 * Display the events in the fatal event set.
 */
static void
verb_fatal(ct_stathdl_t hdl)
{
	uint_t event;
	int err;

	if (err = ct_pr_status_get_fatal(hdl, &event))
		verb_error(err);
	else
		print_bits(event, option_events);
}

/*
 * verb_members
 *
 * Display the list of member contracts.
 */
static void
verb_members(ct_stathdl_t hdl)
{
	pid_t *pids;
	uint_t npids;
	int err;

	if (err = ct_pr_status_get_members(hdl, &pids, &npids)) {
		verb_error(err);
		return;
	}

	print_ids(pids, npids);
}

/*
 * verb_inherit
 *
 * Display the list of inherited contracts.
 */
static void
verb_inherit(ct_stathdl_t hdl)
{
	ctid_t *ctids;
	uint_t nctids;
	int err;

	if (err = ct_pr_status_get_contracts(hdl, &ctids, &nctids))
		verb_error(err);
	else
		print_ids(ctids, nctids);
}

/*
 * verb_svc_fmri
 *
 * Display the process contract service fmri
 */
static void
verb_svc_fmri(ct_stathdl_t hdl)
{
	char *svc_fmri;
	int err;
	if (err = ct_pr_status_get_svc_fmri(hdl, &svc_fmri))
		verb_error(err);
	else
		(void) printf("%s\n", svc_fmri);
}

/*
 * verb_svc_aux
 *
 * Display the process contract service fmri auxiliar
 */
static void
verb_svc_aux(ct_stathdl_t hdl)
{
	char *svc_aux;
	int err;
	if (err = ct_pr_status_get_svc_aux(hdl, &svc_aux))
		verb_error(err);
	else
		(void) printf("%s\n", svc_aux);
}

/*
 * verb_svc_ctid
 *
 * Display the process contract service fmri ctid
 */
static void
verb_svc_ctid(ct_stathdl_t hdl)
{
	ctid_t svc_ctid;
	int err;
	if (err = ct_pr_status_get_svc_ctid(hdl, &svc_ctid))
		verb_error(err);
	else
		(void) printf("%ld\n", svc_ctid);
}

/*
 * verb_svc_creator
 *
 * Display the process contract creator's execname
 */
static void
verb_svc_creator(ct_stathdl_t hdl)
{
	char *svc_creator;
	int err;
	if (err = ct_pr_status_get_svc_creator(hdl, &svc_creator))
		verb_error(err);
	else
		(void) printf("%s\n", svc_creator);
}

/*
 * Common contract status fields.
 */
static verbout_t vcommon[] = {
	"cookie", verb_cookie,
	NULL,
};

/*
 * Process contract-specific status fields.
 * The critical and informative event sets are here because the event
 * names are contract-specific.  They are listed first, however, so
 * they are displayed adjacent to the "normal" common output.
 */
static verbout_t vprocess[] = {
	"informative event set", verb_info,
	"critical event set", verb_crit,
	"fatal event set", verb_fatal,
	"parameter set", verb_param,
	"member processes", verb_members,
	"inherited contracts", verb_inherit,
	"service fmri", verb_svc_fmri,
	"service fmri ctid", verb_svc_ctid,
	"creator", verb_svc_creator,
	"aux", verb_svc_aux,
	NULL
};

/*
 * print_verbose
 *
 * Displays a contract's verbose status, common fields first.
 */
static void
print_verbose(ct_stathdl_t hdl, verbout_t *spec, verbout_t *common)
{
	int i;
	int tmp, maxwidth = 0;

	/*
	 * Compute the width of all the fields.
	 */
	for (i = 0; common[i].label; i++)
		if ((tmp = strlen(common[i].label)) > maxwidth)
			maxwidth = tmp;
	if (spec)
		for (i = 0; spec[i].label; i++)
			if ((tmp = strlen(spec[i].label)) > maxwidth)
				maxwidth = tmp;
	maxwidth += 2;

	/*
	 * Display the data.
	 */
	for (i = 0; common[i].label; i++) {
		tmp = printf("\t%s", common[i].label);
		if (tmp < 0)
			tmp = 0;
		(void) printf("%-*s", maxwidth - tmp + 1, ":");
		common[i].func(hdl);
	}
	if (spec)
		for (i = 0; spec[i].label; i++) {
			(void) printf("\t%s%n", spec[i].label, &tmp);
			(void) printf("%-*s", maxwidth - tmp + 1, ":");
			spec[i].func(hdl);
		}
}

struct {
	const char *name;
	verbout_t *verbout;
} cttypes[] = {
	{ "process", vprocess },
	{ NULL }
};

/*
 * get_type
 *
 * Given a type name, return an index into the above array of types.
 */
static int
get_type(const char *typestr)
{
	int i;
	for (i = 0; cttypes[i].name; i++)
		if (strcmp(cttypes[i].name, typestr) == 0)
			return (i);
	uu_die(gettext("invalid contract type: %s\n"), typestr);
	/* NOTREACHED */
}

/*
 * print_header
 *
 * Display the status header.
 */
static void
print_header(void)
{
	(void) printf("%-8s%-8s%-8s%-8s%-8s%-8s%-8s%-8s\n", "CTID", "ZONEID",
	    "TYPE", "STATE", "HOLDER", "EVENTS", "QTIME", "NTIME");
}

/*
 * print_contract
 *
 * Display status for contract ID 'id' from type directory 'dir'.  If
 * only contracts of a specific set of types should be displayed,
 * 'types' will be a sorted list of type indices of length 'ntypes'.
 */
static void
print_contract(const char *dir, ctid_t id, verbout_t *spec,
    int *types, int ntypes)
{
	ct_stathdl_t status;
	char hstr[100], qstr[20], nstr[20];
	ctstate_t state;
	int fd = 0;
	int t;

	/*
	 * Open and obtain status.
	 */
	if ((fd = contract_open(id, dir, "status", O_RDONLY)) == -1) {
		if (errno == ENOENT)
			return;
		uu_die(gettext("could not open contract status file"));
	}

	if (errno = ct_status_read(fd, opt_verbose ? CTD_ALL : CTD_COMMON,
	    &status))
		uu_die(gettext("failed to get contract status for %d"), id);
	(void) close(fd);

	/*
	 * Unless otherwise directed, don't display dead contracts.
	 */
	state = ct_status_get_state(status);
	if (!opt_showall && state == CTS_DEAD) {
		ct_status_free(status);
		return;
	}

	/*
	 * If we are only allowed to display certain contract types,
	 * perform that filtering here.  We stash a copy of spec so we
	 * don't have to recompute it later.
	 */
	if (types) {
		int key = get_type(ct_status_get_type(status));
		spec = cttypes[key].verbout;
		if (bsearch(&key, types, ntypes, sizeof (int), int_compar) ==
		    NULL) {
			ct_status_free(status);
			return;
		}
	}

	/*
	 * Precompute those fields which have both textual and
	 * numerical values.
	 */
	if ((state == CTS_OWNED) || (state == CTS_INHERITED))
		(void) snprintf(hstr, sizeof (hstr), "%ld",
		    ct_status_get_holder(status));
	else
		(void) snprintf(hstr, sizeof (hstr), "%s", "-");

	if ((t = ct_status_get_qtime(status)) == -1) {
		qstr[0] = nstr[0] = '-';
		qstr[1] = nstr[1] = '\0';
	} else {
		(void) snprintf(qstr, sizeof (qstr), "%d", t);
		(void) snprintf(nstr, sizeof (nstr), "%d",
		    ct_status_get_ntime(status));
	}

	/*
	 * Emit the contract's status.
	 */
	(void) printf("%-7ld %-7ld %-7s %-7s %-7s %-7d %-7s %-8s\n",
	    ct_status_get_id(status),
	    ct_status_get_zoneid(status),
	    ct_status_get_type(status),
	    (state == CTS_OWNED) ? "owned" :
	    (state == CTS_INHERITED) ? "inherit" :
	    (state == CTS_ORPHAN) ? "orphan" : "dead", hstr,
	    ct_status_get_nevents(status), qstr, nstr);

	/*
	 * Emit verbose status information, if requested.  If we
	 * weren't provided a verbose output spec or didn't compute it
	 * earlier, do it now.
	 */
	if (opt_verbose) {
		if (spec == NULL)
			spec = cttypes[get_type(ct_status_get_type(status))].
			    verbout;
		print_verbose(status, spec, vcommon);
	}

	ct_status_free(status);
}

/*
 * scan_type
 *
 * Display all contracts of the requested type.
 */
static void
scan_type(int typeno)
{
	DIR *dir;
	struct dirent64 *de;
	char path[PATH_MAX];

	verbout_t *vo = cttypes[typeno].verbout;
	const char *type = cttypes[typeno].name;

	if (snprintf(path, PATH_MAX, CTFS_ROOT "/%s", type) >= PATH_MAX ||
	    (dir = opendir(path)) == NULL)
		uu_die(gettext("bad contract type: %s\n"), type);
	while ((de = readdir64(dir)) != NULL) {
		/*
		 * Eliminate special files (e.g. '.', '..').
		 */
		if (de->d_name[0] < '0' || de->d_name[0] > '9')
			continue;
		print_contract(type, mystrtoul(de->d_name), vo, NULL, 0);
	}
	(void) closedir(dir);
}

/*
 * scan_ids
 *
 * Display all contracts with the requested IDs.
 */
static void
scan_ids(ctid_t *ids, int nids)
{
	int i;
	for (i = 0; i < nids; i++)
		print_contract("all", ids[i], NULL, NULL, 0);
}

/*
 * scan_all
 *
 * Display the union of the requested IDs and types.  So that the
 * output is sorted by contract ID, it takes the slow road by testing
 * each entry in /system/contract/all against its criteria.  Used when
 * the number of types is greater than 1, when we have a mixture of
 * types and ids, or no lists were provided at all.
 */
static void
scan_all(int *types, int ntypes, ctid_t *ids, int nids)
{
	DIR *dir;
	struct dirent64 *de;
	const char *path = CTFS_ROOT "/all";
	int key, test;

	if ((dir = opendir(path)) == NULL)
		uu_die(gettext("could not open %s"), path);
	while ((de = readdir64(dir)) != NULL) {
		/*
		 * Eliminate special files (e.g. '.', '..').
		 */
		if (de->d_name[0] < '0' || de->d_name[0] > '9')
			continue;
		key = mystrtoul(de->d_name);

		/*
		 * If we are given IDs to look at and this contract
		 * isn't in the ID list, or if we weren't given a list
		 * if IDs but were given a list of types, provide the
		 * list of acceptable types to print_contract.
		 */
		test = nids ? (bsearch(&key, ids, nids, sizeof (int),
		    int_compar) == NULL) : (ntypes != 0);
		print_contract("all", key, NULL, (test ? types : NULL), ntypes);
	}
	(void) closedir(dir);
}

/*
 * walk_args
 *
 * Apply fp to each token in the comma- or space- separated argument
 * string str and store the results in the array starting at results.
 */
static int
walk_args(const char *str, int (*fp)(const char *), int *results)
{
	char *copy, *token;
	int count = 0;

	if ((copy = strdup(str)) == NULL)
		uu_die(gettext("strdup() failed"));

	token = strtok(copy, ", ");
	if (token == NULL) {
		free(copy);
		return (0);
	}

	do {
		if (fp)
			*(results++) = fp(token);
		count++;
	} while (token = strtok(NULL, ", "));
	free(copy);

	return (count);
}

/*
 * parse
 *
 * Parse the comma- or space- separated string str, using fp to covert
 * the tokens to integers.  Append the list of integers to the array
 * pointed to by *idps, growing the array if necessary.
 */
static int
parse(const char *str, int **idsp, int nids, int (*fp)(const char *fp))
{
	int count;
	int *array;

	count = walk_args(str, NULL, NULL);
	if (count == 0)
		return (0);

	if ((array = calloc(nids + count, sizeof (int))) == NULL)
		uu_die(gettext("calloc() failed"));

	if (*idsp) {
		(void) memcpy(array, *idsp, nids * sizeof (int));
		free(*idsp);
	}

	(void) walk_args(str, fp, array + nids);

	*idsp = array;
	return (count + nids);
}

/*
 * parse_ids
 *
 * Extract a list of ids from the comma- or space- separated string str
 * and append them to the array *idsp, growing it if necessary.
 */
static int
parse_ids(const char *arg, int **idsp, int nids)
{
	return (parse(arg, idsp, nids, mystrtoul));
}

/*
 * parse_types
 *
 * Extract a list of types from the comma- or space- separated string
 * str and append them to the array *idsp, growing it if necessary.
 */
static int
parse_types(const char *arg, int **typesp, int ntypes)
{
	return (parse(arg, typesp, ntypes, get_type));
}

/*
 * compact
 *
 * Sorts and removes duplicates from array.  Initial size of array is
 * in *size; final size is stored in *size.
 */
static void
compact(int *array, int *size)
{
	int i, j, last = -1;

	qsort(array, *size, sizeof (int), int_compar);
	for (i = j = 0; i < *size; i++) {
		if (array[i] != last) {
			last = array[i];
			array[j++] = array[i];
		}
	}
	*size = j;
}

int
main(int argc, char **argv)
{
	unsigned int interval = 0, count = 1;
	ctid_t	*ids = NULL;
	int	*types = NULL;
	int	nids = 0, ntypes = 0;
	int	i, s;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	(void) uu_setpname(argv[0]);

	while ((s = getopt(argc, argv, "ai:t:v")) != EOF) {
		switch (s) {
		case 'a':
			opt_showall = 1;
			break;
		case 'i':
			nids = parse_ids(optarg, (int **)&ids, nids);
			break;
		case 't':
			ntypes = parse_types(optarg, &types, ntypes);
			break;
		case 'v':
			opt_verbose = 1;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc > 2 || argc < 0)
		usage();

	if (argc > 0) {
		interval = mystrtoul(argv[0]);
		count = 0;
	}

	if (argc > 1) {
		count = mystrtoul(argv[1]);
		if (count == 0)
			return (0);
	}

	if (nids)
		compact((int *)ids, &nids);
	if (ntypes)
		compact(types, &ntypes);

	for (i = 0; count == 0 || i < count; i++) {
		if (i)
			(void) sleep(interval);
		print_header();
		if (nids && ntypes)
			scan_all(types, ntypes, ids, nids);
		else if (ntypes == 1)
			scan_type(*types);
		else if (nids)
			scan_ids(ids, nids);
		else
			scan_all(types, ntypes, ids, nids);
	}

	return (0);
}
