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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011, Joyent, Inc. All rights reserved.
 * Copyright (c) 2015, 2016 by Delphix. All rights reserved.
 */

/*
 * svcs - display attributes of service instances
 *
 * We have two output formats and six instance selection mechanisms.  The
 * primary output format is a line of attributes (selected by -o), possibly
 * followed by process description lines (if -p is specified), for each
 * instance selected.  The columns available to display are described by the
 * struct column columns array.  The columns to actually display are kept in
 * the opt_columns array as indicies into the columns array.  The selection
 * mechanisms available for this format are service FMRIs (selects all child
 * instances), instance FMRIs, instance FMRI glob patterns, instances with
 * a certain restarter (-R), dependencies of instances (-d), and dependents of
 * instances (-D).  Since the lines must be sorted (per -sS), we'll just stick
 * each into a data structure and print them in order when we're done.  To
 * avoid listing the same instance twice (when -d and -D aren't given), we'll
 * use a hash table of FMRIs to record that we've listed (added to the tree)
 * an instance.
 *
 * The secondary output format (-l "long") is a paragraph of text for the
 * services or instances selected.  Not needing to be sorted, it's implemented
 * by just calling print_detailed() for each FMRI given.
 */

#include "svcs.h"
#include "notify_params.h"

/* Get the byteorder macros to ease sorting. */
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#include <sys/contract.h>
#include <sys/ctfs.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <libintl.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <libnvpair.h>
#include <locale.h>
#include <procfs.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <libzonecfg.h>
#include <zone.h>

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

#define	LEGACY_UNKNOWN	"unknown"

/* Flags for pg_get_single_val() */
#define	EMPTY_OK	0x01
#define	MULTI_OK	0x02


/*
 * An AVL-storable node for output lines and the keys to sort them by.
 */
struct avl_string {
	uu_avl_node_t	node;
	char		*key;
	char		*str;
};

/*
 * For lists of parsed restarter FMRIs.
 */
struct pfmri_list {
	const char		*scope;
	const char		*service;
	const char		*instance;
	struct pfmri_list	*next;
};


/*
 * Globals
 */
scf_handle_t *h;
static scf_propertygroup_t *g_pg;
static scf_property_t *g_prop;
static scf_value_t *g_val;

static size_t line_sz;			/* Bytes in the header line. */
static size_t sortkey_sz;		/* Bytes in sort keys. */
static uu_avl_pool_t *lines_pool;
static uu_avl_t *lines;			/* Output lines. */
int exit_status;
ssize_t max_scf_name_length;
ssize_t max_scf_value_length;
ssize_t max_scf_fmri_length;
static ssize_t max_scf_type_length;
static time_t now;
static struct pfmri_list *restarters = NULL;
static int first_paragraph = 1;		/* For -l mode. */
static char *common_name_buf;		/* Sized for maximal length value. */
char *locale;				/* Current locale. */
char *g_zonename;			/* zone being operated upon */

/*
 * Pathname storage for path generated from the fmri.
 * Used for reading the ctid and (start) pid files for an inetd service.
 */
static char genfmri_filename[MAXPATHLEN] = "";

/* Options */
static int *opt_columns = NULL;		/* Indices into columns to display. */
static int opt_cnum = 0;
static int opt_processes = 0;		/* Print processes? */
static int *opt_sort = NULL;		/* Indices into columns to sort. */
static int opt_snum = 0;
static int opt_nstate_shown = 0;	/* Will nstate be shown? */
static int opt_verbose = 0;
static char *opt_zone;			/* zone selected, if any */

/* Minimize string constants. */
static const char * const scf_property_state = SCF_PROPERTY_STATE;
static const char * const scf_property_next_state = SCF_PROPERTY_NEXT_STATE;
static const char * const scf_property_contract = SCF_PROPERTY_CONTRACT;


/*
 * Utility functions
 */

/*
 * For unexpected libscf errors.  The ending newline is necessary to keep
 * uu_die() from appending the errno error.
 */
#ifndef NDEBUG
void
do_scfdie(const char *file, int line)
{
	uu_die(gettext("%s:%d: Unexpected libscf error: %s.  Exiting.\n"),
	    file, line, scf_strerror(scf_error()));
}
#else
void
scfdie(void)
{
	uu_die(gettext("Unexpected libscf error: %s.  Exiting.\n"),
	    scf_strerror(scf_error()));
}
#endif

void *
safe_malloc(size_t sz)
{
	void *ptr;

	ptr = malloc(sz);
	if (ptr == NULL)
		uu_die(gettext("Out of memory"));

	return (ptr);
}

char *
safe_strdup(const char *str)
{
	char *cp;

	cp = strdup(str);
	if (cp == NULL)
		uu_die(gettext("Out of memory.\n"));

	return (cp);
}

/*
 * FMRI hashtable.  For uniquifing listings.
 */

struct ht_elem {
	const char	*fmri;
	struct ht_elem	*next;
};

static struct ht_elem	**ht_buckets = NULL;
static uint_t		ht_buckets_num = 0;
static uint_t		ht_num;

static void
ht_free(void)
{
	struct ht_elem *elem, *next;
	int i;

	for (i = 0; i < ht_buckets_num; i++) {
		for (elem = ht_buckets[i]; elem != NULL; elem = next) {
			next = elem->next;
			free((char *)elem->fmri);
			free(elem);
		}
	}

	free(ht_buckets);
	ht_buckets_num = 0;
	ht_buckets = NULL;
}

static void
ht_init(void)
{
	assert(ht_buckets == NULL);

	ht_buckets_num = 8;
	ht_buckets = safe_malloc(sizeof (*ht_buckets) * ht_buckets_num);
	bzero(ht_buckets, sizeof (*ht_buckets) * ht_buckets_num);
	ht_num = 0;
}

static uint_t
ht_hash_fmri(const char *fmri)
{
	uint_t h = 0, g;
	const char *p, *k;

	/* All FMRIs begin with svc:/, so skip that part. */
	assert(strncmp(fmri, "svc:/", sizeof ("svc:/") - 1) == 0);
	k = fmri + sizeof ("svc:/") - 1;

	/*
	 * Generic hash function from uts/common/os/modhash.c.
	 */
	for (p = k; *p != '\0'; ++p) {
		h = (h << 4) + *p;
		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

static void
ht_grow()
{
	uint_t new_ht_buckets_num;
	struct ht_elem **new_ht_buckets;
	int i;

	new_ht_buckets_num = ht_buckets_num * 2;
	assert(new_ht_buckets_num > ht_buckets_num);
	new_ht_buckets =
	    safe_malloc(sizeof (*new_ht_buckets) * new_ht_buckets_num);
	bzero(new_ht_buckets, sizeof (*new_ht_buckets) * new_ht_buckets_num);

	for (i = 0; i < ht_buckets_num; ++i) {
		struct ht_elem *elem, *next;

		for (elem = ht_buckets[i]; elem != NULL; elem = next) {
			uint_t h;

			next = elem->next;

			h = ht_hash_fmri(elem->fmri);

			elem->next =
			    new_ht_buckets[h & (new_ht_buckets_num - 1)];
			new_ht_buckets[h & (new_ht_buckets_num - 1)] = elem;
		}
	}

	free(ht_buckets);

	ht_buckets = new_ht_buckets;
	ht_buckets_num = new_ht_buckets_num;
}

/*
 * Add an FMRI to the hash table.  Returns 1 if it was already there,
 * 0 otherwise.
 */
static int
ht_add(const char *fmri)
{
	uint_t h;
	struct ht_elem *elem;

	h = ht_hash_fmri(fmri);

	elem = ht_buckets[h & (ht_buckets_num - 1)];

	for (; elem != NULL; elem = elem->next) {
		if (strcmp(elem->fmri, fmri) == 0)
			return (1);
	}

	/* Grow when average chain length is over 3. */
	if (ht_num > 3 * ht_buckets_num)
		ht_grow();

	++ht_num;

	elem = safe_malloc(sizeof (*elem));
	elem->fmri = strdup(fmri);
	elem->next = ht_buckets[h & (ht_buckets_num - 1)];
	ht_buckets[h & (ht_buckets_num - 1)] = elem;

	return (0);
}



/*
 * Convenience libscf wrapper functions.
 */

/*
 * Get the single value of the named property in the given property group,
 * which must have type ty, and put it in *vp.  If ty is SCF_TYPE_ASTRING, vp
 * is taken to be a char **, and sz is the size of the buffer.  sz is unused
 * otherwise.  Return 0 on success, -1 if the property doesn't exist, has the
 * wrong type, or doesn't have a single value.  If flags has EMPTY_OK, don't
 * complain if the property has no values (but return nonzero).  If flags has
 * MULTI_OK and the property has multiple values, succeed with E2BIG.
 */
int
pg_get_single_val(scf_propertygroup_t *pg, const char *propname, scf_type_t ty,
    void *vp, size_t sz, uint_t flags)
{
	char *buf, root[MAXPATHLEN];
	size_t buf_sz;
	int ret = -1, r;
	boolean_t multi = B_FALSE;

	assert((flags & ~(EMPTY_OK | MULTI_OK)) == 0);

	if (scf_pg_get_property(pg, propname, g_prop) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		goto out;
	}

	if (scf_property_is_type(g_prop, ty) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_TYPE_MISMATCH)
			goto misconfigured;
		scfdie();
	}

	if (scf_property_get_value(g_prop, g_val) != SCF_SUCCESS) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			if (flags & EMPTY_OK)
				goto out;
			goto misconfigured;

		case SCF_ERROR_CONSTRAINT_VIOLATED:
			if (flags & MULTI_OK) {
				multi = B_TRUE;
				break;
			}
			goto misconfigured;

		case SCF_ERROR_PERMISSION_DENIED:
		default:
			scfdie();
		}
	}

	switch (ty) {
	case SCF_TYPE_ASTRING:
		r = scf_value_get_astring(g_val, vp, sz) > 0 ? SCF_SUCCESS : -1;
		break;

	case SCF_TYPE_BOOLEAN:
		r = scf_value_get_boolean(g_val, (uint8_t *)vp);
		break;

	case SCF_TYPE_COUNT:
		r = scf_value_get_count(g_val, (uint64_t *)vp);
		break;

	case SCF_TYPE_INTEGER:
		r = scf_value_get_integer(g_val, (int64_t *)vp);
		break;

	case SCF_TYPE_TIME: {
		int64_t sec;
		int32_t ns;
		r = scf_value_get_time(g_val, &sec, &ns);
		((struct timeval *)vp)->tv_sec = sec;
		((struct timeval *)vp)->tv_usec = ns / 1000;
		break;
	}

	case SCF_TYPE_USTRING:
		r = scf_value_get_ustring(g_val, vp, sz) > 0 ? SCF_SUCCESS : -1;
		break;

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Unknown type %d.\n", __FILE__, __LINE__, ty);
#endif
		abort();
	}
	if (r != SCF_SUCCESS)
		scfdie();

	ret = multi ? E2BIG : 0;
	goto out;

misconfigured:
	buf_sz = max_scf_fmri_length + 1;
	buf = safe_malloc(buf_sz);
	if (scf_property_to_fmri(g_prop, buf, buf_sz) == -1)
		scfdie();

	uu_warn(gettext("Property \"%s\" is misconfigured.\n"), buf);

	free(buf);

out:
	if (ret != 0 || g_zonename == NULL ||
	    (strcmp(propname, SCF_PROPERTY_LOGFILE) != 0 &&
	    strcmp(propname, SCF_PROPERTY_ALT_LOGFILE) != 0))
		return (ret);

	/*
	 * If we're here, we have a log file and we have specified a zone.
	 * As a convenience, we're going to prepend the zone path to the
	 * name of the log file.
	 */
	root[0] = '\0';
	(void) zone_get_rootpath(g_zonename, root, sizeof (root));
	(void) strlcat(root, vp, sizeof (root));
	(void) snprintf(vp, sz, "%s", root);

	return (ret);
}

static scf_snapshot_t *
get_running_snapshot(scf_instance_t *inst)
{
	scf_snapshot_t *snap;

	snap = scf_snapshot_create(h);
	if (snap == NULL)
		scfdie();

	if (scf_instance_get_snapshot(inst, "running", snap) == 0)
		return (snap);

	if (scf_error() != SCF_ERROR_NOT_FOUND)
		scfdie();

	scf_snapshot_destroy(snap);
	return (NULL);
}

/*
 * As pg_get_single_val(), except look the property group up in an
 * instance.  If "use_running" is set, and the running snapshot exists,
 * do a composed lookup there.  Otherwise, do an (optionally composed)
 * lookup on the current values.  Note that lookups using snapshots are
 * always composed.
 */
int
inst_get_single_val(scf_instance_t *inst, const char *pgname,
    const char *propname, scf_type_t ty, void *vp, size_t sz, uint_t flags,
    int use_running, int composed)
{
	scf_snapshot_t *snap = NULL;
	int r;

	if (use_running)
		snap = get_running_snapshot(inst);
	if (composed || use_running)
		r = scf_instance_get_pg_composed(inst, snap, pgname, g_pg);
	else
		r = scf_instance_get_pg(inst, pgname, g_pg);
	if (snap)
		scf_snapshot_destroy(snap);
	if (r == -1)
		return (-1);

	r = pg_get_single_val(g_pg, propname, ty, vp, sz, flags);

	return (r);
}

static int
instance_enabled(scf_instance_t *inst, boolean_t temp)
{
	uint8_t b;

	if (inst_get_single_val(inst,
	    temp ? SCF_PG_GENERAL_OVR : SCF_PG_GENERAL, SCF_PROPERTY_ENABLED,
	    SCF_TYPE_BOOLEAN, &b, 0, 0, 0, 0) != 0)
		return (-1);

	return (b ? 1 : 0);
}

/*
 * Get a string property from the restarter property group of the given
 * instance.  Return an empty string on normal problems.
 */
static void
get_restarter_string_prop(scf_instance_t *inst, const char *pname,
    char *buf, size_t buf_sz)
{
	if (inst_get_single_val(inst, SCF_PG_RESTARTER, pname,
	    SCF_TYPE_ASTRING, buf, buf_sz, 0, 0, 1) != 0)
		*buf = '\0';
}

static int
get_restarter_time_prop(scf_instance_t *inst, const char *pname,
    struct timeval *tvp, int ok_if_empty)
{
	int r;

	r = inst_get_single_val(inst, SCF_PG_RESTARTER, pname, SCF_TYPE_TIME,
	    tvp, NULL, ok_if_empty ? EMPTY_OK : 0, 0, 1);

	return (r == 0 ? 0 : -1);
}

static int
get_restarter_count_prop(scf_instance_t *inst, const char *pname, uint64_t *cp,
    uint_t flags)
{
	return (inst_get_single_val(inst, SCF_PG_RESTARTER, pname,
	    SCF_TYPE_COUNT, cp, 0, flags, 0, 1));
}


/*
 * Generic functions
 */

/*
 * Return an array of pids associated with the given contract id.
 * Returned pids are added to the end of the pidsp array.
 */
static void
ctid_to_pids(uint64_t c, pid_t **pidsp, uint_t *np)
{
	ct_stathdl_t ctst;
	uint_t m;
	int fd;
	int r, err;
	pid_t *pids;

	fd = contract_open(c, NULL, "status", O_RDONLY);
	if (fd < 0)
		return;

	err = ct_status_read(fd, CTD_ALL, &ctst);
	if (err != 0) {
		uu_warn(gettext("Could not read status of contract "
		    "%ld: %s.\n"), c, strerror(err));
		(void) close(fd);
		return;
	}

	(void) close(fd);

	r = ct_pr_status_get_members(ctst, &pids, &m);
	assert(r == 0);

	if (m == 0) {
		ct_status_free(ctst);
		return;
	}

	*pidsp = realloc(*pidsp, (*np + m) * sizeof (*pidsp));
	if (*pidsp == NULL)
		uu_die(gettext("Out of memory"));

	bcopy(pids, *pidsp + *np, m * sizeof (*pids));
	*np += m;

	ct_status_free(ctst);
}

static int
propvals_to_pids(scf_propertygroup_t *pg, const char *pname, pid_t **pidsp,
    uint_t *np, scf_property_t *prop, scf_value_t *val, scf_iter_t *iter)
{
	scf_type_t ty;
	uint64_t c;
	int r;

	if (scf_pg_get_property(pg, pname, prop) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		return (ENOENT);
	}

	if (scf_property_type(prop, &ty) != 0)
		scfdie();

	if (ty != SCF_TYPE_COUNT)
		return (EINVAL);

	if (scf_iter_property_values(iter, prop) != 0)
		scfdie();

	for (;;) {
		r = scf_iter_next_value(iter, val);
		if (r == -1)
			scfdie();
		if (r == 0)
			break;

		if (scf_value_get_count(val, &c) != 0)
			scfdie();

		ctid_to_pids(c, pidsp, np);
	}

	return (0);
}

/*
 * Check if instance has general/restarter property that matches
 * given string.  Restarter string must be in canonified form.
 * Returns 0 for success; -1 otherwise.
 */
static int
check_for_restarter(scf_instance_t *inst, const char *restarter)
{
	char	*fmri_buf;
	char	*fmri_buf_canonified = NULL;
	int	ret = -1;

	if (inst == NULL)
		return (-1);

	/* Get restarter */
	fmri_buf = safe_malloc(max_scf_fmri_length + 1);
	if (inst_get_single_val(inst, SCF_PG_GENERAL,
	    SCF_PROPERTY_RESTARTER, SCF_TYPE_ASTRING, fmri_buf,
	    max_scf_fmri_length + 1, 0, 0, 1) != 0)
		goto out;

	fmri_buf_canonified = safe_malloc(max_scf_fmri_length + 1);
	if (scf_canonify_fmri(fmri_buf, fmri_buf_canonified,
	    (max_scf_fmri_length + 1)) < 0)
		goto out;

	if (strcmp(fmri_buf, restarter) == 0)
		ret = 0;

out:
	free(fmri_buf);
	if (fmri_buf_canonified)
		free(fmri_buf_canonified);
	return (ret);
}

/*
 * Common code that is used by ctids_by_restarter and pids_by_restarter.
 * Checks for a common restarter and if one is available, it generates
 * the appropriate filename using wip->fmri and stores that in the
 * global genfmri_filename.
 *
 * Restarters currently supported are: svc:/network/inetd:default
 * If a restarter specific action is available, then restarter_spec
 * is set to 1.  If a restarter specific action is not available, then
 * restarter_spec is set to 0 and a -1 is returned.
 *
 * Returns:
 * 0 if success: restarter specific action found and filename generated
 * -1 if restarter specific action not found,
 *    if restarter specific action found but an error was encountered
 *    during the generation of the wip->fmri based filename
 */
static int
common_by_restarter(scf_instance_t *inst, const char *fmri,
    int *restarter_specp)
{
	int		ret = -1;
	int		r;

	/* Check for inetd specific restarter */
	if (check_for_restarter(inst, "svc:/network/inetd:default") != 0) {
		*restarter_specp = 0;
		return (ret);
	}

	*restarter_specp = 1;

	/* Get the ctid filename associated with this instance */
	r = gen_filenms_from_fmri(fmri, "ctid", genfmri_filename, NULL);

	switch (r) {
	case 0:
		break;

	case -1:
		/*
		 * Unable to get filename from fmri.  Print warning
		 * and return failure with no ctids.
		 */
		uu_warn(gettext("Unable to read contract ids for %s -- "
		    "FMRI is too long\n"), fmri);
		return (ret);

	case -2:
		/*
		 * The directory didn't exist, so no contracts.
		 * Return failure with no ctids.
		 */
		return (ret);

	default:
		uu_warn(gettext("%s:%d: gen_filenms_from_fmri() failed with "
		    "unknown error %d\n"), __FILE__, __LINE__, r);
		abort();
	}

	return (0);

}

/*
 * Get or print a contract id using a restarter specific action.
 *
 * If the print_flag is not set, this routine gets the single contract
 * id associated with this instance.
 * If the print flag is set, then print each contract id found.
 *
 * Returns:
 * 0 if success: restarter specific action found and used with no error
 * -1 if restarter specific action not found
 * -1 if restarter specific action found, but there was a failure
 * -1 if print flag is not set and no contract id is found or multiple
 *    contract ids were found
 * E2BIG if print flag is not set, MULTI_OK bit in flag is set and multiple
 *    contract ids were found
 */
static int
ctids_by_restarter(scf_walkinfo_t *wip, uint64_t *cp, int print_flag,
    uint_t flags, int *restarter_specp, void (*callback_header)(),
    void (*callback_ctid)(uint64_t))
{
	FILE		*fp;
	int		ret = -1;
	int		fscanf_ret;
	uint64_t	cp2;
	int		rest_ret;

	/* Check if callbacks are needed and were passed in */
	if (print_flag) {
		if ((callback_header == NULL) || (callback_ctid == NULL))
			return (ret);
	}

	/* Check for restarter specific action and generation of filename */
	rest_ret = common_by_restarter(wip->inst, wip->fmri, restarter_specp);
	if (rest_ret != 0)
		return (rest_ret);

	/*
	 * If fopen fails, then ctid file hasn't been created yet.
	 * If print_flag is set, this is ok; otherwise fail.
	 */
	if ((fp = fopen(genfmri_filename, "r")) == NULL) {
		if (print_flag)
			return (0);
		goto out;
	}

	if (print_flag) {
		/*
		 * Print all contract ids that are found.
		 * First callback to print ctid header.
		 */
		callback_header();

		/* fscanf may not set errno, so be sure to clear it first */
		errno = 0;
		while ((fscanf_ret = fscanf(fp, "%llu", cp)) == 1) {
			/* Callback to print contract id */
			callback_ctid(*cp);
			errno = 0;
		}
		/* EOF is not a failure when no errno. */
		if ((fscanf_ret != EOF) || (errno != 0)) {
			uu_die(gettext("Unable to read ctid file for %s"),
			    wip->fmri);
		}
		(void) putchar('\n');
		ret = 0;
	} else {
		/* Must find 1 ctid or fail */
		if (fscanf(fp, "%llu", cp) == 1) {
			/* If 2nd ctid found - fail */
			if (fscanf(fp, "%llu", &cp2) == 1) {
				if (flags & MULTI_OK)
					ret = E2BIG;
			} else {
				/* Success - found only 1 ctid */
				ret = 0;
			}
		}
	}
	(void) fclose(fp);

out:
	return (ret);
}

/*
 * Get the process ids associated with an instance using a restarter
 * specific action.
 *
 * Returns:
 *	0 if success: restarter specific action found and used with no error
 *	-1 restarter specific action not found or if failure
 */
static int
pids_by_restarter(scf_instance_t *inst, const char *fmri,
    pid_t **pids, uint_t *np, int *restarter_specp)
{
	uint64_t	c;
	FILE		*fp;
	int		fscanf_ret;
	int		rest_ret;

	/* Check for restarter specific action and generation of filename */
	rest_ret = common_by_restarter(inst, fmri, restarter_specp);
	if (rest_ret != 0)
		return (rest_ret);

	/*
	 * If fopen fails with ENOENT then the ctid file hasn't been
	 * created yet so return success.
	 * For all other errors - fail with uu_die.
	 */
	if ((fp = fopen(genfmri_filename, "r")) == NULL) {
		if (errno == ENOENT)
			return (0);
		uu_die(gettext("Unable to open ctid file for %s"), fmri);
	}

	/* fscanf may not set errno, so be sure to clear it first */
	errno = 0;
	while ((fscanf_ret = fscanf(fp, "%llu", &c)) == 1) {
		if (c == 0) {
			(void) fclose(fp);
			uu_die(gettext("ctid file for %s has corrupt data"),
			    fmri);
		}
		ctid_to_pids(c, pids, np);
		errno = 0;
	}
	/* EOF is not a failure when no errno. */
	if ((fscanf_ret != EOF) || (errno != 0)) {
		uu_die(gettext("Unable to read ctid file for %s"), fmri);
	}

	(void) fclose(fp);
	return (0);
}

static int
instance_processes(scf_instance_t *inst, const char *fmri,
    pid_t **pids, uint_t *np)
{
	scf_iter_t *iter;
	int ret;
	int restarter_spec;

	/* Use the restarter specific get pids routine, if available. */
	ret = pids_by_restarter(inst, fmri, pids, np, &restarter_spec);
	if (restarter_spec == 1)
		return (ret);

	if ((iter = scf_iter_create(h)) == NULL)
		scfdie();

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, g_pg) == 0) {
		*pids = NULL;
		*np = 0;

		(void) propvals_to_pids(g_pg, scf_property_contract, pids, np,
		    g_prop, g_val, iter);

		(void) propvals_to_pids(g_pg, SCF_PROPERTY_TRANSIENT_CONTRACT,
		    pids, np, g_prop, g_val, iter);

		ret = 0;
	} else {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		ret = -1;
	}

	scf_iter_destroy(iter);

	return (ret);
}

static int
get_psinfo(pid_t pid, psinfo_t *psip)
{
	char path[100];
	int fd;

	(void) snprintf(path, sizeof (path), "/proc/%lu/psinfo", pid);

	fd = open64(path, O_RDONLY);
	if (fd < 0)
		return (-1);

	if (read(fd, psip, sizeof (*psip)) < 0)
		uu_die(gettext("Could not read info for process %lu"), pid);

	(void) close(fd);

	return (0);
}



/*
 * Column sprint and sortkey functions
 */

struct column {
	const char *name;
	int width;

	/*
	 * This function should write the value for the column into buf, and
	 * grow or allocate buf accordingly.  It should always write at least
	 * width bytes, blanking unused bytes with spaces.  If the field is
	 * greater than the column width we allow it to overlap other columns.
	 * In particular, it shouldn't write any null bytes.  (Though an extra
	 * null byte past the end is currently tolerated.)  If the property
	 * group is non-NULL, then we are dealing with a legacy service.
	 */
	void (*sprint)(char **, scf_walkinfo_t *);

	int sortkey_width;

	/*
	 * This function should write sortkey_width bytes into buf which will
	 * cause memcmp() to sort it properly.  (Unlike sprint() above,
	 * however, an extra null byte may overrun the buffer.)  The second
	 * argument controls whether the results are sorted in forward or
	 * reverse order.
	 */
	void (*get_sortkey)(char *, int, scf_walkinfo_t *);
};

static void
reverse_bytes(char *buf, size_t len)
{
	int i;

	for (i = 0; i < len; ++i)
		buf[i] = ~buf[i];
}

/* CTID */
#define	CTID_COLUMN_WIDTH		6
#define	CTID_COLUMN_BUFSIZE		20	/* max ctid_t + space + \0 */

static void
sprint_ctid(char **buf, scf_walkinfo_t *wip)
{
	int r;
	uint64_t c;
	size_t newsize = (*buf ? strlen(*buf) : 0) + CTID_COLUMN_BUFSIZE;
	char *newbuf = safe_malloc(newsize);
	int restarter_spec;

	/*
	 * Use the restarter specific get pids routine, if available.
	 * Only check for non-legacy services (wip->pg == 0).
	 */
	if (wip->pg != NULL) {
		r = pg_get_single_val(wip->pg, scf_property_contract,
		    SCF_TYPE_COUNT, &c, 0, EMPTY_OK | MULTI_OK);
	} else {
		r = ctids_by_restarter(wip, &c, 0, MULTI_OK, &restarter_spec,
		    NULL, NULL);
		if (restarter_spec == 0) {
			/* No restarter specific routine */
			r = get_restarter_count_prop(wip->inst,
			    scf_property_contract, &c, EMPTY_OK | MULTI_OK);
		}
	}

	if (r == 0)
		(void) snprintf(newbuf, newsize, "%s%*lu ",
		    *buf ? *buf : "", CTID_COLUMN_WIDTH, (ctid_t)c);
	else if (r == E2BIG)
		(void) snprintf(newbuf, newsize, "%s%*lu* ",
		    *buf ? *buf : "", CTID_COLUMN_WIDTH - 1, (ctid_t)c);
	else
		(void) snprintf(newbuf, newsize, "%s%*s ",
		    *buf ? *buf : "", CTID_COLUMN_WIDTH, "-");
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

#define	CTID_SORTKEY_WIDTH		(sizeof (uint64_t))

static void
sortkey_ctid(char *buf, int reverse, scf_walkinfo_t *wip)
{
	int r;
	uint64_t c;
	int restarter_spec;

	/*
	 * Use the restarter specific get pids routine, if available.
	 * Only check for non-legacy services (wip->pg == 0).
	 */
	if (wip->pg != NULL) {
		r = pg_get_single_val(wip->pg, scf_property_contract,
		    SCF_TYPE_COUNT, &c, 0, EMPTY_OK);
	} else {
		r = ctids_by_restarter(wip, &c, 0, MULTI_OK, &restarter_spec,
		    NULL, NULL);
		if (restarter_spec == 0) {
			/* No restarter specific routine */
			r = get_restarter_count_prop(wip->inst,
			    scf_property_contract, &c, EMPTY_OK);
		}
	}

	if (r == 0) {
		/*
		 * Use the id itself, but it must be big-endian for this to
		 * work.
		 */
		c = BE_64(c);

		bcopy(&c, buf, CTID_SORTKEY_WIDTH);
	} else {
		bzero(buf, CTID_SORTKEY_WIDTH);
	}

	if (reverse)
		reverse_bytes(buf, CTID_SORTKEY_WIDTH);
}

/* DESC */
#define	DESC_COLUMN_WIDTH	100

static void
sprint_desc(char **buf, scf_walkinfo_t *wip)
{
	char *x;
	size_t newsize;
	char *newbuf;

	if (common_name_buf == NULL)
		common_name_buf = safe_malloc(max_scf_value_length + 1);

	bzero(common_name_buf, max_scf_value_length + 1);

	if (wip->pg != NULL) {
		common_name_buf[0] = '-';
	} else if (inst_get_single_val(wip->inst, SCF_PG_TM_COMMON_NAME, locale,
	    SCF_TYPE_USTRING, common_name_buf, max_scf_value_length, 0,
	    1, 1) == -1 &&
	    inst_get_single_val(wip->inst, SCF_PG_TM_COMMON_NAME, "C",
	    SCF_TYPE_USTRING, common_name_buf, max_scf_value_length, 0,
	    1, 1) == -1) {
		common_name_buf[0] = '-';
	}

	/*
	 * Collapse multi-line tm_common_name values into a single line.
	 */
	for (x = common_name_buf; *x != '\0'; x++)
		if (*x == '\n')
			*x = ' ';

	if (strlen(common_name_buf) > DESC_COLUMN_WIDTH)
		newsize = (*buf ? strlen(*buf) : 0) +
		    strlen(common_name_buf) + 1;
	else
		newsize = (*buf ? strlen(*buf) : 0) + DESC_COLUMN_WIDTH + 1;
	newbuf = safe_malloc(newsize);
	(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
	    DESC_COLUMN_WIDTH, common_name_buf);
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

/* ARGSUSED */
static void
sortkey_desc(char *buf, int reverse, scf_walkinfo_t *wip)
{
	bzero(buf, DESC_COLUMN_WIDTH);
}

/* State columns (STATE, NSTATE, S, N, SN, STA, NSTA) */

static char
state_to_char(const char *state)
{
	if (strcmp(state, SCF_STATE_STRING_UNINIT) == 0)
		return ('u');

	if (strcmp(state, SCF_STATE_STRING_OFFLINE) == 0)
		return ('0');

	if (strcmp(state, SCF_STATE_STRING_ONLINE) == 0)
		return ('1');

	if (strcmp(state, SCF_STATE_STRING_MAINT) == 0)
		return ('m');

	if (strcmp(state, SCF_STATE_STRING_DISABLED) == 0)
		return ('d');

	if (strcmp(state, SCF_STATE_STRING_DEGRADED) == 0)
		return ('D');

	if (strcmp(state, SCF_STATE_STRING_LEGACY) == 0)
		return ('L');

	return ('?');
}

/* Return true if inst is transitioning. */
static int
transitioning(scf_instance_t *inst)
{
	char nstate_name[MAX_SCF_STATE_STRING_SZ];

	get_restarter_string_prop(inst, scf_property_next_state, nstate_name,
	    sizeof (nstate_name));

	return (state_to_char(nstate_name) != '?');
}

/* ARGSUSED */
static void
sortkey_states(const char *pname, char *buf, int reverse, scf_walkinfo_t *wip)
{
	char state_name[MAX_SCF_STATE_STRING_SZ];

	/*
	 * Lower numbers are printed first, so these are arranged from least
	 * interesting ("legacy run") to most interesting (unknown).
	 */
	if (wip->pg == NULL) {
		get_restarter_string_prop(wip->inst, pname, state_name,
		    sizeof (state_name));

		if (strcmp(state_name, SCF_STATE_STRING_ONLINE) == 0)
			*buf = 2;
		else if (strcmp(state_name, SCF_STATE_STRING_DEGRADED) == 0)
			*buf = 3;
		else if (strcmp(state_name, SCF_STATE_STRING_OFFLINE) == 0)
			*buf = 4;
		else if (strcmp(state_name, SCF_STATE_STRING_MAINT) == 0)
			*buf = 5;
		else if (strcmp(state_name, SCF_STATE_STRING_DISABLED) == 0)
			*buf = 1;
		else if (strcmp(state_name, SCF_STATE_STRING_UNINIT) == 0)
			*buf = 6;
		else
			*buf = 7;
	} else
		*buf = 0;

	if (reverse)
		*buf = 255 - *buf;
}

static void
sprint_state(char **buf, scf_walkinfo_t *wip)
{
	char state_name[MAX_SCF_STATE_STRING_SZ + 1];
	size_t newsize;
	char *newbuf;

	if (wip->pg == NULL) {
		get_restarter_string_prop(wip->inst, scf_property_state,
		    state_name, sizeof (state_name));

		/* Don't print blank fields, to ease parsing. */
		if (state_name[0] == '\0') {
			state_name[0] = '-';
			state_name[1] = '\0';
		}

		if (!opt_nstate_shown && transitioning(wip->inst)) {
			/* Append an asterisk if nstate is valid. */
			(void) strcat(state_name, "*");
		}
	} else
		(void) strcpy(state_name, SCF_STATE_STRING_LEGACY);

	newsize = (*buf ? strlen(*buf) : 0) + MAX_SCF_STATE_STRING_SZ + 2;
	newbuf = safe_malloc(newsize);
	(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
	    MAX_SCF_STATE_STRING_SZ + 1, state_name);

	if (*buf)
		free(*buf);
	*buf = newbuf;
}

static void
sortkey_state(char *buf, int reverse, scf_walkinfo_t *wip)
{
	sortkey_states(scf_property_state, buf, reverse, wip);
}

static void
sprint_nstate(char **buf, scf_walkinfo_t *wip)
{
	char next_state_name[MAX_SCF_STATE_STRING_SZ];
	boolean_t blank = 0;
	size_t newsize;
	char *newbuf;

	if (wip->pg == NULL) {
		get_restarter_string_prop(wip->inst, scf_property_next_state,
		    next_state_name, sizeof (next_state_name));

		/* Don't print blank fields, to ease parsing. */
		if (next_state_name[0] == '\0' ||
		    strcmp(next_state_name, SCF_STATE_STRING_NONE) == 0)
			blank = 1;
	} else
		blank = 1;

	if (blank) {
		next_state_name[0] = '-';
		next_state_name[1] = '\0';
	}

	newsize = (*buf ? strlen(*buf) : 0) + MAX_SCF_STATE_STRING_SZ + 1;
	newbuf = safe_malloc(newsize);
	(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
	    MAX_SCF_STATE_STRING_SZ - 1, next_state_name);
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

static void
sortkey_nstate(char *buf, int reverse, scf_walkinfo_t *wip)
{
	sortkey_states(scf_property_next_state, buf, reverse, wip);
}

static void
sprint_s(char **buf, scf_walkinfo_t *wip)
{
	char tmp[3];
	char state_name[MAX_SCF_STATE_STRING_SZ];
	size_t newsize = (*buf ? strlen(*buf) : 0) + 4;
	char *newbuf = safe_malloc(newsize);

	if (wip->pg == NULL) {
		get_restarter_string_prop(wip->inst, scf_property_state,
		    state_name, sizeof (state_name));
		tmp[0] = state_to_char(state_name);

		if (!opt_nstate_shown && transitioning(wip->inst))
			tmp[1] = '*';
		else
			tmp[1] = ' ';
	} else {
		tmp[0] = 'L';
		tmp[1] = ' ';
	}
	tmp[2] = ' ';
	(void) snprintf(newbuf, newsize, "%s%-*s", *buf ? *buf : "",
	    3, tmp);
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

static void
sprint_n(char **buf, scf_walkinfo_t *wip)
{
	char tmp[2];
	size_t newsize = (*buf ? strlen(*buf) : 0) + 3;
	char *newbuf = safe_malloc(newsize);
	char nstate_name[MAX_SCF_STATE_STRING_SZ];

	if (wip->pg == NULL) {
		get_restarter_string_prop(wip->inst, scf_property_next_state,
		    nstate_name, sizeof (nstate_name));

		if (strcmp(nstate_name, SCF_STATE_STRING_NONE) == 0)
			tmp[0] = '-';
		else
			tmp[0] = state_to_char(nstate_name);
	} else
		tmp[0] = '-';

	(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
	    2, tmp);
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

static void
sprint_sn(char **buf, scf_walkinfo_t *wip)
{
	char tmp[3];
	size_t newsize = (*buf ? strlen(*buf) : 0) + 4;
	char *newbuf = safe_malloc(newsize);
	char nstate_name[MAX_SCF_STATE_STRING_SZ];
	char state_name[MAX_SCF_STATE_STRING_SZ];

	if (wip->pg == NULL) {
		get_restarter_string_prop(wip->inst, scf_property_state,
		    state_name, sizeof (state_name));
		get_restarter_string_prop(wip->inst, scf_property_next_state,
		    nstate_name, sizeof (nstate_name));
		tmp[0] = state_to_char(state_name);

		if (strcmp(nstate_name, SCF_STATE_STRING_NONE) == 0)
			tmp[1] = '-';
		else
			tmp[1] = state_to_char(nstate_name);
	} else {
		tmp[0] = 'L';
		tmp[1] = '-';
	}

	tmp[2] = ' ';
	(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
	    3, tmp);
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

/* ARGSUSED */
static void
sortkey_sn(char *buf, int reverse, scf_walkinfo_t *wip)
{
	sortkey_state(buf, reverse, wip);
	sortkey_nstate(buf + 1, reverse, wip);
}

static const char *
state_abbrev(const char *state)
{
	if (strcmp(state, SCF_STATE_STRING_UNINIT) == 0)
		return ("UN");
	if (strcmp(state, SCF_STATE_STRING_OFFLINE) == 0)
		return ("OFF");
	if (strcmp(state, SCF_STATE_STRING_ONLINE) == 0)
		return ("ON");
	if (strcmp(state, SCF_STATE_STRING_MAINT) == 0)
		return ("MNT");
	if (strcmp(state, SCF_STATE_STRING_DISABLED) == 0)
		return ("DIS");
	if (strcmp(state, SCF_STATE_STRING_DEGRADED) == 0)
		return ("DGD");
	if (strcmp(state, SCF_STATE_STRING_LEGACY) == 0)
		return ("LRC");

	return ("?");
}

static void
sprint_sta(char **buf, scf_walkinfo_t *wip)
{
	char state_name[MAX_SCF_STATE_STRING_SZ];
	char sta[5];
	size_t newsize = (*buf ? strlen(*buf) : 0) + 6;
	char *newbuf = safe_malloc(newsize);

	if (wip->pg == NULL)
		get_restarter_string_prop(wip->inst, scf_property_state,
		    state_name, sizeof (state_name));
	else
		(void) strcpy(state_name, SCF_STATE_STRING_LEGACY);

	(void) strcpy(sta, state_abbrev(state_name));

	if (wip->pg == NULL && !opt_nstate_shown && transitioning(wip->inst))
		(void) strcat(sta, "*");

	(void) snprintf(newbuf, newsize, "%s%-4s ", *buf ? *buf : "", sta);
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

static void
sprint_nsta(char **buf, scf_walkinfo_t *wip)
{
	char state_name[MAX_SCF_STATE_STRING_SZ];
	size_t newsize = (*buf ? strlen(*buf) : 0) + 6;
	char *newbuf = safe_malloc(newsize);

	if (wip->pg == NULL)
		get_restarter_string_prop(wip->inst, scf_property_next_state,
		    state_name, sizeof (state_name));
	else
		(void) strcpy(state_name, SCF_STATE_STRING_NONE);

	if (strcmp(state_name, SCF_STATE_STRING_NONE) == 0)
		(void) snprintf(newbuf, newsize, "%s%-4s ", *buf ? *buf : "",
		    "-");
	else
		(void) snprintf(newbuf, newsize, "%s%-4s ", *buf ? *buf : "",
		    state_abbrev(state_name));
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

/* FMRI */
#define	FMRI_COLUMN_WIDTH	50
static void
sprint_fmri(char **buf, scf_walkinfo_t *wip)
{
	char *fmri_buf = safe_malloc(max_scf_fmri_length + 1);
	size_t newsize;
	char *newbuf;

	if (wip->pg == NULL) {
		if (scf_instance_to_fmri(wip->inst, fmri_buf,
		    max_scf_fmri_length + 1) == -1)
			scfdie();
	} else {
		(void) strcpy(fmri_buf, SCF_FMRI_LEGACY_PREFIX);
		if (pg_get_single_val(wip->pg, SCF_LEGACY_PROPERTY_NAME,
		    SCF_TYPE_ASTRING, fmri_buf +
		    sizeof (SCF_FMRI_LEGACY_PREFIX) - 1,
		    max_scf_fmri_length + 1 -
		    (sizeof (SCF_FMRI_LEGACY_PREFIX) - 1), 0) != 0)
			(void) strcat(fmri_buf, LEGACY_UNKNOWN);
	}

	if (strlen(fmri_buf) > FMRI_COLUMN_WIDTH)
		newsize = (*buf ? strlen(*buf) : 0) + strlen(fmri_buf) + 2;
	else
		newsize = (*buf ? strlen(*buf) : 0) + FMRI_COLUMN_WIDTH + 2;
	newbuf = safe_malloc(newsize);
	(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
	    FMRI_COLUMN_WIDTH, fmri_buf);
	free(fmri_buf);
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

static void
sortkey_fmri(char *buf, int reverse, scf_walkinfo_t *wip)
{
	char *tmp = NULL;

	sprint_fmri(&tmp, wip);
	bcopy(tmp, buf, FMRI_COLUMN_WIDTH);
	free(tmp);
	if (reverse)
		reverse_bytes(buf, FMRI_COLUMN_WIDTH);
}

/* Component columns */
#define	COMPONENT_COLUMN_WIDTH	20
static void
sprint_scope(char **buf, scf_walkinfo_t *wip)
{
	char *scope_buf = safe_malloc(max_scf_name_length + 1);
	size_t newsize = (*buf ? strlen(*buf) : 0) + COMPONENT_COLUMN_WIDTH + 2;
	char *newbuf = safe_malloc(newsize);

	assert(wip->scope != NULL);

	if (scf_scope_get_name(wip->scope, scope_buf, max_scf_name_length) < 0)
		scfdie();

	(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
	    COMPONENT_COLUMN_WIDTH, scope_buf);
	if (*buf)
		free(*buf);
	*buf = newbuf;
	free(scope_buf);
}

static void
sortkey_scope(char *buf, int reverse, scf_walkinfo_t *wip)
{
	char *tmp = NULL;

	sprint_scope(&tmp, wip);
	bcopy(tmp, buf, COMPONENT_COLUMN_WIDTH);
	free(tmp);
	if (reverse)
		reverse_bytes(buf, COMPONENT_COLUMN_WIDTH);
}

static void
sprint_service(char **buf, scf_walkinfo_t *wip)
{
	char *svc_buf = safe_malloc(max_scf_name_length + 1);
	char *newbuf;
	size_t newsize;

	if (wip->pg == NULL) {
		if (scf_service_get_name(wip->svc, svc_buf,
		    max_scf_name_length + 1) < 0)
			scfdie();
	} else {
		if (pg_get_single_val(wip->pg, "name", SCF_TYPE_ASTRING,
		    svc_buf, max_scf_name_length + 1, EMPTY_OK) != 0)
			(void) strcpy(svc_buf, LEGACY_UNKNOWN);
	}


	if (strlen(svc_buf) > COMPONENT_COLUMN_WIDTH)
		newsize = (*buf ? strlen(*buf) : 0) + strlen(svc_buf) + 2;
	else
		newsize = (*buf ? strlen(*buf) : 0) +
		    COMPONENT_COLUMN_WIDTH + 2;
	newbuf = safe_malloc(newsize);
	(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
	    COMPONENT_COLUMN_WIDTH, svc_buf);
	free(svc_buf);
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

static void
sortkey_service(char *buf, int reverse, scf_walkinfo_t *wip)
{
	char *tmp = NULL;

	sprint_service(&tmp, wip);
	bcopy(tmp, buf, COMPONENT_COLUMN_WIDTH);
	free(tmp);
	if (reverse)
		reverse_bytes(buf, COMPONENT_COLUMN_WIDTH);
}

/* INST */
static void
sprint_instance(char **buf, scf_walkinfo_t *wip)
{
	char *tmp = safe_malloc(max_scf_name_length + 1);
	size_t newsize = (*buf ? strlen(*buf) : 0) + COMPONENT_COLUMN_WIDTH + 2;
	char *newbuf = safe_malloc(newsize);

	if (wip->pg == NULL) {
		if (scf_instance_get_name(wip->inst, tmp,
		    max_scf_name_length + 1) < 0)
			scfdie();
	} else {
		tmp[0] = '-';
		tmp[1] = '\0';
	}

	(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
	    COMPONENT_COLUMN_WIDTH, tmp);
	if (*buf)
		free(*buf);
	*buf = newbuf;
	free(tmp);
}

static void
sortkey_instance(char *buf, int reverse, scf_walkinfo_t *wip)
{
	char *tmp = NULL;

	sprint_instance(&tmp, wip);
	bcopy(tmp, buf, COMPONENT_COLUMN_WIDTH);
	free(tmp);
	if (reverse)
		reverse_bytes(buf, COMPONENT_COLUMN_WIDTH);
}

/* STIME */
#define	STIME_COLUMN_WIDTH		8
#define	FORMAT_TIME			"%k:%M:%S"
#define	FORMAT_DATE			"%b_%d  "
#define	FORMAT_YEAR			"%Y    "

/*
 * sprint_stime() will allocate a new buffer and snprintf the services's
 * state timestamp.  If the timestamp is unavailable for some reason
 * a '-' is given instead.
 */
static void
sprint_stime(char **buf, scf_walkinfo_t *wip)
{
	int r;
	struct timeval tv;
	time_t then;
	struct tm *tm;
	char st_buf[STIME_COLUMN_WIDTH + 1];
	size_t newsize = (*buf ? strlen(*buf) : 0) + STIME_COLUMN_WIDTH + 2;
	char *newbuf = safe_malloc(newsize);

	if (wip->pg == NULL) {
		r = get_restarter_time_prop(wip->inst,
		    SCF_PROPERTY_STATE_TIMESTAMP, &tv, 0);
	} else {
		r = pg_get_single_val(wip->pg, SCF_PROPERTY_STATE_TIMESTAMP,
		    SCF_TYPE_TIME, &tv, NULL, 0);
	}

	if (r != 0) {
		/*
		 * There's something amiss with our service
		 * so we'll print a '-' for STIME.
		 */
		(void) snprintf(newbuf, newsize, "%s%-*s", *buf ? *buf : "",
		    STIME_COLUMN_WIDTH + 1, "-");
	} else {
		/* tv should be valid so we'll format it */
		then = (time_t)tv.tv_sec;

		tm = localtime(&then);
		/*
		 * Print time if started within the past 24 hours, print date
		 * if within the past 12 months or, finally, print year if
		 * started greater than 12 months ago.
		 */
		if (now - then < 24 * 60 * 60) {
			(void) strftime(st_buf, sizeof (st_buf),
			    gettext(FORMAT_TIME), tm);
		} else if (now - then < 12 * 30 * 24 * 60 * 60) {
			(void) strftime(st_buf, sizeof (st_buf),
			    gettext(FORMAT_DATE), tm);
		} else {
			(void) strftime(st_buf, sizeof (st_buf),
			    gettext(FORMAT_YEAR), tm);
		}
		(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
		    STIME_COLUMN_WIDTH + 1, st_buf);
	}
	if (*buf)
		free(*buf);
	*buf = newbuf;
}

#define	STIME_SORTKEY_WIDTH		(sizeof (uint64_t) + sizeof (uint32_t))

/* ARGSUSED */
static void
sortkey_stime(char *buf, int reverse, scf_walkinfo_t *wip)
{
	struct timeval tv;
	int r;

	if (wip->pg == NULL)
		r = get_restarter_time_prop(wip->inst,
		    SCF_PROPERTY_STATE_TIMESTAMP, &tv, 0);
	else
		r = pg_get_single_val(wip->pg, SCF_PROPERTY_STATE_TIMESTAMP,
		    SCF_TYPE_TIME, &tv, NULL, 0);

	if (r == 0) {
		int64_t sec;
		int32_t us;

		/* Stick it straight into the buffer. */
		sec = tv.tv_sec;
		us = tv.tv_usec;

		sec = BE_64(sec);
		us = BE_32(us);
		bcopy(&sec, buf, sizeof (sec));
		bcopy(&us, buf + sizeof (sec), sizeof (us));
	} else {
		bzero(buf, STIME_SORTKEY_WIDTH);
	}

	if (reverse)
		reverse_bytes(buf, STIME_SORTKEY_WIDTH);
}

/* ZONE */
#define	ZONE_COLUMN_WIDTH	16
/*ARGSUSED*/
static void
sprint_zone(char **buf, scf_walkinfo_t *wip)
{
	size_t newsize;
	char *newbuf, *zonename = g_zonename, b[ZONENAME_MAX];

	if (zonename == NULL) {
		zoneid_t zoneid = getzoneid();

		if (getzonenamebyid(zoneid, b, sizeof (b)) < 0)
			uu_die(gettext("could not determine zone name"));

		zonename = b;
	}

	if (strlen(zonename) > ZONE_COLUMN_WIDTH)
		newsize = (*buf ? strlen(*buf) : 0) + strlen(zonename) + 2;
	else
		newsize = (*buf ? strlen(*buf) : 0) + ZONE_COLUMN_WIDTH + 2;

	newbuf = safe_malloc(newsize);
	(void) snprintf(newbuf, newsize, "%s%-*s ", *buf ? *buf : "",
	    ZONE_COLUMN_WIDTH, zonename);

	if (*buf)
		free(*buf);
	*buf = newbuf;
}

static void
sortkey_zone(char *buf, int reverse, scf_walkinfo_t *wip)
{
	char *tmp = NULL;

	sprint_zone(&tmp, wip);
	bcopy(tmp, buf, ZONE_COLUMN_WIDTH);
	free(tmp);
	if (reverse)
		reverse_bytes(buf, ZONE_COLUMN_WIDTH);
}

/*
 * Information about columns which can be displayed.  If you add something,
 * check MAX_COLUMN_NAME_LENGTH_STR & update description_of_column() below.
 */
static const struct column columns[] = {
	{ "CTID", CTID_COLUMN_WIDTH, sprint_ctid,
		CTID_SORTKEY_WIDTH, sortkey_ctid },
	{ "DESC", DESC_COLUMN_WIDTH, sprint_desc,
		DESC_COLUMN_WIDTH, sortkey_desc },
	{ "FMRI", FMRI_COLUMN_WIDTH, sprint_fmri,
		FMRI_COLUMN_WIDTH, sortkey_fmri },
	{ "INST", COMPONENT_COLUMN_WIDTH, sprint_instance,
		COMPONENT_COLUMN_WIDTH, sortkey_instance },
	{ "N", 1,  sprint_n, 1, sortkey_nstate },
	{ "NSTA", 4, sprint_nsta, 1, sortkey_nstate },
	{ "NSTATE", MAX_SCF_STATE_STRING_SZ - 1, sprint_nstate,
		1, sortkey_nstate },
	{ "S", 2, sprint_s, 1, sortkey_state },
	{ "SCOPE", COMPONENT_COLUMN_WIDTH, sprint_scope,
		COMPONENT_COLUMN_WIDTH, sortkey_scope },
	{ "SN", 2, sprint_sn, 2, sortkey_sn },
	{ "SVC", COMPONENT_COLUMN_WIDTH, sprint_service,
		COMPONENT_COLUMN_WIDTH, sortkey_service },
	{ "STA", 4, sprint_sta, 1, sortkey_state },
	{ "STATE", MAX_SCF_STATE_STRING_SZ - 1 + 1, sprint_state,
		1, sortkey_state },
	{ "STIME", STIME_COLUMN_WIDTH, sprint_stime,
		STIME_SORTKEY_WIDTH, sortkey_stime },
	{ "ZONE", ZONE_COLUMN_WIDTH, sprint_zone,
		ZONE_COLUMN_WIDTH, sortkey_zone },
};

#define	MAX_COLUMN_NAME_LENGTH_STR	"6"

static const int ncolumns = sizeof (columns) / sizeof (columns[0]);

/*
 * Necessary thanks to gettext() & xgettext.
 */
static const char *
description_of_column(int c)
{
	const char *s = NULL;

	switch (c) {
	case 0:
		s = gettext("contract ID for service (see contract(4))");
		break;
	case 1:
		s = gettext("human-readable description of the service");
		break;
	case 2:
		s = gettext("Fault Managed Resource Identifier for service");
		break;
	case 3:
		s = gettext("portion of the FMRI indicating service instance");
		break;
	case 4:
		s = gettext("abbreviation for next state (if in transition)");
		break;
	case 5:
		s = gettext("abbreviation for next state (if in transition)");
		break;
	case 6:
		s = gettext("name for next state (if in transition)");
		break;
	case 7:
		s = gettext("abbreviation for current state");
		break;
	case 8:
		s = gettext("name for scope associated with service");
		break;
	case 9:
		s = gettext("abbreviation for current state and next state");
		break;
	case 10:
		s = gettext("portion of the FMRI representing service name");
		break;
	case 11:
		s = gettext("abbreviation for current state");
		break;
	case 12:
		s = gettext("name for current state");
		break;
	case 13:
		s = gettext("time of last state change");
		break;
	case 14:
		s = gettext("name of zone");
		break;
	}

	assert(s != NULL);
	return (s);
}


static void
print_usage(const char *progname, FILE *f)
{
	(void) fprintf(f, gettext(
	    "Usage: %1$s [-aHpv] [-o col[,col ... ]] [-R restarter] "
	    "[-sS col] [-Z | -z zone ]\n            [<service> ...]\n"
	    "       %1$s -d | -D [-Hpv] [-o col[,col ... ]] [-sS col] "
	    "[-Z | -z zone ]\n            [<service> ...]\n"
	    "       %1$s [-l | -L] [-Z | -z zone] <service> ...\n"
	    "       %1$s -x [-v] [-Z | -z zone] [<service> ...]\n"
	    "       %1$s -?\n"), progname);
}

static __NORETURN void
argserr(const char *progname)
{
	print_usage(progname, stderr);
	exit(UU_EXIT_USAGE);
}

static void
print_help(const char *progname)
{
	int i;

	print_usage(progname, stdout);

	(void) printf(gettext("\n"
	"\t-a  list all service instances rather than "
	"only those that are enabled\n"
	"\t-d  list dependencies of the specified service(s)\n"
	"\t-D  list dependents of the specified service(s)\n"
	"\t-H  omit header line from output\n"
	"\t-l  list detailed information about the specified service(s)\n"
	"\t-L  list the log file associated with the specified service(s)\n"
	"\t-o  list only the specified columns in the output\n"
	"\t-p  list process IDs and names associated with each service\n"
	"\t-R  list only those services with the specified restarter\n"
	"\t-s  sort output in ascending order by the specified column(s)\n"
	"\t-S  sort output in descending order by the specified column(s)\n"
	"\t-v  list verbose information appropriate to the type of output\n"
	"\t-x  explain the status of services that might require maintenance,\n"
	"\t    or explain the status of the specified service(s)\n"
	"\t-z  from global zone, show services in a specified zone\n"
	"\t-Z  from global zone, show services in all zones\n"
	"\n\t"
	"Services can be specified using an FMRI, abbreviation, or fnmatch(5)\n"
	"\tpattern, as shown in these examples for svc:/network/smtp:sendmail\n"
	"\n"
	"\t%1$s [opts] svc:/network/smtp:sendmail\n"
	"\t%1$s [opts] network/smtp:sendmail\n"
	"\t%1$s [opts] network/*mail\n"
	"\t%1$s [opts] network/smtp\n"
	"\t%1$s [opts] smtp:sendmail\n"
	"\t%1$s [opts] smtp\n"
	"\t%1$s [opts] sendmail\n"
	"\n\t"
	"Columns for output or sorting can be specified using these names:\n"
	"\n"), progname);

	for (i = 0; i < ncolumns; i++) {
		(void) printf("\t%-" MAX_COLUMN_NAME_LENGTH_STR "s  %s\n",
		    columns[i].name, description_of_column(i));
	}
}


/*
 * A getsubopt()-like function which returns an index into the columns table.
 * On success, *optionp is set to point to the next sub-option, or the
 * terminating null if there are none.
 */
static int
getcolumnopt(char **optionp)
{
	char *str = *optionp, *cp;
	int i;

	assert(optionp != NULL);
	assert(*optionp != NULL);

	cp = strchr(*optionp, ',');
	if (cp != NULL)
		*cp = '\0';

	for (i = 0; i < ncolumns; ++i) {
		if (strcasecmp(str, columns[i].name) == 0) {
			if (cp != NULL)
				*optionp = cp + 1;
			else
				*optionp = strchr(*optionp, '\0');

			return (i);
		}
	}

	return (-1);
}

static void
print_header()
{
	int i;
	char *line_buf, *cp;

	line_buf = safe_malloc(line_sz);
	cp = line_buf;
	for (i = 0; i < opt_cnum; ++i) {
		const struct column * const colp = &columns[opt_columns[i]];

		(void) snprintf(cp, colp->width + 1, "%-*s", colp->width,
		    colp->name);
		cp += colp->width;
		*cp++ = ' ';
	}

	/* Trim the trailing whitespace */
	--cp;
	while (*cp == ' ')
		--cp;
	*(cp+1) = '\0';
	(void) puts(line_buf);

	free(line_buf);
}



/*
 * Long listing (-l) functions.
 */

static int
pidcmp(const void *l, const void *r)
{
	pid_t lp = *(pid_t *)l, rp = *(pid_t *)r;

	if (lp < rp)
		return (-1);
	if (lp > rp)
		return (1);
	return (0);
}

/*
 * This is the strlen() of the longest label ("description"), plus intercolumn
 * space.
 */
#define	DETAILED_WIDTH	(11 + 2)

/*
 * Callback routine to print header for contract id.
 * Called by ctids_by_restarter and print_detailed.
 */
static void
print_ctid_header()
{
	(void) printf("%-*s", DETAILED_WIDTH, "contract_id");
}

/*
 * Callback routine to print a contract id.
 * Called by ctids_by_restarter and print_detailed.
 */
static void
print_ctid_detailed(uint64_t c)
{
	(void) printf("%lu ", (ctid_t)c);
}

static void
detailed_list_processes(scf_walkinfo_t *wip)
{
	uint64_t c;
	pid_t *pids;
	uint_t i, n;
	psinfo_t psi;

	if (get_restarter_count_prop(wip->inst, scf_property_contract, &c,
	    EMPTY_OK) != 0)
		return;

	if (instance_processes(wip->inst, wip->fmri, &pids, &n) != 0)
		return;

	qsort(pids, n, sizeof (*pids), pidcmp);

	for (i = 0; i < n; ++i) {
		(void) printf("%-*s%lu", DETAILED_WIDTH, gettext("process"),
		    pids[i]);

		if (get_psinfo(pids[i], &psi) == 0)
			(void) printf(" %.*s", PRARGSZ, psi.pr_psargs);

		(void) putchar('\n');
	}

	free(pids);
}

/*
 * Determines the state of a dependency.  If the FMRI specifies a file, then we
 * fake up a state based on whether we can access the file.
 */
static void
get_fmri_state(char *fmri, char *state, size_t state_sz)
{
	char *lfmri;
	const char *svc_name, *inst_name, *pg_name, *path;
	scf_service_t *svc;
	scf_instance_t *inst;
	scf_iter_t *iter;

	lfmri = safe_strdup(fmri);

	/*
	 * Check for file:// dependencies
	 */
	if (scf_parse_file_fmri(lfmri, NULL, &path) == SCF_SUCCESS) {
		struct stat64 statbuf;
		const char *msg;

		if (stat64(path, &statbuf) == 0)
			msg = "online";
		else if (errno == ENOENT)
			msg = "absent";
		else
			msg = "unknown";

		(void) strlcpy(state, msg, state_sz);
		return;
	}

	/*
	 * scf_parse_file_fmri() may have overwritten part of the string, so
	 * copy it back.
	 */
	(void) strcpy(lfmri, fmri);

	if (scf_parse_svc_fmri(lfmri, NULL, &svc_name, &inst_name,
	    &pg_name, NULL) != SCF_SUCCESS) {
		free(lfmri);
		(void) strlcpy(state, "invalid", state_sz);
		return;
	}

	free(lfmri);

	if (svc_name == NULL || pg_name != NULL) {
		(void) strlcpy(state, "invalid", state_sz);
		return;
	}

	if (inst_name != NULL) {
		/* instance: get state */
		inst = scf_instance_create(h);
		if (inst == NULL)
			scfdie();

		if (scf_handle_decode_fmri(h, fmri, NULL, NULL, inst, NULL,
		    NULL, SCF_DECODE_FMRI_EXACT) == SCF_SUCCESS)
			get_restarter_string_prop(inst, scf_property_state,
			    state, state_sz);
		else {
			switch (scf_error()) {
			case SCF_ERROR_INVALID_ARGUMENT:
				(void) strlcpy(state, "invalid", state_sz);
				break;
			case SCF_ERROR_NOT_FOUND:
				(void) strlcpy(state, "absent", state_sz);
				break;

			default:
				scfdie();
			}
		}

		scf_instance_destroy(inst);
		return;
	}

	/*
	 * service: If only one instance, use that state.  Otherwise, say
	 * "multiple".
	 */
	if ((svc = scf_service_create(h)) == NULL ||
	    (inst = scf_instance_create(h)) == NULL ||
	    (iter = scf_iter_create(h)) == NULL)
		scfdie();

	if (scf_handle_decode_fmri(h, fmri, NULL, svc, NULL, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) != SCF_SUCCESS) {
		switch (scf_error()) {
		case SCF_ERROR_INVALID_ARGUMENT:
			(void) strlcpy(state, "invalid", state_sz);
			goto out;
		case SCF_ERROR_NOT_FOUND:
			(void) strlcpy(state, "absent", state_sz);
			goto out;

		default:
			scfdie();
		}
	}

	if (scf_iter_service_instances(iter, svc) != SCF_SUCCESS)
		scfdie();

	switch (scf_iter_next_instance(iter, inst)) {
	case 0:
		(void) strlcpy(state, "absent", state_sz);
		goto out;

	case 1:
		break;

	default:
		scfdie();
	}

	/* Get the state in case this is the only instance. */
	get_restarter_string_prop(inst, scf_property_state, state, state_sz);

	switch (scf_iter_next_instance(iter, inst)) {
	case 0:
		break;

	case 1:
		/* Nope, multiple instances. */
		(void) strlcpy(state, "multiple", state_sz);
		goto out;

	default:
		scfdie();
	}

out:
	scf_iter_destroy(iter);
	scf_instance_destroy(inst);
	scf_service_destroy(svc);
}

static void
print_application_properties(scf_walkinfo_t *wip, scf_snapshot_t *snap)
{
	scf_iter_t *pg_iter, *prop_iter, *val_iter;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *val;
	scf_pg_tmpl_t *pt;
	scf_prop_tmpl_t *prt;
	char *pg_name_buf = safe_malloc(max_scf_name_length + 1);
	char *prop_name_buf = safe_malloc(max_scf_name_length + 1);
	char *snap_name = safe_malloc(max_scf_name_length + 1);
	char *val_buf = safe_malloc(max_scf_value_length + 1);
	char *desc, *cp;
	scf_type_t type;
	int i, j, k;
	uint8_t vis;

	if ((pg_iter = scf_iter_create(h)) == NULL ||
	    (prop_iter = scf_iter_create(h)) == NULL ||
	    (val_iter = scf_iter_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (pt = scf_tmpl_pg_create(h)) == NULL ||
	    (prt = scf_tmpl_prop_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL)
		scfdie();

	if (scf_iter_instance_pgs_typed_composed(pg_iter, wip->inst, snap,
	    SCF_PG_APP_DEFAULT) == -1)
		scfdie();

	/*
	 * Format for output:
	 *	pg (pgtype)
	 *	 description
	 *	pg/prop (proptype) = <value> <value>
	 *	 description
	 */
	while ((i = scf_iter_next_pg(pg_iter, pg)) == 1) {
		int tmpl = 0;

		if (scf_pg_get_name(pg, pg_name_buf, max_scf_name_length) < 0)
			scfdie();
		if (scf_snapshot_get_name(snap, snap_name,
		    max_scf_name_length) < 0)
			scfdie();

		if (scf_tmpl_get_by_pg_name(wip->fmri, snap_name, pg_name_buf,
		    SCF_PG_APP_DEFAULT, pt, 0) == 0)
			tmpl = 1;
		else
			tmpl = 0;

		(void) printf("%s (%s)\n", pg_name_buf, SCF_PG_APP_DEFAULT);

		if (tmpl == 1 && scf_tmpl_pg_description(pt, NULL, &desc) > 0) {
			(void) printf("  %s\n", desc);
			free(desc);
		}

		if (scf_iter_pg_properties(prop_iter, pg) == -1)
			scfdie();
		while ((j = scf_iter_next_property(prop_iter, prop)) == 1) {
			if (scf_property_get_name(prop, prop_name_buf,
			    max_scf_name_length) < 0)
				scfdie();
			if (scf_property_type(prop, &type) == -1)
				scfdie();

			if ((tmpl == 1) &&
			    (scf_tmpl_get_by_prop(pt, prop_name_buf, prt,
			    0) != 0))
				tmpl = 0;

			if (tmpl == 1 &&
			    scf_tmpl_prop_visibility(prt, &vis) != -1 &&
			    vis == SCF_TMPL_VISIBILITY_HIDDEN)
				continue;

			(void) printf("%s/%s (%s) = ", pg_name_buf,
			    prop_name_buf, scf_type_to_string(type));

			if (scf_iter_property_values(val_iter, prop) == -1)
				scfdie();

			while ((k = scf_iter_next_value(val_iter, val)) == 1) {
				if (scf_value_get_as_string(val, val_buf,
				    max_scf_value_length + 1) < 0)
					scfdie();
				if (strpbrk(val_buf, " \t\n\"()") != NULL) {
					(void) printf("\"");
					for (cp = val_buf; *cp != '\0'; ++cp) {
						if (*cp == '"' || *cp == '\\')
							(void) putc('\\',
							    stdout);

						(void) putc(*cp, stdout);
					}
					(void) printf("\"");
				} else {
					(void) printf("%s ", val_buf);
				}
			}

			(void) printf("\n");

			if (k == -1)
				scfdie();

			if (tmpl == 1 && scf_tmpl_prop_description(prt, NULL,
			    &desc) > 0) {
				(void) printf("  %s\n", desc);
				free(desc);
			}
		}
		if (j == -1)
			scfdie();
	}
	if (i == -1)
		scfdie();


	scf_iter_destroy(pg_iter);
	scf_iter_destroy(prop_iter);
	scf_iter_destroy(val_iter);
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_tmpl_pg_destroy(pt);
	scf_tmpl_prop_destroy(prt);
	scf_pg_destroy(pg);
	free(pg_name_buf);
	free(prop_name_buf);
	free(snap_name);
	free(val_buf);
}

static void
print_detailed_dependency(scf_propertygroup_t *pg)
{
	scf_property_t *eprop;
	scf_iter_t *iter;
	scf_type_t ty;
	char *val_buf;
	int i;

	if ((eprop = scf_property_create(h)) == NULL ||
	    (iter = scf_iter_create(h)) == NULL)
		scfdie();

	val_buf = safe_malloc(max_scf_value_length + 1);

	if (scf_pg_get_property(pg, SCF_PROPERTY_ENTITIES, eprop) !=
	    SCF_SUCCESS ||
	    scf_property_type(eprop, &ty) != SCF_SUCCESS ||
	    ty != SCF_TYPE_FMRI)
		return;

	(void) printf("%-*s", DETAILED_WIDTH, gettext("dependency"));

	/* Print the grouping */
	if (pg_get_single_val(pg, SCF_PROPERTY_GROUPING, SCF_TYPE_ASTRING,
	    val_buf, max_scf_value_length + 1, 0) == 0)
		(void) fputs(val_buf, stdout);
	else
		(void) putchar('?');

	(void) putchar('/');

	if (pg_get_single_val(pg, SCF_PROPERTY_RESTART_ON, SCF_TYPE_ASTRING,
	    val_buf, max_scf_value_length + 1, 0) == 0)
		(void) fputs(val_buf, stdout);
	else
		(void) putchar('?');

	/* Print the dependency entities. */
	if (scf_iter_property_values(iter, eprop) == -1)
		scfdie();

	while ((i = scf_iter_next_value(iter, g_val)) == 1) {
		char state[MAX_SCF_STATE_STRING_SZ];

		if (scf_value_get_astring(g_val, val_buf,
		    max_scf_value_length + 1) < 0)
			scfdie();

		(void) putchar(' ');
		(void) fputs(val_buf, stdout);

		/* Print the state. */
		state[0] = '-';
		state[1] = '\0';

		get_fmri_state(val_buf, state, sizeof (state));

		(void) printf(" (%s)", state);
	}
	if (i == -1)
		scfdie();

	(void) putchar('\n');

	free(val_buf);
	scf_iter_destroy(iter);
	scf_property_destroy(eprop);
}

/* ARGSUSED */
static int
print_detailed(void *unused, scf_walkinfo_t *wip)
{
	scf_snapshot_t *snap;
	scf_propertygroup_t *rpg;
	scf_iter_t *pg_iter;

	char *buf;
	char *timebuf;
	size_t tbsz;
	int ret;
	uint64_t c;
	int temp, perm;
	struct timeval tv;
	time_t stime;
	struct tm *tmp;
	int restarter_spec;
	int restarter_ret;

	const char * const fmt = "%-*s%s\n";

	assert(wip->pg == NULL);

	rpg = scf_pg_create(h);
	if (rpg == NULL)
		scfdie();

	if (first_paragraph)
		first_paragraph = 0;
	else
		(void) putchar('\n');

	buf = safe_malloc(max_scf_fmri_length + 1);

	if (scf_instance_to_fmri(wip->inst, buf, max_scf_fmri_length + 1) != -1)
		(void) printf(fmt, DETAILED_WIDTH, "fmri", buf);

	if (common_name_buf == NULL)
		common_name_buf = safe_malloc(max_scf_value_length + 1);

	if (inst_get_single_val(wip->inst, SCF_PG_TM_COMMON_NAME, locale,
	    SCF_TYPE_USTRING, common_name_buf, max_scf_value_length, 0, 1, 1)
	    == 0)
		(void) printf(fmt, DETAILED_WIDTH, gettext("name"),
		    common_name_buf);
	else if (inst_get_single_val(wip->inst, SCF_PG_TM_COMMON_NAME, "C",
	    SCF_TYPE_USTRING, common_name_buf, max_scf_value_length, 0, 1, 1)
	    == 0)
		(void) printf(fmt, DETAILED_WIDTH, gettext("name"),
		    common_name_buf);

	if (g_zonename != NULL)
		(void) printf(fmt, DETAILED_WIDTH, gettext("zone"), g_zonename);

	/*
	 * Synthesize an 'enabled' property that hides the enabled_ovr
	 * implementation from the user.  If the service has been temporarily
	 * set to a state other than its permanent value, alert the user with
	 * a '(temporary)' message.
	 */
	perm = instance_enabled(wip->inst, B_FALSE);
	temp = instance_enabled(wip->inst, B_TRUE);
	if (temp != -1) {
		if (temp != perm)
			(void) printf(gettext("%-*s%s (temporary)\n"),
			    DETAILED_WIDTH, gettext("enabled"),
			    temp ? gettext("true") : gettext("false"));
		else
			(void) printf(fmt, DETAILED_WIDTH,
			    gettext("enabled"), temp ? gettext("true") :
			    gettext("false"));
	} else if (perm != -1) {
		(void) printf(fmt, DETAILED_WIDTH, gettext("enabled"),
		    perm ? gettext("true") : gettext("false"));
	}

	/*
	 * Property values may be longer than max_scf_fmri_length, but these
	 * shouldn't be, so we'll just reuse buf.  The user can use svcprop if
	 * they suspect something fishy.
	 */
	if (scf_instance_get_pg(wip->inst, SCF_PG_RESTARTER, rpg) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		scf_pg_destroy(rpg);
		rpg = NULL;
	}

	if (rpg) {
		if (pg_get_single_val(rpg, scf_property_state, SCF_TYPE_ASTRING,
		    buf, max_scf_fmri_length + 1, 0) == 0)
			(void) printf(fmt, DETAILED_WIDTH, gettext("state"),
			    buf);

		if (pg_get_single_val(rpg, scf_property_next_state,
		    SCF_TYPE_ASTRING, buf, max_scf_fmri_length + 1, 0) == 0)
			(void) printf(fmt, DETAILED_WIDTH,
			    gettext("next_state"), buf);

		if (pg_get_single_val(rpg, SCF_PROPERTY_STATE_TIMESTAMP,
		    SCF_TYPE_TIME, &tv, NULL, 0) == 0) {
			stime = tv.tv_sec;
			tmp = localtime(&stime);
			for (tbsz = 50; ; tbsz *= 2) {
				timebuf = safe_malloc(tbsz);
				if (strftime(timebuf, tbsz, NULL, tmp) != 0)
					break;
				free(timebuf);
			}
			(void) printf(fmt, DETAILED_WIDTH,
			    gettext("state_time"),
			    timebuf);
			free(timebuf);
		}

		if (pg_get_single_val(rpg, SCF_PROPERTY_ALT_LOGFILE,
		    SCF_TYPE_ASTRING, buf, max_scf_fmri_length + 1, 0) == 0)
			(void) printf(fmt, DETAILED_WIDTH,
			    gettext("alt_logfile"), buf);

		if (pg_get_single_val(rpg, SCF_PROPERTY_LOGFILE,
		    SCF_TYPE_ASTRING, buf, max_scf_fmri_length + 1, 0) == 0)
			(void) printf(fmt, DETAILED_WIDTH, gettext("logfile"),
			    buf);
	}

	if (inst_get_single_val(wip->inst, SCF_PG_GENERAL,
	    SCF_PROPERTY_RESTARTER, SCF_TYPE_ASTRING, buf,
	    max_scf_fmri_length + 1, 0, 0, 1) == 0)
		(void) printf(fmt, DETAILED_WIDTH, gettext("restarter"), buf);
	else
		(void) printf(fmt, DETAILED_WIDTH, gettext("restarter"),
		    SCF_SERVICE_STARTD);

	free(buf);

	/*
	 * Use the restarter specific routine to print the ctids, if available.
	 * If restarter specific action is available and it fails, then die.
	 */
	restarter_ret = ctids_by_restarter(wip, &c, 1, 0,
	    &restarter_spec, print_ctid_header, print_ctid_detailed);
	if (restarter_spec == 1) {
		if (restarter_ret != 0)
			uu_die(gettext("Unable to get restarter for %s"),
			    wip->fmri);
		goto restarter_common;
	}

	if (rpg) {
		scf_iter_t *iter;

		if ((iter = scf_iter_create(h)) == NULL)
			scfdie();

		if (scf_pg_get_property(rpg, scf_property_contract, g_prop) ==
		    0) {
			if (scf_property_is_type(g_prop, SCF_TYPE_COUNT) == 0) {

				/* Callback to print ctid header */
				print_ctid_header();

				if (scf_iter_property_values(iter, g_prop) != 0)
					scfdie();

				for (;;) {
					ret = scf_iter_next_value(iter, g_val);
					if (ret == -1)
						scfdie();
					if (ret == 0)
						break;

					if (scf_value_get_count(g_val, &c) != 0)
						scfdie();

					/* Callback to print contract id. */
					print_ctid_detailed(c);
				}

				(void) putchar('\n');
			} else {
				if (scf_error() != SCF_ERROR_TYPE_MISMATCH)
					scfdie();
			}
		} else {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();
		}

		scf_iter_destroy(iter);
	} else {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();
	}

restarter_common:
	scf_pg_destroy(rpg);

	/* Dependencies. */
	if ((pg_iter = scf_iter_create(h)) == NULL)
		scfdie();

	snap = get_running_snapshot(wip->inst);

	if (scf_iter_instance_pgs_typed_composed(pg_iter, wip->inst, snap,
	    SCF_GROUP_DEPENDENCY) != SCF_SUCCESS)
		scfdie();

	while ((ret = scf_iter_next_pg(pg_iter, g_pg)) == 1)
		print_detailed_dependency(g_pg);
	if (ret == -1)
		scfdie();

	scf_iter_destroy(pg_iter);

	if (opt_processes)
		detailed_list_processes(wip);

	/* "application" type property groups */
	if (opt_verbose == 1)
		print_application_properties(wip, snap);

	scf_snapshot_destroy(snap);

	return (0);
}

/* ARGSUSED */
static int
print_log(void *unused, scf_walkinfo_t *wip)
{
	scf_propertygroup_t *rpg;
	char buf[MAXPATHLEN];

	if ((rpg = scf_pg_create(h)) == NULL)
		scfdie();

	if (scf_instance_get_pg(wip->inst, SCF_PG_RESTARTER, rpg) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		goto out;
	}

	if (pg_get_single_val(rpg, SCF_PROPERTY_LOGFILE,
	    SCF_TYPE_ASTRING, buf, sizeof (buf), 0) == 0) {
		(void) printf("%s\n", buf);
	}

out:
	scf_pg_destroy(rpg);

	return (0);
}

int
qsort_str_compare(const void *p1, const void *p2)
{
	return (strcmp((const char *)p1, (const char *)p2));
}

/*
 * get_notify_param_classes()
 * return the fma classes that don't have a tag in fma_tags[], otherwise NULL
 */
static char **
get_notify_param_classes()
{
	scf_handle_t		*h = _scf_handle_create_and_bind(SCF_VERSION);
	scf_instance_t		*inst = scf_instance_create(h);
	scf_snapshot_t		*snap = scf_snapshot_create(h);
	scf_snaplevel_t		*slvl = scf_snaplevel_create(h);
	scf_propertygroup_t	*pg = scf_pg_create(h);
	scf_iter_t		*iter = scf_iter_create(h);
	int size = 4;
	int n = 0;
	size_t sz = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	int err;
	char *pgname = safe_malloc(sz);
	char **buf = safe_malloc(size * sizeof (char *));

	if (h == NULL || inst == NULL || snap == NULL || slvl == NULL ||
	    pg == NULL || iter == NULL) {
		uu_die(gettext("Failed object creation: %s\n"),
		    scf_strerror(scf_error()));
	}

	if (scf_handle_decode_fmri(h, SCF_NOTIFY_PARAMS_INST, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) != 0)
		uu_die(gettext("Failed to decode %s: %s\n"),
		    SCF_NOTIFY_PARAMS_INST, scf_strerror(scf_error()));

	if (scf_instance_get_snapshot(inst, "running", snap) != 0)
		uu_die(gettext("Failed to get snapshot: %s\n"),
		    scf_strerror(scf_error()));

	if (scf_snapshot_get_base_snaplevel(snap, slvl) != 0)
		uu_die(gettext("Failed to get base snaplevel: %s\n"),
		    scf_strerror(scf_error()));

	if (scf_iter_snaplevel_pgs_typed(iter, slvl,
	    SCF_NOTIFY_PARAMS_PG_TYPE) != 0)
		uu_die(gettext("Failed to get iterator: %s\n"),
		    scf_strerror(scf_error()));

	while ((err = scf_iter_next_pg(iter, pg)) == 1) {
		char *c;

		if (scf_pg_get_name(pg, pgname, sz) == -1)
			uu_die(gettext("Failed to get pg name: %s\n"),
			    scf_strerror(scf_error()));
		if ((c = strrchr(pgname, ',')) != NULL)
			*c = '\0';
		if (has_fma_tag(pgname))
			continue;
		if (!is_fma_token(pgname))
			/*
			 * We don't emmit a warning here so that we don't
			 * pollute the output
			 */
			continue;

		if (n + 1 >= size) {
			size *= 2;
			buf = realloc(buf, size * sizeof (char *));
			if (buf == NULL)
				uu_die(gettext("Out of memory.\n"));
		}
		buf[n] = safe_strdup(pgname);
		++n;
	}
	/*
	 * NULL terminate buf
	 */
	buf[n] = NULL;
	if (err == -1)
		uu_die(gettext("Failed to iterate pgs: %s\n"),
		    scf_strerror(scf_error()));

	/* sort the classes */
	qsort((void *)buf, n, sizeof (char *), qsort_str_compare);

	free(pgname);
	scf_iter_destroy(iter);
	scf_pg_destroy(pg);
	scf_snaplevel_destroy(slvl);
	scf_snapshot_destroy(snap);
	scf_instance_destroy(inst);
	scf_handle_destroy(h);

	return (buf);
}

/*
 * get_fma_notify_params()
 * populates an nvlist_t with notifycation parameters for a given FMA class
 * returns 0 if the nvlist is populated, 1 otherwise;
 */
int
get_fma_notify_params(nvlist_t *nvl, const char *class)
{
	if (_scf_get_fma_notify_params(class, nvl, 0) != 0) {
		/*
		 * if the preferences have just been deleted
		 * or does not exist, just skip.
		 */
		if (scf_error() != SCF_ERROR_NOT_FOUND &&
		    scf_error() != SCF_ERROR_DELETED)
			uu_warn(gettext(
			    "Failed get_fma_notify_params %s\n"),
			    scf_strerror(scf_error()));

		return (1);
	}

	return (0);
}

/*
 * print_notify_fma()
 * outputs the notification paramets of FMA events.
 * It first outputs classes in fma_tags[], then outputs the other classes
 * sorted alphabetically
 */
static void
print_notify_fma(void)
{
	nvlist_t *nvl;
	char **tmp = NULL;
	char **classes, *p;
	const char *class;
	uint32_t i;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		uu_die(gettext("Out of memory.\n"));

	for (i = 0; (class = get_fma_class(i)) != NULL; ++i) {
		if (get_fma_notify_params(nvl, class) == 0)
			listnotify_print(nvl, get_fma_tag(i));
	}

	if ((classes = get_notify_param_classes()) == NULL)
		goto cleanup;

	tmp = classes;
	for (p = *tmp; p; ++tmp, p = *tmp) {
		if (get_fma_notify_params(nvl, p) == 0)
			listnotify_print(nvl, re_tag(p));

		free(p);
	}

	free(classes);

cleanup:
	nvlist_free(nvl);
}

/*
 * print_notify_fmri()
 * prints notifycation parameters for an SMF instance.
 */
static void
print_notify_fmri(const char *fmri)
{
	nvlist_t *nvl;

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		uu_die(gettext("Out of memory.\n"));

	if (_scf_get_svc_notify_params(fmri, nvl, SCF_TRANSITION_ALL, 0, 0) !=
	    SCF_SUCCESS) {
		if (scf_error() != SCF_ERROR_NOT_FOUND &&
		    scf_error() != SCF_ERROR_DELETED)
			uu_warn(gettext(
			    "Failed _scf_get_svc_notify_params: %s\n"),
			    scf_strerror(scf_error()));
	} else {
		if (strcmp(SCF_INSTANCE_GLOBAL, fmri) == 0)
			safe_printf(
			    gettext("System wide notification parameters:\n"));
		safe_printf("%s:\n", fmri);
		listnotify_print(nvl, NULL);
	}
	nvlist_free(nvl);
}

/*
 * print_notify_special()
 * prints notification parameters for FMA events and system wide SMF state
 * transitions parameters
 */
static void
print_notify_special()
{
	safe_printf("Notification parameters for FMA Events\n");
	print_notify_fma();
	print_notify_fmri(SCF_INSTANCE_GLOBAL);
}

/*
 * print_notify()
 * callback function to print notification parameters for SMF state transition
 * instances. It skips global and notify-params instances as they should be
 * printed by print_notify_special()
 */
/* ARGSUSED */
static int
print_notify(void *unused, scf_walkinfo_t *wip)
{
	if (strcmp(SCF_INSTANCE_GLOBAL, wip->fmri) == 0 ||
	    strcmp(SCF_NOTIFY_PARAMS_INST, wip->fmri) == 0)
		return (0);

	print_notify_fmri(wip->fmri);

	return (0);
}

/*
 * Append a one-lined description of each process in inst's contract(s) and
 * return the augmented string.
 */
static char *
add_processes(scf_walkinfo_t *wip, char *line, scf_propertygroup_t *lpg)
{
	pid_t *pids = NULL;
	uint_t i, n = 0;

	if (lpg == NULL) {
		if (instance_processes(wip->inst, wip->fmri, &pids, &n) != 0)
			return (line);
	} else {
		/* Legacy services */
		scf_iter_t *iter;

		if ((iter = scf_iter_create(h)) == NULL)
			scfdie();

		(void) propvals_to_pids(lpg, scf_property_contract, &pids, &n,
		    g_prop, g_val, iter);

		scf_iter_destroy(iter);
	}

	if (n == 0)
		return (line);

	qsort(pids, n, sizeof (*pids), pidcmp);

	for (i = 0; i < n; ++i) {
		char *cp, stime[9];
		psinfo_t psi;
		struct tm *tm;
		int len = 1 + 15 + 8 + 3 + 6 + 1 + PRFNSZ;

		if (get_psinfo(pids[i], &psi) != 0)
			continue;

		line = realloc(line, strlen(line) + len);
		if (line == NULL)
			uu_die(gettext("Out of memory.\n"));

		cp = strchr(line, '\0');

		tm = localtime(&psi.pr_start.tv_sec);

		/*
		 * Print time if started within the past 24 hours, print date
		 * if within the past 12 months, print year if started greater
		 * than 12 months ago.
		 */
		if (now - psi.pr_start.tv_sec < 24 * 60 * 60)
			(void) strftime(stime, sizeof (stime),
			    gettext(FORMAT_TIME), tm);
		else if (now - psi.pr_start.tv_sec < 12 * 30 * 24 * 60 * 60)
			(void) strftime(stime, sizeof (stime),
			    gettext(FORMAT_DATE), tm);
		else
			(void) strftime(stime, sizeof (stime),
			    gettext(FORMAT_YEAR), tm);

		(void) snprintf(cp, len, "\n               %-8s   %6ld %.*s",
		    stime, pids[i], PRFNSZ, psi.pr_fname);
	}

	free(pids);

	return (line);
}

/*ARGSUSED*/
static int
list_instance(void *unused, scf_walkinfo_t *wip)
{
	struct avl_string *lp;
	char *cp;
	int i;
	uu_avl_index_t idx;

	/*
	 * If the user has specified a restarter, check for a match first
	 */
	if (restarters != NULL) {
		struct pfmri_list *rest;
		int match;
		char *restarter_fmri;
		const char *scope_name, *svc_name, *inst_name, *pg_name;

		/* legacy services don't have restarters */
		if (wip->pg != NULL)
			return (0);

		restarter_fmri = safe_malloc(max_scf_fmri_length + 1);

		if (inst_get_single_val(wip->inst, SCF_PG_GENERAL,
		    SCF_PROPERTY_RESTARTER, SCF_TYPE_ASTRING, restarter_fmri,
		    max_scf_fmri_length + 1, 0, 0, 1) != 0)
			(void) strcpy(restarter_fmri, SCF_SERVICE_STARTD);

		if (scf_parse_svc_fmri(restarter_fmri, &scope_name, &svc_name,
		    &inst_name, &pg_name, NULL) != SCF_SUCCESS) {
			free(restarter_fmri);
			return (0);
		}

		match = 0;
		for (rest = restarters; rest != NULL; rest = rest->next) {
			if (strcmp(rest->scope, scope_name) == 0 &&
			    strcmp(rest->service, svc_name) == 0 &&
			    strcmp(rest->instance, inst_name) == 0)
				match = 1;
		}

		free(restarter_fmri);

		if (!match)
			return (0);
	}

	if (wip->pg == NULL && ht_buckets != NULL && ht_add(wip->fmri)) {
		/* It was already there. */
		return (0);
	}

	lp = safe_malloc(sizeof (*lp));

	lp->str = NULL;
	for (i = 0; i < opt_cnum; ++i) {
		columns[opt_columns[i]].sprint(&lp->str, wip);
	}
	cp = lp->str + strlen(lp->str);
	cp--;
	while (*cp == ' ')
		cp--;
	*(cp+1) = '\0';

	/* If we're supposed to list the processes, too, do that now. */
	if (opt_processes)
		lp->str = add_processes(wip, lp->str, wip->pg);

	/* Create the sort key. */
	cp = lp->key = safe_malloc(sortkey_sz);
	for (i = 0; i < opt_snum; ++i) {
		int j = opt_sort[i] & 0xff;

		assert(columns[j].get_sortkey != NULL);
		columns[j].get_sortkey(cp, opt_sort[i] & ~0xff, wip);
		cp += columns[j].sortkey_width;
	}

	/* Insert into AVL tree. */
	uu_avl_node_init(lp, &lp->node, lines_pool);
	(void) uu_avl_find(lines, lp, NULL, &idx);
	uu_avl_insert(lines, lp, idx);

	return (0);
}

static int
list_if_enabled(void *unused, scf_walkinfo_t *wip)
{
	if (wip->pg != NULL ||
	    instance_enabled(wip->inst, B_FALSE) == 1 ||
	    instance_enabled(wip->inst, B_TRUE) == 1)
		return (list_instance(unused, wip));

	return (0);
}

/*
 * Service FMRI selection: Lookup and call list_instance() for the instances.
 * Instance FMRI selection: Lookup and call list_instance().
 *
 * Note: This is shoehorned into a walk_dependencies() callback prototype so
 * it can be used in list_dependencies.
 */
static int
list_svc_or_inst_fmri(void *complain, scf_walkinfo_t *wip)
{
	char *fmri;
	const char *svc_name, *inst_name, *pg_name, *save;
	scf_iter_t *iter;
	int ret;

	fmri = safe_strdup(wip->fmri);

	if (scf_parse_svc_fmri(fmri, NULL, &svc_name, &inst_name, &pg_name,
	    NULL) != SCF_SUCCESS) {
		if (complain)
			uu_warn(gettext("FMRI \"%s\" is invalid.\n"),
			    wip->fmri);
		exit_status = UU_EXIT_FATAL;
		free(fmri);
		return (0);
	}

	/*
	 * Yes, this invalidates *_name, but we only care whether they're NULL
	 * or not.
	 */
	free(fmri);

	if (svc_name == NULL || pg_name != NULL) {
		if (complain)
			uu_warn(gettext("FMRI \"%s\" does not designate a "
			    "service or instance.\n"), wip->fmri);
		return (0);
	}

	if (inst_name != NULL) {
		/* instance */
		if (scf_handle_decode_fmri(h, wip->fmri, wip->scope, wip->svc,
		    wip->inst, NULL, NULL, 0) != SCF_SUCCESS) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();

			if (complain)
				uu_warn(gettext(
				    "Instance \"%s\" does not exist.\n"),
				    wip->fmri);
			return (0);
		}

		return (list_instance(NULL, wip));
	}

	/* service: Walk the instances. */
	if (scf_handle_decode_fmri(h, wip->fmri, wip->scope, wip->svc, NULL,
	    NULL, NULL, 0) != SCF_SUCCESS) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		if (complain)
			uu_warn(gettext("Service \"%s\" does not exist.\n"),
			    wip->fmri);

		exit_status = UU_EXIT_FATAL;

		return (0);
	}

	iter = scf_iter_create(h);
	if (iter == NULL)
		scfdie();

	if (scf_iter_service_instances(iter, wip->svc) != SCF_SUCCESS)
		scfdie();

	if ((fmri = malloc(max_scf_fmri_length + 1)) == NULL) {
		scf_iter_destroy(iter);
		exit_status = UU_EXIT_FATAL;
		return (0);
	}

	save = wip->fmri;
	wip->fmri = fmri;
	while ((ret = scf_iter_next_instance(iter, wip->inst)) == 1) {
		if (scf_instance_to_fmri(wip->inst, fmri,
		    max_scf_fmri_length + 1) <= 0)
			scfdie();
		(void) list_instance(NULL, wip);
	}
	free(fmri);
	wip->fmri = save;
	if (ret == -1)
		scfdie();

	exit_status = UU_EXIT_OK;

	scf_iter_destroy(iter);

	return (0);
}

/*
 * Dependency selection: Straightforward since each instance lists the
 * services it depends on.
 */

static void
walk_dependencies(scf_walkinfo_t *wip, scf_walk_callback callback, void *data)
{
	scf_snapshot_t *snap;
	scf_iter_t *iter, *viter;
	int ret, vret;
	char *dep;

	assert(wip->inst != NULL);

	if ((iter = scf_iter_create(h)) == NULL ||
	    (viter = scf_iter_create(h)) == NULL)
		scfdie();

	snap = get_running_snapshot(wip->inst);

	if (scf_iter_instance_pgs_typed_composed(iter, wip->inst, snap,
	    SCF_GROUP_DEPENDENCY) != SCF_SUCCESS)
		scfdie();

	dep = safe_malloc(max_scf_value_length + 1);

	while ((ret = scf_iter_next_pg(iter, g_pg)) == 1) {
		scf_type_t ty;

		/* Ignore exclude_any dependencies. */
		if (scf_pg_get_property(g_pg, SCF_PROPERTY_GROUPING, g_prop) !=
		    SCF_SUCCESS) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();

			continue;
		}

		if (scf_property_type(g_prop, &ty) != SCF_SUCCESS)
			scfdie();

		if (ty != SCF_TYPE_ASTRING)
			continue;

		if (scf_property_get_value(g_prop, g_val) != SCF_SUCCESS) {
			if (scf_error() != SCF_ERROR_CONSTRAINT_VIOLATED)
				scfdie();

			continue;
		}

		if (scf_value_get_astring(g_val, dep,
		    max_scf_value_length + 1) < 0)
			scfdie();

		if (strcmp(dep, SCF_DEP_EXCLUDE_ALL) == 0)
			continue;

		if (scf_pg_get_property(g_pg, SCF_PROPERTY_ENTITIES, g_prop) !=
		    SCF_SUCCESS) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();

			continue;
		}

		if (scf_iter_property_values(viter, g_prop) != SCF_SUCCESS)
			scfdie();

		while ((vret = scf_iter_next_value(viter, g_val)) == 1) {
			if (scf_value_get_astring(g_val, dep,
			    max_scf_value_length + 1) < 0)
				scfdie();

			wip->fmri = dep;
			if (callback(data, wip) != 0)
				goto out;
		}
		if (vret == -1)
			scfdie();
	}
	if (ret == -1)
		scfdie();

out:
	scf_iter_destroy(viter);
	scf_iter_destroy(iter);
	scf_snapshot_destroy(snap);
}

static int
list_dependencies(void *data, scf_walkinfo_t *wip)
{
	walk_dependencies(wip, list_svc_or_inst_fmri, data);
	return (0);
}


/*
 * Dependent selection: The "providing" service's or instance's FMRI is parsed
 * into the provider_* variables, the instances are walked, and any instance
 * which lists an FMRI which parses to these components is selected.  This is
 * inefficient in the face of multiple operands, but that should be uncommon.
 */

static char *provider_scope;
static char *provider_svc;
static char *provider_inst;	/* NULL for services */

/*ARGSUSED*/
static int
check_against_provider(void *arg, scf_walkinfo_t *wip)
{
	char *cfmri;
	const char *scope_name, *svc_name, *inst_name, *pg_name;
	int *matchp = arg;

	cfmri = safe_strdup(wip->fmri);

	if (scf_parse_svc_fmri(cfmri, &scope_name, &svc_name, &inst_name,
	    &pg_name, NULL) != SCF_SUCCESS) {
		free(cfmri);
		return (0);
	}

	if (svc_name == NULL || pg_name != NULL) {
		free(cfmri);
		return (0);
	}

	/*
	 * If the user has specified an instance, then also match dependencies
	 * on the service itself.
	 */
	*matchp = (strcmp(provider_scope, scope_name) == 0 &&
	    strcmp(provider_svc, svc_name) == 0 &&
	    (provider_inst == NULL ? (inst_name == NULL) :
	    (inst_name == NULL || strcmp(provider_inst, inst_name) == 0)));

	free(cfmri);

	/* Stop on matches. */
	return (*matchp);
}

static int
list_if_dependent(void *unused, scf_walkinfo_t *wip)
{
	/* Only proceed if this instance depends on provider_*. */
	int match = 0;

	(void) walk_dependencies(wip, check_against_provider, &match);

	if (match)
		return (list_instance(unused, wip));

	return (0);
}

/*ARGSUSED*/
static int
list_dependents(void *unused, scf_walkinfo_t *wip)
{
	char *save;
	int ret;

	if (scf_scope_get_name(wip->scope, provider_scope,
	    max_scf_fmri_length) <= 0 ||
	    scf_service_get_name(wip->svc, provider_svc,
	    max_scf_fmri_length) <= 0)
		scfdie();

	save = provider_inst;
	if (wip->inst == NULL)
		provider_inst = NULL;
	else if (scf_instance_get_name(wip->inst, provider_inst,
	    max_scf_fmri_length) <= 0)
		scfdie();

	ret = scf_walk_fmri(h, 0, NULL, 0, list_if_dependent, NULL, NULL,
	    uu_warn);

	provider_inst = save;

	return (ret);
}

/*
 * main() & helpers
 */

static void
add_sort_column(const char *col, int reverse)
{
	int i;

	++opt_snum;

	opt_sort = realloc(opt_sort, opt_snum * sizeof (*opt_sort));
	if (opt_sort == NULL)
		uu_die(gettext("Too many sort criteria: out of memory.\n"));

	for (i = 0; i < ncolumns; ++i) {
		if (strcasecmp(col, columns[i].name) == 0)
			break;
	}

	if (i < ncolumns)
		opt_sort[opt_snum - 1] = (reverse ? i | 0x100 : i);
	else
		uu_die(gettext("Unrecognized sort column \"%s\".\n"), col);

	sortkey_sz += columns[i].sortkey_width;
}

static void
add_restarter(const char *fmri)
{
	char *cfmri;
	const char *pg_name;
	struct pfmri_list *rest;

	cfmri = safe_strdup(fmri);
	rest = safe_malloc(sizeof (*rest));

	if (scf_parse_svc_fmri(cfmri, &rest->scope, &rest->service,
	    &rest->instance, &pg_name, NULL) != SCF_SUCCESS)
		uu_die(gettext("Restarter FMRI \"%s\" is invalid.\n"), fmri);

	if (rest->instance == NULL || pg_name != NULL)
		uu_die(gettext("Restarter FMRI \"%s\" does not designate an "
		    "instance.\n"), fmri);

	rest->next = restarters;
	restarters = rest;
	return;

err:
	free(cfmri);
	free(rest);
}

/* ARGSUSED */
static int
line_cmp(const void *l_arg, const void *r_arg, void *private)
{
	const struct avl_string *l = l_arg;
	const struct avl_string *r = r_arg;

	return (memcmp(l->key, r->key, sortkey_sz));
}

/* ARGSUSED */
static int
print_line(void *e, void *private)
{
	struct avl_string *lp = e;

	(void) puts(lp->str);

	return (UU_WALK_NEXT);
}

/* ARGSUSED */
static void
errignore(const char *str, ...)
{}

int
main(int argc, char **argv)
{
	char opt, opt_mode;
	int i, n;
	char *columns_str = NULL;
	char *cp;
	const char *progname;
	int err, missing = 1, ignored, *errarg;
	uint_t nzents = 0, zent = 0;
	zoneid_t *zids = NULL;
	char zonename[ZONENAME_MAX];
	void (*errfunc)(const char *, ...);

	int show_all = 0;
	int show_header = 1;
	int show_zones = 0;

	const char * const options = "aHpvno:R:s:S:dDlL?xZz:";

	(void) setlocale(LC_ALL, "");

	locale = setlocale(LC_MESSAGES, NULL);
	if (locale) {
		locale = safe_strdup(locale);
		_scf_sanitize_locale(locale);
	}

	(void) textdomain(TEXT_DOMAIN);
	progname = uu_setpname(argv[0]);

	exit_status = UU_EXIT_OK;

	max_scf_name_length = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);
	max_scf_value_length = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	max_scf_fmri_length = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	max_scf_type_length = scf_limit(SCF_LIMIT_MAX_PG_TYPE_LENGTH);

	if (max_scf_name_length == -1 || max_scf_value_length == -1 ||
	    max_scf_fmri_length == -1 || max_scf_type_length == -1)
		scfdie();

	now = time(NULL);
	assert(now != -1);

	/*
	 * opt_mode is the mode of operation.  0 for plain, 'd' for
	 * dependencies, 'D' for dependents, and 'l' for detailed (long).  We
	 * need to know now so we know which options are valid.
	 */
	opt_mode = 0;
	while ((opt = getopt(argc, argv, options)) != -1) {
		switch (opt) {
		case '?':
			if (optopt == '?') {
				print_help(progname);
				return (UU_EXIT_OK);
			} else {
				argserr(progname);
				/* NOTREACHED */
			}

		case 'd':
		case 'D':
		case 'l':
		case 'L':
			if (opt_mode != 0)
				argserr(progname);

			opt_mode = opt;
			break;

		case 'n':
			if (opt_mode != 0)
				argserr(progname);

			opt_mode = opt;
			break;

		case 'x':
			if (opt_mode != 0)
				argserr(progname);

			opt_mode = opt;
			break;

		default:
			break;
		}
	}

	sortkey_sz = 0;

	optind = 1;	/* Reset getopt() */
	while ((opt = getopt(argc, argv, options)) != -1) {
		switch (opt) {
		case 'a':
			if (opt_mode != 0)
				argserr(progname);
			show_all = 1;
			break;

		case 'H':
			if (opt_mode == 'l' || opt_mode == 'x')
				argserr(progname);
			show_header = 0;
			break;

		case 'p':
			if (opt_mode == 'x')
				argserr(progname);
			opt_processes = 1;
			break;

		case 'v':
			opt_verbose = 1;
			break;

		case 'o':
			if (opt_mode == 'l' || opt_mode == 'x')
				argserr(progname);
			columns_str = optarg;
			break;

		case 'R':
			if (opt_mode != 0 || opt_mode == 'x')
				argserr(progname);

			add_restarter(optarg);
			break;

		case 's':
		case 'S':
			if (opt_mode != 0)
				argserr(progname);

			add_sort_column(optarg, optopt == 'S');
			break;

		case 'd':
		case 'D':
		case 'l':
		case 'L':
		case 'n':
		case 'x':
			assert(opt_mode == optopt);
			break;

		case 'z':
			if (getzoneid() != GLOBAL_ZONEID)
				uu_die(gettext("svcs -z may only be used from "
				    "the global zone\n"));
			if (show_zones)
				argserr(progname);

			opt_zone = optarg;
			break;

		case 'Z':
			if (getzoneid() != GLOBAL_ZONEID)
				uu_die(gettext("svcs -Z may only be used from "
				    "the global zone\n"));
			if (opt_zone != NULL)
				argserr(progname);

			show_zones = 1;
			break;

		case '?':
			argserr(progname);

		default:
			assert(0);
			abort();
		}
	}

	/*
	 * -a is only meaningful when given no arguments
	 */
	if (show_all && optind != argc)
		uu_warn(gettext("-a ignored when used with arguments.\n"));

	while (show_zones) {
		uint_t found;

		if (zone_list(NULL, &nzents) != 0)
			uu_die(gettext("could not get number of zones"));

		if ((zids = malloc(nzents * sizeof (zoneid_t))) == NULL) {
			uu_die(gettext("could not allocate array for "
			    "%d zone IDs"), nzents);
		}

		found = nzents;

		if (zone_list(zids, &found) != 0)
			uu_die(gettext("could not get zone list"));

		/*
		 * If the number of zones has not changed between our calls to
		 * zone_list(), we're done -- otherwise, we must free our array
		 * of zone IDs and take another lap.
		 */
		if (found == nzents)
			break;

		free(zids);
	}

	argc -= optind;
	argv += optind;

again:
	h = scf_handle_create(SCF_VERSION);
	if (h == NULL)
		scfdie();

	if (opt_zone != NULL || zids != NULL) {
		scf_value_t *zone;

		assert(opt_zone == NULL || zids == NULL);

		if (opt_zone == NULL) {
			if (getzonenamebyid(zids[zent++],
			    zonename, sizeof (zonename)) < 0) {
				uu_warn(gettext("could not get name for "
				    "zone %d; ignoring"), zids[zent - 1]);
				goto nextzone;
			}

			g_zonename = zonename;
		} else {
			g_zonename = opt_zone;
		}

		if ((zone = scf_value_create(h)) == NULL)
			scfdie();

		if (scf_value_set_astring(zone, g_zonename) != SCF_SUCCESS)
			scfdie();

		if (scf_handle_decorate(h, "zone", zone) != SCF_SUCCESS)
			uu_die(gettext("invalid zone '%s'\n"), g_zonename);

		scf_value_destroy(zone);
	}

	if (scf_handle_bind(h) == -1) {
		if (g_zonename != NULL) {
			uu_warn(gettext("Could not bind to repository "
			    "server for zone %s: %s\n"), g_zonename,
			    scf_strerror(scf_error()));

			if (!show_zones)
				return (UU_EXIT_FATAL);

			goto nextzone;
		}

		uu_die(gettext("Could not bind to repository server: %s.  "
		    "Exiting.\n"), scf_strerror(scf_error()));
	}

	if ((g_pg = scf_pg_create(h)) == NULL ||
	    (g_prop = scf_property_create(h)) == NULL ||
	    (g_val = scf_value_create(h)) == NULL)
		scfdie();

	if (show_zones) {
		/*
		 * It's hard to avoid editorializing here, but suffice it to
		 * say that scf_walk_fmri() takes an error handler, the
		 * interface to which has been regrettably misdesigned:  the
		 * handler itself takes exclusively a string -- even though
		 * scf_walk_fmri() has detailed, programmatic knowledge
		 * of the error condition at the time it calls its errfunc.
		 * That is, only the error message and not the error semantics
		 * are given to the handler.  This is poor interface at best,
		 * but it is particularly problematic when we are talking to
		 * multiple repository servers (as when we are iterating over
		 * all zones) as we do not want to treat failure to find a
		 * match in one zone as overall failure.  Ideally, we would
		 * simply ignore SCF_MSG_PATTERN_NOINSTANCE and correctly
		 * process the others, but alas, no such interface exists --
		 * and we must settle for instead ignoring all errfunc-called
		 * errors in the case that we are iterating over all zones...
		 */
		errfunc = errignore;
		errarg = missing ? &missing : &ignored;
		missing = 0;
	} else {
		errfunc = uu_warn;
		errarg = &exit_status;
	}

	/*
	 * If we're in long mode, take care of it now before we deal with the
	 * sorting and the columns, since we won't use them anyway.
	 */
	if (opt_mode == 'l') {
		if (argc == 0)
			argserr(progname);

		if ((err = scf_walk_fmri(h, argc, argv, SCF_WALK_MULTIPLE,
		    print_detailed, NULL, errarg, errfunc)) != 0) {
			uu_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}

		goto nextzone;
	}

	if (opt_mode == 'L') {
		if ((err = scf_walk_fmri(h, argc, argv, SCF_WALK_MULTIPLE,
		    print_log, NULL, &exit_status, uu_warn)) != 0) {
			uu_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}

		goto nextzone;
	}

	if (opt_mode == 'n') {
		print_notify_special();
		if ((err = scf_walk_fmri(h, argc, argv, SCF_WALK_MULTIPLE,
		    print_notify, NULL, errarg, errfunc)) != 0) {
			uu_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}

		goto nextzone;
	}

	if (opt_mode == 'x') {
		explain(opt_verbose, argc, argv);
		goto nextzone;
	}

	if (columns_str == NULL) {
		if (opt_snum == 0) {
			if (show_zones)
				add_sort_column("zone", 0);

			/* Default sort. */
			add_sort_column("state", 0);
			add_sort_column("stime", 0);
			add_sort_column("fmri", 0);
		}

		if (!opt_verbose) {
			columns_str = safe_strdup(show_zones ?
			    "zone,state,stime,fmri" : "state,stime,fmri");
		} else {
			columns_str = safe_strdup(show_zones ?
			    "zone,state,nstate,stime,ctid,fmri" :
			    "state,nstate,stime,ctid,fmri");
		}
	}

	if (opt_columns == NULL) {
		/* Decode columns_str into opt_columns. */
		line_sz = 0;

		opt_cnum = 1;
		for (cp = columns_str; *cp != '\0'; ++cp)
			if (*cp == ',')
				++opt_cnum;

		if (*columns_str == '\0')
			uu_die(gettext("No columns specified.\n"));

		opt_columns = malloc(opt_cnum * sizeof (*opt_columns));
		if (opt_columns == NULL)
			uu_die(gettext("Too many columns.\n"));

		for (n = 0; *columns_str != '\0'; ++n) {
			i = getcolumnopt(&columns_str);
			if (i == -1)
				uu_die(gettext("Unknown column \"%s\".\n"),
				    columns_str);

			if (strcmp(columns[i].name, "N") == 0 ||
			    strcmp(columns[i].name, "SN") == 0 ||
			    strcmp(columns[i].name, "NSTA") == 0 ||
			    strcmp(columns[i].name, "NSTATE") == 0)
				opt_nstate_shown = 1;

			opt_columns[n] = i;
			line_sz += columns[i].width + 1;
		}

		if ((lines_pool = uu_avl_pool_create("lines_pool",
		    sizeof (struct avl_string), offsetof(struct avl_string,
		    node), line_cmp, UU_AVL_DEBUG)) == NULL ||
		    (lines = uu_avl_create(lines_pool, NULL, 0)) == NULL)
			uu_die(gettext("Unexpected libuutil error: %s\n"),
			    uu_strerror(uu_error()));
	}

	switch (opt_mode) {
	case 0:
		/*
		 * If we already have a hash table (e.g., because we are
		 * processing multiple zones), destroy it before creating
		 * a new one.
		 */
		if (ht_buckets != NULL)
			ht_free();

		ht_init();

		/* Always show all FMRIs when given arguments or restarters */
		if (argc != 0 || restarters != NULL)
			show_all =  1;

		if ((err = scf_walk_fmri(h, argc, argv,
		    SCF_WALK_MULTIPLE | SCF_WALK_LEGACY,
		    show_all ? list_instance : list_if_enabled, NULL,
		    errarg, errfunc)) != 0) {
			uu_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}
		break;

	case 'd':
		if (argc == 0)
			argserr(progname);

		if ((err = scf_walk_fmri(h, argc, argv,
		    SCF_WALK_MULTIPLE, list_dependencies, NULL,
		    errarg, errfunc)) != 0) {
			uu_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}
		break;

	case 'D':
		if (argc == 0)
			argserr(progname);

		provider_scope = safe_malloc(max_scf_fmri_length);
		provider_svc = safe_malloc(max_scf_fmri_length);
		provider_inst = safe_malloc(max_scf_fmri_length);

		if ((err = scf_walk_fmri(h, argc, argv,
		    SCF_WALK_MULTIPLE | SCF_WALK_SERVICE,
		    list_dependents, NULL, &exit_status, uu_warn)) != 0) {
			uu_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}

		free(provider_scope);
		free(provider_svc);
		free(provider_inst);
		break;

	case 'n':
		break;

	default:
		assert(0);
		abort();
	}

nextzone:
	if (show_zones && zent < nzents && exit_status == 0) {
		scf_handle_destroy(h);
		goto again;
	}

	if (show_zones && exit_status == 0)
		exit_status = missing;

	if (opt_columns == NULL)
		return (exit_status);

	if (show_header)
		print_header();

	(void) uu_avl_walk(lines, print_line, NULL, 0);

	return (exit_status);
}
