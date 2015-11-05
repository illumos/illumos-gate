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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2015, Joyent, Inc. All rights reserved.
 */

/*
 * svcadm - request adminstrative actions for service instances
 */

#include <locale.h>
#include <libintl.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <sys/contract/process.h>
#include <libuutil.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <procfs.h>
#include <assert.h>
#include <errno.h>
#include <zone.h>

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

/* Must be a power of two */
#define	HT_BUCKETS	64

/*
 * Exit codes for enable and disable -s.
 */
#define	EXIT_SVC_FAILURE	3
#define	EXIT_DEP_FAILURE	4

#define	WALK_FLAGS	(SCF_WALK_UNIPARTIAL | SCF_WALK_MULTIPLE)

/*
 * How long we will wait (in seconds) for a service to change state
 * before re-checking its dependencies.
 */
#define	WAIT_INTERVAL		3

#define	bad_error(func, err)						\
	uu_panic("%s:%d: %s() failed with unexpected error %d.\n",	\
	    __FILE__, __LINE__, (func), (err));

struct ht_elt {
	struct ht_elt	*next;
	boolean_t	active;
	char		str[1];
};


scf_handle_t *h;
ssize_t max_scf_fmri_sz;
static const char *emsg_permission_denied;
static const char *emsg_nomem;
static const char *emsg_create_pg_perm_denied;
static const char *emsg_pg_perm_denied;
static const char *emsg_prop_perm_denied;
static const char *emsg_no_service;

static int exit_status = 0;
static int verbose = 0;
static char *scratch_fmri;
static char *g_zonename = NULL;
static char svcstate[80];
static boolean_t svcsearch = B_FALSE;

static struct ht_elt **visited;

void do_scfdie(int lineno) __NORETURN;
static void usage_milestone(void) __NORETURN;
static void set_astring_prop(const char *, const char *, const char *,
    uint32_t, const char *, const char *);
static void pr_warn(const char *format, ...);

/*
 * Visitors from synch.c, needed for enable -s and disable -s.
 */
extern int is_enabled(scf_instance_t *);
extern int has_potential(scf_instance_t *, int);

void
do_scfdie(int lineno)
{
	scf_error_t err;

	switch (err = scf_error()) {
	case SCF_ERROR_CONNECTION_BROKEN:
		uu_die(gettext("Connection to repository server broken.  "
		    "Exiting.\n"));
		/* NOTREACHED */

	case SCF_ERROR_BACKEND_READONLY:
		uu_die(gettext("Repository is read-only.  Exiting.\n"));
		/* NOTREACHED */

	default:
#ifdef NDEBUG
		uu_die(gettext("Unexpected libscf error: %s.  Exiting.\n"),
		    scf_strerror(err));
#else
		uu_die("Unexpected libscf error on line %d: %s.\n", lineno,
		    scf_strerror(err));
#endif
	}
}

#define	scfdie()	do_scfdie(__LINE__)

static void
usage()
{
	(void) fprintf(stderr, gettext(
	"Usage: %1$s [-S <state>] [-v] [-Z | -z zone] [cmd [args ... ]]\n\n"
	"\t%1$s enable [-rst] [<service> ...]\t- enable and online service(s)\n"
	"\t%1$s disable [-st] [<service> ...]\t- disable and offline "
	"service(s)\n"
	"\t%1$s restart [-d] [<service> ...]\t- restart specified service(s)\n"
	"\t%1$s refresh [<service> ...]\t\t- re-read service configuration\n"
	"\t%1$s mark [-It] <state> [<service> ...] - set maintenance state\n"
	"\t%1$s clear [<service> ...]\t\t- clear maintenance state\n"
	"\t%1$s milestone [-d] <milestone>\t- advance to a service milestone\n"
	"\n\t"
	"Services can be specified using an FMRI, abbreviation, or fnmatch(5)\n"
	"\tpattern, as shown in these examples for svc:/network/smtp:sendmail\n"
	"\n"
	"\t%1$s <cmd> svc:/network/smtp:sendmail\n"
	"\t%1$s <cmd> network/smtp:sendmail\n"
	"\t%1$s <cmd> network/*mail\n"
	"\t%1$s <cmd> network/smtp\n"
	"\t%1$s <cmd> smtp:sendmail\n"
	"\t%1$s <cmd> smtp\n"
	"\t%1$s <cmd> sendmail\n"), uu_getpname());

	exit(UU_EXIT_USAGE);
}


/*
 * FMRI hash table for recursive enable.
 */

static uint32_t
hash_fmri(const char *str)
{
	uint32_t h = 0, g;
	const char *p;

	/* Generic hash function from uts/common/os/modhash.c . */
	for (p = str; *p != '\0'; ++p) {
		h = (h << 4) + *p;
		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

/*
 * Return 1 if str has been visited, 0 if it has not, and -1 if memory could not
 * be allocated.
 */
static int
visited_find_or_add(const char *str, struct ht_elt **hep)
{
	uint32_t h;
	uint_t i;
	struct ht_elt *he;

	h = hash_fmri(str);
	i = h & (HT_BUCKETS - 1);

	for (he = visited[i]; he != NULL; he = he->next) {
		if (strcmp(he->str, str) == 0) {
			if (hep)
				*hep = he;
			return (1);
		}
	}

	he = malloc(offsetof(struct ht_elt, str) + strlen(str) + 1);
	if (he == NULL)
		return (-1);

	(void) strcpy(he->str, str);

	he->next = visited[i];
	visited[i] = he;

	if (hep)
		*hep = he;
	return (0);
}


/*
 * Returns 0, ECANCELED if pg is deleted, ENOENT if propname doesn't exist,
 * EINVAL if the property is not of boolean type or has no values, and E2BIG
 * if it has more than one value.  *bp is set if 0 or E2BIG is returned.
 */
int
get_bool_prop(scf_propertygroup_t *pg, const char *propname, uint8_t *bp)
{
	scf_property_t *prop;
	scf_value_t *val;
	int ret;

	if ((prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL)
		scfdie();

	if (scf_pg_get_property(pg, propname, prop) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			ret = ECANCELED;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_NOT_SET:
			assert(0);
			abort();
			/* NOTREACHED */

		default:
			scfdie();
		}
	}

	if (scf_property_get_value(prop, val) == 0) {
		ret = 0;
	} else {
		switch (scf_error()) {
		case SCF_ERROR_DELETED:
			ret = ENOENT;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			ret = EINVAL;
			goto out;

		case SCF_ERROR_CONSTRAINT_VIOLATED:
			ret = E2BIG;
			break;

		case SCF_ERROR_NOT_SET:
			assert(0);
			abort();
			/* NOTREACHED */

		default:
			scfdie();
		}
	}

	if (scf_value_get_boolean(val, bp) != 0) {
		if (scf_error() != SCF_ERROR_TYPE_MISMATCH)
			scfdie();

		ret = EINVAL;
		goto out;
	}

out:
	scf_value_destroy(val);
	scf_property_destroy(prop);
	return (ret);
}

/*
 * Returns 0, EPERM, or EROFS.
 */
static int
set_bool_prop(scf_propertygroup_t *pg, const char *propname, boolean_t b)
{
	scf_value_t *v;
	scf_transaction_t *tx;
	scf_transaction_entry_t *ent;
	int ret = 0, r;

	if ((tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL ||
	    (v = scf_value_create(h)) == NULL)
		scfdie();

	scf_value_set_boolean(v, b);

	for (;;) {
		if (scf_transaction_start(tx, pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			default:
				scfdie();
			}
		}

		if (scf_transaction_property_change_type(tx, ent, propname,
		    SCF_TYPE_BOOLEAN) != 0) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();

			if (scf_transaction_property_new(tx, ent, propname,
			    SCF_TYPE_BOOLEAN) != 0)
				scfdie();
		}

		r = scf_entry_add_value(ent, v);
		assert(r == 0);

		r = scf_transaction_commit(tx);
		if (r == 1)
			break;

		scf_transaction_reset(tx);

		if (r != 0) {
			switch (scf_error()) {
			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			default:
				scfdie();
			}
		}

		if (scf_pg_update(pg) == -1)
			scfdie();
	}

out:
	scf_transaction_destroy(tx);
	scf_entry_destroy(ent);
	scf_value_destroy(v);
	return (ret);
}

/*
 * Gets the single astring value of the propname property of pg.  prop & v are
 * scratch space.  Returns the length of the string on success or
 *   -ENOENT - pg has no property named propname
 *   -E2BIG - property has no values or multiple values
 *   -EINVAL - property type is not compatible with astring
 */
ssize_t
get_astring_prop(const scf_propertygroup_t *pg, const char *propname,
    scf_property_t *prop, scf_value_t *v, char *buf, size_t bufsz)
{
	ssize_t sz;

	if (scf_pg_get_property(pg, propname, prop) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		return (-ENOENT);
	}

	if (scf_property_get_value(prop, v) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
			return (-E2BIG);

		default:
			scfdie();
		}
	}

	sz = scf_value_get_astring(v, buf, bufsz);
	if (sz < 0) {
		if (scf_error() != SCF_ERROR_TYPE_MISMATCH)
			scfdie();

		return (-EINVAL);
	}

	return (sz);
}

/*
 * Returns 0 or EPERM.
 */
static int
pg_get_or_add(const scf_instance_t *inst, const char *pgname,
    const char *pgtype, uint32_t pgflags, scf_propertygroup_t *pg)
{
again:
	if (scf_instance_get_pg(inst, pgname, pg) == 0)
		return (0);

	if (scf_error() != SCF_ERROR_NOT_FOUND)
		scfdie();

	if (scf_instance_add_pg(inst, pgname, pgtype, pgflags, pg) == 0)
		return (0);

	switch (scf_error()) {
	case SCF_ERROR_EXISTS:
		goto again;

	case SCF_ERROR_PERMISSION_DENIED:
		return (EPERM);

	default:
		scfdie();
		/* NOTREACHED */
	}
}

static int
my_ct_name(char *out, size_t len)
{
	ct_stathdl_t st;
	char *ct_fmri;
	ctid_t ct;
	int fd, errno, ret;

	if ((ct = getctid()) == -1)
		uu_die(gettext("Could not get contract id for process"));

	fd = contract_open(ct, "process", "status", O_RDONLY);

	if ((errno = ct_status_read(fd, CTD_ALL, &st)) != 0)
		uu_warn(gettext("Could not read status of contract "
		    "%ld: %s.\n"), ct, strerror(errno));

	if ((errno = ct_pr_status_get_svc_fmri(st, &ct_fmri)) != 0)
		uu_warn(gettext("Could not get svc_fmri for contract "
		    "%ld: %s.\n"), ct, strerror(errno));

	ret = strlcpy(out, ct_fmri, len);

	ct_status_free(st);
	(void) close(fd);

	return (ret);
}

/*
 * Set auxiliary_tty and auxiliary_fmri properties in restarter_actions pg to
 * communicate whether the action is requested from a tty and the fmri of the
 * responsible process.
 *
 * Returns 0, EPERM, or EROFS
 */
static int
restarter_setup(const char *fmri, const scf_instance_t *inst)
{
	boolean_t b = B_FALSE;
	scf_propertygroup_t *pg = NULL;
	int ret = 0;

	if ((pg = scf_pg_create(h)) == NULL)
		scfdie();

	if (pg_get_or_add(inst, SCF_PG_RESTARTER_ACTIONS,
	    SCF_PG_RESTARTER_ACTIONS_TYPE, SCF_PG_RESTARTER_ACTIONS_FLAGS,
	    pg) == EPERM) {
		if (!verbose)
			uu_warn(emsg_permission_denied, fmri);
		else
			uu_warn(emsg_create_pg_perm_denied, fmri,
			    SCF_PG_RESTARTER_ACTIONS);

		ret = EPERM;
		goto out;
	}

	/* Set auxiliary_tty property */
	if (isatty(STDIN_FILENO))
		b = B_TRUE;

	/* Create and set state to disabled */
	switch (set_bool_prop(pg, SCF_PROPERTY_AUX_TTY, b) != 0) {
	case 0:
		break;

	case EPERM:
		if (!verbose)
			uu_warn(emsg_permission_denied, fmri);
		else
			uu_warn(emsg_prop_perm_denied, fmri,
			    SCF_PG_RESTARTER_ACTIONS, SCF_PROPERTY_AUX_TTY);

		ret = EPERM;
		goto out;
		/* NOTREACHED */

	case EROFS:
		/* Shouldn't happen, but it can. */
		if (!verbose)
			uu_warn(gettext("%s: Repository read-only.\n"), fmri);
		else
			uu_warn(gettext("%s: Could not set %s/%s "
			    "(repository read-only).\n"), fmri,
			    SCF_PG_RESTARTER_ACTIONS, SCF_PROPERTY_AUX_TTY);

		ret = EROFS;
		goto out;
		/* NOTREACHED */

	default:
		scfdie();
	}

	if (my_ct_name(scratch_fmri, max_scf_fmri_sz) > 0) {
		set_astring_prop(fmri, SCF_PG_RESTARTER_ACTIONS,
		    SCF_PG_RESTARTER_ACTIONS_TYPE,
		    SCF_PG_RESTARTER_ACTIONS_FLAGS,
		    SCF_PROPERTY_AUX_FMRI, scratch_fmri);
	} else {
		uu_warn(gettext("%s: Could not set %s/%s: "
		    "my_ct_name failed.\n"), fmri,
		    SCF_PG_RESTARTER_ACTIONS, SCF_PROPERTY_AUX_FMRI);
	}

out:
	scf_pg_destroy(pg);
	return (ret);
}

/*
 * Enable or disable inst, per enable.  If temp is true, set
 * general_ovr/enabled.  Otherwise set general/enabled and delete
 * general_ovr/enabled if it exists (order is important here: we don't want the
 * enabled status to glitch).
 */
static void
set_inst_enabled(const char *fmri, scf_instance_t *inst, boolean_t temp,
    boolean_t enable)
{
	scf_propertygroup_t *pg;
	uint8_t b;
	const char *pgname = NULL;	/* For emsg_pg_perm_denied */
	int r;

	pg = scf_pg_create(h);
	if (pg == NULL)
		scfdie();

	if (restarter_setup(fmri, inst))
		goto out;

	/*
	 * An instance's configuration is incomplete if general/enabled
	 * doesn't exist. Create both the property group and property
	 * here if they don't exist.
	 */
	pgname = SCF_PG_GENERAL;
	if (pg_get_or_add(inst, pgname, SCF_PG_GENERAL_TYPE,
	    SCF_PG_GENERAL_FLAGS, pg) != 0)
		goto eperm;

	if (get_bool_prop(pg, SCF_PROPERTY_ENABLED, &b) != 0) {
		/* Create and set state to disabled */
		switch (set_bool_prop(pg, SCF_PROPERTY_ENABLED, B_FALSE) != 0) {
		case 0:
			break;

		case EPERM:
			goto eperm;

		case EROFS:
			/* Shouldn't happen, but it can. */
			if (!verbose)
				uu_warn(gettext("%s: Repository read-only.\n"),
				    fmri);
			else
				uu_warn(gettext("%s: Could not set %s/%s "
				    "(repository read-only).\n"), fmri,
				    SCF_PG_GENERAL, SCF_PROPERTY_ENABLED);
			goto out;

		default:
			assert(0);
			abort();
		}
	}

	if (temp) {
		/* Set general_ovr/enabled */
		pgname = SCF_PG_GENERAL_OVR;
		if (pg_get_or_add(inst, pgname, SCF_PG_GENERAL_OVR_TYPE,
		    SCF_PG_GENERAL_OVR_FLAGS, pg) != 0)
			goto eperm;

		switch (set_bool_prop(pg, SCF_PROPERTY_ENABLED, enable) != 0) {
		case 0:
			break;

		case EPERM:
			goto eperm;

		case EROFS:
			/* Shouldn't happen, but it can. */
			if (!verbose)
				uu_warn(gettext("%s: Repository read-only.\n"),
				    fmri);
			else
				uu_warn(gettext("%s: Could not set %s/%s "
				    "(repository read-only).\n"), fmri,
				    SCF_PG_GENERAL_OVR, SCF_PROPERTY_ENABLED);
			goto out;

		default:
			assert(0);
			abort();
		}

		if (verbose)
			(void) printf(enable ?
			    gettext("%s temporarily enabled.\n") :
			    gettext("%s temporarily disabled.\n"), fmri);
	} else {
again:
		/*
		 * Both pg and property should exist since we created
		 * them earlier. However, there's still a chance that
		 * someone may have deleted the property out from under
		 * us.
		 */
		if (pg_get_or_add(inst, pgname, SCF_PG_GENERAL_TYPE,
		    SCF_PG_GENERAL_FLAGS, pg) != 0)
			goto eperm;

		switch (set_bool_prop(pg, SCF_PROPERTY_ENABLED, enable)) {
		case 0:
			break;

		case EPERM:
			goto eperm;

		case EROFS:
			/*
			 * If general/enabled is already set the way we want,
			 * proceed.
			 */
			switch (get_bool_prop(pg, SCF_PROPERTY_ENABLED, &b)) {
			case 0:
				if ((b != 0) == (enable != B_FALSE))
					break;
				/* FALLTHROUGH */

			case ENOENT:
			case EINVAL:
			case E2BIG:
				if (!verbose)
					uu_warn(gettext("%s: Repository "
					    "read-only.\n"), fmri);
				else
					uu_warn(gettext("%s: Could not set "
					    "%s/%s (repository read-only).\n"),
					    fmri, SCF_PG_GENERAL,
					    SCF_PROPERTY_ENABLED);
				goto out;

			case ECANCELED:
				goto again;

			default:
				assert(0);
				abort();
			}
			break;

		default:
			assert(0);
			abort();
		}

		pgname = SCF_PG_GENERAL_OVR;
		r = scf_instance_delete_prop(inst, pgname,
		    SCF_PROPERTY_ENABLED);
		switch (r) {
		case 0:
			break;

		case ECANCELED:
			uu_warn(emsg_no_service, fmri);
			goto out;

		case EPERM:
			goto eperm;

		case EACCES:
			uu_warn(gettext("Could not delete %s/%s "
			    "property of %s: backend access denied.\n"),
			    pgname, SCF_PROPERTY_ENABLED, fmri);
			goto out;

		case EROFS:
			uu_warn(gettext("Could not delete %s/%s "
			    "property of %s: backend is read-only.\n"),
			    pgname, SCF_PROPERTY_ENABLED, fmri);
			goto out;

		default:
			bad_error("scf_instance_delete_prop", r);
		}

		if (verbose)
			(void) printf(enable ?  gettext("%s enabled.\n") :
			    gettext("%s disabled.\n"), fmri);
	}

	scf_pg_destroy(pg);
	return;

eperm:
	assert(pgname != NULL);
	if (!verbose)
		uu_warn(emsg_permission_denied, fmri);
	else
		uu_warn(emsg_pg_perm_denied, fmri, pgname);

out:
	scf_pg_destroy(pg);
	exit_status = 1;
}

/*
 * Set inst to the instance which corresponds to fmri.  If fmri identifies
 * a service with a single instance, get that instance.
 *
 * Fails with
 *   ENOTSUP - fmri has an unsupported scheme
 *   EINVAL - fmri is invalid
 *   ENOTDIR - fmri does not identify a service or instance
 *   ENOENT - could not locate instance
 *   E2BIG - fmri is a service with multiple instances (warning not printed)
 */
static int
get_inst_mult(const char *fmri, scf_instance_t *inst)
{
	char *cfmri;
	const char *svc_name, *inst_name, *pg_name;
	scf_service_t *svc;
	scf_instance_t *inst2;
	scf_iter_t *iter;
	int ret;

	if (strncmp(fmri, "lrc:", sizeof ("lrc:") - 1) == 0) {
		uu_warn(gettext("FMRI \"%s\" is a legacy service.\n"), fmri);
		exit_status = 1;
		return (ENOTSUP);
	}

	cfmri = strdup(fmri);
	if (cfmri == NULL)
		uu_die(emsg_nomem);

	if (scf_parse_svc_fmri(cfmri, NULL, &svc_name, &inst_name, &pg_name,
	    NULL) != SCF_SUCCESS) {
		free(cfmri);
		uu_warn(gettext("FMRI \"%s\" is invalid.\n"), fmri);
		exit_status = 1;
		return (EINVAL);
	}

	free(cfmri);

	if (svc_name == NULL || pg_name != NULL) {
		uu_warn(gettext(
		    "FMRI \"%s\" does not designate a service or instance.\n"),
		    fmri);
		exit_status = 1;
		return (ENOTDIR);
	}

	if (inst_name != NULL) {
		if (scf_handle_decode_fmri(h, fmri, NULL, NULL, inst, NULL,
		    NULL, SCF_DECODE_FMRI_EXACT) == 0)
			return (0);

		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		uu_warn(gettext("No such instance \"%s\".\n"), fmri);
		exit_status = 1;

		return (ENOENT);
	}

	if ((svc = scf_service_create(h)) == NULL ||
	    (inst2 = scf_instance_create(h)) == NULL ||
	    (iter = scf_iter_create(h)) == NULL)
		scfdie();

	if (scf_handle_decode_fmri(h, fmri, NULL, svc, NULL, NULL, NULL,
	    SCF_DECODE_FMRI_EXACT) != SCF_SUCCESS) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		uu_warn(emsg_no_service, fmri);
		exit_status = 1;

		ret = ENOENT;
		goto out;
	}

	/* If the service has only one child, use it. */
	if (scf_iter_service_instances(iter, svc) != SCF_SUCCESS)
		scfdie();

	ret = scf_iter_next_instance(iter, inst);
	if (ret < 0)
		scfdie();
	if (ret != 1) {
		uu_warn(gettext("Service \"%s\" has no instances.\n"),
		    fmri);
		exit_status = 1;
		ret = ENOENT;
		goto out;
	}

	ret = scf_iter_next_instance(iter, inst2);
	if (ret < 0)
		scfdie();

	if (ret != 0) {
		ret = E2BIG;
		goto out;
	}

	ret = 0;

out:
	scf_iter_destroy(iter);
	scf_instance_destroy(inst2);
	scf_service_destroy(svc);
	return (ret);
}

/*
 * Same as get_inst_mult(), but on E2BIG prints a warning and returns ENOENT.
 */
static int
get_inst(const char *fmri, scf_instance_t *inst)
{
	int r;

	r = get_inst_mult(fmri, inst);
	if (r != E2BIG)
		return (r);

	uu_warn(gettext("operation on service %s is ambiguous; "
	    "instance specification needed.\n"), fmri);
	return (ENOENT);
}

static char *
inst_get_fmri(const scf_instance_t *inst)
{
	ssize_t sz;

	sz = scf_instance_to_fmri(inst, scratch_fmri, max_scf_fmri_sz);
	if (sz < 0)
		scfdie();
	if (sz >= max_scf_fmri_sz)
		uu_die(gettext("scf_instance_to_fmri() returned unexpectedly "
		    "long value.\n"));

	return (scratch_fmri);
}

static ssize_t
dep_get_astring(const char *fmri, const char *pgname,
    const scf_propertygroup_t *pg, const char *propname, scf_property_t *prop,
    scf_value_t *v, char *buf, size_t bufsz)
{
	ssize_t sz;

	sz = get_astring_prop(pg, propname, prop, v, buf, bufsz);
	if (sz >= 0)
		return (sz);

	switch (-sz) {
	case ENOENT:
		uu_warn(gettext("\"%s\" is misconfigured (\"%s\" dependency "
		    "lacks \"%s\" property.)\n"), fmri, pgname, propname);
		return (-1);

	case E2BIG:
		uu_warn(gettext("\"%s\" is misconfigured (\"%s/%s\" property "
		    "is not single-valued.)\n"), fmri, pgname, propname);
		return (-1);

	case EINVAL:
		uu_warn(gettext("\"%s\" is misconfigured (\"%s/%s\" property "
		    "is not of astring type.)\n"), fmri, pgname, propname);
		return (-1);

	default:
		assert(0);
		abort();
		/* NOTREACHED */
	}
}

static boolean_t
multiple_instances(scf_iter_t *iter, scf_value_t *v, char *buf)
{
	int count = 0, r;
	boolean_t ret;
	scf_instance_t *inst;

	inst = scf_instance_create(h);
	if (inst == NULL)
		scfdie();

	for (;;) {
		r = scf_iter_next_value(iter, v);
		if (r == 0) {
			ret = B_FALSE;
			goto out;
		}
		if (r != 1)
			scfdie();

		if (scf_value_get_astring(v, buf, max_scf_fmri_sz) < 0)
			scfdie();

		switch (get_inst_mult(buf, inst)) {
		case 0:
			++count;
			if (count > 1) {
				ret = B_TRUE;
				goto out;
			}
			break;

		case ENOTSUP:
		case EINVAL:
		case ENOTDIR:
		case ENOENT:
			continue;

		case E2BIG:
			ret = B_TRUE;
			goto out;

		default:
			assert(0);
			abort();
		}
	}

out:
	scf_instance_destroy(inst);
	return (ret);
}

/*
 * Enable the service or instance identified by fmri and its dependencies,
 * recursively.  Specifically, call get_inst(fmri), enable the result, and
 * recurse on its restarter and the dependencies.  To avoid duplication of
 * effort or looping around a dependency cycle, each FMRI is entered into the
 * "visited" hash table.  While recursing, the hash table entry is marked
 * "active", so that if we come upon it again, we know we've hit a cycle.
 * exclude_all and optional_all dependencies are ignored.  require_any
 * dependencies are followed only if they comprise a single service; otherwise
 * the user is warned.
 *
 * fmri must point to a writable max_scf_fmri_sz buffer.  Returns EINVAL if fmri
 * is invalid, E2BIG if fmri identifies a service with multiple instances, ELOOP
 * on cycle detection, or 0 on success.
 */
static int
enable_fmri_rec(char *fmri, boolean_t temp)
{
	scf_instance_t *inst;
	scf_snapshot_t *snap;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *v;
	scf_iter_t *pg_iter, *val_iter;
	scf_type_t ty;
	char *buf, *pgname;
	ssize_t name_sz, len, sz;
	int ret;
	struct ht_elt *he;

	len = scf_canonify_fmri(fmri, fmri, max_scf_fmri_sz);
	if (len < 0) {
		assert(scf_error() == SCF_ERROR_INVALID_ARGUMENT);
		return (EINVAL);
	}
	assert(len < max_scf_fmri_sz);

	switch (visited_find_or_add(fmri, &he)) {
	case 0:
		he->active = B_TRUE;
		break;

	case 1:
		return (he->active ? ELOOP : 0);

	case -1:
		uu_die(emsg_nomem);

	default:
		assert(0);
		abort();
	}

	inst = scf_instance_create(h);
	if (inst == NULL)
		scfdie();

	switch (get_inst_mult(fmri, inst)) {
	case 0:
		break;

	case E2BIG:
		he->active = B_FALSE;
		return (E2BIG);

	default:
		he->active = B_FALSE;
		return (0);
	}

	set_inst_enabled(fmri, inst, temp, B_TRUE);

	if ((snap = scf_snapshot_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (v = scf_value_create(h)) == NULL ||
	    (pg_iter = scf_iter_create(h)) == NULL ||
	    (val_iter = scf_iter_create(h)) == NULL)
		scfdie();

	buf = malloc(max_scf_fmri_sz);
	if (buf == NULL)
		uu_die(emsg_nomem);

	name_sz = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);
	if (name_sz < 0)
		scfdie();
	++name_sz;
	pgname = malloc(name_sz);
	if (pgname == NULL)
		uu_die(emsg_nomem);

	if (scf_instance_get_snapshot(inst, "running", snap) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		scf_snapshot_destroy(snap);
		snap = NULL;
	}

	/* Enable restarter */
	if (scf_instance_get_pg_composed(inst, snap, SCF_PG_GENERAL, pg) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		uu_warn(gettext("\"%s\" is misconfigured (lacks \"%s\" "
		    "property group).\n"), fmri, SCF_PG_GENERAL);
		ret = 0;
		goto out;
	}

	sz = get_astring_prop(pg, SCF_PROPERTY_RESTARTER, prop, v, buf,
	    max_scf_fmri_sz);
	if (sz > max_scf_fmri_sz) {
		uu_warn(gettext("\"%s\" is misconfigured (the value of "
		    "\"%s/%s\" is too long).\n"), fmri, SCF_PG_GENERAL,
		    SCF_PROPERTY_RESTARTER);
		ret = 0;
		goto out;
	} else if (sz >= 0) {
		switch (enable_fmri_rec(buf, temp)) {
		case 0:
			break;

		case EINVAL:
			uu_warn(gettext("Restarter FMRI for \"%s\" is "
			    "invalid.\n"), fmri);
			break;

		case E2BIG:
			uu_warn(gettext("Restarter FMRI for \"%s\" identifies "
			    "a service with multiple instances.\n"), fmri);
			break;

		case ELOOP:
			ret = ELOOP;
			goto out;

		default:
			assert(0);
			abort();
		}
	} else if (sz < 0) {
		switch (-sz) {
		case ENOENT:
			break;

		case E2BIG:
			uu_warn(gettext("\"%s\" is misconfigured (\"%s/%s\" "
			    "property is not single-valued).\n"), fmri,
			    SCF_PG_GENERAL, SCF_PROPERTY_RESTARTER);
			ret = 0;
			goto out;

		case EINVAL:
			uu_warn(gettext("\"%s\" is misconfigured (\"%s/%s\" "
			    "property is not of astring type).\n"), fmri,
			    SCF_PG_GENERAL, SCF_PROPERTY_RESTARTER);
			ret = 0;
			goto out;

		default:
			assert(0);
			abort();
		}
	}

	if (scf_iter_instance_pgs_typed_composed(pg_iter, inst, snap,
	    SCF_GROUP_DEPENDENCY) == -1)
		scfdie();

	while (scf_iter_next_pg(pg_iter, pg) > 0) {
		len = scf_pg_get_name(pg, pgname, name_sz);
		if (len < 0)
			scfdie();
		assert(len < name_sz);

		if (dep_get_astring(fmri, pgname, pg, SCF_PROPERTY_TYPE, prop,
		    v, buf, max_scf_fmri_sz) < 0)
			continue;

		if (strcmp(buf, "service") != 0)
			continue;

		if (dep_get_astring(fmri, pgname, pg, SCF_PROPERTY_GROUPING,
		    prop, v, buf, max_scf_fmri_sz) < 0)
			continue;

		if (strcmp(buf, SCF_DEP_EXCLUDE_ALL) == 0 ||
		    strcmp(buf, SCF_DEP_OPTIONAL_ALL) == 0)
			continue;

		if (strcmp(buf, SCF_DEP_REQUIRE_ALL) != 0 &&
		    strcmp(buf, SCF_DEP_REQUIRE_ANY) != 0) {
			uu_warn(gettext("Dependency \"%s\" of \"%s\" has "
			    "unknown type \"%s\".\n"), pgname, fmri, buf);
			continue;
		}

		if (scf_pg_get_property(pg, SCF_PROPERTY_ENTITIES, prop) ==
		    -1) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();

			uu_warn(gettext("\"%s\" is misconfigured (\"%s\" "
			    "dependency lacks \"%s\" property.)\n"), fmri,
			    pgname, SCF_PROPERTY_ENTITIES);
			continue;
		}

		if (scf_property_type(prop, &ty) != SCF_SUCCESS)
			scfdie();

		if (ty != SCF_TYPE_FMRI) {
			uu_warn(gettext("\"%s\" is misconfigured (property "
			    "\"%s/%s\" is not of fmri type).\n"), fmri, pgname,
			    SCF_PROPERTY_ENTITIES);
			continue;
		}

		if (scf_iter_property_values(val_iter, prop) == -1)
			scfdie();

		if (strcmp(buf, SCF_DEP_REQUIRE_ANY) == 0) {
			if (multiple_instances(val_iter, v, buf)) {
				(void) printf(gettext("%s requires one of:\n"),
				    fmri);

				if (scf_iter_property_values(val_iter, prop) !=
				    0)
					scfdie();

				for (;;) {
					int r;

					r = scf_iter_next_value(val_iter, v);
					if (r == 0)
						break;
					if (r != 1)
						scfdie();

					if (scf_value_get_astring(v, buf,
					    max_scf_fmri_sz) < 0)
						scfdie();

					(void) fputs("  ", stdout);
					(void) puts(buf);
				}

				continue;
			}

			/*
			 * Since there's only one instance, we can enable it.
			 * Reset val_iter and continue.
			 */
			if (scf_iter_property_values(val_iter, prop) != 0)
				scfdie();
		}

		for (;;) {
			ret = scf_iter_next_value(val_iter, v);
			if (ret == 0)
				break;
			if (ret != 1)
				scfdie();

			if (scf_value_get_astring(v, buf, max_scf_fmri_sz) ==
			    -1)
				scfdie();

			switch (enable_fmri_rec(buf, temp)) {
			case 0:
				break;

			case EINVAL:
				uu_warn(gettext("\"%s\" dependency of \"%s\" "
				    "has invalid FMRI \"%s\".\n"), pgname,
				    fmri, buf);
				break;

			case E2BIG:
				uu_warn(gettext("%s depends on %s, which has "
				    "multiple instances.\n"), fmri, buf);
				break;

			case ELOOP:
				ret = ELOOP;
				goto out;

			default:
				assert(0);
				abort();
			}
		}
	}

	ret = 0;

out:
	he->active = B_FALSE;

	free(buf);
	free(pgname);

	(void) scf_value_destroy(v);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_snapshot_destroy(snap);
	scf_iter_destroy(pg_iter);
	scf_iter_destroy(val_iter);

	return (ret);
}

/*
 * fmri here is only used for verbose messages.
 */
static void
set_inst_action(const char *fmri, const scf_instance_t *inst,
    const char *action)
{
	scf_transaction_t *tx;
	scf_transaction_entry_t *ent;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *v;
	int ret;
	int64_t t;
	hrtime_t timestamp;

	const char * const scf_pg_restarter_actions = SCF_PG_RESTARTER_ACTIONS;

	if ((pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (v = scf_value_create(h)) == NULL ||
	    (tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL)
		scfdie();

	if (restarter_setup(fmri, inst)) {
		exit_status = 1;
		goto out;
	}

	if (scf_instance_get_pg(inst, scf_pg_restarter_actions, pg) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		/* Try creating the restarter_actions property group. */
		if (scf_instance_add_pg(inst, scf_pg_restarter_actions,
		    SCF_PG_RESTARTER_ACTIONS_TYPE,
		    SCF_PG_RESTARTER_ACTIONS_FLAGS, pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_EXISTS:
				/* Someone must have added it. */
				break;

			case SCF_ERROR_PERMISSION_DENIED:
				if (!verbose)
					uu_warn(emsg_permission_denied, fmri);
				else
					uu_warn(emsg_create_pg_perm_denied,
					    fmri, scf_pg_restarter_actions);
				goto out;

			default:
				scfdie();
			}
		}
	}

	/*
	 * If we lose the transaction race and need to retry, there are 2
	 * potential other winners:
	 *	- another process setting actions
	 *	- the restarter marking the action complete
	 * Therefore, re-read the property every time through the loop before
	 * making any decisions based on their values.
	 */
	do {
		timestamp = gethrtime();

		if (scf_transaction_start(tx, pg) == -1) {
			if (scf_error() != SCF_ERROR_PERMISSION_DENIED)
				scfdie();

			if (!verbose)
				uu_warn(emsg_permission_denied, fmri);
			else
				uu_warn(emsg_pg_perm_denied, fmri,
				    scf_pg_restarter_actions);
			goto out;
		}

		if (scf_pg_get_property(pg, action, prop) == -1) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();
			if (scf_transaction_property_new(tx, ent,
			    action, SCF_TYPE_INTEGER) == -1)
				scfdie();
			goto action_set;
		} else {
			if (scf_transaction_property_change_type(tx, ent,
			    action, SCF_TYPE_INTEGER) == -1)
				scfdie();
		}

		if (scf_property_get_value(prop, v) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONSTRAINT_VIOLATED:
			case SCF_ERROR_NOT_FOUND:
				/* Misconfigured, so set anyway. */
				goto action_set;

			default:
				scfdie();
			}
		} else {
			if (scf_value_get_integer(v, &t) == -1) {
				assert(scf_error() == SCF_ERROR_TYPE_MISMATCH);
				goto action_set;
			}
			if (t > timestamp)
				break;
		}

action_set:
		scf_value_set_integer(v, timestamp);
		if (scf_entry_add_value(ent, v) == -1)
			scfdie();

		ret = scf_transaction_commit(tx);
		if (ret == -1) {
			if (scf_error() != SCF_ERROR_PERMISSION_DENIED)
				scfdie();

			if (!verbose)
				uu_warn(emsg_permission_denied, fmri);
			else
				uu_warn(emsg_prop_perm_denied, fmri,
				    scf_pg_restarter_actions, action);
			scf_transaction_reset(tx);
			goto out;
		}

		scf_transaction_reset(tx);

		if (ret == 0) {
			if (scf_pg_update(pg) == -1)
				scfdie();
		}
	} while (ret == 0);

	if (verbose)
		(void) printf(gettext("Action %s set for %s.\n"), action, fmri);

out:
	scf_value_destroy(v);
	scf_entry_destroy(ent);
	scf_transaction_destroy(tx);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
}

/*
 * Get the state of inst.  state should point to a buffer of
 * MAX_SCF_STATE_STRING_SZ bytes.  Returns 0 on success or -1 if
 *   no restarter property group
 *   no state property
 *   state property is misconfigured (wrong type, not single-valued)
 *   state value is too long
 * In these cases, fmri is used to print a warning.
 *
 * If pgp is non-NULL, a successful call to inst_get_state will store
 * the SCF_PG_RESTARTER property group in *pgp, and the caller will be
 * responsible for calling scf_pg_destroy on the property group.
 */
int
inst_get_state(scf_instance_t *inst, char *state, const char *fmri,
    scf_propertygroup_t **pgp)
{
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *val;
	int ret = -1;
	ssize_t szret;

	if ((pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL)
		scfdie();

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER, pg) != SCF_SUCCESS) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		uu_warn(gettext("%s is misconfigured (lacks \"%s\" property "
		    "group).\n"), fmri ? fmri : inst_get_fmri(inst),
		    SCF_PG_RESTARTER);
		goto out;
	}

	szret = get_astring_prop(pg, SCF_PROPERTY_STATE, prop, val, state,
	    MAX_SCF_STATE_STRING_SZ);
	if (szret < 0) {
		switch (-szret) {
		case ENOENT:
			uu_warn(gettext("%s is misconfigured (\"%s\" property "
			    "group lacks \"%s\" property).\n"),
			    fmri ? fmri : inst_get_fmri(inst), SCF_PG_RESTARTER,
			    SCF_PROPERTY_STATE);
			goto out;

		case E2BIG:
			uu_warn(gettext("%s is misconfigured (\"%s/%s\" "
			    "property is not single-valued).\n"),
			    fmri ? fmri : inst_get_fmri(inst), SCF_PG_RESTARTER,
			    SCF_PROPERTY_STATE);
			goto out;

		case EINVAL:
			uu_warn(gettext("%s is misconfigured (\"%s/%s\" "
			    "property is not of type astring).\n"),
			    fmri ? fmri : inst_get_fmri(inst), SCF_PG_RESTARTER,
			    SCF_PROPERTY_STATE);
			goto out;

		default:
			assert(0);
			abort();
		}
	}
	if (szret >= MAX_SCF_STATE_STRING_SZ) {
		uu_warn(gettext("%s is misconfigured (\"%s/%s\" property value "
		    "is too long).\n"), fmri ? fmri : inst_get_fmri(inst),
		    SCF_PG_RESTARTER, SCF_PROPERTY_STATE);
		goto out;
	}

	ret = 0;
	if (pgp)
		*pgp = pg;

out:
	(void) scf_value_destroy(val);
	scf_property_destroy(prop);
	if (ret || pgp == NULL)
		scf_pg_destroy(pg);
	return (ret);
}

static void
set_astring_prop(const char *fmri, const char *pgname, const char *pgtype,
    uint32_t pgflags, const char *propname, const char *str)
{
	scf_instance_t *inst;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *val;
	scf_transaction_t *tx;
	scf_transaction_entry_t *txent;
	int ret;

	inst = scf_instance_create(h);
	if (inst == NULL)
		scfdie();

	if (get_inst(fmri, inst) != 0)
		return;

	if ((pg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL ||
	    (tx = scf_transaction_create(h)) == NULL ||
	    (txent = scf_entry_create(h)) == NULL)
		scfdie();

	if (scf_instance_get_pg(inst, pgname, pg) != SCF_SUCCESS) {
		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		if (scf_instance_add_pg(inst, pgname, pgtype, pgflags, pg) !=
		    SCF_SUCCESS) {
			switch (scf_error()) {
			case SCF_ERROR_EXISTS:
				if (scf_instance_get_pg(inst, pgname, pg) !=
				    SCF_SUCCESS) {
					if (scf_error() != SCF_ERROR_NOT_FOUND)
						scfdie();

					uu_warn(gettext("Repository write "
					    "contention.\n"));
					goto out;
				}
				break;

			case SCF_ERROR_PERMISSION_DENIED:
				if (!verbose)
					uu_warn(emsg_permission_denied, fmri);
				else
					uu_warn(emsg_create_pg_perm_denied,
					    fmri, pgname);
				goto out;

			default:
				scfdie();
			}
		}
	}

	do {
		if (scf_transaction_start(tx, pg) != SCF_SUCCESS) {
			if (scf_error() != SCF_ERROR_PERMISSION_DENIED)
				scfdie();

			if (!verbose)
				uu_warn(emsg_permission_denied, fmri);
			else
				uu_warn(emsg_pg_perm_denied, fmri, pgname);
			goto out;
		}

		if (scf_transaction_property_change_type(tx, txent, propname,
		    SCF_TYPE_ASTRING) != 0) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();

			if (scf_transaction_property_new(tx, txent, propname,
			    SCF_TYPE_ASTRING) != 0)
				scfdie();
		}

		if (scf_value_set_astring(val, str) != SCF_SUCCESS)
			scfdie();

		if (scf_entry_add_value(txent, val) != SCF_SUCCESS)
			scfdie();

		ret = scf_transaction_commit(tx);
		if (ret == -1) {
			if (scf_error() != SCF_ERROR_PERMISSION_DENIED)
				scfdie();

			if (!verbose)
				uu_warn(emsg_permission_denied, fmri);
			else
				uu_warn(emsg_prop_perm_denied, fmri, pgname,
				    propname);
			goto out;
		}

		if (ret == 0) {
			scf_transaction_reset(tx);

			if (scf_pg_update(pg) == -1)
				scfdie();
		}
	} while (ret == 0);

out:
	scf_transaction_destroy(tx);
	scf_entry_destroy(txent);
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	scf_instance_destroy(inst);
}


/*
 * Flags to control enable and disable actions.
 */
#define	SET_ENABLED	0x1
#define	SET_TEMPORARY	0x2
#define	SET_RECURSIVE	0x4

static int
set_fmri_enabled(void *data, scf_walkinfo_t *wip)
{
	int flags = (int)data;

	assert(wip->inst != NULL);
	assert(wip->pg == NULL);

	if (svcsearch) {
		char state[MAX_SCF_STATE_STRING_SZ];

		if (inst_get_state(wip->inst, state, wip->fmri, NULL) != 0)
			return (0);
		if (strcmp(state, svcstate) != 0)
			return (0);
	}

	if (flags & SET_RECURSIVE) {
		char *fmri_buf = malloc(max_scf_fmri_sz);
		if (fmri_buf == NULL)
			uu_die(emsg_nomem);

		visited = calloc(HT_BUCKETS, sizeof (*visited));
		if (visited == NULL)
			uu_die(emsg_nomem);

		/* scf_walk_fmri() guarantees that fmri isn't too long */
		assert(strlen(wip->fmri) <= max_scf_fmri_sz);
		(void) strlcpy(fmri_buf, wip->fmri, max_scf_fmri_sz);

		switch (enable_fmri_rec(fmri_buf, (flags & SET_TEMPORARY))) {
		case E2BIG:
			uu_warn(gettext("operation on service %s is ambiguous; "
			    "instance specification needed.\n"), fmri_buf);
			break;

		case ELOOP:
			uu_warn(gettext("%s: Dependency cycle detected.\n"),
			    fmri_buf);
		}

		free(visited);
		free(fmri_buf);

	} else {
		set_inst_enabled(wip->fmri, wip->inst,
		    (flags & SET_TEMPORARY) != 0, (flags & SET_ENABLED) != 0);
	}

	return (0);
}

/* ARGSUSED */
static int
wait_fmri_enabled(void *data, scf_walkinfo_t *wip)
{
	scf_propertygroup_t *pg = NULL;
	char state[MAX_SCF_STATE_STRING_SZ];

	assert(wip->inst != NULL);
	assert(wip->pg == NULL);

	do {
		if (pg)
			scf_pg_destroy(pg);
		if (inst_get_state(wip->inst, state, wip->fmri, &pg) != 0) {
			exit_status = EXIT_SVC_FAILURE;
			return (0);
		}

		if (strcmp(state, SCF_STATE_STRING_ONLINE) == 0 ||
		    strcmp(state, SCF_STATE_STRING_DEGRADED) == 0) {
			/*
			 * We're done.
			 */
			goto out;
		}

		if (strcmp(state, SCF_STATE_STRING_MAINT) == 0) {
			/*
			 * The service is ill.
			 */
			uu_warn(gettext("Instance \"%s\" is in maintenance"
			    " state.\n"), wip->fmri);
			exit_status = EXIT_SVC_FAILURE;
			goto out;
		}

		if (!is_enabled(wip->inst)) {
			/*
			 * Someone stepped in and disabled the service.
			 */
			uu_warn(gettext("Instance \"%s\" has been disabled"
			    " by another entity.\n"), wip->fmri);
			exit_status = EXIT_SVC_FAILURE;
			goto out;
		}

		if (!has_potential(wip->inst, B_FALSE)) {
			/*
			 * Our dependencies aren't met.  We'll never
			 * amount to anything.
			 */
			uu_warn(gettext("Instance \"%s\" has unsatisfied"
			    " dependencies.\n"), wip->fmri);
			/*
			 * EXIT_SVC_FAILURE takes precedence over
			 * EXIT_DEP_FAILURE
			 */
			if (exit_status == 0)
				exit_status = EXIT_DEP_FAILURE;
			goto out;
		}
	} while (_scf_pg_wait(pg, WAIT_INTERVAL) >= 0);
	scfdie();
	/* NOTREACHED */

out:
	scf_pg_destroy(pg);
	return (0);
}

/* ARGSUSED */
static int
wait_fmri_disabled(void *data, scf_walkinfo_t *wip)
{
	scf_propertygroup_t *pg = NULL;
	char state[MAX_SCF_STATE_STRING_SZ];

	assert(wip->inst != NULL);
	assert(wip->pg == NULL);

	do {
		if (pg)
			scf_pg_destroy(pg);
		if (inst_get_state(wip->inst, state, wip->fmri, &pg) != 0) {
			exit_status = EXIT_SVC_FAILURE;
			return (0);
		}

		if (strcmp(state, SCF_STATE_STRING_DISABLED) == 0) {
			/*
			 * We're done.
			 */
			goto out;
		}

		if (is_enabled(wip->inst)) {
			/*
			 * Someone stepped in and enabled the service.
			 */
			uu_warn(gettext("Instance \"%s\" has been enabled"
			    " by another entity.\n"), wip->fmri);
			exit_status = EXIT_SVC_FAILURE;
			goto out;
		}

		if (!has_potential(wip->inst, B_TRUE)) {
			/*
			 * Our restarter is hopeless.
			 */
			uu_warn(gettext("Restarter for instance \"%s\" is"
			    " unavailable.\n"), wip->fmri);
			/*
			 * EXIT_SVC_FAILURE takes precedence over
			 * EXIT_DEP_FAILURE
			 */
			if (exit_status == 0)
				exit_status = EXIT_DEP_FAILURE;
			goto out;
		}

	} while (_scf_pg_wait(pg, WAIT_INTERVAL) >= 0);
	scfdie();
	/* NOTREACHED */

out:
	scf_pg_destroy(pg);
	return (0);
}

/* ARGSUSED */
static int
clear_instance(void *data, scf_walkinfo_t *wip)
{
	char state[MAX_SCF_STATE_STRING_SZ];

	assert(wip->inst != NULL);
	assert(wip->pg == NULL);

	if (inst_get_state(wip->inst, state, wip->fmri, NULL) != 0)
		return (0);

	if (svcsearch && strcmp(state, svcstate) != 0)
		return (0);

	if (strcmp(state, SCF_STATE_STRING_MAINT) == 0) {
		set_inst_action(wip->fmri, wip->inst, SCF_PROPERTY_MAINT_OFF);
	} else if (strcmp(state, SCF_STATE_STRING_DEGRADED) ==
	    0) {
		set_inst_action(wip->fmri, wip->inst, SCF_PROPERTY_RESTORE);
	} else {
		uu_warn(gettext("Instance \"%s\" is not in a "
		    "maintenance or degraded state.\n"), wip->fmri);

		exit_status = 1;
	}

	return (0);
}

static int
set_fmri_action(void *action, scf_walkinfo_t *wip)
{
	assert(wip->inst != NULL && wip->pg == NULL);

	if (svcsearch) {
		char state[MAX_SCF_STATE_STRING_SZ];

		if (inst_get_state(wip->inst, state, wip->fmri, NULL) != 0)
			return (0);
		if (strcmp(state, svcstate) != 0)
			return (0);
	}

	set_inst_action(wip->fmri, wip->inst, action);

	return (0);
}

/*
 * Flags to control 'mark' action.
 */
#define	MARK_IMMEDIATE	0x1
#define	MARK_TEMPORARY	0x2

static int
force_degraded(void *data, scf_walkinfo_t *wip)
{
	int flags = (int)data;
	char state[MAX_SCF_STATE_STRING_SZ];

	if (inst_get_state(wip->inst, state, wip->fmri, NULL) != 0) {
		exit_status = 1;
		return (0);
	}

	if (svcsearch && strcmp(state, svcstate) != 0)
		return (0);

	if (strcmp(state, SCF_STATE_STRING_ONLINE) != 0) {
		uu_warn(gettext("Instance \"%s\" is not online.\n"), wip->fmri);
		exit_status = 1;
		return (0);
	}

	set_inst_action(wip->fmri, wip->inst, (flags & MARK_IMMEDIATE) ?
	    SCF_PROPERTY_DEGRADE_IMMEDIATE : SCF_PROPERTY_DEGRADED);

	return (0);
}

static int
force_maintenance(void *data, scf_walkinfo_t *wip)
{
	int flags = (int)data;
	const char *prop;

	if (svcsearch) {
		char state[MAX_SCF_STATE_STRING_SZ];

		if (inst_get_state(wip->inst, state, wip->fmri, NULL) != 0)
			return (0);
		if (strcmp(state, svcstate) != 0)
			return (0);
	}

	if (flags & MARK_IMMEDIATE) {
		prop = (flags & MARK_TEMPORARY) ?
		    SCF_PROPERTY_MAINT_ON_IMMTEMP :
		    SCF_PROPERTY_MAINT_ON_IMMEDIATE;
	} else {
		prop = (flags & MARK_TEMPORARY) ?
		    SCF_PROPERTY_MAINT_ON_TEMPORARY :
		    SCF_PROPERTY_MAINT_ON;
	}

	set_inst_action(wip->fmri, wip->inst, prop);

	return (0);
}

static void
set_milestone(const char *fmri, boolean_t temporary)
{
	scf_instance_t *inst;
	scf_propertygroup_t *pg;
	int r;

	if (temporary) {
		set_astring_prop(SCF_SERVICE_STARTD, SCF_PG_OPTIONS_OVR,
		    SCF_PG_OPTIONS_OVR_TYPE, SCF_PG_OPTIONS_OVR_FLAGS,
		    SCF_PROPERTY_MILESTONE, fmri);
		return;
	}

	if ((inst = scf_instance_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL)
		scfdie();

	if (get_inst(SCF_SERVICE_STARTD, inst) != 0) {
		scf_instance_destroy(inst);
		return;
	}

	/*
	 * Set the persistent milestone before deleting the override so we don't
	 * glitch.
	 */
	set_astring_prop(SCF_SERVICE_STARTD, SCF_PG_OPTIONS,
	    SCF_PG_OPTIONS_TYPE, SCF_PG_OPTIONS_FLAGS, SCF_PROPERTY_MILESTONE,
	    fmri);

	r = scf_instance_delete_prop(inst, SCF_PG_OPTIONS_OVR,
	    SCF_PROPERTY_MILESTONE);
	switch (r) {
	case 0:
		break;

	case ECANCELED:
		uu_warn(emsg_no_service, fmri);
		exit_status = 1;
		goto out;

	case EPERM:
		uu_warn(gettext("Could not delete %s/%s property of "
		    "%s: permission denied.\n"), SCF_PG_OPTIONS_OVR,
		    SCF_PROPERTY_MILESTONE, SCF_SERVICE_STARTD);
		exit_status = 1;
		goto out;

	case EACCES:
		uu_warn(gettext("Could not delete %s/%s property of "
		    "%s: access denied.\n"), SCF_PG_OPTIONS_OVR,
		    SCF_PROPERTY_MILESTONE, SCF_SERVICE_STARTD);
		exit_status = 1;
		goto out;

	case EROFS:
		uu_warn(gettext("Could not delete %s/%s property of "
		    "%s: backend read-only.\n"), SCF_PG_OPTIONS_OVR,
		    SCF_PROPERTY_MILESTONE, SCF_SERVICE_STARTD);
		exit_status = 1;
		goto out;

	default:
		bad_error("scf_instance_delete_prop", r);
	}

out:
	scf_pg_destroy(pg);
	scf_instance_destroy(inst);
}

static char const *milestones[] = {
	SCF_MILESTONE_SINGLE_USER,
	SCF_MILESTONE_MULTI_USER,
	SCF_MILESTONE_MULTI_USER_SERVER,
	NULL
};

static void
usage_milestone(void)
{
	const char **ms;

	(void) fprintf(stderr, gettext(
	"Usage: svcadm milestone [-d] <milestone>\n\n"
	"\t-d\tmake the specified milestone the default for system boot\n\n"
	"\tMilestones can be specified using an FMRI or abbreviation.\n"
	"\tThe major milestones are as follows:\n\n"
	"\tall\n"
	"\tnone\n"));

	for (ms = milestones; *ms != NULL; ms++)
		(void) fprintf(stderr, "\t%s\n", *ms);

	exit(UU_EXIT_USAGE);
}

static const char *
validate_milestone(const char *milestone)
{
	const char **ms;
	const char *tmp;
	size_t len;

	if (strcmp(milestone, "all") == 0)
		return (milestone);

	if (strcmp(milestone, "none") == 0)
		return (milestone);

	/*
	 * Determine if this is a full or partial milestone
	 */
	for (ms = milestones; *ms != NULL; ms++) {
		if ((tmp = strstr(*ms, milestone)) != NULL) {
			len = strlen(milestone);

			/*
			 * The beginning of the string must align with the start
			 * of a milestone fmri, or on the boundary between
			 * elements.  The end of the string must align with the
			 * end of the milestone, or at the instance boundary.
			 */
			if ((tmp == *ms || tmp[-1] == '/') &&
			    (tmp[len] == '\0' || tmp[len] == ':'))
				return (*ms);
		}
	}

	(void) fprintf(stderr,
	    gettext("\"%s\" is not a valid major milestone.\n"), milestone);

	usage_milestone();
	/* NOTREACHED */
}

/*PRINTFLIKE1*/
static void
pr_warn(const char *format, ...)
{
	const char *pname = uu_getpname();
	va_list alist;

	va_start(alist, format);

	if (pname != NULL)
		(void) fprintf(stderr, "%s", pname);

	if (g_zonename != NULL)
		(void) fprintf(stderr, " (%s)", g_zonename);

	(void) fprintf(stderr, ": ");

	(void) vfprintf(stderr, format, alist);

	if (strrchr(format, '\n') == NULL)
		(void) fprintf(stderr, ": %s\n", strerror(errno));

	va_end(alist);
}

/*ARGSUSED*/
static void
quiet(const char *fmt, ...)
{
	/* Do nothing */
}

int
main(int argc, char *argv[])
{
	int o;
	int err;
	int sw_back;
	boolean_t do_zones = B_FALSE;
	boolean_t do_a_zone = B_FALSE;
	char zonename[ZONENAME_MAX];
	uint_t nzents = 0, zent = 0;
	zoneid_t *zids = NULL;
	int orig_optind, orig_argc;
	char **orig_argv;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	(void) uu_setpname(argv[0]);

	if (argc < 2)
		usage();

	max_scf_fmri_sz = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	if (max_scf_fmri_sz < 0)
		scfdie();
	++max_scf_fmri_sz;

	scratch_fmri = malloc(max_scf_fmri_sz);
	if (scratch_fmri == NULL)
		uu_die(emsg_nomem);

	while ((o = getopt(argc, argv, "S:vZz:")) != -1) {
		switch (o) {
		case 'S':
			(void) strlcpy(svcstate, optarg, sizeof (svcstate));
			svcsearch = B_TRUE;
			break;

		case 'v':
			verbose = 1;
			break;

		case 'z':
			if (getzoneid() != GLOBAL_ZONEID)
				uu_die(gettext("svcadm -z may only be used "
				    "from the global zone\n"));
			if (do_zones)
				usage();

			(void) strlcpy(zonename, optarg, sizeof (zonename));
			do_a_zone = B_TRUE;
			break;

		case 'Z':
			if (getzoneid() != GLOBAL_ZONEID)
				uu_die(gettext("svcadm -Z may only be used "
				    "from the global zone\n"));
			if (do_a_zone)
				usage();

			do_zones = B_TRUE;
			break;

		default:
			usage();
		}
	}

	while (do_zones) {
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

	emsg_permission_denied = gettext("%s: Permission denied.\n");
	emsg_nomem = gettext("Out of memory.\n");
	emsg_create_pg_perm_denied = gettext("%s: Couldn't create \"%s\" "
	    "property group (permission denied).\n");
	emsg_pg_perm_denied = gettext("%s: Couldn't modify \"%s\" property "
	    "group (permission denied).\n");
	emsg_prop_perm_denied = gettext("%s: Couldn't modify \"%s/%s\" "
	    "property (permission denied).\n");
	emsg_no_service = gettext("No such service \"%s\".\n");

	orig_optind = optind;
	orig_argc = argc;
	orig_argv = argv;

again:
	h = scf_handle_create(SCF_VERSION);
	if (h == NULL)
		scfdie();

	if (do_zones) {
		zone_status_t status;

		if (zone_getattr(zids[zent], ZONE_ATTR_STATUS, &status,
		    sizeof (status)) < 0 || status != ZONE_IS_RUNNING) {
			/*
			 * If this zone is not running or we cannot
			 * get its status, we do not want to attempt
			 * to bind an SCF handle to it, lest we
			 * accidentally interfere with a zone that
			 * is not yet running by looking up a door
			 * to its svc.configd (which could potentially
			 * block a mount with an EBUSY).
			 */
			zent++;
			goto nextzone;
		}

		if (getzonenamebyid(zids[zent++], zonename,
		    sizeof (zonename)) < 0) {
			uu_warn(gettext("could not get name for "
			    "zone %d; ignoring"), zids[zent - 1]);
			goto nextzone;
		}

		g_zonename = zonename;
	}

	if (do_a_zone || do_zones) {
		scf_value_t *zone;

		if ((zone = scf_value_create(h)) == NULL)
			scfdie();

		if (scf_value_set_astring(zone, zonename) != SCF_SUCCESS)
			scfdie();

		if (scf_handle_decorate(h, "zone", zone) != SCF_SUCCESS) {
			if (do_a_zone) {
				uu_die(gettext("invalid zone '%s'\n"), optarg);
			} else {
				scf_value_destroy(zone);
				goto nextzone;
			}
		}

		scf_value_destroy(zone);
	}

	if (scf_handle_bind(h) == -1) {
		if (do_zones)
			goto nextzone;

		uu_die(gettext("Couldn't bind to configuration repository: "
		    "%s.\n"), scf_strerror(scf_error()));
	}

	optind = orig_optind;
	argc = orig_argc;
	argv = orig_argv;

	if (optind >= argc)
		usage();

	if (strcmp(argv[optind], "enable") == 0) {
		int flags = SET_ENABLED;
		int wait = 0;
		int error = 0;

		++optind;

		while ((o = getopt(argc, argv, "rst")) != -1) {
			if (o == 'r')
				flags |= SET_RECURSIVE;
			else if (o == 't')
				flags |= SET_TEMPORARY;
			else if (o == 's')
				wait = 1;
			else if (o == '?')
				usage();
			else {
				assert(0);
				abort();
			}
		}
		argc -= optind;
		argv += optind;

		if (argc == 0 && !svcsearch)
			usage();

		if (argc > 0 && svcsearch)
			usage();

		/*
		 * We want to continue with -s processing if we had
		 * invalid options, but not if an enable failed.  We
		 * squelch output the second time we walk fmris; we saw
		 * the errors the first time.
		 */
		if ((err = scf_walk_fmri(h, argc, argv, WALK_FLAGS,
		    set_fmri_enabled, (void *)flags, &error, pr_warn)) != 0) {

			pr_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;

		} else if (wait && exit_status == 0 &&
		    (err = scf_walk_fmri(h, argc, argv, WALK_FLAGS,
		    wait_fmri_enabled, (void *)flags, &error, quiet)) != 0) {

			pr_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}

		if (error > 0)
			exit_status = error;

	} else if (strcmp(argv[optind], "disable") == 0) {
		int flags = 0;
		int wait = 0;
		int error = 0;

		++optind;

		while ((o = getopt(argc, argv, "st")) != -1) {
			if (o == 't')
				flags |= SET_TEMPORARY;
			else if (o == 's')
				wait = 1;
			else if (o == '?')
				usage();
			else {
				assert(0);
				abort();
			}
		}
		argc -= optind;
		argv += optind;

		if (argc == 0 && !svcsearch)
			usage();

		if (argc > 0 && svcsearch)
			usage();

		/*
		 * We want to continue with -s processing if we had
		 * invalid options, but not if a disable failed.  We
		 * squelch output the second time we walk fmris; we saw
		 * the errors the first time.
		 */
		if ((err = scf_walk_fmri(h, argc, argv, WALK_FLAGS,
		    set_fmri_enabled, (void *)flags, &exit_status,
		    pr_warn)) != 0) {

			pr_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;

		} else if (wait && exit_status == 0 &&
		    (err = scf_walk_fmri(h, argc, argv, WALK_FLAGS,
		    wait_fmri_disabled, (void *)flags, &error, quiet)) != 0) {

			pr_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}

		if (error > 0)
			exit_status = error;

	} else if (strcmp(argv[optind], "restart") == 0) {
		boolean_t do_dump = B_FALSE;

		++optind;

		while ((o = getopt(argc, argv, "d")) != -1) {
			if (o == 'd')
				do_dump = B_TRUE;
			else if (o == '?')
				usage();
			else {
				assert(0);
				abort();
			}
		}
		argc -= optind;
		argv += optind;

		if (argc == 0 && !svcsearch)
			usage();

		if (argc > 0 && svcsearch)
			usage();

		if (do_dump) {
			if ((err = scf_walk_fmri(h, argc, argv, WALK_FLAGS,
			    set_fmri_action, (void *)SCF_PROPERTY_DODUMP,
			    &exit_status, pr_warn)) != 0) {
				pr_warn(gettext("failed to iterate over "
				    "instances: %s\n"), scf_strerror(err));
				exit_status = UU_EXIT_FATAL;
			}
		}

		if ((err = scf_walk_fmri(h, argc, argv, WALK_FLAGS,
		    set_fmri_action, (void *)SCF_PROPERTY_RESTART, &exit_status,
		    pr_warn)) != 0) {
			pr_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}

	} else if (strcmp(argv[optind], "refresh") == 0) {
		++optind;
		argc -= optind;
		argv += optind;

		if (argc == 0 && !svcsearch)
			usage();

		if (argc > 0 && svcsearch)
			usage();

		if ((err = scf_walk_fmri(h, argc, argv, WALK_FLAGS,
		    set_fmri_action, (void *)SCF_PROPERTY_REFRESH, &exit_status,
		    pr_warn)) != 0) {
			pr_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(scf_error()));
			exit_status = UU_EXIT_FATAL;
		}

	} else if (strcmp(argv[optind], "mark") == 0) {
		int flags = 0;
		scf_walk_callback callback;

		++optind;

		while ((o = getopt(argc, argv, "It")) != -1) {
			if (o == 'I')
				flags |= MARK_IMMEDIATE;
			else if (o == 't')
				flags |= MARK_TEMPORARY;
			else if (o == '?')
				usage();
			else {
				assert(0);
				abort();
			}
		}

		if (argc - optind < 2)
			usage();

		if (strcmp(argv[optind], "degraded") == 0) {
			if (flags & MARK_TEMPORARY)
				uu_xdie(UU_EXIT_USAGE, gettext("-t may not be "
				    "used with degraded.\n"));
			callback = force_degraded;

		} else if (strcmp(argv[optind], "maintenance") == 0) {
			callback = force_maintenance;
		} else {
			usage();
		}

		optind++;
		argc -= optind;
		argv += optind;

		if (argc == 0 && !svcsearch)
			usage();

		if (argc > 0 && svcsearch)
			usage();

		if ((err = scf_walk_fmri(h, argc, argv, WALK_FLAGS, callback,
		    NULL, &exit_status, pr_warn)) != 0) {
			pr_warn(gettext("failed to iterate over "
			    "instances: %s\n"),
			    scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}

	} else if (strcmp(argv[optind], "clear") == 0) {
		++optind;
		argc -= optind;
		argv += optind;

		if (argc == 0 && !svcsearch)
			usage();

		if (svcsearch) {
			if (argc > 0)
				usage();
			if (strcmp(svcstate, SCF_STATE_STRING_MAINT) != 0 &&
			    strcmp(svcstate, SCF_STATE_STRING_DEGRADED) != 0)
				uu_die(gettext("State must be '%s' or '%s'\n"),
				    SCF_STATE_STRING_MAINT,
				    SCF_STATE_STRING_DEGRADED);
		}

		if ((err = scf_walk_fmri(h, argc, argv, WALK_FLAGS,
		    clear_instance, NULL, &exit_status, pr_warn)) != 0) {
			pr_warn(gettext("failed to iterate over "
			    "instances: %s\n"), scf_strerror(err));
			exit_status = UU_EXIT_FATAL;
		}

	} else if (strcmp(argv[optind], "milestone") == 0) {
		boolean_t temporary = B_TRUE;
		const char *milestone;

		++optind;

		while ((o = getopt(argc, argv, "d")) != -1) {
			if (o == 'd')
				temporary = B_FALSE;
			else if (o == '?')
				usage_milestone();
			else {
				assert(0);
				abort();
			}
		}

		if (optind >= argc)
			usage_milestone();

		milestone = validate_milestone(argv[optind]);

		set_milestone(milestone, temporary);
	} else if (strcmp(argv[optind], "_smf_backup") == 0) {
		const char *reason = NULL;

		++optind;

		if (optind != argc - 1)
			usage();

		if ((err = _scf_request_backup(h, argv[optind])) !=
		    SCF_SUCCESS) {
			switch (scf_error()) {
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_BACKEND_READONLY:
				scfdie();
				break;

			case SCF_ERROR_PERMISSION_DENIED:
			case SCF_ERROR_INVALID_ARGUMENT:
				reason = scf_strerror(scf_error());
				break;

			case SCF_ERROR_INTERNAL:
				reason =
				    "unknown error (see console for details)";
				break;
			}

			pr_warn("failed to backup repository: %s\n", reason);
			exit_status = UU_EXIT_FATAL;
		}
	} else if (strcmp(argv[optind], "_smf_repository_switch") == 0) {
		const char *reason = NULL;

		++optind;

		/*
		 * Check argument and setup scf_switch structure
		 */
		if (optind != argc - 1)
			exit(1);

		if (strcmp(argv[optind], "fast") == 0) {
			sw_back = 0;
		} else if (strcmp(argv[optind], "perm") == 0) {
			sw_back = 1;
		} else {
			exit(UU_EXIT_USAGE);
		}

		/*
		 * Call into switch primitive
		 */
		if ((err = _scf_repository_switch(h, sw_back)) !=
		    SCF_SUCCESS) {
			/*
			 * Retrieve per thread SCF error code
			 */
			switch (scf_error()) {
			case SCF_ERROR_NOT_BOUND:
				abort();
				/* NOTREACHED */

			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_BACKEND_READONLY:
				scfdie();
				/* NOTREACHED */

			case SCF_ERROR_PERMISSION_DENIED:
			case SCF_ERROR_INVALID_ARGUMENT:
				reason = scf_strerror(scf_error());
				break;

			case SCF_ERROR_INTERNAL:
				reason = "File operation error: (see console)";
				break;

			default:
				abort();
				/* NOTREACHED */
			}

			pr_warn("failed to switch repository: %s\n", reason);
			exit_status = UU_EXIT_FATAL;
		}
	} else {
		usage();
	}

	if (scf_handle_unbind(h) == -1)
		scfdie();
nextzone:
	scf_handle_destroy(h);
	if (do_zones && zent < nzents)
		goto again;

	return (exit_status);
}
