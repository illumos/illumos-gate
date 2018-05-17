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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2011, Joyent, Inc. All rights reserved.
 */

/*
 * svcprop - report service configuration properties
 */

#include <locale.h>
#include <libintl.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <assert.h>
#include <zone.h>

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

/*
 * Error functions.  These can change if the quiet (-q) option is used.
 */
static void (*warn)(const char *, ...) = uu_warn;
static __NORETURN void (*die)(const char *, ...) = uu_die;

/*
 * Entity encapsulation.  This allows me to treat services and instances
 * similarly, and avoid duplicating process_ent().
 */
typedef struct {
	char type;			/* !=0: service, 0: instance */
	union {
		scf_service_t *svc;
		scf_instance_t *inst;
	} u;
} scf_entityp_t;

#define	ENT_INSTANCE	0

#define	SCF_ENTITY_SET_TO_SERVICE(ent, s)	{ ent.type = 1; ent.u.svc = s; }

#define	SCF_ENTITY_SET_TO_INSTANCE(ent, i)	\
	{ ent.type = ENT_INSTANCE; ent.u.inst = i; }

#define	scf_entity_get_pg(ent, name, pg) \
	(ent.type ? scf_service_get_pg(ent.u.svc, name, pg) : \
	scf_instance_get_pg(ent.u.inst, name, pg))

#define	scf_entity_to_fmri(ent, buf, buf_sz) \
	(ent.type ? scf_service_to_fmri(ent.u.svc, buf, buf_sz) : \
	scf_instance_to_fmri(ent.u.inst, buf, buf_sz))

#define	SCF_ENTITY_TYPE_NAME(ent)	(ent.type ? "service" : "instance")

/*
 * Data structure for -p arguments.  Since they may be name or name/name, we
 * just track the components.
 */
typedef struct svcprop_prop_node {
	uu_list_node_t	spn_list_node;
	const char	*spn_comp1;
	const char	*spn_comp2;
} svcprop_prop_node_t;

static uu_list_pool_t	*prop_pool;
static uu_list_t	*prop_list;

static scf_handle_t *hndl;
static ssize_t max_scf_name_length;
static ssize_t max_scf_value_length;
static ssize_t max_scf_fmri_length;

/* Options */
static int quiet = 0;			/* No output. Nothing found, exit(1) */
static int types = 0;			/* Display types of properties. */
static int verbose = 0;			/* Print not found errors to stderr. */
static int fmris = 0;			/* Display full FMRIs for properties. */
static int wait = 0;			/* Wait mode. */
static char *snapshot = "running";	/* Snapshot to use. */
static int Cflag = 0;			/* C option supplied */
static int cflag = 0;			/* c option supplied */
static int sflag = 0;			/* s option supplied */
static int return_code;			/* main's return code */

#define	PRINT_NOPROP_ERRORS	(!quiet || verbose)

/*
 * For unexpected libscf errors.  The ending newline is necessary to keep
 * uu_die() from appending the errno error.
 */
static void
scfdie(void)
{
	die(gettext("Unexpected libscf error: %s.  Exiting.\n"),
	    scf_strerror(scf_error()));
}

static void *
safe_malloc(size_t sz)
{
	void *p;

	p = malloc(sz);
	if (p == NULL)
		die(gettext("Could not allocate memory"));

	return (p);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext("Usage: %1$s [-fqtv] "
	    "[-C | -c | -s snapshot] [-z zone] "
	    "[-p [name/]name]... \n"
	    "         {FMRI | pattern}...\n"
	    "       %1$s -w [-fqtv] [-z zone] [-p [name/]name] "
	    "{FMRI | pattern}\n"), uu_getpname());
	exit(UU_EXIT_USAGE);
}

/*
 * Return an allocated copy of str, with the Bourne shell's metacharacters
 * escaped by '\'.
 *
 * What about unicode?
 */
static char *
quote_for_shell(const char *str)
{
	const char *sp;
	char *dst, *dp;
	size_t dst_len;

	const char * const metachars = ";&()|^<>\n \t\\\"\'`";

	if (str[0] == '\0')
		return (strdup("\"\""));

	dst_len = 0;
	for (sp = str; *sp != '\0'; ++sp) {
		++dst_len;

		if (strchr(metachars, *sp) != NULL)
			++dst_len;
	}

	if (sp - str == dst_len)
		return (strdup(str));

	dst = safe_malloc(dst_len + 1);

	for (dp = dst, sp = str; *sp != '\0'; ++dp, ++sp) {
		if (strchr(metachars, *sp) != NULL)
			*dp++ = '\\';

		*dp = *sp;
	}
	*dp = '\0';

	return (dst);
}

static void
print_value(scf_value_t *val)
{
	char *buf, *qbuf;
	ssize_t bufsz, r;

	bufsz = scf_value_get_as_string(val, NULL, 0) + 1;
	if (bufsz - 1 < 0)
		scfdie();

	buf = safe_malloc(bufsz);

	r = scf_value_get_as_string(val, buf, bufsz);
	assert(r + 1 == bufsz);

	qbuf = quote_for_shell(buf);
	(void) fputs(qbuf, stdout);

	free(qbuf);
	free(buf);
}

/*
 * Display a property's values on a line.  If types is true, prepend
 * identification (the FMRI if fmris is true, pg/prop otherwise) and the type
 * of the property.
 */
static void
display_prop(scf_propertygroup_t *pg, scf_property_t *prop)
{
	scf_value_t *val;
	scf_iter_t *iter;
	int ret, first, err;

	const char * const permission_denied_emsg =
	    gettext("Permission denied.\n");

	if (types) {
		scf_type_t ty;
		char *buf;
		size_t buf_sz;

		if (fmris) {
			buf_sz = max_scf_fmri_length + 1;
			buf = safe_malloc(buf_sz);

			if (scf_property_to_fmri(prop, buf, buf_sz) == -1)
				scfdie();
			(void) fputs(buf, stdout);

			free(buf);
		} else {
			buf_sz = max_scf_name_length + 1;
			buf = safe_malloc(buf_sz);

			if (scf_pg_get_name(pg, buf, buf_sz) < 0)
				scfdie();
			(void) fputs(buf, stdout);
			(void) putchar('/');

			if (scf_property_get_name(prop, buf, buf_sz) < 0)
				scfdie();
			(void) fputs(buf, stdout);

			free(buf);
		}

		(void) putchar(' ');

		if (scf_property_type(prop, &ty) == -1)
			scfdie();
		(void) fputs(scf_type_to_string(ty), stdout);
		(void) putchar(' ');
	}

	if ((iter = scf_iter_create(hndl)) == NULL ||
	    (val = scf_value_create(hndl)) == NULL)
		scfdie();

	if (scf_iter_property_values(iter, prop) == -1)
		scfdie();

	first = 1;
	while ((ret = scf_iter_next_value(iter, val)) == 1) {
		if (first)
			first = 0;
		else
			(void) putchar(' ');
		print_value(val);
	}
	if (ret == -1) {
		err = scf_error();
		if (err == SCF_ERROR_PERMISSION_DENIED) {
			if (uu_list_numnodes(prop_list) > 0)
				die(permission_denied_emsg);
		} else {
			scfdie();
		}
	}

	(void) putchar('\n');

	scf_iter_destroy(iter);
	(void) scf_value_destroy(val);
}

/*
 * display_prop() all of the properties in the given property group.  Force
 * types to true so identification will be displayed.
 */
static void
display_pg(scf_propertygroup_t *pg)
{
	scf_property_t *prop;
	scf_iter_t *iter;
	int ret;

	types = 1;	/* Always display types for whole propertygroups. */

	if ((prop = scf_property_create(hndl)) == NULL ||
	    (iter = scf_iter_create(hndl)) == NULL)
		scfdie();

	if (scf_iter_pg_properties(iter, pg) == -1)
		scfdie();

	while ((ret = scf_iter_next_property(iter, prop)) == 1)
		display_prop(pg, prop);
	if (ret == -1)
		scfdie();

	scf_iter_destroy(iter);
	scf_property_destroy(prop);
}

/*
 * Common code to execute when a nonexistant property is encountered.
 */
static void
noprop_common_action()
{
	if (!PRINT_NOPROP_ERRORS)
		/* We're not printing errors, so we can cut out early. */
		exit(UU_EXIT_FATAL);

	return_code = UU_EXIT_FATAL;
}

/*
 * Iterate the properties of a service or an instance when no snapshot
 * is specified.
 */
static int
scf_iter_entity_pgs(scf_iter_t *iter, scf_entityp_t ent)
{
	int ret = 0;

	if (ent.type) {
		/*
		 * If we are displaying properties for a service,
		 * treat it as though it were a composed, current
		 * lookup. (implicit cflag) However, if a snapshot
		 * was specified, fail.
		 */
		if (sflag)
			die(gettext("Only instances have "
			    "snapshots.\n"));
		ret = scf_iter_service_pgs(iter, ent.u.svc);
	} else {
		if (Cflag)
			ret = scf_iter_instance_pgs(iter, ent.u.inst);
		else
			ret = scf_iter_instance_pgs_composed(iter, ent.u.inst,
			    NULL);
	}
	return (ret);
}

/*
 * Return a snapshot for the supplied instance and snapshot name.
 */
static scf_snapshot_t *
get_snapshot(const scf_instance_t *inst, const char *snapshot)
{
	scf_snapshot_t *snap = scf_snapshot_create(hndl);

	if (snap == NULL)
		scfdie();

	if (scf_instance_get_snapshot(inst, snapshot, snap) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_INVALID_ARGUMENT:
			die(gettext("Invalid snapshot name.\n"));
			/* NOTREACHED */

		case SCF_ERROR_NOT_FOUND:
			if (sflag == 0) {
				scf_snapshot_destroy(snap);
				snap = NULL;
			} else
				die(gettext("No such snapshot.\n"));
			break;

		default:
			scfdie();
		}
	}

	return (snap);
}

/*
 * Entity (service or instance): If there are -p options,
 * display_{pg,prop}() the named property groups and/or properties.  Otherwise
 * display_pg() all property groups.
 */
static void
process_ent(scf_entityp_t ent)
{
	scf_snapshot_t *snap = NULL;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_iter_t *iter;
	svcprop_prop_node_t *spn;
	int ret, err;

	if (uu_list_numnodes(prop_list) == 0) {
		if (quiet)
			return;

		if ((pg = scf_pg_create(hndl)) == NULL ||
		    (iter = scf_iter_create(hndl)) == NULL)
			scfdie();

		if (cflag || Cflag || ent.type != ENT_INSTANCE) {
			if (scf_iter_entity_pgs(iter, ent) == -1)
				scfdie();
		} else {
			if (snapshot != NULL)
				snap = get_snapshot(ent.u.inst, snapshot);

			if (scf_iter_instance_pgs_composed(iter, ent.u.inst,
			    snap) == -1)
				scfdie();
			if (snap)
				scf_snapshot_destroy(snap);
		}

		while ((ret = scf_iter_next_pg(iter, pg)) == 1)
			display_pg(pg);
		if (ret == -1)
			scfdie();

		/*
		 * In normal usage, i.e. against the running snapshot,
		 * we must iterate over the current non-persistent
		 * pg's.
		 */
		if (sflag == 0 && snap != NULL) {
			scf_iter_reset(iter);
			if (scf_iter_instance_pgs_composed(iter, ent.u.inst,
			    NULL) == -1)
				scfdie();
			while ((ret = scf_iter_next_pg(iter, pg)) == 1) {
				uint32_t flags;

				if (scf_pg_get_flags(pg, &flags) == -1)
					scfdie();
				if (flags & SCF_PG_FLAG_NONPERSISTENT)
					display_pg(pg);
			}
		}
		if (ret == -1)
			scfdie();

		scf_iter_destroy(iter);
		scf_pg_destroy(pg);

		return;
	}

	if ((pg = scf_pg_create(hndl)) == NULL ||
	    (prop = scf_property_create(hndl)) == NULL)
		scfdie();

	if (ent.type == ENT_INSTANCE && snapshot != NULL)
		snap = get_snapshot(ent.u.inst, snapshot);

	for (spn = uu_list_first(prop_list);
	    spn != NULL;
	    spn = uu_list_next(prop_list, spn)) {
		if (ent.type == ENT_INSTANCE) {
			if (Cflag)
				ret = scf_instance_get_pg(ent.u.inst,
				    spn->spn_comp1, pg);
			else
				ret = scf_instance_get_pg_composed(ent.u.inst,
				    snap, spn->spn_comp1, pg);
			err = scf_error();

			/*
			 * If we didn't find it in the specified snapshot, use
			 * the current values if the pg is nonpersistent.
			 */
			if (ret == -1 && !Cflag &&snap != NULL && err ==
			    SCF_ERROR_NOT_FOUND) {
				ret = scf_instance_get_pg_composed(
				    ent.u.inst, NULL, spn->spn_comp1,
				    pg);

				if (ret == 0) {
					uint32_t flags;

					if (scf_pg_get_flags(pg, &flags) == -1)
						scfdie();
					if ((flags & SCF_PG_FLAG_NONPERSISTENT)
					    == 0) {
						ret = -1;
					}
				}
			}
		} else {
			/*
			 * If we are displaying properties for a service,
			 * treat it as though it were a composed, current
			 * lookup. (implicit cflag) However, if a snapshot
			 * was specified, fail.
			 */
			if (sflag)
				die(gettext("Only instances have "
				    "snapshots.\n"));
			ret = scf_entity_get_pg(ent, spn->spn_comp1, pg);
			err = scf_error();
		}
		if (ret == -1) {
			if (err != SCF_ERROR_NOT_FOUND)
				scfdie();

			if (PRINT_NOPROP_ERRORS) {
				char *buf;

				buf = safe_malloc(max_scf_fmri_length + 1);
				if (scf_entity_to_fmri(ent, buf,
				    max_scf_fmri_length + 1) == -1)
					scfdie();

				uu_warn(gettext("Couldn't find property group "
				    "`%s' for %s `%s'.\n"), spn->spn_comp1,
				    SCF_ENTITY_TYPE_NAME(ent), buf);

				free(buf);
			}

			noprop_common_action();

			continue;
		}

		if (spn->spn_comp2 == NULL) {
			if (!quiet)
				display_pg(pg);
			continue;
		}

		if (scf_pg_get_property(pg, spn->spn_comp2, prop) == -1) {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();

			if (PRINT_NOPROP_ERRORS) {
				char *buf;

				buf = safe_malloc(max_scf_fmri_length + 1);
				if (scf_entity_to_fmri(ent, buf,
				    max_scf_fmri_length + 1) == -1)
					scfdie();

				/* FMRI syntax knowledge */
				uu_warn(gettext("Couldn't find property "
				    "`%s/%s' for %s `%s'.\n"), spn->spn_comp1,
				    spn->spn_comp2, SCF_ENTITY_TYPE_NAME(ent),
				    buf);

				free(buf);
			}

			noprop_common_action();

			continue;
		}

		if (!quiet)
			display_prop(pg, prop);
	}

	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	if (snap)
		scf_snapshot_destroy(snap);
}

/*
 * Without -p options, just call display_pg().  Otherwise display_prop() the
 * named properties of the property group.
 */
static void
process_pg(scf_propertygroup_t *pg)
{
	scf_property_t *prop;
	svcprop_prop_node_t *spn;

	if (uu_list_first(prop_list) == NULL) {
		if (quiet)
			return;

		display_pg(pg);
		return;
	}

	prop = scf_property_create(hndl);
	if (prop == NULL)
		scfdie();

	for (spn = uu_list_first(prop_list);
	    spn != NULL;
	    spn = uu_list_next(prop_list, spn)) {
		if (spn->spn_comp2 != NULL) {
			char *buf;

			buf = safe_malloc(max_scf_fmri_length + 1);
			if (scf_pg_to_fmri(pg, buf, max_scf_fmri_length + 1) ==
			    -1)
				scfdie();

			uu_xdie(UU_EXIT_USAGE, gettext("-p argument `%s/%s' "
			    "has too many components for property "
			    "group `%s'.\n"), spn->spn_comp1, spn->spn_comp2,
			    buf);

			free(buf);
		}

		if (scf_pg_get_property(pg, spn->spn_comp1, prop) == 0) {
			if (!quiet)
				display_prop(pg, prop);
			continue;
		}

		if (scf_error() != SCF_ERROR_NOT_FOUND)
			scfdie();

		if (PRINT_NOPROP_ERRORS) {
			char *buf;

			buf = safe_malloc(max_scf_fmri_length + 1);
			if (scf_pg_to_fmri(pg, buf, max_scf_fmri_length + 1) ==
			    -1)
				scfdie();

			uu_warn(gettext("Couldn't find property `%s' in "
			    "property group `%s'.\n"), spn->spn_comp1, buf);

			free(buf);
		}

		noprop_common_action();
	}
}

/*
 * If there are -p options, show the error.  Otherwise just call
 * display_prop().
 */
static void
process_prop(scf_propertygroup_t *pg, scf_property_t *prop)
{
	if (uu_list_first(prop_list) != NULL) {
		uu_warn(gettext("The -p option cannot be used with property "
		    "operands.\n"));
		usage();
	}

	if (quiet)
		return;

	display_prop(pg, prop);
}

/* Decode an operand & dispatch. */
/* ARGSUSED */
static int
process_fmri(void *unused, scf_walkinfo_t *wip)
{
	scf_entityp_t ent;

	/* Multiple matches imply multiple entities. */
	if (wip->count > 1)
		types = fmris = 1;

	if (wip->prop != NULL) {
		process_prop(wip->pg, wip->prop);
	} else if (wip->pg != NULL) {
		process_pg(wip->pg);
	} else if (wip->inst != NULL) {
		SCF_ENTITY_SET_TO_INSTANCE(ent, wip->inst);
		process_ent(ent);
	} else {
		/* scf_walk_fmri() won't let this happen */
		assert(wip->svc != NULL);
		SCF_ENTITY_SET_TO_SERVICE(ent, wip->svc);
		process_ent(ent);
	}

	return (0);
}

static void
add_prop(char *property)
{
	svcprop_prop_node_t *p, *last;
	char *slash;

	const char * const invalid_component_emsg =
	    gettext("Invalid component name `%s'.\n");

	/* FMRI syntax knowledge. */
	slash = strchr(property, '/');
	if (slash != NULL) {
		if (strchr(slash + 1, '/') != NULL) {
			uu_warn(gettext("-p argument `%s' has too many "
			    "components.\n"), property);
			usage();
		}
	}

	if (slash != NULL)
		*slash = '\0';

	p = safe_malloc(sizeof (svcprop_prop_node_t));
	uu_list_node_init(p, &p->spn_list_node, prop_pool);

	p->spn_comp1 = property;
	p->spn_comp2 = (slash == NULL) ? NULL : slash + 1;

	if (uu_check_name(p->spn_comp1, UU_NAME_DOMAIN) == -1)
		uu_xdie(UU_EXIT_USAGE, invalid_component_emsg, p->spn_comp1);
	if (p->spn_comp2 != NULL &&
	    uu_check_name(p->spn_comp2, UU_NAME_DOMAIN) == -1)
		uu_xdie(UU_EXIT_USAGE, invalid_component_emsg, p->spn_comp2);

	last = uu_list_last(prop_list);
	if (last != NULL) {
		if ((last->spn_comp2 == NULL) ^ (p->spn_comp2 == NULL)) {
			/*
			 * The -p options have mixed numbers of components.
			 * If they both turn out to be valid, then the
			 * single-component ones will specify property groups,
			 * so we need to turn on types to keep the output of
			 * display_prop() consistent with display_pg().
			 */
			types = 1;
		}
	}

	(void) uu_list_insert_after(prop_list, NULL, p);
}


/*
 * Wait for a property group or property change.
 *
 * Extract a pg and optionally a property name from fmri & prop_list.
 * _scf_pg_wait() for the pg, and display_pg(pg) or display_prop(pg, prop)
 * when it returns.
 */
/* ARGSUSED */
static int
do_wait(void *unused, scf_walkinfo_t *wip)
{
	scf_property_t *prop;
	scf_propertygroup_t *lpg, *pg;
	const char *propname;
	svcprop_prop_node_t *p;

	const char *emsg_not_found = gettext("Not found.\n");

	if ((lpg = scf_pg_create(hndl)) == NULL ||
	    (prop = scf_property_create(hndl)) == NULL)
		scfdie();

	if (wip->prop != NULL) {
		if (uu_list_numnodes(prop_list) > 0)
			uu_xdie(UU_EXIT_USAGE, gettext("-p cannot be used with "
			    "property FMRIs.\n"));
		pg = wip->pg;

		assert(strrchr(wip->fmri, '/') != NULL);
		propname = strrchr(wip->fmri, '/') + 1;

	} else if (wip->pg != NULL) {
		p = uu_list_first(prop_list);

		if (p != NULL) {
			if (p->spn_comp2 != NULL)
				uu_xdie(UU_EXIT_USAGE, gettext("-p argument "
				    "\"%s/%s\" has too many components for "
				    "property group %s.\n"),
				    p->spn_comp1, p->spn_comp2, wip->fmri);

			propname = p->spn_comp1;

			if (scf_pg_get_property(wip->pg, propname, prop) !=
			    SCF_SUCCESS) {
				switch (scf_error()) {
				case SCF_ERROR_INVALID_ARGUMENT:
					uu_xdie(UU_EXIT_USAGE,
					    gettext("Invalid property name "
					    "\"%s\".\n"), propname);

					/* NOTREACHED */

				case SCF_ERROR_NOT_FOUND:
					die(emsg_not_found);

				default:
					scfdie();
				}
			}
		} else {
			propname = NULL;
		}

		pg = wip->pg;

	} else if (wip->inst != NULL) {

		p = uu_list_first(prop_list);
		if (p == NULL)
			uu_xdie(UU_EXIT_USAGE,
			    gettext("Cannot wait for an instance.\n"));

		if (scf_instance_get_pg(wip->inst, p->spn_comp1, lpg) !=
		    SCF_SUCCESS) {
			switch (scf_error()) {
			case SCF_ERROR_INVALID_ARGUMENT:
				uu_xdie(UU_EXIT_USAGE, gettext("Invalid "
				    "property group name \"%s\".\n"),
				    p->spn_comp1);
				/* NOTREACHED */

			case SCF_ERROR_NOT_FOUND:
				die(emsg_not_found);

			default:
				scfdie();
			}
		}

		propname = p->spn_comp2;

		if (propname != NULL) {
			if (scf_pg_get_property(lpg, propname, prop) !=
			    SCF_SUCCESS) {
				switch (scf_error()) {
				case SCF_ERROR_INVALID_ARGUMENT:
					uu_xdie(UU_EXIT_USAGE,
					    gettext("Invalid property name "
					    "\"%s\".\n"), propname);
					/* NOTREACHED */

				case SCF_ERROR_NOT_FOUND:
					die(emsg_not_found);

				default:
					scfdie();
				}
			}
		}

		pg = lpg;

	} else if (wip->svc != NULL) {

		p = uu_list_first(prop_list);
		if (p == NULL)
			uu_xdie(UU_EXIT_USAGE,
			    gettext("Cannot wait for a service.\n"));

		if (scf_service_get_pg(wip->svc, p->spn_comp1, lpg) !=
		    SCF_SUCCESS) {
			switch (scf_error()) {
			case SCF_ERROR_INVALID_ARGUMENT:
				uu_xdie(UU_EXIT_USAGE, gettext("Invalid "
				    "property group name \"%s\".\n"),
				    p->spn_comp1);
				/* NOTREACHED */

			case SCF_ERROR_NOT_FOUND:
				die(emsg_not_found);

			default:
				scfdie();
			}
		}

		propname = p->spn_comp2;

		if (propname != NULL) {
			if (scf_pg_get_property(lpg, propname, prop) !=
			    SCF_SUCCESS) {
				switch (scf_error()) {
				case SCF_ERROR_INVALID_ARGUMENT:
					uu_xdie(UU_EXIT_USAGE,
					    gettext("Invalid property name "
					    "\"%s\".\n"), propname);

					/* NOTREACHED */

				case SCF_ERROR_NOT_FOUND:
					die(emsg_not_found);

				default:
					scfdie();
				}
			}
		}

		pg = lpg;

	} else {
		uu_xdie(UU_EXIT_USAGE, gettext("FMRI must specify an entity, "
		    "property group, or property.\n"));
	}

	for (;;) {
		int ret;

		ret = _scf_pg_wait(pg, -1);
		if (ret != SCF_SUCCESS)
			scfdie();

		ret = scf_pg_update(pg);
		if (ret < 0) {
			if (scf_error() != SCF_ERROR_DELETED)
				scfdie();

			die(emsg_not_found);
		}
		if (ret == SCF_COMPLETE)
			break;
	}

	if (propname != NULL) {
		if (scf_pg_get_property(pg, propname, prop) == SCF_SUCCESS) {
			if (!quiet)
				display_prop(pg, prop);
		} else {
			if (scf_error() != SCF_ERROR_NOT_FOUND)
				scfdie();

			if (PRINT_NOPROP_ERRORS)
				uu_warn(emsg_not_found);

			return_code = UU_EXIT_FATAL;
		}
	} else {
		if (!quiet)
			display_pg(pg);
	}

	scf_property_destroy(prop);
	scf_pg_destroy(lpg);

	return (0);
}

/*
 * These functions replace uu_warn() and uu_die() when the quiet (-q) option is
 * used, and silently ignore any output.
 */

/*ARGSUSED*/
static void
quiet_warn(const char *fmt, ...)
{
	/* Do nothing */
}

/*ARGSUSED*/
static __NORETURN void
quiet_die(const char *fmt, ...)
{
	exit(UU_EXIT_FATAL);
}

int
main(int argc, char *argv[])
{
	int c;
	scf_walk_callback callback;
	int flags;
	int err;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	return_code = UU_EXIT_OK;

	(void) uu_setpname(argv[0]);

	prop_pool = uu_list_pool_create("properties",
	    sizeof (svcprop_prop_node_t),
	    offsetof(svcprop_prop_node_t, spn_list_node), NULL, 0);
	if (prop_pool == NULL)
		uu_die("%s\n", uu_strerror(uu_error()));

	prop_list = uu_list_create(prop_pool, NULL, 0);

	hndl = scf_handle_create(SCF_VERSION);
	if (hndl == NULL)
		scfdie();

	while ((c = getopt(argc, argv, "Ccfp:qs:tvwz:")) != -1) {
		switch (c) {
		case 'C':
			if (cflag || sflag || wait)
				usage();	/* Not with -c, -s or -w */
			Cflag++;
			snapshot = NULL;
			break;

		case 'c':
			if (Cflag || sflag || wait)
				usage();	/* Not with -C, -s or -w */
			cflag++;
			snapshot = NULL;
			break;

		case 'f':
			types = 1;
			fmris = 1;
			break;

		case 'p':
			add_prop(optarg);
			break;

		case 'q':
			quiet = 1;
			warn = quiet_warn;
			die = quiet_die;
			break;

		case 's':
			if (Cflag || cflag || wait)
				usage();	/* Not with -C, -c or -w */
			snapshot = optarg;
			sflag++;
			break;

		case 't':
			types = 1;
			break;

		case 'v':
			verbose = 1;
			break;

		case 'w':
			if (Cflag || cflag || sflag)
				usage();	/* Not with -C, -c or -s */
			wait = 1;
			break;

		case 'z': {
			scf_value_t *zone;
			scf_handle_t *h = hndl;

			if (getzoneid() != GLOBAL_ZONEID)
				uu_die(gettext("svcprop -z may only be used "
				    "from the global zone\n"));

			if ((zone = scf_value_create(h)) == NULL)
				scfdie();

			if (scf_value_set_astring(zone, optarg) != SCF_SUCCESS)
				scfdie();

			if (scf_handle_decorate(h, "zone", zone) != SCF_SUCCESS)
				uu_die(gettext("invalid zone '%s'\n"), optarg);

			scf_value_destroy(zone);
			break;
		}

		case '?':
			switch (optopt) {
			case 'p':
				usage();

			default:
				break;
			}

			/* FALLTHROUGH */

		default:
			usage();
		}
	}

	if (optind == argc)
		usage();

	max_scf_name_length = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);
	max_scf_value_length = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	max_scf_fmri_length = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH);
	if (max_scf_name_length == -1 || max_scf_value_length == -1 ||
	    max_scf_fmri_length == -1)
		scfdie();

	if (scf_handle_bind(hndl) == -1)
		die(gettext("Could not connect to configuration repository: "
		    "%s.\n"), scf_strerror(scf_error()));

	flags = SCF_WALK_PROPERTY | SCF_WALK_SERVICE | SCF_WALK_EXPLICIT;

	if (wait) {
		if (uu_list_numnodes(prop_list) > 1)
			usage();

		if (argc - optind > 1)
			usage();

		callback = do_wait;

	} else {
		callback = process_fmri;

		flags |= SCF_WALK_MULTIPLE;
	}

	if ((err = scf_walk_fmri(hndl, argc - optind, argv + optind, flags,
	    callback, NULL, &return_code, warn)) != 0) {
		warn(gettext("failed to iterate over instances: %s\n"),
		    scf_strerror(err));
		return_code = UU_EXIT_FATAL;
	}

	scf_handle_destroy(hndl);

	return (return_code);
}
