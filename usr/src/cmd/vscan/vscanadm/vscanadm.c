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
#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <strings.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libintl.h>
#include <libvscan.h>


/* Property Names */
#define	VS_ADM_MAXSIZE		"max-size"
#define	VS_ADM_MAXSIZE_ACTION	"max-size-action"
#define	VS_ADM_TYPES		"types"

/* Scan Engine Property Names */
#define	VS_ADM_SE_ENABLE	"enable"
#define	VS_ADM_SE_HOST		"host"
#define	VS_ADM_SE_PORT		"port"
#define	VS_ADM_SE_MAXCONN	"max-connection"

/* Property Values */
#define	VS_ADM_ON		"on"
#define	VS_ADM_OFF		"off"
#define	VS_ADM_ALLOW		"allow"
#define	VS_ADM_DENY		"deny"


/*
 * Print buffer length: used for sizing buffers that are filled with
 * user-readable strings for property values. Define a number that
 * accounts for some pre-value information, and won't (likely)
 * wrap an 80-column display
 */
#define	VS_ADM_PRINT_BUF_LEN	4096

/* Program exit codes */
#define	VS_ADM_EXIT_SUCCESS	0
#define	VS_ADM_EXIT_ERROR	1
#define	VS_ADM_EXIT_USAGE	2


/*
 * vscanadm property definition. Maps the property ids to a
 * property name, and includes functions to convert to and from
 * input strings and native data.
 */
typedef struct vs_adm_property {
	const char *vap_name;
	uint64_t vap_id;
	int (*vap_parse)(const char *, void *);
	int (*vap_unparse)(const void *, char *, size_t);
} vs_adm_property_t;


/* usage/help information for subcommnds */
#define	VS_ADM_HELP_GET		("[-p property]...\n" \
	"\tdisplay vscan properties")
#define	VS_ADM_HELP_SET		("-p property=value [-p property=value]...\n" \
	"\tset values of vscan properties")
#define	VS_ADM_HELP_GET_ENG	("[-p property] [engine_id]\n" \
	"\tdisplay values of scan engine properties")
#define	VS_ADM_HELP_ADD_ENG	("[-p property=value]... engine_id\n" \
	"\tadd scan engine")
#define	VS_ADM_HELP_SET_ENG	("-p property=value [-p property=value]" \
	"... engine_id\n\tset values of scan engine properties")
#define	VS_ADM_HELP_REM_ENG	("engine_id\n" \
	"\tremove scan engine")
#define	VS_ADM_HELP_SHOW	("\n\tdisplay the values of all vscan " \
	"service and scan engine properties")
#define	VS_ADM_HELP_STATS	("[-z]\n\tdisplay vscan service statistics")
#define	VS_ADM_HELP_IMPORT	("-p property filename\n" \
	"\timport property from file")
#define	VS_ADM_HELP_EXPORT	("-p property filename\n" \
	"\texport property to file")
#define	VS_ADM_HELP_VALIDATE	("-p property filename\n" \
	"\tvalidate property in file")


/*
 * vscanadm command structure. Encapsulates the vscanadm
 * subcommand name, pointer to the subcommand implementation
 * function, and a help id to get usage/help information.
 */
typedef struct vs_adm_cmd {
	int (*vac_func)(int, char *[]);
	const char *vac_name;
	char *vac_helpid;
}
vs_adm_cmd_t;


/* Subcommand implementation functions */
static int vs_adm_set(int, char **);
static int vs_adm_get(int, char **);
static int vs_adm_set_engine(int, char **);
static int vs_adm_get_engine(int, char **);
static int vs_adm_rem_engine(int, char **);
static int vs_adm_show(int, char **);
static int vs_adm_stats(int, char **);
static int vs_adm_import(int, char **);
static int vs_adm_export(int, char **);
static int vs_adm_validate(int, char **);


/*
 * Parse routines to transform libvscan API data into user-readable strings
 */
static int vs_adm_parse_maxsize(const char *, void *);
static int vs_adm_parse_maxsize_action(const char *, void *);
static int vs_adm_parse_types(const char *, void *);
static int vs_adm_parse_enable(const char *, void *);
static int vs_adm_parse_host(const char *, void *);
static int vs_adm_parse_port(const char *, void *);
static int vs_adm_parse_maxconn(const char *, void *);


/*
 * Unparse routines to transform strings from the user input into
 * API native data.
 *
 * While some value validation is performed in the course of unparsing
 * string data, complete value validation is left to libvscan.
 * Values that are in unacceptable form, out of range, or otherwise
 * violate rules for a given property will be rejected
 */
static int vs_adm_unparse_maxsize(const void *, char *, size_t);
static int vs_adm_unparse_maxsize_action(const void *, char *, size_t);
static int vs_adm_unparse_types(const void *, char *, size_t);
static int vs_adm_unparse_enable(const void *, char *, size_t);
static int vs_adm_unparse_host(const void *, char *, size_t);
static int vs_adm_unparse_port(const void *, char *, size_t);
static int vs_adm_unparse_maxconn(const void *, char *, size_t);


/*
 * The properties table includes a vscanadm property entry, specifying
 * the property nane, property id, parse amd inparse methods,
 * for each vscanadm property.
 */
static const vs_adm_property_t vs_adm_props_all[] = {
	{ VS_ADM_MAXSIZE, VS_PROPID_MAXSIZE,
		vs_adm_parse_maxsize, vs_adm_unparse_maxsize },
	{ VS_ADM_MAXSIZE_ACTION, VS_PROPID_MAXSIZE_ACTION,
		vs_adm_parse_maxsize_action, vs_adm_unparse_maxsize_action },
	{ VS_ADM_TYPES, VS_PROPID_TYPES,
		vs_adm_parse_types, vs_adm_unparse_types },
	{ VS_ADM_SE_ENABLE, VS_PROPID_SE_ENABLE,
		vs_adm_parse_enable, vs_adm_unparse_enable },
	{ VS_ADM_SE_HOST, VS_PROPID_SE_HOST,
		vs_adm_parse_host, vs_adm_unparse_host },
	{ VS_ADM_SE_PORT, VS_PROPID_SE_PORT,
		vs_adm_parse_port, vs_adm_unparse_port },
	{ VS_ADM_SE_MAXCONN, VS_PROPID_SE_MAXCONN,
		vs_adm_parse_maxconn, vs_adm_unparse_maxconn },
	{ NULL, 0, NULL, NULL }
};


/*
 * The subcommand table.  Used to find the subcommand specified
 * by the user and dispatch the processing for the subcommand.
 * Also used to display usage information for each subcommand.
 */
static const vs_adm_cmd_t vs_adm_cmds[] =
{
	{ vs_adm_get, "get", VS_ADM_HELP_GET },
	{ vs_adm_set, "set", VS_ADM_HELP_SET },
	{ vs_adm_get_engine, "get-engine", VS_ADM_HELP_GET_ENG },
	{ vs_adm_set_engine, "set-engine", VS_ADM_HELP_SET_ENG },
	{ vs_adm_set_engine, "add-engine", VS_ADM_HELP_ADD_ENG },
	{ vs_adm_rem_engine, "remove-engine", VS_ADM_HELP_REM_ENG },
	{ vs_adm_import, "import", VS_ADM_HELP_IMPORT },
	{ vs_adm_export, "export", VS_ADM_HELP_EXPORT },
	{ vs_adm_validate, "validate", VS_ADM_HELP_VALIDATE },
	{ vs_adm_show, "show", VS_ADM_HELP_SHOW },
	{ vs_adm_stats, "stats", VS_ADM_HELP_STATS },
	{ NULL, NULL, NULL }
};


static const char *vs_adm_cmd;
static const char *vs_adm_subcmd;

static int vs_adm_usage(FILE *);
static int vs_adm_props_from_input(int, char **, vs_props_t *, uint64_t *);
static void vs_adm_output_getcmd(uint64_t, const void *);
static void vs_adm_output_stats(vs_stats_t *);
static const vs_adm_property_t *vs_adm_prop_by_name(const char *);
static const vs_adm_property_t *vs_adm_prop_by_id(const uint64_t);
static int vs_adm_parse(const vs_adm_property_t *, const char *, void *);
static void vs_adm_unparse(const vs_adm_property_t *, const void *,
    char *, size_t);

static int vs_adm_file_read(char *, char *, int);
static int vs_adm_file_write(char *, char *);
static int vs_adm_file_usage(int argc, char **argv);

/*
 * main
 */
int
main(int argc, char **argv)
{
	const vs_adm_cmd_t *cp;
	const char *p;
	int i, err;

	/* executable and subcommand names */
	if ((p = strrchr(argv[0], '/')) == NULL)
		vs_adm_cmd = argv[0];
	else
		vs_adm_cmd = p + 1;

	vs_adm_subcmd = argv[1];

	/* require at least command and sub-command */
	if (argc < 2)
		return (vs_adm_usage(stdout));

	/* Check for the "-?" help switch */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-?") == 0)
			return (vs_adm_usage(stdout));
	}

	/* Locate the specified subcommand */
	for (cp = vs_adm_cmds; cp->vac_name != NULL; cp++) {
		if (strcmp(cp->vac_name, vs_adm_subcmd) == 0)
			break;
	}

	if (cp->vac_name == NULL) {
		(void) fprintf(stderr, "%s: %s -- %s\n",
		    gettext("invalid subcommand"),
		    vs_adm_cmd, vs_adm_subcmd);
		return (vs_adm_usage(stderr));
	}

	/* invoke sub-command handler */
	err = cp->vac_func(argc, argv);

	return (err == VS_ADM_EXIT_USAGE ? vs_adm_usage(stderr) : err);
}


/*
 * vs_adm_usage
 */
static int
vs_adm_usage(FILE *fp)
{
	const vs_adm_cmd_t *cp;

	for (cp = vs_adm_cmds; cp->vac_name != NULL; cp++) {
		(void) fprintf(fp, "%s %s", vs_adm_cmd, cp->vac_name);
		if (cp->vac_helpid != NULL)
			(void) fprintf(fp, " %s\n", cp->vac_helpid);
	}

	return (VS_ADM_EXIT_USAGE);
}


/*
 * vs_adm_get
 *
 * Gets and displays general vscan service configuration properties.
 */
static int
vs_adm_get(int argc, char **argv)
{
	uint64_t propids;
	int i, rc;
	vs_props_t vp;
	const vs_adm_property_t *vap;

	(void) memset(&vp, 0, sizeof (vp));

	if (argc <= 2) {
		propids = VS_PROPID_GEN_ALL;
	} else {
		propids = 0LL;
		for (i = 2; i < argc; i++) {
			/* the "-p" specifier is optional */
			if (strcmp(argv[i], "-p") == 0) {
				if (++i >= argc)
					return (VS_ADM_EXIT_USAGE);
			}

			if ((vap = vs_adm_prop_by_name(argv[i])) == NULL) {
				(void) fprintf(stderr, "%s '%s'\n",
				    gettext("invalid property"), argv[i]);
				return (VS_ADM_EXIT_ERROR);
			}

			propids |= vap->vap_id;
		}
	}

	rc = vs_props_get(&vp, propids);
	if (rc != VS_ERR_NONE) {
		(void) fprintf(stderr, "%s\n", vs_strerror(rc));
		return (VS_ADM_EXIT_ERROR);
	}

	vs_adm_output_getcmd(propids, &vp);

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_set
 *
 * Sets values for general vscan service configuration properties
 *
 * Calls a common function used by the set, add, and remove
 * subcommands to modify general property values.
 */
static int
vs_adm_set(int argc, char **argv)
{
	vs_props_t vp;
	uint64_t propids;
	int rc;

	if (argc < 3)
		return (VS_ADM_EXIT_USAGE);

	rc = vs_adm_props_from_input(argc, argv, &vp, &propids);
	if (rc != VS_ADM_EXIT_SUCCESS)
		return (rc);

	rc = vs_props_set(&vp, propids);
	if (rc != VS_ERR_NONE) {
		(void) fprintf(stderr, "%s\n", vs_strerror(rc));
		return (VS_ADM_EXIT_ERROR);
	}

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_get_engine
 *
 * Gets and displays scan engine configuration properties for
 * one or more scan engines.
 */
static int
vs_adm_get_engine(int argc, char **argv)
{
	int i, rc;
	uint64_t propids;
	char *engid = NULL;
	const vs_adm_property_t *vap;
	vs_props_all_t va;

	propids = 0LL;
	for (i = 2; i < argc; i++) {
		/* if not preceded by -p, must be engine id and must be last */
		if (strcmp(argv[i], "-p") != 0) {
			if (i != (argc - 1))
				return (VS_ADM_EXIT_USAGE);

			engid = argv[i];
			if (strlen(engid) > VS_SE_NAME_LEN) {
				(void) fprintf(stderr, "%s\n",
				    gettext("invalid scan engine"));
				return (VS_ADM_EXIT_ERROR);
			}
		} else {
			/* property should follow the -p */
			if (++i >= argc)
				return (VS_ADM_EXIT_USAGE);

			if ((vap = vs_adm_prop_by_name(argv[i])) == NULL) {
				(void) fprintf(stderr, "%s '%s'\n",
				    gettext("invalid property"), argv[i]);
				return (VS_ADM_EXIT_ERROR);
			}

			propids |= vap->vap_id;
		}
	}

	if (propids == 0LL)
		propids = VS_PROPID_SE_ALL;

	/* get properties for specified engine */
	if (engid) {
		rc = vs_props_se_get(engid, &va.va_se[0], propids);
		if (rc != VS_ERR_NONE) {
			(void) fprintf(stderr, "%s\n", vs_strerror(rc));
			return (VS_ADM_EXIT_ERROR);
		}
		vs_adm_output_getcmd(propids, &va.va_se[0]);
		return (VS_ADM_EXIT_SUCCESS);
	}

	/* get properties for all engines */
	if ((rc = vs_props_get_all(&va)) != VS_ERR_NONE) {
		(void) fprintf(stderr, "%s\n", vs_strerror(rc));
		return (VS_ADM_EXIT_ERROR);
	}

	for (i = 0; i < VS_SE_MAX; i++) {
		if (*(va.va_se[i].vep_engid) == 0)
			break;
		vs_adm_output_getcmd(propids, &va.va_se[i]);
	}
	if (i == 0) {
		(void) fprintf(stdout, "%s\n",
		    gettext("no scan engines configured"));
	}

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_set_engine
 *
 * Sets one or more scan engine configuration properties for a
 * single scan engine.
 */
static int
vs_adm_set_engine(int argc, char **argv)
{
	const vs_adm_property_t *vap;
	vs_props_se_t sep;
	char *val;
	uint64_t propids;
	int i, rc;
	char *engid;
	int add = (strcmp(vs_adm_subcmd, "add-engine") == 0) ? 1 : 0;


	if ((argc < 3) || ((!add) && (argc < 4)))
		return (VS_ADM_EXIT_USAGE);

	/* Get the engine id */
	engid = argv[argc - 1];
	if (strchr(engid, '=') || strcmp(argv[argc - 2], "-p") == 0) {
		return (VS_ADM_EXIT_USAGE);
	}

	if (strlen(engid) > VS_SE_NAME_LEN) {
		(void) fprintf(stderr, "%s\n",
		    gettext("invalid scan engine"));
		return (VS_ADM_EXIT_ERROR);
	}

	propids = 0LL;

	for (i = 2; i < (argc - 1); i++) {
		/* The "-p" is optional */
		if (strcmp(argv[i], "-p") == 0) {
			if (++i >= argc)
				return (VS_ADM_EXIT_USAGE);
		}

		if ((val = strchr(argv[i], '=')) == NULL)
			return (VS_ADM_EXIT_USAGE);

		*val = 0;
		val++;

		/* Find the SE property pointer from the SE property name */
		if ((vap = vs_adm_prop_by_name(argv[i])) == NULL) {
			(void) fprintf(stderr, "%s '%s'\n",
			    gettext("invalid property"), argv[i]);
			return (VS_ADM_EXIT_ERROR);
		}

		propids |= vap->vap_id;

		if ((vs_adm_parse(vap, val, &sep)) != 0) {
			(void) fprintf(stderr, "%s '%s'\n",
			    gettext("invalid property value"), val);
			return (VS_ADM_EXIT_ERROR);
		}
	}

	if (add)
		rc = vs_props_se_create(engid, &sep, propids);
	else
		rc = vs_props_se_set(engid, &sep, propids);

	if (rc != VS_ERR_NONE) {
		(void) fprintf(stderr, "%s\n", vs_strerror(rc));
		return (VS_ADM_EXIT_ERROR);
	}

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_rem_engine
 */
/* ARGSUSED */
static int
vs_adm_rem_engine(int argc, char **argv)
{
	int rc;
	char *engid;

	if (argc != 3)
		return (VS_ADM_EXIT_USAGE);

	engid = argv[2];

	if (strlen(engid) > VS_SE_NAME_LEN) {
		(void) fprintf(stderr, "%s\n",
		    gettext("invalid scan engine"));
		return (VS_ADM_EXIT_ERROR);
	}

	if ((rc = vs_props_se_delete(engid)) != VS_ERR_NONE) {
		(void) fprintf(stderr, "%s\n", vs_strerror(rc));
		return (rc);
	}

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_import
 */
static int
vs_adm_import(int argc, char **argv)
{
	int rc;
	vs_props_t vp;
	uint64_t propids;
	char *filename;

	if ((rc = vs_adm_file_usage(argc, argv)) != VS_ADM_EXIT_SUCCESS)
		return (rc);

	filename = argv[argc - 1];
	rc = vs_adm_file_read(filename, vp.vp_types, sizeof (vp.vp_types));
	if (rc != VS_ADM_EXIT_SUCCESS)
		return (rc);

	propids = VS_PROPID_TYPES;
	rc = vs_props_set(&vp, propids);
	if (rc != VS_ERR_NONE) {
		(void) fprintf(stderr, "%s\n", vs_strerror(rc));
		return (VS_ADM_EXIT_ERROR);
	}

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_validate
 */
static int
vs_adm_validate(int argc, char **argv)
{
	int rc;
	vs_props_t vp;
	char *filename;

	if ((rc = vs_adm_file_usage(argc, argv)) != VS_ADM_EXIT_SUCCESS)
		return (rc);

	filename = argv[argc - 1];
	rc = vs_adm_file_read(filename, vp.vp_types, sizeof (vp.vp_types));
	if (rc != VS_ADM_EXIT_SUCCESS)
		return (rc);

	if (vs_props_validate(&vp, VS_PROPID_TYPES) != VS_ERR_NONE) {
		(void) fprintf(stderr, "%s: %s\n", filename, vs_strerror(rc));
		return (VS_ADM_EXIT_ERROR);
	}

	(void) fprintf(stdout, "%s: valid\n", filename);
	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_export
 */
static int
vs_adm_export(int argc, char **argv)
{
	int rc;
	vs_props_t vp;
	uint64_t propids;
	char *filename;

	if ((rc = vs_adm_file_usage(argc, argv)) != VS_ADM_EXIT_SUCCESS)
		return (rc);

	filename = argv[argc - 1];
	(void) memset(&vp, 0, sizeof (vs_props_t));
	propids = VS_PROPID_TYPES;
	if ((rc = vs_props_get(&vp, propids)) != VS_ERR_NONE) {
		(void) fprintf(stderr, "%s: %s\n", filename, vs_strerror(rc));
		return (VS_ADM_EXIT_ERROR);
	}

	rc = vs_adm_file_write(filename, vp.vp_types);
	if (rc != VS_ADM_EXIT_SUCCESS)
		return (rc);

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_file_usage
 *
 * import, export and validate - VS_PROPID_TYPES only
 */
static int
vs_adm_file_usage(int argc, char **argv)
{
	const vs_adm_property_t *vap;
	char *prop;

	if (argc < 4)
		return (VS_ADM_EXIT_USAGE);

	/* -p optional */
	if (strcmp(argv[2], "-p") == 0) {
		if (argc != 5)
			return (VS_ADM_EXIT_USAGE);
	} else if (argc != 4)
		return (VS_ADM_EXIT_USAGE);

	/* only VS_PROPID_TYPES supported */
	prop = argv[argc - 2];
	vap = vs_adm_prop_by_name(prop);
	if ((vap == NULL) || (vap->vap_id != VS_PROPID_TYPES)) {
		(void) fprintf(stderr, "%s '%s'\n",
		    gettext("invalid property"), prop);
		return (VS_ADM_EXIT_USAGE);
	}

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_file_read
 */
static int
vs_adm_file_read(char *filename, char *buf, int len)
{
	FILE *fp;

	if ((fp = fopen(filename, "r")) == NULL) {
		(void) fprintf(stderr, "%s: %s\n", filename,
		    vs_strerror(VS_ERR_SYS));
		return (VS_ADM_EXIT_ERROR);
	}

	(void) memset(buf, 0, len);
	if (fgets(buf, len, fp) == NULL) {
		(void) fprintf(stderr, "%s: %s\n", filename,
		    gettext("invalid property value"));
		(void) fclose(fp);
		return (VS_ADM_EXIT_ERROR);
	}

	(void) fclose(fp);

	/* remove newline */
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = '\0';

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_file_write
 */
static int
vs_adm_file_write(char *filename, char *buf)
{
	FILE *fp;
	int bytes;

	if ((fp = fopen(filename, "w")) == NULL) {
		(void) fprintf(stderr, "%s: %s\n", filename,
		    vs_strerror(VS_ERR_SYS));
		return (VS_ADM_EXIT_ERROR);
	}

	bytes = fprintf(fp, "%s\n", buf);
	if ((bytes < 0) || (bytes != strlen(buf) + 1)) {
		(void) fprintf(stderr, "%s: %s\n", filename,
		    vs_strerror(VS_ERR_SYS));
		(void) fclose(fp);
		return (VS_ADM_EXIT_ERROR);
	}

	(void) fclose(fp);
	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_show
 *
 * Gets and displays all general properties and all scan engine
 * properties.
 */
/* ARGSUSED */
static int
vs_adm_show(int argc, char **argv)
{
	if (argc > 2)
		return (VS_ADM_EXIT_USAGE);

	(void) vs_adm_get(argc, argv);
	(void) vs_adm_get_engine(argc, argv);

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_stats
 *
 * Gets and displays vscan service statistics.
 */
/* ARGSUSED */
static int
vs_adm_stats(int argc, char **argv)
{
	int rc;
	vs_stats_t stats;

	/* get statistics */
	if (argc == 2) {
		if ((rc = vs_statistics(&stats)) == VS_ERR_NONE) {
			vs_adm_output_stats(&stats);
			return (VS_ADM_EXIT_SUCCESS);
		} else {
			(void) fprintf(stdout, "%s\n", vs_strerror(rc));
			return (VS_ADM_EXIT_ERROR);
		}
	}

	/* reset statistics */
	if (argc == 3 && strcmp(argv[2], "-z") == 0) {
		if ((rc = vs_statistics_reset()) == VS_ERR_NONE) {
			return (VS_ADM_EXIT_SUCCESS);
		} else {
			(void) fprintf(stdout, "%s\n", vs_strerror(rc));
			return (VS_ADM_EXIT_ERROR);
		}
	}

	/* usage error */
	return (vs_adm_usage(stdout));
}


/*
 * vs_adm_output_stats
 */
static void
vs_adm_output_stats(vs_stats_t *stats)
{
	int i;
	char *engid;

	if (stats == NULL)
		return;

	(void) fprintf(stdout, "scanned=%lld\n", stats->vss_scanned);
	(void) fprintf(stdout, "infected=%lld\n", stats->vss_infected);
	if (stats->vss_cleaned > 0)
		(void) printf("cleaned=%lld\n", stats->vss_cleaned);
	(void) fprintf(stdout, "failed=%lld\n", stats->vss_failed);

	for (i = 0; i < VS_SE_MAX; i++) {
		engid = stats->vss_eng[i].vss_engid;
		if (*engid == 0)
			break;
		(void) fprintf(stdout, "%s:errors=%lld\n", engid,
		    stats->vss_eng[i].vss_errors);
	}
}


/*
 * vs_adm_props_from_input
 */
static int
vs_adm_props_from_input(int argc, char **argv, vs_props_t *vsprops,
    uint64_t *propids)
{
	const vs_adm_property_t *vap;
	char *val;
	int i;

	(void) memset(vsprops, 0, sizeof (vs_props_t));

	*propids = 0LL;
	for (i = 2; i < argc; i++) {
		/* The "-p" is optional */
		if (strcmp(argv[i], "-p") == 0) {
			if (++i >= argc)
				return (VS_ADM_EXIT_USAGE);
		}

		if ((val = strchr(argv[i], '=')) == NULL)
			return (VS_ADM_EXIT_USAGE);

		/* Find the vscanadm property pointer from the property name */
		*val = '\0';
		val++;
		if ((vap = vs_adm_prop_by_name(argv[i])) == NULL) {
			(void) fprintf(stderr, "%s '%s'\n",
			    gettext("invalid property"), argv[i]);
			return (VS_ADM_EXIT_ERROR);
		}

		/* Add in the property id and parse the property value */
		*propids |= vap->vap_id;
		if ((vs_adm_parse(vap, val, vsprops)) != 0) {
			(void) fprintf(stderr, "%s '%s'\n",
			    gettext("invalid property value"), val);
			return (VS_ADM_EXIT_ERROR);
		}
	}

	return (VS_ADM_EXIT_SUCCESS);
}


/*
 * vs_adm_output_getcmd
 *
 * Prints the results of a get command; both the get for general
 * configuration properties as well as the get for an engine
 * properties.
 *
 */
static void
vs_adm_output_getcmd(uint64_t propids, const void *props)
{
	char value[VS_ADM_PRINT_BUF_LEN];
	uint64_t propid;
	const vs_adm_property_t *vap;
	char *label = NULL;

	if (VS_PROPID_IS_SE(propids))
		label = ((vs_props_se_t *)props)->vep_engid;

	/*
	 * Unparse values from the property structure into readable strings
	 * and print them.
	 */
	for (propid = 1LL; propid <= VS_PROPID_MAX; propid <<= 1) {
		if ((propids & propid) == 0)
			continue;

		if ((vap = vs_adm_prop_by_id(propid)) == NULL)
			continue;

		*value = '\0';
		vs_adm_unparse(vap, props, value, sizeof (value));

		if (label)
			(void) fprintf(stdout, "%s:", label);
		(void) fprintf(stdout, "%s=%s\n", vap->vap_name, value);
	}

	(void) fprintf(stdout, "\n");
}


/*
 * vs_adm_prop_by_name
 *
 * Finds and returns a pointer to a vscan property structure from the
 * property table by property name.
 */
static const vs_adm_property_t *
vs_adm_prop_by_name(const char *propname)
{
	const vs_adm_property_t *p;

	for (p = vs_adm_props_all; p->vap_name != NULL; p++) {
		if (strcmp(propname, p->vap_name) == 0)
			return (p);
	}

	return (NULL);
}


/*
 * vs_adm_prop_by_id
 *
 * Finds and returns a pointer to a vscan property structure from the
 * property table by property name.
 */
static const vs_adm_property_t *
vs_adm_prop_by_id(const uint64_t propid)
{
	const vs_adm_property_t *p;

	for (p = vs_adm_props_all; p->vap_id != 0; p++) {
		if (propid == p->vap_id)
			return (p);
	}

	return (NULL);
}


/*
 * vs_adm_parse
 *
 * Entry point for parsing the user input strings into a data structure
 * used for setting values. Dispatches the actual parsing to the parse
 * routine for the specified vscanadm property.
 *
 * This function is used to dispatch parsing for values supplied by the
 * user for all subcommands; both the general configuration as well as
 * scan engine configuration. The structure pointer is therefore typed
 * as a void pointer, and cast appropriately in the parse routine for
 * the vscanadm property.
 */
static int
vs_adm_parse(const vs_adm_property_t *vap, const char *valvap_name,
	void *vp)
{
	return ((vap->vap_parse)(valvap_name, vp));
}


/*
 * vs_adm_parse_maxsize
 *
 * Parses a user-supplied string into a maxsize (decimal) value for
 * the general vscan configuration properties.
 */
static int
vs_adm_parse_maxsize(const char *valstr, void *vp)
{
	vs_props_t *svcp = vp;

	uint64_t maxsize;
	char *end;

	errno = 0;
	maxsize = strtoll(valstr, &end, 10);
	if (errno != 0)
		return (-1);
	(void) snprintf(svcp->vp_maxsize, sizeof (svcp->vp_maxsize),
	    "%llu%s", maxsize, end);

	return (0);
}


/*
 * vs_adm_parse_maxsize_action
 *
 * Parses a user-supplied string into a maxsize action value for the
 * general vscan configuration properties.
 *
 * Returns: 0 success
 *         -1 failure
 */
static int
vs_adm_parse_maxsize_action(const char *valstr, void *vp)
{
	vs_props_t *svcp = vp;

	if (strcmp(valstr, VS_ADM_ALLOW) == 0) {
		svcp->vp_maxsize_action = B_TRUE;
		return (0);
	}

	if (strcmp(valstr, VS_ADM_DENY) == 0) {
		svcp->vp_maxsize_action = B_FALSE;
		return (0);
	}

	return (-1);
}


/*
 * vs_adm_parse_types
 *
 * Returns: 0 success
 *         -1 on failure.
 */
static int
vs_adm_parse_types(const char *valstr, void *vp)
{
	vs_props_t *svcp = vp;

	if (strlen(valstr) >= sizeof (svcp->vp_types))
		return (-1);

	if (strlcpy(svcp->vp_types, valstr, sizeof (svcp->vp_types))
	    >= sizeof (svcp->vp_types))
		return (-1);

	return (0);
}


/*
 * vs_adm_parse_enable
 *
 * Parses a user-supplied string into an enable value for the
 * properties of a scan engine.
 *
 * Returns: 0 success
 *         -1 on failure.
 */
static int
vs_adm_parse_enable(const char *valstr, void *vp)
{
	vs_props_se_t *sep = vp;

	if (strcmp(valstr, VS_ADM_ON) == 0) {
		sep->vep_enable = B_TRUE;
		return (0);
	}

	if (strcmp(valstr, VS_ADM_OFF) == 0) {
		sep->vep_enable = B_FALSE;
		return (0);
	}

	return (-1);
}


/*
 * vs_adm_parse_host
 *
 * Parses a user-supplied string into an ip address value for the
 * properties of a scan engine.
 */
static int
vs_adm_parse_host(const char *valstr, void *vp)
{
	vs_props_se_t *sep = vp;

	if (strlen(valstr) >= sizeof (sep->vep_host))
		return (-1);

	if (strlcpy(sep->vep_host, valstr, sizeof (sep->vep_host)) >=
	    sizeof (sep->vep_host))
		return (-1);

	return (0);
}


/*
 * vs_adm_parse_port
 *
 * Parses a user-supplied string into a port value for the properties of
 * a scan engine. The port is an unsigned short int, but the conversion
 * must be done on a word-sized int. Casting the converted int into the
 * port member of the property structure can result in a valid but
 * unintended value, so the range is checked first for validity.
 *
 * Returns: 0 success
 *         -1 on failure.
 */
static int
vs_adm_parse_port(const char *valstr, void *vp)
{
	vs_props_se_t *sep = vp;
	unsigned long port;
	char *end;

	end = 0;
	port = strtoul(valstr, &end, 0);
	if (port > UINT16_MAX || (end < (valstr + strlen(valstr))))
		return (-1);

	sep->vep_port = port;

	return (0);
}


/*
 * vs_adm_parse_maxconn
 *
 * Parses a user-supplied string into a max connections (decimal) value
 * for the properties of a scan engine.
 *
 * Returns: 0 success
 *         -1 on failure.
 */
static int
vs_adm_parse_maxconn(const char *valstr, void *vp)
{
	vs_props_se_t *sep = vp;
	char *end;

	sep->vep_maxconn = strtoll(valstr, &end, 10);
	if (end < valstr + strlen(valstr))
		return (-1);

	return (0);
}


/*
 * vs_adm_unparse
 *
 * Entry point for unparsing native data into a readable string
 * used for display to the user. Dispatches the actual unparsing to
 * the unparse routine for the specified vscanadm property.
 *
 * This function is used to dispatch unparsing for all subcommands.
 * The structure pointer is therefore typed as a void pointer, and
 * cast appropriately in the unparse routine for the vscanadm property.
 */
static void
vs_adm_unparse(const vs_adm_property_t *vap, const void *vp,
	char *buf, size_t len)
{
	if ((vap->vap_unparse)(vp, buf, len) != 0)
		(void) snprintf(buf, len, gettext(" (error) "));
}


/*
 *  vs_adm_unparse_maxsize
 *
 * Unparses a max fsize value in native data form into a
 * user-readable string.
 */
/* ARGSUSED */
static int
vs_adm_unparse_maxsize(const void *vp, char *buf, size_t len)
{
	const vs_props_t *svcp = vp;

	(void) snprintf(buf, len, "%s", svcp->vp_maxsize);

	return (0);
}


/*
 * vs_adm_unparse_maxsize_action
 *
 * Unparses a max fsize action value in native data form into a
 * user-readable string.
 */
/* ARGSUSED */
static int
vs_adm_unparse_maxsize_action(const void *vp, char *buf, size_t len)
{
	const vs_props_t *svcp = vp;

	(void) snprintf(buf, len, "%s",
	    svcp->vp_maxsize_action ?  VS_ADM_ALLOW : VS_ADM_DENY);

	return (0);
}


/*
 * vs_adm_unparse_types
 *
 * Returns: 0 success
 *         -1 on failure.
 */
static int
vs_adm_unparse_types(const void *vp, char *buf, size_t len)
{
	const vs_props_t *svcp = vp;

	(void) strlcpy(buf, svcp->vp_types, len);

	return (0);
}


/*
 * vs_adm_unparse_enable
 *
 * Unparses the enable value for a scan engine in native data
 * form into a user-readable string.
 */
/* ARGSUSED */
static int
vs_adm_unparse_enable(const void *vp, char *buf, size_t len)
{
	const vs_props_se_t *sep = vp;

	(void) snprintf(buf, len, "%s",
	    sep->vep_enable ?  VS_ADM_ON : VS_ADM_OFF);

	return (0);
}


/*
 * vs_adm_unparse_host
 *
 * Unparses an ip address for a scan engine in native data
 * form into a user-readable string.
 *
 * Returns: 0 success
 *         -1 on failure.
 */
/* ARGSUSED */
static int
vs_adm_unparse_host(const void *vp, char *buf, size_t len)
{
	const vs_props_se_t *sep = vp;

	(void) strlcpy(buf, sep->vep_host, len);

	return (0);
}


/*
 * vs_adm_unparse_port
 *
 * Unparses a port value for a scan engine in native data
 * form into a user-readable string.
 */
/* ARGSUSED */
static int
vs_adm_unparse_port(const void *vp, char *buf, size_t len)
{
	const vs_props_se_t *sep = vp;

	(void) snprintf(buf, len, "%hu", sep->vep_port);

	return (0);
}


/*
 * vs_adm_unparse_maxconn
 *
 * Unparses a max connecctions for a scan engine in native data
 * form into a user-readable string.
 *
 */
/* ARGSUSED */
static int
vs_adm_unparse_maxconn(const void *vp, char *buf, size_t len)
{
	const vs_props_se_t *sep = vp;

	(void) snprintf(buf, len, "%lld", sep->vep_maxconn);

	return (0);
}
