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

/*
 * lsvcrun - run an rc?.d script, modifying appropriate data in the
 * repository to reflect legacy behavior.
 *
 * We try to keep track of what we can for the legacy scripts via
 * property groups under the smf/legacy_run service.  Each property
 * group identifies a service, named in the form 'rc2_d_S10foo'.
 *
 * Each group has the following properties: name, the script name
 * displayed by svcs(1m); state_timestamp; contract, contract ID;
 * inode, the inode of the script; and suffix, the suffix of the
 * script name, e.g. 'foo'.
 *
 * When we run a K script, we try to identify and remove the
 * property group by means of examining the inode and script
 * suffix.  The inode check means more than one script with the
 * same suffix will still work as intended in the common case.
 *
 * If we cannot find a property group, or one already exists
 * when we try to add one, then we print a suitable warning.  These
 * are warnings because there was no strict requirement that K
 * and S scripts be matched up.
 *
 * In the face of these assumptions being proved wrong, we always
 * make sure to execute the script anyway in an attempt to keep
 * things working as they used to.  If we can't execute the script,
 * we try to leave the repository in the state it was before.
 */

#include <sys/ctfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <libintl.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libuutil.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>


/* Environment variables to pass on.  See clean_environment(). */
static char *evars_to_pass[] = { "LANG", "LC_ALL", "LC_COLLATE", "LC_CTYPE",
	"LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME", "PATH", "TZ"
};

#define	EVARS_TO_PASS_NUM						\
	(sizeof (evars_to_pass) / sizeof (*evars_to_pass))


static void
usage()
{
	(void) fprintf(stderr,
	    gettext("Usage: %s [-s] script {start | stop}\n"), uu_getpname());
	exit(UU_EXIT_USAGE);
}

/*
 * Pick out the script name and convert it for use as an SMF property
 * group name.
 */
static char *
start_pg_name(const char *path)
{
	char *out, *cp;

	if (fnmatch("/etc/rc[0-6S].d/S*", path, FNM_PATHNAME) != 0) {
		uu_warn(gettext("couldn't parse name %s.\n"), path);
		return (NULL);
	}

	out = strdup(path + sizeof ("/etc/") - 1);

	if (out == NULL) {
		uu_warn(gettext("strdup() failed (%s).\n"), strerror(errno));
		return (NULL);
	}

	/* Convert illegal characters to _. */
	for (cp = out; *cp != '\0'; ++cp) {
		/* locale problem? */
		if (!isalnum(*cp) && *cp != '-')
			*cp = '_';
	}

	return (out);
}

static char *
script_suffix(const char *path)
{
	const char *cp;
	char *out;

	if (fnmatch("/etc/rc[0-6S].d/[SK]*", path, FNM_PATHNAME) != 0) {
		uu_warn(gettext("couldn't parse name %s.\n"), path);
		return (NULL);
	}

	cp = path + sizeof ("/etc/rc0.d/S") - 1;

	while (isdigit(*cp))
		cp++;

	if (*cp == '\0') {
		uu_warn(gettext("couldn't parse name %s.\n"), path);
		return (NULL);
	}

	out = strdup(cp);
	if (out == NULL)
		uu_warn(gettext("strdup() failed (%s).\n"), strerror(errno));

	return (out);
}

/*
 * Convert a path to an acceptable SMF (service) name.
 */
static char *
path_to_svc_name(const char *path)
{
	char *out, *cp;

	out = strdup(path);
	if (out == NULL) {
		uu_warn(gettext("strdup() failed (%s).\n"), strerror(errno));
		return (NULL);
	}

	/* Convert illegal characters to _. */
	for (cp = out; *cp != '\0'; ++cp) {
		/* locale problem? */
		if (!isalnum(*cp) && *cp != '-' && *cp != '/')
			*cp = '_';
	}

	/* If the first character is _, use a instead. */
	if (*out == '_')
		*out = 'a';

	return (out);
}

static void
scferr(const char *func)
{
	uu_warn(gettext("%s failed (%s).  Repository will not be modified.\n"),
	    func, scf_strerror(scf_error()));
}

static scf_propertygroup_t *
get_start_pg(const char *script, scf_handle_t *h, scf_service_t *svc,
    boolean_t *ok)
{
	char *pg_name = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;

	if ((pg_name = start_pg_name(script)) == NULL)
		return (NULL);

	if ((pg = scf_pg_create(h)) == NULL) {
		scferr("scf_pg_create()");
		goto out;
	}

add:
	if (scf_service_add_pg(svc, pg_name, SCF_GROUP_FRAMEWORK,
	    SCF_PG_FLAG_NONPERSISTENT, pg) == 0) {
		*ok = 1;
		free(pg_name);
		return (pg);
	}

	switch (scf_error()) {
	case SCF_ERROR_INVALID_ARGUMENT:
		assert(0);
		abort();
		/* NOTREACHED */

	case SCF_ERROR_EXISTS:
		break;

	case SCF_ERROR_PERMISSION_DENIED:
		uu_die(gettext(
		    "Insufficient privilege to add repository properties; "
		    "not launching \"%s\".\n"), script);
		/* NOTREACHED */

	default:
		scferr("scf_service_add_pg()");
		scf_pg_destroy(pg);
		pg = NULL;
		goto out;
	}

	if (scf_service_get_pg(svc, pg_name, pg) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_INVALID_ARGUMENT:
			assert(0);
			abort();
			/* NOTREACHED */

		case SCF_ERROR_NOT_FOUND:
			goto add;

		default:
			scferr("scf_service_get_pg()");
			scf_pg_destroy(pg);
			pg = NULL;
			goto out;
		}
	}

	if ((prop = scf_property_create(h)) == NULL) {
		scferr("scf_property_create()");
		scf_pg_destroy(pg);
		pg = NULL;
		goto out;
	}

	/*
	 * See if the pg has the name property.  If it has, that
	 * implies we successfully ran the same script before.  We
	 * should re-run it anyway, but not modify the existing pg;
	 * this might lose contract-control but there's not much we
	 * can do.
	 *
	 * If there's no name property, then we probably couldn't
	 * remove the pg fully after a script failed to run.
	 */

	if (scf_pg_get_property(pg, SCF_LEGACY_PROPERTY_NAME, prop) == 0) {
		uu_warn(gettext("Service matching \"%s\" "
		    "seems to be running.\n"), script);
		scf_pg_destroy(pg);
		pg = NULL;
	} else if (scf_error() != SCF_ERROR_NOT_FOUND) {
		scferr("scf_pg_get_property()");
		scf_pg_destroy(pg);
		pg = NULL;
	} else {
		uu_warn(gettext("Service \"%s\" has an invalid property "
		    "group.\n"), script);
	}

out:
	free(pg_name);
	scf_property_destroy(prop);
	return (pg);
}

static scf_propertygroup_t *
pg_match(scf_handle_t *h, scf_service_t *svc, ino_t ino, const char *suffix)
{
	char buf[PATH_MAX];
	scf_iter_t *iter = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;

	if ((pg = scf_pg_create(h)) == NULL) {
		scferr("scf_pg_create()");
		goto err;
	}

	if ((iter = scf_iter_create(h)) == NULL) {
		scferr("scf_iter_create()");
		goto err;
	}

	if ((prop = scf_property_create(h)) == NULL) {
		scferr("scf_property_create()");
		goto err;
	}

	if ((val = scf_value_create(h)) == NULL) {
		scferr("scf_value_create()");
		goto err;
	}

	if (scf_iter_service_pgs_typed(iter, svc, SCF_GROUP_FRAMEWORK) !=
	    0) {
		scferr("scf_iter_service_pgs_typed()");
		goto err;
	}

	while (scf_iter_next_pg(iter, pg) > 0) {
		int match = 1;

		if (suffix != NULL) {
			ssize_t len;

			if (scf_pg_get_property(pg, SCF_LEGACY_PROPERTY_SUFFIX,
			    prop) != 0)
				continue;

			if (scf_property_get_value(prop, val) != 0)
				continue;

			len = scf_value_get_astring(val, buf, sizeof (buf));
			if (len < 0) {
				scferr("scf_value_get_astring()");
				goto err;
			}
			if (len >= sizeof (buf))
				continue;

			match = (strcmp(buf, suffix) == 0);
		}

		if (ino != 0) {
			uint64_t pval;

			if (scf_pg_get_property(pg, SCF_LEGACY_PROPERTY_INODE,
			    prop) != 0)
				continue;

			if (scf_property_get_value(prop, val) != 0)
				continue;

			if (scf_value_get_count(val, &pval) != 0)
				continue;

			match = (ino == pval) && match;
		}

		if (match)
			goto out;
	}

err:
	scf_pg_destroy(pg);
	pg = NULL;

out:
	scf_value_destroy(val);
	scf_iter_destroy(iter);
	scf_property_destroy(prop);
	return (pg);
}

/*
 * Try and find the property group matching the service this script
 * stops.  First we look for a matching inode plus a matching suffix.
 * This commonly succeeds, but if not, we just search for inode.
 * Finally, we try for just the script suffix.
 */
static scf_propertygroup_t *
get_stop_pg(const char *script, scf_handle_t *h, scf_service_t *svc,
    boolean_t *ok)
{
	struct stat st;
	char *suffix;
	scf_propertygroup_t *pg;

	if (stat(script, &st) != 0) {
		uu_warn(gettext("Couldn't stat %s (%s).\n"), script,
		    strerror(errno));
		return (NULL);
	}

	if ((suffix = script_suffix(script)) == NULL) {
		pg = pg_match(h, svc, st.st_ino, NULL);
		if (pg != NULL)
			goto out;
		return (NULL);
	}

	if ((pg = pg_match(h, svc, st.st_ino, suffix)) != NULL)
		goto out;

	if ((pg = pg_match(h, svc, st.st_ino, NULL)) != NULL)
		goto out;

	if ((pg = pg_match(h, svc, 0, suffix)) == NULL) {
		uu_warn(gettext("Service matching \"%s\" "
		    "doesn't seem to be running.\n"), script);
		free(suffix);
		return (NULL);
	}

out:
	*ok = 1;
	free(suffix);
	return (pg);
}

static scf_propertygroup_t *
get_script_pg(const char *script, boolean_t start_flag, boolean_t *ok)
{
	scf_handle_t *h = NULL;
	scf_scope_t *scope = NULL;
	scf_service_t *svc = NULL;
	scf_propertygroup_t *pg = NULL;

	*ok = 0;

	h = scf_handle_create(SCF_VERSION);
	if (h == NULL) {
		scferr("scf_handle_create()");
		goto out;
	}

	if (scf_handle_bind(h) != 0) {
		if (scf_error() != SCF_ERROR_NO_SERVER) {
			scferr("scf_handle_bind()");
		} else {
			uu_warn(gettext(
			    "Could not connect to svc.configd.\n"));
		}
		goto out;
	}

	if ((scope = scf_scope_create(h)) == NULL) {
		scferr("scf_scope_create()");
		goto out;
	}

	if ((svc = scf_service_create(h)) == NULL) {
		scferr("scf_service_create()");
		goto out;
	}

	if (scf_handle_get_scope(h, SCF_SCOPE_LOCAL, scope) != 0) {
		scferr("scf_handle_get_local_scope()");
		goto out;
	}

	if (scf_scope_get_service(scope, SCF_LEGACY_SERVICE, svc) != 0) {
		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			scferr("scf_scope_get_service()");
			goto out;
		}

		if (scf_scope_add_service(scope, SCF_LEGACY_SERVICE, svc) !=
		    0) {
			scferr("scf_scope_add_service()");
			goto out;
		}
	}

	if (start_flag)
		pg = get_start_pg(script, h, svc, ok);
	else
		pg = get_stop_pg(script, h, svc, ok);

out:
	scf_service_destroy(svc);
	scf_scope_destroy(scope);
	return (pg);
}

static int
prepare_contract(const char *script, const char *action)
{
	int fd;
	char *svc_name;
	char *svc_strbuf;
	int err = 0;

	do
		fd = open64(CTFS_ROOT "/process/template", O_RDWR);
	while (fd < 0 && errno == EINTR);
	if (fd < 0) {
		uu_warn(gettext("Can not create contract"));
		return (-1);
	}

	svc_strbuf = malloc(CT_PARAM_MAX_SIZE);
	if (svc_strbuf == NULL) {
		uu_warn(gettext("Can not allocate memory"));
		err = -1;
		goto cleanup;
	}

	(void) strlcpy(svc_strbuf, SCF_FMRI_LEGACY_PREFIX, CT_PARAM_MAX_SIZE);
	svc_name = path_to_svc_name(script);
	(void) strlcat(svc_strbuf, svc_name ? svc_name : script,
	    CT_PARAM_MAX_SIZE);
	if (svc_name != NULL) {
		free(svc_name);
	}

	if ((errno = ct_pr_tmpl_set_svc_fmri(fd, svc_strbuf)) != 0) {
		uu_warn(gettext("Can not set svc_fmri"));
		err = -1;
		goto cleanup;
	}

	(void) strlcpy(svc_strbuf, action, CT_PARAM_MAX_SIZE);
	if ((errno = ct_pr_tmpl_set_svc_aux(fd, svc_strbuf)) != 0) {
		uu_warn(gettext("Can not set svc_aux"));
		err = -1;
		goto cleanup;
	}

	/* Leave HWERR in fatal set. */

	errno = ct_tmpl_activate(fd);
	if (errno != 0) {
		assert(errno == EPERM);
		uu_warn(gettext("Can not activate contract template"));
		err = -1;
		goto cleanup;
	}

cleanup:
	if (svc_strbuf != NULL)
		free(svc_strbuf);
	(void) close(fd);

	return (err);
}

static void
cleanup_pg(scf_propertygroup_t *pg)
{
	scf_error_t err;
	char buf[80];

	if (scf_pg_delete(pg) == 0)
		return;

	err = scf_error();

	if (scf_pg_to_fmri(pg, buf, sizeof (buf)) != 0)
		(void) strcpy(buf, "?");

	uu_warn(gettext("Could not remove property group %s: %s.\n"), buf,
	    scf_strerror(err));
}

/*
 * Create a duplicate environment which only contains approved
 * variables---those in evars_to_pass and those beginning with "_INIT_".
 */
static char **
approved_env(char **env)
{
	char **newenv;
	int i, i_new, j;

	for (i = 0; env[i] != NULL; ++i)
		;

	newenv = malloc(sizeof (*newenv) * (i + 1));
	if (newenv == NULL)
		return (NULL);

	i_new = 0;

	for (i = 0; env[i] != NULL; ++i) {
		if (strncmp(env[i], "_INIT_", sizeof ("_INIT_") - 1) == 0) {
			newenv[i_new++] = env[i];
			continue;
		}

		for (j = 0; j < EVARS_TO_PASS_NUM; ++j) {
			size_t l = strlen(evars_to_pass[j]);

			if (env[i][l] == '=' &&
			    strncmp(env[i], evars_to_pass[j], l) == 0)
				newenv[i_new++] = env[i];
		}
	}

	newenv[i_new] = NULL;

	return (newenv);
}

/*
 * Create a duplicate environment which does not contain any SMF_ variables.
 */
static char **
env_without_smf(char **env)
{
	char **newenv;
	int i, i_new;

	for (i = 0; env[i] != NULL; ++i)
		;

	newenv = malloc(sizeof (*newenv) * (i + 1));
	if (newenv == NULL)
		return (NULL);

	i_new = 0;

	for (i = 0; env[i] != NULL; ++i) {
		if (strncmp(env[i], "SMF_", sizeof ("SMF_") - 1) == 0)
			continue;

		newenv[i_new++] = env[i];
	}

	newenv[i_new] = NULL;

	return (newenv);
}

static int
add_new_property(scf_handle_t *h, scf_transaction_t *tx, const char *name,
    scf_type_t ty, const void *val)
{
	scf_transaction_entry_t *e;
	scf_value_t *v;
	const char *func;
	const struct timeval *t;
	int r;

	if ((e = scf_entry_create(h)) == NULL) {
		func = "scf_entry_create()";
		goto err;
	}

	if ((v = scf_value_create(h)) == NULL) {
		func = "scf_value_create()";
		goto err;
	}

	r = scf_transaction_property_new(tx, e, name, ty);
	if (r != 0) {
		func = "scf_transaction_property_new()";
		goto err;
	}

	switch (ty) {
	case SCF_TYPE_COUNT:
		scf_value_set_count(v, (uint64_t)(uintptr_t)val);
		break;

	case SCF_TYPE_TIME:
		t = val;
		r = scf_value_set_time(v, t->tv_sec, 1000 * t->tv_usec);
		assert(r == 0);
		break;

	case SCF_TYPE_ASTRING:
		r = scf_value_set_astring(v, val);
		assert(r == 0);
		break;

	default:
		assert(0);
		abort();
	}

	if (scf_entry_add_value(e, v) == 0)
		return (0);

	func = "scf_entry_add_value()";

err:
	uu_warn(gettext("%s failed (%s).\n"), func, scf_strerror(scf_error()));
	return (-1);
}

static void
set_legacy_service(scf_propertygroup_t *pg, const char *script)
{
	scf_handle_t *h;
	const char *func;
	char *suffix;
	scf_transaction_t *tx;
	struct timeval tstamp;
	struct stat st;
	ctid_t ctid;
	char *svc_name = NULL;
	int ret;

	h = scf_pg_handle(pg);
	if (h == NULL) {
		func = "scf_pg_handle()";
		goto scferr;
	}

	ret = gettimeofday(&tstamp, NULL);
	assert(ret == 0);

	if (stat(script, &st) != 0) {
		uu_warn(gettext("Couldn't stat %s (%s).\n"), script,
		    strerror(errno));
		goto err;
	}

	if (errno = contract_latest(&ctid)) {
		uu_warn(gettext("Could not get contract"));
		goto err;
	}

	tx = scf_transaction_create(h);
	if (tx == NULL) {
		func = "scf_transaction_create()";
		goto scferr;
	}

	if (scf_transaction_start(tx, pg) != 0) {
		func = "scf_transaction_start()";
		goto scferr;
	}

	/*
	 * We'd like to use the prettier svc_name, but if path_to_svc_name()
	 * fails, we can use the script name anyway.
	 */
	svc_name = path_to_svc_name(script);

	if (add_new_property(h, tx, SCF_LEGACY_PROPERTY_NAME, SCF_TYPE_ASTRING,
	    (void *)(svc_name ? svc_name : script)) != 0)
		goto err;

	if (add_new_property(h, tx, SCF_PROPERTY_STATE_TIMESTAMP,
	    SCF_TYPE_TIME, &tstamp) != 0)
		goto err;

	if (add_new_property(h, tx, SCF_LEGACY_PROPERTY_INODE,
	    SCF_TYPE_COUNT, (void *)st.st_ino) != 0)
		goto err;

	if ((suffix = script_suffix(script)) != NULL) {
		if (add_new_property(h, tx, SCF_LEGACY_PROPERTY_SUFFIX,
		    SCF_TYPE_ASTRING, (void *)suffix) != 0)
			goto err;

		free(suffix);
	}

	if (add_new_property(h, tx, SCF_PROPERTY_CONTRACT, SCF_TYPE_COUNT,
	    (void *)ctid) != 0)
		goto err;

	for (;;) {
		switch (scf_transaction_commit(tx)) {
		case 1:
			free(svc_name);
			return;

		case 0:
			if (scf_pg_update(pg) == -1) {
				func = "scf_pg_update()";
				goto scferr;
			}
			continue;

		case -1:
			func = "scf_transaction_commit()";
			goto scferr;

		default:
			assert(0);
			abort();
		}
	}

scferr:
	uu_warn(gettext("%s failed (%s).\n"), func, scf_strerror(scf_error()));
err:
	uu_die(gettext("Could not commit property values to repository.\n"));
}

int
main(int argc, char *argv[], char *envp[])
{
	const char *restarter, *script, *action;
	boolean_t source = 0;
	int o;
	boolean_t start_flag;
	char **newenv;
	pid_t pid;
	int pipefds[2];
	char c;
	int exitstatus;

	scf_propertygroup_t *pg;
	boolean_t pg_ok;

	(void) uu_setpname(argv[0]);
	uu_alt_exit(UU_PROFILE_LAUNCHER);

	/* Make sure we were run by svc.startd. */
	if ((restarter = getenv("SMF_RESTARTER")) == NULL ||
	    strcmp(restarter, SCF_SERVICE_STARTD) != 0)
		uu_die(gettext("invocation outside smf(5) inappropriate\n"));

	while ((o = getopt(argc, argv, "s")) != -1) {
		switch (o) {
		case 's':
			source = 1;
			break;

		default:
			usage();
		}
	}

	if (argc - optind != 2)
		usage();

	script = argv[optind];
	action = argv[optind + 1];

	if (strcmp(action, "start") == 0)
		start_flag = 1;
	else if (strcmp(action, "stop") == 0)
		start_flag = 0;
	else
		usage();

	/*
	 * Look for the pg & exit if appropriate.  Also, if we're starting,
	 * add the pg now so we can exit before launching the script if we
	 * have insufficient repository privilege.
	 *
	 * If any other problem occurs, we carry on anyway.
	 */
	pg = get_script_pg(script, start_flag, &pg_ok);

	/* Clean the environment.  Now so we can fail early. */
	if (!source)
		newenv = approved_env(envp);
	else
		newenv = env_without_smf(envp);
	if (newenv == NULL)
		uu_die(gettext(
		    "Could not create new environment: out of memory.\n"));

	if (prepare_contract(script, action) == -1) {
		if (start_flag && pg != NULL)
			cleanup_pg(pg);

		exit(UU_EXIT_FATAL);
	}

	/* pipe to communicate exec success or failure */
	if (pipe(pipefds) != 0) {
		uu_warn(gettext("Could not create pipe"));

		if (start_flag && pg != NULL)
			cleanup_pg(pg);

		exit(UU_EXIT_FATAL);
	}

	if (!pg_ok)
		(void) printf(gettext("Executing legacy init script \"%s\" "
		    "despite previous errors.\n"), script);
	else
		(void) printf(gettext("Executing legacy init script \"%s\".\n"),
		    script);
	(void) fflush(stdout);

	pid = fork();
	if (pid < 0) {
		uu_warn(gettext("Could not fork"));

		if (start_flag && pg != NULL)
			cleanup_pg(pg);

		exit(UU_EXIT_FATAL);
	}

	if (pid == 0) {
		/* child */

		const char *arg1, *arg2, *arg3;

		(void) close(pipefds[0]);
		(void) fcntl(pipefds[1], F_SETFD, FD_CLOEXEC);

		if (!source) {
			arg1 = "/bin/sh";
			arg2 = script;
			arg3 = action;
		} else {
			arg1 = "/bin/sh";
			arg2 = "-c";
			arg3 = script;
		}

		(void) execle(arg1, arg1, arg2, arg3, NULL, newenv);

		uu_warn(gettext("Could not exec \"%s %s %s\""), arg1,
		    arg2, arg3);


		/* Notify parent of the failure. */
		while (write(pipefds[1], &c, 1) != 1) {
			switch (errno) {
			case EAGAIN:
				(void) sleep(1);

				/* FALLTHROUGH */

			case EINTR:
				continue;
			}

			uu_warn(gettext("Could not inform parent of error"));
			break;
		}

		exit(UU_EXIT_FATAL);
	}

	(void) close(pipefds[1]);

	if (read(pipefds[0], &c, sizeof (c)) > 0) {
		if (!start_flag)
			uu_die(gettext("exec() failed; leaving properties.\n"));
		else {
			uu_warn(gettext("exec() failed.\n"));
			if (pg != NULL)
				cleanup_pg(pg);
			exit(UU_EXIT_FATAL);
		}
	}

	while (waitpid(pid, &exitstatus, 0) == -1) {
		assert(errno == EINTR);
	}

	if (WIFSIGNALED(exitstatus)) {
		char buf[SIG2STR_MAX];
		(void) sig2str(WTERMSIG(exitstatus), buf);
		(void) printf(gettext("Legacy init script \"%s\" failed due "
		    "to signal %s.\n"), script, buf);
	} else {
		(void) printf(gettext("Legacy init script \"%s\" exited with "
		    "return code %d.\n"), script, WEXITSTATUS(exitstatus));
	}

	if (pg != NULL) {
		if (start_flag)
			set_legacy_service(pg, script);
		else
			cleanup_pg(pg);
		scf_pg_destroy(pg);
	}

	return (UU_EXIT_OK);
}
