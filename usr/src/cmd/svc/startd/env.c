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
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#include <assert.h>
#include <definit.h>
#include <libuutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zone.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "startd.h"

/*
 * This file contains functions for setting the environment for
 * processes started by svc.startd.
 */

#define	MAXCMDL		512
#define	DEF_PATH	"PATH=/usr/sbin:/usr/bin"

static char **glob_envp;	/* Array of environment strings */
static int glob_env_n;		/* Number of environment slots allocated. */

static char zonename[ZONENAME_MAX];

/*
 * init_env()
 *   A clone of the work init.c does to provide as much compatibility
 *   for startup scripts as possible.
 */
void
init_env()
{
	void		*dstate;
	const char	*tokp;
	int		i;

	glob_env_n = 16;
	glob_envp = startd_alloc(sizeof (*glob_envp) * glob_env_n);

	glob_envp[0] = startd_alloc((unsigned)(strlen(DEF_PATH)+2));
	(void) strcpy(glob_envp[0], DEF_PATH);

	if (definit_open(DEFINIT_DEFAULT_FILE, &dstate) != 0) {
		uu_warn("Cannot open %s. Environment not initialized.\n",
		    DEFINIT_DEFAULT_FILE);

		glob_envp[1] = NULL;
		return;
	}

	i = 1;
	while ((tokp = definit_token(dstate)) != NULL) {
		size_t length = strlen(tokp);

		/*
		 * init already started us with this umask, and we
		 * handled it in startd.c, so just skip it.
		 */
		if (strncmp(tokp, "CMASK=", 6) == 0 ||
		    strncmp(tokp, "SMF_", 4) == 0) {
			continue;
		}

		glob_envp[i] = startd_alloc((unsigned)(length + 1));
		(void) strcpy(glob_envp[i], tokp);

		/*
		 * Double the environment size whenever it is
		 * full.
		 */
		if (++i == glob_env_n) {
			char **newp;

			glob_env_n *= 2;
			newp = startd_alloc(sizeof (*glob_envp) * glob_env_n);
			(void) memcpy(newp, glob_envp,
			    sizeof (*glob_envp) * glob_env_n / 2);
			startd_free(glob_envp,
			    sizeof (*glob_envp) * glob_env_n / 2);
			glob_envp = newp;
		}
	}

	/* Append a null pointer to the environment array to mark its end. */
	glob_envp[i] = NULL;

	definit_close(dstate);

	/*
	 * Get the zonename once; it is used to set SMF_ZONENAME for methods.
	 */
	(void) getzonenamebyid(getzoneid(), zonename, sizeof (zonename));

}

static int
valid_env_var(const char *var, const restarter_inst_t *inst, const char *path)
{
	char *cp = strchr(var, '=');

	if (cp == NULL || cp == var) {
		if (inst != NULL)
			log_instance(inst, B_FALSE, "Invalid environment "
			    "variable \"%s\".", var);
		return (0);
	} else if (strncmp(var, "SMF_", 4) == 0) {
		if (inst != NULL)
			log_instance(inst, B_FALSE, "Invalid environment "
			    "variable \"%s\"; \"SMF_\" prefix is reserved.",
			    var);
		return (0);
	} else if (path != NULL && strncmp(var, "PATH=", 5) == 0) {
		return (0);
	}

	return (1);
}

static char **
find_dup(const char *var, char **env, const restarter_inst_t *inst)
{
	char **p;
	char *tmp;

	for (p = env; *p != NULL; p++) {
		assert((tmp = strchr(*p, '=')) != NULL);
		tmp++;
		if (strncmp(*p, var, tmp - *p) == 0)
			break;
	}

	if (*p == NULL)
		return (NULL);

	/*
	 * The first entry in the array can be ignored when it is the
	 * default path.
	 */
	if (inst != NULL && p != env &&
	    strncmp(*p, DEF_PATH, strlen(DEF_PATH)) != 0) {
		log_instance(inst, B_FALSE, "Ignoring duplicate "
		    "environment variable \"%s\".", *p);
	}

	return (p);
}

/*
 * Create an environment which is appropriate for spawning an SMF
 * aware process. The new environment will consist of the values from
 * the global environment as modified by the supplied (local) environment.
 *
 * In order to preserve the correctness of the new environment,
 * various checks are performed on the local environment (init_env()
 * is relied upon to ensure the global environment is correct):
 *
 * - All SMF_ entries are ignored. All SMF_ entries should be provided
 *   by this function.
 * - Duplicates in the entry are eliminated.
 * - Malformed entries are eliminated.
 *
 * Detected errors are logged as warnings to the appropriate instance
 * logfile, since a single bad entry should not be enough to prevent
 * an SMF_ functional environment from being created. The faulty entry
 * is then ignored when building the environment.
 *
 * If env is NULL, then the return is an environment which contains
 * all default values.
 *
 * If "path" is non-NULL, it will silently over-ride any previous
 * PATH environment variable.
 *
 * NB: The returned env and strings are allocated using startd_alloc().
 */
char **
set_smf_env(char **env, size_t env_sz, const char *path,
    const restarter_inst_t *inst, const char *method)
{
	char **nenv;
	char **p, **np;
	size_t nenv_size;
	size_t sz;

	/*
	 * Max. of glob_env, env, four SMF_ variables,
	 * path, and terminating NULL.
	 */
	nenv_size = glob_env_n + env_sz + 4 + 1 + 1;

	nenv = startd_zalloc(sizeof (char *) * nenv_size);

	np = nenv;

	if (path != NULL) {
		sz = strlen(path) + 1;
		*np = startd_alloc(sz);
		(void) strlcpy(*np, path, sz);
		np++;
	}

	if (inst) {
		sz = sizeof ("SMF_FMRI=") + strlen(inst->ri_i.i_fmri);
		*np = startd_alloc(sz);
		(void) strlcpy(*np, "SMF_FMRI=", sz);
		(void) strlcat(*np, inst->ri_i.i_fmri, sz);
		np++;
	}

	if (method) {
		sz = sizeof ("SMF_METHOD=") + strlen(method);
		*np = startd_alloc(sz);
		(void) strlcpy(*np, "SMF_METHOD=", sz);
		(void) strlcat(*np, method, sz);
		np++;
	}

	sz = sizeof ("SMF_RESTARTER=") + strlen(SCF_SERVICE_STARTD);
	*np = startd_alloc(sz);
	(void) strlcpy(*np, "SMF_RESTARTER=", sz);
	(void) strlcat(*np, SCF_SERVICE_STARTD, sz);
	np++;

	sz = sizeof ("SMF_ZONENAME=") + strlen(zonename);
	*np = startd_alloc(sz);
	(void) strlcpy(*np, "SMF_ZONENAME=", sz);
	(void) strlcat(*np, zonename, sz);
	np++;

	for (p = glob_envp; *p != NULL; p++) {
		if (valid_env_var(*p, inst, path)) {
			sz = strlen(*p) + 1;
			*np = startd_alloc(sz);
			(void) strlcpy(*np, *p, sz);
			np++;
		}
	}

	if (env) {
		for (p = env; *p != NULL; p++) {
			char **dup_pos;

			if (!valid_env_var(*p, inst, path))
				continue;

			if ((dup_pos = find_dup(*p, nenv, inst)) != NULL) {
				startd_free(*dup_pos, strlen(*dup_pos) + 1);
				sz = strlen(*p) + 1;
				*dup_pos = startd_alloc(sz);
				(void) strlcpy(*dup_pos, *p, sz);
			} else {
				sz = strlen(*p) + 1;
				*np = startd_alloc(sz);
				(void) strlcpy(*np, *p, sz);
				np++;
			}
		}
	}
	*np = NULL;

	return (nenv);
}
