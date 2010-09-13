/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <strings.h>
#include <libintl.h>

#include "inetd_impl.h"

extern char **environ;

static int
valid_env_var(const char *var, const char *instance, const char *method)
{
	char *cp = strchr(var, '=');

	if (cp == NULL || cp == var) {
		if (method == NULL)
			return (0);
		error_msg(gettext("Invalid environment variable \"%s\" for "
		    "method %s of instance %s.\n"), var, method, instance);
		return (0);
	} else if (strncmp(var, "SMF_", 4) == 0) {
		if (method == NULL)
			return (0);
		error_msg(gettext("Invalid environment variable \"%s\" for "
		    "method %s of instance %s; \"SMF_\" prefix is reserved.\n"),
		    var, method, instance);
		return (0);
	}

	return (1);
}

static char **
find_dup(const char *var, char **env, const char *instance, const char *method)
{
	char **p;
	char *tmp;

	for (p = env; *p != NULL; p++) {
		tmp = strchr(*p, '=');
		assert(tmp != NULL);
		tmp++;
		if (strncmp(*p, var, tmp - *p) == 0)
			break;
	}

	if (*p == NULL)
		return (NULL);

	error_msg(gettext("Ignoring duplicate environment variable \"%s\" "
	    "for method %s of instance %s.\n"), *p, method, instance);
	return (p);
}

/*
 * Create an environment which is appropriate for spawning an SMF aware
 * process.
 *
 * In order to preserve the correctness of the new environment, various
 * checks are performed:
 *
 * - All SMF_ entries are ignored.  All SMF_ entries should be provided
 *   by this function.
 * - Duplicates in the entry are eliminated.
 * - Malformed entries are eliminated.
 *
 * Detected errors are logged but not fatal, since a single bad entry
 * should not be enough to prevent an SMF_ functional environment from
 * being created.
 */
char **
set_smf_env(struct method_context *mthd_ctxt, instance_t *instance,
    const char *method)
{
	char **nenv;
	char **p, **np;
	size_t nenv_size;

	/*
	 * Max. of env, three SMF_ variables, and terminating NULL.
	 */
	nenv_size = mthd_ctxt->env_sz + 3 + 1;

	if (instance->config->basic->inherit_env) {
		for (p = environ; *p != NULL; p++)
			nenv_size++;
	}

	nenv = malloc(sizeof (char *) * nenv_size);
	if (nenv == NULL)
		return (NULL);
	(void) memset(nenv, 0, sizeof (char *) * nenv_size);

	np = nenv;

	*np = uu_msprintf("SMF_RESTARTER=%s", INETD_INSTANCE_FMRI);
	if (*np == NULL)
		goto fail;
	else
		np++;
	*np = uu_msprintf("SMF_FMRI=%s", instance->fmri);
	if (*np == NULL)
		goto fail;
	else
		np++;
	*np = uu_msprintf("SMF_METHOD=%s", method);
	if (*np == NULL)
		goto fail;
	else
		np++;

	if (instance->config->basic->inherit_env) {
		for (p = environ; *p != NULL; p++) {
			if (!valid_env_var(*p, NULL, NULL))
				continue;

			*np = strdup(*p);
			if (*np == NULL)
				goto fail;
			else
				np++;
		}
	}

	if (mthd_ctxt->env != NULL) {
		for (p = mthd_ctxt->env; *p != NULL; p++) {
			char **dup_pos;

			if (!valid_env_var(*p, instance->fmri, method))
				continue;

			if ((dup_pos = find_dup(*p, nenv, instance->fmri,
			    method)) != NULL) {
				free(*dup_pos);
				*dup_pos = strdup(*p);
				if (*dup_pos == NULL)
					goto fail;
			} else {
				*np = strdup(*p);
				if (*np == NULL)
					goto fail;
				else
					np++;
			}
		}
	}
	*np = NULL;

	return (nenv);
fail:
	p = nenv;
	while (nenv_size--)
		free(*p++);
	free(nenv);
	return (NULL);
}
