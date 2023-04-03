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
 * Utility functions
 */
#include <libintl.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <alloca.h>
#include "sgs.h"
#include "rtc.h"
#include "_crle.h"
#include "msg.h"

/*
 * Add an environment string.  A list of environment variable descriptors is
 * maintained so that duplicate definitions can be caught, the first one wins.
 */
int
addenv(Crle_desc *crle, const char *arg, unsigned int flags)
{
	Env_desc	*env;
	char		*str;
	size_t		varsz, totsz = strlen(arg) + 1;

	/*
	 * Determine "=" location so as to separated the variable name from
	 * its value.
	 */
	if ((str = strchr(arg, '=')) != NULL) {
		Aliste	idx;

		varsz = (size_t)(str - arg);

		/*
		 * Traverse any existing environment variables to see if we've
		 * caught a duplicate.
		 */
		for (APLIST_TRAVERSE(crle->c_env, idx, env)) {
			if ((env->e_varsz == varsz) &&
			    (strncmp(env->e_str, arg, varsz) == 0)) {
				/*
				 * If the user has already specified this string
				 * given them a warning, and ignore the new one.
				 */
				if ((env->e_flags & RTC_ENV_CONFIG) == 0) {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_WARN_ENV),
					    crle->c_name, (int)varsz,
					    env->e_str);
					return (2);
				}

				/*
				 * Otherwise the original string must have been
				 * retrieved from a config file.  In this case
				 * allow the user to override it.
				 */
				free((void *)env->e_str);
				crle->c_strsize -= env->e_totsz;
				crle->c_strsize += totsz;

				if ((env->e_str = strdup(arg)) == 0) {
					int err = errno;
					(void) fprintf(stderr,
					    MSG_INTL(MSG_SYS_MALLOC),
					    crle->c_name, strerror(err));
					return (0);
				}
				env->e_varsz = varsz;
				env->e_totsz = totsz;
				env->e_flags &= ~RTC_ENV_CONFIG;
				env->e_flags |= flags;

				return (1);
			}
		}
	} else {
		Aliste	idx;

		/*
		 * Although this is just a plain environment definition (no "=")
		 * and probably has no effect on ld.so.1 anyway, we might as
		 * well make sure we're not duplicating the same string.
		 */
		for (APLIST_TRAVERSE(crle->c_env, idx, env)) {
			if (env->e_varsz)
				continue;
			if (strcmp(env->e_str, arg) == 0) {
				if ((env->e_flags & RTC_ENV_CONFIG) == 0) {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_WARN_ENV),
					    crle->c_name, (int)totsz,
					    env->e_str);
					return (2);
				}
				env->e_flags &= ~RTC_ENV_CONFIG;
				env->e_flags |= flags;

				return (1);
			}
		}
		varsz = 0;
	}

	/*
	 * Allocate a new environment descriptor.
	 */
	if (((env = malloc(sizeof (Env_desc))) == NULL) ||
	    ((env->e_str = strdup(arg)) == NULL)) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC),
		    crle->c_name, strerror(err));
		free(env);
		return (0);
	}
	env->e_varsz = varsz;
	env->e_totsz = totsz;
	env->e_flags = flags;

	if (aplist_append(&(crle->c_env), env, AL_CNT_CRLE) == NULL)
		return (0);

	/*
	 * Update the number of environment variables found, and the string
	 * table requirement.
	 */
	crle->c_envnum++;
	crle->c_strsize += totsz;

	return (1);
}

/*
 * Add a library path.  Multiple library paths are concatenated together into a
 * colon separated string suitable for runtime processing.  These colon
 * separated strings can also be passed in as arguments to addlib(), e.g.,
 * -l /usr/lib:/usr/local/lib.  This is enabled to make update easier.
 */
int
addlib(Crle_desc *crle, char **lib, const char *args)
{
	char		*str, *arg;
	char		*lasts;
	size_t		tlen = strlen(args) + 1;
	const char	*colon = MSG_ORIG(MSG_STR_COLON);

	/*
	 * Parse the argument for any ":" separated elements.
	 */
	str = alloca(tlen);
	(void) strcpy(str, args);
	arg = str;

	if ((arg = strtok_r(arg, colon, &lasts)) != NULL) {
		do {
			size_t	llen, alen = strlen(arg);

			if (*lib) {
				/*
				 * Determine whether this argument exists in the
				 * existing string buffer.
				 */
				if (((str = strstr(*lib, arg)) != NULL) &&
				    (((str == *lib) ||
				    (*(str - 1) == *colon)) &&
				    (str += alen) &&
				    ((*str == '\0') || (*str == *colon))))
					continue;

				llen = strlen(*lib);
				tlen = llen + 1;
			} else {
				/*
				 * This is the first argument to be added.
				 */
				llen = 0;
				tlen = 0;
			}

			/*
			 * This is a new string, so add it to the buffer.  If
			 * this is the first occurrence of a string the size is
			 * simply the size of the string + a trailing null.
			 * Otherwise the size is the old string + ":" + the
			 * size of the new string + a trailing null.
			 */
			alen += 1;
			tlen += alen;
			if ((str = realloc((void *)*lib, tlen)) == 0) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC),
				    crle->c_name, strerror(err));
				return (1);
			}
			if (llen == 0)
				(void) strcpy(str, arg);
			else {
				/* LINTED */
				(void) sprintf(&str[llen],
				    MSG_ORIG(MSG_FMT_COLON), arg);
			}
			*lib = str;
			crle->c_strsize += alen;

		} while ((arg = strtok_r(NULL, colon, &lasts)) != NULL);
	}

	return (0);
}


/*
 * -f option expansion.  Interpret its argument as a numeric or symbolic
 * representation of the dldump(3dl) flags.
 */
int
dlflags(Crle_desc *crle, const char *arg)
{
	int		_flags;
	char		*tok, *_arg;
	char		*lasts;
	const char	*separate = MSG_ORIG(MSG_MOD_SEPARATE);

	/*
	 * Scan the argument looking for allowable tokens.  First determine if
	 * the string is numeric, otherwise try and parse any known flags.
	 */
	if ((_flags = (int)strtol(arg, (char **)NULL, 0)) != 0)
		return (_flags);

	if ((_arg = malloc(strlen(arg) + 1)) == 0)
		return (0);
	(void) strcpy(_arg, arg);

	if ((tok = strtok_r(_arg, separate, &lasts)) != NULL) {
		/* BEGIN CSTYLED */
		do {
		    if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_RELATIVE)) == 0)
			_flags |= RTLD_REL_RELATIVE;
		    else if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_EXEC)) == 0)
			_flags |= RTLD_REL_EXEC;
		    else if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_DEPENDS)) == 0)
			_flags |= RTLD_REL_DEPENDS;
		    else if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_PRELOAD)) == 0)
			_flags |= RTLD_REL_PRELOAD;
		    else if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_SELF)) == 0)
			_flags |= RTLD_REL_SELF;
		    else if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_WEAK)) == 0)
			_flags |= RTLD_REL_WEAK;
		    else if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_ALL)) == 0)
			_flags |= RTLD_REL_ALL;
		    else if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_MEMORY)) == 0)
			_flags |= RTLD_MEMORY;
		    else if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_STRIP)) == 0)
			_flags |= RTLD_STRIP;
		    else if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_NOHEAP)) == 0)
			_flags |= RTLD_NOHEAP;
		    else if (strcmp(tok, MSG_ORIG(MSG_MOD_REL_CONFGEN)) == 0)
			_flags |= RTLD_CONFGEN;
		    else {
			(void) fprintf(stderr, MSG_INTL(MSG_ARG_FLAGS),
			    crle->c_name, tok);
			free(_arg);
			return (0);
		    }
		} while ((tok = strtok_r(NULL, separate, &lasts)) != NULL);
		/* END CSTYLED */
	}
	if (_flags == 0)
		(void) fprintf(stderr, MSG_INTL(MSG_ARG_FLAGS),
		    crle->c_name, arg);

	free(_arg);
	return (_flags);
}

/*
 * Internationalization interface for sgsmsg(1l) use.
 */
const char *
_crle_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}
