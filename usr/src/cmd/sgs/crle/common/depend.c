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

#include	<sys/types.h>
#include	<stdio.h>
#include	<errno.h>
#include	<unistd.h>
#include	<string.h>
#include	<wait.h>
#include	<limits.h>
#include	<gelf.h>
#include	"machdep.h"
#include	"sgs.h"
#include	"conv.h"
#include	"_crle.h"
#include	"msg.h"

/*
 * Establish an association between a filter and filtee.  Both the filter and
 * filtee already exist in the internal hash table, since auditing registers
 * objects (la_objopen()) before it registers filters (la_objfilter()).
 */
static int
filter(Crle_desc *crle, const char *filter, const char *str, const char *filtee)
{
	Hash_ent	*fltrent, *flteent;
	Flt_desc	*flt;
	Aliste		idx;

	/*
	 * Locate the filter.  Mark the underlying object as the filter to
	 * reflect that no matter how it is referenced, it's a filter.
	 */
	if ((fltrent = get_hash(crle->c_strtbl, (Addr)filter, 0,
	    HASH_FND_ENT)) == NULL)
		return (1);
	if ((fltrent = get_hash(crle->c_strtbl, (Addr)fltrent->e_obj->o_path, 0,
	    HASH_FND_ENT)) == NULL)
		return (1);
	fltrent->e_obj->o_flags |= RTC_OBJ_FILTER;

	/*
	 * Locate the filtee.  Mark the referencing object as the filtee, as
	 * this is the object referenced by the filter.
	 */
	if ((flteent = get_hash(crle->c_strtbl, (Addr)filtee, 0,
	    HASH_FND_ENT)) == NULL)
		return (1);
	flteent->e_flags |= RTC_OBJ_FILTEE;

	/*
	 * Traverse the filter list using the filters real name.  If ld.so.1
	 * inspects the resulting configuration file for filters, it's the
	 * objects real name that will be used (PATHNAME()).
	 */
	for (APLIST_TRAVERSE(crle->c_flt, idx, flt)) {
		/*
		 * Determine whether this filter and filtee string pair already
		 * exist.
		 */
		if ((strcmp(flt->f_fent->e_obj->o_path,
		    fltrent->e_obj->o_path) != 0) &&
		    (strcmp(flt->f_str, str) != 0))
			continue;

		/*
		 * Add this filtee additional association.
		 */
		if (aplist_append(&(flt->f_filtee), flteent,
		    AL_CNT_CRLE) == NULL)
			return (1);

		crle->c_fltenum++;
		return (0);
	}

	/*
	 * This is a new filter descriptor.  Add this new filtee association.
	 */
	if (((flt = malloc(sizeof (Flt_desc))) == NULL) ||
	    ((flt->f_strsz = strlen(str) + 1) == 0) ||
	    ((flt->f_str = malloc(flt->f_strsz)) == NULL)) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_MALLOC),
		    crle->c_name, strerror(err));
		free(flt);
		return (1);
	}
	if ((aplist_append(&(crle->c_flt), flt, AL_CNT_CRLE) == NULL) ||
	    (aplist_append(&(flt->f_filtee), flteent, AL_CNT_CRLE) == NULL))
		return (1);

	flt->f_fent = fltrent;
	(void) memcpy((void *)flt->f_str, (void *)str, flt->f_strsz);
	crle->c_strsize += flt->f_strsz;
	crle->c_fltrnum += 1;
	crle->c_fltenum += 2;		/* Account for null filtee desc. */

	return (0);
}

/*
 * Establish the dependencies of an ELF object and add them to the internal
 * configuration information. This information is gathered by using libcrle.so.1
 * as an audit library - this is akin to using ldd(1) only simpler.
 */
int
depend(Crle_desc *crle, const char *name, Half flags, GElf_Ehdr *ehdr)
{
	const char	*exename;
	const char	*preload;
	int		fildes[2], pid;

	/*
	 * If we're dealing with a dynamic executable we'll execute it,
	 * otherwise we'll preload the shared object with one of the lddstub's.
	 */
	if (ehdr->e_type == ET_EXEC) {
		exename = name;
		preload = NULL;
	} else {
		exename = conv_lddstub(M_CLASS);
		preload = name;
	}

	/*
	 * Set up a pipe through which the audit library will write the
	 * dependencies.
	 */
	if (pipe(fildes) == -1) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_PIPE),
		    crle->c_name, strerror(err));
		return (1);
	}

	/*
	 * Fork ourselves to run our executable and collect its dependencies.
	 */
	if ((pid = fork()) == -1) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_FORK),
		    crle->c_name, strerror(err));
		return (1);
	}

	if (pid) {
		/*
		 * Parent. Read each dependency from the audit library. The read
		 * side of the pipe is attached to stdio to make obtaining the
		 * individual dependencies easier.
		 */
		int	error = 0, status;
		FILE	*fd;
		char	buffer[PATH_MAX];

		(void) close(fildes[1]);
		if ((fd = fdopen(fildes[0], MSG_ORIG(MSG_STR_READ))) != NULL) {
			char	*str;

			while (fgets(buffer, PATH_MAX, fd) != NULL) {
				/*
				 * Make sure we recognize the message, remove
				 * the newline (which allowed fgets() use) and
				 * register the name;
				 */
				if (strncmp(MSG_ORIG(MSG_AUD_PRF), buffer,
				    MSG_AUD_PRF_SIZE))
					continue;

				str = strrchr(buffer, '\n');
				*str = '\0';
				str = buffer + MSG_AUD_PRF_SIZE;

				if (strncmp(MSG_ORIG(MSG_AUD_DEPEND),
				    str, MSG_AUD_DEPEND_SIZE) == 0) {
					/*
					 * Process any dependencies.
					 */
					str += MSG_AUD_DEPEND_SIZE;

					if ((error = inspect(crle, str,
					    (flags & ~RTC_OBJ_GROUP))) != 0)
						break;

				} else if (strncmp(MSG_ORIG(MSG_AUD_FILTER),
				    str, MSG_AUD_FILTER_SIZE) == 0) {
					char	*_flt, *_str;

					/*
					 * Process any filters.
					 */
					_flt = str += MSG_AUD_FILTER_SIZE;
					_str = strchr(str, ':');
					*_str++ = '\0'; str = _str++;
					str = strrchr(str, ')');
					*str++ = '\0'; str++;
					if ((error = filter(crle, _flt, _str,
					    str)) != 0)
						break;
				}
			}
		} else
			error = errno;

		while (wait(&status) != pid)
			;
		if (status) {
			if (WIFSIGNALED(status)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_SYS_EXEC), crle->c_name,
				    exename, (WSIGMASK & status),
				    ((status & WCOREFLG) ?
				    MSG_INTL(MSG_SYS_CORE) :
				    MSG_ORIG(MSG_STR_EMPTY)));
			}
			error = status;
		}
		(void) fclose(fd);

		return (error);
	} else {
		char	efds[MSG_ENV_AUD_FD_SIZE + 10];
		char	epld[PATH_MAX];
		char	eldf[PATH_MAX];

		(void) close(fildes[0]);

		/*
		 * Child. Set up environment variables to enable and identify
		 * auditing.  Initialize CRLE_FD and LD_FLAGS strings.
		 */
		(void) snprintf(efds, (MSG_ENV_AUD_FD_SIZE + 10),
		    MSG_ORIG(MSG_ENV_AUD_FD), fildes[1]);
		(void) snprintf(eldf, PATH_MAX, MSG_ORIG(MSG_ENV_LD_FLAGS));

		/*
		 * If asked to dump a group of dependencies make sure any
		 * lazily-loaded objects get processed - (append loadavail to
		 * LD_FLAGS=confgen).
		 */
		if (flags & RTC_OBJ_GROUP)
			(void) strcat(eldf, MSG_ORIG(MSG_LDFLG_LOADAVAIL));

		/*
		 * Put LD_PRELOAD= in the environment if necessary.
		 */
		if (preload) {
			(void) snprintf(epld, PATH_MAX,
			    MSG_ORIG(MSG_ENV_LD_PRELOAD), preload);
		}

		/*
		 * Put strings in the environment for exec().
		 * NOTE, use of automatic variables for construction of the
		 * environment variables is legitimate here, as they are local
		 * to the child process and are established solely for exec().
		 */
		if ((putenv(efds) != 0) || (putenv(crle->c_audit) != 0) ||
		    (putenv(eldf) != 0) || (preload && (putenv(epld) != 0))) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_PUTENV),
			    crle->c_name, strerror(err));
			return (1);
		}

		if (execlp(exename, exename, 0) == -1) {
			_exit(errno);
			/* NOTREACHED */
		}
	}
	return (0);
}
