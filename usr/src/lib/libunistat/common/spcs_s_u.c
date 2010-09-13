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
/*
 *	The SPCS status support user utilities
 *	See spcs_s_u.h and the docs subdirectory for functional spec
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <locale.h>
#include <libintl.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_s_impl.h>
#include <sys/unistat/spcs_errors.h>
#include <sys/unistat/spcs_etext.h>
#include <sys/unistat/spcs_etrinkets.h>
#include <sys/unistat/spcs_dtrinkets.h>

/*
 *	Initialize ioctl status storage to "remove" any old status present
 */

void
spcs_s_uinit(spcs_s_info_t ustatus)
{
	spcs_s_pinfo_t *p = (spcs_s_pinfo_t *)ustatus;
	p->major = SPCS_S_MAJOR_REV;
	p->minor = SPCS_S_MINOR_REV;
	p->icount = 0;
	p->scount = 0;
	p->tcount = 0;
}

/*
 *	Create and initialize local status. Call this prior to invoking
 * 	an ioctl.
 */

spcs_s_info_t
spcs_s_ucreate()
{
	static int need_to_bind = 1;
	spcs_s_pinfo_t *ustatus;

	if (need_to_bind) {
	    (void) setlocale(LC_ALL, "");
	    (void) bindtextdomain("unistat", LIBUNISTAT_LOCALE);
	    need_to_bind = 0;
	};

	ustatus = (spcs_s_pinfo_t *)malloc(sizeof (spcs_s_pinfo_t));
	spcs_s_uinit((spcs_s_info_t)ustatus);

	return ((spcs_s_info_t)ustatus);
}

/*
 *	Return the idata index of the last status code in the array (i.e.
 *	the "youngest" code present). The assumption is that the caller has
 *	checked to see that pcount is nonzero.
 */

ISSTATIC int
last_code_idx(spcs_s_pinfo_t *p)
{
	int last = 0;
	int idx = 0;

	while (idx < p->icount) {
		last = idx;
		idx += p->idata[idx].f.sup_count + 1;
	}
	return (last);
}

/*
 *	Return a string with the module label and error message text or NULL
 *      if none left
 */

char *
spcs_s_string(spcs_s_info_t ustatus, char *msg)
{
	spcs_s_pinfo_t *p = (spcs_s_pinfo_t *)ustatus;
	int idx;
	int sup;
	int s;
	char *format;
	char *sp[SPCS_S_MAXSUPP];
	char mtemp[SPCS_S_MAXLINE];

	if (p->icount > 0) {
		idx = last_code_idx(p);
		strcpy(msg, module_names[p->idata[idx].f.module]);
		strcat(msg, ": ");
		sup = p->idata[idx].f.sup_count;

		if (p->idata[idx].f.module)
			/*
			 * The gettext formal parameter is a const char*
			 * I guess the gettext creator couldn't imagine
			 * needing a variable string. If there is an underlying
			 * routine that can be called it should be used.
			 * otherwise there will be a compiler warning about this
			 * line FOREVER (TS).
			 */
			format = (char *)dgettext("unistat",
				SPCS_S_MSG[p->idata[idx].f.module]
				[p->idata[idx].f.code]);

		else
			format = strerror(p->idata[idx].f.code);

		/*
		 * step across the status code to the first supplemental data
		 * descriptor.
		 */

		idx += 1;

		/*
		 * Initialize the array with empty string pointers so we don't
		 * seg fault if there are actually fewer values than "%s"
		 * format descriptors.
		 */
		for (s = 0; s < SPCS_S_MAXSUPP; s++)
			sp[s] = "";

		/*
		 * Walk through the supplemental value descriptors and build
		 * an array of string pointers.
		 */

		for (s = 0; s < sup; s++) {
			sp[s] = (char *)(p->sdata + p->idata[idx+s].su.offset);
		}

		/*
		 * Now format the message. The unused string pointers will be
		 * ignored.
		 * NOTE: Any change to SPCS_S_MAXSUPP requires a change to
		 * this sprintf.
		 */

		sprintf(mtemp, format, sp[0], sp[1], sp[2], sp[3], sp[4], sp[5],
				    sp[6], sp[7]);

		/* remove the code and its supplemental info */

		p->icount -= (sup + 1);

		return (strcat(msg, mtemp));
	} else
		return (NULL);
}

/*
 *	Write status info
 */

void
spcs_s_report(spcs_s_info_t ustatus, FILE *fd)
{
	spcs_s_pinfo_t *p = (spcs_s_pinfo_t *)ustatus;
	short saved_count = p->icount;
	char msg[SPCS_S_MAXTEXT];
	char *sp;
	char *se;
	int first_time = 1;

	do {
		if (sp = spcs_s_string(ustatus, msg))
			fprintf(fd, "%s\n", sp);
		else if (first_time && (errno > 0)) {
			/*
			 * This covers the case where Solaris aborted the
			 * operation or the ioctl service code got an EFAULT
			 * or something from copyin or couldn't allocate the
			 * kernel status structure. If errno > 0 but not a
			 * valid Solaris error code the extended error is
			 * decoded and printed.
			 */
			se = strerror(errno);
			if (se)
				fprintf(fd, "%s\n", se);
			else {
				spcs_s_udata_t spcs_errno;

				spcs_errno.i = errno;
				fprintf(fd, "%s: %s\n",
					module_names[spcs_errno.f.module],
					dgettext("unistat",
						SPCS_S_MSG[spcs_errno.f.module]
						[spcs_errno.f.code]));

			}
		}
		first_time = 0;
	} while (sp);

	p->icount = saved_count;
}

/*ARGSUSED*/
void
spcs_s_exception(spcs_s_info_t ustatus, void *env)
{
}

/*
 *	Release (free) ioctl status storage.
 */

void
spcs_s_ufree(spcs_s_info_t *ustatus_a)
{
	free((void *)*ustatus_a);
	*ustatus_a = NULL;
}
