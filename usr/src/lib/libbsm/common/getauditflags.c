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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * get audit preselection mask values
 */

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>

#define	ON 1
#define	OK 0
#define	OFF -1
#define	COMMA  ','

#define	MAXFLDLEN 25

int getauditflagsbin();

static int
match_class(s, prefix, m, v)
char	*s;
char	*prefix;
unsigned int	m;
int	v;
{
	au_class_ent_t *p_class;

	(void) strcat(s, prefix);
	if (cacheauclass(&p_class, m) == 1) {
		(void) strcat(s, v ? p_class->ac_desc : p_class->ac_name);
		(void) strcat(s, ",");
		return (0);
	}
	return (-1);
}


/*
 * getauditflagschar() - convert bit flag to character string
 *
 * input:	masks->am_success - audit on success
 *		masks->am_failure - audit on failure
 *		verbose - string format. 0 if short name; 1 if long name;
 *
 * output: auditstring - resultant audit string
 *
 * returns: 	0 - entry read ok
 *		-1 - error
 */

int
getauditflagschar(auditstring, masks, verbose)
char	*auditstring;
au_mask_t *masks;
int	verbose;
{
	char	*prefix;		/* +, -, or null */
	unsigned int	m;		/* for masking with masks */
	au_mask_t all; 		/* value for the string "all" */
	int	plus_all = 0;	/* true if +all */
	int	minus_all = 0;	/* true if -all */
	int	l;

	/* initialize input buffer */
	*auditstring = '\0';
	/* no masks, no flags; we're outta here */
	if ((masks->am_success == 0) && (masks->am_failure == 0)) {
		if (match_class(auditstring, "", 0, verbose) != 0)
			return (-1);
		/* kludge to get rid of trailing comma */
		l = strlen(auditstring) - 1;
		if (auditstring[l] == COMMA)
			auditstring[l] = '\0';
		return (0);
	}
	/* Get the mask value for the string "all" */
	all.am_success = 0;
	all.am_failure = 0;
	if (getauditflagsbin("all", &all) != 0)
		return (-1);
	if (all.am_success == masks->am_success) {
		if (all.am_failure == masks->am_failure) {
			(void) strcat(auditstring, "all");
			return (0);
		}
		(void) strcat(auditstring, "+all,");
		plus_all = 1;
	} else if (all.am_failure == masks->am_failure) {
		(void) strcat(auditstring, "-all,");
		minus_all = 1;
	}
	for (m = (unsigned)0x80000000; m != 0; m >>= 1) {
		if (m & masks->am_success & masks->am_failure)
			prefix = plus_all ? "-" : (minus_all ? "+" : "");
		else if (m & masks->am_success)
			prefix = "+";
		else if (m & masks->am_failure)
			prefix = "-";
			else
			continue;
		if (match_class(auditstring, prefix, m, verbose) != 0)
			return (-1);
	}
	if (*(prefix = auditstring + strlen(auditstring) - 1) == COMMA)
		*prefix = '\0';
	return (0);

}

/*
 * getauditflagsbin() -  converts character string to success and
 *			 failure bit masks
 *
 * input:	auditstring - audit string
 *		cnt - number of elements in the masks array
 *
 * output:	masks->am_success - audit on success
 *		masks->am_failure - audit on failure
 *
 * returns: 0 - ok
 *	    -1 - error - string contains characters which do
 *		not match event flag names or invalid pointers
 *              passed in.
 */

int
getauditflagsbin(auditstring, masks)
char	*auditstring;
au_mask_t *masks;
{
	int	gotone, done = 0, invert = 0, tryagain;
	int	retstat = 0, succ_event, fail_event;
	char	*ptr, tmp_buff[MAXFLDLEN];
	au_class_ent_t *p_class;

	if ((masks == NULL) || (auditstring == NULL))
		return (-1);

	masks->am_success = masks->am_failure = 0;

	/* process character string */
	do {
		gotone = 0;
		/* read through string storing chars. until a comma */
		for (ptr = tmp_buff; !gotone; /* */) {
			if (*auditstring != COMMA && *auditstring != '\0' &&
			    *auditstring != '\n' && *auditstring != ' ' &&
			    *auditstring != '\t')
				*ptr++ = *auditstring++;
			else if (*auditstring == ' ' || *auditstring == '\t')
				auditstring++;
			else {
				if (*auditstring == '\0' ||
						*auditstring == '\n') {
					done = 1;
					if (ptr == tmp_buff)
						done = 2;
				}
				gotone = 1;
			}
		}
		/* * process audit state */
		if (gotone && done != 2) {
			if (!done)
				auditstring++;
			*ptr++ = '\0';
			ptr = tmp_buff;
			gotone = 0;
			succ_event = ON;
			fail_event = ON;
			tryagain = 1;
			invert = 0;

			/* get flags */
			do {
				switch (*ptr++) {
				case '^':
					invert = 1;
					succ_event = OFF;
					fail_event = OFF;
					break;
				case '+':
					if (invert)
						fail_event = OK;
					else {
						succ_event = ON;
						fail_event = OK;
					}
					break;
				case '-':
					if (invert)
						succ_event = OK;
					else {
						fail_event = ON;
						succ_event = OK;
					}
					break;
				default:
					tryagain = 0;
					ptr--;
					break;
				}
			} while (tryagain);

			/* add audit state to mask */


			if (cacheauclassnam(&p_class, ptr) == 1) {
				if (succ_event == ON)
					masks->am_success |= p_class->ac_class;
				else if (succ_event == OFF)
					masks->am_success &=
						~(p_class->ac_class);
				if (fail_event == ON)
					masks->am_failure |= p_class->ac_class;
				else if (fail_event == OFF)
					masks->am_failure &=
						~(p_class->ac_class);
				gotone = 1;
			} else {  /* Bug 4330887 */
				syslog(LOG_CRIT,
					"auditflags have invalid flag %s",
					ptr);
				continue;
			}
			if (!gotone) {
				retstat = -1;
				done = 1;
			}
		}
	} while (!done);


	return (retstat);
}
