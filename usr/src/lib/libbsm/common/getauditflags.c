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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * get audit preselection mask values
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <sys/errno.h>
#include <sys/types.h>
#include <bsm/audit.h>
#include <bsm/libbsm.h>

#include <adt_xlate.h>		/* adt_write_syslog */

#define	SUCCESS 0x1		/* '+' success mask */
#define	FAILURE	0x2		/* '-' failure mask */
#define	INVERSE	0x4		/* '^' invert the mask */

static int
match_class(char *s, char *prefix, uint_t m, int v)
{
	au_class_ent_t *p_class;

	(void) strcat(s, prefix);
	if (cacheauclass(&p_class, m) == 1) {
		if (v == 0) {
			(void) strncat(s, p_class->ac_name, AU_CLASS_NAME_MAX);
		} else {
			(void) strncat(s, p_class->ac_desc, AU_CLASS_DESC_MAX);
		}
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
getauditflagschar(char *auditstring, au_mask_t *masks, int verbose)
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
		if (auditstring[l] == ',')
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
	if (*(prefix = auditstring + strlen(auditstring) - 1) == ',')
		*prefix = '\0';
	return (0);

}

/*
 *  Audit flags:
 *
 *	[+ | - | ^ | ^+ | ^-]<classname>{,[+ | - | ^ | ^+ | ^-]<classname>}*
 *
 *	  <classname>, add class mask to success and failure mask.
 *	 +<classname>, add class mask only to success mask.
 *	 -<classname>, add class mask only to failure mask.
 *	 ^<classname>, remove class mask from success and failure mask.
 *	^+<classname>, remove class mask from success mask.
 *	^-<classname>, remove class mask from failure mask.
 */

/*
 * __chkflags - check if the audit flags are valid for this system
 *
 *	Entry	flags = audit flags string.
 *		cont  = B_TRUE, continue parsing even if error.
 *			B_FALSE, return failure on error.
 *
 *	Exit	mask = audit mask as defined by flags.
 *
 *	Return	B_TRUE if no errors, or continue == B_TRUE.
 *		B_FALSE and if error != NULL, flags in error.
 */

boolean_t
__chkflags(char *flags, au_mask_t *mask, boolean_t cont, char **error)
{
	uint32_t	prefix;
	au_class_ent_t	*class;
	char		name[AU_CLASS_NAME_MAX+1];
	int		i;

	if (flags == NULL || mask == NULL) {
		return (B_FALSE);
	}

	mask->am_success = 0;
	mask->am_failure = 0;

	while (*flags != '\0') {
		prefix = (SUCCESS | FAILURE);

		/* skip white space */
		while (isspace(*flags)) {
			flags++;
		}

		if (*flags == '\0') {
			break;
		}
		if (error != NULL) {
			/* save error pointer */
			*error = flags;
		}

		/* get the prefix */
		if (*flags == '+') {
			flags++;
			prefix ^= FAILURE;
		} else if (*flags == '-') {
			flags++;
			prefix ^= SUCCESS;
		} else if (*flags == '^') {
			flags++;
			prefix |= INVERSE;
			if (*flags == '+') {
				flags++;
				prefix ^= FAILURE;
			} else if (*flags == '-') {
				flags++;
				prefix ^= SUCCESS;
			}
		}

		/* get class name */

		for (i = 0; (i < sizeof (name) - 1) &&
		    !(*flags == '\0' || *flags == ','); i++) {
			name[i] = *flags++;
		}
		name[i++] = '\0';
		if (*flags == ',') {
			/* skip comma (',') */
			flags++;
		}
		if (cacheauclassnam(&class, name) != 1) {
			if (!cont) {
				return (B_FALSE);
			} else {
				char	msg[512];

				(void) snprintf(msg, sizeof (msg), "invalid "
				    "audit flag %s", name);
				adt_write_syslog(msg, EINVAL);
			}
		} else {
			/* add class mask */

			if ((prefix & (INVERSE | SUCCESS)) == SUCCESS) {
				mask->am_success |= class->ac_class;
			} else if ((prefix & (INVERSE | SUCCESS)) ==
			    (INVERSE | SUCCESS)) {
				mask->am_success &= ~(class->ac_class);
			}
			if ((prefix & (INVERSE | FAILURE)) == FAILURE) {
				mask->am_failure |= class->ac_class;
			} else if ((prefix & (INVERSE | FAILURE)) ==
			    (INVERSE | FAILURE)) {
				mask->am_failure &= ~(class->ac_class);
			}
		}
	}

	return (B_TRUE);
}

/*
 * getauditflagsbin() -  converts character string to success and
 *			 failure bit masks
 *
 * input:	auditstring - audit string
 *
 * output:	masks->am_success - audit on success
 *		masks->am_failure - audit on failure
 *
 * returns: 0 - ok
 *          -1 - error - string or mask NULL.
 */

int
getauditflagsbin(char *auditstring, au_mask_t *masks)
{
	if (__chkflags(auditstring, masks, B_TRUE, NULL)) {
		return (0);
	}
	return (-1);
}
