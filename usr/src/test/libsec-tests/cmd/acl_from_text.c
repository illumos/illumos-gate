/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 RackTop Systems, Inc.
 */

/*
 * Test program for libsec:acl_fromtext
 */

#include <sys/types.h>
#include <sys/acl.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

extern char *acl_strerror(int);
extern acl_t acl_canned;

int
acl_compare(acl_t *lib, acl_t *ref)
{
	ace_t *lib_acep;
	ace_t *ref_acep;
	int errs;
	int i;

	if (lib->acl_type != ref->acl_type) {
		fprintf(stderr, "acl_type = %d (expected %d)\n",
		    lib->acl_type, ref->acl_type);
		return (-1);
	}
	if (lib->acl_cnt != ref->acl_cnt) {
		fprintf(stderr, "acl_cnt = %d (expected %d)\n",
		    lib->acl_cnt, ref->acl_cnt);
		return (-1);
	}
	if (lib->acl_entry_size != ref->acl_entry_size) {
		fprintf(stderr, "acl_entry_size = %d (expected %d)\n",
		    lib->acl_entry_size, ref->acl_entry_size);
		return (-1);
	}

	lib_acep = lib->acl_aclp;
	ref_acep = ref->acl_aclp;
	errs = 0;
	for (i = 0; i < lib->acl_cnt; i++) {
		if (lib_acep->a_who != ref_acep->a_who) {
			fprintf(stderr, "ace[%d].a_who = %u"
			    " (expected %u)\n", i,
			    lib_acep->a_who,
			    ref_acep->a_who);
			errs++;
		}
		if (lib_acep->a_access_mask != ref_acep->a_access_mask) {
			fprintf(stderr, "ace[%d].a_access_mask = 0x%x"
			    " (expected 0x%x)\n", i,
			    lib_acep->a_access_mask,
			    ref_acep->a_access_mask);
			errs++;
		}
		if (lib_acep->a_flags != ref_acep->a_flags) {
			fprintf(stderr, "ace[%d].a_flags = %u"
			    " (expected %u)\n", i,
			    lib_acep->a_flags,
			    ref_acep->a_flags);
			errs++;
		}
		if (lib_acep->a_type != ref_acep->a_type) {
			fprintf(stderr, "ace[%d].a_type = %u"
			    " (expected %u)\n", i,
			    lib_acep->a_type,
			    ref_acep->a_type);
			errs++;
		}
		lib_acep++;
		ref_acep++;
	}
	return (errs);
}

int
main(int argc, char **argv)
{
	acl_t	*aclp = NULL;	/* acl info */
	char	*str;
	char	*p;
	int i, err;

	for (i = 1; i < argc; i++) {
		/*
		 * Allow input with newlines instead of commas.
		 */
		str = strdup(argv[i]);
		if (str == NULL) {
			perror("strdup");
			return (1);
		}
		for (p = str; *p != '\0'; p++) {
			if (*p == '\n')
				*p = ',';
		}

		err = acl_fromtext(str, &aclp);
		if (err != 0) {
			fprintf(stderr, "acl_fromtext(%s): %s\n",
			    str, acl_strerror(err));
			return (1);
		}

		if (acl_compare(aclp, &acl_canned) != 0) {
			fprintf(stderr, "compare failed on: %s\n", str);
			return (1);
		}

		acl_free(aclp);
		aclp = NULL;
	}

	return (0);
}
