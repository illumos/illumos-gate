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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <locale.h>
#include <errno.h>
#include <krb5.h>
#include <profile.h>
#include <com_err.h>

struct profile_string_list {
	char	**list;
	int	num;
	int	max;
};

/*
 * From prof_get.c as the following four functions are private in mech_krb5.
 */
/*
 * Initialize the string list abstraction.
 */
static errcode_t
init_list(struct profile_string_list *list)
{
	list->num = 0;
	list->max = 10;
	list->list = malloc(list->max * sizeof (char *));
	if (list->list == NULL)
		return (ENOMEM);
	list->list[0] = NULL;
	return (0);
}

/*
 * If re_list is non-NULL then pass the list header to the caller else free
 * the previously allocated list.
 */
static void
end_list(struct profile_string_list *list, char ***ret_list)
{

	if (list == NULL)
		return;

	if (ret_list) {
		*ret_list = list->list;
		return;
	} else
		profile_free_list(list->list);
	list->num = list->max = 0;
	list->list = NULL;
}

/*
 * Add a string to the list.
 */
static errcode_t
add_to_list(struct profile_string_list *list, const char *str)
{
	char 	*newstr, **newlist;
	int	newmax;

	if (list->num + 1 >= list->max) {
		newmax = list->max + 10;
		newlist = realloc(list->list, newmax * sizeof (char *));
		if (newlist == NULL)
			return (ENOMEM);
		list->max = newmax;
		list->list = newlist;
	}
	newstr = strdup(str);
	if (newstr == NULL)
		return (ENOMEM);

	list->list[list->num++] = newstr;
	list->list[list->num] = NULL;
	return (0);
}

static void
usage()
{
	(void) fprintf(stderr, gettext("kconf -f <file> -r <realm> "
	    "-k <kdc[,kdc]> -m <master_kdc>\n -p <kpasswd_protocol> "
	    "-d <domain>\n"));

	exit(1);
}

int
main(int argc, char **argv)
{
	profile_t	profile;
	errcode_t	code;
	char		c, *realm, *kdcs, *master, *domain, *token, *lasts;
	char		*file, **ret_values = NULL;
	boolean_t	set_change = FALSE;
	struct profile_string_list values;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif /* TEXT_DOMAIN */

	(void) textdomain(TEXT_DOMAIN);

	/*
	 * kconf -f <file> -r <realm> -k <kdc[,kdc]> -m <master_kdc>
	 * -p <kpasswd_protocol> -d <domain>
	 */
	while ((c = getopt(argc, argv, "f:r:k:a:s:p:d:m:")) != -1) {
		switch (c) {
		case 'f':
			file = optarg;
			break;
		case 'r':
			realm = optarg;
			break;
		case 'k':
			kdcs = optarg;
			break;
		case 'm':
			master = optarg;
			break;
		case 'p':
			if (strcmp(optarg, "SET_CHANGE") == 0)
				set_change = TRUE;
			break;
		case 'd':
			domain = optarg;
			break;
		default:
			usage();
			break;
		}
	}

	code = __profile_init(file, &profile);
	if (code != 0) {
		fprintf(stderr, gettext("Wasn't able to initialize profile\n"));
		exit(code);
	}

	if (code = init_list(&values)) {
		fprintf(stderr, gettext("Can not initialize list %d\n"), code);
		goto error;
	}
	token = strtok_r(kdcs, ",", &lasts);
	do {
		if (token != NULL) {
			code = add_to_list(&values, token);
			if (code != 0) {
				fprintf(stderr, gettext("Can not add to list "
				    "%d\n"), code);
				goto error;
			}
		} else {
			fprintf(stderr, gettext("Couldn't parse kdc list %d\n"),
			    code);
			goto error;
		}
	} while ((token = strtok_r(NULL, ",", &lasts)) != NULL);
	end_list(&values, &ret_values);

	code = __profile_add_realm(profile, realm, master, ret_values,
	    set_change, TRUE);
	if (code != 0) {
		fprintf(stderr, gettext("Wasn't able to add realm "
		    "information\n"));
		goto error;
	}

	code = __profile_add_domain_mapping(profile, domain, realm);
	if (code != 0) {
		fprintf(stderr, gettext("Wasn't able to add domain mapping\n"));
		goto error;
	}

error:
	if (ret_values != NULL)
		profile_free_list(ret_values);

	/*
	 * Release profile, which will subsequently flush new profile to file.
	 * If this fails then at least free profile memory.
	 */
	if ((code =  __profile_release(profile)) != 0)
		__profile_abandon(profile);

	return (code);
}
