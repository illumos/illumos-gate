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
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * implement "iconv -l"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/param.h>
#include <stddef.h>
#include <dirent.h>
#include <unistd.h>

#define	PATH_LIBICONV	"/usr/lib/iconv"
#define	PATH_BTABLES	"/usr/lib/iconv/geniconvtbl/binarytables"
#define	PATH_ALIASES	"/usr/lib/iconv/alias"

typedef struct codeset {
	avl_node_t cs_node;
	char *cs_name;
	list_t cs_aliases;
} codeset_t;

typedef struct csalias {
	list_node_t a_node;
	char *a_name;
} csalias_t;

static avl_tree_t	cs_avl;

static void alias_destroy(csalias_t *);

/*
 * codesets
 */

static int
cs_compare(const void *n1, const void *n2)
{
	const codeset_t *c1 = n1;
	const codeset_t *c2 = n2;
	int rv;

	rv = strcmp(c1->cs_name, c2->cs_name);
	return ((rv < 0) ? -1 : (rv > 0) ? 1 : 0);
}

static void
cs_insert(char *key)
{
	codeset_t tmp, *cs;
	avl_index_t where;

	(void) memset(&tmp, 0, sizeof (tmp));
	tmp.cs_name = key;

	cs = avl_find(&cs_avl, &tmp, &where);
	if (cs != NULL)
		return; /* already there */

	cs = calloc(1, sizeof (*cs));
	if (cs == NULL) {
		perror("cs_insert:calloc");
		exit(1);
	}
	cs->cs_name = strdup(key);
	if (cs->cs_name == NULL) {
		perror("cs_insert:strdup");
		exit(1);
	}
	list_create(&cs->cs_aliases, sizeof (csalias_t),
	    offsetof(csalias_t, a_node));

	avl_insert(&cs_avl, cs, where);
}

const char topmatter[] =
	"The following are all supported code set names.  All combinations\n"
	"of those names are not necessarily available for the pair of the\n"
	"fromcode-tocode.  Some of those code set names have aliases, which\n"
	"are case-insensitive and described in parentheses following the\n"
	"canonical name:\n";


static void
cs_dump(void)
{
	codeset_t *cs;
	csalias_t *a;

	(void) puts(topmatter);

	for (cs = avl_first(&cs_avl); cs != NULL;
	    cs = AVL_NEXT(&cs_avl, cs)) {

		(void) printf("    %s", cs->cs_name);
		if (!list_is_empty(&cs->cs_aliases)) {
			a = list_head(&cs->cs_aliases);
			(void) printf(" (%s", a->a_name);
			while ((a = list_next(&cs->cs_aliases, a)) != NULL) {
				(void) printf(", %s", a->a_name);
			}
			(void) printf(")");
		}
		(void) printf(",\n");
	}
}

static void
cs_destroy(void)
{
	void *cookie = NULL;
	codeset_t *cs;
	csalias_t *a;

	while ((cs = avl_destroy_nodes(&cs_avl, &cookie)) != NULL) {
		while ((a = list_remove_head(&cs->cs_aliases)) != NULL) {
			alias_destroy(a);
		}
		free(cs->cs_name);
		free(cs);
	}
	avl_destroy(&cs_avl);
}

/*
 * aliases
 */

static void
alias_insert(char *codeset, char *alias)
{
	codeset_t tcs, *cs;
	csalias_t *a;

	/*
	 * Find the codeset.  If non-existent,
	 * ignore aliases of this codeset.
	 */
	(void) memset(&tcs, 0, sizeof (tcs));
	tcs.cs_name = codeset;
	cs = avl_find(&cs_avl, &tcs, NULL);
	if (cs == NULL)
		return;

	/*
	 * Add this alias
	 */
	a = calloc(1, sizeof (*a));
	if (a == NULL) {
		perror("alias_insert:calloc");
		exit(1);
	}
	a->a_name = strdup(alias);
	if (a->a_name == NULL) {
		perror("alias_insert:strdup");
		exit(1);
	}

	list_insert_tail(&cs->cs_aliases, a);
}

static void
alias_destroy(csalias_t *a)
{
	free(a->a_name);
	free(a);
}


static void
scan_dir(DIR *dh, char sep, char *suffix)
{
	char namebuf[MAXNAMELEN];
	struct dirent *de;

	while ((de = readdir(dh)) != NULL) {
		char *p2, *p1;

		/*
		 * We'll modify, so let's copy.  If the dirent name is
		 * longer than MAXNAMELEN, then it can't possibly be a
		 * valid pair of codeset names, so just skip it.
		 */
		if (strlcpy(namebuf, de->d_name, sizeof (namebuf)) >=
		    sizeof (namebuf))
			continue;

		/* Find suffix (.so | .t) */
		p2 = strrchr(namebuf, *suffix);
		if (p2 == NULL)
			continue;
		if (strcmp(p2, suffix) != 0)
			continue;
		*p2 = '\0';

		p1 = strchr(namebuf, sep);
		if (p1 == NULL)
			continue;
		*p1++ = '\0';

		/* More than one sep? */
		if (strchr(p1, sep) != NULL)
			continue;

		/* Empty strings? */
		if (*namebuf == '\0' || *p1 == '\0')
			continue;

		/* OK, add both to the map. */
		cs_insert(namebuf);
		cs_insert(p1);
	}
}

static void
scan_aliases(FILE *fh)
{
	char linebuf[256];
	char *p1, *p2;

	while (fgets(linebuf, sizeof (linebuf), fh) != NULL) {
		if (linebuf[0] == '#')
			continue;
		p1 = strchr(linebuf, ' ');
		if (p1 == NULL)
			continue;
		*p1++ = '\0';
		p2 = strchr(p1, '\n');
		if (p2 == NULL)
			continue;
		*p2 = '\0';
		alias_insert(p1, linebuf);
	}
}

int
list_codesets(void)
{
	DIR *dh;
	FILE *fh;

	avl_create(&cs_avl, cs_compare, sizeof (codeset_t),
	    offsetof(codeset_t, cs_node));

	dh = opendir(PATH_LIBICONV);
	if (dh == NULL) {
		perror(PATH_LIBICONV);
		return (1);
	}
	scan_dir(dh, '%', ".so");
	rewinddir(dh);
	scan_dir(dh, '.', ".t");
	(void) closedir(dh);

	dh = opendir(PATH_BTABLES);
	if (dh == NULL) {
		perror(PATH_BTABLES);
		return (1);
	}
	scan_dir(dh, '%', ".bt");
	(void) closedir(dh);

	fh = fopen(PATH_ALIASES, "r");
	if (fh == NULL) {
		perror(PATH_ALIASES);
		/* let's continue */
	} else {
		scan_aliases(fh);
		(void) fclose(fh);
	}

	cs_dump();

	cs_destroy();

	return (0);
}
