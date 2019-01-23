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

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "xlator.h"
#include "util.h"
#include "bucket.h"
#include "errlog.h"

/* Statics: */
#define	TRUE	1
#define	FALSE	0
#define	NLISTS	50
#define	NPAR	25

static bucket_t **Buckethead;
static int N_lists;

static int Bc = -1; /* For iterators. */
static bucket_t *Bp;

static void start_new_list(const bucket_t *);
static void grow_lists(void);
static bucket_t *new_bucket(const char *, int);
static void print_iface(const Interface *);
static void new_hashmap(void);
static int add_to_hashmap(const char *, const bucket_t *);
static bucket_t *find_in_hashmap(const char *);
/*
 * initialization interfaces.
 */

/*
 * create_lists -- initialize the bucket list and hash map.
 */
void
create_lists(void)
{

	errlog(BEGIN, "create_lists() {");
	new_hashmap();
	if ((Buckethead = calloc(sizeof (bucket_t *), NLISTS)) == NULL) {
		errlog(FATAL, "out of memory creating initial "
			"list of versions");

	}
	N_lists = NLISTS;
	errlog(END, "}");
}


/*
 * data-loading interfaces -- adding buckets to lists and
 *	interfaces to buckets.
 */

/*
 * add_parent -- add a parent node. Returns TRUE or FALSE.
 *
 * 	if *version == NULL, then
 * 		the bucket version (eg, SUNW_1.1) hasn't
 * 		been parsed correctly.  Die.
 * 	if *after == NULL, then this is the ``initial case'',
 * 		where no predecessor (child) exists.  We start a new
 * 		tree of buckets.
 * 	if *after != NULL, we have the normal case, and
 * 		add to an existing tree.
 * 	if *after is not a version name found among the buckets,
 * 		then something got misparsed or the versions file is
 * 		malformed. Function will print problem and
 * 		return 0 so caller can report location of error.
 *      If either version or after is NULL, it's a programmer error.
 */
int
add_parent(const char *version, const char *after, int weak)
{
	bucket_t *new, *child;

	/* Sanity-check parameters. */
	assert(version != NULL, "passed a null version to add_parent");
	assert(after != NULL, "passed a null after to add_parent");
	errlog(BEGIN, "add_parent(%s,%s,%d) {", version, after, weak);
	if ((new = find_in_hashmap(version)) == NULL) {
		/* We don't have one have one yet. */
		new = new_bucket(version, weak);
	}
	new->b_weak = weak;
	if (*after == '\0') {
		/*
		 * This is the ``initial case'', where no
		 * child exists.  We start a new tree of buckets.
		 */
		(void) add_to_hashmap(version, new);
		start_new_list(new);
	} else {
		if ((child = find_in_hashmap(after)) == NULL) {
			/*
			 * The version in the spec doesn't appear in the
			 * versions file.  One or the other is lying.
			 */
			errlog(WARNING, "set file: can't find version \"%s\","
			    "therefor can't add it's parent, \"%s\"",
			    after, version);
			errlog(END, "} /* add_parent */");
			return (FALSE);
		}
		(void) add_to_hashmap(version, new);
		child->b_parent = new;
	}
	errlog(END, "} /* add_parent */");
	return (TRUE);
}

/*
 * add_uncle -- adds an uncle node
 */
int
add_uncle(const char *version, const char *after, int weak)
{
	bucket_t *new, *child;
	struct bucketlist *uncle;

	/* Sanity-check parameters. */
	assert(version != NULL, "passed a null version to add_uncle");
	assert(after != NULL, "passed a null after to add_uncle");
	errlog(BEGIN, "add_uncle(%s,%s,%d) {", version, after, weak);
	if ((new = find_in_hashmap(version)) == NULL) {
		/* We don't have one have one yet. */
		new = new_bucket(version, weak);
	}
	if (*after == '\0') {
		/*
		 * This is the ``initial case'', where no
		 * child exists.  We start a new tree of buckets.
		 */
		(void) add_to_hashmap(version, new);
		start_new_list(new);
	} else {
		if ((child = find_in_hashmap(after)) == NULL) {
			/*
			 * The version in the spec doesn't appear in the
			 * versions file.  One or the other is lying.
			 */
			errlog(WARNING, "set file: can't find version \"%s\","
			    "therefor can't add it's uncle, \"%s\"",
			    after, version);
			errlog(END, "}");
			return (FALSE);
		}
		(void) add_to_hashmap(version, new);
		uncle =	malloc(sizeof (struct bucketlist));
		uncle->bl_next = child->b_uncles;
		uncle->bl_bucket = new;
		child->b_uncles = uncle;
	}
	errlog(END, "}");
	return (TRUE);
}

/*
 * set_weak -- set a version to be a weak version
 */
void
set_weak(const char *version, int weak)
{
	bucket_t *v;
	if ((v = find_in_hashmap(version)) == NULL) {
		/* We don't have one have one yet. */
		errlog(ERROR|FATAL, "Unable to set weak. Version not found");
	}
	v->b_weak = weak;
}

/*
 * add_by_name -- look up bucket and add an interface to it.
 *      Returns 0 for success or an errno.h value for failure.
 *
 * 	if *version is not among the buckets, then the
 * 		version in the spec doesn't appear in the
 * 		set file.  One or the other is lying. Function will
 * 		report the problem and return ENOENT
 * 		so the front end can report and exit (or
 * 		continue if it wants).
 * 	if interface ore version is NULL, then
 * 		the begin line code should
 * 		have caught it long before, to avoid passing
 * 		a null pointer around. Die.
 *
 */
#define	ADD_EQUALS(str)	if (strchr(str, '=') == NULL) (void) strcat(str, " =")

int
add_by_name(const char *version, const Interface *interface)
{
	bucket_t *b;
	char buffer[1024];

	assert(version != NULL, "passed a null version to add_by_name");
	assert(interface != NULL, "passed a null interface to add_by_name");

	errlog(BEGIN, "add_by_name(%s,", version);
	print_iface(interface);
	errlog(TRACING, ");");

	/* Sanity-check the parameters. */
	if ((b = find_in_hashmap(version)) == NULL) {
		/*
		 * The version in the spec doesn't appear in the
		 * versions file. Alas, this isn't an error.  It can
		 * happen whenever doing just sparc, just i386
		 * or the like.
		 */
		errlog(END, "}");
		return (ENOENT);
	}
	/*
	 * Add to bucket.
	 */
	(void) snprintf(buffer, sizeof (buffer), "%s", interface->IF_name);

	if (interface->IF_filter && interface->IF_auxiliary) {
		errlog(FATAL, "Error: cannot set both FILTER and AUXILIARY "
		    "for an interface: %s", interface->IF_name);
	}

	if (interface->IF_filter) {
		ADD_EQUALS(buffer);
		if (interface->IF_type == FUNCTION) {
			(void) strcat(buffer, " FUNCTION");
		} else if (interface->IF_type == DATA) {
			(void) strcat(buffer, " DATA");
		}
		(void) strcat(buffer, " FILTER ");
		(void) strcat(buffer, interface->IF_filter);
	} else if (interface->IF_auxiliary) {
		ADD_EQUALS(buffer);
		(void) strcat(buffer, " AUXILIARY ");
		(void) strcat(buffer, interface->IF_auxiliary);
	} else if (IsFilterLib) {
		/*
		 * For DATA types it is currently assumed that they are
		 * handled via a minimal C file, e.g. 'data.c', in the
		 * library's build.  Hence, we do not append '= DATA' here.
		 */
		if (interface->IF_type == FUNCTION) {
			ADD_EQUALS(buffer);
			(void) strcat(buffer, " FUNCTION");
		}
	}

	switch (interface->IF_binding) {
	case DIRECT:
		ADD_EQUALS(buffer);
		(void) strcat(buffer, " DIRECT");
		break;
	case NODIRECT:
		ADD_EQUALS(buffer);
		(void) strcat(buffer, " NODIRECT");
		break;
	}

	if (interface->IF_binding == PROTECTED) {
		/* Assign in case of realloc. */
		b->b_protected_table =
		    add_to_stringtable(b->b_protected_table, buffer);
		b->b_has_protecteds = 1;
		errlog(VERBOSE, "set has_protecteds on bucket 0x%p", b);
	} else {
		/* Assign in case of realloc. */
		b->b_global_table = add_to_stringtable(b->b_global_table,
			buffer);
	}
	errlog(END, "}");
	return (0);
}


/*
 * Processing interfaces
 */

/*
 * sort_buckets -- sort the interfaces within the buckets into
 *      alphabetical order.
 */
void
sort_buckets(void)
{
	bucket_t *l, *b;

	errlog(BEGIN, "sort_buckets() {");
	for (l = first_list(); l != NULL; l = next_list()) {
		errlog(VERBOSE, "l-bucket: %s", l->b_name);
		for (b = first_from_list(l); b != NULL; b = next_from_list()) {
			errlog(VERBOSE, "   b-bkt: %s", b->b_name);
			sort_stringtable(b->b_global_table);
			sort_stringtable(b->b_protected_table);
			if (b->b_uncles) {

				if (b->b_uncles->bl_bucket) {
		sort_stringtable(b->b_uncles->bl_bucket->b_global_table);
		sort_stringtable(b->b_uncles->bl_bucket->b_protected_table);
				}
			}
		}
	}
	errlog(END, "}");
}


/*
 * add_local -- set the local flag on the logically first bucket.
 *     This decision may belong in the caller, as it is about
 *     mapfiles, not inherent ordering or bucket contents...
 */
void
add_local(void)
{
	bucket_t *b, *list;
	int	done = 0;

	errlog(BEGIN, "add_local() {");
	/* Iterate across lists of buckets */
	for (list = first_list(); list != NULL; list = next_list()) {
		/* Traverse the list found. */
		for (b = list; b != NULL; b = b->b_parent) {
			if (b->b_weak != 1) {
				/* We've found the first non-weak. */
				b->b_has_locals = done = 1;
				errlog(VERBOSE,
				    "set has_locals on bucket 0x%p", b);
				break;
			}
		}
		if (b != NULL && b->b_has_locals == 1)
			break;
	}
	if (done == 0) {
		errlog(WARNING, "has_locals never set");
	}
	errlog(END, "}");
}


/*
 * Output interfaces, mostly iterators
 */


/*
 * parents_of -- return a list of all parents.
 */
char **
parents_of(const bucket_t *start)
{
	static char *a[NPAR] = {NULL};
	const bucket_t *b = start;
	char **p = &a[0];

	assert(start != NULL, "passed a null start to parents_of");
	errlog(BEGIN, "parents_of() {");
	a[0] = '\0';

	/* Go to parent, print it and all its uncle. */
	if (b->b_parent == NULL) {
		errlog(TRACING, "returning empty string");
		errlog(END, "}");
		return (a);
	}
	b = b->b_parent;
	*p++ = b->b_name;
	*p = '\0';

	assert(p < &a[NPAR], "p fell off the end of a in parents_of");
	errlog(END, "}");
	return (a);
}

/*
 * first, next_from_bucket --iterators for bucket contents. Serially
 *      reusable only.
 */
int Ic = -1;

/*
 * debugging interfaces
 */
void
print_bucket(const bucket_t *b)
{

	errlog(TRACING, "bucket_t at 0x%p {", (void *)b);
	errlog(TRACING, "    char   *b_name = \"%s\";", b->b_name);
	errlog(TRACING, "    struct bucket_t *b_parent = 0x%p;",
		(void *)b->b_parent);
	errlog(TRACING, "    struct bucketlist *b_uncles = 0x%p;",
		(void *)b->b_uncles);
	errlog(TRACING, "    struct bucket_t *b_thread = 0x%p;",
		(void *)b->b_thread);
	errlog(TRACING, "    int	b_has_locals = %d;",
		b->b_has_locals);
	errlog(TRACING, "    int	b_has_protecteds = %d;",
		b->b_has_protecteds);
	errlog(TRACING, "    int        b_was_printed = %d;",
		b->b_was_printed);
	errlog(TRACING, "    int        b_weak = %d;",
		b->b_weak);
	errlog(TRACING, "    table_t  *b_global_table = 0x%p;",
		(void *)b->b_global_table);
	errlog(TRACING, "    table_t  *b_protected_table = 0x%p;",
		(void *)b->b_protected_table);
	errlog(TRACING, "}");
}

void
print_all_buckets(void)
{
	bucket_t *l, *b;
	int i = 0, j = 0;
	char **p;

	for (i = 0, l = first_list(); l != NULL; l = next_list(), ++i) {
		errlog(TRACING, "list %d", i);
		for (j = 0, b = first_from_list(l);
		    b != NULL; b = next_from_list(), ++j) {
			errlog(TRACING, "bucket %d", j);
			print_bucket(b);
			errlog(TRACING, "global interfaces = {");
			print_stringtable(b->b_global_table);
			errlog(TRACING, "}");
			errlog(TRACING, "protected interfaces = {");
			print_stringtable(b->b_protected_table);
			errlog(TRACING, "}");

			for (p = parents_of(b); p != NULL && *p != NULL; ++p) {
				errlog(TRACING, " %s", *p);
			}
			errlog(TRACING, ";");

			if (b->b_uncles) {
				errlog(TRACING, " uncle bucket %d.1", j);
				print_bucket(b->b_uncles->bl_bucket);
				errlog(TRACING, "global interfaces = {");
				print_stringtable(
				    b->b_uncles->bl_bucket->b_global_table);
				errlog(TRACING, "}");
				errlog(TRACING, "protected interfaces = {");
				print_stringtable(
				    b->b_uncles->bl_bucket->b_protected_table);
				errlog(TRACING, "}");
			}
		}
	}
}


/*
 * lower-level functions, not visible outside the file.
 */

/*
 * new_bucket -- create a bucket for a given version. Must not fail.
 */
static bucket_t *
new_bucket(const char *name, int weak)
{
	bucket_t *b;

	if ((b = (bucket_t *)calloc(1, sizeof (bucket_t))) == NULL) {
		errlog(FATAL, "out of memory creating a bucket "
			"to store interfaces in");
	}
	if ((b->b_name = strdup(name)) == NULL) {
		errlog(FATAL, "out of memory storing an interface "
			"in a version bucket");
	}
	b->b_uncles = NULL;
	b->b_global_table = create_stringtable(TABLE_INITIAL);
	b->b_protected_table = create_stringtable(TABLE_INITIAL);
	b->b_weak = weak;
	return (b);
}


/*
 * start_new_list -- start a list of buckets.
 */
static void
start_new_list(const bucket_t *b)
{
	int i;

	errlog(BEGIN, "start_new_list() {");
	assert(Buckethead != NULL, "Buckethead null in start_new_list");
	for (i = 0; Buckethead[i] != NULL && i < N_lists; ++i)
		continue;
	if (i >= N_lists) {
		grow_lists();
	}
	Buckethead[i] = (bucket_t *)b;
	errlog(END, "}");
}

/*
 * grow_list -- make more lists.  This should never occur...
 */
static void
grow_lists(void)
{
	int i = N_lists;

	errlog(BEGIN, "grow_lists() {");
	errlog(WARNING, "Warning: more than %d version lists "
	    "required (< %d is normal). Check sets file "
	    "to see why so many lines appear.",
	    N_lists, NLISTS);

	N_lists *= 2;
	if ((Buckethead = realloc(Buckethead, sizeof (bucket_t *) * N_lists))
		== NULL) {
		errlog(FATAL, "out of memory growing list of "
			"version buckets");
	}
	for (; i < N_lists; ++i) {
		Buckethead[i] = NULL;
	}
}

/*
 * delete_lists -- clean up afterwards.
 */
void
delete_lists(void)
{
	N_lists = 0;
	free(Buckethead);
	Buckethead = 0;
}

/*
 * first_list, next_list -- an iterator for lists themselves.  Serially
 *      reusable only.
 */
bucket_t *
first_list(void)
{
	Bc = 0;
	return (Buckethead[Bc]);
}

bucket_t *
next_list(void)
{
	return (Buckethead[++Bc]);
}


/*
 * first, next, last_from_list -- iterators for individual lists. Serially
 *      reusable only.
 */
bucket_t *
first_from_list(const bucket_t *l)
{
	return (Bp = (bucket_t *)l);
}

bucket_t *
next_from_list(void)
{
	return (Bp = Bp->b_parent);
}



/*
 * Iface print utility
 */
static void
print_iface(const Interface * p)
{

	errlog(TRACING, "%s (%s, %s, %s %d)", p->IF_name,
		(p->IF_type == FUNCTION) ? "function" :
		(p->IF_type == DATA) ? "data" : "unknown type",
		(p->IF_version) ? p->IF_version : "unknown version",
		(p->IF_class) ? p->IF_class : "unknown class",
		p->IF_binding);
}



#define	HASHMAPSIZE	100
#define	ERR	(-1)

static struct {
	hashmap_t *hh_map;
	int hh_map_size;
	int hh_mapC;
	hashmap_t *hh_last;
} Hashhead = {
	NULL, -1, -1, NULL
};

static int checksum(const char *);
static void print_hashmap(const hashmap_t *);

/*
 * new_hashmap -- create the hash.
 */
static void
new_hashmap(void)
{

	errlog(BEGIN, "new_hashmap() {");
	if ((Hashhead.hh_map = calloc(sizeof (hashmap_t), HASHMAPSIZE))
	    == NULL) {
		errlog(FATAL, "out of memory creating a hash-map of "
			"the versions");
	}
	Hashhead.hh_mapC = 0;
	errlog(END, "}");
}

/*
 * add_to_hashmap -- add a bucket to the map.  This is strictly for
 *	use by add_parent()/add_uncle().
 */
static int
add_to_hashmap(const char *version_name, const bucket_t *bucket)
{
	hashmap_t *p;

	assert(Hashhead.hh_map != NULL,
	    "Hashead.map was null in add_to_hashmap");
	assert(Hashhead.hh_mapC < HASHMAPSIZE,
	    "mapC too big in add_to_hashmap");
	errlog(BEGIN, "add_to_hashmap(%s, %s) {", version_name, bucket);
	if (find_in_hashmap(version_name) != NULL) {
		/* Seen for the second time. TBD... */
		errlog(END, "} /* add_to_hashmap */");
		return (ERR);
	}
	p = &Hashhead.hh_map[Hashhead.hh_mapC++];
	if ((p->h_version_name = strdup(version_name)) == NULL) {
		errlog(FATAL, "out of memory storing a version name");

	}
	p->h_bucket = (bucket_t *)bucket;
	p->h_hash = checksum(version_name);
	Hashhead.hh_last = p;
	print_hashmap(p);
	errlog(END, "} /* add_to_hashmap */");
	return (0);
}


/*
 * find_in_hashmap -- find a bucket by name.  Strictly for use by addByName().
 */
static bucket_t *
find_in_hashmap(const char *version_name)
{
	hashmap_t *current;
	int hash = checksum(version_name);

	assert(Hashhead.hh_map != NULL,
		"Hashhead.hh_map was null in find_in_hashmap");
	errlog(BEGIN, "find_in_hashmap(%s) {", version_name);
	if (Hashhead.hh_last != NULL && Hashhead.hh_last->h_hash == hash &&
	    strcmp(Hashhead.hh_last->h_version_name, version_name) == 0) {
		errlog(END, "}");
		return (Hashhead.hh_last->h_bucket);
	}
	for (current = Hashhead.hh_map;
		current->h_version_name != NULL; ++current) {
		if (current->h_hash == hash &&
			strcmp(current->h_version_name, version_name) == 0) {
			/* Found it */
			Hashhead.hh_last = current;
			errlog(END, "}");
			return (current->h_bucket);
		}
	}
	/* Doesn't exist, meaning version name is bogus. */
	errlog(END, "}");
	return (NULL);
}

/*
 * checksum -- from sum(1), algorithm 1.
 */
static int
checksum(const char *p)
{
	int sum;

	for (sum = 0; *p != '\0'; ++p) {
		if (sum & 01)
			sum = (sum >> 1) + 0x8000;
		else
			sum >>= 1;
		sum += *p;
		sum &= 0xFFFF;
	}
	return (sum);
}

static void
print_hashmap(const hashmap_t *h)
{
	errlog(VERBOSE, "struct hashmap_t at 0x4.4x {", h);
	errlog(VERBOSE, "    int    h_hash = %d;", h->h_hash);
	errlog(VERBOSE, "    char   *h_version_name = \"%s\";",
		h->h_version_name);
	errlog(VERBOSE, "    bucket_t *h_bucket = 0x%p;;",
		(void *) h->h_bucket);
	errlog(VERBOSE, "}");
}
