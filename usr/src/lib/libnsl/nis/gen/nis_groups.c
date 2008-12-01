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
 * 	nis_groups.c
 *
 * This file contains
 *	(1) Routines to test "is principal A in group B?".  The
 *	    implementation of this includes code to cache groups,
 *	(2) Operations on groups: add a principal, remove a principal,
 *	    check that a group exists, create and destroy groups.
 */

#include "mt.h"
#include <syslog.h>	/* ==== Is it really our place to syslog() things? */
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#define	__NIS_PRIVATE_INTERFACES
#include <rpcsvc/nis.h>
#include <stdio.h>
#include "nis_local.h"


/*
 * Results of do_ismember_2() and lookup_recursive().  ISMEM_DUNNO means
 * "I couldn't look up the group (or some recursive group), so I don't know".
 */
enum ismem { ISMEM_DUNNO, ISMEM_NO, ISMEM_YES };

/* === Should be defined with the rest of the hash-table routines */
typedef void	(*nis_flush_func)(NIS_HASH_ITEM *);
extern 	void nis_flush_table(NIS_HASH_TABLE *, nis_flush_func);
typedef bool_t	(*nis_scan_func)(NIS_HASH_ITEM *item, void *funcarg);
extern void	nis_scan_table(NIS_HASH_TABLE *, nis_scan_func, void *funcarg);

/* Forward declarations */
typedef nis_result *(*nis_lookup_func)(nis_name, uint_t);
static nis_object *get_group(nis_name, nis_name, nis_lookup_func, nis_error *);
static enum ismem do_ismember_2(nis_name, nis_name, nis_name,
	nis_lookup_func, nis_error *);


/*
 * The top level of the group cache.  There is a single instance of this:
 *   it's a hash-table that maps group-names to g_entry structures (q.v.)
 */
struct g_cache {
	NIS_HASH_TABLE	ht;
	/*
	 * Cache statistics, available from the server with the TAG_S_GCACHE
	 * tag.
	 */
	int		ncalls;
	int		nhits;
	int		nmisses;
};

typedef struct g_cache	*g_cache_ptr;

rwlock_t g_cache_lock = DEFAULTRWLOCK;
static g_cache_ptr	groups_cache;

static g_cache_ptr
get_g_cache(void)
{
	g_cache_ptr gc;

	/* always enter with a READ LOCK and exit with one too */
	ASSERT(RW_READ_HELD(&g_cache_lock));
	if ((gc = groups_cache) != 0) {
		return (gc);
	}
	(void) rw_unlock(&g_cache_lock);

	/* write lock the cache and try again */
	(void) rw_wrlock(&g_cache_lock);
	if ((gc = groups_cache) != 0) {
		(void) rw_unlock(&g_cache_lock);
		(void) rw_rdlock(&g_cache_lock);
		return (gc);
	}

	gc = groups_cache = calloc(1, sizeof (*groups_cache));
	if (groups_cache == 0) {
		(void) rw_unlock(&g_cache_lock);
		(void) rw_rdlock(&g_cache_lock);
		return (0);
	}
	(void) rw_unlock(&g_cache_lock);
	(void) rw_rdlock(&g_cache_lock);
	return (gc);
}


/* Interface for rpc.nisd and anyone else who wants to know */
int
__nis_group_cache_stats(int *grpcachecall, int *grpcachehits,
    int *grpcachemisses)
{
	(void) rw_rdlock(&g_cache_lock);
	if (groups_cache == 0) {
		*grpcachecall = 0;
		*grpcachehits = 0;
		*grpcachemisses = 0;
		(void) rw_unlock(&g_cache_lock);
		return (0);
	}
	*grpcachecall = groups_cache->ncalls;
	*grpcachehits = groups_cache->nhits;
	*grpcachemisses = groups_cache->nmisses;
	(void) rw_unlock(&g_cache_lock);
	return (1);
}

/*
 * Storage for the three sorts of group members:
 *	explicit  (name of a principal),
 *	implicit  (name of a domain, meaning all principals in that domain)
 *	recursive (name of a group,  meaning all principals in that group )
 * We expect lots of explicit members, so we use a hash table; for the other
 *   two we use singly-linked lists (if there are lots of implicit members
 *   then a hash table could be used there too, but there'll probably just be
 *   zero or one implicit members).
 * Memory-management policy: we (or the hash-table routines) malloc/free space
 *   for the tables/lists, but not for the strings they contain; the strings
 *   are all assumed to be pointers into the gr_members<> vector in the
 *   group object, which we keep around.
 */

struct cons {
	struct cons	*prochain;
	char		*nom;
};

struct g_varieties {
	NIS_HASH_TABLE	*explicit;
	struct cons	*implicit;
	struct cons	*recursive;
};

typedef struct g_varieties g_varieties;


/*
 * ===  For our purposes, most of NIS_HASH_TABLE is excess baggage.  We don't
 *	need keychain and we don't need the first/prv_item/nxt_item chain.
 *	Unless there's something that really needs stack-ordered semantics,
 *	we should get rid of them and reduce items from 20 bytes to 8.
 */

static bool_t
insert_explicit(g_varieties *varp, nis_name princp)
{
	NIS_HASH_ITEM	*it;

	if (varp->explicit == 0) {
		if (0 == (varp->explicit =
		    calloc(1, sizeof (NIS_HASH_TABLE)))) {
			return (FALSE);
		}
	}
	/* Don't use nis_insert_name() because we don't need the strdup(), */
	/*   so do the same sort of thing ourselves			   */
	if ((it = malloc(sizeof (NIS_HASH_ITEM))) == NULL) {
		/* Memory is tight;  can we free some that we don't need? */
		if (varp->explicit->first == 0) {
			/* Yup, no entries in the hash-table, so free it */
			free(varp->explicit);
			varp->explicit = 0;
		}
		return (FALSE);
	}
	it->name = princp;
	if (!nis_insert_item(it, varp->explicit)) {
		free(it);
		return (FALSE);
	}
	return (TRUE);
}

static bool_t
lookup_explicit(g_varieties *varp, nis_name princp)
{
	int dummy;

	ASSERT(RW_READ_HELD(&g_cache_lock));
	if (varp->explicit == 0) {
		return (FALSE);
	}
	return (nis_in_table(princp, varp->explicit, &dummy) == 1);
}

static void
delete_explicit(g_varieties *varp)
{
	if (varp->explicit != 0) {
		nis_flush_table(varp->explicit, (nis_flush_func)free);
		free(varp->explicit);
		varp->explicit = 0;
	}
}

/* ARGSUSED1 */
static bool_t
printf_hname(NIS_HASH_ITEM *it, void *dummy)
{
	(void) printf("\t%s\n", it->name);
	return (FALSE);	/* i.e. continue */
}

static void
printf_explicit(const g_varieties *varp, const char *title)
{
	if (varp->explicit == 0) {
		(void) printf("    No explicit %smembers\n", title);
	} else {
		(void) printf("    Explicit %smembers:\n", title);
		nis_scan_table(((g_varieties *)varp)->explicit,
		    printf_hname, (void *)0);
	}
}


static bool_t
push_namelist(struct cons **nlp, char *name)
{
	struct cons	*it;

	/* Don't bother looking for duplicates.  They were quite likely */
	/* with the old group semantics but would be pretty weird now.	*/
	if ((it = malloc(sizeof (*it))) == NULL) {
		return (FALSE);
	}
	it->nom = name;
	it->prochain = *nlp;
	*nlp = it;
	return (TRUE);
}

static void
free_namelist(struct cons **nlp)
{
	struct cons	*cur, *nxt;

	for (cur = *nlp; cur != 0; cur = nxt) {
		nxt = cur->prochain;
		free(cur);
	}
	*nlp = 0;
}

static void
print_namelist(const struct cons *nl)
{
	while (nl != 0) {
		(void) printf("\t%s\n", nl->nom);
		nl = nl->prochain;
	}
}


static bool_t
insert_implicit(g_varieties *varp, nis_name implicit)
{
	/* Assumes that the "*." has been stripped from 'implicit' */
	return (push_namelist(&varp->implicit, implicit));
}

static bool_t
lookup_implicit(g_varieties *varp, nis_name princp)
{
	nis_name	domain	= nis_domain_of(princp);
	struct cons	*nl;

	ASSERT(RW_READ_HELD(&g_cache_lock));
	for (nl = varp->implicit;  nl != 0;  nl = nl->prochain) {
		/* ==== Using nis_dir_cmp is silly; just strcasecmp()? */
		if (nis_dir_cmp(domain, nl->nom) == SAME_NAME) {
			return (TRUE);
		}
	}
	return (FALSE);

#if	0
	/* Alternative semantics, where "*" means a subtree of the */
	/* namespace rather than just one level wildcarded.	   */
	for (nl = varp->implicit;  nl != 0;  nl = nl->prochain) {
		if (nis_dir_cmp(princp, nl->nom) == LOWER_NAME)
			return (TRUE);
	}
	return (FALSE);
#endif
}

static void
delete_implicit(g_varieties *varp)
{
	free_namelist(&varp->implicit);
}

static void
printf_implicit(const g_varieties *varp, const char *title)
{
	if (varp->implicit == 0) {
		(void) printf("    No implicit %smembers\n", title);
	} else {
		(void) printf("    Implicit %smembers:\n", title);
		print_namelist(varp->implicit);
	}
}


static bool_t
insert_recursive(g_varieties *varp, nis_name recurs)
{
	/* Assumes the "@" has been stripped from 'recurs' */
	return (push_namelist(&varp->recursive, recurs));
}

static enum ismem
lookup_recursive(
	g_varieties	*varp,
	nis_name	princp,
	nis_name	refname,	/* name of the group that contains */
					/*   these recursive references    */
	nis_lookup_func	lookup,
	nis_error	*stat)
{
	struct cons	*nl;
	enum ismem	status = ISMEM_NO;

	ASSERT(RW_READ_HELD(&g_cache_lock));
	for (nl = varp->recursive;  nl != 0;  nl = nl->prochain) {
		switch (do_ismember_2(princp, nl->nom, refname, lookup, stat)) {
			case ISMEM_YES:
				ASSERT(RW_READ_HELD(&g_cache_lock));
				return (ISMEM_YES);
			case ISMEM_NO:
				break;
			default:
				status = ISMEM_DUNNO;
				break;
		}
	}
	ASSERT(RW_READ_HELD(&g_cache_lock));
	return (status);
}

static void
delete_recursive(g_varieties *varp)
{
	free_namelist(&varp->recursive);
}

static void
printf_recursive(const g_varieties *varp, const char *title)
{
	if (varp->recursive == 0) {
		(void) printf("    No recursive %smembers\n", title);
	} else {
		(void) printf("    Recursive %smembers:\n", title);
		print_namelist(varp->recursive);
	}
}

static void
printf_varieties(g_varieties *varp, const char *title)
{
	printf_explicit(varp, title);
	printf_implicit(varp, title);
	printf_recursive(varp, title);
}


/*
 * g_entry:  A transformed group entry, of the sort we put in the group cache.
 */

struct g_entry {
	NIS_HASH_ITEM	hdata;		/* Hash table info		*/
	uint32_t	tte;		/* Time to expire		*/
	g_varieties	include;	/* Semantics are "in(include)	*/
	g_varieties	exclude;	/*	AND NOT in(exclude)"	*/
	nis_object	*group_obj;	/* Keep it around,since all the */
					/*   stuff above points into it */
	int		visiting;	/* Recursion-detection for	*/
					/*   do_ismember_2(), q.v.	*/
};

typedef struct g_entry g_entry;

static bool_t visited(g_entry *ge);

static g_entry *
insert_g_entry(g_cache_ptr gc, g_entry *ge)
{
	ASSERT(RW_WRITE_HELD(&g_cache_lock));
	return nis_insert_item((NIS_HASH_ITEM *)ge, &gc->ht) == 0
	    ? 0 : ge;
}

static g_entry *
lookup_g_entry(g_cache_ptr gc, nis_name name)
{
	ASSERT(RW_READ_HELD(&g_cache_lock) || (RW_WRITE_HELD(&g_cache_lock)));
	return (g_entry *) nis_find_item(name, &gc->ht);
}

static void
free_g_entry(g_entry *el)
{
	if (el != 0) {
		if (el->hdata.name != 0) {
			free(el->hdata.name);
		}
		delete_explicit(&el->include);
		delete_implicit(&el->include);
		delete_recursive(&el->include);
		delete_explicit(&el->exclude);
		delete_implicit(&el->exclude);
		delete_recursive(&el->exclude);
		if (el->group_obj != 0) {
			nis_destroy_object(el->group_obj);
		}
		free(el);
	}
}

static void
remove_g_entry(
	g_cache_ptr	gc,
	nis_name	name)	/* NIS name to remove	*/
{
	g_entry	*el;

	ASSERT(RW_WRITE_HELD(&g_cache_lock));
	if (0 != (el = (g_entry *) nis_remove_item(name, &gc->ht))) {
		free_g_entry(el);
	}
}

static void
delete_g_entry(g_cache_ptr gc)
{
	ASSERT(RW_WRITE_HELD(&g_cache_lock));
	nis_flush_table(&gc->ht, (nis_flush_func)free_g_entry);
}


/*
 * transform_group() -- fetch a group, massage it into the form it should have
 *	had in the first place, and return a pointer to it.
 */

static g_entry *
transform_group(
	nis_name	gname,
	nis_object	*gobj,	/* Assumed to be a NIS_GROUP_OBJ */
	nis_error	*stat)
{
	g_entry		*ge;
	struct timeval	tv;
	int		nm;
	int		i;
	nis_name	*ml;

	ge = calloc(1, sizeof (*ge));
	if (ge == 0) {
		syslog(LOG_WARNING, "nislib:transform_group() out of memory");
		*stat = NIS_NOMEMORY;
		return (0);
	}
	ge->hdata.name	= strdup(gname);	/* ==== is strdup necessary? */
	ge->group_obj	= gobj;
	/* The calloc() set ge->visiting to zero for us */

	nm = gobj->GR_data.gr_members.gr_members_len;
	ml = gobj->GR_data.gr_members.gr_members_val;

	for (i = 0;  i < nm; i++) {
		g_varieties	*var;
		nis_name	t;
		bool_t		ok = TRUE;

		var = &ge->include;
		t = ml[i];
		if (*t == '-') {
			var = &ge->exclude;
			t++;
		}

		if (*t == '*') {
			ok = insert_implicit(var, t+2);
		} else if (*t == '@') {
			ok = insert_recursive(var, t+1);
			/* ===  could check to see whether someone specified */
			/*	it twice (or specified it in both 'include'  */
			/*	and 'exclude'), but probably not worth it.   */
		} else {
			ok = insert_explicit(var, t);
		}
		if (!ok) {
			free_g_entry(ge);
			*stat = NIS_NOMEMORY;
			syslog(LOG_WARNING,
		"nislib:transform_group() insert failed, maybe out of memory");
			return (0);
		}
	}
	(void) gettimeofday(&tv, (struct timezone *)0);
	ge->tte = (uint32_t)tv.tv_sec + gobj->zo_ttl;
	return (ge);
}

/*
 * cached_group_entry(groupnam, refname, lookup)
 *
 *	Returns a pointer to an entry in group_cache for the group called
 *	[group].  Adds the group to the cache if it isn't there already.
 *	Also checks the time-to-expire and refreshes if necessary.
 *	Returns NULL only if the universe is really broken.
 */

static g_entry *
cached_group_entry(
	nis_name group,
	nis_name refname,
	nis_lookup_func lookup,
	nis_error *stat)
{
	g_entry		*ge;		/* Group entry from cache	*/
	g_cache_ptr	gc;

	*stat = NIS_SUCCESS;
	/* always come in with a READ LOCK and exit with one too */
	ASSERT(RW_READ_HELD(&g_cache_lock));
	gc = get_g_cache();
	if (gc == 0) {
		*stat = NIS_NOMEMORY;
		return (0);
	}

	ge = lookup_g_entry(gc, group);

	if (ge != 0 && !visited(ge)) {
		struct timeval	tv;
		/* Expire the group if necessary */
		(void) gettimeofday(&tv, (struct timezone *)0);
		if (ge->tte < tv.tv_sec) {
			(void) rw_unlock(&g_cache_lock);
			(void) rw_wrlock(&g_cache_lock);
			remove_g_entry(gc, group);
			ge = 0;
		}
	}

	if (ge != 0) {
		(void) rw_unlock(&g_cache_lock);
		(void) rw_wrlock(&g_cache_lock);
		gc->nhits++;
		gc->ncalls++;
		(void) rw_unlock(&g_cache_lock);
		(void) rw_rdlock(&g_cache_lock);
		return (ge);
	}
	(void) rw_unlock(&g_cache_lock);

	/* write lock the cache and try again */
	(void) rw_wrlock(&g_cache_lock);
	ge = lookup_g_entry(gc, group);

	if (ge != 0 && !visited(ge)) {
		struct timeval	tv;
		/* Expire the group if necessary */
		(void) gettimeofday(&tv, (struct timezone *)0);
		if (ge->tte < tv.tv_sec) {
			remove_g_entry(gc, group);
			ge = 0;
		}
	}

	if (ge != 0) {
		gc->nhits++;
		gc->ncalls++;
		(void) rw_unlock(&g_cache_lock);
		(void) rw_rdlock(&g_cache_lock);
		return (ge);
	} else {
		nis_object	*obj;

		gc->nmisses++;
		/* Lets drop the cache lock as actual lookup may take a while */
		(void) rw_unlock(&g_cache_lock);
		obj = get_group(group, refname, lookup, stat);
		(void) rw_wrlock(&g_cache_lock);
		if (obj == 0) {
			gc->ncalls++;
			(void) rw_unlock(&g_cache_lock);
			(void) rw_rdlock(&g_cache_lock);
			return (0); /* Couldn't read it */
		}
		ge = transform_group(group, obj, stat);
		if (ge == 0) {
			gc->ncalls++;
			(void) rw_unlock(&g_cache_lock);
			nis_destroy_object(obj);
			(void) rw_rdlock(&g_cache_lock);
			return (0);
		}
		if (insert_g_entry(gc, ge) == 0) {
			gc->ncalls++;
			(void) rw_unlock(&g_cache_lock);
			free_g_entry(ge);
			(void) rw_rdlock(&g_cache_lock);
			*stat = NIS_NOMEMORY;
			return (0);
		}
		gc->ncalls++;
		(void) rw_unlock(&g_cache_lock);
		(void) rw_rdlock(&g_cache_lock);
		return (ge);
	}
	/* NOTREACHED */
}

static pthread_key_t visit_log_key = PTHREAD_ONCE_KEY_NP;
struct visit_log {
	g_entry		 *ge_id;
	struct visit_log *next;
};
static struct visit_log *visit_list_main;

static void
mark_visit(g_entry *ge)
{
	struct visit_log *v;

	v = calloc(1, sizeof (struct visit_log));
	v->ge_id = ge;
	if (thr_main()) {
		v->next = visit_list_main;
		visit_list_main = v;
	} else {
		v->next = thr_get_storage(&visit_log_key, 0, NULL);
		(void) pthread_setspecific(visit_log_key, v);
	}
}

static void
unmark_fatal(void)
{
	(void) printf("unmark: fatal error\n");
	abort();
}

static void
unmark_visit(g_entry *ge)
{
	struct visit_log *v;

	if (thr_main()) {
		v = visit_list_main;
		if (v == NULL || v->ge_id != ge) /* must be in LIFO order */
			unmark_fatal();
		visit_list_main = v->next;
	} else {
		v = thr_get_storage(&visit_log_key, 0, NULL);
		if (v == NULL || v->ge_id != ge) /* must be in LIFO order */
			unmark_fatal();
		(void) pthread_setspecific(visit_log_key, v->next);
	}
	free(v);
}

static bool_t
visited(g_entry *ge)
{
	struct visit_log *v = thr_main()? visit_list_main :
	    thr_get_storage(&visit_log_key, 0, NULL);

	while (v) {
		if (v->ge_id == ge)
			return (TRUE);
		v = v->next;
	}
	return (FALSE);
}

/*
 * The main machinery for testing "is A a member of B?".  The work gets done in
 *   do_ismember_2(), but clients won't normally call it directly;  they use
 *   __do_ismember() or nis_ismember().
 */
static enum ismem
do_ismember_2(
	nis_name	princp,	 /* Principal name */
	nis_name	group,	 /* NIS group name */
	nis_name	refname, /* Group that's recursively using this one */
	nis_lookup_func	lookup,
	nis_error	*stat)
{
	g_entry		*ge;
	int		easy_include;
	enum ismem	answer;

	/*
	 * return YES if
	 *	in(princp, ge->include) AND NOT in(princp, ge->exclude)
	 * return NO if
	 *	in(princp, ge->exclude)  OR NOT in(princp, ge->include)
	 * return DUNNO if
	 *	we can't look at some group.
	 *
	 * Checking for explicit members should be cheap, implicit members
	 *   should be fairly cheap, and recursive members may be expensive;
	 *   we try to order the tests accordingly.
	 */

	/* always enter with a READ LOCK and exit with one too */
	ASSERT(RW_READ_HELD(&g_cache_lock));
	ge = cached_group_entry(group, refname, lookup, stat);
	if (ge == 0) {
		/* === Should discover whether get_group() got NOTFOUND */
		/*	and, if so, return a definite ISMEM_NO (?)	*/
		ASSERT(RW_READ_HELD(&g_cache_lock));
		return (ISMEM_DUNNO);
	}

	if (lookup_explicit(&ge->exclude, princp) ||
	    lookup_implicit(&ge->exclude, princp)) {
		ASSERT(RW_READ_HELD(&g_cache_lock));
		return (ISMEM_NO);
	}
	easy_include =
	    lookup_explicit(&ge->include, princp) ||
	    lookup_implicit(&ge->include, princp);

	/* Probable optimization; result will be the same with or without */
	if (easy_include == 0 && ge->include.recursive == 0) {
		ASSERT(RW_READ_HELD(&g_cache_lock));
		return (ISMEM_NO);
	}

	if (visited(ge)) {
		ASSERT(RW_READ_HELD(&g_cache_lock));
		return (ISMEM_DUNNO);
	}
	mark_visit(ge);

	switch (lookup_recursive(&ge->exclude, princp, group, lookup, stat)) {
		case ISMEM_YES:
			answer = ISMEM_NO;
			break;
		case ISMEM_NO:
			if (easy_include) {
				answer = ISMEM_YES;
		} else {
			answer = lookup_recursive(&ge->include, princp,
			    group, lookup, stat);
		}
		break;
		default:
		if (!easy_include &&
		    (lookup_recursive(&ge->include, princp, group,
		    lookup, stat) == ISMEM_NO)) {
			answer = ISMEM_NO;
		} else {
			answer = ISMEM_DUNNO;
		}
	}
	unmark_visit(ge);
	ASSERT(RW_READ_HELD(&g_cache_lock));
	return (answer);
}

/*
 * nis_ismember(princp, group)
 *
 * This is the client function. It is a wrapper around an internal
 * interface that is used by both the clients and servers ofNIS
 * namespaces.
 */
bool_t
nis_ismember(
	nis_name	princp,	/* Principal name 		*/
	nis_name	group)	/* NIS group name 		*/
{
	bool_t	ret;
	nis_error x;

	(void) rw_rdlock(&g_cache_lock);
	/* Err on the side of security:  in case of doubt, return FALSE */
	ret = (do_ismember_2(princp, group, 0, nis_lookup, &x) == ISMEM_YES);
	(void) rw_unlock(&g_cache_lock);
	return (ret);
}

/*
 * __do_ismember(princp, obj, lookup)
 *
 * Same as nis_ismember(), but calls an arbitrary lookup function rather than
 *   nis_lookup().  Clearly nis_ismember() could call this, but just this
 *   once let's save the extra function call.
 */
bool_t
__do_ismember(
	nis_name	princp,	/* Principal name 		*/
	nis_object	*obj,
	nis_lookup_func	lookup)
{
	nis_error stat;
	enum ismem isit;

	(void) rw_rdlock(&g_cache_lock);
	/* Err on the side of security:  in case of doubt, return FALSE */
	isit = do_ismember_2(princp, obj->zo_group, 0, lookup, &stat);
	(void) rw_unlock(&g_cache_lock);
	if (isit == ISMEM_DUNNO) {
		if (stat != NIS_SUCCESS) {
			syslog(LOG_ERR,
			"lookup failure on group \"%s\" from object \"%s.%s\"",
			    obj->zo_group, obj->zo_name, obj->zo_domain);
		}
	}
	return (isit == ISMEM_YES);
}


void
nis_print_group_entry(
	nis_name	group) /* Name of the group to print */
{
	g_entry		*ge;
	nis_error	stat;

	(void) rw_rdlock(&g_cache_lock);
	ge = cached_group_entry(group, (nis_name)0, nis_lookup, &stat);
	if (ge == 0) {
		(void) printf("Could not find group \"%s\".\n", group);
		(void) rw_unlock(&g_cache_lock);
		return;
	}

	(void) printf("Group entry for \"%s\" group:\n", ge->hdata.name);
	printf_varieties(&ge->include, "");
	printf_varieties(&ge->exclude, "non");
	(void) rw_unlock(&g_cache_lock);
}


/*
 * nis_flushgroups()
 *
 * This function will free all memory associated with the group cache.
 */
void
nis_flushgroups(void)
{
	(void) rw_wrlock(&g_cache_lock);
	if (groups_cache != 0) {
		delete_g_entry(groups_cache);
	}
	(void) rw_unlock(&g_cache_lock);
	/* Else there's no cache, so no flushing to do */
}

/*
 * nis_flushgroup(groupname) -- means "I've probably changed this group; flush
 *   any group_cache info that depends on it".  With the old group-cache
 *   semantics, any group that included this one (directly or recursively)
 *   would have to be flushed, so it was easiest just to do a complete
 *   nis_flushgroups();  with the group-cache semantics here (i.e. information
 *   about recursive members isn't propagated), we only have to flush the one
 *   group.
 */
void
__nis_flush_one_group(nis_name groupname) /* === new kinda public interface */
{
	(void) rw_wrlock(&g_cache_lock);
	if (groups_cache != 0) {
		remove_g_entry(groups_cache, groupname);
	}
	(void) rw_unlock(&g_cache_lock);
	/* Else there's no cache, so no flushing to do */
}

/*
 * Same as __nis_flush_one_group() except that it accepts expanded group
 * names i.e. with embedded "groups_dir" as part of the name.
 */
void
__nis_flush_group_exp_name(nis_name groupname)
{
	char *domainname;

	domainname = nis_domain_of(groupname);
	if (strncmp(domainname, "groups_dir.", strlen("groups_dir.")) == 0) {
		/* Strip off "groups_dir" part of it */
		char tname[NIS_MAXNAMELEN];
		char buf[NIS_MAXNAMELEN];

		(void) snprintf(tname, sizeof (tname), "%s.%s",
		    nis_leaf_of_r(groupname, buf, NIS_MAXNAMELEN),
		    nis_domain_of(domainname));
		__nis_flush_one_group(tname);
	} else {
		__nis_flush_one_group(groupname);
	}
}

nis_name
__nis_splice_name_r(const nis_name name, const char *splice, char *buf,
    size_t bufsize)
{
	size_t newsize = strlen(name) + strlen(splice) + 2;
	char *p = buf;

	if (bufsize < newsize) {
		return (0);
	}

	(void) nis_leaf_of_r(name, p, bufsize);
	p += strlen(p);

	*p++ = '.';

	(void) strcpy(p, splice);
	p += strlen(p);

	*p++ = '.';

	(void) strcpy(p, nis_domain_of(name));
	return (buf);
}

nis_name
__nis_map_group_r(
	const nis_name	name,
	char		*buf,
	size_t		bufsize)
{
	return (__nis_splice_name_r(name, "groups_dir", buf, bufsize));
}

/*
 * get_group()
 *
 * This function is a wrapper around the NIS code to fetch the group
 * objects.  The object returned is not static; it has been malloc()ed.
 */

static nis_object *
get_group(
	nis_name	name,		/* group name			    */
	nis_name	refname,	/* group that referenced this group */
	nis_lookup_func	lookup,
	nis_error	*stat)		/* error status. */
{
	nis_result	*res;
	nis_name	gname;
	nis_object	*obj;
	char		namebuf[NIS_MAXNAMELEN];

	gname = __nis_map_group_r(name, namebuf, sizeof (namebuf));
	res = (*lookup)(gname, FOLLOW_LINKS + NO_AUTHINFO);
	if (res->status == NIS_NOTFOUND) {
		/* Finally, the reason for passing that 'refname' parameter  */
		/*   all over creation:  printing a worthwhile error message */
		if (refname)
			syslog(LOG_ERR,
"nislib:get_group() group object \"%s\", referenced by \"%s\", does not exist.",
			    name, refname);
		else
			syslog(LOG_ERR,
"nislib:get_group() group object \"%s\" does not exist.",
			    name);

		*stat = res->status;
		nis_freeresult(res);
		return (0);
	} else if (res->status != NIS_SUCCESS) {
		if (refname)
			syslog(LOG_ERR,
"nislib:get_group() object \"%s\", referenced by \"%s\", lookup failed.",
			    name, refname);
		else
			syslog(LOG_ERR,
"nislib:get_group() object \"%s\" lookup failed.",
			    name);

		nis_lerror(res->status, "nislib:get_group reason");
		*stat = res->status;
		nis_freeresult(res);
		return (0);
	}

	if (__type_of(NIS_RES_OBJECT(res)) != NIS_GROUP_OBJ) {
		if (refname)
			syslog(LOG_ERR,
"nislib:get_group() object \"%s\", referenced by \"%s\", is not a group.",
			    name, refname);
		else
			syslog(LOG_ERR,
"nislib:get_group() object \"%s\" is not a group.",
			    name);

		nis_freeresult(res);
		*stat = NIS_BADOBJECT;
		return (0);
	}

	/*
	 * Steal the object before we free the whole result (cheaper than
	 *  cloning).   ==== This will leak if ever (NIS_RES_NUMOBJ(res) > 1).
	 */
	obj = NIS_RES_OBJECT(res);
	NIS_RES_OBJECT(res) = 0;
	NIS_RES_NUMOBJ(res) = 0;
	*stat = res->status;
	nis_freeresult(res);
	return (obj);
}


/*
 * nis_addmember(princp, group)
 */
nis_error
nis_addmember(
	nis_name	princp,	/* Principal name */
	nis_name	group)	/* NIS group name */
{
	nis_result	*res;	/* the group in question */
	nis_object	*obj;	/* The group object	*/
	nis_error	result;	/* our result		*/
	int		nm,	/* Number of members 	*/
	    i;
	nis_name	*ml;	/* member list		*/
	nis_object	ngrp;	/* New group object	*/
	char		name[NIS_MAXNAMELEN]; /* Group name	*/

	/* Read the group object. */
	obj = get_group(group, 0, nis_lookup, &result);
	if (obj == 0) {
		return (result);
	}

	nm = obj->GR_data.gr_members.gr_members_len;
	ml = obj->GR_data.gr_members.gr_members_val;
	for (i = 0; i < nm; i++) {
		if (nis_dir_cmp(princp, ml[i]) == SAME_NAME) {
			nis_destroy_object(obj);
			return (NIS_NAMEEXISTS);
		}
	}

	__nis_flush_one_group(group);

	ngrp = *obj; /* copy the object */
	ngrp.GR_data.gr_members.gr_members_val =
	    malloc((nm+1) * sizeof (nis_name));
	if (!ngrp.GR_data.gr_members.gr_members_val) {
		syslog(LOG_ERR, "nis_addmember: Out of memory");
		nis_destroy_object(obj);
		return (NIS_NOMEMORY);
	}
	for (i = 0; i < nm; i++) {
		ngrp.GR_data.gr_members.gr_members_val[i] = ml[i];
	}
	ngrp.GR_data.gr_members.gr_members_val[nm] = princp;
	ngrp.GR_data.gr_members.gr_members_len = nm+1;
	(void) snprintf(name, sizeof (name),
	    "%s.%s", obj->zo_name, obj->zo_domain);
	/* XXX overwrite problem if multiple writers ? */
	res = nis_modify(name, &ngrp);
	free(ngrp.GR_data.gr_members.gr_members_val);
	result = res->status;
	nis_freeresult(res);
	nis_destroy_object(obj);
	return (result);
}

/*
 * nis_removemember(princp, group)
 */
nis_error
nis_removemember(
	nis_name	princp,	/* Principal name */
	nis_name	group)	/* NIS group name */
{
	nis_result	*res;	/* the group in question */
	nis_object	*obj;	/* The group object	*/
	nis_error	result;	/* our result		*/
	int		nm,	/* Number of members 	*/
	    i, x;
	nis_name	*ml;	/* member list		*/
	nis_object	ngrp;	/* New group object	*/
	char		name[NIS_MAXNAMELEN]; /* Group name	*/

	obj = get_group(group, 0, nis_lookup, &result);
	if (!obj)
		return (result);
	nm = obj->GR_data.gr_members.gr_members_len;
	ml = obj->GR_data.gr_members.gr_members_val;
	for (i = 0; i < nm; i++) {
		if (nis_dir_cmp(princp, ml[i]) == SAME_NAME)
			break;
	}
	/* If i == nm then we didn't find the member to remove */
	if (i == nm) {
		nis_destroy_object(obj);
		return (NIS_NOSUCHNAME);
	}

	__nis_flush_one_group(group);

	ngrp = *obj; /* copy the object */
	ngrp.GR_data.gr_members.gr_members_val = malloc(nm * sizeof (nis_name));
	if (!ngrp.GR_data.gr_members.gr_members_val) {
		syslog(LOG_ERR, "nis_addmember: Out of memory");
		nis_destroy_object(obj);
		return (NIS_NOMEMORY);
	}
	/*
	 * We know that ml[0..i-1] aren't the same name, and ml[i] is, so
	 *   copy the former, skip the latter, and then check ml[i+1..nm-1]
	 */
	for (x = 0; x < i; x++) {
		ngrp.GR_data.gr_members.gr_members_val[x] = ml[x];
	}
	/* Note: Removes _all_ instances of a principal name */
	while (++i < nm) {
		if (nis_dir_cmp(princp, ml[i]) != SAME_NAME) {
			ngrp.GR_data.gr_members.gr_members_val[x] = ml[i];
			++x;
		}
	}
	ngrp.GR_data.gr_members.gr_members_len = x;
	(void) snprintf(name, sizeof (name),
	    "%s.%s", obj->zo_name, obj->zo_domain);
	res = nis_modify(name, &ngrp);
	free(ngrp.GR_data.gr_members.gr_members_val);
	result = res->status;
	nis_freeresult(res);
	nis_destroy_object(obj);
	return (result);
}

/*
 * nis_verifygroup(group)
 *
 * Verify the existence of the named group.
 *
 */
nis_error
nis_verifygroup(nis_name group)	/* NIS group name */
{
	nis_name	grpname;
	nis_result	*res;
	nis_error	result;
	char		namebuf[NIS_MAXNAMELEN];

	grpname = __nis_map_group_r(group, namebuf, sizeof (namebuf));
	res = nis_lookup(grpname, FOLLOW_LINKS);
	if ((res->status == NIS_SUCCESS) || (res->status == NIS_S_SUCCESS)) {
		if (__type_of(res->objects.objects_val) == NIS_GROUP_OBJ)
			result = NIS_SUCCESS;
		else
			result = NIS_BADOBJECT;
	} else
		result = res->status;
	nis_freeresult(res);
	return (result);
}

/*
 * __nis_creategroup_obj(name, flags, obj)
 *
 * This function creates an empty group of the given name.
 * Using obj for setting the group object defaults.
 */
nis_error
__nis_creategroup_obj(nis_name name, uint_t flags, nis_object *obj)
{
	nis_object 	grpobj;
	group_obj	*grdata;
	nis_name	grpname;
	nis_error	result;
	nis_result	*res;
	char		namebuf[NIS_MAXNAMELEN];
	char		leafbuf[NIS_MAXSTRINGLEN];

	grpname = __nis_map_group_r(name, namebuf, sizeof (namebuf));
	grpobj.zo_data.zo_type = NIS_GROUP_OBJ;
	grdata = &(grpobj.GR_data);

	/* Tease apart the name we just created in nis_map_group_r();	*/
	/*   ==== maybe we need a more sensible interface.		*/
	grpobj.zo_name	= nis_leaf_of_r(grpname, leafbuf, sizeof (leafbuf));
	grpobj.zo_domain = nis_domain_of(grpname);
	if (obj) {
		grpobj.zo_owner	= obj->zo_owner;
		grpobj.zo_group = obj->zo_group;
		grpobj.zo_access = obj->zo_access;
		grpobj.zo_ttl = obj->zo_ttl;
	} else {
		grpobj.zo_owner	= nis_local_principal();
		grpobj.zo_group = nis_local_group();
		grpobj.zo_access = DEFAULT_RIGHTS;
		grpobj.zo_ttl = 3600; /* one hour by default */
	}
	grdata->gr_flags = flags;
	grdata->gr_members.gr_members_len = 0;
	grdata->gr_members.gr_members_val = 0;
	res = nis_add(grpname, &grpobj);
	result = res->status;
	nis_freeresult(res);
	/* If we're just creating it then it shouldn't have been in the */
	/*	cache so this is a no-op, but let's play safe.		*/
	__nis_flush_one_group(name);
	return (result);
}

/*
 * nis_creategroup(name, flags)
 *
 * This function creates an empty group of the given name.
 */
nis_error
nis_creategroup(nis_name name, uint_t flags)
{
	return (__nis_creategroup_obj(name, flags, NULL));
}

nis_error
nis_destroygroup(nis_name name)
{
	nis_name	grpname;
	nis_result	*res;
	nis_error	result;
	char		namebuf[NIS_MAXNAMELEN];

	grpname = __nis_map_group_r(name, namebuf, sizeof (namebuf));
	res = nis_remove(grpname, (nis_object *)0);
	result = res->status;
	nis_freeresult(res);
	__nis_flush_one_group(name);
	return (result);
}
