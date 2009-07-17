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
 * Copyright (c) 2008-2009, Intel Corporation.
 * All Rights Reserved.
 */

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>

#include "latencytop.h"

/* Statistics for each process/thread. */
typedef struct _lt_stat_collection lt_stat_collection_t;
typedef gboolean (*check_child_func_t) (gpointer key,
    lt_stat_collection_t *stat, void *user);

typedef struct {
	lt_stat_entry_t summary;
	/* cause_id -> stat entry */
	GHashTable *sctable;
} lt_datagroup_t;

#define	NGROUPS			2
#define	GROUP_CAUSE		0
#define	GROUP_SOBJ		1

/*
 * A data collection (i.e. a "bucket"). E.g. system, process or thread.
 * Collections are hierarchic, 1 sys -> many processes -> more threads.
 */
struct _lt_stat_collection {
	lt_stat_level_t level;
	unsigned int id;
	char *name;
	lt_datagroup_t groups[NGROUPS];
	/*
	 * The following fields: parent, children and check_child_func
	 * maintain the tree structure.
	 */
	lt_stat_collection_t *parent;		/* Parent node */
	GHashTable *children;	/* pid (or tid) -> lt_stat_collection_t */
	check_child_func_t check_child_func;	/* Release dead children */
};

/* Internal data struct backs up a stat_list */
typedef struct _lt_stat_list lt_stat_list_t;
typedef void (*free_list_func_t)(lt_stat_list_t *);
struct _lt_stat_list {
	int entry_count;
	lt_stat_entry_t **entries;
	uint64_t gtotal;
	free_list_func_t free_func;
};

/* The root collection: system level statistics */
static lt_stat_collection_t *stat_system = NULL;

/*
 * The data structure which supports synchronization objects.
 * We don't use normal "cause table" because this needs to be cleared
 * every time we refresh, so that dead synchronization objects don't
 * eat up memory little by little.
 */
typedef struct {
	int sobj_type;
	unsigned long long sobj_addr;
} lt_sobj_id_t;
typedef struct {
	lt_sobj_id_t sobj_id;
	int cause_id;
	char string[32];	/* Enough to hold "%s: 0x%llX" */
} lt_sobj_t;

static GHashTable *sobj_table = NULL;
static int sobj_table_len = 0;

/*
 * Hash synchronize object ID by returning lower 32bit of its address.
 */
static guint
sobj_id_hash(lt_sobj_id_t *id)
{
	g_assert(id != NULL);
	return (id->sobj_addr & 0xFFFFFFFF);
}

/*
 * Test if two synchronization objects are the same.
 */
static gboolean
sobj_id_equal(lt_sobj_id_t *a, lt_sobj_id_t *b)
{
	g_assert(a != NULL && b != NULL);
	return (a->sobj_type == b->sobj_type && a->sobj_addr == b->sobj_addr);
}

/*
 * Lookup the cause_id of an synchronization object.
 * Note this cause_id is only unique in GROUP_SOBJ, and changes after refresh.
 */
static lt_sobj_t *
lookup_sobj(lt_sobj_id_t *id)
{
	const char *stype_str[] = {
		"None",
		"Mutex",
		"RWLock",
		"CV",
		"Sema",
		"User",
		"User_PI",
		"Shuttle"
	};
	const int stype_str_len =
	    sizeof (stype_str) / sizeof (stype_str[0]);
	lt_sobj_t *ret = NULL;

	g_assert(id != NULL);
	if (id->sobj_type < 0 || id->sobj_type >= stype_str_len) {
		return (NULL);
	}

	if (sobj_table != NULL) {
		ret = (lt_sobj_t *)g_hash_table_lookup(sobj_table, id);
	} else {
		sobj_table = g_hash_table_new_full(
		    (GHashFunc)sobj_id_hash, (GEqualFunc)sobj_id_equal,
		    NULL, (GDestroyNotify)free);
		lt_check_null(sobj_table);
	}

	if (ret == NULL) {
		ret = (lt_sobj_t *)lt_zalloc(sizeof (lt_sobj_t));
		ret->cause_id = ++sobj_table_len;
		(void) snprintf(ret->string, sizeof (ret->string),
		    "%s: 0x%llX", stype_str[id->sobj_type], id->sobj_addr);
		ret->sobj_id.sobj_type = id->sobj_type;
		ret->sobj_id.sobj_addr = id->sobj_addr;

		g_hash_table_insert(sobj_table, &ret->sobj_id, ret);
	}

	return (ret);
}

/*
 * Check if a process is alive by looking at /proc/pid
 */
/* ARGSUSED */
static gboolean
check_process(gpointer key, lt_stat_collection_t *stat, void *user)
{
	char name[PATH_MAX];

	(void) snprintf(name, PATH_MAX, "/proc/%u", stat->id);
	/* Don't remove (return FALSE) if file exists */
	return (lt_file_exist(name) ? FALSE : TRUE);
}

/*
 * Check if a thread is alive by looking at /proc/pid/lwp/tid
 */
/* ARGSUSED */
static gboolean
check_thread(gpointer key, lt_stat_collection_t *stat, void *user)
{
	char name[PATH_MAX];

	g_assert(stat->parent != NULL);
	g_assert(stat->parent->level == LT_LEVEL_PROCESS);

	(void) snprintf(name, PATH_MAX, "/proc/%u/lwp/%u",
	    stat->parent->id, stat->id);
	/* Don't remove (return FALSE) if file exists */
	return (lt_file_exist(name) ? FALSE : TRUE);
}

/*
 * Helper function to free a stat node.
 */
static void
free_stat(lt_stat_collection_t *stat)
{
	int i;

	if (stat == NULL) {
		return;
	}

	for (i = 0; i < NGROUPS; ++i) {
		if (stat->groups[i].sctable != NULL) {
			g_hash_table_destroy(stat->groups[i].sctable);
		}
	}

	if (stat->children != NULL) {
		g_hash_table_destroy(stat->children);
	}

	if (stat->name != NULL) {
		free(stat->name);
	}

	free(stat);
}

/*
 * Helper function zeroing a stat node.
 */
/* ARGSUSED */
static void
clear_stat(gpointer key, lt_stat_collection_t *stat, void *user)
{
	int i;

	g_assert(stat != NULL);

	for (i = 0; i < NGROUPS; ++i) {
		if (stat->groups[i].sctable != NULL) {
			g_hash_table_destroy(stat->groups[i].sctable);
			stat->groups[i].sctable = NULL;
		}

		stat->groups[i].summary.data.count = 0;
		stat->groups[i].summary.data.total = 0;
		stat->groups[i].summary.data.max = 0;
	}

	if (stat->children != NULL) {
		g_hash_table_foreach_remove(stat->children,
		    (GHRFunc)stat->check_child_func, NULL);
		g_hash_table_foreach(stat->children,
		    (GHFunc)clear_stat, NULL);
	}
}

/*
 * Update a collection for the value given.
 * Recursively update its parent until it reaches the root.
 */
static void
update_stat_entry(lt_stat_collection_t *stat, int cause_id,
		lt_stat_type_t type, uint64_t value,
		const char *string, int group_to_use)
{
	lt_stat_entry_t *entry = NULL;
	lt_datagroup_t *group;

	if (group_to_use < 0 || group_to_use >= NGROUPS) {
		return;
	}
	group = &(stat->groups[group_to_use]);

	if (group->sctable != NULL) {
		entry = (lt_stat_entry_t *)g_hash_table_lookup(
		    group->sctable, LT_INT_TO_POINTER(cause_id));
	} else   {
		group->sctable = g_hash_table_new_full(
		    g_direct_hash, g_direct_equal,
		    NULL, (GDestroyNotify)free);
		lt_check_null(group->sctable);
	}

	if (entry == NULL) {
		entry = (lt_stat_entry_t *)lt_zalloc(sizeof (lt_stat_entry_t));
		entry->string = string;

		switch (group_to_use) {
		case GROUP_CAUSE:
			entry->type = STAT_CAUSE;
			entry->type_data.cause.id = cause_id;
			entry->type_data.cause.flags =
			    lt_table_get_cause_flag(cause_id, CAUSE_ALL_FLAGS);
			/* hide the first '#' */
			if ((entry->type_data.cause.flags
			    & CAUSE_FLAG_HIDE_IN_SUMMARY) != 0) {
				++entry->string;
			}
			break;
		case GROUP_SOBJ:
			entry->type = STAT_SOBJ;
			entry->type_data.sobj.id = cause_id;
			break;
		}

		g_hash_table_insert(group->sctable, LT_INT_TO_POINTER(cause_id),
		    entry);
	}

	lt_update_stat_value(&entry->data, type, value);

	if (group_to_use == GROUP_SOBJ ||
	    (entry->type_data.cause.flags & CAUSE_FLAG_HIDE_IN_SUMMARY) == 0) {
		lt_update_stat_value(&group->summary.data, type, value);
	}

	if (stat->parent != NULL) {
		update_stat_entry(stat->parent, cause_id, type, value,
		    string, group_to_use);
	}
}

/*
 * Identify the cause from a stack trace.
 * Returns the cause_id.
 */
static int
find_cause(char *stack)
{
	int cause_temp;
	int prio_temp;
	int cause = INVALID_CAUSE;
	int priority = 0;
	int found = 0;

	while (stack != NULL) {
		char *sep;
		sep = strchr(stack, ' ');
		if (sep != NULL) {
			*sep = 0;
		}

		found = lt_table_lookup_cause(stack, &cause_temp, &prio_temp);
		if (found && (cause == INVALID_CAUSE ||
		    HIGHER_PRIORITY(prio_temp, priority))) {
			cause = cause_temp;
			priority = prio_temp;
		}

		if (sep != NULL) {
			*sep = ' ';
			stack = sep + 1;
		} else   {
			stack = NULL;
		}
	}
	return (cause);
}

/*
 * Create a new collection, hook it to the parent.
 */
static lt_stat_collection_t *
new_collection(lt_stat_level_t level, unsigned int id, char *name,
    lt_stat_collection_t *parent, check_child_func_t check_child_func)
{
	int i;
	lt_stat_collection_t *ret;

	ret = (lt_stat_collection_t *)
	    lt_zalloc(sizeof (lt_stat_collection_t));

	ret->level = level;
	ret->check_child_func = check_child_func;
	ret->id = id;
	ret->name = name;

	for (i = 0; i < NGROUPS; ++i) {
		ret->groups[i].summary.string = (const char *)name;
	}

	if (parent != NULL) {
		ret->parent = parent;
		if (parent->children == NULL) {
			parent->children = g_hash_table_new_full(
			    g_direct_hash, g_direct_equal,
			    NULL, (GDestroyNotify)free_stat);
			lt_check_null(parent->children);
		}
		g_hash_table_insert(parent->children,
		    LT_INT_TO_POINTER((int)id), ret);
	}

	return (ret);
}

/*
 * Finds the "leaf" collection, use given pid and tid.
 */
static lt_stat_collection_t *
get_stat_c(pid_t pid, id_t tid)
{
	lt_stat_collection_t *stat_p = NULL;
	lt_stat_collection_t *stat_t = NULL;

	if (stat_system == NULL) {
		stat_system = new_collection(LT_LEVEL_GLOBAL,
		    PID_SYS_GLOBAL, lt_strdup("SYSTEM"), NULL, check_process);
	} else if (stat_system->children != NULL) {
		stat_p = (lt_stat_collection_t *)
		    g_hash_table_lookup(stat_system->children,
		    LT_INT_TO_POINTER(pid));
	}

	if (stat_p == NULL) {
		char *fname;

		fname = lt_get_proc_field(pid, LT_FIELD_FNAME);
		if (fname == NULL) {
			/*
			 * we cannot get process execname,
			 * process is probably already dead.
			 */
			return (NULL);
		}

		stat_p = new_collection(LT_LEVEL_PROCESS,
		    (unsigned int)pid, fname, stat_system, check_thread);
	} else if (stat_p->children != NULL) {
		stat_t = (lt_stat_collection_t *)
		    g_hash_table_lookup(stat_p->children,
		    LT_INT_TO_POINTER(tid));
	}

	if (stat_t == NULL) {
		const int tname_size = 16; /* Enough for "Thread %d" */
		char *tname;

		tname = (char *)lt_malloc(tname_size);
		(void) snprintf(tname, tname_size, "Thread %d", tid);

		stat_t = new_collection(LT_LEVEL_THREAD,
		    (unsigned int)tid, tname, stat_p, NULL);
	}

	return (stat_t);
}

/*
 * Update the statistics given cause_id directly. Value will be added to
 * internal statistics.
 */
void
lt_stat_update_cause(pid_t pid, id_t tid, int cause_id, lt_stat_type_t type,
    uint64_t value)
{
	const char *string;
	lt_stat_collection_t *stat_t = NULL;

	if (cause_id < 0 || value == 0) {
		return;
	}

	if (lt_table_get_cause_flag(cause_id, CAUSE_FLAG_DISABLED)) {
		/* we don't care about this cause, ignore. */
		return;
	}

	stat_t = get_stat_c(pid, tid);
	if (stat_t == NULL) {
		/* cannot get fname, process must be dead. */
		return;
	}

	string = lt_table_get_cause_name(cause_id);

	update_stat_entry(stat_t, cause_id, type, value, string, GROUP_CAUSE);
}

/*
 * Update the statistics given the stack trace.
 * Internally it will be mapped to a cause using lt_table_lookup_cause(),
 * and call lt_stat_update_cause().
 */
void
lt_stat_update(pid_t pid, id_t tid, char *stack, lt_stat_type_t type,
    uint64_t value)
{
	int cause_id = INVALID_CAUSE;

	if (value == 0) {
		return;
	}

	cause_id = find_cause(stack);
	if (cause_id == INVALID_CAUSE) {
		cause_id = lt_table_lookup_named_cause(stack, 1);
		lt_klog_log(LT_KLOG_LEVEL_UNMAPPED, pid, stack, type, value);
	} else   {
		lt_klog_log(LT_KLOG_LEVEL_MAPPED, pid, stack, type, value);
	}

	lt_stat_update_cause(pid, tid, cause_id, type, value);
}

/*
 * Zero all statistics, but keep the data structure in memory
 * to be filled with new data immediately after.
 */
void
lt_stat_clear_all(void)
{
	if (stat_system != NULL) {
		clear_stat(NULL, stat_system, NULL);
	}

	if (sobj_table != NULL) {
		g_hash_table_destroy(sobj_table);
		sobj_table = NULL;
	}
}

/*
 * Clean up function that frees all memory used by statistics.
 */
void
lt_stat_free_all(void)
{
	if (stat_system != NULL) {
		free_stat(stat_system);
		stat_system = NULL;
	}

	if (sobj_table != NULL) {
		g_hash_table_destroy(sobj_table);
		sobj_table = NULL;
	}
}

/*
 * Get top N causes of latency for a process. Returns handle to a stat_list.
 * Use pid = PID_SYS_GLOBAL to get global top list.
 * Call lt_stat_list_free after use.
 */
void *
lt_stat_list_create(lt_list_type_t list_type, lt_stat_level_t level,
    pid_t pid, id_t tid, int count, lt_sort_t sort_by)
{
	GCompareFunc func;
	GList *list, *walk;
	lt_stat_collection_t *stat_c = NULL;
	lt_stat_list_t *ret;
	lt_datagroup_t *group;

	if (level == LT_LEVEL_GLOBAL) {
		/* Use global entry */
		stat_c = stat_system;
	} else if (stat_system != NULL && stat_system->children != NULL) {
		/* Find process entry first */
		stat_c = (lt_stat_collection_t *)g_hash_table_lookup(
		    stat_system->children, LT_INT_TO_POINTER(pid));

		if (level == LT_LEVEL_THREAD) {
			/*
			 * If we request thread entry, find it based on
			 * process entry.
			 */
			if (stat_c != NULL && stat_c->children != NULL) {
				stat_c = (lt_stat_collection_t *)
				    g_hash_table_lookup(stat_c->children,
				    LT_INT_TO_POINTER(tid));
			} else	{
				/*
				 * Couldn't find thread entry, set it to NULL
				 * so we will return empty list later.
				 */
				stat_c = NULL;
			}
		}
	}

	ret = (lt_stat_list_t *)lt_zalloc(sizeof (lt_stat_list_t));
	ret->entries = (lt_stat_entry_t **)
	    lt_zalloc(count * sizeof (lt_stat_entry_t *));

	if (stat_c == NULL) {
		/* empty list */
		return (ret);
	}

	if (list_type == LT_LIST_SOBJ) {
		group = &(stat_c->groups[GROUP_SOBJ]);
	} else {
		group = &(stat_c->groups[GROUP_CAUSE]);
	}

	if (group->sctable == NULL) {
		/* empty list */
		return (ret);
	}

	ret->gtotal = group->summary.data.total;

	list = g_hash_table_get_values(group->sctable);

	switch (sort_by) {
	case LT_SORT_TOTAL:
		func = (GCompareFunc)lt_sort_by_total_desc;
		break;
	case LT_SORT_MAX:
		func = (GCompareFunc)lt_sort_by_max_desc;
		break;
	case LT_SORT_AVG:
		func = (GCompareFunc)lt_sort_by_avg_desc;
		break;
	case LT_SORT_COUNT:
		func = (GCompareFunc)lt_sort_by_count_desc;
		break;
	}
	list = g_list_sort(list, func);

	for (walk = list;
	    walk != NULL && count > 0;
	    walk = g_list_next(walk), --count) {
		lt_stat_entry_t *data = (lt_stat_entry_t *)walk->data;

		if (list_type == LT_LIST_CAUSE &&
		    data->type == STAT_CAUSE &&
		    (data->type_data.cause.flags & CAUSE_FLAG_HIDE_IN_SUMMARY)
		    != 0) {
			continue;
		}
		if (list_type == LT_LIST_SPECIALS &&
		    data->type == STAT_CAUSE &&
		    (data->type_data.cause.flags & CAUSE_FLAG_SPECIAL)
		    == 0) {
			continue;
		}
		if (data->data.count == 0) {
			break;
		}
		ret->entries[ret->entry_count++] = data;
	}

	g_list_free(list);

	return (ret);
}

/*
 * Free memory allocated by lt_stat_list_create().
 */
void
lt_stat_list_free(void *ptr)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL) {
		return;
	}

	if (list->free_func != NULL) {
		list->free_func(list);
	}

	if (list->entries != NULL) {
		free(list->entries);
	}

	free(list);
}

/*
 * Check if the list has item number i.
 */
int
lt_stat_list_has_item(void *ptr, int i)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL || i < 0 || i >= list->entry_count ||
	    list->entries[i] == NULL) {
		return (0);
	}
	return (1);
}

/*
 * Get the display name of item number i in the list.
 */
const char *
lt_stat_list_get_reason(void *ptr, int i)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;
	if (list == NULL || i < 0 || i >= list->entry_count ||
	    list->entries[i] == NULL) {
		return (NULL);
	}

	g_assert(list->entries[i]->string != NULL);

	return (list->entries[i]->string);
}

/*
 * Get the max. of item number i in the list.
 */
uint64_t
lt_stat_list_get_max(void *ptr, int i)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL || i < 0 || i >= list->entry_count ||
	    list->entries[i] == NULL) {
		return (0);
	}

	return (list->entries[i]->data.max);
}

/*
 * Get the total of item number i in the list.
 */
uint64_t
lt_stat_list_get_sum(void *ptr, int i)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL || i < 0 || i >= list->entry_count ||
	    list->entries[i] == NULL) {
		return (0);
	}

	return (list->entries[i]->data.total);
}

/*
 * Get the count of item number i in the list.
 */
uint64_t
lt_stat_list_get_count(void *ptr, int i)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL || i < 0 || i >= list->entry_count ||
	    list->entries[i] == NULL) {
		return (0);
	}

	return (list->entries[i]->data.count);
}

/*
 * Get grand total of all latencies in the pid where the list is drawn.
 */
uint64_t
lt_stat_list_get_gtotal(void *ptr)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL) {
		return (0);
	}
	return (list->gtotal);
}

/*
 * ============================================================================
 * Process and thread list.
 * They share a lot of static variables as stat part does,
 * so put them in the same file.
 */

/*
 * Helper function, sort by PID/TID ascend.
 */
static int
sort_id(lt_stat_collection_t *a, lt_stat_collection_t *b)
{
	return ((int)(a->id - b->id));
}

/*
 * Get current list of processes. Call lt_stat_proc_list_free after use.
 */
static int
plist_create(pid_t ** list)
{
	GList *pid_list, *walk;
	int ret, count;

	ret = g_hash_table_size(stat_system->children);
	*list = (pid_t *)lt_malloc(sizeof (pid_t) * ret);

	pid_list = g_hash_table_get_values(stat_system->children);
	pid_list = g_list_sort(pid_list, (GCompareFunc)sort_id);

	for (walk = pid_list, count = 0;
	    walk != NULL && count < ret;
	    walk = g_list_next(walk), ++count) {
		(*list)[count] = (int)
		    ((lt_stat_collection_t *)(walk->data))->id;
	}

	g_list_free(pid_list);

	return (ret);
}

/*
 * Count how many threads are found so far in a process.
 * Only thread caused SSLEEP will be found.
 */
/* ARGSUSED */
static void
count_threads(gpointer key, lt_stat_collection_t *stat_c, int *ret)
{
	g_assert(ret != NULL);

	if (stat_c->children != NULL) {
		*ret += g_hash_table_size(stat_c->children);
	}
}

/*
 * Get current list of processes+threads.
 * Call lt_stat_proc_list_free after use.
 */
static int
tlist_create(pid_t ** plist, id_t ** tlist)
{
	GList *pid_list, *walk_p;
	GList *tid_list, *walk_t;
	int ret = 0;
	int count = 0;

	g_hash_table_foreach(stat_system->children,
	    (GHFunc)count_threads, &ret);

	*plist = (pid_t *)lt_malloc(sizeof (pid_t) * ret);
	*tlist = (id_t *)lt_malloc(sizeof (id_t) * ret);

	pid_list = g_hash_table_get_values(stat_system->children);
	pid_list = g_list_sort(pid_list, (GCompareFunc)sort_id);

	for (walk_p = pid_list; walk_p != NULL;
	    walk_p = g_list_next(walk_p)) {
		lt_stat_collection_t *stat_p =
		    (lt_stat_collection_t *)walk_p->data;

		if (stat_p->children == NULL) {
			continue;
		}

		tid_list = g_hash_table_get_values(stat_p->children);
		tid_list = g_list_sort(tid_list, (GCompareFunc)sort_id);

		for (walk_t = tid_list; walk_t != NULL;
		    walk_t = g_list_next(walk_t)) {
			lt_stat_collection_t *stat_t =
			    (lt_stat_collection_t *)walk_t->data;

			(*plist)[count] = (int)stat_p->id;
			(*tlist)[count] = (int)stat_t->id;

			++count;
		}
		g_list_free(tid_list);
	}

	g_list_free(pid_list);
	g_assert(count == ret);

	return (ret);
}

/*
 * List processes that have been processed in LatencyTOP.
 */
int
lt_stat_proc_list_create(pid_t ** plist, id_t ** tlist)
{
	if (plist == NULL) {
		return (-1);
	}

	if (stat_system == NULL || stat_system->children == NULL) {
		*plist = NULL;

		if (tlist != NULL) {
			*tlist = NULL;
		}

		return (0);
	}

	if (tlist == NULL) {
		return (plist_create(plist));
	} else	{
		return (tlist_create(plist, tlist));
	}
}

/*
 * Free memory allocated by lt_stat_proc_list_create().
 */
void
lt_stat_proc_list_free(pid_t *plist, id_t *tlist)
{
	if (plist != NULL) {
		free(plist);
	}

	if (tlist != NULL) {
		free(tlist);
	}
}

/*
 * Get execname of a PID.
 */
const char *
lt_stat_proc_get_name(pid_t pid)
{
	lt_stat_collection_t *stat_p = NULL;

	if (stat_system == NULL || stat_system->children == NULL) {
		return (NULL);
	}

	stat_p = (lt_stat_collection_t *)
	    g_hash_table_lookup(stat_system->children, LT_INT_TO_POINTER(pid));

	if (stat_p != NULL) {
		return (stat_p->name);
	} else   {
		return (NULL);
	}
}

/*
 * Get number of threads.
 */
int
lt_stat_proc_get_nthreads(pid_t pid)
{
	lt_stat_collection_t *stat_p = NULL;

	if (stat_system == NULL || stat_system->children == NULL) {
		return (0);
	}

	stat_p = (lt_stat_collection_t *)
	    g_hash_table_lookup(stat_system->children, LT_INT_TO_POINTER(pid));

	if (stat_p != NULL) {
		return (g_hash_table_size(stat_p->children));
	} else   {
		return (0);
	}
}

/*
 * Update the statistics for synchronization objects.
 */
void
lt_stat_update_sobj(pid_t pid, id_t tid, int stype,
    unsigned long long wchan,
    lt_stat_type_t type, uint64_t value)
{
	lt_sobj_id_t id;
	lt_sobj_t *sobj;
	int cause_id;
	lt_stat_collection_t *stat_t = NULL;

	stat_t = get_stat_c(pid, tid);
	if (stat_t == NULL) {
		return;
	}

	id.sobj_type = stype;
	id.sobj_addr = wchan;
	sobj = lookup_sobj(&id);
	if (sobj == NULL) {
		return;
	}

	cause_id = sobj->cause_id;

	update_stat_entry(stat_t, cause_id, type, value,
	    sobj->string, GROUP_SOBJ);
}
