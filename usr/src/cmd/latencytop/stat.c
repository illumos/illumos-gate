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
	lt_stat_entry_t lt_grp_summary;
	/* cause_id -> stat entry */
	GHashTable *lt_grp_cidlist;
} lt_datagroup_t;

#define	NGROUPS			2
#define	GROUP_CAUSE		0
#define	GROUP_SOBJ		1

/*
 * A data collection hierarchy involving three entities - system, process
 * and thread. The hierarchic relationship is as follows :
 *
 *		1 system -> 1 or more processes -> 1 or more threads
 */
struct _lt_stat_collection {
	lt_stat_level_t lt_sc_level;
	unsigned int lt_sc_id;
	char *lt_sc_name;
	lt_datagroup_t lt_sc_groups[NGROUPS];
	/*
	 * The following fields: lt_sc_parent, lt_sc_children and
	 * lt_sc_check_child_func maintain the tree structure.
	 */
	lt_stat_collection_t *lt_sc_parent;		/* Parent node */
	GHashTable *lt_sc_children;	/* pid/tid -> lt_stat_collection_t */
	check_child_func_t lt_sc_check_child_func; /* Release dead children */
};

/* Internal data structure to back up a stat_list */
typedef struct _lt_stat_list lt_stat_list_t;
typedef void (*free_list_func_t)(lt_stat_list_t *);
struct _lt_stat_list {
	int lt_sl_entry_count;
	lt_stat_entry_t **lt_sl_entries;
	uint64_t lt_sl_gtotal;
	free_list_func_t lt_sl_free_func;
};

/* Root of the collection hierarchy: system level statistics */
static lt_stat_collection_t *stat_system = NULL;

/*
 * Data structure to hold synchronization objects.
 * We don't use normal "cause table" because this needs to be cleared
 * every time we refresh in order to make sure that stale synchronization
 * objects don't consume memory.
 */
typedef struct {
	int lt_soi_type;
	unsigned long long lt_soi_addr;
} lt_sobj_id_t;

typedef struct {
	lt_sobj_id_t lt_so_oid;
	int lt_so_cause_id;
	char lt_so_string[32];	/* Enough to hold "%s: 0x%llX" */
} lt_sobj_t;

static GHashTable *sobj_table = NULL;
static int sobj_table_len = 0;

/*
 * Lower 32-bit of the address of synchronization objects is used to hash
 * them.
 */
static guint
sobj_id_hash(lt_sobj_id_t *id)
{
	g_assert(id != NULL);
	return (id->lt_soi_addr & 0xFFFFFFFF);
}

/*
 * Test if two synchronization objects are the same.
 */
static gboolean
sobj_id_equal(lt_sobj_id_t *a, lt_sobj_id_t *b)
{
	g_assert(a != NULL && b != NULL);
	return (a->lt_soi_type == b->lt_soi_type &&
	    a->lt_soi_addr == b->lt_soi_addr);
}

/*
 * Look up the cause_id of a synchronization object.
 * Note that this cause_id is only unique in GROUP_SOBJ, and changes after
 * a refresh.
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

	if (id->lt_soi_type < 0 || id->lt_soi_type >= stype_str_len) {
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
		ret->lt_so_cause_id = ++sobj_table_len;
		(void) snprintf(ret->lt_so_string, sizeof (ret->lt_so_string),
		    "%s: 0x%llX", stype_str[id->lt_soi_type], id->lt_soi_addr);
		ret->lt_so_oid.lt_soi_type = id->lt_soi_type;
		ret->lt_so_oid.lt_soi_addr = id->lt_soi_addr;

		g_hash_table_insert(sobj_table, &ret->lt_so_oid, ret);
	}

	return (ret);
}

/*
 * Check if a process exists by using /proc/pid
 */
/* ARGSUSED */
static gboolean
check_process(gpointer key, lt_stat_collection_t *stat, void *user)
{
	char name[PATH_MAX];

	(void) snprintf(name, PATH_MAX, "/proc/%u", stat->lt_sc_id);
	return (lt_file_exist(name) ? FALSE : TRUE);
}

/*
 * Check if a thread exists by using /proc/pid/lwp/tid
 */
/* ARGSUSED */
static gboolean
check_thread(gpointer key, lt_stat_collection_t *stat, void *user)
{
	char name[PATH_MAX];

	g_assert(stat->lt_sc_parent != NULL);
	g_assert(stat->lt_sc_parent->lt_sc_level == LT_LEVEL_PROCESS);

	(void) snprintf(name, PATH_MAX, "/proc/%u/lwp/%u",
	    stat->lt_sc_parent->lt_sc_id, stat->lt_sc_id);
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
		if (stat->lt_sc_groups[i].lt_grp_cidlist != NULL) {
			g_hash_table_destroy(stat->lt_sc_groups[i].
			    lt_grp_cidlist);
		}
	}

	if (stat->lt_sc_children != NULL) {
		g_hash_table_destroy(stat->lt_sc_children);
	}

	if (stat->lt_sc_name != NULL) {
		free(stat->lt_sc_name);
	}

	free(stat);
}

/*
 * Helper function to initialize a stat node.
 */
/* ARGSUSED */
static void
clear_stat(gpointer key, lt_stat_collection_t *stat, void *user)
{
	int i;

	g_assert(stat != NULL);

	for (i = 0; i < NGROUPS; ++i) {
		if (stat->lt_sc_groups[i].lt_grp_cidlist != NULL) {
			g_hash_table_destroy(stat->lt_sc_groups[i].
			    lt_grp_cidlist);
			stat->lt_sc_groups[i].lt_grp_cidlist = NULL;
		}

		stat->lt_sc_groups[i].lt_grp_summary.lt_se_data.lt_s_count = 0;
		stat->lt_sc_groups[i].lt_grp_summary.lt_se_data.lt_s_total = 0;
		stat->lt_sc_groups[i].lt_grp_summary.lt_se_data.lt_s_max = 0;
	}

	if (stat->lt_sc_children != NULL) {
		g_hash_table_foreach_remove(stat->lt_sc_children,
		    (GHRFunc)stat->lt_sc_check_child_func, NULL);
		g_hash_table_foreach(stat->lt_sc_children,
		    (GHFunc)clear_stat, NULL);
	}
}

/*
 * Update a collection with the given value.
 * Recursively update parents in the hierarchy  until the root is reached.
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

	group = &(stat->lt_sc_groups[group_to_use]);

	if (group->lt_grp_cidlist != NULL) {
		entry = (lt_stat_entry_t *)g_hash_table_lookup(
		    group->lt_grp_cidlist, LT_INT_TO_POINTER(cause_id));
	} else   {
		group->lt_grp_cidlist = g_hash_table_new_full(
		    g_direct_hash, g_direct_equal,
		    NULL, (GDestroyNotify)free);
		lt_check_null(group->lt_grp_cidlist);
	}

	if (entry == NULL) {
		entry = (lt_stat_entry_t *)lt_zalloc(sizeof (lt_stat_entry_t));
		entry->lt_se_string = string;

		switch (group_to_use) {
		case GROUP_CAUSE:
			entry->lt_se_type = STAT_CAUSE;
			entry->lt_se_tsdata.lt_se_t_cause.lt_se_c_id = cause_id;
			entry->lt_se_tsdata.lt_se_t_cause.lt_se_c_flags =
			    lt_table_get_cause_flag(cause_id, CAUSE_ALL_FLAGS);

			/* hide the first '#' */
			if ((entry->lt_se_tsdata.lt_se_t_cause.lt_se_c_flags
			    & CAUSE_FLAG_HIDE_IN_SUMMARY) != 0) {
				++entry->lt_se_string;
			}

			break;
		case GROUP_SOBJ:
			entry->lt_se_type = STAT_SOBJ;
			entry->lt_se_tsdata.lt_se_t_sobj.lt_se_s_id = cause_id;
			break;
		}

		g_hash_table_insert(group->lt_grp_cidlist,
		    LT_INT_TO_POINTER(cause_id), entry);
	}

	lt_update_stat_value(&entry->lt_se_data, type, value);

	if (group_to_use == GROUP_SOBJ ||
	    (entry->lt_se_tsdata.lt_se_t_cause.lt_se_c_flags &
	    CAUSE_FLAG_HIDE_IN_SUMMARY) == 0) {
		lt_update_stat_value(&group->lt_grp_summary.lt_se_data, type,
		    value);
	}

	if (stat->lt_sc_parent != NULL) {
		update_stat_entry(stat->lt_sc_parent, cause_id, type, value,
		    string, group_to_use);
	}
}

/*
 * Identify the cause of latency from the given stack trace.
 * Return cause_id.
 */
static void
find_cause(char *stack, int *cause_id, int *cause_priority)
{
	int cause_temp;
	int prio_temp;
	int cause = INVALID_CAUSE;
	int priority = 0;
	int found = 0;

	g_assert(cause_id != NULL);
	g_assert(cause_priority != NULL);

	while (stack != NULL) {
		char *sep;
		sep = strchr(stack, ' ');

		if (sep != NULL) {
			*sep = '\0';
		}

		found = lt_table_cause_from_stack(stack, &cause_temp,
		    &prio_temp);

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

	*cause_id = cause;
	*cause_priority = priority;
}

/*
 * Create a new collection and hook it to the parent.
 */
static lt_stat_collection_t *
new_collection(lt_stat_level_t level, unsigned int id, char *name,
    lt_stat_collection_t *parent, check_child_func_t check_child_func)
{
	int i;
	lt_stat_collection_t *ret;

	ret = (lt_stat_collection_t *)
	    lt_zalloc(sizeof (lt_stat_collection_t));

	ret->lt_sc_level = level;
	ret->lt_sc_check_child_func = check_child_func;
	ret->lt_sc_id = id;
	ret->lt_sc_name = name;

	for (i = 0; i < NGROUPS; ++i) {
		ret->lt_sc_groups[i].lt_grp_summary.lt_se_string =
		    (const char *)name;
	}

	if (parent != NULL) {
		ret->lt_sc_parent = parent;

		if (parent->lt_sc_children == NULL) {
			parent->lt_sc_children = g_hash_table_new_full(
			    g_direct_hash, g_direct_equal,
			    NULL, (GDestroyNotify)free_stat);
			lt_check_null(parent->lt_sc_children);
		}

		g_hash_table_insert(parent->lt_sc_children,
		    LT_INT_TO_POINTER((int)id), ret);
	}

	return (ret);
}

/*
 * Find the "leaf" in the collection hierarchy, using the given pid and tid.
 */
static lt_stat_collection_t *
get_stat_c(pid_t pid, id_t tid)
{
	lt_stat_collection_t *stat_p = NULL;
	lt_stat_collection_t *stat_t = NULL;

	if (stat_system == NULL) {
		stat_system = new_collection(LT_LEVEL_GLOBAL,
		    PID_SYS_GLOBAL, lt_strdup("SYSTEM"), NULL, check_process);
	} else if (stat_system->lt_sc_children != NULL) {
		stat_p = (lt_stat_collection_t *)
		    g_hash_table_lookup(stat_system->lt_sc_children,
		    LT_INT_TO_POINTER(pid));
	}

	if (stat_p == NULL) {
		char *fname;
		fname = lt_get_proc_field(pid, LT_FIELD_FNAME);

		if (fname == NULL) {
			/*
			 * we could not get the executable name of the
			 * process; the process is probably already dead.
			 */
			return (NULL);
		}

		stat_p = new_collection(LT_LEVEL_PROCESS,
		    (unsigned int)pid, fname, stat_system, check_thread);
	} else if (stat_p->lt_sc_children != NULL) {
		stat_t = (lt_stat_collection_t *)
		    g_hash_table_lookup(stat_p->lt_sc_children,
		    LT_INT_TO_POINTER(tid));
	}

	if (stat_t == NULL) {
		const int tname_size = 16; /* Enough for "Thread %d" */
		char *tname;

		tname = (char *)lt_zalloc(tname_size);
		(void) snprintf(tname, tname_size, "Thread %d", tid);

		stat_t = new_collection(LT_LEVEL_THREAD,
		    (unsigned int)tid, tname, stat_p, NULL);
	}

	return (stat_t);
}

/*
 * Update statistics with the given cause_id. Values will be added to
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
		/* Ignore this cause */
		return;
	}

	stat_t = get_stat_c(pid, tid);

	if (stat_t == NULL) {
		/* Process must be dead. */
		return;
	}

	string = lt_table_get_cause_name(cause_id);

	update_stat_entry(stat_t, cause_id, type, value, string, GROUP_CAUSE);
}

/*
 * Update statistics with the given stack trace.
 * The stack trace is mapped to a cause and lt_stat_update_cause() is called
 * to update statistics.
 */
void
lt_stat_update(pid_t pid, id_t tid, char *stack, char *tag,
    unsigned int tag_priority, lt_stat_type_t type, uint64_t value)
{
	int tag_cause_id = INVALID_CAUSE;
	int stack_cause_id = INVALID_CAUSE;
	int cause_id = INVALID_CAUSE;
	int stack_priority = 0;

	if (value == 0) {
		return;
	}

	find_cause(stack, &stack_cause_id, &stack_priority);

	if (tag_priority != 0) {
		tag_cause_id = lt_table_cause_from_name(tag, 0, 0);

		if (tag_cause_id == INVALID_CAUSE) {
			/* This must be a syscall tag */
			char tmp[64];
			(void) snprintf(tmp, sizeof (tmp), "Syscall: %s", tag);
			tag_cause_id = lt_table_cause_from_name(tmp, 1, 0);
		}
	}

	cause_id = (tag_priority > stack_priority) ? tag_cause_id :
	    stack_cause_id;

	if (cause_id == INVALID_CAUSE) {
		/*
		 * We got an unmapped stack. Set SPECIAL flag to display it
		 * in pane 2. This makes it easier to find the cause.
		 */
		cause_id = lt_table_cause_from_name(stack, 1,
		    CAUSE_FLAG_SPECIAL);
		lt_klog_log(LT_KLOG_LEVEL_UNMAPPED, pid, stack, type, value);
	} else   {
		lt_klog_log(LT_KLOG_LEVEL_MAPPED, pid, stack, type, value);
	}

	lt_stat_update_cause(pid, tid, cause_id, type, value);
}

/*
 * Zero out all statistics, but keep the data structures in memory
 * to be used to hold new data immediately following.
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
 * Clean up function that frees all memory used for statistics.
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
 * Get top N causes of latency for a process. Return handle to a stat_list.
 * Use pid = PID_SYS_GLOBAL to get global top list.
 * Call lt_stat_list_free after use to clean up.
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
	} else if (stat_system != NULL && stat_system->lt_sc_children != NULL) {
		/* Find process entry first */
		stat_c = (lt_stat_collection_t *)g_hash_table_lookup(
		    stat_system->lt_sc_children, LT_INT_TO_POINTER(pid));

		if (level == LT_LEVEL_THREAD) {
			/*
			 * If thread entry is requested, find it based on
			 * process entry.
			 */
			if (stat_c != NULL && stat_c->lt_sc_children != NULL) {
				stat_c = (lt_stat_collection_t *)
				    g_hash_table_lookup(stat_c->lt_sc_children,
				    LT_INT_TO_POINTER(tid));
			} else {
				/*
				 * Thread entry was not found; set it to NULL,
				 * so that we can return empty list later.
				 */
				stat_c = NULL;
			}
		}
	}

	ret = (lt_stat_list_t *)lt_zalloc(sizeof (lt_stat_list_t));
	ret->lt_sl_entries = (lt_stat_entry_t **)
	    lt_zalloc(count * sizeof (lt_stat_entry_t *));

	if (stat_c == NULL) {
		/* Empty list */
		return (ret);
	}

	if (list_type == LT_LIST_SOBJ) {
		group = &(stat_c->lt_sc_groups[GROUP_SOBJ]);
	} else {
		group = &(stat_c->lt_sc_groups[GROUP_CAUSE]);
	}

	if (group->lt_grp_cidlist == NULL) {
		/* Empty list */
		return (ret);
	}

	ret->lt_sl_gtotal = group->lt_grp_summary.lt_se_data.lt_s_total;

	list = g_hash_table_get_values(group->lt_grp_cidlist);

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
		    data->lt_se_type == STAT_CAUSE &&
		    (data->lt_se_tsdata.lt_se_t_cause.lt_se_c_flags &
		    CAUSE_FLAG_HIDE_IN_SUMMARY) != 0) {
			continue;
		}

		if (list_type == LT_LIST_SPECIALS &&
		    data->lt_se_type == STAT_CAUSE &&
		    (data->lt_se_tsdata.lt_se_t_cause.lt_se_c_flags &
		    CAUSE_FLAG_SPECIAL) == 0) {
			continue;
		}

		if (data->lt_se_data.lt_s_count == 0) {
			break;
		}

		ret->lt_sl_entries[ret->lt_sl_entry_count++] = data;
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

	if (list->lt_sl_free_func != NULL) {
		list->lt_sl_free_func(list);
	}

	if (list->lt_sl_entries != NULL) {
		free(list->lt_sl_entries);
	}

	free(list);
}

/*
 * Check if the given list contains the given item.
 */
int
lt_stat_list_has_item(void *ptr, int i)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL || i < 0 || i >= list->lt_sl_entry_count ||
	    list->lt_sl_entries[i] == NULL) {
		return (0);
	}

	return (1);
}

/*
 * Get display name of the given item i in the given list.
 */
const char *
lt_stat_list_get_reason(void *ptr, int i)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL || i < 0 || i >= list->lt_sl_entry_count ||
	    list->lt_sl_entries[i] == NULL) {
		return (NULL);
	}

	g_assert(list->lt_sl_entries[i]->lt_se_string != NULL);

	return (list->lt_sl_entries[i]->lt_se_string);
}

/*
 * Get maximum value of the given item i in the given list.
 */
uint64_t
lt_stat_list_get_max(void *ptr, int i)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL || i < 0 || i >= list->lt_sl_entry_count ||
	    list->lt_sl_entries[i] == NULL) {
		return (0);
	}

	return (list->lt_sl_entries[i]->lt_se_data.lt_s_max);
}

/*
 * Get total value of the given item i in the given list.
 */
uint64_t
lt_stat_list_get_sum(void *ptr, int i)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL || i < 0 || i >= list->lt_sl_entry_count ||
	    list->lt_sl_entries[i] == NULL) {
		return (0);
	}

	return (list->lt_sl_entries[i]->lt_se_data.lt_s_total);
}

/*
 * Get count value of the given item i in the given list.
 */
uint64_t
lt_stat_list_get_count(void *ptr, int i)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL || i < 0 || i >= list->lt_sl_entry_count ||
	    list->lt_sl_entries[i] == NULL) {
		return (0);
	}

	return (list->lt_sl_entries[i]->lt_se_data.lt_s_count);
}

/*
 * Get grand total of all latency in the list.
 */
uint64_t
lt_stat_list_get_gtotal(void *ptr)
{
	lt_stat_list_t *list = (lt_stat_list_t *)ptr;

	if (list == NULL) {
		return (0);
	}

	return (list->lt_sl_gtotal);
}

/*
 * ============================================================================
 * Process and thread list.
 * They share a lot of the static variables that are used for keeping
 * statistics, hence they are located in this file.
 */

/*
 * Helper function, sort by PID/TID ascend.
 */
static int
sort_id(lt_stat_collection_t *a, lt_stat_collection_t *b)
{
	return ((int)(a->lt_sc_id - b->lt_sc_id));
}

/*
 * Get the current list of processes. Call lt_stat_proc_list_free after use
 * to clean up.
 */
static int
plist_create(pid_t ** list)
{
	GList *pid_list, *walk;
	int ret, count;

	ret = g_hash_table_size(stat_system->lt_sc_children);
	*list = (pid_t *)lt_malloc(sizeof (pid_t) * ret);

	pid_list = g_hash_table_get_values(stat_system->lt_sc_children);
	pid_list = g_list_sort(pid_list, (GCompareFunc)sort_id);

	for (walk = pid_list, count = 0;
	    walk != NULL && count < ret;
	    walk = g_list_next(walk), ++count) {
		(*list)[count] = (int)
		    ((lt_stat_collection_t *)(walk->data))->lt_sc_id;
	}

	g_list_free(pid_list);

	return (ret);
}

/*
 * Count the no. of threads currently present in a process.
 * Only thread that have SSLEEP are counted.
 */
/* ARGSUSED */
static void
count_threads(gpointer key, lt_stat_collection_t *stat_c, int *ret)
{
	g_assert(ret != NULL);

	if (stat_c->lt_sc_children != NULL) {
		*ret += g_hash_table_size(stat_c->lt_sc_children);
	}
}

/*
 * Get current list of processes and threads.
 * Call lt_stat_proc_list_free after use to clean up.
 */
static int
tlist_create(pid_t ** plist, id_t ** tlist)
{
	GList *pid_list, *walk_p;
	GList *tid_list, *walk_t;
	int ret = 0;
	int count = 0;

	g_hash_table_foreach(stat_system->lt_sc_children,
	    (GHFunc)count_threads, &ret);

	*plist = (pid_t *)lt_malloc(sizeof (pid_t) * ret);
	*tlist = (id_t *)lt_malloc(sizeof (id_t) * ret);

	pid_list = g_hash_table_get_values(stat_system->lt_sc_children);
	pid_list = g_list_sort(pid_list, (GCompareFunc)sort_id);

	for (walk_p = pid_list; walk_p != NULL;
	    walk_p = g_list_next(walk_p)) {
		lt_stat_collection_t *stat_p =
		    (lt_stat_collection_t *)walk_p->data;

		if (stat_p->lt_sc_children == NULL) {
			continue;
		}

		tid_list = g_hash_table_get_values(stat_p->lt_sc_children);
		tid_list = g_list_sort(tid_list, (GCompareFunc)sort_id);

		for (walk_t = tid_list; walk_t != NULL;
		    walk_t = g_list_next(walk_t)) {
			lt_stat_collection_t *stat_t =
			    (lt_stat_collection_t *)walk_t->data;

			(*plist)[count] = (int)stat_p->lt_sc_id;
			(*tlist)[count] = (int)stat_t->lt_sc_id;

			++count;
		}
		g_list_free(tid_list);
	}

	g_list_free(pid_list);
	g_assert(count == ret);

	return (ret);
}

/*
 * List of processes that are tracked by LatencyTOP.
 */
int
lt_stat_proc_list_create(pid_t ** plist, id_t ** tlist)
{
	if (plist == NULL) {
		return (-1);
	}

	if (stat_system == NULL || stat_system->lt_sc_children == NULL) {
		*plist = NULL;

		if (tlist != NULL) {
			*tlist = NULL;
		}

		return (0);
	}

	if (tlist == NULL) {
		return (plist_create(plist));
	} else {
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
 * Get executable name of the given process (ID).
 */
const char *
lt_stat_proc_get_name(pid_t pid)
{
	lt_stat_collection_t *stat_p = NULL;

	if (stat_system == NULL || stat_system->lt_sc_children == NULL) {
		return (NULL);
	}

	stat_p = (lt_stat_collection_t *)g_hash_table_lookup(
	    stat_system->lt_sc_children, LT_INT_TO_POINTER(pid));

	if (stat_p != NULL) {
		return (stat_p->lt_sc_name);
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

	if (stat_system == NULL || stat_system->lt_sc_children == NULL) {
		return (0);
	}

	stat_p = (lt_stat_collection_t *)g_hash_table_lookup(
	    stat_system->lt_sc_children, LT_INT_TO_POINTER(pid));

	if (stat_p != NULL) {
		return (g_hash_table_size(stat_p->lt_sc_children));
	} else   {
		return (0);
	}
}

/*
 * Update statistics for synchronization objects.
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

	id.lt_soi_type = stype;
	id.lt_soi_addr = wchan;
	sobj = lookup_sobj(&id);

	if (sobj == NULL) {
		return;
	}

	cause_id = sobj->lt_so_cause_id;

	update_stat_entry(stat_t, cause_id, type, value,
	    sobj->lt_so_string, GROUP_SOBJ);
}
