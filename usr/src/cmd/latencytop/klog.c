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

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <procfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include "latencytop.h"

static GHashTable *proc_table = NULL; /* pid -> char * */
static GHashTable *klog_table = NULL; /* char * -> uint64_t total */
static char klog_filename[PATH_MAX] = DEFAULT_KLOG_FILE;
static int klog_level = LT_KLOG_LEVEL_NONE;

static void
print_proc(void *key, const char *args, FILE *fp)
{
	(void) fprintf(fp, "%-8ld \"%s\"\n", (long)key, args);
}

static void
print_stat(const char *key, lt_stat_data_t *log, FILE *fp)
{
	(void) fprintf(fp, "%lld, %lld, %lld, %s\n",
	    (long long)log->lt_s_total,
	    (long long)log->lt_s_count,
	    (long long)log->lt_s_max,
	    key);
}

/*
 * Initialization for kernel logging.
 */
void
lt_klog_init(void)
{
	if (klog_table != NULL || proc_table != NULL) {
		return;
	}

	klog_table = g_hash_table_new_full(g_str_hash, g_str_equal,
	    (GDestroyNotify)free, (GDestroyNotify)free);
	lt_check_null(klog_table);

	proc_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
	    NULL, (GDestroyNotify)free);
	lt_check_null(proc_table);
}

/*
 * Set log file path.
 */
int
lt_klog_set_log_file(const char *filename)
{
	FILE *fp;
	int file_exist;

	g_assert(strlen(filename) < sizeof (klog_filename));

	file_exist = lt_file_exist(filename);
	/* Test if we can write to the file */
	fp = fopen(filename, "a");

	if (fp == NULL) {
		return (-2);
	}

	(void) fclose(fp);
	/* Don't leave empty file around */
	if (!file_exist) {
		(void) unlink(filename);
	}

	(void) strncpy(klog_filename, filename,
	    sizeof (klog_filename));

	return (0);
}

/*
 * Set log level.
 */
int
lt_klog_set_log_level(int level)
{
	if (level < 0 || level > (int)LT_KLOG_LEVEL_ALL) {
		return (-1);
	}

	klog_level = level;

	return (0);
}

/*
 * Write content to log file.
 */
void
lt_klog_write(void)
{
	FILE *fp;
	char buffer[32];

	if (klog_level == LT_KLOG_LEVEL_NONE) {
		return;
	}

	g_assert(klog_table != NULL && proc_table != NULL);
	fp = fopen(klog_filename, "a");

	if (fp == NULL) {
		return;
	}

	lt_time_str(buffer, sizeof (buffer));

	(void) fprintf(fp, "# Log generated at %s by %s\n", buffer, TITLE);
	(void) fprintf(fp, "# List of processes\n");
	(void) fprintf(fp, "PID, CMD\n");
	g_hash_table_foreach(proc_table, (GHFunc)print_proc, fp);

	(void) fprintf(fp, "# Statistics\n");
	(void) fprintf(fp, "TOTAL, COUNT, MAX, PID, KSTACK\n");
	g_hash_table_foreach(klog_table, (GHFunc)print_stat, fp);

	(void) fclose(fp);
}

/*
 * Clean up. It flushes all log content in memory to log file.
 */
void
lt_klog_deinit(void)
{
	if (klog_table != NULL) {
		g_hash_table_destroy(klog_table);
		klog_table = NULL;
	}

	if (proc_table != NULL) {
		g_hash_table_destroy(proc_table);
		proc_table = NULL;
	}
}

/*
 * Write a kernel stack and its statistics to log file. Only "total" will
 * be logged, others are internally discarded.
 */
/* ARGSUSED */
void
lt_klog_log(int level, pid_t pid, char *stack,
    lt_stat_type_t type, uint64_t value)
{
	lt_stat_data_t *entry = NULL;
	char *psargs;
	char *str;
	int str_len;

	if ((level & klog_level) == 0) {
		return;
	}

	g_assert(klog_table != NULL && proc_table != NULL);
	psargs = (char *)g_hash_table_lookup(proc_table,
	    LT_INT_TO_POINTER(pid));

	if (psargs == NULL) {
		psargs = lt_get_proc_field(pid, LT_FIELD_PSARGS);

		if (psargs == NULL) {
			psargs = lt_get_proc_field(pid, LT_FIELD_FNAME);
		}

		if (psargs == NULL) {
			return;
		}

		g_hash_table_insert(proc_table,
		    LT_INT_TO_POINTER(pid), psargs);
	}

	str_len = strlen(stack) + 20;
	str = lt_malloc(str_len);
	(void) snprintf(str, str_len, "%ld, \"%s\"", pid, stack);
	entry = (lt_stat_data_t *)g_hash_table_lookup(klog_table, str);

	if (entry == NULL) {
		entry = (lt_stat_data_t *)lt_zalloc(sizeof (lt_stat_data_t));
		g_hash_table_insert(klog_table, str, entry);
	} else {
		free(str);
	}

	lt_update_stat_value(entry, type, value);
}
