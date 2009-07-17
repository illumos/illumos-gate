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
#include <string.h>
#include <memory.h>
#include <stdio.h>
#include <ctype.h>

#include "latencytop.h"

/*
 * Structure that holds detail of a cause.
 */
typedef struct {
	int cause_id;
	int flags;
	char *name;
} lt_cause_t;

/*
 * Structure that represents a matched cause.
 */
typedef struct  {
	int priority;
	int cause_id;
} lt_match_t;

/* All lt_cause_t that are created. */
static GPtrArray *causes_array = NULL;
static int causes_array_len = 0;
/*
 * This hash table maps a symbol to a cause entry.
 * key type is "char *" and value type is "lt_match_t *".
 */
static GHashTable *symbol_lookup_table = NULL;
/*
 * This hash table maps a cause name to an cause id.
 * Note only cause names that are found in D script is put in this table.
 * key type is "char *" and value type is "int" (which is cause_id).
 */
static GHashTable *named_causes = NULL;

/*
 * Help function to free one lt_cause_t structure.
 */
/* ARGSUSED */
static void
free_cause(lt_cause_t *cause, void *user)
{
	g_assert(cause != NULL && cause->name != NULL);

	free(cause->name);
	free(cause);
}

/*
 * Add a cause.
 * Note this function takes ownership of char *name.
 */
static lt_cause_t *
new_cause(char *name, int flags)
{
	lt_cause_t *entry;

	g_assert(name != NULL);

	entry = (lt_cause_t *)lt_malloc(sizeof (lt_cause_t));
	entry->flags = flags;
	entry->name = name;
	entry->cause_id = causes_array_len;

	g_ptr_array_add(causes_array, entry);
	++causes_array_len;

	return (entry);
}

/*
 * Set a cause to "disabled" state.
 */
static void
disable_cause(char *cause_str, GHashTable *cause_table)
{
	lt_cause_t *cause;

	cause = (lt_cause_t *)g_hash_table_lookup(cause_table, cause_str);
	if (cause != NULL) {
		cause->flags |= CAUSE_FLAG_DISABLED;
	}
}

/*
 * Helper functions that reads a line from a char * array.
 */
static int
read_line_from_mem(const char *mem, int mem_len, char *line, int line_len,
    int *index)
{
	g_assert(mem != NULL && line != NULL && index != NULL);

	if (line_len <= 0 || mem_len <= 0) {
		return (0);
	}
	if (*index >= mem_len) {
		return (0);
	}

	while (line_len > 1 && *index < mem_len) {
		*line = mem[(*index)++];
		--line_len;
		++line;
		if (*(line-1) == '\r' || *(line-1) == '\n') {
			break;
		}
	}
	*line = 0;

	return (1);
}

/*
 * The main loop that parses the translation rules one line at a time,
 * and construct latencytop lookup data structure from it.
 */
static int
parse_config(const char *work, int work_len)
{
	char line[256];
	int len;
	char *begin, *end, *tmp;
	int priority = 0;
	char *match;
	char *match_dup;
	char *cause_str;
	lt_cause_t *cause;
	lt_match_t *match_entry;
	int current = 0;
	GHashTable *cause_lookup;
	GSequence *cmd_disable;

	cause_lookup = g_hash_table_new(g_str_hash, g_str_equal);
	lt_check_null(cause_lookup);

	cmd_disable = g_sequence_new((GDestroyNotify)free);
	lt_check_null(cmd_disable);

	while (read_line_from_mem(work, work_len, line, sizeof (line),
	    &current)) {
		len = strlen(line);
		if (line[len-1] != '\n' && line[len-1] != '\r' &&
		    current < work_len) {
			lt_display_error("Configuration line too long.\n");
			goto err;
		}

		begin = line;
		while (isspace(*begin)) {
			++begin;
		}
		if (*begin == '\0') {
			/* empty line, ignore */
			continue;
		}

		/* Delete trailing spaces. */
		end = begin + strlen(begin) - 1;
		while (isspace(*end)) {
			--end;
		}
		end[1] = 0;

		if (*begin == '#') {
			continue;
		} else if (*begin == ';') {
			char old_chr = 0;
			/* special command */
			/* ; disable_cause  FSFlush Daemon  */
			/* ^ */
			++begin;

			while (isspace(*begin)) {
				++begin;
			}
			/* ; disable_cause  FSFlush Daemon  */
			/*   ^ */
			if (*begin == '\0') {
				continue;
			}

			for (tmp = begin;
			    *tmp != '\0' && !isspace(*tmp);
			    ++tmp) {
			}
			old_chr = *tmp;
			*tmp = 0;

			if (strcmp("disable_cause", begin) == 0) {
				if (old_chr == '\0') {
					/* Must have an argument */
					lt_display_error(
					    "Invalid command format: %s\n",
					    begin);
					goto err;
				}

				begin = tmp+1;
				while (isspace(*begin)) {
					++begin;
				}

				g_sequence_append(cmd_disable,
				    lt_strdup(begin));
			} else   {
				*tmp = old_chr;
				lt_display_error(
				    "Unknown command: %s\n", begin);
				goto err;
			}
			continue;
		}

		g_assert(*begin != '#' && *begin != ';');

		/* 10	genunix`indir			Syscall indir */
		/* ^ */
		priority = strtol(begin, &tmp, 10);
		if (tmp == begin || priority == 0) {
			lt_display_error(
			    "Invalid configuration line: %s\n", line);
			goto err;
		}
		begin = tmp;

		/* 10	genunix`indir			Syscall indir */
		/*   ^ */
		while (isspace(*begin)) {
			++begin;
		}
		if (*begin == 0) {
			lt_display_error(
			    "Invalid configuration line: %s\n", line);
			goto err;
		}

		/* 10	genunix`indir			Syscall indir */
		/* -----^ */
		for (tmp = begin;
		    *tmp != '\0' && !isspace(*tmp);
		    ++tmp) {
		}
		if (*tmp == '\0') {
			lt_display_error(
			    "Invalid configuration line: %s\n", line);
			goto err;
		}
		*tmp = 0;
		match = begin;

		/* Check if we have mapped this function before. */
		match_entry = (lt_match_t *)
		    g_hash_table_lookup(symbol_lookup_table, match);
		if (match_entry != NULL &&
		    HIGHER_PRIORITY(match_entry->priority, priority)) {
			/* We already have a higher entry. Ignore this. */
			continue;
		}

		begin = tmp+1;

		/* 10	genunix`indir			Syscall indir */
		/* -------------------------------------^ */
		while (isspace(*begin)) {
			++begin;
		}
		if (*begin == 0) {
			lt_display_error(
			    "Invalid configuration line: %s\n", line);
			goto err;
		}
		cause_str = begin;

		/* Check if we have mapped this cause before. */
		cause = (lt_cause_t *)
		    g_hash_table_lookup(cause_lookup, cause_str);
		if (cause == NULL) {
			char *cause_dup = lt_strdup(cause_str);
			cause = new_cause(cause_dup, 0);
			g_hash_table_insert(cause_lookup, cause_dup, cause);
		}

		match_entry = (lt_match_t *)lt_malloc(sizeof (lt_match_t));
		g_assert(NULL != match_entry);
		match_entry->priority = priority;
		match_entry->cause_id = cause->cause_id;
		match_dup = lt_strdup(match);

		g_hash_table_insert(symbol_lookup_table, match_dup,
		    match_entry);
	}

	g_sequence_foreach(cmd_disable, (GFunc)disable_cause, cause_lookup);
	g_sequence_free(cmd_disable);
	g_hash_table_destroy(cause_lookup);

	return (0);

err:
	g_sequence_free(cmd_disable);
	g_hash_table_destroy(cause_lookup);

	return (-1);
}

/*
 * Init function, called when latencytop starts.
 * It loads the translation rules from a file.
 * A configuration file defines some causes and symbols matching these causes.
 */
int
lt_table_init(void)
{
	char *config_loaded = NULL;
	int config_loaded_len = 0;
	const char *work = NULL;
	int work_len = 0;
	lt_cause_t *cause;

#ifdef EMBED_CONFIGS
	work = (char *)latencytop_trans;
	work_len = latencytop_trans_len;
#endif

	if (g_config.config_name != NULL) {
		FILE *fp;

		fp = fopen(g_config.config_name, "r");
		if (NULL == fp) {
			lt_display_error(
			    "Unable to open configuration file.\n");
			return (-1);
		}

		(void) fseek(fp, 0, SEEK_END);
		config_loaded_len = (int)ftell(fp);
		config_loaded = (char *)lt_malloc(config_loaded_len);
		(void) fseek(fp, 0, SEEK_SET);

		if (fread(config_loaded, config_loaded_len, 1, fp) == 0) {
			lt_display_error(
			    "Unable to read configuration file.\n");
			(void) fclose(fp);
			free(config_loaded);
			return (-1);
		}

		(void) fclose(fp);
		(void) printf("Loaded configuration from %s\n",
		    g_config.config_name);

		work = config_loaded;
		work_len = config_loaded_len;
	}

	g_assert(work != NULL && work_len != 0);

	lt_table_deinit();
	causes_array = g_ptr_array_new();
	lt_check_null(causes_array);

	/* 0 is not used, to keep a place for bugs etc. */
	cause = new_cause(lt_strdup("Nothing"), CAUSE_FLAG_DISABLED);
	g_assert(cause->cause_id == INVALID_CAUSE);

	symbol_lookup_table = g_hash_table_new_full(
	    g_str_hash, g_str_equal,
	    (GDestroyNotify)free, (GDestroyNotify)free);
	lt_check_null(symbol_lookup_table);

	if (parse_config(work, work_len) != 0) {
		return (-1);
	}

	if (config_loaded != NULL) {
		free(config_loaded);
	}

	return (0);
}

/*
 * Some causes, such as "lock spinning", does not have stack trace.
 * Instead, their names are explicitly specified in DTrace script.
 * This function will resolve such causes, and dynamically add them
 * to the global tables when first met (lazy initialization).
 * auto_create: set to TRUE will create the entry if it is not found.
 * Returns cause_id of the cause.
 */
int
lt_table_lookup_named_cause(char *name, int auto_create)
{
	int cause_id = INVALID_CAUSE;

	if (named_causes == NULL) {
		named_causes = g_hash_table_new_full(
		    g_str_hash, g_str_equal, (GDestroyNotify)free, NULL);
		lt_check_null(named_causes);
	} else   {
		cause_id = LT_POINTER_TO_INT(g_hash_table_lookup(
		    named_causes, name));
	}

	if (cause_id == INVALID_CAUSE && auto_create) {
		int flags = CAUSE_FLAG_SPECIAL;
		lt_cause_t *cause;

		if (name[0] == '#') {
			flags |= CAUSE_FLAG_HIDE_IN_SUMMARY;
		}

		cause = new_cause(lt_strdup(name), flags);
		if (cause == NULL) {
			return (INVALID_CAUSE);
		}
		cause_id = cause->cause_id;

		g_hash_table_insert(named_causes, lt_strdup(name),
		    LT_INT_TO_POINTER(cause_id));
	}

	return (cause_id);
}

/*
 * Try to map a symbol on stack to a known cause.
 * module_func has the format "module_name`function_name".
 * cause_id and priority will be set if a cause is found.
 * Returns 1 if found, 0 if not found.
 */
int
lt_table_lookup_cause(const char *module_func, int *cause_id, int *priority)
{
	lt_match_t *match;

	g_assert(module_func != NULL && cause_id != NULL && priority != NULL);

	if (symbol_lookup_table == NULL) {
		return (0);
	}

	match = (lt_match_t *)
	    g_hash_table_lookup(symbol_lookup_table, module_func);
	if (match == NULL) {
		char *func = strchr(module_func, '`');

		if (func != NULL) {
			match = (lt_match_t *)
			    g_hash_table_lookup(symbol_lookup_table, func);
		}
	}

	if (match == NULL) {
		return (0);
	} else   {
		*cause_id = match->cause_id;
		*priority = match->priority;
		return (1);
	}
}

/*
 * Get the display name of a cause. Cause_id must be valid,
 * which is usually return from lt_table_lookup_cause() or
 * lt_table_lookup_named_cause().
 */
const char *
lt_table_get_cause_name(int cause_id)
{
	lt_cause_t *cause;

	if (cause_id < 0 || cause_id >= causes_array_len) {
		return (NULL);
	}

	cause = (lt_cause_t *)g_ptr_array_index(causes_array, cause_id);
	if (cause == NULL) {
		return (NULL);
	} else {
		return (cause->name);
	}
}

/*
 * Check a cause's flag, e.g. if it has CAUSE_FLAG_DISABLED.
 * Use CAUSE_ALL_FLAGS to get all flags at once.
 */
int
lt_table_get_cause_flag(int cause_id, int flag)
{
	lt_cause_t *cause;

	if (cause_id < 0 || cause_id >= causes_array_len) {
		return (0);
	}
	cause = (lt_cause_t *)g_ptr_array_index(causes_array, cause_id);

	if (cause == NULL) {
		return (0);
	} else {
		return (cause->flags & flag);
	}
}

/*
 * Clean up function.
 * Free the resource used for symbol table. E.g. symbols, causes.
 */
void
lt_table_deinit(void)
{
	if (symbol_lookup_table != NULL) {
		g_hash_table_destroy(symbol_lookup_table);
		symbol_lookup_table = NULL;
	}

	if (named_causes != NULL) {
		g_hash_table_destroy(named_causes);
		named_causes = NULL;
	}

	if (causes_array != NULL) {
		g_ptr_array_foreach(causes_array, (GFunc)free_cause, NULL);
		g_ptr_array_free(causes_array, TRUE);
		causes_array = NULL;
	}

	causes_array_len = 0;
}
