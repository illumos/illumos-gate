#ifndef history_h
#define history_h

/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004 by Martin C. Shepherd.
 * 
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>    /* FILE * */

/*-----------------------------------------------------------------------
 * This module is used to record and traverse historical lines of user input.
 */

typedef struct GlHistory GlHistory;

/*
 * Create a new history maintenance object.
 */
GlHistory *_new_GlHistory(size_t buflen);

/*
 * Delete a history maintenance object.
 */
GlHistory *_del_GlHistory(GlHistory *glh);

int _glh_add_history(GlHistory *glh, const char *line, int force);

int _glh_search_prefix(GlHistory *glh, const char *line, int prefix_len);

char *_glh_find_backwards(GlHistory *glh, char *line, size_t dim);
char *_glh_find_forwards(GlHistory *glh, char *line, size_t dim);

int _glh_cancel_search(GlHistory *glh);

char *_glh_oldest_line(GlHistory *glh, char *line, size_t dim);
char *_glh_current_line(GlHistory *glh, char *line, size_t dim);

/*
 * Whenever a new line is added to the history buffer, it is given
 * a unique ID, recorded in an object of the following type.
 */
typedef unsigned long GlhLineID;

/*
 * Query the id of a history line offset by a given number of lines from
 * the one that is currently being recalled. If a recall session isn't
 * in progress, or the offset points outside the history list, 0 is
 * returned.
 */
GlhLineID _glh_line_id(GlHistory *glh, int offset);

/*
 * Recall a line by its history buffer ID. If the line is no longer
 * in the buffer, or the specified id is zero, NULL is returned.
 */
char *_glh_recall_line(GlHistory *glh, GlhLineID id, char *line, size_t dim);

/*
 * Write the contents of the history buffer to a given file. Note that
 * ~ and $ expansion are not performed on the filename.
 */
int _glh_save_history(GlHistory *glh, const char *filename,
		      const char *comment, int max_lines);

/*
 * Restore the contents of the history buffer from a given file.
 * Note that ~ and $ expansion are not performed on the filename.
 */
int _glh_load_history(GlHistory *glh, const char *filename, const char *comment,
		      char *line, size_t dim);

/*
 * Set and query the current history group.
 */
int _glh_set_group(GlHistory *glh, unsigned group);
int _glh_get_group(GlHistory *glh);

/*
 * Display the contents of the history list to the specified stdio
 * output group.
 */
int _glh_show_history(GlHistory *glh, GlWriteFn *write_fn, void *data,
		      const char *fmt, int all_groups, int max_lines);

/*
 * Change the size of the history buffer.
 */
int _glh_resize_history(GlHistory *glh, size_t bufsize);

/*
 * Set an upper limit to the number of lines that can be recorded in the
 * history list, or remove a previously specified limit.
 */
void _glh_limit_history(GlHistory *glh, int max_lines);

/*
 * Discard either all history, or the history associated with the current
 * history group.
 */
void _glh_clear_history(GlHistory *glh, int all_groups);

/*
 * Temporarily enable or disable the history facility.
 */
void _glh_toggle_history(GlHistory *glh, int enable);

/*
 * Lookup a history line by its sequential number of entry in the
 * history buffer.
 */
int _glh_lookup_history(GlHistory *glh, GlhLineID id, const char **line,
			unsigned *group, time_t *timestamp);

/*
 * Query the state of the history list.
 */
void _glh_state_of_history(GlHistory *glh, int *enabled, unsigned *group,
			   int *max_lines);

/*
 * Get the range of lines in the history buffer.
 */
void _glh_range_of_history(GlHistory *glh, unsigned long *oldest,
			   unsigned long *newest, int *nlines);

/*
 * Return the size of the history buffer and the amount of the
 * buffer that is currently in use.
 */
void _glh_size_of_history(GlHistory *glh, size_t *buff_size, size_t *buff_used);

/*
 * Get information about the last error in this module.
 */
const char *_glh_last_error(GlHistory *glh);

/*
 * Return non-zero if a history search session is currently in progress.
 */
int _glh_search_active(GlHistory *glh);

#endif
