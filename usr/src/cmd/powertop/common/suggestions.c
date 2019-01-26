/*
 * Copyright 2009, Intel Corporation
 * Copyright 2009, Sun Microsystems, Inc
 *
 * This file is part of PowerTOP
 *
 * This program file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program in a file named COPYING; if not, write to the
 * Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA
 *
 * Authors:
 *      Arjan van de Ven <arjan@linux.intel.com>
 *      Eric C Saxe <eric.saxe@sun.com>
 *      Aubrey Li <aubrey.li@intel.com>
 */

/*
 * GPL Disclaimer
 *
 * For the avoidance of doubt, except that if any license choice other
 * than GPL or LGPL is available it will apply instead, Sun elects to
 * use only the General Public License version 2 (GPLv2) at this time
 * for any software where a choice of GPL license versions is made
 * available with the language indicating that GPLv2 or any later
 * version may be used, or where a choice of which version of the GPL
 * is applied is otherwise unspecified.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "powertop.h"

/*
 * Default number of intervals we display a suggestion before moving
 * to the next.
 */
#define	PT_SUGG_DEF_SLICE	3

/*
 * Global pointer to the current suggestion.
 */
sugg_t	*g_curr_sugg;

/*
 * Head of the list of suggestions.
 */
static sugg_t *sugg;

/*
 * Add a new suggestion. Only one suggestion per text allowed.
 */
void
pt_sugg_add(char *text, int weight, char key, char *sb_msg, sugg_func_t *func)
{
	sugg_t *new, *n, *pos = NULL;

	/*
	 * Text is a required field for suggestions
	 */
	if (text == NULL)
		return;

	if (sugg == NULL) {
		/*
		 * Creating first element
		 */
		if ((new = calloc(1, sizeof (sugg_t))) == NULL)
			return;

		if (sb_msg != NULL)
			new->sb_msg = strdup(sb_msg);

		if (text != NULL)
			new->text = strdup(text);

		new->weight = weight;
		new->key = key;
		new->func = func;
		new->slice = 0;

		sugg = new;
		new->prev = NULL;
		new->next = NULL;
	} else {
		for (n = sugg; n != NULL; n = n->next) {
			if (strcmp(n->text, text) == 0)
				return;

			if (weight > n->weight && pos == NULL)
				pos = n;
		}
		/*
		 * Create a new element
		 */
		if ((new = calloc(1, sizeof (sugg_t))) == NULL)
			return;

		if (sb_msg != NULL)
			new->sb_msg = strdup(sb_msg);

		new->text = strdup(text);

		new->weight = weight;
		new->key = key;
		new->func = func;
		new->slice = 0;

		if (pos == NULL) {
			/*
			 * Ordering placed the new element at the end
			 */
			for (n = sugg; n->next != NULL; n = n->next)
				;

			n->next = new;
			new->prev = n;
			new->next = NULL;
		} else {
			if (pos == sugg) {
				/*
				 * Ordering placed the new element at the start
				 */
				new->next = sugg;
				new->prev = sugg;
				sugg->prev = new;
				sugg = new;
			} else {
				/*
				 * Ordering placed the new element somewhere in
				 * the middle
				 */
				new->next = pos;
				new->prev = pos->prev;
				pos->prev->next = new;
				pos->prev = new;
			}
		}
	}
}

/*
 * Removes a suggestion, returning 0 if not found and 1 if so.
 */
int
pt_sugg_remove(sugg_func_t *func)
{
	sugg_t *n;
	int ret = 0;

	for (n = sugg; n != NULL; n = n->next) {
		if (n->func == func) {
			/* Removing the first element */
			if (n == sugg) {
				if (sugg->next == NULL) {
					/* Removing the only element */
					sugg = NULL;
				} else {
					sugg = n->next;
					sugg->prev = NULL;
				}
			} else {
				if (n->next == NULL) {
					/* Removing the last element */
					n->prev->next = NULL;
				} else {
					/* Removing an intermediate element */
					n->prev->next = n->next;
					n->next->prev = n->prev;
				}
			}

			/*
			 * If this suggestions is currently being suggested,
			 * remove it and update the screen.
			 */
			if (n == g_curr_sugg) {
				if (n->sb_msg != NULL) {
					pt_display_mod_status_bar(n->sb_msg);
					pt_display_status_bar();
				}
				if (n->text != NULL)
					pt_display_suggestions(NULL);
			}

			free(n);
			ret = 1;
		}
	}

	return (ret);
}

/*
 * Chose a suggestion to display. The list of suggestions is ordered by weight,
 * so we only worry about fariness here. Each suggestion, starting with the
 * first (the 'heaviest') is displayed during PT_SUGG_DEF_SLICE intervals.
 */
void
pt_sugg_pick(void)
{
	sugg_t *n;

	if (sugg == NULL) {
		g_curr_sugg = NULL;
		return;
	}

search:
	for (n = sugg; n != NULL; n = n->next) {

		if (n->slice++ < PT_SUGG_DEF_SLICE) {

			/*
			 * Don't need to re-suggest the current suggestion.
			 */
			if (g_curr_sugg == n && !g_sig_resize)
				return;

			/*
			 * Remove the current suggestion from screen.
			 */
			if (g_curr_sugg != NULL) {
				if (g_curr_sugg->sb_msg != NULL) {
					pt_display_mod_status_bar(
					    g_curr_sugg->sb_msg);
					pt_display_status_bar();
				}
				if (g_curr_sugg->text != NULL)
					pt_display_suggestions(NULL);
			}

			if (n->sb_msg != NULL) {
				pt_display_mod_status_bar(n->sb_msg);
				pt_display_status_bar();
			}

			pt_display_suggestions(n->text);

			g_curr_sugg = n;

			return;
		}
	}

	/*
	 * All suggestions have run out of slice quotas, so we restart.
	 */
	for (n = sugg; n != NULL; n = n->next)
		n->slice = 0;

	goto search;
}

void
pt_sugg_as_root(void)
{
	pt_sugg_add("Suggestion: run as root to get suggestions"
	    " for reducing system power consumption",  40, 0, NULL,
	    NULL);
}
