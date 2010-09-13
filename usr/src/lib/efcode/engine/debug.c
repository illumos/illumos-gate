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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <fcode/private.h>
#include <fcode/log.h>

#ifndef DEBUG_LVL
#define	DEBUG_LVL	0
#endif

struct bitab {
	token_t bi_ptr;
	char *bi_name;
	int bi_type;
};

struct bitab *lookup_builtin(token_t);

static int debug_level = DEBUG_LVL;

void
set_interpreter_debug_level(long lvl)
{
	debug_level = lvl;
}

long
get_interpreter_debug_level(void)
{
	return (debug_level);
}

void
output_data_stack(fcode_env_t *env, int msglevel)
{
	int i;

	log_message(msglevel, "( ");
	if (DS > env->ds0) {
		for (i = 0; i < (DS - env->ds0); i++)
			log_message(msglevel, "%llx ",
			    (uint64_t)(env->ds0[i + 1]));
	} else
		log_message(msglevel, "<empty> ");
	log_message(msglevel, ") ");
}

void
output_return_stack(fcode_env_t *env, int show_wa, int msglevel)
{
	int i;
	int anyout = 0;

	log_message(msglevel, "R:( ");
	if (show_wa) {
		log_message(msglevel, "%s ",
		    acf_backup_search(env, (acf_t)WA));
		anyout++;
	}
	if (IP) {
		anyout++;
		log_message(msglevel, "%s ", acf_backup_search(env, IP));
	}
	for (i = (RS - env->rs0) - 1; i > 0; i--) {
		anyout++;
		log_message(msglevel, "%s ",
			    acf_backup_search(env, (acf_t)env->rs0[i+1]));
	}
	if (!anyout)
		log_message(msglevel, "<empty> ");
	log_message(msglevel, ") ");
}

void
dump_comma(fcode_env_t *env, char *type)
{
	xforth_t d;

	if (strcmp(type, "x,") == 0)
		d = peek_xforth(env);
	else
		d = TOS;
	log_message(MSG_FC_DEBUG, "%s %p, %llx\n", type, HERE, (uint64_t)d);
}

static int ndebug_names;
#define	MAXDEBUG_NAMES	10
static char *debug_names[MAXDEBUG_NAMES];

static int ndebug_acfs;
#define	MAXDEBUG_ACFS	10
static acf_t debug_acfs[MAXDEBUG_ACFS];

void
add_debug_acf(fcode_env_t *env, acf_t acf)
{
	int i;

	for (i = 0; i < ndebug_acfs; i++)
		if (acf == debug_acfs[i])
			return;

	if (!within_dictionary(env, acf))
		log_message(MSG_ERROR, "Can't debug builtin\n");
	else if (ndebug_acfs >= MAXDEBUG_ACFS)
		log_message(MSG_ERROR, "Too many debug ACF's\n");
	else {
		debug_acfs[ndebug_acfs++] = acf;
		*LINK_TO_FLAGS(ACF_TO_LINK(acf)) |= FLAG_DEBUG;
	}
}

static void
paren_debug(fcode_env_t *env)
{
	acf_t acf;

	acf = (acf_t)POP(DS);
	if (!within_dictionary(env, acf)) {
		log_message(MSG_INFO, "acf: %llx not in dictionary\n",
		    (uint64_t)acf);
		return;
	}
	if ((acf_t)_ALIGN(acf, token_t) != acf) {
		log_message(MSG_INFO, "acf: %llx not aligned\n",
		    (uint64_t)acf);
		return;
	}
	if (*acf != (token_t)(&do_colon)) {
		log_message(MSG_INFO, "acf: %llx not a colon-def\n",
		    (uint64_t)acf);
		return;
	}
	add_debug_acf(env, acf);
}

static void
debug(fcode_env_t *env)
{
	fstack_t d;
	char *word;
	acf_t acf;

	parse_word(env);
	dollar_find(env);
	d = POP(DS);
	if (d) {
		acf = (acf_t)POP(DS);
		add_debug_acf(env, acf);
	} else if (ndebug_names >= MAXDEBUG_NAMES) {
		log_message(MSG_ERROR, "Too many forward debug words\n");
		two_drop(env);
	} else {
		word = pop_a_duped_string(env, NULL);
		log_message(MSG_INFO, "Forward defined word: %s\n", word);
		debug_names[ndebug_names++] = word;
	}
}

/*
 * Eliminate dups and add vocabulary forth to end if not already on list.
 */
static void
order_to_dict_list(fcode_env_t *env, token_t *order[])
{
	int i, j, norder = 0;

	if (env->current)
		order[norder++] = env->current;
	for (i = env->order_depth; i >= 0; i--) {
		for (j = 0; j < norder && order[j] != env->order[i]; j++)
			;
		if (j == norder)
			order[norder++] = env->order[i];
	}
	for (j = 0; j < norder && order[j] != (token_t *)&env->forth_voc_link;
	    j++)
		;
	if (j == norder)
		order[norder++] = (token_t *)&env->forth_voc_link;
	order[norder] = NULL;
}

static acf_t
search_all_dictionaries(fcode_env_t *env,
    acf_t (*fn)(fcode_env_t *, acf_t, void *),
    void *arg)
{
	token_t *order[MAX_ORDER+1];
	int i;
	token_t *dptr;
	acf_t acf;

	order_to_dict_list(env, order);
	for (i = 0; (dptr = order[i]) != NULL; i++) {
		for (dptr = (token_t *)(*dptr); dptr;
		    dptr = (token_t *)(*dptr))
			if ((acf = (*fn)(env, LINK_TO_ACF(dptr), arg)) != NULL)
				return (acf);
	}
	return (NULL);
}

char *
acf_to_str(acf_t acf)
{
	static char msg[(sizeof (acf) * 2) + 3];

	sprintf(msg, "(%08p)", acf);
	return (msg);
}

char *
get_name_or_acf(token_t *dptr)
{
	char *name;

	if ((name = get_name(dptr)) != NULL)
		return (name);
	return (acf_to_str(LINK_TO_ACF(dptr)));
}

static void
output_acf_name(acf_t acf)
{
	char *name;
	token_t *dptr;
	static int acf_count = 0;

	if (acf == NULL) {
		if (acf_count)
			log_message(MSG_INFO, "\n");
		acf_count = 0;
		return;
	}
	dptr = ACF_TO_LINK(acf);
	if ((name = get_name(dptr)) == NULL)
		name = "<noname>";

	log_message(MSG_INFO, "%24s (%08p)", name, acf);
	if (++acf_count >= 2) {
		log_message(MSG_INFO, "\n");
		acf_count = 0;
	} else
		log_message(MSG_INFO, "    ");
}

static void
dot_debug(fcode_env_t *env)
{
	int i;
	token_t *dptr;

	if (ndebug_names == 0)
		log_message(MSG_INFO, "No forward debug words\n");
	else {
		for (i = 0; i < ndebug_names; i++)
			log_message(MSG_INFO, "%s Forward\n", debug_names[i]);
	}
	if (ndebug_acfs == 0)
		log_message(MSG_INFO, "No debug words\n");
	else {
		for (i = 0; i < ndebug_acfs; i++)
			log_message(MSG_INFO, "%s\n",
			    get_name_or_acf(ACF_TO_LINK(debug_acfs[i])));
	}
}

static void
do_undebug(fcode_env_t *env, char *name)
{
	int i;

	for (i = 0; i < ndebug_names; i++) {
		if (strcmp(debug_names[i], name) == 0) {
			log_message(MSG_INFO, "Undebugging forward word %s\n",
			    name);
			FREE(debug_names[i]);
			for (i++; i < ndebug_names; i++)
				debug_names[i - 1] = debug_names[i];
			ndebug_names--;
			break;
		}
	}
}

static void
undebug(fcode_env_t *env)
{
	fstack_t d;
	acf_t acf;
	flag_t *flagp;
	char *name;
	int i, j;

	parse_word(env);
	two_dup(env);
	dollar_find(env);
	d = POP(DS);
	if (d) {
		acf = (acf_t)POP(DS);
		flagp = LINK_TO_FLAGS(ACF_TO_LINK(acf));
		if ((*flagp & FLAG_DEBUG) == 0)
			log_message(MSG_WARN, "Word not debugged?\n");
		else {
			log_message(MSG_INFO, "Undebugging acf: %p\n", acf);
			*flagp &= ~FLAG_DEBUG;
			for (i = 0; i < ndebug_acfs; i++) {
				if (debug_acfs[i] == acf) {
					for (j = i + 1; j < ndebug_acfs; j++)
						debug_acfs[j-1] = debug_acfs[j];
					ndebug_acfs--;
					break;
				}
			}
		}
	} else
		two_drop(env);
	name = pop_a_string(env, NULL);
	do_undebug(env, name);
}

int
name_is_debugged(fcode_env_t *env, char *name)
{
	int i;

	if (ndebug_names <= 0)
		return (0);
	for (i = 0; i < ndebug_names; i++)
		if (strcmp(debug_names[i], name) == 0)
			return (1);
	return (0);
}

/*
 * This is complicated by being given ACF's to temporary compile words which
 * don't have a header.
 */
int
is_debug_word(fcode_env_t *env, acf_t acf)
{
	flag_t *flagp;
	int i;

	/* check to see if any words are being debugged */
	if (ndebug_acfs == 0)
		return (0);

	/* only words in dictionary can be debugged */
	if (!within_dictionary(env, acf))
		return (0);

	/* check that word has "FLAG_DEBUG" on */
	flagp = LINK_TO_FLAGS(ACF_TO_LINK(acf));
	if ((*flagp & FLAG_DEBUG) == 0)
		return (0);

	/* look in table of debug acf's */
	for (i = 0; i < ndebug_acfs; i++)
		if (debug_acfs[i] == acf)
			return (1);
	return (0);
}

#define	MAX_DEBUG_STACK	100
token_t debug_low[MAX_DEBUG_STACK], debug_high[MAX_DEBUG_STACK];
int debug_prev_level[MAX_DEBUG_STACK];
int debug_curr_level[MAX_DEBUG_STACK];
int ndebug_stack = 0;

void
debug_set_level(fcode_env_t *env, int level)
{
	debug_curr_level[ndebug_stack - 1] = level;
	set_interpreter_debug_level(level);
}

token_t
find_semi_in_colon_def(fcode_env_t *env, acf_t acf)
{
	for (; within_dictionary(env, acf); acf++)
		if (*acf == (token_t)(&semi_ptr))
			return ((token_t)acf);
	return (0);
}

void
check_for_debug_entry(fcode_env_t *env)
{
	int top;

	if (is_debug_word(env, WA) && ndebug_stack < MAX_DEBUG_STACK) {
		top = ndebug_stack++;
		debug_prev_level[top] = get_interpreter_debug_level();
		debug_low[top] = (token_t)WA;
		if (*WA == (token_t)(&do_colon)) {
			debug_high[top] =
			    find_semi_in_colon_def(env, WA);
		} else {
			debug_high[top] = 0;	/* marker... */
		}
		debug_set_level(env, DEBUG_STEPPING);
		output_step_message(env);
	}
}

void
check_for_debug_exit(fcode_env_t *env)
{
	if (ndebug_stack) {
		int top = ndebug_stack - 1;

		if (debug_high[top] == 0) {
			set_interpreter_debug_level(debug_prev_level[top]);
			ndebug_stack--;
		} else if ((token_t)IP >= debug_low[top] &&
		    (token_t)IP <= debug_high[top]) {
			set_interpreter_debug_level(debug_curr_level[top]);
		} else {
			set_interpreter_debug_level(debug_prev_level[top]);
		}
	}
}

void
check_semi_debug_exit(fcode_env_t *env)
{
	if (ndebug_stack) {
		int top = ndebug_stack - 1;

		if ((token_t)(IP - 1) == debug_high[top]) {
			set_interpreter_debug_level(debug_prev_level[top]);
			ndebug_stack--;
		}
	}
}

/*
 * Really entering do_run, since this may be a recursive entry to do_run,
 * we need to set the debug level to what it was previously.
 */
int
current_debug_state(fcode_env_t *env)
{
	if (ndebug_stack) {
		int top = ndebug_stack - 1;
		set_interpreter_debug_level(debug_prev_level[top]);
	}
	return (ndebug_stack);
}

void
clear_debug_state(fcode_env_t *env, int oldstate)
{
	if (ndebug_stack && oldstate <= ndebug_stack) {
		set_interpreter_debug_level(debug_prev_level[oldstate]);
		ndebug_stack = oldstate;
	}
}

void
unbug(fcode_env_t *env)
{
	int i;
	token_t *link;
	flag_t *flag;

	for (i = ndebug_stack - 1; i >= 0; i--) {
		link = ACF_TO_LINK(debug_low[i]);
		flag = LINK_TO_FLAGS(link);
		*flag &= ~FLAG_DEBUG;
	}
	clear_debug_state(env, 0);
}

void
output_vitals(fcode_env_t *env)
{
	log_message(MSG_FC_DEBUG, "IP=%p, *IP=%p, WA=%p, *WA=%p ", IP,
	    (IP ? *IP : 0), WA, (WA ? *WA : 0));
}

int
do_exec_debug(fcode_env_t *env, void *fn)
{
	int dl = debug_level;
	int show_wa = 1;

	if ((dl & (DEBUG_EXEC_DUMP_DS | DEBUG_EXEC_DUMP_RS |
	    DEBUG_EXEC_SHOW_VITALS | DEBUG_EXEC_TRACE | DEBUG_TRACING |
	    DEBUG_STEPPING)) == 0)
		return (0);

	if (dl & DEBUG_STEPPING) {
		dl |= DEBUG_EXEC_DUMP_DS;
	}
	if (dl & (DEBUG_STEPPING | DEBUG_EXEC_TRACE)) {
		log_message(MSG_FC_DEBUG, "%-15s ", acf_to_name(env, WA));
		show_wa = 0;
	}
	if (dl & DEBUG_EXEC_DUMP_DS)
		output_data_stack(env, MSG_FC_DEBUG);
	if (dl & DEBUG_EXEC_DUMP_RS)
		output_return_stack(env, show_wa, MSG_FC_DEBUG);
	if (dl & DEBUG_EXEC_SHOW_VITALS)
		output_vitals(env);
	if (dl & DEBUG_TRACING)
		do_fclib_trace(env, (void *) fn);
	log_message(MSG_FC_DEBUG, "\n");
	if (dl & DEBUG_STEPPING)
		return (do_fclib_step(env));
	return (0);
}

static void
smatch(fcode_env_t *env)
{
	int len;
	char *str, *p;

	if ((str = parse_a_string(env, &len)) == NULL)
		log_message(MSG_INFO, "smatch: no string\n");
	else {
		for (p = (char *)env->base; p < (char *)HERE; p++)
			if (memcmp(p, str, len) == 0)
				log_message(MSG_DEBUG, "%p\n", p);
	}
}

void
check_vitals(fcode_env_t *env)
{
	int i;
	token_t *dptr;

	dptr = env->current;
	if (*dptr && !within_dictionary(env, (uchar_t *)*dptr))
		log_message(MSG_ERROR, "Current: %p outside dictionary\n",
		    *dptr);
	for (i = env->order_depth; i >= 0; i--) {
		dptr = env->order[i];
		if (!dptr)
			continue;
		if (*dptr && !within_dictionary(env, (uchar_t *)*dptr))
			log_message(MSG_ERROR, "Order%d: %p outside"
			    " dictionary\n", i, *dptr);
	}
	if (HERE < env->base || HERE >= env->base + dict_size) {
		log_message(MSG_ERROR, "HERE: %p outside range\n", HERE);
	}
	if (DS < env->ds0 || DS >= &env->ds0[stack_size]) {
		forth_abort(env, "DS: %p outside range\n", DS);
	}
	if (RS < env->rs0 || RS >= &env->rs0[stack_size]) {
		log_message(MSG_ERROR, "RS: %p outside range\n", RS);
		RS = env->rs0;
	}
	if (IP && !within_dictionary(env, IP))
		log_message(MSG_ERROR, "IP: %p outside dictionary\n", IP);
	if (!within_dictionary(env, (void *)env->forth_voc_link))
		log_message(MSG_ERROR, "forth_voc_link: %p outside"
		    " dictionary\n", env->forth_voc_link);
}

static void
dump_table(fcode_env_t *env)
{
	int i;

	for (i = 0; i < MAX_FCODE; i++) {
		if (*(env->table[i].apf) != (token_t)(&f_error)) {
			log_message(MSG_DEBUG, "Token: %4x %32s acf = %8p,"
			    " %8p\n", i, env->table[i].name, env->table[i].apf,
			    *(env->table[i].apf));
		}
	}
	log_message(MSG_DEBUG, "%d FCODES implemented\n", fcode_impl_count);
}

void
verify_usage(fcode_env_t *env)
{
	int i, untested = 0;

	for (i = 0; i < MAX_FCODE; i++) {
		int verify;

		verify = env->table[i].flags & (ANSI_WORD|P1275_WORD);
		if ((verify) &&
#ifdef DEBUG
			(env->table[i].usage == 0) &&
#endif
			(env->table[i].apf)) {
			log_message(MSG_DEBUG,
			    "Untested: %4x %32s acf = %8p, %8p\n", i,
			    env->table[i].name, env->table[i].apf,
			    *(env->table[i].apf));
			untested++;
		}
	}
	if (untested)
		log_message(MSG_DEBUG, "%d untested tokens\n", untested);
}

static void
debugf(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)&debug_level);
}

static void
control(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)&env->control);
}

struct bittab {
	int b_bitval;
	char *b_bitname;
} bittab[] = {
	DEBUG_CONTEXT,		"context",
	DEBUG_BYTELOAD_DS,	"byteload-ds",
	DEBUG_BYTELOAD_RS,	"byteload-rs",
	DEBUG_BYTELOAD_TOKENS,	"byteload-tokens",
	DEBUG_NEW_TOKEN,	"new-token",
	DEBUG_EXEC_TRACE,	"exec-trace",
	DEBUG_EXEC_SHOW_VITALS,	"exec-show-vitals",
	DEBUG_EXEC_DUMP_DS,	"exec-dump-ds",
	DEBUG_EXEC_DUMP_RS,	"exec-dump-rs",
	DEBUG_COMMA,		"comma",
	DEBUG_HEADER,		"header",
	DEBUG_EXIT_WORDS,	"exit-words",
	DEBUG_EXIT_DUMP,	"exit-dump",
	DEBUG_DUMP_TOKENS,	"dump-tokens",
	DEBUG_COLON,		"colon",
	DEBUG_NEXT_VITALS,	"next-vitals",
	DEBUG_VOC_FIND,		"voc-find",
	DEBUG_DUMP_DICT_TOKENS,	"dump-dict-tokens",
	DEBUG_TOKEN_USAGE,	"token-usage",
	DEBUG_DUMP_TOKEN_TABLE,	"dump-token-table",
	DEBUG_SHOW_STACK,	"show-stack",
	DEBUG_SHOW_RS,		"show-rs",
	DEBUG_TRACING,		"tracing",
	DEBUG_TRACE_STACK,	"trace-stack",
	DEBUG_CALL_METHOD,	"call-method",
	DEBUG_ACTIONS,		"actions",
	DEBUG_STEPPING,		"stepping",
	DEBUG_REG_ACCESS,	"reg-access",
	DEBUG_ADDR_ABUSE,	"addr-abuse",
	DEBUG_FIND_FCODE,	"find-fcode",
	DEBUG_UPLOAD,		"upload",
	0
};

void
debug_flags_to_output(fcode_env_t *env, int flags)
{
	int first = 1, i;

	for (i = 0; bittab[i].b_bitval != 0; i++)
		if (bittab[i].b_bitval & flags) {
			if (!first)
				log_message(MSG_INFO, ",");
			first = 0;
			log_message(MSG_INFO, bittab[i].b_bitname);
		}
	if (first)
		log_message(MSG_INFO, "<empty>");
	log_message(MSG_INFO, "\n");
}

static void
dot_debugf(fcode_env_t *env)
{
	debug_flags_to_output(env, debug_level);
}

static void
debugf_qmark(fcode_env_t *env)
{
	debug_flags_to_output(env, 0xffffffff);
}

int
debug_flags_to_mask(char *str)
{
	int flags = 0;
	char *p;
	int i;

	if (isdigit(*str)) {
		if (*str == '0') {
			str++;
			if (*str == 'x' || *str == 'X') {
				sscanf(str + 1, "%x", &flags);
			} else
				sscanf(str, "%o", &flags);
		} else
			sscanf(str, "%d", &flags);
		return (flags);
	}
	if (strcmp(str, "clear") == 0)
		return (0);
	if (strcmp(str, "all") == 0)
		return (0xffffffff & ~DEBUG_STEPPING);
	if (*str) {
		do {
			if (p = strchr(str, ','))
				*p++ = '\0';
			for (i = 0; bittab[i].b_bitname != 0; i++)
				if (strcmp(str, bittab[i].b_bitname) == 0) {
					flags |= bittab[i].b_bitval;
					break;
			}
			if (bittab[i].b_bitname == 0)
				log_message(MSG_WARN,
				    "Unknown debug flag: '%s'\n", str);
			str = p;
		} while (p);
	}
	return (flags);
}

static void
set_debugf(fcode_env_t *env)
{
	char *str;

	str = parse_a_string(env, NULL);
	debug_level = debug_flags_to_mask(str);
}

static acf_t
show_a_word(fcode_env_t *env, acf_t acf, void *arg)
{
	static int nshow_words = 0;

	if (acf == NULL) {
		if (nshow_words > 0) {
			log_message(MSG_DEBUG, "\n");
			nshow_words = 0;
		}
		return (NULL);
	}
	log_message(MSG_DEBUG, "%15s  ", get_name_or_acf(ACF_TO_LINK(acf)));
	nshow_words++;
	if (nshow_words >= 4) {
		log_message(MSG_DEBUG, "\n");
		nshow_words = 0;
	}
	return (NULL);
}

void
words(fcode_env_t *env)
{
	(void) search_all_dictionaries(env, show_a_word, NULL);
	(void) show_a_word(env, NULL, NULL);
}

static acf_t
dump_a_word(fcode_env_t *env, acf_t acf, void *arg)
{
	output_acf_name(acf);
	return (NULL);
}

void
dump_words(fcode_env_t *env)
{
	(void) search_all_dictionaries(env, dump_a_word, NULL);
	output_acf_name(NULL);
}

static void
dump_line(uchar_t *ptr)
{
	uchar_t *byte;
	int i;

	log_message(MSG_INFO, "%p  ", ptr);
	for (i = 0, byte = ptr; i < 16; i++) {
		if (i == 8)
			log_message(MSG_INFO, " ");
		log_message(MSG_INFO, "%02.2x ", *byte++);
	}
	log_message(MSG_INFO, " ");
	for (i = 0, byte = ptr; i < 16; i++, byte++) {
		log_message(MSG_INFO, "%c",
		    ((*byte < 0x20) || (*byte > 0x7f)) ? '.' : *byte);
	}
	log_message(MSG_INFO, "\n");
}

void
dump_dictionary(fcode_env_t *env)
{
	uchar_t *ptr;

	log_message(MSG_INFO, "Dictionary dump: base: %p\n", env->base);
	for (ptr = (uchar_t *)(((long)(env->base)) & ~0xf); ptr < HERE;
	    ptr += 16)
		dump_line(ptr);
}

static char *
acf_to_fcode_name(fcode_env_t *env, acf_t acf)
{
	int i;

	for (i = 0; i < MAX_FCODE; i++)
		if (env->table[i].apf == acf)
			return (env->table[i].name);
	return (NULL);
}

static acf_t
acf_match(fcode_env_t *env, acf_t sacf, void *macf)
{
	if (sacf == (acf_t)macf)
		return (sacf);
	return (NULL);
}

/*
 * Given an ACF, return ptr to name or "unknown" string.
 */
char *
acf_to_name(fcode_env_t *env, acf_t acf)
{
	struct bitab *bip;
	static char name_buf[256];
	uchar_t *p, *np;
	int i, n;

	if (!within_dictionary(env, acf)) {
		if ((bip = lookup_builtin((token_t)acf)) != NULL)
			return (bip->bi_name);
		return (NULL);
	}
	return (get_name_or_acf(ACF_TO_LINK(acf)));
}

int
within_dictionary(fcode_env_t *env, void *addr)
{
	return ((uchar_t *)addr >= env->base &&
	    (uchar_t *)addr < env->base + dict_size);
}

static int
within_word(fcode_env_t *env, acf_t acf, acf_t wacf)
{
	if (acf == wacf || acf + 1 == wacf)
		return (1);
	if (*acf == (token_t)(&do_colon)) {
		do {
			if (acf == wacf)
				return (1);
		} while (*acf++ != (token_t)(&semi_ptr));
	}
	return (0);
}

/*
 * Given an ACF in the middle of a colon definition, search dictionary towards
 * beginning for "colon" acf.  If we find a "semi" acf first, we're not in
 * the middle of a colon-def (temporary execute?).
 */
char *
acf_backup_search(fcode_env_t *env, acf_t acf)
{
	acf_t nacf;
	char *name;

	if ((acf_t)_ALIGN(acf, token_t) == acf && within_dictionary(env, acf)) {
		for (nacf = acf; nacf >= (acf_t)env->base; nacf--)
			if (*nacf == (token_t)(&do_colon) ||
			    *nacf == (token_t)(&semi_ptr))
				break;
		if (nacf >= (acf_t)env->base && *nacf == (token_t)(&do_colon) &&
		    (name = get_name(ACF_TO_LINK(nacf))) != NULL)
			return (name);
	}
	return (acf_to_str(acf));
}

/*
 * Print out current process's C stack using /usr/proc/bin/pstack
 */
void
ctrace(fcode_env_t *env)
{
	char buf[256];
	FILE *fd;

	log_message(MSG_DEBUG, "Interpreter C Stack:\n");
	sprintf(buf, "/usr/proc/bin/pstack %d", getpid());
	if ((fd = popen(buf, "r")) == NULL)
		log_perror(MSG_ERROR, "Can't run: %s", buf);
	else {
		while (fgets(buf, sizeof (buf), fd))
			log_message(MSG_DEBUG, buf);
		fclose(fd);
	}
}

/*
 * Dump data, return stacks, try to unthread forth calling stack.
 */
void
ftrace(fcode_env_t *env)
{
	log_message(MSG_DEBUG, "Forth Interpreter Stacks:\n");
	output_data_stack(env, MSG_DEBUG);
	output_return_stack(env, 1, MSG_DEBUG);
	log_message(MSG_DEBUG, "\n");
}

int in_forth_abort;

/*
 * Handle fatal error, if interactive mode, return to ok prompt.
 */
void
forth_abort(fcode_env_t *env, char *fmt, ...)
{
	va_list ap;
	char msg[256];

	if (in_forth_abort) {
		log_message(MSG_FATAL, "ABORT: abort within forth_abort\n");
		abort();
	}
	in_forth_abort++;

	va_start(ap, fmt);
	vsprintf(msg, fmt, ap);
	log_message(MSG_ERROR, "ABORT: %s\n", msg);

	if (env) {
		ctrace(env);
		ftrace(env);
	}

	return_to_interact(env);
	/*
	 * If not in interactive mode, return_to_interact just returns.
	 */
	exit(1);
}

/*
 * Handle fatal system call error
 */
void
forth_perror(fcode_env_t *env, char *fmt, ...)
{
	va_list ap;
	char msg[256];
	int save_errno = errno;	/* just in case... */

	va_start(ap, fmt);
	vsprintf(msg, fmt, ap);

	forth_abort(env, "%s: %s", msg, strerror(save_errno));
}

static void
show_stack(fcode_env_t *env)
{
#ifdef DEBUG
	debug_level ^= DEBUG_SHOW_STACK;
#else
	/*EMPTY*/
#endif
}

static void
print_bytes_header(int width, int offset)
{
	int i;

	for (i = 0; i < width; i++)
		log_message(MSG_INFO, " ");
	log_message(MSG_INFO, "  ");
	for (i = 0; i < 16; i++) {
		if (i == 8)
			log_message(MSG_INFO, " ");
		if (i == offset)
			log_message(MSG_INFO, "\\/ ");
		else
			log_message(MSG_INFO, "%2x ", i);
	}
	log_message(MSG_INFO, " ");
	for (i = 0; i < 16; i++) {
		if (i == offset)
			log_message(MSG_INFO, "v");
		else
			log_message(MSG_INFO, "%x", i);
	}
	log_message(MSG_INFO, "\n");
}

static void
dump(fcode_env_t *env)
{
	uchar_t *data;
	int len, offset;
	char buf[20];

	len = POP(DS);
	data = (uchar_t *)POP(DS);
	offset = ((long)data) & 0xf;
	len += offset;
	data = (uchar_t *)((long)data & ~0xf);
	sprintf(buf, "%p", data);
	print_bytes_header(strlen(buf), offset);
	for (len += offset; len > 0; len -= 16, data += 16)
		dump_line(data);
}

static acf_t
do_sifting(fcode_env_t *env, acf_t acf, void *pat)
{
	char *name;

	if ((name = get_name(ACF_TO_LINK(acf))) != NULL && strstr(name, pat))
		output_acf_name(acf);
	return (NULL);
}

static void
sifting(fcode_env_t *env)
{
	char *pat;

	if ((pat = parse_a_string(env, NULL)) != NULL) {
		(void) search_all_dictionaries(env, do_sifting, pat);
		output_acf_name(NULL);
	}
}

void
print_level(int level, int *doprint)
{
	int i;

	if (*doprint) {
		log_message(MSG_DEBUG, "\n    ");
		for (i = 0; i < level; i++)
			log_message(MSG_DEBUG, "    ");
		*doprint = 0;
	}
}

#define	BI_QUOTE	1
#define	BI_BLIT		2
#define	BI_BDO		3
#define	BI_QDO		4
#define	BI_BR		5
#define	BI_QBR		6
#define	BI_BOF		7
#define	BI_LOOP		8
#define	BI_PLOOP	9
#define	BI_TO		10
#define	BI_SEMI		11
#define	BI_COLON	12
#define	BI_NOOP		13
#define	BI_NOTYET	14	/* unimplented in "see" */

struct bitab bitab[] = {
	(token_t)(&quote_ptr),			"\"",		BI_QUOTE,
	(token_t)(&blit_ptr),			"blit",		BI_BLIT,
	(token_t)(&do_bdo_ptr),			"do",		BI_BDO,
	(token_t)(&do_bqdo_ptr),		"?do",		BI_QDO,
	(token_t)(&bbranch_ptrs[0]),		"br",		BI_BR,
	(token_t)(&bbranch_ptrs[1]),		"qbr",		BI_QBR,
	(token_t)(&bbranch_ptrs[2]),		"bof",		BI_BOF,
	(token_t)(&do_loop_ptr),		"loop",		BI_LOOP,
	(token_t)(&do_ploop_ptr),		"+loop",	BI_PLOOP,
	(token_t)(&to_ptr),			"to",		BI_NOOP,
	(token_t)(&semi_ptr),			";",		BI_SEMI,
	(token_t)(&do_colon),			":",		BI_COLON,
	(token_t)(&tlit_ptr),			"[']",		BI_NOOP,
	(token_t)(&do_leave_ptr),		"leave",	BI_NOTYET,
	(token_t)(&create_ptr),			"create",	BI_NOTYET,
	(token_t)(&does_ptr),			"does>",	BI_NOTYET,
	(token_t)(&value_defines[0][0]),	"a.@",		BI_NOTYET,
	(token_t)(&value_defines[0][1]),	"a.!",		BI_NOTYET,
	(token_t)(&value_defines[0][2]),	"a.nop",	BI_NOTYET,
	(token_t)(&value_defines[1][0]),	"a.i@",		BI_NOTYET,
	(token_t)(&value_defines[1][1]),	"a.i!",		BI_NOTYET,
	(token_t)(&value_defines[1][2]),	"a.iad",	BI_NOTYET,
	(token_t)(&value_defines[2][0]),	"a.defer",	BI_NOTYET,
	(token_t)(&value_defines[2][1]),	"a.@",		BI_NOTYET,
	(token_t)(&value_defines[2][2]),	"a.nop",	BI_NOTYET,
	(token_t)(&value_defines[3][0]),	"a.defexec",	BI_NOTYET,
	(token_t)(&value_defines[3][1]),	"a.iset",	BI_NOTYET,
	(token_t)(&value_defines[3][2]),	"a.iad",	BI_NOTYET,
	(token_t)(&value_defines[4][0]),	"a.binit",	BI_NOTYET,
	(token_t)(&value_defines[4][1]),	"a.2drop",	BI_NOTYET,
	(token_t)(&value_defines[4][2]),	"a.nop",	BI_NOTYET,
	(token_t)(&value_defines[5][0]),	"a.ibinit",	BI_NOTYET,
	(token_t)(&value_defines[5][1]),	"a.2drop",	BI_NOTYET,
	(token_t)(&value_defines[5][2]),	"a.iad",	BI_NOTYET,
	0
};

struct bitab *
lookup_builtin(token_t builtin)
{
	int i;

	for (i = 0; bitab[i].bi_ptr; i++)
		if (bitab[i].bi_ptr == builtin)
			return (&bitab[i]);
	return (NULL);
}

static void
paren_see(fcode_env_t *env)
{
	acf_t save_acf = (acf_t)POP(DS);
	acf_t acf = save_acf;
	int i, n, pass;
	token_t brtab[30], thentab[30], brstk[30];
	int nbrtab = 0, nthentab = 0, nbrstk = 0;
	uchar_t *p;
	int level = 0, doprintlevel = 1, nthen;
	struct bitab *bip;
	token_t last_lit = 0, case_lit = 0, endof_loc = 0, endcase_loc = 0;

	if ((bip = lookup_builtin(*acf)) == NULL ||
	    bip->bi_type != BI_COLON) {
		if (bip = lookup_builtin((token_t)acf))
			log_message(MSG_INFO, "%s: builtin\n", bip->bi_name);
		else
			log_message(MSG_INFO, "%s: builtin\n",
			    acf_to_name(env, acf));
		return;
	}
	log_message(MSG_INFO, ": %s", acf_to_name(env, acf));
	for (pass = 0; pass < 2; pass++) {
		acf = save_acf;
		for (acf++; ; acf++) {
			if (pass) {
				print_level(level, &doprintlevel);
				for (nthen = 0; nthentab > 0 &&
				    thentab[nthentab-1] == (token_t)acf;
				    nthentab--)
					nthen++;
				if (nthen) {
					level -= nthen;
					doprintlevel = 1;
					print_level(level, &doprintlevel);
					for (i = 0; i < nthen; i++)
						log_message(MSG_INFO, "then ");
				}
				print_level(level, &doprintlevel);
				for (i = 0; i < nbrtab; i += 2)
					if ((token_t)acf == brtab[i]) {
						log_message(MSG_INFO, "begin ");
						brstk[nbrstk++] = brtab[i+1];
						level++;
						doprintlevel = 1;
					}
				print_level(level, &doprintlevel);
				if (case_lit == (token_t)acf) {
					log_message(MSG_INFO, "case ");
					doprintlevel = 1;
					print_level(level, &doprintlevel);
				}
				if (endof_loc == (token_t)acf) {
					log_message(MSG_INFO, "endof ");
					doprintlevel = 1;
					print_level(level, &doprintlevel);
				}
				if (endcase_loc == (token_t)acf) {
					doprintlevel = 1;
					print_level(level, &doprintlevel);
					log_message(MSG_INFO, "endcase ");
				}
			}
			if ((bip = lookup_builtin((token_t)*acf)) == 0) {
				last_lit = (token_t)acf;
				if (pass)
					log_message(MSG_INFO, "%s ",
					    acf_to_name(env, (acf_t)*acf));
				continue;
			}
			if (bip->bi_type == BI_SEMI) {
				if (pass) {
					log_message(MSG_INFO, "\n");
					log_message(MSG_INFO, "%s\n",
					    bip->bi_name);
				}
				break;
			}
			switch (bip->bi_type) {

			case BI_NOOP:
			case BI_NOTYET:
				if (pass)
					log_message(MSG_INFO, "%s ",
					    bip->bi_name);
				break;

			case BI_QUOTE:
				if (pass)
					log_message(MSG_INFO, "\" ");
				acf++;
				p = (uchar_t *)acf;
				n = *p++;
				if (pass)
					log_message(MSG_INFO, "%s\" ", p);
				p += n + 1;
				for (; ((token_t)(p)) & (sizeof (token_t) - 1);
				    p++)
					;
				acf = (acf_t)p;
				acf--;
				break;

			case BI_BLIT:
				acf++;
				if (pass)
					log_message(MSG_INFO, "%x ", *acf);
				break;

			case BI_BDO:
			case BI_QDO:
				if (pass) {
					log_message(MSG_INFO, "%s ",
					    bip->bi_name);
					doprintlevel = 1;
					level++;
				}
				acf++;
				break;

			case BI_BR:
				acf++;
				if (pass) {
					if (*acf < (token_t)acf) {
						if (nbrstk) {
							doprintlevel = 1;
							level--;
							print_level(level,
							    &doprintlevel);
							log_message(MSG_INFO,
							    "repeat ");
							nbrstk--;
						} else
							log_message(MSG_INFO,
							    "[br back?]");
					} else if (nthentab) {
						doprintlevel = 1;
						print_level(level - 1,
						    &doprintlevel);
						log_message(MSG_INFO, "else ");
						doprintlevel = 1;
						thentab[nthentab - 1] = *acf;
					}
				} else {
					if (*acf < (token_t)acf) {
						brtab[nbrtab++] = *acf;
						brtab[nbrtab++] = (token_t)acf;
					}
					if (endcase_loc == 0 &&
					    case_lit) {
						endcase_loc = *acf;
					}
				}
				break;

			case BI_QBR:
				acf++;
				if (pass) {
					if (*acf < (token_t)acf) {
						if (nbrstk) {
							doprintlevel = 1;
							level--;
							print_level(level,
							    &doprintlevel);
							log_message(MSG_INFO,
							    "until ");
							nbrstk--;
						} else
							log_message(MSG_INFO,
							    "[br back?]");
					} else if (nbrstk > 0 &&
					    *acf >= brstk[nbrstk - 1]) {
						doprintlevel = 1;
						print_level(level - 1,
						    &doprintlevel);
						log_message(MSG_INFO,
						    "while ");
						doprintlevel = 1;
					} else {
						log_message(MSG_INFO, "if ");
						doprintlevel = 1;
						level++;
						thentab[nthentab++] = *acf;
					}
				} else if (*acf < (token_t)acf) {
					brtab[nbrtab++] = *acf;
					brtab[nbrtab++] = (token_t)acf;
				}
				break;

			case BI_BOF:
				acf++;
				if (pass) {
					log_message(MSG_INFO, "of ");
					endof_loc = *acf;
				} else if (case_lit == 0) {
					case_lit = last_lit;
				}
				break;

			case BI_LOOP:
			case BI_PLOOP:
				if (pass) {
					level--;
					doprintlevel = 1;
					print_level(level, &doprintlevel);
					log_message(MSG_INFO, "%s ",
					    bip->bi_name);
				}
				acf++;
				break;

			default:
				log_message(MSG_ERROR, "Invalid builtin %s\n",
				    bip->bi_name);
			}
		}
	}
}

static void
see(fcode_env_t *env)
{
	fstack_t d;

	parse_word(env);
	dollar_find(env);
	d = POP(DS);
	if (d)
		paren_see(env);
	else {
		log_message(MSG_WARN, "?");
		two_drop(env);
	}
}

static acf_t
do_dot_calls(fcode_env_t *env, acf_t acf, void *cacf)
{
	token_t *dptr = ACF_TO_LINK(acf);
	token_t *wptr = acf;

	if (*wptr == (token_t)(&do_colon)) {
		do {
			if ((acf_t)(*wptr) == (acf_t)cacf)
				output_acf_name(acf);
		} while (*wptr++ != (token_t)(&semi_ptr));
	} else if ((acf_t)(*wptr) == cacf)
		output_acf_name(acf);
	else if (wptr == (token_t *)cacf)
		output_acf_name(acf);
	return (NULL);
}

static void
dot_calls(fcode_env_t *env)
{
	acf_t acf = (acf_t)POP(DS);

	search_all_dictionaries(env, do_dot_calls, acf);
	output_acf_name(NULL);
}

static void
dot_pci_space(fcode_env_t *env)
{
	fstack_t d = POP(DS);

	switch ((d >> 24) & 0x3) {
	case 0: log_message(MSG_INFO, "Config,"); break;
	case 1: log_message(MSG_INFO, "IO,"); break;
	case 2: log_message(MSG_INFO, "Memory32,"); break;
	case 3: log_message(MSG_INFO, "Memory64,"); break;
	}
	if (d & 0x80000000)
		log_message(MSG_INFO, "Not_reloc,");
	if (d & 0x400000000)
		log_message(MSG_INFO, "Prefetch,");
	if (d & 0x200000000)
		log_message(MSG_INFO, "Alias,");
	log_message(MSG_INFO, "Bus%d,", (d >> 16) & 0xff);
	log_message(MSG_INFO, "Dev%d,", (d >> 11) & 0x1f);
	log_message(MSG_INFO, "Func%d,", (d >> 8) & 0x7);
	log_message(MSG_INFO, "Reg%x", d & 0xff);
	log_message(MSG_INFO, "\n");
}

void
fcode_debug(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)(&env->fcode_debug));
}

static void
base_addr(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)env->base);
}

static int mw_valid;
static int mw_size;
static void *mw_addr;
static fstack_t mw_value;
static fstack_t mw_lastvalue;

static fstack_t
mw_fetch(void)
{
	switch (mw_size) {
	case 1: return (*((uint8_t *)mw_addr));
	case 2: return (*((uint16_t *)mw_addr));
	case 4: return (*((uint32_t *)mw_addr));
	case 8: return (*((uint64_t *)mw_addr));
	}
	return (0);
}

void
do_memory_watch(fcode_env_t *env)
{
	fstack_t value;

	if (!mw_valid)
		return;
	value = mw_fetch();
	if (value != mw_lastvalue) {
		if (mw_valid == 1 || mw_value == value) {
			log_message(MSG_INFO,
			    "memory-watch: %p/%d: %llx -> %llx\n",
			    mw_addr, mw_size, (uint64_t)mw_lastvalue,
			    (uint64_t)value);
			do_fclib_step(env);
		}
		mw_lastvalue = value;
	}
}

static void
set_memory_watch(fcode_env_t *env, int type, int size, void *addr,
    fstack_t value)
{
	switch (size) {
	case 1: case 2: case 4: case 8:
		break;
	default:
		log_message(MSG_ERROR, "set_memory_watch: invalid size: %d\n",
		    size);
		return;
	}
	mw_valid = type;
	mw_size = size;
	mw_addr = addr;
	mw_value = value;
	mw_lastvalue = mw_fetch();
}

static void
memory_watch(fcode_env_t *env)
{
	int size = POP(DS);
	void *addr = (void *)POP(DS);

	set_memory_watch(env, 1, size, addr, 0);
}

static void
memory_watch_value(fcode_env_t *env)
{
	int size = POP(DS);
	void *addr = (void *)POP(DS);
	fstack_t value = POP(DS);

	set_memory_watch(env, 2, size, addr, value);
}

static void
memory_watch_clear(fcode_env_t *env)
{
	mw_valid = 0;
}

static void
vsearch(fcode_env_t *env)
{
	fstack_t value;
	int size = POP(DS);
	fstack_t match_value = POP(DS);
	uchar_t *toaddr = (uchar_t *)POP(DS);
	uchar_t *fromaddr = (uchar_t *)POP(DS);

	log_message(MSG_INFO, "%p to %p by %d looking for %llx\n", fromaddr,
	    toaddr, size, (uint64_t)match_value);
	for (; fromaddr < toaddr; fromaddr += size) {
		switch (size) {
		case 1: value = *((uint8_t *)fromaddr); break;
		case 2: value = *((uint16_t *)fromaddr); break;
		case 4: value = *((uint32_t *)fromaddr); break;
		case 8: value = *((uint64_t *)fromaddr); break;
		default:
			log_message(MSG_INFO, "Invalid size: %d\n", size);
			return;
		}
		if (value == match_value)
			log_message(MSG_INFO, "%p\n", fromaddr);
	}
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	FORTH(IMMEDIATE,	"words",		words);
	FORTH(IMMEDIATE,	"dump-words",		dump_words);
	FORTH(IMMEDIATE,	"dump-dict",		dump_dictionary);
	FORTH(IMMEDIATE,	"dump-table",		dump_table);
	FORTH(0,		"debugf",		debugf);
	FORTH(0,		".debugf",		dot_debugf);
	FORTH(0,		"set-debugf",		set_debugf);
	FORTH(0,		"debugf?",		debugf_qmark);
	FORTH(0,		"control",		control);
	FORTH(0,		"dump",			dump);
	FORTH(IMMEDIATE,	"showstack",		show_stack);
	FORTH(IMMEDIATE,	"sifting",		sifting);
	FORTH(IMMEDIATE,	"ctrace",		ctrace);
	FORTH(IMMEDIATE,	"ftrace",		ftrace);
	FORTH(0,		"see",			see);
	FORTH(0,		"(see)",		paren_see);
	FORTH(0,		"base-addr",		base_addr);
	FORTH(0,		"smatch",		smatch);
	FORTH(0,		".calls",		dot_calls);
	FORTH(0,		".pci-space",		dot_pci_space);
	FORTH(0,		"(debug)",		paren_debug);
	FORTH(0,		"debug",		debug);
	FORTH(0,		".debug",		dot_debug);
	FORTH(0,		"undebug",		undebug);
	FORTH(0,		"memory-watch",		memory_watch);
	FORTH(0,		"memory-watch-value",	memory_watch_value);
	FORTH(0,		"memory-watch-clear",	memory_watch_clear);
	FORTH(0,		"vsearch",		vsearch);
}
