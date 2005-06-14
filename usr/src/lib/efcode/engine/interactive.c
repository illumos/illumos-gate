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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <setjmp.h>
#include <sys/stat.h>

#include <fcode/private.h>
#include <fcode/log.h>

void (*to_ptr)(fcode_env_t *env) = do_set_action;
jmp_buf *jmp_buf_ptr = NULL;

char *
parse_a_string(fcode_env_t *env, int *lenp)
{
	parse_word(env);
	return (pop_a_string(env, lenp));
}

void
constant(fcode_env_t *env)
{
	char *name;
	int len;

	name = parse_a_string(env, &len);
	env->instance_mode = 0;
	make_common_access(env, name, len, 1, 0,
	    &do_constant, &do_constant, NULL);
}

void
buffer_colon(fcode_env_t *env)
{
	char *name;
	int len;

	PUSH(DS, 0);
	name = parse_a_string(env, &len);
	make_common_access(env, name, len, 2,
	    env->instance_mode, &noop, &noop, &set_buffer_actions);
}

void
value(fcode_env_t *env)
{
	char *name;
	int len;

	name = parse_a_string(env, &len);
	make_common_access(env, name, len, 1,
	    env->instance_mode, &noop, &noop, &set_value_actions);
}

void
variable(fcode_env_t *env)
{
	char *name;
	int len;

	PUSH(DS, 0);
	name = parse_a_string(env, &len);
	make_common_access(env, name, len, 1,
	    env->instance_mode, &instance_variable, &do_create, NULL);
}

void
defer(fcode_env_t *env)
{
	static void (*crash_ptr)(fcode_env_t *env) = do_crash;
	char *name;
	int len;

	PUSH(DS, (fstack_t)&crash_ptr);
	name = parse_a_string(env, &len);
	make_common_access(env, name, len, 1,
		env->instance_mode, &noop, &noop, &set_defer_actions);
}

void
field(fcode_env_t *env)
{
	char *name;
	int len;

	over(env);
	name = parse_a_string(env, &len);
	make_common_access(env, name, len, 1, 0, &do_field, &do_field, NULL);
	add(env);
}

void
bye(fcode_env_t *env)
{
	exit(0);
}

void
do_resume(fcode_env_t *env)
{
	if (env->interactive) env->interactive--;
	COMPLETE_INTERRUPT;
}

/*
 * In interactive mode, jmp_buf_ptr should be non-null.
 */
void
return_to_interact(fcode_env_t *env)
{
	if (jmp_buf_ptr)
		longjmp(*jmp_buf_ptr, 1);
}

void
do_interact(fcode_env_t *env)
{
	int level;
	jmp_buf jmp_env;
	jmp_buf *ojmp_ptr;
	error_frame new;
	input_typ *old_input = env->input;

	log_message(MSG_INFO, "Type resume to return\n");
	env->interactive++;
	level = env->interactive;

	ojmp_ptr = jmp_buf_ptr;
	jmp_buf_ptr = &jmp_env;
	env->input->separator = ' ';
	env->input->maxlen = 256;
	env->input->buffer = MALLOC(env->input->maxlen);
	env->input->scanptr = env->input->buffer;

	if (setjmp(jmp_env)) {
		if (in_forth_abort > 1) {
			RS = env->rs0;
			DS = env->ds0;
			MYSELF = 0;
			IP = 0;
			env->input = old_input;
			env->order_depth = 0;
		} else {
			RS		= new.rs;
			DS		= new.ds;
			MYSELF		= new.myself;
			IP		= new.ip;
			env->input	= old_input;
		}
		do_forth(env);
		do_definitions(env);
		in_forth_abort = 0;
	} else {
		new.rs		= RS;
		new.ds		= DS;
		new.myself	= MYSELF;
		new.ip		= IP;
	}

	while (env->interactive == level) {
		int wlen;
		char *p;

		DEBUGF(SHOW_RS, output_return_stack(env, 0, MSG_FC_DEBUG));
		DEBUGF(SHOW_STACK, output_data_stack(env, MSG_FC_DEBUG));

#define	USE_READLINE
#ifdef USE_READLINE
		{
			char *line;
			void read_line(fcode_env_t *);

			read_line(env);
			if ((line = pop_a_string(env, NULL)) == NULL)
				continue;

			env->input->scanptr = strcpy(env->input->buffer, line);
		}
#else
		if (isatty(fileno(stdin)))
			printf("ok ");

		env->input->scanptr = fgets(env->input->buffer,
		    env->input->maxlen, stdin);

		if (feof(stdin))
			break;

		if (env->input->scanptr == NULL)
			continue;
#endif

		if ((p = strpbrk(env->input->scanptr, "\n\r")) != NULL)
			*p = '\0';

		if ((wlen = strlen(env->input->scanptr)) == 0)
			continue;

		PUSH(DS, (fstack_t)env->input->buffer);
		PUSH(DS, wlen);
		evaluate(env);
	}

	jmp_buf_ptr = ojmp_ptr;
	FREE(env->input->buffer);
}

static void
temp_base(fcode_env_t *env, fstack_t base)
{
	fstack_t obase;

	obase = env->num_base;
	env->num_base = base;
	parse_word(env);
	evaluate(env);
	env->num_base = obase;
}

static void
temp_decimal(fcode_env_t *env)
{
	temp_base(env, 10);
}

static void
temp_hex(fcode_env_t *env)
{
	temp_base(env, 0x10);
}

static void
temp_binary(fcode_env_t *env)
{
	temp_base(env, 2);
}

static void
do_hex(fcode_env_t *env)
{
	env->num_base = 0x10;
}

static void
do_decimal(fcode_env_t *env)
{
	env->num_base = 10;
}

static void
do_binary(fcode_env_t *env)
{
	env->num_base = 2;
}

static void
do_clear(fcode_env_t *env)
{
	DS = env->ds0;
}

static void
action_one(fcode_env_t *env)
{

	do_tick(env);
	if (env->state) {
		COMPILE_TOKEN(&to_ptr);
	} else {
		PUSH(DS, 1);
		perform_action(env);
	}
}

void
do_if(fcode_env_t *env)
{
	branch_common(env, 1, 1, 0);
}

void
do_else(fcode_env_t *env)
{
	branch_common(env, 1, 0, 1);
	bresolve(env);
}

void
do_then(fcode_env_t *env)
{
	bresolve(env);
}

void
do_of(fcode_env_t *env)
{
	branch_common(env, 0, 2, 0);
}

void
load_file(fcode_env_t *env)
{
	int fd;
	int len, n;
	char *name;
	char *buffer;
	struct stat buf;

	CHECK_DEPTH(env, 2, "load-file");
	name = pop_a_string(env, &len);
	log_message(MSG_INFO, "load_file: '%s'\n", name);
	fd = open(name, O_RDONLY);
	if (fd < 0) {
		forth_perror(env, "Can't open '%s'", name);
	}
	fstat(fd, &buf);
	len = buf.st_size;
	buffer = MALLOC(len);
	if (buffer == 0)
		forth_perror(env, "load_file: MALLOC(%d)", len);

	if ((n = read(fd, buffer, len)) < 0)
		forth_perror(env, "read error '%s'", name);

	close(fd);
	PUSH(DS, (fstack_t)buffer);
	PUSH(DS, (fstack_t)n);
}

void
load(fcode_env_t *env)
{
	parse_word(env);
	if (TOS > 0)
		load_file(env);
}

void
fevaluate(fcode_env_t *env)
{
	char *buffer;
	int bytes, len;

	two_dup(env);
	buffer = pop_a_string(env, &len);
	for (bytes = 0; bytes < len; bytes++) {
		if ((buffer[bytes] == '\n') || (buffer[bytes] == '\r'))
			buffer[bytes] = ' ';
	}
	evaluate(env);
}

void
fload(fcode_env_t *env)
{
	char *buffer;

	load(env);
	two_dup(env);
	buffer = pop_a_string(env, NULL);
	fevaluate(env);
	FREE(buffer);
}

#include <sys/termio.h>

#define	MAX_LINE_BUF	20

static char *history_lines[MAX_LINE_BUF];
int num_lines = 0;

static void
add_line_to_history(fcode_env_t *env, char *line)
{
	int i;

	if (num_lines < MAX_LINE_BUF)
		history_lines[num_lines++] = STRDUP(line);
	else {
		FREE(history_lines[0]);
		for (i = 0; i < MAX_LINE_BUF - 1; i++)
			history_lines[i] = history_lines[i + 1];
		history_lines[MAX_LINE_BUF - 1] = STRDUP(line);
	}
}

static void
do_emit_chars(fcode_env_t *env, char c, int n)
{
	int i;

	for (i = 0; i < n; i++)
		do_emit(env, c);
}

static void
do_emit_str(fcode_env_t *env, char *str, int n)
{
	int i;

	for (i = 0; i < n; i++)
		do_emit(env, *str++);
}

static char *
find_next_word(char *cursor, char *eol)
{
	while (cursor < eol && *cursor != ' ')
		cursor++;
	while (cursor < eol && *cursor == ' ')
		cursor++;
	return (cursor);
}

static char *
find_prev_word(char *buf, char *cursor)
{
	int skippedword = 0;

	if (cursor == buf)
		return (cursor);
	cursor--;
	while (cursor > buf && *cursor == ' ')
		cursor--;
	while (cursor > buf && *cursor != ' ') {
		skippedword++;
		cursor--;
	}
	if (skippedword && *cursor == ' ')
		cursor++;
	return (cursor);
}

void
redraw_line(fcode_env_t *env, char *prev_l, char *prev_cursor, char *prev_eol,
    char *new_l, char *new_cursor, char *new_eol)
{
	int len;

	/* backup to beginning of previous line */
	do_emit_chars(env, '\b', prev_cursor - prev_l);

	/* overwrite new line */
	do_emit_str(env, new_l, new_eol - new_l);

	/* Output blanks to erase previous line chars if old line was longer */
	len = max(0, (prev_eol - prev_l) - (new_eol - new_l));
	do_emit_chars(env, ' ', len);

	/* Backup cursor for new line */
	do_emit_chars(env, '\b', len + (new_eol - new_cursor));
}

#define	MAX_LINE_SIZE	256

static void
do_save_buf(char *save_buf, char *buf, int n)
{
	n = max(0, min(n, MAX_LINE_SIZE));
	memcpy(save_buf, buf, n);
	save_buf[n] = '\0';
}

char prompt_string[80] = "ok ";

void
read_line(fcode_env_t *env)
{
	char buf[MAX_LINE_SIZE+1], save_buf[MAX_LINE_SIZE+1];
	char save_line[MAX_LINE_SIZE+1];
	char *p, *cursor, *eol, *tp, *cp;
	fstack_t d;
	int saw_esc = 0, do_quote = 0, i, cur_line, len, my_line, save_cursor;
	struct termio termio, savetermio;

	if (!isatty(fileno(stdin))) {
		fgets(buf, sizeof (buf), stdin);
		push_string(env, buf, strlen(buf));
		return;
	}
	printf(prompt_string);
	fflush(stdout);
	ioctl(fileno(stdin), TCGETA, &termio);
	savetermio = termio;
	termio.c_lflag &= ~(ICANON|ECHO|ECHOE|IEXTEN);
	termio.c_cc[VTIME] = 0;
	termio.c_cc[VMIN] = 1;
	ioctl(fileno(stdin), TCSETA, &termio);
	my_line = cur_line = num_lines;
	save_buf[0] = '\0';
	for (cursor = eol = buf; ; ) {
		for (d = FALSE; d == FALSE; d = POP(DS))
			keyquestion(env);
		key(env);
		d = POP(DS);
		if (do_quote) {
			do_quote = 0;
			if ((cursor - buf) < MAX_LINE_SIZE) {
				*cursor++ = d;
				if (cursor > eol)
					eol = cursor;
				do_emit(env, d);
			}
			continue;
		}
		if (saw_esc) {
			saw_esc = 0;
			switch (d) {

			default:		/* Ignore anything else */
				continue;

			case 'b':	/* Move backward one word */
			case 'B':
				tp = find_prev_word(buf, cursor);
				if (tp < cursor) {
					do_emit_chars(env, '\b', cursor - tp);
					cursor = tp;
				}
				continue;

			case 'f':	/* Move forward one word */
			case 'F':
				tp = find_next_word(cursor, eol);
				if (tp > cursor) {
					do_emit_str(env, tp, tp - cursor);
					cursor = tp;
				}
				continue;

			case 'h':	/* Erase from beginning of word to */
			case 'H':	/* just before cursor, saving chars */
				d = CTRL('w');
				break;

			case 'd':
			case 'D':
				tp = find_next_word(cursor, eol);
				if (tp <= cursor)
					continue;
				len = tp - cursor;
				do_save_buf(save_buf, cursor, len);
				memmove(cursor, tp, eol - tp);
				redraw_line(env, buf, cursor, eol, buf, cursor,
				    eol - len);
				eol -= len;
				continue;
			}
		}
		switch (d) {

		default:
			if ((cursor - buf) < MAX_LINE_SIZE) {
				*cursor++ = d;
				if (cursor > eol)
					eol = cursor;
				do_emit(env, d);
			}
			continue;

		case CTRL('['):		/* saw esc. character */
			saw_esc = 1;
			continue;

		case CTRL('f'):		/* move forward one char */
			if (cursor < eol)
				do_emit(env, *cursor++);
			continue;

		case CTRL('a'):		/* cursor to beginning of line */
			do_emit_chars(env, '\b', cursor - buf);
			cursor = buf;
			continue;

		case CTRL('e'):		/* cursor to end of line */
			do_emit_str(env, cursor, eol - cursor);
			cursor = eol;
			continue;


		case CTRL('n'):		/* Move to next line in buffer */
		case CTRL('p'):		/* Move to previous line in buffer */
			if (d == CTRL('p')) {
				if (cur_line <= 0)
					continue;
				if (my_line == cur_line) {
					do_save_buf(save_line, buf, eol - buf);
					save_cursor = cursor - buf;
				}
				cur_line--;
			} else {
				if (cur_line >= num_lines)
					continue;
				cur_line++;
				if (cur_line == num_lines) {
					len = strlen(save_line);
					redraw_line(env, buf, cursor, eol,
					    save_line, save_line + save_cursor,
					    save_line + len);
					strcpy(buf, save_line);
					eol = buf + len;
					cursor = buf + save_cursor;
					continue;
				}
			}
			p = history_lines[cur_line];
			len = strlen(p);
			redraw_line(env, buf, cursor, eol, p, p, p + len);
			strcpy(buf, history_lines[cur_line]);
			cursor = buf;
			eol = buf + len;
			continue;

		case CTRL('o'):		/* Insert newline */
			continue;

		case CTRL('k'):		/* Erase from cursor to eol, saving */
					/* chars, at eol, joins two lines */
			if (cursor == eol) {
				if (cur_line >= num_lines)
					continue;
				if (cur_line == num_lines - 1) {
					p = save_line;
					len = strlen(save_line);
					num_lines -= 1;
					my_line = num_lines;
				} else {
					cur_line++;
					p = history_lines[cur_line];
					len = strlen(p);
				}
				len = min(len, MAX_LINE_SIZE - (eol - buf));
				memcpy(eol, p, len);
				redraw_line(env, buf, cursor, eol, buf, cursor,
				    eol + len);
				eol += len;
				continue;
			}
			do_save_buf(save_buf, cursor, eol - cursor);
			redraw_line(env, buf, cursor, eol, buf, cursor,
			    cursor);
			eol = cursor;
			continue;

		case CTRL('w'):		/* Erase word */
			tp = find_prev_word(buf, cursor);
			if (tp == cursor)
				continue;
			len = cursor - tp;
			do_save_buf(save_buf, tp, len);
			memmove(tp, cursor, eol - cursor);
			redraw_line(env, buf, cursor, eol, buf, cursor - len,
			    eol - len);
			eol -= len;
			cursor -= len;
			continue;

		case CTRL('u'):		/* Erases line, saving chars */
			do_save_buf(save_buf, buf, eol - buf);
			redraw_line(env, buf, cursor, eol, buf, buf, buf);
			cursor = buf;
			eol = buf;
			continue;

		case CTRL('y'):		/* Insert save buffer before cursor */
			len = min(strlen(save_buf),
			    MAX_LINE_SIZE - (eol - buf));
			if (len == 0)
				continue;
			memmove(cursor + len, cursor, eol - cursor);
			memcpy(cursor, save_buf, len);
			redraw_line(env, buf, cursor, eol, buf, cursor + len,
			    eol + len);
			cursor += len;
			eol += len;
			continue;

		case CTRL('q'):		/* Quote next char */
			do_quote = 1;
			continue;

		case CTRL('l'):		/* Display edit buffer */
			do_emit(env, '\n');
			for (i = 0; i < num_lines; i++) {
				do_emit_str(env, history_lines[i],
				    strlen(history_lines[i]));
				do_emit(env, '\n');
			}
			redraw_line(env, buf, buf, buf, buf, cursor, eol);
			continue;

		case CTRL('r'):		/* redraw line */
			redraw_line(env, buf, cursor, eol, buf, cursor, eol);
			continue;

		case CTRL('c'):		/* Exit script editor */
			continue;

		case CTRL('b'):		/* backup cursor */
			if (cursor <= buf)
				continue;
			cursor--;
			do_emit(env, '\b');
			continue;

		case CTRL('h'):		/* Backspace */
		case 0x7f:		/* DEL */
			if (cursor <= buf)
				continue;
			memmove(cursor - 1, cursor, eol - cursor);
			redraw_line(env, buf, cursor, eol, buf, cursor - 1,
			    eol - 1);
			cursor--;
			eol--;
			continue;

		case '\r':
		case '\n':
			*eol = '\0';
			do_emit(env, '\n');
			break;
		}
		break;
	}
	add_line_to_history(env, buf);
	ioctl(fileno(stdin), TCSETA, &savetermio);
	push_string(env, buf, strlen(buf));
}

static void
set_prompt(fcode_env_t *env)
{
	char *prompt;

	if ((prompt = parse_a_string(env, NULL)) != NULL)
		strncpy(prompt_string, prompt, sizeof (prompt_string));
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	FORTH(IMMEDIATE,	"if",			do_if);
	FORTH(IMMEDIATE,	"else",			do_else);
	FORTH(IMMEDIATE,	"then",			do_then);
	FORTH(IMMEDIATE,	"case",			bcase);
	FORTH(IMMEDIATE,	"of",			do_of);
	FORTH(IMMEDIATE,	"endof",		do_else);
	FORTH(IMMEDIATE,	"endcase",		bendcase);
	FORTH(IMMEDIATE,	"value",		value);
	FORTH(IMMEDIATE,	"variable",		variable);
	FORTH(IMMEDIATE,	"constant",		constant);
	FORTH(IMMEDIATE,	"defer",		defer);
	FORTH(IMMEDIATE,	"buffer:",		buffer_colon);
	FORTH(IMMEDIATE,	"field",		field);
	FORTH(IMMEDIATE,	"struct",		zero);
	FORTH(IMMEDIATE,	"to",			action_one);
	FORTH(IMMEDIATE,	"d#",			temp_decimal);
	FORTH(IMMEDIATE,	"h#",			temp_hex);
	FORTH(IMMEDIATE,	"b#",			temp_binary);
	FORTH(0,		"decimal",		do_decimal);
	FORTH(0,		"hex",			do_hex);
	FORTH(0,		"binary",		do_binary);
	FORTH(0,		"clear",		do_clear);
	FORTH(IMMEDIATE,	"bye",			bye);
	FORTH(0,		"interact",		do_interact);
	FORTH(IMMEDIATE,	"resume",		do_resume);
	FORTH(0,		"fload",		fload);
	FORTH(0,		"load",			load);
	FORTH(0,		"read-line",		read_line);
	FORTH(0,		"set-prompt",		set_prompt);
}
