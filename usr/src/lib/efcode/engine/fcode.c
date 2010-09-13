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
#include <string.h>
#include <ctype.h>

#include <fcode/private.h>
#include <fcode/log.h>

int fcode_impl_count = 0;

void (*crash_ptr)(fcode_env_t *env) = do_crash;

uchar_t
next_bytecode(fcode_env_t *env)
{
	uchar_t	byte;

	byte = *env->fcode_ptr;
	env->fcode_ptr += env->fcode_incr;
	return (byte);
}

ushort_t
get_next_token(fcode_env_t *env)
{
	ushort_t token = next_bytecode(env);
	if ((token) && (token < 0x10)) {
		token = (token << 8) | next_bytecode(env);
	}
	env->last_fcode = token;
	return (token);
}

ushort_t
get_short(fcode_env_t *env)
{
	ushort_t u;

	/*
	 * Logical or DOES NOT guarantee left to right evaluation...
	 */
	u = next_bytecode(env) << 8;
	return (u | next_bytecode(env));
}

uint_t
get_int(fcode_env_t *env)
{
	uint_t u;

	/*
	 * Logical or DOES NOT guarantee left to right evaluation...
	 */
	u = get_short(env) << 16;
	return (u | get_short(env));
}

void
expose_acf(fcode_env_t *env, char *name)
{
	if (name == NULL)
		name = "<unknown>";
	EXPOSE_ACF;
	debug_msg(DEBUG_CONTEXT, "CONTEXT:expose_acf: acf: %p/'%s' %p\n",
	    LINK_TO_ACF(env->lastlink), name, env->current);
}

void
do_code(fcode_env_t *env, int token, char *name, void (*fn)(fcode_env_t *))
{
	env->table[token].name = name;
	if (fn == NULL) {
		env->table[token].apf = NULL;
		env->table[token].name = name;
	} else {
		header(env, name, strlen(name), 0);
		env->table[token].apf = (acf_t)HERE;
		COMPILE_TOKEN(fn);
		expose_acf(env, name);
	}
}

void
define_word(fcode_env_t *env, int flag, char *name, void (*fn)(fcode_env_t *))
{
	header(env, name, strlen(name), flag);
	COMPILE_TOKEN(fn);
	expose_acf(env, name);
}

void
end0(fcode_env_t *env)
{
	env->interpretting = 0;
}

static void
end1(fcode_env_t *env)
{
	env->interpretting = 0;
}

void
blit(fcode_env_t *env)
{
	fstack_t d = (int)get_int(env);
	PUSH(DS, d);
	literal(env);
}

void (*bbranch_ptrs[3])(fcode_env_t *env) = {
	do_bbranch,
	do_bqbranch,
	do_bofbranch
};

void
branch_common(fcode_env_t *env, short direction, fstack_t which, int doswap)
{
	fstack_t *sp;
	token_t *branch_loc;

	ASSERT((which < 3) && (which >= 0));
	which = (fstack_t)&bbranch_ptrs[which];
	set_temporary_compile(env);
	COMPILE_TOKEN(which);
	if (direction >= 0) {
		bmark(env);
		if (doswap)
			swap(env);
		PUSH(DS, 0);
		compile_comma(env);
	} else {

		/*
		 * We look down the stack for a branch location
		 * that isn't pointing to zero (i.e. a forward branch label).
		 * We move the first one we find to the top of the stack,
		 * which is what gets compiled in with 'compile_comma'.
		 * Not finding a valid branch label is bad.
		 */
		for (sp = env->ds; sp >= env->ds0; sp--) {
			branch_loc = (token_t *)*sp;
			if (branch_loc && *branch_loc) {
				break;
			}
		}
		if (sp < env->ds0)
			log_message(MSG_ERROR, "branch_common: back: "
			    "no branch loc on stack\n");
		else {
			/* Move branch_loc to top of data stack */
			for (; sp < env->ds; sp++)
				*sp = sp[1];
			*sp = (fstack_t)branch_loc;
		}
		env->level--;
		compile_comma(env);
		temporary_execute(env);
	}
}

void
bbranch(fcode_env_t *env)
{
	short offset = (short)get_short(env);

	branch_common(env, offset, 0, 1);
}

void
bqbranch(fcode_env_t *env)
{
	short offset = (short)get_short(env);

	branch_common(env, offset, 1, 0);
}

void
do_quote(fcode_env_t *env)
{
	int len;
	uchar_t *strptr;

	strptr = (uchar_t *)IP;
	len = *strptr;
	PUSH(DS, (fstack_t)strptr+1);
	PUSH(DS, len);
	strptr += TOKEN_ROUNDUP(len+2);
	IP = (token_t *)strptr;
}

void
bquote(fcode_env_t *env)
{
	char stringbuff[256];
	int len, count;
	char *strptr;

	count = len = next_bytecode(env);
	if (env->state) {
		COMPILE_TOKEN(&quote_ptr);
		strptr = (char *)HERE;
		*strptr++ = len;
		while (count--)
			*strptr++ = next_bytecode(env);
		*strptr++ = 0;
		set_here(env, (uchar_t *)strptr, "bquote");
		token_roundup(env, "bquote");
	} else {
		strptr = stringbuff;
		while (count--)
			*strptr++ = next_bytecode(env);
		*strptr = 0;
		push_string(env, stringbuff, len);
	}
}

char *
get_name(token_t *linkp)
{
	char *name, *p;
	flag_t *fptr = LINK_TO_FLAGS(linkp);
	int len;
	char *cptr;

	if (*fptr & FLAG_NONAME)
		return (NULL);

	cptr = (char *)fptr;
	len = cptr[-1];
	if (len <= 0 || len > 64 || cptr[-2] != '\0')
		return (NULL);

	name = cptr - (len+2);

	for (p = name; *p != '\0'; p++)
		if (!isprint(*p))
			return (NULL);

	if ((p - name) != len)
		return (NULL);

	return (name);
}

void
header(fcode_env_t *env, char *name, int len, flag_t flag)
{
	char *strptr;
	flag_t *fptr;
	acf_t dptr;
	extern void add_debug_acf(fcode_env_t *, acf_t);

	/* Now form the entry in the dictionary */
	token_roundup(env, "header");
	dptr = (acf_t)HERE;
	if (len) {
		int bytes = len+2+sizeof (flag_t);
		dptr = (acf_t)(TOKEN_ROUNDUP(HERE+bytes));
		fptr = LINK_TO_FLAGS(dptr);
		strptr = (char *)fptr - 1;
		*strptr-- = len;
		*strptr-- = 0;
		while (len)
			*strptr-- = name[--len];
	} else {
		dptr++;
		fptr = LINK_TO_FLAGS(dptr);
		flag |= FLAG_NONAME;
	}
	*fptr = flag;
	*dptr = *((acf_t)env->current);
	env->lastlink = dptr++;
	set_here(env, (uchar_t *)dptr, "header");

	if (name_is_debugged(env, name)) {
		log_message(MSG_INFO, "Turning debug on for %s\n", name);
		add_debug_acf(env, LINK_TO_ACF(env->lastlink));
	}
	debug_msg(DEBUG_HEADER, "Define: '%s' @ %p\n", name, HERE);
}

void
token_common(fcode_env_t *env, int headered, int visible)
{
	char namebuff[32];
	int len, count, token;
	char *strptr, c;

	strptr = namebuff;
	if (headered) {
		len = next_bytecode(env);
		for (count = 0; count < len; count++) {
			c = next_bytecode(env);
			if (count < sizeof (namebuff))
				*strptr++ = c;
		}
	}

	if (!visible)
		len = 0;
	*strptr = 0;
	token = get_short(env);
	env->last_token = token;

	debug_msg(DEBUG_NEW_TOKEN, "Define %s token: '%s' (%x)\n",
	    (visible ? "named" : "headerless"), namebuff, token);

	header(env, namebuff, len, 0);
	env->table[token].flags = 0;
	if (len) {
		env->table[token].name = MALLOC(len+1);
		strncpy(env->table[token].name, namebuff, len);
	} else {
		env->table[token].name = NULL;
	}
	env->last_token = token;
}

void
named_token(fcode_env_t *env)
{
	token_common(env, 1, env->fcode_debug);
}

void
external_token(fcode_env_t *env)
{
	token_common(env, 1, 1);
}

void
new_token(fcode_env_t *env)
{
	token_common(env, 0, 0);
}

void
offset16(fcode_env_t *env)
{
	env->offset_incr = 2;
}

void
minus_one(fcode_env_t *env)
{
	PUSH(DS, -1);
}

void
zero(fcode_env_t *env)
{
	PUSH(DS, 0);
}

void
one(fcode_env_t *env)
{
	PUSH(DS, 1);
}

void
two(fcode_env_t *env)
{
	PUSH(DS, 2);
}

void
three(fcode_env_t *env)
{
	PUSH(DS, 3);
}

void
version1(fcode_env_t *env)
{
	env->fcode_incr = 1;
}

static void
start0(fcode_env_t *env)
{
	env->fcode_incr = 1;
}

static void
start1(fcode_env_t *env)
{
	env->fcode_incr = 1;
}

void
start2(fcode_env_t *env)
{
	env->fcode_incr = 2;
}

static void
start4(fcode_env_t *env)
{
	env->fcode_incr = 4;
}

int
check_fcode_header(char *fname, uchar_t *header, int len)
{
	uint32_t length;
	static char func_name[] = "check_fcode_header";

	if (len <= 8) {
		log_message(MSG_ERROR, "%s: '%s' fcode size (%d) <= 8\n",
		    func_name, fname, len);
		return (0);
	}
	if (header[0] != 0xf1 && header[0] != 0xfd) {
		log_message(MSG_ERROR, "%s: '%s' header[0] is 0x%02x not"
		    " 0xf1/0xfd\n", func_name, fname, header[0]);
		return (0);
	}
	length = (header[4] << 24) | (header[5] << 16) | (header[6] << 8) |
	    header[7];
	if (length > len) {
		log_message(MSG_ERROR, "%s: '%s' length (%d) >"
		    " fcode size (%d)\n", func_name, fname, length, len);
		return (0);
	}
	if (length < len) {
		log_message(MSG_WARN, "%s: '%s' length (%d) <"
		    " fcode size (%d)\n", func_name, fname, length, len);
	}
	return (1);
}

void
byte_load(fcode_env_t *env)
{
	uchar_t	*fcode_buffer;
	uchar_t	*fcode_ptr;
	int	fcode_incr;
	int	offset_incr;
	int	fcode_xt;
	int	interpretting;
	int	depth;
	int	length;
	int	past_eob = 0;
	int db;

	/* save any existing interpret state */
	fcode_buffer = env->fcode_buffer;
	fcode_ptr = env->fcode_ptr;
	fcode_incr = env->fcode_incr;
	offset_incr  = env->offset_incr;
	interpretting = env->interpretting;
	depth = DEPTH-2;

	/* Now init them */
	CHECK_DEPTH(env, 2, "byte-load");
	fcode_xt = POP(DS);
	env->fcode_ptr = env->fcode_buffer = (uchar_t *)POP(DS);
	if (fcode_xt != 1) {
		log_message(MSG_WARN, "byte-load: ignoring xt\n");
	}

	length = (env->fcode_buffer[4] << 24) | (env->fcode_buffer[5] << 16) |
	    (env->fcode_buffer[6] << 8) | env->fcode_buffer[7];
	if (!check_fcode_header("byte-load", env->fcode_ptr, length))
		log_message(MSG_WARN, "byte-load: header NOT OK\n");

	env->fcode_incr = 1;
	env->offset_incr = 1;
	env->interpretting = 1;
	env->level = 0;

	db = get_interpreter_debug_level() &
	    (DEBUG_BYTELOAD_DS|DEBUG_BYTELOAD_RS|DEBUG_BYTELOAD_TOKENS);
	debug_msg(db, "byte_load: %p, %d\n", env->fcode_buffer, fcode_xt);
	debug_msg(db, "   header: %x, %x\n",
	    env->fcode_buffer[0], env->fcode_buffer[1]);
	debug_msg(db, "      crc: %x\n",
	    (env->fcode_buffer[2]<<8)|(env->fcode_buffer[3]));
	debug_msg(db, "   length: %x\n", length);
	env->fcode_ptr += 8;

	debug_msg(db, "Interpretting: %d\n", env->interpretting);

	while (env->interpretting) {
		int token;
		fcode_token *entry;
		acf_t apf;

		if (!past_eob && env->fcode_ptr >= env->fcode_buffer + length) {
			log_message(MSG_WARN, "byte-load: past EOB\n");
			past_eob = 1;
		}

		env->last_fcode_ptr = env->fcode_ptr;
		token = get_next_token(env);

		entry = &env->table[token];
		apf   = entry->apf;

		DEBUGF(BYTELOAD_DS, output_data_stack(env, MSG_FC_DEBUG));
		DEBUGF(BYTELOAD_RS, output_return_stack(env, 1, MSG_FC_DEBUG));
		DEBUGF(BYTELOAD_TOKENS, log_message(MSG_FC_DEBUG,
		    "%s: %04x %03x %s (%x)",
		    ((env->state && (entry->flags & IMMEDIATE) == 0)) ?
		    "Compile" : "Execute",
		    env->last_fcode_ptr - env->fcode_buffer, token,
		    entry->name ? entry->name : "???", entry->flags));
		if (db)
			log_message(MSG_FC_DEBUG, "\n");
		if (apf) {
			DEBUGF(TOKEN_USAGE, entry->usage++);
			PUSH(DS, (fstack_t)apf);
			if ((env->state) &&
				((entry->flags & IMMEDIATE) == 0)) {
				/* Compile in references */
				compile_comma(env);
			} else {
				execute(env);
			}
		}
	}
	if (DEPTH != depth) {
		log_message(MSG_ERROR, "FCODE has net stack change of %d\n",
		    DEPTH-depth);
	}
	/* restore old state */
	env->fcode_ptr		= fcode_ptr;
	env->fcode_buffer	= fcode_buffer;
	env->fcode_incr		= fcode_incr;
	env->offset_incr	= offset_incr;
	env->interpretting	= interpretting;
}

void
btick(fcode_env_t *env)
{
	int token = get_next_token(env);

	PUSH(DS, (fstack_t)env->table[token].apf);
	tick_literal(env);
}

static void
show_fcode_def(fcode_env_t *env, char *type)
{
	int i = env->last_token;

	if (get_interpreter_debug_level() & DEBUG_DUMP_TOKENS) {
		if (env->table[i].name)
			log_message(MSG_INFO, "%s: %s %03x %p\n", type,
			    env->table[i].name, i, env->table[i].apf);
		else
			log_message(MSG_INFO, "%s: <noname> %03x %p\n", type, i,
			    env->table[i].apf);
	}
}

void
bcolon(fcode_env_t *env)
{
	if (env->state == 0) {
		env->table[env->last_token].apf = (acf_t)HERE;
		env->table[env->last_token].flags = 0;
		show_fcode_def(env, "bcolon");
	}
	env->state |= 1;
	COMPILE_TOKEN(&do_colon);
}

void
bcreate(fcode_env_t *env)
{
	env->table[env->last_token].apf = (acf_t)HERE;
	show_fcode_def(env, "bcreate");
	COMPILE_TOKEN(&do_create);
	expose_acf(env, "<bcreate>");
}

void
get_token_name(fcode_env_t *env, int token, char **name, int *len)
{
	*name = env->table[token].name;
	if (*name) {
		*len = strlen(*name);
	} else
		*len = 0;
}

void
bvalue(fcode_env_t *env)
{
	env->table[env->last_token].apf = (acf_t)HERE;
	show_fcode_def(env, "bvalue");
	make_common_access(env, 0, 0, 1,
	    env->instance_mode, &noop, &noop, &set_value_actions);
}

void
bvariable(fcode_env_t *env)
{
	env->table[env->last_token].apf = (acf_t)HERE;
	show_fcode_def(env, "bvariable");
	PUSH(DS, 0);
	make_common_access(env, 0, 0, 1,
	    env->instance_mode, &instance_variable, &do_create, NULL);
}

void
bconstant(fcode_env_t *env)
{
	env->table[env->last_token].apf = (acf_t)HERE;
	show_fcode_def(env, "bconstant");
	make_common_access(env, 0, 0, 1,
	    env->instance_mode, &do_constant, &do_constant, NULL);
}

void
bdefer(fcode_env_t *env)
{
	env->table[env->last_token].apf = (acf_t)HERE;
	show_fcode_def(env, "bdefer");

	PUSH(DS, (fstack_t)&crash_ptr);
	make_common_access(env, 0, 0, 1, env->instance_mode,
	    &noop, &noop, &set_defer_actions);
}

void
bbuffer_colon(fcode_env_t *env)
{
	env->table[env->last_token].apf = (acf_t)HERE;
	show_fcode_def(env, "buffer:");
	PUSH(DS, 0);
	make_common_access(env, 0, 0, 2, env->instance_mode,
	    &noop, &noop, &set_buffer_actions);
}

void
do_field(fcode_env_t *env)
{
	fstack_t *d;

	d = (fstack_t *)WA;
	TOS += *d;
}

void
bfield(fcode_env_t *env)
{
	env->table[env->last_token].apf = (acf_t)HERE;
	show_fcode_def(env, "bfield");
	COMPILE_TOKEN(&do_field);
	over(env);
	compile_comma(env);
	add(env);
	expose_acf(env, "<bfield>");
}

void
bto(fcode_env_t *env)
{
	btick(env);

	if (env->state) {
		COMPILE_TOKEN(&to_ptr);
	} else {
		do_set_action(env);
	}
}

void
get_token(fcode_env_t *env)
{
	fstack_t tok;
	fstack_t immediate = 0;

	CHECK_DEPTH(env, 1, "get-token");
	tok = POP(DS);
	tok &= MAX_FCODE;
	PUSH(DS, (fstack_t)env->table[tok].apf);
	if (env->table[tok].flags & IMMEDIATE) 	immediate = 1;
	PUSH(DS, immediate);
}

void
set_token(fcode_env_t *env)
{
	fstack_t tok;
	fstack_t immediate;
	acf_t acf;

	CHECK_DEPTH(env, 3, "set-token");
	tok = POP(DS);
	tok &= MAX_FCODE;
	immediate = POP(DS);
	acf = (acf_t)POP(DS);
	if (immediate)
		env->table[tok].flags |= IMMEDIATE;
	else
		env->table[tok].flags &= ~IMMEDIATE;
	env->table[tok].apf = acf;
	immediate = env->last_token;
	env->last_token = tok;
	show_fcode_def(env, "set_token");
	env->last_token = immediate;
}

void
bof(fcode_env_t *env)
{
	short offset = get_short(env);
	branch_common(env, offset, 2, 0);
}

void
bcase(fcode_env_t *env)
{
	env->level++;
	set_temporary_compile(env);
	PUSH(DS, 0);
}

void
bendcase(fcode_env_t *env)
{
	COMPILE_TOKEN(env->table[0x46].apf);	/* Hack for now... */
	while (TOS) {
		bresolve(env);
	}
	(void) POP(DS);
	env->level--;
	temporary_execute(env);
}

void
bendof(fcode_env_t *env)
{
	short offset = get_short(env);
	branch_common(env, offset, 0, 1);
	bresolve(env);
}

void
fcode_revision(fcode_env_t *env)
{
	/* We are Version 3.0 */
	PUSH(DS, 0x30000);
}

void
alloc_mem(fcode_env_t *env)
{
	CHECK_DEPTH(env, 1, "alloc-mem");
	TOS = (fstack_t)MALLOC((size_t)TOS);
	if (!TOS) {
		throw_from_fclib(env, 1, "alloc-mem failed");
	}
}

void
free_mem(fcode_env_t *env)
{
	void *p;

	CHECK_DEPTH(env, 2, "free-mem");
	(void) POP(DS);
	p = (void *) POP(DS);
	FREE(p);
}

void
parse_two_int(fcode_env_t *env)
{
	uint_t lo, hi;
	char *str;
	int len;

	CHECK_DEPTH(env, 2, "parse-2int");
	lo = 0;
	hi = 0;
	str = pop_a_string(env, &len);
	if (len) {
		if (sscanf(str, "%x,%x", &hi, &lo) != 2) {
			throw_from_fclib(env, 1, "parse_2int");
		}
	}
	PUSH(DS, lo);
	PUSH(DS, hi);
}

void
left_parse_string(fcode_env_t *env)
{
	char sep, *cptr, *lstr, *rstr;
	int len, llen, rlen;

	CHECK_DEPTH(env, 3, "left-parse-string");
	sep = (char)POP(DS);
	if (TOS == 0) {
		two_dup(env);
		return;
	}
	lstr = pop_a_string(env, &llen);
	len = 0;
	cptr = NULL;
	while (len < llen) {
		if (lstr[len] == sep) {
			cptr = lstr+len;
			break;
		}
		len++;
	}
	if (cptr != NULL) {
		rstr = cptr+1;
		rlen = lstr + llen - rstr;
		llen = len;
	} else {
		rlen = 0;
		rstr = lstr;
	}
	PUSH(DS, (fstack_t)rstr);
	PUSH(DS, rlen);
	PUSH(DS, (fstack_t)lstr);
	PUSH(DS, llen);
}

/*
 * (is-user-word)  ( name-str name-len xt -- )
 */
void
is_user_word(fcode_env_t *env)
{
	fstack_t xt;
	char *name;
	int len;

	CHECK_DEPTH(env, 3, "(is-user-word)");
	xt = POP(DS);
	name = pop_a_string(env, &len);
	header(env, name, len, 0);
	COMPILE_TOKEN(&do_alias);
	COMPILE_TOKEN(xt);
	expose_acf(env, name);
}

void
f_error(fcode_env_t *env)
{
#if 0
	env->interpretting = 0;
	log_message(MSG_ERROR, "Uniplemented FCODE token encountered %x\n",
	    env->last_fcode);
#else
	forth_abort(env, "Unimplemented FCODE token: 0x%x\n", env->last_fcode);
#endif
}

static void
fcode_buffer_addr(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)(env->fcode_buffer));
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	P1275(0x000, DEFINER,	"end0",			end0);
	P1275(0x010, DEFINER,	"b(lit)",		blit);
	P1275(0x011, DEFINER,	"b(')",			btick);
	P1275(0x012, DEFINER,	"b(\")",		bquote);
	P1275(0x013, DEFINER,	"bbranch",		bbranch);
	P1275(0x014, DEFINER,	"b?branch",		bqbranch);
	P1275(0x015, DEFINER,	"b(loop)",		bloop);
	P1275(0x016, DEFINER,	"b(+loop)",		bplusloop);
	P1275(0x017, DEFINER,	"b(do)",		bdo);
	P1275(0x018, DEFINER,	"b(?do)",		bqdo);
	P1275(0x01b, DEFINER,	"b(leave)",		bleave);
	P1275(0x01c, DEFINER,	"b(of)",		bof);

	P1275(0x087, 0,		"fcode-revision",	fcode_revision);

	P1275(0x08b, 0,		"alloc-mem",		alloc_mem);
	P1275(0x08c, 0,		"free-mem",		free_mem);

	P1275(0x0a4, 0,		"-1",			minus_one);
	P1275(0x0a5, 0,		"0",			zero);
	P1275(0x0a6, 0,		"1",			one);
	P1275(0x0a7, 0,		"2",			two);
	P1275(0x0a8, 0,		"3",			three);

	P1275(0x0ae, 0,		"aligned",		aligned);
	P1275(0x0b1, DEFINER,	"b(<mark)",		bmark);
	P1275(0x0b2, DEFINER,	"b(>resolve)",		bresolve);
	FCODE(0x0b3, 0,		"set-token-table",	fc_historical);
	FCODE(0x0b4, 0,		"set-table",		fc_historical);
	P1275(0x0b5, 0,		"new-token",		new_token);
	P1275(0x0b6, 0,		"named-token",		named_token);
	P1275(0x0b7, DEFINER,	"b(:)",			bcolon);
	P1275(0x0b8, DEFINER,	"b(value)",		bvalue);
	P1275(0x0b9, DEFINER,	"b(variable)",		bvariable);
	P1275(0x0ba, DEFINER,	"b(constant)",		bconstant);
	P1275(0x0bb, DEFINER,	"b(create)",		bcreate);
	P1275(0x0bc, DEFINER,	"b(defer)",		bdefer);
	P1275(0x0bd, 0,		"b(buffer:)",		bbuffer_colon);
	P1275(0x0be, 0,		"b(field)",		bfield);
	FCODE(0x0bf, 0,		"b(code)",		fc_historical);
	P1275(0x0c0, IMMEDIATE,	"instance",		instance);

	P1275(0x0c2, DEFINER,	"b(;)",			semi);
	P1275(0x0c3, DEFINER,	"b(to)",		bto);
	P1275(0x0c4, DEFINER,	"b(case)",		bcase);
	P1275(0x0c5, DEFINER,	"b(endcase)",		bendcase);
	P1275(0x0c6, DEFINER,	"b(endof)",		bendof);

	P1275(0x0ca, 0,		"external-token",	external_token);
	P1275(0x0cc, 0,		"offset16",		offset16);
	P1275(0x0cd, 0,		"evaluate",		evaluate);

	P1275(0x0da, 0,		"get-token",		get_token);
	P1275(0x0db, 0,		"set-token",		set_token);

	P1275(0x0f0, 0,		"start0",		start0);
	P1275(0x0f1, 0,		"start1",		start1);
	P1275(0x0f2, 0,		"start2",		start2);
	P1275(0x0f3, 0,		"start4",		start4);

	P1275(0x0fd, 0,		"version1",		version1);
	FCODE(0x0fe, 0,		"4-byte-id",		fc_historical);

	P1275(0x0ff, 0,		"end1",			end1);

	/* Call it "old-dma-alloc" so no one gets confused */
	FCODE(0x101, 0,		"old-dma-alloc",	fc_historical);

	FCODE(0x104, 0,		"memmap",		fc_historical);
	FCODE(0x105, 0,		"free-virtual",		fc_unimplemented);

	FCODE(0x106, 0,		">physical",		fc_historical);

	FCODE(0x10f, 0,		"my-params",		fc_historical);

	P1275(0x11b, 0,		"parse-2int",		parse_two_int);

	FCODE(0x122, 0,		"memory-test-suite",	fc_unimplemented);
	FCODE(0x123, 0,		"group-code",		fc_historical);
	FCODE(0x124, 0,		"mask",			fc_unimplemented);

	FCODE(0x130, 0,		"map-low",		fc_unimplemented);
	FCODE(0x131, 0,		"sbus-intr>cpu",	fc_unimplemented);

	FCODE(0x170, 0,		"fb1-draw-character",	fc_historical);
	FCODE(0x171, 0,		"fb1-reset-screen",	fc_historical);
	FCODE(0x172, 0,		"fb1-toggle-cursor",	fc_historical);
	FCODE(0x173, 0,		"fb1-erase-screen",	fc_historical);
	FCODE(0x174, 0,		"fb1-blink-screen",	fc_historical);
	FCODE(0x175, 0,		"fb1-invert-screen",	fc_historical);
	FCODE(0x176, 0,		"fb1-insert-characters",	fc_historical);
	FCODE(0x177, 0,		"fb1-delete-characters",	fc_historical);
	FCODE(0x178, 0,		"fb1-insert-lines",	fc_historical);
	FCODE(0x179, 0,		"fb1-delete-lines",	fc_historical);
	FCODE(0x17a, 0,		"fb1-draw-logo",	fc_historical);
	FCODE(0x17b, 0,		"fb1-install",		fc_historical);
	FCODE(0x17c, 0,		"fb1-slide-up",		fc_historical);

	FCODE(0x190, 0,		"VME-bus Support",	fc_obsolete);
	FCODE(0x191, 0,		"VME-bus Support",	fc_obsolete);
	FCODE(0x192, 0,		"VME-bus Support",	fc_obsolete);
	FCODE(0x193, 0,		"VME-bus Support",	fc_obsolete);
	FCODE(0x194, 0,		"VME-bus Support",	fc_obsolete);
	FCODE(0x195, 0,		"VME-bus Support",	fc_obsolete);
	FCODE(0x196, 0,		"VME-bus Support",	fc_obsolete);

	FCODE(0x1a0, 0,		"return-buffer",	fc_historical);
	FCODE(0x1a1, 0,		"xmit-packet",		fc_historical);
	FCODE(0x1a2, 0,		"poll-packet",		fc_historical);

	FCODE(0x210, 0,		"processor-type",	fc_historical);
	FCODE(0x211, 0,		"firmware-version",	fc_historical);
	FCODE(0x212, 0,		"fcode-version",	fc_historical);

	FCODE(0x214, 0,		"(is-user-word)",	is_user_word);
	FCODE(0x215, 0,		"suspend-fcode",	fc_unimplemented);

	FCODE(0x229, 0,		"adr-mask",		fc_historical);

	FCODE(0x238, 0,		"probe",		fc_historical);
	FCODE(0x239, 0,		"probe-virtual",	fc_historical);

	P1275(0x23e, 0,		"byte-load",		byte_load);

	P1275(0x240, 0,		"left-parse-string",	left_parse_string);
	FORTH(0,		"fcode-buffer",		fcode_buffer_addr);
}
