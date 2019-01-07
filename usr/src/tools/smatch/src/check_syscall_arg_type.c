/*
 * Copyright (C) 2017 Oracle.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see http://www.gnu.org/copyleft/gpl.txt
 */

/*
 * This is to help create Trinity fuzzer templates.
 *
 */

#include "smatch.h"
#include "smatch_slist.h"

static int my_id;

STATE(ARG_FD);
#if 0
STATE(arg_range);
STATE(arg_op);
STATE(arg_list);
STATE(arg_cpu);
STATE(arg_pathname);
#endif
// nr_segs * sizeof(struct iovec)
// if (nr_segs > UIO_MAXIOV)
#if 0
STATE(arg_ioveclen);
STATE(arg_sockaddrlen);
STATE(arg_socketinfo);
#endif

struct smatch_state *merge_states(struct smatch_state *s1, struct smatch_state *s2)
{
	if (s1 == &undefined)
		return s2;
	return s1;
}

struct typedef_lookup {
	const char *name;
	struct symbol *sym;
	int failed;
};

static struct symbol *_typedef_lookup(const char *name)
{
	struct ident *id;
	struct symbol *node;

	id = built_in_ident(name);
	if (!id)
		return NULL;
	node = lookup_symbol(id, NS_TYPEDEF);
	if (!node || node->type != SYM_NODE)
		return NULL;
	return get_real_base_type(node);
}

static void typedef_lookup(struct typedef_lookup *tl)
{
	if (tl->sym || tl->failed)
		return;
	tl->sym = _typedef_lookup(tl->name);
	if (!tl->sym)
		tl->failed = 1;
}

static int is_mode_t(struct symbol *sym)
{
	static struct typedef_lookup umode_t = { .name = "umode_t" };
	struct symbol *type;

	typedef_lookup(&umode_t);
	if (!umode_t.sym)
		return 0;
	type = get_base_type(sym);
	if (type == umode_t.sym)
		return 1;
	return 0;
}

static int is_pid_t(struct symbol *sym)
{
	static struct typedef_lookup pid_t = { .name = "pid_t" };
	struct symbol *type;

	typedef_lookup(&pid_t);
	if (!pid_t.sym)
		return 0;
	type = get_base_type(sym);
	if (type == pid_t.sym)
		return 1;
	return 0;
}

static const char *get_arg_type_from_type(struct symbol *sym)
{
	struct symbol *type;

	if (is_mode_t(sym))
		return "ARG_MODE_T";
	if (is_pid_t(sym))
		return "ARG_PID";

	type = get_real_base_type(sym);
	if (!type || type->type != SYM_PTR)
		return NULL;
	type = get_real_base_type(type);
	if (!type)
		return NULL;
	if (type == &char_ctype)
		return "ARG_MMAP";
	if (!type->ident)
		return NULL;
	if (strcmp(type->ident->name, "iovec") == 0)
		return "ARG_IOVEC";
	if (strcmp(type->ident->name, "sockaddr") == 0)
		return "ARG_SOCKADDR";
	return "ARG_ADDRESS";
}

static void match_fdget(const char *fn, struct expression *expr, void *unused)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(expr->args, 0);
	set_state_expr(my_id, arg, &ARG_FD);
}

const char *get_syscall_arg_type(struct symbol *sym)
{
	struct smatch_state *state;
	const char *type;

	if (!sym || !sym->ident)
		return "ARG_UNDEFINED";
	type = get_arg_type_from_type(sym);
	if (type)
		return type;
	state = get_state(my_id, sym->ident->name, sym);
	if (!state)
		return "ARG_UNDEFINED";
	return state->name;
}

void check_syscall_arg_type(int id)
{
	my_id = id;
	if (option_project != PROJ_KERNEL)
		return;

	add_merge_hook(my_id, &merge_states);
	add_function_hook("fdget", &match_fdget, NULL);
}


