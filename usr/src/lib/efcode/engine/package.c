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
 * Copyright 2006 Sun Microsystems, Inc.   All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Peter Tribble.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

#define	MIN_VALUES	100

static void
check_my_self(fcode_env_t *env, char *fn)
{
	if (!MYSELF)
		forth_abort(env, "%s: MYSELF is NULL", fn);
}

uint_t
get_number_of_parent_address_cells(fcode_env_t *env)
{
	uint_t ncells;
	device_t *d;
	static char func_name[] = "get_number_of_parent_address_cells";

	if (MYSELF == NULL)	/* Kludge for testing */
		return (2);
	d = MYSELF->device;
	ncells = d->parent_adr_cells;
	if (ncells == 0) {
		ncells = get_default_intprop(env, "#address-cells", d->parent,
		    2);
		if (ncells > MAX_MY_ADDR) {
			log_message(MSG_ERROR, "%s: %s:"
			    " ncells (%d) > MAX_MY_ADDR (%d)\n", func_name,
			    get_path(env, d->parent), ncells, MAX_MY_ADDR);
			ncells = MAX_MY_ADDR;
		}
		d->parent_adr_cells = ncells;
	}
	return (ncells);
}

instance_t *
create_ihandle(fcode_env_t *env, device_t *phandle, instance_t *parent)
{
	instance_t *ihandle;
	int i;

	ihandle = MALLOC(sizeof (instance_t));

	i = max(phandle->data_size[INIT_DATA], MIN_VALUES);
	ihandle->data[INIT_DATA] = MALLOC(sizeof (fstack_t) * i);
	memcpy(ihandle->data[INIT_DATA], phandle->init_data,
	    (size_t) (sizeof (fstack_t) * i));

	i = max(phandle->data_size[UINIT_DATA], MIN_VALUES);
	ihandle->data[UINIT_DATA] = MALLOC(sizeof (fstack_t) * i);

	ihandle->my_space = phandle->my_space;
	memcpy(ihandle->my_addr, phandle->my_addr, sizeof (ihandle->my_addr));
	ihandle->parent = parent;
	ihandle->device = phandle;
	return (ihandle);
}

device_t *
create_phandle(fcode_env_t *env, device_t *parent)
{
	device_t *phandle;

	phandle = MALLOC(sizeof (device_t));
	phandle->init_data = MALLOC(sizeof (fstack_t) * MIN_VALUES);
	phandle->data_size[INIT_DATA] = 0;
	phandle->data_size[UINIT_DATA] = 0;
	phandle->parent = parent;
	return (phandle);
}


static void
do_push_package(fcode_env_t *env, device_t *d)
{
	do_previous(env);
	do_also(env);
	if (d != NULL) {
		CONTEXT = (token_t *)(&d->vocabulary);
		debug_msg(DEBUG_CONTEXT, "CONTEXT:push_package: %s%d/%p/%p\n",
		    get_path(env, d), env->order_depth, CONTEXT, env->current);
	}
}

static void
push_package(fcode_env_t *env)
{
	device_t *d;
	phandle_t ph;

	CHECK_DEPTH(env, 1, "push-package");
	ph = POP(DS);
	CONVERT_PHANDLE(env, d, ph);
	do_push_package(env, d);
}

static void
pop_package(fcode_env_t *env)
{
	do_previous(env);
	do_definitions(env);
}

static void
interpose(fcode_env_t *env)
{
	TODO;	/* interpose - not yet implemented */
}

void
activate_device(fcode_env_t *env, device_t *d)
{
	env->current_device = d;
	do_push_package(env, d);
	do_definitions(env);
}

void
deactivate_device(fcode_env_t *env, device_t *d)
{
	env->current_device = d;
	do_previous(env);
	if (d != NULL) {
		CONTEXT = (token_t *)(&d->vocabulary);
		debug_msg(DEBUG_CONTEXT, "CONTEXT:deactivate_device:"
		    " %s%d/%p/%p\n", get_path(env, d), env->order_depth,
		    CONTEXT, env->current);
	}
	do_definitions(env);
}

void
root_node(fcode_env_t *env)
{
	do_also(env);
	activate_device(env, env->root_node);
}

void
child_node(fcode_env_t *env)
{
	device_t *d;

	CHECK_DEPTH(env, 1, "child");
	CONVERT_PHANDLE(env, d, TOS);
	TOS = (fstack_t)d->child;
	REVERT_PHANDLE(env, TOS, d->child);
}

void
peer_node(fcode_env_t *env)
{
	device_t *d;

	CHECK_DEPTH(env, 1, "peer");
	CONVERT_PHANDLE(env, d, TOS);
	REVERT_PHANDLE(env, TOS, d->peer);
}

void
new_device(fcode_env_t *env)
{
	device_t *phandle, *parent;
	device_t *peer;

	check_my_self(env, "new-device");

	parent = MYSELF->device;
	phandle = create_phandle(env, parent);
	MYSELF = create_ihandle(env, phandle, MYSELF);
	activate_device(env, phandle);
	if (parent->child) {
		/* Insert new child at end of peer list */
		for (peer = parent->child; peer->peer; peer = peer->peer)
			;
		peer->peer = phandle;
	} else
		parent->child = phandle;	/* First child */
	ALLOCATE_PHANDLE(env);
}

void
finish_device(fcode_env_t *env)
{
	fstack_t *mem;
	device_t *my_dev, *parent_dev;
	instance_t *parent, *myself = MYSELF;
	int  n;

	check_my_self(env, "finish-device");
	ASSERT(myself->device);
	ASSERT(env->current_device);
	n = myself->device->data_size[INIT_DATA];

	/*
	 * Paranoia.. reserve a little more instance data than we need
	 */
	mem = MALLOC(sizeof (fstack_t) * (n+8));
	memcpy(mem, MYSELF->device->init_data, sizeof (fstack_t) * n);
	FREE(myself->device->init_data);
	my_dev = myself->device;
	my_dev->init_data = mem;
	parent = MYSELF->parent;
	parent_dev = env->current_device->parent;
	FREE(MYSELF);
	MYSELF = parent;
	activate_device(env, parent_dev);
}

static void
create_internal_value(fcode_env_t *env, char *name, int offset, int token)
{
	header(env, name, strlen(name), 0);
	COMPILE_TOKEN(&noop);
	EXPOSE_ACF;
	if (token) {
		SET_TOKEN(token, 0, name, LINK_TO_ACF(env->lastlink));
	}
	PUSH(DS, offset);
	lcomma(env);
	set_internal_value_actions(env);
}

static void
create_my_self(fcode_env_t *env)
{
	int offset = offsetof(fcode_env_t, my_self);

	create_internal_value(env, "my-self", offset, 0x203);
}

static void
create_my_space(fcode_env_t *env)
{
	int offset = offsetof(instance_t, my_space);

	create_internal_value(env, "my-space", -offset, 0x103);
}

void
my_address(fcode_env_t *env)
{
	fstack_t *adr_ptr;
	uint_t ncells;

	check_my_self(env, "my-address");
	ncells = get_number_of_parent_address_cells(env);
	adr_ptr = MYSELF->my_addr;
	while (--ncells) {
		PUSH(DS, *adr_ptr);
		adr_ptr++;
	}
}

void
my_unit(fcode_env_t *env)
{
	check_my_self(env, "my-unit");
	my_address(env);
	PUSH(DS, MYSELF->my_space);
}

static void
my_args(fcode_env_t *env)
{
	check_my_self(env, "my-args");
	PUSH(DS, (fstack_t)MYSELF->my_args);
	PUSH(DS, (fstack_t)MYSELF->my_args_len);
}

int
call_my_parent(fcode_env_t *env, char *method)
{
	push_a_string(env, method);
	dollar_call_parent(env);
	return (env->last_error);
}

void
set_args(fcode_env_t *env)
{
	int args_len;
	common_data_t *cdp;
	uint_t ncells;
	fstack_t *adr_ptr, *adr_ptr1, space;

	CHECK_DEPTH(env, 4, "set-args");

	check_my_self(env, "set-args");

	/*
	 * Handle args argument of set-args.
	 */
	if (MYSELF->my_args) {
		FREE(MYSELF->my_args);
		MYSELF->my_args = NULL;
	}
	two_swap(env);
	MYSELF->my_args = pop_a_duped_string(env, &args_len);
	MYSELF->my_args_len = args_len;

	if (call_my_parent(env, "decode-unit"))
		forth_abort(env, "set-args: decode-unit failed");

	ncells = get_number_of_parent_address_cells(env);

	/*
	 * Kludge: For GP2, my-space comes from decode-unit hi.address.
	 * for PCI, my-space from decode-unit won't have the bus#, so we need
	 * to get it from config_address.  Unfortunately, there is no easy
	 * way to figure out here which one we're looking at.  We take the
	 * expediant of or'ing the two values together.
	 */
	space = POP(DS);	/* pop phys.hi */
	if ((cdp = (common_data_t *)env->private) != NULL)
		space |= cdp->fc.config_address;

	MYSELF->device->my_space = MYSELF->my_space = space;

	adr_ptr = MYSELF->my_addr;
	adr_ptr1 = MYSELF->device->my_addr;
	while (--ncells) {
		*adr_ptr++ = *adr_ptr1++ = POP(DS);
	}
}

void
my_parent(fcode_env_t *env)
{
	check_my_self(env, "my-parent");
	PUSH(DS, (fstack_t)MYSELF->parent);
}

instance_t *
open_instance_chain(fcode_env_t *env, device_t *phandle, int exec)
{
	instance_t *parent;

	if (!phandle)
		return (NULL);
	parent = open_instance_chain(env, phandle->parent, exec);
	return (create_ihandle(env, phandle, parent));
}

void
close_instance_chain(fcode_env_t *env, instance_t *ihandle, int exec)
{
	instance_t *parent;

	if (ihandle) {
		parent = ihandle->parent;
		close_instance_chain(env, parent, exec);
		if (ihandle->my_args)
			FREE(ihandle->my_args);
		FREE(ihandle);
	}
}

void
begin_package(fcode_env_t *env)
{
	fstack_t ok;
	char *name;

	CHECK_DEPTH(env, 6, "begin-package");
	two_dup(env);
	name = pop_a_string(env, NULL);
	find_package(env);
	ok = POP(DS);
	if (ok) {
		PUSH(DS, 0);
		PUSH(DS, 0);
		rot(env);
		open_package(env);
		MYSELF = (instance_t *)POP(DS);
		check_my_self(env, "begin-package");
		new_device(env);
		set_args(env);
	} else {
		log_message(MSG_INFO, "Package '%s' not found\n", name);
	}
}

void
open_package(fcode_env_t *env)
{
	device_t *phandle;
	instance_t *ihandle;
	int len;

	CHECK_DEPTH(env, 3, "open-package");
	CONVERT_PHANDLE(env, phandle, POP(DS));
	ihandle = open_instance_chain(env, phandle, 1);
	ihandle->my_args = pop_a_duped_string(env, &len);
	ihandle->my_args_len = len;
	PUSH(DS, (fstack_t)ihandle);
}

void
dollar_open_package(fcode_env_t *env)
{
	fstack_t ok;

	CHECK_DEPTH(env, 4, "$open-package");
	find_package(env);
	ok = POP(DS);
	if (ok) {
		open_package(env);
	} else {
		(void) POP(DS);
		(void) POP(DS);
		PUSH(DS, 0);
	}
}

void
close_package(fcode_env_t *env)
{
	instance_t *ihandle;

	CHECK_DEPTH(env, 1, "close-package");
	ihandle = (instance_t *)POP(DS);
	close_instance_chain(env, ihandle, 1);
}

static void (*find_method_hook)(fcode_env_t *);

void
set_find_method_hook(fcode_env_t *env, void (*hook)(fcode_env_t *))
{
	find_method_hook = hook;
}

void
find_method(fcode_env_t *env)
{
	fstack_t d;
	device_t *device;
	acf_t acf = 0;

	CHECK_DEPTH(env, 3, "find-method");
	if (find_method_hook) {
		(*find_method_hook)(env);
		if (TOS)		/* Found it */
			return;
		POP(DS);
	}

	d = POP(DS);
	CONVERT_PHANDLE(env, device, d);
	PUSH(DS, (fstack_t)&device->vocabulary);
	acf = voc_find(env);
	PUSH(DS, (fstack_t)acf);
	if (acf) {
		PUSH(DS, TRUE);
	}
}

/*
 * 'call-package' Fcode
 */
void
call_package(fcode_env_t *env)
{
	instance_t *ihandle, *saved_myself;

	CHECK_DEPTH(env, 2, "call-package");
	ihandle = (instance_t *)POP(DS);
	saved_myself = MYSELF;
	MYSELF = ihandle;
	execute(env);
	MYSELF = saved_myself;
}

void
ihandle_to_phandle(fcode_env_t *env)
{
	instance_t *i;

	CHECK_DEPTH(env, 1, "ihandle>phandle");
	i = (instance_t *)TOS;
	REVERT_PHANDLE(env, TOS, i->device);
}

char *
get_package_name(fcode_env_t *env, device_t *d)
{
	char *name;
	prop_t *prop;

	prop = lookup_package_property(env, "name", d);
	if (prop == NULL) {
		name = "<Unnamed>";
	} else {
		name = (char *)prop->data;
	}
	return (name);
}

static char *package_search_path = "/packages:/openprom";

device_t *
match_package_path(fcode_env_t *env, char *path)
{
	device_t *d;
	char *name;
	int len;

	if (*path == '/') {
		d = env->root_node->child;
		path++;
	} else
		d = env->current_device;
	while (*path != '\0' && d != NULL) {
		name = get_package_name(env, d);
		len = strlen(name);
		if (strncmp(name, path, len) == 0) {
			path += len;
			if (*path == '\0') {
				return (d);
			}
			/* skip the '/' */
			if (*path++ != '/')
				break;
			d = d->child;
		} else {
			d = d->peer;
		}
	}
	return (NULL);
}

device_t *
locate_package(fcode_env_t *env, char *start)
{
	device_t *d;
	char *p, *next_p;
	char *tpath, *fpath;

	if ((d = match_package_path(env, start)) != NULL)
		return (d);

	/*
	 * ignore starting '/'
	 */
	if (*start == '/')
		*start++;

	fpath = STRDUP(package_search_path);
	for (p = fpath; p != NULL; p = next_p) {
		if ((next_p = strchr(p, ':')) != NULL)
			*next_p++ = '\0';
		tpath = MALLOC(strlen(p) + strlen(start) + 2);
		sprintf(tpath, "%s/%s", p, start);
		if ((d = match_package_path(env, tpath)) != NULL) {
			FREE(fpath);
			FREE(tpath);
			return (d);
		}
		FREE(tpath);
	}
	FREE(fpath);
	return (NULL);
}

void
find_package(fcode_env_t *env)
{
	char *path;
	device_t *package;
	fstack_t ph = 0;

	CHECK_DEPTH(env, 2, "find-package");
	if ((path = pop_a_duped_string(env, NULL)) != NULL) {
		if (strcmp(path, "/") == 0)
			package = env->root_node;
		else
			package = locate_package(env, path);
		FREE(path);
		REVERT_PHANDLE(env, ph, package);
	}
	PUSH(DS, ph);
	if (package)
		PUSH(DS, TRUE);
}

static void
encode_unit_hack(fcode_env_t *env)
{
	int hi, i;
	uint_t ncells = get_number_of_parent_address_cells(env);

	for (i = 0; i < ncells; i++)
		POP(DS);
	push_a_string(env, NULL);
}

void
dollar_call_method(fcode_env_t *env)
{
	instance_t *old_myself;
	instance_t *myself;
	device_t *device;
	char *method;

	CHECK_DEPTH(env, 3, "$call-method");
	check_my_self(env, "$call-method");
	old_myself = MYSELF;
	myself = (instance_t *)POP(DS);

	method = (char *)DS[-1];
	debug_msg(DEBUG_CALL_METHOD, "$call_method %s\n", method);

	if (old_myself && !myself) {
		/* We hit the root of our tree */
		device = old_myself->device;
		return;
	}

	MYSELF = myself;
	check_my_self(env, "$call-method");
	device = MYSELF->device;
	do_push_package(env, device);
	PUSH(DS, (fstack_t)device);
	REVERT_PHANDLE(env, TOS, device);
	find_method(env);
	if (TOS) {
		(void) POP(DS);
		execute(env);
	} else if (strcmp(method, "encode-unit") == 0) {
		encode_unit_hack(env);
	} else {
		throw_from_fclib(env, 1, "Unimplemented package method: %s%s",
		    get_path(env, device), method);
	}
	MYSELF = old_myself;
	do_push_package(env, MYSELF->device);
}

void
dollar_call_parent(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "$call-parent");

	check_my_self(env, "$call-parent");

	PUSH(DS, (fstack_t)MYSELF->parent);
	dollar_call_method(env);
}

#ifdef DEBUG
void
current_device(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)&env->current_device);
}

char *
get_path(fcode_env_t *env, device_t *d)
{
	char *pre_path, *name, *path;
	int n;

	if (d->parent)
		pre_path = get_path(env, d->parent);
	else
		pre_path = STRDUP("");

	name = get_package_name(env, d);
	n = strlen(pre_path) + strlen(name) + 1;
	path = MALLOC(n);
	strcpy(path, pre_path);
	strcat(path, name);
	if (d->child && d->parent)
		strcat(path, "/");
	FREE(pre_path);
	return (path);
}

static void
pwd_dollar(fcode_env_t *env)
{
	if (env->current_device)
		push_a_string(env, get_path(env, env->current_device));
	else
		push_a_string(env, NULL);
}

void
pwd(fcode_env_t *env)
{
	if (env->current_device) {
		log_message(MSG_INFO, "%s\n",
		    get_path(env, env->current_device));
	} else {
		log_message(MSG_INFO, "No device context\n");
	}
}

void
do_ls(fcode_env_t *env)
{
	device_t *d;

	if (env->current_device == NULL) {
		log_message(MSG_INFO, "No device context\n");
		return;
	}

	d = env->current_device->child;
	while (d) {
		char *name;
		fstack_t ph;
		name = get_package_name(env, d);
		REVERT_PHANDLE(env, ph, d);
		log_message(MSG_INFO, "%llx %s\n", (uint64_t)ph, name);
		d = d->peer;
	}
}

void
paren_cd(fcode_env_t *env)
{
	char *str;
	device_t *p;

	str = pop_a_string(env, NULL);
	if (strcmp(str, "/") == 0) {
		root_node(env);
		return;
	}

	if (env->current_device == NULL) {
		log_message(MSG_INFO, "No device context\n");
		return;
	}

	if (strcmp(str, "..") == 0)
		p = env->current_device->parent;
	else {
		device_t *n = env->current_device->child;

		p = NULL;
		while (n) {
			char *name;

			name = get_package_name(env, n);
			if (strcmp(name, str) == 0) {
				p = n;
				break;
			}
			n = n->peer;
		}
	}

	if (p) {
		activate_device(env, p);
	} else {
		log_message(MSG_INFO, "No such node: %s\n", str);
	}
}

void
do_cd(fcode_env_t *env)
{
	parse_word(env);
	paren_cd(env);
}

void
do_unselect_dev(fcode_env_t *env)
{
	check_my_self(env, "unselect-dev");
	PUSH(DS, (fstack_t)MYSELF);
	close_package(env);
	deactivate_device(env, NULL);
}

void
do_select_dev(fcode_env_t *env)
{
	PUSH(DS, 0);
	PUSH(DS, 0);
	two_swap(env);
	dollar_open_package(env);
	if (TOS) {
		MYSELF = (instance_t *)POP(DS);
		check_my_self(env, "select-dev");
		activate_device(env, MYSELF->device);
	} else {
		drop(env);
		log_message(MSG_INFO, "Can't open package\n");
	}
}

void
device_end(fcode_env_t *env)
{
	if (env->current_device) {
		deactivate_device(env, NULL);
	}
}

void
end_package(fcode_env_t *env)
{
	finish_device(env);
	close_instance_chain(env, MYSELF, 0);
	device_end(env);
	MYSELF = NULL;
}

void
exec_parent_method(fcode_env_t *env)
{
	instance_t *old_myself;
	instance_t *myself;
	device_t *device;
	char *method;
	fstack_t d;

	check_my_self(env, "exec-parent-method");
	old_myself = MYSELF;
	MYSELF = MYSELF->parent;

	method = (char *)DS[-1];
	debug_msg(DEBUG_FIND_FCODE, "exec_parent_method: '%s'\n", method);

	check_my_self(env, "exec-parent-method");
	device = MYSELF->device;
	do_push_package(env, device);
	PUSH(DS, (fstack_t)device);
	REVERT_PHANDLE(env, TOS, device);
	find_method(env);
	d = POP(DS);
	if (d) {
		debug_msg(DEBUG_FIND_FCODE, "exec-parent-method: '%s'/%x"
		    " execute\n", method, (int)TOS);
		execute(env);
		PUSH(DS, TRUE);
	} else {
		debug_msg(DEBUG_FIND_FCODE, "exec-parent-method: '%s'"
		    " not found\n", method);
		PUSH(DS, FALSE);
	}
	MYSELF = old_myself;
	do_push_package(env, MYSELF->device);
}

void
dump_device(fcode_env_t *env)
{
	device_t *phandle;
	int i;

	CONVERT_PHANDLE(env, phandle, POP(DS));
	log_message(MSG_DEBUG, "Node:      %p\n", phandle);
	log_message(MSG_DEBUG, "  Parent:  (%8p) %p\n",
	    &phandle->parent, phandle->parent);
	log_message(MSG_DEBUG, "  Child:   (%8p) %p\n",
	    &phandle->child, phandle->child);
	log_message(MSG_DEBUG, "  Peer:    (%8p) %p\n",
	    &phandle->peer, phandle->peer);
	log_message(MSG_DEBUG, "  Private: (%8p) %p\n",
	    &phandle->private, phandle->private);
	log_message(MSG_DEBUG, "  Props:   (%8p) %p\n",
	    &phandle->properties, phandle->properties);
	log_message(MSG_DEBUG, "  Voc:     (%8p) %p\n",
	    &phandle->vocabulary, phandle->vocabulary);
	log_message(MSG_DEBUG, "  sizes:   (%8p) %d %d\n",
	    &phandle->data_size,
	    phandle->data_size[INIT_DATA],
	    phandle->data_size[UINIT_DATA]);
	log_message(MSG_DEBUG, "  my_space: %x\n", phandle->my_space);
	log_message(MSG_DEBUG, "  my_addr :");
	for (i = 0; i < MAX_MY_ADDR; i++)
		log_message(MSG_DEBUG, " %x", (int)phandle->my_addr[i]);
	log_message(MSG_DEBUG, "\n");
	log_message(MSG_DEBUG, "  data:    (%8p)\n", phandle->init_data);
	for (i = 0; i < phandle->data_size[INIT_DATA]; i++) {
		log_message(MSG_DEBUG, "    %3d  -> (%8p) %x\n", i,
		    &phandle->init_data[i], phandle->init_data[i]);
	}
}

void
dump_instance(fcode_env_t *env)
{
	int i;
	instance_t *ihandle;

	ihandle = (instance_t *)POP(DS);
	log_message(MSG_DEBUG, "Ihandle:      %p\n", ihandle);
	log_message(MSG_DEBUG, "  Parent:  (%8p) %p\n",
	    &ihandle->parent, ihandle->parent);
	log_message(MSG_DEBUG, "  Device:  (%8p) %p\n",
	    &ihandle->device, ihandle->device);
	log_message(MSG_DEBUG, "  args:     '%s'\n",
	    ((ihandle->my_args) ? ihandle->my_args : ""));
	log_message(MSG_DEBUG, "  my-space: %x\n", ihandle->my_space);
	log_message(MSG_DEBUG, "  my_addr :");
	for (i = 0; i < MAX_MY_ADDR; i++)
		log_message(MSG_DEBUG, " %x", (int)ihandle->my_addr[i]);
	log_message(MSG_DEBUG, "\n");
	log_message(MSG_DEBUG, "  sizes:   %d %d\n",
	    ihandle->device->data_size[INIT_DATA],
	    ihandle->device->data_size[UINIT_DATA]);
	log_message(MSG_DEBUG, "  data:    (%8p) %x %x\n",
	    ihandle->data, ihandle->data[0], ihandle->data[1]);
	if (ihandle->device->data_size[INIT_DATA]) {
		log_message(MSG_DEBUG, "  Initialised:\n");
		for (i = 0; i < ihandle->device->data_size[INIT_DATA]; i++) {
			log_message(MSG_DEBUG, "    %3d  -> (%8p) %x\n", i,
			    &ihandle->data[INIT_DATA][i],
			    ihandle->data[INIT_DATA][i]);
		}
	}
	if (ihandle->device->data_size[INIT_DATA]) {
		log_message(MSG_DEBUG, "  UnInitialised:\n");
		for (i = 0; i < ihandle->device->data_size[UINIT_DATA]; i++) {
			log_message(MSG_DEBUG, "    %3d  -> (%8p) %x\n", i,
			    &ihandle->data[UINIT_DATA][i],
			    ihandle->data[UINIT_DATA][i]);
		}
	}
}

#endif

#pragma init(_init)

#ifdef CONVERT_HANDLES
static device_t	*
safe_convert_phandle(fcode_env_t *env, fstack_t d)
{
	return ((device_t *)d);
}

static fstack_t
safe_revert_phandle(fcode_env_t *env, device_t *d)
{
	return ((fstack_t)d);
}

static void
safe_allocate_phandle(fcode_env_t *env)
{
}

#endif

static void
_init(void)
{
	fcode_env_t *env = initial_env;
	char *name = "/";
	device_t *d;

	ASSERT(env);
	NOTICE;

#ifdef CONVERT_HANDLES
	env->convert_phandle = safe_convert_phandle;
	env->revert_phandle = safe_revert_phandle;
	env->allocate_phandle = safe_allocate_phandle;
#endif

	/* build the root node */
	d = create_phandle(env, NULL);
	env->current_device = d;
	env->root_node = d;
	push_a_string(env, name);
	device_name(env);
	env->current_device = NULL;

	create_my_self(env);
	create_my_space(env);

	P1275(0x102, 0,		"my-address",		my_address);
	/* Fcode 0x103 "my-space" is created using create_internal_value */

	P1275(0x11f, 0,		"new-device",		new_device);

	P1275(0x127, 0,		"finish-device",	finish_device);

	FCODE(0x129, 0,		"push-package",		push_package);
	FCODE(0x12a, 0,		"pop-package",		pop_package);
	FCODE(0x12b, 0,		"interpose",		interpose);

	P1275(0x202, 0,		"my-args",		my_args);
	/* Fcode 0x203 "my-self" is created using create_internal_value */
	P1275(0x204, 0,		"find-package",		find_package);
	P1275(0x205, 0,		"open-package",		open_package);
	P1275(0x206, 0,		"close-package",	close_package);
	P1275(0x207, 0,		"find-method",		find_method);
	P1275(0x208, 0,		"call-package",		call_package);
	P1275(0x209, 0,		"$call-parent",		dollar_call_parent);
	P1275(0x20a, 0,		"my-parent",		my_parent);
	P1275(0x20b, 0,		"ihandle>phandle",	ihandle_to_phandle);

	P1275(0x20d, 0,		"my-unit",		my_unit);
	P1275(0x20e, 0,		"$call-method",		dollar_call_method);
	P1275(0x20f, 0,		"$open-package",	dollar_open_package);

	P1275(0x23b, 0,		"child",		child_node);
	P1275(0x23c, 0,		"peer",			peer_node);

	P1275(0x23f, 0,		"set-args",		set_args);

	FORTH(IMMEDIATE,	"root-node",		root_node);
	FORTH(0,		"current-device",	current_device);
	FORTH(0,		"pwd$",			pwd_dollar);
	FORTH(IMMEDIATE,	"pwd",			pwd);
	FORTH(IMMEDIATE,	"ls",			do_ls);
	FORTH(IMMEDIATE,	"(cd)",			paren_cd);
	FORTH(IMMEDIATE,	"cd",			do_cd);
	FORTH(IMMEDIATE,	"device-end",		device_end);
	FORTH(0,		"select-dev",		do_select_dev);
	FORTH(0,		"unselect-dev",		do_unselect_dev);
	FORTH(0,		"begin-package",	begin_package);
	FORTH(0,		"end-package",		end_package);
	FORTH(IMMEDIATE,	"dump-device",		dump_device);
	FORTH(IMMEDIATE,	"dump-instance",	dump_instance);
	FORTH(0,		"exec-parent-method",	exec_parent_method);
}
