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
#include <strings.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

static device_t *builtin_driver_device;

static int
is_device_builtin_package(fcode_env_t *env, device_t *d)
{
	return (d == builtin_driver_device);
}

static char *dropin_name;

/*
 * do-builtin-dropin  ( -- )
 * Convoluted name just in case someone has "do-dropin" word in Fcode.
 * Somewhat different from do-dropin in OBP, as we just load the Fcode, we
 * don't do a byte-load.
 */
static void
do_builtin_dropin(fcode_env_t *env)
{
	fc_cell_t len, result;
	char *buf;
	int error;
	static char func_name[] = "do-builtin-dropin";
	extern int check_fcode_header(char *, uchar_t *, int);

	if (dropin_name == NULL) {
		log_message(MSG_ERROR, "%s: dropin_name not set\n", func_name);
		return;
	}
	debug_msg(DEBUG_FIND_FCODE, "%s: '%s'\n", func_name, dropin_name);
	error = fc_run_priv(env->private, "sunos,get-fcode-size", 1, 1,
	    fc_ptr2cell(dropin_name), &len);
	if (error)
		return;
	if (len == 0) {
		log_message(MSG_WARN, "%s: '%s' zero length Fcode\n",
		    func_name, dropin_name);
		return;
	}
	buf = MALLOC(len);
	error = fc_run_priv(env->private, "sunos,get-fcode", 3, 1,
	    fc_ptr2cell(dropin_name), fc_ptr2cell(buf), len, &result);
	if (error) {
		FREE(buf);
		return;
	}

	if (check_fcode_header(dropin_name, (uchar_t *)buf, len) == 0)
		log_message(MSG_WARN, "%s: '%s' fcode header NOT OK\n",
		    func_name, dropin_name);

	debug_msg(DEBUG_FIND_FCODE,
	    "%s: '%s' doing byte-load len: %x\n", func_name, dropin_name,
	    (int)len);
	PUSH(DS, (fstack_t)buf);
	PUSH(DS, 1);
	byte_load(env);
}

static void
do_builtin_file(fcode_env_t *env)
{
	char *fname;
	static char func_name[] = "do-builtin-file";
	fstack_t d;

	if (dropin_name == NULL) {
		log_message(MSG_ERROR, "%s: dropin_name not set\n", func_name);
		return;
	}
	debug_msg(DEBUG_FIND_FCODE, "%s: '%s'\n", func_name, dropin_name);
	push_a_string(env, dropin_name);
	load_file(env);
	d = POP(DS);
	if (d) {
		debug_msg(DEBUG_FIND_FCODE, "%s: byte-load '%s'\n", func_name,
		    dropin_name);
		PUSH(DS, 1);
		byte_load(env);
	} else
		debug_msg(DEBUG_FIND_FCODE, "%s: load_file '%s' FAIL\n",
		    func_name, dropin_name);
}

/*
 * We need to lookup the builtin name via an FC_RUN_PRIV call to make sure
 * the builtin exists.  If it exists, then we need to leave the xt of
 * do-builtin-dropin on the stack and remember the name for do-dropin.  This is
 * extremely convoluted because we can't a priori populate
 * SUNW,builtin-drivers.
 */
static void
builtin_driver_method_hook(fcode_env_t *env)
{
	device_t *device;
	char *method, *path;
	fc_cell_t len;
	fstack_t d;
	int error;
	static char func_name[] = "builtin-driver-method-hook";

	d = POP(DS);
	CONVERT_PHANDLE(env, device, d);
	if (!is_device_builtin_package(env, device)) {
		PUSH(DS, d);
		PUSH(DS, FALSE);
		return;
	}

	method = pop_a_string(env, NULL);

	/*
	 * Check for file in filesystem.  If it exists, we'll just try to do
	 * a do-dropin-file.
	 */
	if ((path = search_for_fcode_file(env, method)) != NULL) {
		debug_msg(DEBUG_FIND_FCODE, "%s: '%s' file: '%s'\n", func_name,
		    method, path);
		if (dropin_name) {
			FREE(dropin_name);
		}
		dropin_name = STRDUP(path);
		push_a_string(env, "do-builtin-file");
		dollar_find(env);
		return;
	}

	error = fc_run_priv(env->private, "sunos,get-fcode-size", 1, 1,
	    fc_ptr2cell(method), &len);
	if (error || len == 0) {
		if (len == 0)
			debug_msg(DEBUG_FIND_FCODE, "%s: '%s' NOT FOUND\n",
			    func_name, method);
		push_a_string(env, method);
		PUSH(DS, d);
		PUSH(DS, FALSE);
	} else {
		debug_msg(DEBUG_FIND_FCODE, "%s: '%s' FOUND len: %x\n",
		    func_name, method, (int)len);
		if (dropin_name) {
			FREE(dropin_name);
		}
		dropin_name = STRDUP(method);
		push_a_string(env, "do-builtin-dropin");
		dollar_find(env);
	}
}

void
make_a_node(fcode_env_t *env, char *name, int finish)
{
	new_device(env);
	push_a_string(env, name);
	device_name(env);
	if (finish)
		finish_device(env);
}

void
install_package_nodes(fcode_env_t *env)
{
	MYSELF = open_instance_chain(env, env->root_node, 0);
	if (MYSELF != NULL) {
		make_a_node(env, "packages", 0);
		make_a_node(env, "disk-label", 0);
		finish_device(env);
		make_a_node(env, "SUNW,builtin-drivers", 0);
		builtin_driver_device = env->current_device;
		finish_device(env);
		finish_device(env);
		close_instance_chain(env, MYSELF, 0);
		device_end(env);
		MYSELF = 0;
	}
}

/*
 * find-builtin-driver  ( str len -- xt true | false )
 */
void
find_builtin_driver(fcode_env_t *env)
{
	fstack_t d;

	CHECK_DEPTH(env, 2, "find-builtin-driver");
	push_a_string(env, "SUNW,builtin-drivers");
	find_package(env);
	d = POP(DS);
	if (d) {
		find_method(env);
	} else {
		two_drop(env);
		PUSH(DS, FALSE);
	}
}

void
exec_builtin_driver(fcode_env_t *env)
{
	fstack_t d;
	char *method, *path, *buf;
	fc_cell_t len, result;
	int error;
	static char func_name[] = "exec-builtin-driver";
	extern int check_fcode_header(char *, uchar_t *, int);

	CHECK_DEPTH(env, 2, func_name);
	method = pop_a_string(env, NULL);

	/*
	 * Check for file in filesystem.  If it exists, we'll just try to do
	 * a do-dropin-file.
	 */
	if ((path = search_for_fcode_file(env, method)) != NULL) {
		push_a_string(env, path);
		load_file(env);
		return;
	}

	error = fc_run_priv(env->private, "sunos,get-fcode-size", 1, 1,
	    fc_ptr2cell(method), &len);
	if (error || len == 0) {
		if (len == 0)
			debug_msg(DEBUG_FIND_FCODE, "%s: '%s' NOT FOUND\n",
			    func_name, method);
		PUSH(DS, 0);
		return;
	}
	debug_msg(DEBUG_FIND_FCODE, "%s: '%s' FOUND len: %x\n",
	    func_name, method, (int)len);
	buf = MALLOC(len);
	error = fc_run_priv(env->private, "sunos,get-fcode", 3, 1,
	    fc_ptr2cell(method), fc_ptr2cell(buf), len, &result);
	if (error) {
		FREE(buf);
		PUSH(DS, 0);
		return;
	}

	if (check_fcode_header(dropin_name, (uchar_t *)buf, len) == 0)
		log_message(MSG_WARN, "%s: '%s' fcode header NOT OK\n",
		    func_name, method);

	debug_msg(DEBUG_FIND_FCODE, "%s: '%s' dropin Fcode: 0x%p/0x%x\n",
	    func_name, method, buf, (int)len);
	PUSH(DS, (fstack_t)buf);
	PUSH(DS, len);
}

#pragma init(_init)

static void
_init(void)
{
	extern void set_find_method_hook(fcode_env_t *,
	    void (*)(fcode_env_t *));
	fcode_env_t *env = initial_env;
	fstack_t d;

	ASSERT(env);
	NOTICE;

	set_find_method_hook(env, builtin_driver_method_hook);

	FORTH(0,	"install-package-nodes",	install_package_nodes);
	FORTH(0,	"find-builtin-driver",		find_builtin_driver);
	FORTH(0,	"exec-builtin-driver",		exec_builtin_driver);
	FORTH(0,	"builtin-driver-method-hook",
	    builtin_driver_method_hook);
	FORTH(0,	"do-builtin-dropin",		do_builtin_dropin);
	FORTH(0,	"do-builtin-file",		do_builtin_file);
}
