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

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/pci.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

static char *pkg_my_args;
static char fcode_dev[] = "/dev/fcode";

static void
dot_request(fcode_env_t *env)
{
	common_data_t *cdp = env->private;

	log_message(MSG_INFO, "request: cfgadd: %x fc_size: %x unitadd: %s"
	    " attach: %x args: '%s'\n", cdp->fc.config_address,
	    cdp->fc.fcode_size, cdp->fc.unit_address, cdp->attach,
	    pkg_my_args ? pkg_my_args : "<null>");
}

/*
 * Get next request from /dev/fcode.
 */
int
fc_get_request(common_data_t *cdp)
{
	char c;
	int nbytes;

	if (cdp->fcode_fd < 0) {
		log_message(MSG_FATAL, "fc_get_request: fcode_fd not open\n");
		return (0);
	}

	if ((nbytes = read(cdp->fcode_fd, &c, sizeof (c))) < 0) {
		log_perror(MSG_FATAL, "read(%s) failed", fcode_dev);
		return (0);
	}

	if (ioctl(cdp->fcode_fd, FC_GET_PARAMETERS, &cdp->fc) < 0) {
		log_perror(MSG_FATAL, "ioctl(FC_GET_PARAMETERS) failed");
		return (0);
	}

	if ((cdp->attach = fc_get_ap(cdp)) == 0)
		return (0);

	return (1);
}

static void
get_my_args(fcode_env_t *env)
{
	common_data_t *cdp = env->private;
	char buffer[BUFSIZ];

	/*
	 * Don't get if already set.
	 */
	if (pkg_my_args)
		return;

	if (ioctl(cdp->fcode_fd, FC_GET_MY_ARGS, buffer) < 0) {
		return;
	}
	pkg_my_args = STRDUP(buffer);
}

static void
set_my_args(fcode_env_t *env)
{
	if (pkg_my_args)
		FREE(pkg_my_args);

	parse_word(env);
	pkg_my_args = pop_a_duped_string(env, NULL);
}

static void
dot_my_args(fcode_env_t *env)
{
	if (pkg_my_args)
		log_message(MSG_INFO, "%s\n", pkg_my_args);
	else
		log_message(MSG_INFO, "NULL\n");
}

void
push_my_args(fcode_env_t *env)
{
	push_a_string(env, pkg_my_args);
}

void
get_fcode_from_device(fcode_env_t *env)
{
	common_data_t *cdp = env->private;
	char *p, *buf;
	static char func_name[] = "get_fcode_from_device";
	fc_fcode_info_t fcode_info;

	if (!cdp->fc.fcode_size) {
		debug_msg(DEBUG_FIND_FCODE, "%s: Fcode zero length\n",
		    func_name);
		push_a_string(env, NULL);
		return;
	}
	fcode_info.fcode_size = cdp->fc.fcode_size;
	fcode_info.fcode_ptr = MALLOC(cdp->fc.fcode_size);
	if (ioctl(cdp->fcode_fd, FC_GET_FCODE_DATA, &fcode_info) < 0) {
		log_perror(MSG_FATAL, "ioctl(FC_GET_FCODE_DATA) failed");
		push_a_string(env, NULL);
	} else {
		debug_msg(DEBUG_FIND_FCODE,
		    "%s: Fcode from device: len: 0x%x\n", func_name,
		    (int)cdp->fc.fcode_size);
		PUSH(DS, (fstack_t)fcode_info.fcode_ptr);
		PUSH(DS, (fstack_t)cdp->fc.fcode_size);
	}
}

static void
save_fcode_to_file(fcode_env_t *env)
{
	char *buf, *fname;
	int len;
	FILE *fd;

	CHECK_DEPTH(env, 4, "save-fcode-to-file");
	if ((fname = pop_a_string(env, NULL)) == NULL) {
		log_message(MSG_DEBUG, "fname?\n");
		return;
	}
	if ((buf = pop_a_string(env, &len)) == NULL) {
		log_message(MSG_INFO, "buf?\n");
		return;
	}
	if ((fd = fopen(fname, "w")) == NULL) {
		log_perror(MSG_DEBUG, "Save_fcode_to_file: Can't open '%s'",
		    fname);
		return;
	}
	log_message(MSG_INFO, "Fcode %p,%x to file '%s'\n", buf, len, fname);
	fwrite(buf, len, sizeof (char), fd);
	fclose(fd);
}

void
exec_fcode_builtin_method(fcode_env_t *env)
{
	fstack_t d;
	char *method;
	extern void exec_parent_method(fcode_env_t *);
	extern void exec_builtin_driver(fcode_env_t *);

	method = (char *)DS[-1];
	exec_parent_method(env);
	d = POP(DS);
	if (d) {
		debug_msg(DEBUG_FIND_FCODE, "builtin-driver: %s -> %s found\n",
		    method, (char *)DS[-1]);
		exec_builtin_driver(env);
		debug_msg(DEBUG_FIND_FCODE, "builtin-driver-exec: %p %x\n",
		    (char *)DS[-1], (int)TOS);
	} else {
		debug_msg(DEBUG_FIND_FCODE, "builtin-driver: %s not found\n",
		    method);
		PUSH(DS, FALSE);
	}
}

void
get_fcode_from_filesystem(fcode_env_t *env)
{
	fstack_t d;
	char *method, *fc_name, *path;
	extern void exec_parent_method(fcode_env_t *);
	static char fname[] = "get-fcode-from-filesystem";

	method = (char *)DS[-1];
	exec_parent_method(env);
	d = POP(DS);
	if (d) {
		fc_name = pop_a_string(env, NULL);
		debug_msg(DEBUG_FIND_FCODE, "%s: %s -> %s found\n", fname,
		    method, fc_name);
		if ((path = search_for_fcode_file(env, fc_name)) != NULL) {
			debug_msg(DEBUG_FIND_FCODE, "%s: file: %s FOUND\n",
			    fname, path);
			push_a_string(env, path);
			load_file(env);
		} else {
			debug_msg(DEBUG_FIND_FCODE, "%s: file '%s' not found\n",
			    fname, fc_name);
			PUSH(DS, FALSE);
		}
	} else {
		debug_msg(DEBUG_FIND_FCODE, "%s: method '%s' not found\n",
		    fname, method);
		PUSH(DS, FALSE);
	}
}

/*
 * Looks for "device-id" and "class-id" methods in parent, if there,
 * executes them to get "builtin drivers" file name or method name, then
 * executes the builtin-driver method.  If both those fail, try getting the
 * fcode from the device.  Note that we sleaze resetting the data stack.
 * This would be cleaner if we had a way to do the equivalent of "catch/throw"
 * from within C code.
 */
void
find_fcode(fcode_env_t *env)
{
	fstack_t *dp = env->ds;
	common_data_t *cdp = env->private;
	static char func_name[] = "find_fcode";
	int error;

	my_unit(env);
	push_a_string(env, "device-id");
	get_fcode_from_filesystem(env);
	if (TOS) {
		debug_msg(DEBUG_FIND_FCODE, "%s: FS dev-id: len: 0x%x\n",
		    func_name, TOS);
		return;
	}

	env->ds = dp;
	my_unit(env);
	push_a_string(env, "class-id");
	get_fcode_from_filesystem(env);
	if (TOS) {
		debug_msg(DEBUG_FIND_FCODE, "%s: FS cls-id len: 0x%x\n",
		    func_name, TOS);
		return;
	}

	env->ds = dp;
	get_fcode_from_device(env);
	if (TOS) {
		debug_msg(DEBUG_FIND_FCODE, "%s: DEV fcode len: 0x%x\n",
		    func_name, TOS);
		return;
	}

	env->ds = dp;
	my_unit(env);
	push_a_string(env, "device-id");
	exec_fcode_builtin_method(env);
	if (TOS) {
		debug_msg(DEBUG_FIND_FCODE, "%s: dropin dev-id len: 0x%x\n",
		    func_name, TOS);
		return;
	}

	env->ds = dp;
	my_unit(env);
	push_a_string(env, "class-id");
	exec_fcode_builtin_method(env);
	if (TOS) {
		debug_msg(DEBUG_FIND_FCODE, "%s: dropin cls-id len: 0x%x\n",
		    func_name, TOS);
		return;
	}

	debug_msg(DEBUG_FIND_FCODE, "%s: not found\n", func_name);
	error = FC_NO_FCODE;
	if (ioctl(cdp->fcode_fd, FC_SET_FCODE_ERROR, &error) < 0) {
		log_perror(MSG_FATAL, "ioctl(FC_SET_FCODE_ERROR) failed");
		return;
	}
}

int
open_fcode_dev(fcode_env_t *env)
{
	common_data_t *cdp = env->private;

	if ((cdp->fcode_fd = open(fcode_dev, O_RDONLY)) < 0)
		log_perror(MSG_ERROR, "Can't open '%s'", fcode_dev);
	return (cdp->fcode_fd >= 0);
}

static void
get_request(fcode_env_t *env)
{
	common_data_t *cdp = env->private;

	if (cdp->fcode_fd >= 0)
		close(cdp->fcode_fd);
	if (!open_fcode_dev(env))
		exit(1);
	if (!fc_get_request(cdp)) {
		log_message(MSG_FATAL, "fc_get_request failed\n");
		exit(1);
	}

	get_my_args(env);

	DEBUGF(UPLOAD, dot_request(env));
}

/*
 * invoked from efdaemon, /dev/fcode event has been read and /dev/fcode opened
 * file descriptor is fd 0.
 */
static void
get_efdaemon_request(fcode_env_t *env)
{
	common_data_t *cdp = env->private;

	cdp->fcode_fd = 0;
	if (ioctl(cdp->fcode_fd, FC_GET_PARAMETERS, &cdp->fc) < 0) {
		log_perror(MSG_FATAL, "ioctl(FC_GET_PARAMETERS) failed");
		exit(1);
	}

	if ((cdp->attach = fc_get_ap(cdp)) == 0)
		exit(1);

	get_my_args(env);

	DEBUGF(UPLOAD, dot_request(env));
}

static void
process_request(fcode_env_t *env)
{
	common_data_t *cdp = env->private;
	fstack_t fcode_len;
	char *path;

	build_tree(env);
	install_builtin_nodes(env);
	push_my_args(env);
	push_a_string(env, cdp->fc.unit_address);
	if ((path = get_path(env, env->attachment_pt)) == NULL) {
		log_message(MSG_FATAL, "Can't get_path of"
		    " attachment_pt %p\n", env->attachment_pt);
		exit(1);
	}
	debug_msg(DEBUG_UPLOAD, "Attach Point: %s\n", path);

	push_a_string(env, path);
	begin_package(env);
	find_fcode(env);
	fcode_len = POP(DS);
	if (!fcode_len) {
		(void) POP(DS);
		debug_msg(DEBUG_UPLOAD, "Zero length Fcode\n");
		return;
	}

	debug_msg(DEBUG_UPLOAD, "byte-load fcode_len: %x\n",
	    fcode_len);

	PUSH(DS, 1);
	byte_load(env);
	end_package(env);
	upload_nodes(env);
	validate_nodes(env);
	debug_msg(DEBUG_UPLOAD, "Upload Done\n");
}

static void
finish_request(fcode_env_t *env)
{
	common_data_t *cdp = env->private;

	close(cdp->fcode_fd);
}

/*
 * Non-daemon "do-request", for debugging
 */
static void
do_request(fcode_env_t *env)
{
	get_request(env);
	process_request(env);
	finish_request(env);
}

/*
 * This process one request from efdaemon, we know that /dev/fcode is already
 * open and passed in fd0 (stdin).  If it's not, we throw up our hands.
 */
void
run_one_efdaemon_request(fcode_env_t *env)
{
	get_efdaemon_request(env);
	process_request(env);
	finish_request(env);
	exit(0);
}

void
probe_space(fcode_env_t *env)
{
	fc_cell_t cfg = 0;
	int error;

	error = fc_run_priv(env->private, FC_PROBE_SPACE, 0, 1, &cfg);
	if (error)
		throw_from_fclib(env, 1, "FC_PROBE_SPACE failed\n");
	PUSH(DS, fc_cell2uint32_t(cfg));
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	FORTH(0,	"get-fcode-from-device",	get_fcode_from_device);
	FORTH(0,	"save-fcode-to-file",		save_fcode_to_file);
	FORTH(0,	"get-my-args",			get_my_args);
	FORTH(0,	"set-my-args",			set_my_args);
	FORTH(0,	".my-args",			dot_my_args);
	FORTH(0,	".request",			dot_request);
	FORTH(0,	"get-request",			get_request);
	FORTH(0,	"process-request",		process_request);
	FORTH(0,	"finish-request",		finish_request);
	FORTH(0,	"do-request",			do_request);
	FORTH(0,	"find-fcode",			find_fcode);
	FORTH(0,	"exec-fcode-builtin-method", exec_fcode_builtin_method);
	FORTH(0,	"run-one-efdaemon-request",  run_one_efdaemon_request);
	FORTH(0,	"get-efdaemon-request",		get_efdaemon_request);
	FORTH(0,	"probe-space",			probe_space);
}
