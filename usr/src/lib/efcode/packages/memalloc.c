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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

/*
 * claim under /openprom/client-services is used by schizo and oberon Fcode, we
 * call "claim-memory" service.
 */
void
claim(fcode_env_t *env)
{
	size_t size;
	void *hint;
	int align;
	fc_cell_t vaddr;
	int error;

	CHECK_DEPTH(env, 3, "claim-memory");
	hint = (void *)POP(DS);
	size = POP(DS);
	align = POP(DS);
	error = fc_run_priv(env->private, "claim-memory", 3, 1,
	    fc_int2cell(align), fc_size2cell(size), fc_ptr2cell(hint), &vaddr);
	if (error)
		throw_from_fclib(env, 1, "client-services/claim failed\n");
	vaddr = mapping_to_mcookie(vaddr, size, 0, 0);
	PUSH(DS, (fstack_t)vaddr);
}

void
release(fcode_env_t *env)
{
	size_t size;
	void *addr;
	int error;

	CHECK_DEPTH(env, 2, "release-memory");
	addr = (void *)POP(DS);
	size = POP(DS);
	error = fc_run_priv(env->private, "release-memory", 2, 0,
	    fc_size2cell(size), fc_ptr2cell(addr));
	if (error)
		throw_from_fclib(env, 1, "client-services/release failed\n");
	delete_mapping((fstack_t)addr);
}

static void
fc_vtop(fcode_env_t *env)
{
	void *vaddr;
	fc_cell_t physlo, physhi;
	int error;

	CHECK_DEPTH(env, 1, "vtop");
	vaddr = (void *)POP(DS);
	error = fc_run_priv(env->private, "vtop", 1, 2,
	    fc_ptr2cell(vaddr), &physlo, &physhi);
	if (error)
		throw_from_fclib(env, 1, "fc_vtop: '>physical' failed\n");

	PUSH(DS, physlo);
	PUSH(DS, physhi);
}

void
install_openprom_nodes(fcode_env_t *env)
{
	MYSELF = open_instance_chain(env, env->root_node, 0);
	if (MYSELF != NULL) {
		make_a_node(env, "openprom", 0);
		make_a_node(env, "client-services", 0);
		FORTH(0,	"claim",	claim);
		FORTH(0,	"release",	release);
		finish_device(env);
		finish_device(env);
		close_instance_chain(env, MYSELF, 0);
		device_end(env);
		MYSELF = 0;
	}
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	FORTH(0,	"install-openprom-nodes",	install_openprom_nodes);
	FORTH(0,	"claim",			claim);
	FORTH(0,	"release",			release);
	P1275(0x106,	0,	">physical",		fc_vtop);
}
