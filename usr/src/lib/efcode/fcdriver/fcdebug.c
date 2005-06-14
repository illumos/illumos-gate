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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

static void
dump_private(fcode_env_t *env)
{
	common_data_t *cdp;
	private_data_t *p;

	if (env->current_device) {
		p = env->current_device->private;
		if (p) {
			cdp = p->common;
		} else
			cdp = NULL;
	} else {
		cdp = env->private;
		p = NULL;
	}

	if (cdp == NULL) {
		log_message(MSG_ERROR, "dump_private: NULL private ptr!\n");
		return;
	}

	log_message(MSG_DEBUG, "Private Data:\n");
	log_message(MSG_DEBUG, "Progname:  %s\n", cdp->Progname);
	log_message(MSG_DEBUG, "fcode_fd:  %8p\n", cdp->fcode_fd);
	log_message(MSG_DEBUG, "attach:    %llx\n", cdp->attach);
	log_message(MSG_DEBUG, "Params:    (%8p)\n", &cdp->fc);
	log_message(MSG_DEBUG, "  size:    %d\n", cdp->fc.fcode_size);
	log_message(MSG_DEBUG, "  unit:    %s\n", cdp->fc.unit_address);
	if (p != NULL) {
		log_message(MSG_DEBUG, "Node:      %p\n", p->node);
		log_message(MSG_DEBUG, "Parent:    %p\n", p->parent);
		log_message(MSG_DEBUG, "upload:    %d\n", p->upload);
		log_message(MSG_DEBUG, "debug:     %8x\n", p->debug);
	}
}

static void
trigger(fcode_env_t *env)
{
	common_data_t *cdp = (common_data_t *)env->private;

	ASSERT(cdp);

	cdp->fcode_fd = open("/dev/fcode", O_RDONLY);
	if (cdp->fcode_fd >= 0) {
		log_message(MSG_INFO, "Trigger...");
		if (!fc_get_request(cdp))
			log_message(MSG_ERROR, "fc_get_request failed\n");
		else
			log_message(MSG_INFO, "\n");
	} else
		forth_abort(env, "Can't open /dev/fcode\n");
}

static void
do_trigger(fcode_env_t *env)
{
	trigger(env);
	build_tree(env);
	install_builtin_nodes(env);
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	FORTH(0,	"dump-private",		dump_private);
	FORTH(0,	"trigger",		do_trigger);
}
