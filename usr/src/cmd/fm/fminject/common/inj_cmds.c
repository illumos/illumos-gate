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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The "program" executed by the injector consists of a tree of commands.
 * Routines in this file build and execute said command tree.
 */

#include <sys/fm/protocol.h>
#include <unistd.h>

#include <inj.h>
#include <inj_event.h>
#include <inj_lex.h>
#include <inj_err.h>

/*
 * Command tree construction
 */

static inj_list_t inj_cmds;

void
inj_cmds_add(inj_cmd_t *cmd)
{
	inj_list_append(&inj_cmds, cmd);
}

inj_list_t *
inj_cmds_get(void)
{
	return (&inj_cmds);
}

inj_randelem_t *
inj_rand_create(inj_defn_t *ev, uint_t prob)
{
	inj_randelem_t *re = inj_zalloc(sizeof (inj_randelem_t));

	re->re_event = ev;
	re->re_prob = prob;

	return (re);
}

inj_randelem_t *
inj_rand_add(inj_randelem_t *list, inj_randelem_t *new)
{
	new->re_next = list;
	return (new);
}

inj_cmd_t *
inj_cmd_rand(inj_randelem_t *rlist)
{
	inj_randelem_t *r;
	inj_cmd_t *cmd;
	uint_t prob, tmpprob;
	int nelems, i;

	prob = 0;
	for (i = 0, r = rlist; r != NULL; r = r->re_next, i++)
		prob += r->re_prob;

	if (prob != 100) {
		yyerror("probabilities don't sum to 100\n");
		return (NULL);
	}

	nelems = i;

	cmd = inj_zalloc(sizeof (inj_cmd_t));
	cmd->cmd_type = CMD_RANDOM;
	cmd->cmd_num = nelems;
	cmd->cmd_rand = inj_alloc(sizeof (inj_randelem_t *) * nelems);

	prob = 0;
	for (r = rlist, i = 0; i < nelems; i++, r = r->re_next) {
		tmpprob = r->re_prob;
		r->re_prob = prob;
		prob += tmpprob;

		cmd->cmd_rand[i] = r;
	}

	return (cmd);
}

inj_cmd_t *
inj_cmd_repeat(inj_cmd_t *repcmd, uint_t num)
{
	inj_cmd_t *cmd = inj_zalloc(sizeof (inj_cmd_t));

	cmd->cmd_type = CMD_REPEAT;
	cmd->cmd_num = num;
	cmd->cmd_subcmd = repcmd;

	return (cmd);
}

inj_cmd_t *
inj_cmd_send(inj_defn_t *ev)
{
	inj_cmd_t *cmd = inj_zalloc(sizeof (inj_cmd_t));

	cmd->cmd_type = CMD_SEND_EVENT;
	cmd->cmd_event = ev;

	return (cmd);
}

inj_cmd_t *
inj_cmd_sleep(uint_t secs)
{
	inj_cmd_t *cmd = inj_zalloc(sizeof (inj_cmd_t));

	cmd->cmd_type = CMD_SLEEP;
	cmd->cmd_num = secs;

	return (cmd);
}

inj_cmd_t *
inj_cmd_addhrt(hrtime_t delta)
{
	const char *class = "resource.fm.fmd.clock.addhrtime";
	inj_cmd_t *cmd = inj_zalloc(sizeof (inj_cmd_t));
	inj_defn_t *ev = inj_zalloc(sizeof (inj_defn_t));

	ev->defn_name = class;
	ev->defn_lineno = yylineno;

	if ((errno = nvlist_alloc(&ev->defn_nvl, NV_UNIQUE_NAME, 0)) != 0)
		die("failed to allocate nvl for %s event", class);

	if ((errno = nvlist_add_string(ev->defn_nvl, FM_CLASS, class)) != 0 ||
	    (errno = nvlist_add_uint8(ev->defn_nvl, FM_VERSION, 1)) != 0 ||
	    (errno = nvlist_add_int64(ev->defn_nvl, "delta", delta)) != 0)
		die("failed to build nvl for %s event", class);

	cmd->cmd_type = CMD_SEND_EVENT;
	cmd->cmd_event = ev;

	return (cmd);
}

inj_cmd_t *
inj_cmd_endhrt(void)
{
	return (inj_cmd_addhrt(-1LL)); /* clock underflow causes end of time */
}

static uint64_t
inj_ena(void)
{
	return (((gethrtime() & ENA_FMT1_TIME_MASK) <<
	    ENA_FMT1_TIME_SHFT) | (FM_ENA_FMT1 & ENA_FORMAT_MASK));
}

static void
cmd_run_send(const inj_mode_ops_t *mode, void *hdl, inj_defn_t *ev)
{
	if (!quiet) {
		(void) printf("sending event %s ... ", ev->defn_name);
		(void) fflush(stdout);
	}

	if ((errno = nvlist_add_boolean_value(ev->defn_nvl, "__injected",
	    1)) != 0)
		warn("failed to add __injected to %s", ev->defn_name);

	if (ev->defn_decl && (ev->defn_decl->decl_flags & DECL_F_AUTOENA) &&
	    (errno = nvlist_add_uint64(ev->defn_nvl, "ena", inj_ena())) != 0)
		warn("failed to add ena to %s", ev->defn_name);

	if (verbose) {
		nvlist_print(stdout, ev->defn_nvl);
		(void) printf("\n");
	}

	mode->mo_send(hdl, ev->defn_nvl);

	if (!quiet)
		(void) printf("done\n");
}

static void
cmd_run_random(const inj_mode_ops_t *mode, void *hdl, inj_cmd_t *cmd)
{
	uint_t num = lrand48() % 100;
	int i;

	for (i = 1; i < cmd->cmd_num; i++) {
		if (cmd->cmd_rand[i]->re_prob > num)
			break;
	}

	cmd_run_send(mode, hdl, cmd->cmd_rand[i - 1]->re_event);
}

static void
cmd_run(const inj_mode_ops_t *mode, void *hdl, inj_cmd_t *cmd)
{
	switch (cmd->cmd_type) {
	case CMD_SEND_EVENT:
		cmd_run_send(mode, hdl, cmd->cmd_event);
		break;

	case CMD_SLEEP:
		(void) printf("sleeping for %d sec%s ... ",
		    cmd->cmd_num, cmd->cmd_num > 1 ? "s" : "");
		(void) fflush(stdout);
		(void) sleep(cmd->cmd_num);
		(void) printf("done\n");
		break;

	case CMD_RANDOM:
		cmd_run_random(mode, hdl, cmd);
		break;

	default:
		warn("ignoring unknown command type: %d\n", cmd->cmd_type);
	}
}

void
inj_program_run(inj_list_t *prog, const inj_mode_ops_t *mode, void *mode_arg)
{
	void *hdl = mode->mo_open(mode_arg);
	inj_cmd_t *cmd;
	int i;

	for (cmd = inj_list_next(prog); cmd != NULL; cmd = inj_list_next(cmd)) {
		if (cmd->cmd_type == CMD_REPEAT) {
			for (i = 1; i <= cmd->cmd_num; i++) {
				if (verbose) {
					(void) printf("(repeat %d of %d)\n",
					    i, cmd->cmd_num);
				}
				cmd_run(mode, hdl, cmd->cmd_subcmd);
			}
		} else
			cmd_run(mode, hdl, cmd);
	}

	mode->mo_close(hdl);
}
