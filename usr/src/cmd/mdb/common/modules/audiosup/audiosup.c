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

#include <mdb/mdb_modapi.h>
#include <sys/types.h>
#include <sys/audio/audio_trace.h>

typedef struct audiotrace_walk_data {
	uintptr_t aw_bufstart;
	uintptr_t aw_bufend;
	int aw_cnt;
} audiotrace_walk_data_t;

int
audiotrace_walk_init(mdb_walk_state_t *wsp)
{
	size_t size;
	uint_t seq, pos;
	GElf_Sym sym;
	audio_trace_buf_t *buffer;
	audio_trace_buf_t atb[2];
	audiotrace_walk_data_t *aw;

	if (mdb_readvar(&size, "audio_tb_siz") == -1) {
		mdb_warn("failed to read 'audio_tb_siz'");
		return (WALK_ERR);
	}

	if (size == 0)
		return (WALK_DONE);

	if (mdb_lookup_by_name("audio_trace_buffer", &sym) == -1) {
		mdb_warn("failed to find 'audio_trace_buffer'");
		return (WALK_ERR);
	}

	buffer = (audio_trace_buf_t *)(uintptr_t)sym.st_value;

	if (mdb_readvar(&seq, "audio_tb_seq") == -1) {
		mdb_warn("failed to read 'audio_tb_seq'");
		return (WALK_ERR);
	}

	if (mdb_readvar(&pos, "audio_tb_pos") == -1) {
		mdb_warn("failed to read 'audio_tb_pos'");
		return (WALK_ERR);
	}

	/* by default start the walk with the first buffer entry */
	wsp->walk_addr = (uintptr_t)buffer;

	if (seq > size && pos > 0) {
		/* start the walk with the oldest buffer entry */

		if (mdb_vread(&atb, sizeof (atb),
		    (uintptr_t)(buffer + pos - 1)) == -1) {
			mdb_warn("failed to read audio_trace_buf_t at %p",
			    buffer + pos - 1);
			return (WALK_ERR);
		}

		if (atb[1].atb_seq < atb[0].atb_seq)
			wsp->walk_addr = (uintptr_t)(buffer + pos);
	}

	aw = mdb_alloc(sizeof (audiotrace_walk_data_t), UM_SLEEP);
	aw->aw_bufstart = (uintptr_t)buffer;
	aw->aw_bufend = (uintptr_t)(buffer + size);
	aw->aw_cnt = MIN(seq, size);
	wsp->walk_data = aw;

	return (WALK_NEXT);
}

int
audiotrace_walk_step(mdb_walk_state_t *wsp)
{
	uintptr_t addr = wsp->walk_addr;
	audiotrace_walk_data_t *aw = wsp->walk_data;
	audio_trace_buf_t atb;

	if (aw->aw_cnt == 0)
		return (WALK_DONE);

	aw->aw_cnt--;
	wsp->walk_addr += sizeof (audio_trace_buf_t);

	if (wsp->walk_addr >= aw->aw_bufend)
		wsp->walk_addr = aw->aw_bufstart;

	if (mdb_vread(&atb, sizeof (atb), addr) == -1) {
		mdb_warn("failed to read audio_trace_buf_t at %p", addr);
		return (WALK_DONE);
	}

	return (wsp->walk_callback(addr, &atb, wsp->walk_cbdata));
}

void
audiotrace_walk_fini(mdb_walk_state_t *wsp)
{
	mdb_free(wsp->walk_data, sizeof (audiotrace_walk_data_t));
}


/*ARGSUSED*/
int
audiotrace(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	int count;
	uint_t seq;
	const mdb_arg_t *argp = &argv[0];
	audio_trace_buf_t atb;
	char str[256];

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("audiotrace", "audiotrace", argc, argv)
		    == -1) {
			mdb_warn("can't walk audio trace buffer entries");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (argc > 1)
		return (DCMD_USAGE);

	/*
	 * Specifying an address and a count at the same time doesn't make
	 * sense.
	 */
	if (argc == 1 && !(flags & DCMD_LOOP))
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%<u>%6s %?s %-40s%</u>\n",
		    "SEQNO", "DATA", "COMMENT");

	if (mdb_vread(&atb, sizeof (atb), addr) == -1) {
		mdb_warn("failed to read audiotrace_t at %p", addr);
		return (DCMD_ERR);
	}

	if (argc == 1) {
		/*
		 * Display the last 'count' entries only. Skip any other
		 * entries.
		 */
		if (mdb_readvar(&seq, "audio_tb_seq") == -1) {
			mdb_warn("failed to read 'audio_tb_seq'");
			return (DCMD_ERR);
		}

		if (argp->a_type == MDB_TYPE_IMMEDIATE)
			count = argp->a_un.a_val;
		else
			count = mdb_strtoull(argp->a_un.a_str);

		if (atb.atb_seq < seq - count)
			return (DCMD_OK);
	}

	if (mdb_readstr(str, sizeof (str), (uintptr_t)atb.atb_comment) == -1) {
		mdb_warn("failed to read string at %p", atb.atb_comment);
		return (DCMD_ERR);
	}

	mdb_printf("%6d %?x %s\n", atb.atb_seq, atb.atb_data, str);

	return (DCMD_OK);
}

void
audiotrace_help(void)
{
	mdb_printf(
	    "If count is specified ::audiotrace prints the specified\n"
	    "number of entries from the logical end of the trace buffer.\n");
}

/*
 * MDB module linkage
 */
static const mdb_dcmd_t dcmds[] = {
	{ "audiotrace", "?[count]", "display audio trace buffer entries",
	    audiotrace, audiotrace_help },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "audiotrace", "walk audio trace buffer entries", audiotrace_walk_init,
	    audiotrace_walk_step, audiotrace_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
