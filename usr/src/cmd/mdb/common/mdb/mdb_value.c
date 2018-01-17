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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Immediate Value Target
 *
 * The immediate value target is used when the '=' verb is used to
 * format an immediate value, or with ::print -i.  The target is
 * initialized with a specific value, and then simply copies bytes from
 * this integer in its read routine.  Two notes:
 *
 * (1) the address parameter of value_read is treated as an offset into
 * the immediate value.
 *
 * (2) on big-endian systems, we need to be careful about the place we
 * copy data from. If the caller specified a typesize in the argv array
 * we use that for offsetting, otherwise we use the read size.
 * If the user didn't specify the typesize, then 'addr' is ignored,
 * and all reads are at an offset of 0 into the immediate value. This
 * covers both the usage of ::print -i, and the semantics of adb
 * commands like "0x1234=X", which should produce 0x1234 as a result;
 * the adb model is for it to act like a cast down to the smaller
 * integer type; this is handled as mentioned.
 */

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_types.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>

#include <sys/isa_defs.h>
#include <strings.h>

void mdb_value_tgt_destroy(mdb_tgt_t *);

typedef struct mdb_value_data {
	uintmax_t mvd_data;
	size_t mvd_typesize;
} mdb_value_data_t;

static ssize_t
value_read(mdb_tgt_t *t, void *dst, size_t nbytes, uintptr_t addr)
{
	mdb_value_data_t *data = t->t_data;
	size_t size = data->mvd_typesize;
	const char *src = (const char *)&data->mvd_data;
	size_t off;

	/*
	 * If no output size was specified, use the current read size.
	 * In this case, "addr" is not an offset into the mvd_data,
	 * so we ignore it.
	 */
	if (size == 0) {
		size = nbytes;
		addr = 0;
	} else {
		nbytes = MIN(size, nbytes);
	}

	off = addr;
#ifdef _BIG_ENDIAN
	if (sizeof (uintmax_t) >= size)
		off += sizeof (uintmax_t) - size;
#endif

	if (off > sizeof (uintmax_t))
		return (0);
	if (off + nbytes > sizeof (uintmax_t))
		nbytes = sizeof (uintmax_t) - off;

	if (nbytes != 0)
		bcopy(src + off, dst, nbytes);

	return (nbytes);
}

/*ARGSUSED*/
static ssize_t
value_write(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	return (nbytes); /* We allow writes to silently fail */
}

static const mdb_tgt_ops_t value_ops = {
	(int (*)()) mdb_tgt_notsup,		/* t_setflags */
	(int (*)()) mdb_tgt_notsup,		/* t_setcontext */
	(void (*)()) mdb_tgt_nop,		/* t_activate */
	(void (*)()) mdb_tgt_nop,		/* t_deactivate */
	(void (*)()) mdb_tgt_nop,		/* t_periodic */
	mdb_value_tgt_destroy,			/* t_destroy */
	(const char *(*)()) mdb_tgt_null,	/* t_name */
	(const char *(*)()) mdb_conf_isa,	/* t_isa */
	(const char *(*)()) mdb_conf_platform,	/* t_platform */
	(int (*)()) mdb_tgt_notsup,		/* t_uname */
	(int (*)()) mdb_tgt_notsup,		/* t_dmodel */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_aread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_awrite */
	value_read,				/* t_vread */
	value_write,				/* t_vwrite */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_pread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_pwrite */
	value_read,				/* t_fread */
	value_write,				/* t_fwrite */
	value_read,				/* t_ioread */
	value_write,				/* t_iowrite */
	(int (*)()) mdb_tgt_notsup,		/* t_vtop */
	(int (*)()) mdb_tgt_notsup,		/* t_lookup_by_name */
	(int (*)()) mdb_tgt_notsup,		/* t_lookup_by_addr */
	(int (*)()) mdb_tgt_notsup,		/* t_symbol_iter */
	(int (*)()) mdb_tgt_notsup,		/* t_mapping_iter */
	(int (*)()) mdb_tgt_notsup,		/* t_object_iter */
	(const mdb_map_t *(*)()) mdb_tgt_null,	/* t_addr_to_map */
	(const mdb_map_t *(*)()) mdb_tgt_null,	/* t_name_to_map */
	(struct ctf_file *(*)()) mdb_tgt_null,	/* t_addr_to_ctf */
	(struct ctf_file *(*)()) mdb_tgt_null,	/* t_name_to_ctf */
	(int (*)()) mdb_tgt_notsup,		/* t_status */
	(int (*)()) mdb_tgt_notsup,		/* t_run */
	(int (*)()) mdb_tgt_notsup,		/* t_step */
	(int (*)()) mdb_tgt_notsup,		/* t_step_out */
	(int (*)()) mdb_tgt_notsup,		/* t_next */
	(int (*)()) mdb_tgt_notsup,		/* t_cont */
	(int (*)()) mdb_tgt_notsup,		/* t_signal */
	(int (*)()) mdb_tgt_null,		/* t_add_vbrkpt */
	(int (*)()) mdb_tgt_null,		/* t_add_sbrkpt */
	(int (*)()) mdb_tgt_null,		/* t_add_pwapt */
	(int (*)()) mdb_tgt_null,		/* t_add_vwapt */
	(int (*)()) mdb_tgt_null,		/* t_add_iowapt */
	(int (*)()) mdb_tgt_null,		/* t_add_sysenter */
	(int (*)()) mdb_tgt_null,		/* t_add_sysexit */
	(int (*)()) mdb_tgt_null,		/* t_add_signal */
	(int (*)()) mdb_tgt_null,		/* t_add_fault */
	(int (*)()) mdb_tgt_notsup,		/* t_getareg */
	(int (*)()) mdb_tgt_notsup,		/* t_putareg */
	(int (*)()) mdb_tgt_nop,		/* t_stack_iter */
	(int (*)()) mdb_tgt_notsup		/* t_auxv */
};

int
mdb_value_tgt_create(mdb_tgt_t *t, int argc, const char *argv[])
{
	mdb_value_data_t *data;

	if (argc < 1 || argv[0] == NULL)
		return (set_errno(EINVAL));
	if (argc == 2 && argv[1] == NULL)
		return (set_errno(EINVAL));
	if (argc > 2)
		return (set_errno(EINVAL));

	t->t_ops = &value_ops;
	data = mdb_zalloc(sizeof (mdb_value_data_t), UM_SLEEP);
	t->t_data = data;
	data->mvd_data = *((uintmax_t *)(void *)argv[0]);
	if (argc == 2)
		data->mvd_typesize = *((size_t *)(void *)argv[1]);

	return (0);
}

void
mdb_value_tgt_destroy(mdb_tgt_t *t)
{
	mdb_free(t->t_data, sizeof (mdb_value_data_t));
}
