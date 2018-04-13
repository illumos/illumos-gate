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
 * Raw File Target
 *
 * The raw file target is invoked whenever a file of unrecognizable type is
 * specified on the command line, or when raw file examination is forced using
 * the -f option.  If one file is specified, that file will be opened as the
 * "object" file.  If two files are specified, the second one will be opened
 * as the "core" file.  Each file is opened using the fdio backend, which
 * internally supports both byte-oriented i/o and block-oriented i/o as needed.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#include <sys/dtrace.h>
#include <fcntl.h>

typedef struct rf_data {
	mdb_io_t *r_object_fio;
	mdb_io_t *r_core_fio;
} rf_data_t;

#define	RF_OBJECT(p)	(((rf_data_t *)(p))->r_object_fio)
#define	RF_CORE(p)	(((rf_data_t *)(p))->r_core_fio)

static void
rf_data_destroy(rf_data_t *rf)
{
	if (rf->r_object_fio != NULL)
		mdb_io_destroy(rf->r_object_fio);

	if (rf->r_core_fio != NULL)
		mdb_io_destroy(rf->r_core_fio);

	mdb_free(rf, sizeof (rf_data_t));
}

static int
rf_setflags(mdb_tgt_t *t, int flags)
{
	if ((flags ^ t->t_flags) & MDB_TGT_F_RDWR) {
		uint_t otflags = t->t_flags;
		rf_data_t *orf = t->t_data;
		const char *argv[2];
		int argc = 0;

		if (orf->r_object_fio != NULL)
			argv[argc++] = IOP_NAME(orf->r_object_fio);
		if (orf->r_core_fio != NULL)
			argv[argc++] = IOP_NAME(orf->r_core_fio);

		t->t_flags = (t->t_flags & ~MDB_TGT_F_RDWR) |
		    (flags & MDB_TGT_F_RDWR);

		if (mdb_rawfile_tgt_create(t, argc, argv) == -1) {
			t->t_flags = otflags;
			t->t_data = orf;
			return (-1);
		}

		rf_data_destroy(orf);
	}

	return (0);
}

static void
rf_destroy(mdb_tgt_t *t)
{
	rf_data_destroy(t->t_data);
}

/*ARGSUSED*/
static const char *
rf_name(mdb_tgt_t *t)
{
	return ("raw");
}

static ssize_t
rf_read(mdb_io_t *io, void *buf, size_t nbytes, uint64_t addr)
{
	ssize_t rbytes;

	if (io == NULL)
		return (set_errno(EMDB_NOMAP));

	if (IOP_SEEK(io, addr, SEEK_SET) == -1)
		return (-1); /* errno is set for us */

	if ((rbytes = IOP_READ(io, buf, nbytes)) == 0)
		(void) set_errno(EMDB_EOF);

	return (rbytes);
}

static ssize_t
rf_write(mdb_io_t *io, const void *buf, size_t nbytes, uint64_t addr)
{
	if (io == NULL)
		return (set_errno(EMDB_NOMAP));

	if (IOP_SEEK(io, addr, SEEK_SET) == -1)
		return (-1); /* errno is set for us */

	return (IOP_WRITE(io, buf, nbytes));
}

static ssize_t
rf_aread(mdb_tgt_t *t, mdb_tgt_as_t as, void *buf,
    size_t len, mdb_tgt_addr_t addr)
{
	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_VIRT:
	case (uintptr_t)MDB_TGT_AS_PHYS:
		if (RF_CORE(t->t_data) != NULL)
			return (rf_read(RF_CORE(t->t_data), buf, len, addr));
		/*FALLTHRU*/
	case (uintptr_t)MDB_TGT_AS_FILE:
		return (rf_read(RF_OBJECT(t->t_data), buf, len, addr));
	default:
		return (set_errno(EMDB_NOMAP));
	}
}

static ssize_t
rf_awrite(mdb_tgt_t *t, mdb_tgt_as_t as, const void *buf,
    size_t len, mdb_tgt_addr_t addr)
{
	switch ((uintptr_t)as) {
	case (uintptr_t)MDB_TGT_AS_VIRT:
	case (uintptr_t)MDB_TGT_AS_PHYS:
		if (RF_CORE(t->t_data) != NULL)
			return (rf_write(RF_CORE(t->t_data), buf, len, addr));
		/*FALLTHRU*/
	case (uintptr_t)MDB_TGT_AS_FILE:
		return (rf_write(RF_OBJECT(t->t_data), buf, len, addr));
	default:
		return (set_errno(EMDB_NOMAP));
	}
}

static ssize_t
rf_vread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	if (RF_CORE(t->t_data) != NULL)
		return (rf_read(RF_CORE(t->t_data), buf, nbytes, addr));

	return (rf_read(RF_OBJECT(t->t_data), buf, nbytes, addr));
}

static ssize_t
rf_vwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	if (RF_CORE(t->t_data) != NULL)
		return (rf_write(RF_CORE(t->t_data), buf, nbytes, addr));

	return (rf_write(RF_OBJECT(t->t_data), buf, nbytes, addr));
}

static ssize_t
rf_pread(mdb_tgt_t *t, void *buf, size_t nbytes, physaddr_t addr)
{
	if (RF_CORE(t->t_data) != NULL)
		return (rf_read(RF_CORE(t->t_data), buf, nbytes, addr));

	return (rf_read(RF_OBJECT(t->t_data), buf, nbytes, addr));
}

static ssize_t
rf_pwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, physaddr_t addr)
{
	if (RF_CORE(t->t_data) != NULL)
		return (rf_write(RF_CORE(t->t_data), buf, nbytes, addr));

	return (rf_write(RF_OBJECT(t->t_data), buf, nbytes, addr));
}

static ssize_t
rf_fread(mdb_tgt_t *t, void *buf, size_t nbytes, uintptr_t addr)
{
	return (rf_read(RF_OBJECT(t->t_data), buf, nbytes, addr));
}

static ssize_t
rf_fwrite(mdb_tgt_t *t, const void *buf, size_t nbytes, uintptr_t addr)
{
	return (rf_write(RF_OBJECT(t->t_data), buf, nbytes, addr));
}


static int
rf_print_map(mdb_io_t *io, const char *type, int tflags,
    mdb_tgt_map_f *func, void *private)
{
	mdb_map_t map;

	(void) mdb_iob_snprintf(map.map_name, MDB_TGT_MAPSZ,
	    "%s (%s)", IOP_NAME(io), type);

	map.map_base = 0;
	map.map_size = IOP_SEEK(io, 0, SEEK_END);
	map.map_flags = MDB_TGT_MAP_R;

	if (tflags & MDB_TGT_F_RDWR)
		map.map_flags |= MDB_TGT_MAP_W;

	return (func(private, &map, map.map_name));
}

static int
rf_mapping_iter(mdb_tgt_t *t, mdb_tgt_map_f *func, void *private)
{
	rf_data_t *rf = t->t_data;

	if (rf->r_object_fio != NULL && rf_print_map(rf->r_object_fio,
	    "object file", t->t_flags, func, private) != 0)
		return (0);

	if (rf->r_core_fio != NULL && rf_print_map(rf->r_core_fio,
	    "core file", t->t_flags, func, private) != 0)
		return (0);

	return (0);
}

/*ARGSUSED*/
static int
rf_status(mdb_tgt_t *t, mdb_tgt_status_t *tsp)
{
	bzero(tsp, sizeof (mdb_tgt_status_t));

	if (RF_CORE(t->t_data) != NULL)
		tsp->st_state = MDB_TGT_DEAD;
	else
		tsp->st_state = MDB_TGT_IDLE;

	return (0);
}

/*ARGSUSED*/
static int
rf_status_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	rf_data_t *rf = mdb.m_target->t_data;

	if (rf->r_object_fio != NULL) {
		mdb_printf("debugging file '%s' (object file)",
		    IOP_NAME(rf->r_object_fio));

		if (rf->r_core_fio != NULL) {
			mdb_printf(" and file '%s' (core file)",
			    IOP_NAME(rf->r_core_fio));
		}

		mdb_printf("\n");
	} else {
		mdb_printf("debugging empty target\n");
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t rf_dcmds[] = {
	{ "status", NULL, "print summary of current target", rf_status_dcmd },
	{ NULL }
};

static const struct rf_magic {
	const char *rfm_str;
	size_t rfm_len;
	const char *rfm_mod;
} rf_magic[] = {
	{ DOF_MAG_STRING, DOF_MAG_STRLEN, "dof" },
	{ NULL, 0, NULL }
};

static void
rf_activate(mdb_tgt_t *t)
{
	rf_data_t *rf = t->t_data;
	const struct rf_magic *m;
	mdb_var_t *v;
	off64_t size;

	(void) mdb_tgt_register_dcmds(t, &rf_dcmds[0], MDB_MOD_FORCE);

	/*
	 * We set the legacy adb variable 'd' to be the size of the file (data
	 * segment).  To get this value, we call seek() on the underlying fdio.
	 */
	if (rf->r_object_fio != NULL) {
		size = IOP_SEEK(rf->r_object_fio, 0, SEEK_END);
		if ((v = mdb_nv_lookup(&mdb.m_nv, "d")) != NULL)
			mdb_nv_set_value(v, size);
	}

	/*
	 * Load any debugging support modules that match the file type, as
	 * determined by our poor man's /etc/magic.  If many clients need
	 * to use this feature, rf_magic[] should be computed dynamically.
	 */
	for (m = rf_magic; m->rfm_str != NULL; m++) {
		char *buf = mdb_alloc(m->rfm_len, UM_SLEEP);

		if (mdb_tgt_vread(t, buf, m->rfm_len, 0) == m->rfm_len &&
		    bcmp(buf, m->rfm_str, m->rfm_len) == 0) {
			(void) mdb_module_load(m->rfm_mod,
			    MDB_MOD_LOCAL | MDB_MOD_SILENT);
		}

		mdb_free(buf, m->rfm_len);
	}
}

static void
rf_deactivate(mdb_tgt_t *t)
{
	const mdb_dcmd_t *dcp;

	for (dcp = &rf_dcmds[0]; dcp->dc_name != NULL; dcp++) {
		if (mdb_module_remove_dcmd(t->t_module, dcp->dc_name) == -1)
			warn("failed to remove dcmd %s", dcp->dc_name);
	}
}

static const mdb_tgt_ops_t rawfile_ops = {
	rf_setflags,				/* t_setflags */
	(int (*)()) mdb_tgt_notsup,		/* t_setcontext */
	rf_activate,				/* t_activate */
	rf_deactivate,				/* t_deactivate */
	(void (*)()) mdb_tgt_nop,		/* t_periodic */
	rf_destroy,				/* t_destroy */
	rf_name,				/* t_name */
	(const char *(*)()) mdb_conf_isa,	/* t_isa */
	(const char *(*)()) mdb_conf_platform,	/* t_platform */
	(int (*)()) mdb_tgt_notsup,		/* t_uname */
	(int (*)()) mdb_tgt_notsup,		/* t_dmodel */
	rf_aread,				/* t_aread */
	rf_awrite,				/* t_awrite */
	rf_vread,				/* t_vread */
	rf_vwrite,				/* t_vwrite */
	rf_pread,				/* t_pread */
	rf_pwrite,				/* t_pwrite */
	rf_fread,				/* t_fread */
	rf_fwrite,				/* t_fwrite */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_ioread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_iowrite */
	(int (*)()) mdb_tgt_notsup,		/* t_vtop */
	(int (*)()) mdb_tgt_notsup,		/* t_lookup_by_name */
	(int (*)()) mdb_tgt_notsup,		/* t_lookup_by_addr */
	(int (*)()) mdb_tgt_notsup,		/* t_symbol_iter */
	rf_mapping_iter,			/* t_mapping_iter */
	rf_mapping_iter,			/* t_object_iter */
	(const mdb_map_t *(*)()) mdb_tgt_null,	/* t_addr_to_map */
	(const mdb_map_t *(*)()) mdb_tgt_null,	/* t_name_to_map */
	(struct ctf_file *(*)()) mdb_tgt_null,	/* t_addr_to_ctf */
	(struct ctf_file *(*)()) mdb_tgt_null,	/* t_name_to_ctf */
	rf_status,				/* t_status */
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
	(int (*)()) mdb_tgt_notsup,		/* t_stack_iter */
	(int (*)()) mdb_tgt_notsup		/* t_auxv */
};

int
mdb_rawfile_tgt_create(mdb_tgt_t *t, int argc, const char *argv[])
{
	mdb_io_t *io[2] = { NULL, NULL };
	rf_data_t *rf;
	int oflags, i;

	if (argc > 2)
		return (set_errno(EINVAL));

	rf = mdb_zalloc(sizeof (rf_data_t), UM_SLEEP);
	t->t_ops = &rawfile_ops;
	t->t_data = rf;

	if (t->t_flags & MDB_TGT_F_RDWR)
		oflags = O_RDWR;
	else
		oflags = O_RDONLY;

	for (i = 0; i < argc; i++) {
		io[i] = mdb_fdio_create_path(NULL, argv[i], oflags, 0);
		if (io[i] == NULL) {
			warn("failed to open %s", argv[i]);
			goto err;
		}
	}

	rf->r_object_fio = io[0];	/* first file is the "object" */
	rf->r_core_fio = io[1];		/* second file is the "core" */
	t->t_flags |= MDB_TGT_F_ASIO;	/* do i/o using aread and awrite */

	return (0);

err:
	for (i = 0; i < argc; i++) {
		if (io[i] != NULL)
			mdb_io_destroy(io[i]);
	}


	mdb_free(rf, sizeof (rf_data_t));
	return (set_errno(EMDB_TGT));
}
