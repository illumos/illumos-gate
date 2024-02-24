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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 */

#include <mdb/mdb_disasm_impl.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_nv.h>
#include <mdb/mdb.h>

#include <libdisasm.h>

int
mdb_dis_select(const char *name)
{
	mdb_var_t *v = mdb_nv_lookup(&mdb.m_disasms, name);

	if (v != NULL) {
		mdb.m_disasm = mdb_nv_get_cookie(v);
		return (0);
	}

	if (mdb.m_target == NULL) {
		if (mdb.m_defdisasm != NULL)
			strfree(mdb.m_defdisasm);
		mdb.m_defdisasm = strdup(name);
		return (0);
	}

	return (set_errno(EMDB_NODIS));
}

mdb_disasm_t *
mdb_dis_create(mdb_dis_ctor_f *ctor)
{
	mdb_disasm_t *dp = mdb_zalloc(sizeof (mdb_disasm_t), UM_SLEEP);

	if ((dp->dis_module = mdb.m_lmod) == NULL)
		dp->dis_module = &mdb.m_rmod;

	if (ctor(dp) == 0) {
		mdb_var_t *v = mdb_nv_lookup(&mdb.m_disasms, dp->dis_name);

		if (v != NULL) {
			dp->dis_ops->dis_destroy(dp);
			mdb_free(dp, sizeof (mdb_disasm_t));
			(void) set_errno(EMDB_DISEXISTS);
			return (NULL);
		}

		(void) mdb_nv_insert(&mdb.m_disasms, dp->dis_name, NULL,
		    (uintptr_t)dp, MDB_NV_RDONLY | MDB_NV_SILENT);

		if (mdb.m_disasm == NULL) {
			mdb.m_disasm = dp;
		} else if (mdb.m_defdisasm != NULL &&
		    strcmp(mdb.m_defdisasm, dp->dis_name) == 0) {
			mdb.m_disasm = dp;
			strfree(mdb.m_defdisasm);
			mdb.m_defdisasm = NULL;
		}

		return (dp);
	}

	mdb_free(dp, sizeof (mdb_disasm_t));
	return (NULL);
}

void
mdb_dis_destroy(mdb_disasm_t *dp)
{
	mdb_var_t *v = mdb_nv_lookup(&mdb.m_disasms, dp->dis_name);

	ASSERT(v != NULL);
	mdb_nv_remove(&mdb.m_disasms, v);
	dp->dis_ops->dis_destroy(dp);
	mdb_free(dp, sizeof (mdb_disasm_t));

	if (mdb.m_disasm == dp)
		(void) mdb_dis_select("default");
}

mdb_tgt_addr_t
mdb_dis_ins2str(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    char *buf, size_t len, mdb_tgt_addr_t addr)
{
	return (dp->dis_ops->dis_ins2str(dp, t, as, buf, len, addr));
}

mdb_tgt_addr_t
mdb_dis_previns(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t addr, uint_t n)
{
	return (dp->dis_ops->dis_previns(dp, t, as, addr, n));
}

mdb_tgt_addr_t
mdb_dis_nextins(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t addr)
{
	return (dp->dis_ops->dis_nextins(dp, t, as, addr));
}

/*ARGSUSED*/
int
cmd_dismode(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) || argc > 1)
		return (DCMD_USAGE);

	if (argc != 0) {
		const char *name;

		if (argv->a_type == MDB_TYPE_STRING)
			name = argv->a_un.a_str;
		else
			name = numtostr(argv->a_un.a_val, 10, NTOS_UNSIGNED);

		if (mdb_dis_select(name) == -1) {
			warn("failed to set disassembly mode");
			return (DCMD_ERR);
		}
	}

	mdb_printf("disassembly mode is %s (%s)\n",
	    mdb.m_disasm->dis_name, mdb.m_disasm->dis_desc);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
print_dis(mdb_var_t *v, void *ignore)
{
	mdb_disasm_t *dp = mdb_nv_get_cookie(v);

	mdb_printf("%-24s - %s\n", dp->dis_name, dp->dis_desc);
	return (0);
}

/*ARGSUSED*/
int
cmd_disasms(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if ((flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	mdb_nv_sort_iter(&mdb.m_disasms, print_dis, NULL, UM_SLEEP | UM_GC);
	return (DCMD_OK);
}

/*
 * Generic libdisasm disassembler interfaces.
 */

#define	DISBUFSZ	64

/*
 * Internal structure used by the read and lookup routines.
 */
typedef struct dis_buf {
	mdb_tgt_t	*db_tgt;
	mdb_tgt_as_t	db_as;
	mdb_tgt_addr_t	db_addr;
	mdb_tgt_addr_t	db_nextaddr;
	uchar_t		db_buf[DISBUFSZ];
	ssize_t		db_bufsize;
	boolean_t	db_readerr;
} dis_buf_t;

/*
 * Disassembler support routine for lookup up an address.  Rely on mdb's "%a"
 * qualifier to convert the address to a symbol.
 */
/*ARGSUSED*/
static int
libdisasm_lookup(void *data, uint64_t addr, char *buf, size_t buflen,
    uint64_t *start, size_t *len)
{
	char c;
	GElf_Sym sym;

	if (buf != NULL) {
#ifdef __sparc
		uint32_t instr[3];
		uint32_t dtrace_id;

		/*
		 * On SPARC, DTrace FBT trampoline entries have a sethi/or pair
		 * that indicates the dtrace probe id; this may appear as the
		 * first two instructions or one instruction into the
		 * trampoline.
		 */
		if (mdb_vread(instr, sizeof (instr), (uintptr_t)addr) ==
		    sizeof (instr)) {
			if ((instr[0] & 0xfffc0000) == 0x11000000 &&
			    (instr[1] & 0xffffe000) == 0x90122000) {
				dtrace_id = (instr[0] << 10) |
				    (instr[1] & 0x1fff);
				(void) mdb_snprintf(buf, sizeof (buf), "dt=%#x",
				    dtrace_id);
				goto out;
			} else if ((instr[1] & 0xfffc0000) == 0x11000000 &&
			    (instr[2] & 0xffffe000) == 0x90122000) {
				dtrace_id = (instr[1] << 10) |
				    (instr[2] & 0x1fff);
				(void) mdb_snprintf(buf, sizeof (buf), "dt=%#x",
				    dtrace_id);
				goto out;
			}
		}
#endif
		(void) mdb_snprintf(buf, buflen, "%a", (uintptr_t)addr);
	}

#ifdef __sparc
out:
#endif
	if (mdb_lookup_by_addr(addr, MDB_SYM_FUZZY, &c, 1, &sym) < 0)
		return (-1);
	if (start != NULL)
		*start = sym.st_value;
	if (len != NULL)
		*len = sym.st_size;

	return (0);
}

/*
 * Disassembler support routine for reading from the target.  Rather than having
 * to read one byte at a time, we read from the address space in chunks.  If the
 * current address doesn't lie within our buffer range, we read in the chunk
 * starting from the given address.
 */
static int
libdisasm_read(void *data, uint64_t pc, void *buf, size_t buflen)
{
	dis_buf_t *db = data;
	size_t offset;
	size_t len;

	if (pc - db->db_addr >= db->db_bufsize) {
		if (mdb_tgt_aread(db->db_tgt, db->db_as, db->db_buf,
		    sizeof (db->db_buf), pc) != -1) {
			db->db_bufsize = sizeof (db->db_buf);
		} else if (mdb_tgt_aread(db->db_tgt, db->db_as, db->db_buf,
		    buflen, pc) != -1) {
			db->db_bufsize = buflen;
		} else {
			if (!db->db_readerr)
				mdb_warn("failed to read instruction at %#lr",
				    (uintptr_t)pc);
			db->db_readerr = B_TRUE;
			return (-1);
		}
		db->db_addr = pc;
	}

	offset = pc - db->db_addr;

	len = MIN(buflen, db->db_bufsize - offset);

	(void) memcpy(buf, (char *)db->db_buf + offset, len);
	db->db_nextaddr = pc + len;

	return (len);
}

static mdb_tgt_addr_t
libdisasm_ins2str(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    char *buf, size_t len, mdb_tgt_addr_t pc)
{
	dis_handle_t *dhp = dp->dis_data;
	dis_buf_t db = { 0 };
	const char *p;

	/*
	 * Set the libdisasm data to point to our buffer.  This will be
	 * passed as the first argument to the lookup and read functions.
	 */
	db.db_tgt = t;
	db.db_as = as;

	dis_set_data(dhp, &db);

	if ((p = mdb_tgt_name(t)) != NULL && strcmp(p, "proc") == 0) {
		/* check for ELF ET_REL type; turn on NOIMMSYM if so */
		GElf_Ehdr	leh;

		if (mdb_tgt_getxdata(t, "ehdr", &leh, sizeof (leh)) != -1 &&
		    leh.e_type == ET_REL)  {
			dis_flags_set(dhp, DIS_NOIMMSYM);
		} else {
			dis_flags_clear(dhp, DIS_NOIMMSYM);
		}
	}

	/*
	 * Attempt to disassemble the instruction.  If this fails because of an
	 * unknown opcode, drive on anyway.  If it fails because we couldn't
	 * read from the target, bail out immediately.
	 */
	if (dis_disassemble(dhp, pc, buf, len) != 0)
		(void) mdb_snprintf(buf, len,
		    "***ERROR--unknown op code***");

	if (db.db_readerr)
		return (pc);

	/*
	 * Return the updated location
	 */
	return (db.db_nextaddr);
}

static mdb_tgt_addr_t
libdisasm_previns(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t pc, uint_t n)
{
	dis_handle_t *dhp = dp->dis_data;
	dis_buf_t db = { 0 };

	/*
	 * Set the libdisasm data to point to our buffer.  This will be
	 * passed as the first argument to the lookup and read functions.
	 * We set 'readerr' to B_TRUE to turn off the mdb_warn() in
	 * libdisasm_read, because the code works by probing backwards until a
	 * valid address is found.
	 */
	db.db_tgt = t;
	db.db_as = as;
	db.db_readerr = B_TRUE;

	dis_set_data(dhp, &db);

	return (dis_previnstr(dhp, pc, n));
}

/*ARGSUSED*/
static mdb_tgt_addr_t
libdisasm_nextins(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t pc)
{
	mdb_tgt_addr_t npc;
	char c;

	if ((npc = libdisasm_ins2str(dp, t, as, &c, 1, pc)) == pc)
		return (pc);

	/*
	 * Probe the address to make sure we can read something from it - we
	 * want the address we return to actually contain something.
	 */
	if (mdb_tgt_aread(t, as, &c, 1, npc) != 1)
		return (pc);

	return (npc);
}

static void
libdisasm_destroy(mdb_disasm_t *dp)
{
	dis_handle_t *dhp = dp->dis_data;

	dis_handle_destroy(dhp);
}

static const mdb_dis_ops_t libdisasm_ops = {
	.dis_destroy = libdisasm_destroy,
	.dis_ins2str = libdisasm_ins2str,
	.dis_previns = libdisasm_previns,
	.dis_nextins = libdisasm_nextins
};

/*
 * Generic function for creating a libdisasm-backed disassembler.  Creates an
 * MDB disassembler with the given name backed by libdis with the given flags.
 */
static int
libdisasm_create(mdb_disasm_t *dp, const char *name,
    const char *desc, int flags)
{
	if ((dp->dis_data = dis_handle_create(flags, NULL, libdisasm_lookup,
	    libdisasm_read)) == NULL)
		return (-1);

	dp->dis_name = name;
	dp->dis_ops = &libdisasm_ops;
	dp->dis_desc = desc;

	return (0);
}

#if defined(__i386) || defined(__amd64)
static int
ia16_create(mdb_disasm_t *dp)
{
	return (libdisasm_create(dp,
	    "ia16",
	    "Intel 16-bit disassembler",
	    DIS_X86_SIZE16));
}

static int
ia32_create(mdb_disasm_t *dp)
{
	return (libdisasm_create(dp,
	    "ia32",
	    "Intel 32-bit disassembler",
	    DIS_X86_SIZE32));
}
#endif

#if defined(__amd64)
static int
amd64_create(mdb_disasm_t *dp)
{
	return (libdisasm_create(dp,
	    "amd64",
	    "AMD64 and IA32e 64-bit disassembler",
	    DIS_X86_SIZE64));
}
#endif

#if defined(__sparc)
static int
sparc1_create(mdb_disasm_t *dp)
{
	return (libdisasm_create(dp,
	    "1",
	    "SPARC-v8 disassembler",
	    DIS_SPARC_V8));
}

static int
sparc2_create(mdb_disasm_t *dp)
{
	return (libdisasm_create(dp,
	    "2",
	    "SPARC-v9 disassembler",
	    DIS_SPARC_V9));
}

static int
sparc4_create(mdb_disasm_t *dp)
{
	return (libdisasm_create(dp,
	    "4",
	    "UltraSPARC1-v9 disassembler",
	    DIS_SPARC_V9 | DIS_SPARC_V9_SGI));
}

static int
sparcv8_create(mdb_disasm_t *dp)
{
	return (libdisasm_create(dp,
	    "v8",
	    "SPARC-v8 disassembler",
	    DIS_SPARC_V8));
}

static int
sparcv9_create(mdb_disasm_t *dp)
{
	return (libdisasm_create(dp,
	    "v9",
	    "SPARC-v9 disassembler",
	    DIS_SPARC_V9));
}

static int
sparcv9plus_create(mdb_disasm_t *dp)
{
	return (libdisasm_create(dp,
	    "v9plus",
	    "UltraSPARC1-v9 disassembler",
	    DIS_SPARC_V9 | DIS_SPARC_V9_SGI));
}
#endif

/*ARGSUSED*/
static void
defdis_destroy(mdb_disasm_t *dp)
{
	/* Nothing to do here */
}

/*ARGSUSED*/
static mdb_tgt_addr_t
defdis_ins2str(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    char *buf, size_t len, mdb_tgt_addr_t addr)
{
	return (addr);
}

/*ARGSUSED*/
static mdb_tgt_addr_t
defdis_previns(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t addr, uint_t n)
{
	return (addr);
}

/*ARGSUSED*/
static mdb_tgt_addr_t
defdis_nextins(mdb_disasm_t *dp, mdb_tgt_t *t, mdb_tgt_as_t as,
    mdb_tgt_addr_t addr)
{
	return (addr);
}

static const mdb_dis_ops_t defdis_ops = {
	.dis_destroy = defdis_destroy,
	.dis_ins2str = defdis_ins2str,
	.dis_previns = defdis_previns,
	.dis_nextins = defdis_nextins,
};

static int
defdis_create(mdb_disasm_t *dp)
{
	dp->dis_name = "default";
	dp->dis_desc = "default no-op disassembler";
	dp->dis_ops = &defdis_ops;

	return (0);
}

mdb_dis_ctor_f *const mdb_dis_builtins[] = {
	defdis_create,
#if defined(__amd64)
	ia16_create,
	ia32_create,
	amd64_create,
#elif defined(__i386)
	ia16_create,
	ia32_create,
#elif defined(__sparc)
	sparc1_create,
	sparc2_create,
	sparc4_create,
	sparcv8_create,
	sparcv9_create,
	sparcv9plus_create,
#endif
	NULL
};
