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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>
#include <dtrace.h>

extern int dof_sec(uintptr_t, uint_t, int, const mdb_arg_t *);
extern const char *dof_sec_name(uint32_t);

extern const mdb_walker_t kernel_walkers[];
extern const mdb_dcmd_t kernel_dcmds[];

/*ARGSUSED*/
static void
dis_log(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	mdb_printf("%-4s %%r%u, %%r%u, %%r%u", name,
	    DIF_INSTR_R1(instr), DIF_INSTR_R2(instr), DIF_INSTR_RD(instr));
}

/*ARGSUSED*/
static void
dis_branch(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	mdb_printf("%-4s %u", name, DIF_INSTR_LABEL(instr));
}

/*ARGSUSED*/
static void
dis_load(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	mdb_printf("%-4s [%%r%u], %%r%u", name,
	    DIF_INSTR_R1(instr), DIF_INSTR_RD(instr));
}

/*ARGSUSED*/
static void
dis_store(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	mdb_printf("%-4s %%r%u, [%%r%u]", name,
	    DIF_INSTR_R1(instr), DIF_INSTR_RD(instr));
}

/*ARGSUSED*/
static void
dis_str(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	mdb_printf("%s", name);
}

/*ARGSUSED*/
static void
dis_r1rd(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	mdb_printf("%-4s %%r%u, %%r%u", name,
	    DIF_INSTR_R1(instr), DIF_INSTR_RD(instr));
}

/*ARGSUSED*/
static void
dis_cmp(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	mdb_printf("%-4s %%r%u, %%r%u", name,
	    DIF_INSTR_R1(instr), DIF_INSTR_R2(instr));
}

/*ARGSUSED*/
static void
dis_tst(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	mdb_printf("%-4s %%r%u", name, DIF_INSTR_R1(instr));
}

static const char *
dis_varname(const dtrace_difo_t *dp, uint_t id, uint_t scope)
{
	dtrace_difv_t *dvp;
	size_t varsize;
	caddr_t addr = NULL, str;
	uint_t i;

	if (dp == NULL)
		return (NULL);

	varsize = sizeof (dtrace_difv_t) * dp->dtdo_varlen;
	dvp = mdb_alloc(varsize, UM_SLEEP);

	if (mdb_vread(dvp, varsize, (uintptr_t)dp->dtdo_vartab) == -1) {
		mdb_free(dvp, varsize);
		return ("<unreadable>");
	}

	for (i = 0; i < dp->dtdo_varlen; i++) {
		if (dvp[i].dtdv_id == id && dvp[i].dtdv_scope == scope) {
			if (dvp[i].dtdv_name < dp->dtdo_strlen)
				addr = dp->dtdo_strtab + dvp[i].dtdv_name;
			break;
		}
	}

	mdb_free(dvp, varsize);

	if (addr == NULL)
		return (NULL);

	str = mdb_zalloc(dp->dtdo_strlen + 1, UM_SLEEP | UM_GC);

	for (i = 0; i == 0 || str[i - 1] != '\0'; i++, addr++) {
		if (mdb_vread(&str[i], sizeof (char), (uintptr_t)addr) == -1)
			return ("<unreadable>");
	}

	return (str);
}

static uint_t
dis_scope(const char *name)
{
	switch (name[2]) {
	case 'l': return (DIFV_SCOPE_LOCAL);
	case 't': return (DIFV_SCOPE_THREAD);
	case 'g': return (DIFV_SCOPE_GLOBAL);
	default: return (-1u);
	}
}

static void
dis_lda(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	uint_t var = DIF_INSTR_R1(instr);
	const char *vname;

	mdb_printf("%-4s DIF_VAR(%x), %%r%u, %%r%u", name,
	    var, DIF_INSTR_R2(instr), DIF_INSTR_RD(instr));

	if ((vname = dis_varname(dp, var, dis_scope(name))) != NULL)
		mdb_printf("\t\t! %s", vname);
}

static void
dis_ldv(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	uint_t var = DIF_INSTR_VAR(instr);
	const char *vname;

	mdb_printf("%-4s DIF_VAR(%x), %%r%u", name, var, DIF_INSTR_RD(instr));

	if ((vname = dis_varname(dp, var, dis_scope(name))) != NULL)
		mdb_printf("\t\t! %s", vname);
}

static void
dis_stv(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	uint_t var = DIF_INSTR_VAR(instr);
	const char *vname;

	mdb_printf("%-4s %%r%u, DIF_VAR(%x)", name, DIF_INSTR_RS(instr), var);

	if ((vname = dis_varname(dp, var, dis_scope(name))) != NULL)
		mdb_printf("\t\t! %s", vname);
}

static void
dis_setx(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	uint_t intptr = DIF_INSTR_INTEGER(instr);

	mdb_printf("%-4s DIF_INTEGER[%u], %%r%u", name,
	    intptr, DIF_INSTR_RD(instr));

	if (dp != NULL && intptr < dp->dtdo_intlen) {
		uint64_t *ip = mdb_alloc(dp->dtdo_intlen *
		    sizeof (uint64_t), UM_SLEEP | UM_GC);

		if (mdb_vread(ip, dp->dtdo_intlen * sizeof (uint64_t),
		    (uintptr_t)dp->dtdo_inttab) == -1)
			mdb_warn("failed to read data at %p", dp->dtdo_inttab);
		else
			mdb_printf("\t\t! 0x%llx", ip[intptr]);
	}
}

static void
dis_sets(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	uint_t strptr = DIF_INSTR_STRING(instr);

	mdb_printf("%-4s DIF_STRING[%u], %%r%u", name,
	    strptr, DIF_INSTR_RD(instr));

	if (dp != NULL && strptr < dp->dtdo_strlen) {
		char *str = mdb_alloc(dp->dtdo_strlen, UM_SLEEP | UM_GC);

		if (mdb_vread(str, dp->dtdo_strlen,
		    (uintptr_t)dp->dtdo_strtab) == -1)
			mdb_warn("failed to read data at %p", dp->dtdo_strtab);
		else
			mdb_printf("\t\t! \"%s\"", str + strptr);
	}
}

/*ARGSUSED*/
static void
dis_ret(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	mdb_printf("%-4s %%r%u", name, DIF_INSTR_RD(instr));
}

/*ARGSUSED*/
static void
dis_call(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	uint_t subr = DIF_INSTR_SUBR(instr);

	mdb_printf("%-4s DIF_SUBR(%u), %%r%u\t\t! %s",
	    name, subr, DIF_INSTR_RD(instr), dtrace_subrstr(NULL, subr));
}

/*ARGSUSED*/
static void
dis_pushts(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	static const char *const tnames[] = { "TYPE_CTF", "TYPE_STRING" };
	uint_t type = DIF_INSTR_TYPE(instr);

	mdb_printf("%-4s DIF_TYPE(%u), %%r%u, %%r%u",
	    name, type, DIF_INSTR_R2(instr), DIF_INSTR_RS(instr));

	if (type < sizeof (tnames) / sizeof (tnames[0]))
		mdb_printf("\t\t! %s", tnames[type]);
}

/*ARGSUSED*/
static void
dis_xlate(const dtrace_difo_t *dp, const char *name, dif_instr_t instr)
{
	mdb_printf("%-4s DIF_XLREF[%u], %%r%u", name,
	    DIF_INSTR_XLREF(instr), DIF_INSTR_RD(instr));
}

static char *
dis_typestr(const dtrace_diftype_t *t, char *buf, size_t len)
{
	char kind[8];

	switch (t->dtdt_kind) {
	case DIF_TYPE_CTF:
		(void) strcpy(kind, "D type");
		break;
	case DIF_TYPE_STRING:
		(void) strcpy(kind, "string");
		break;
	default:
		(void) mdb_snprintf(kind, sizeof (kind), "0x%x", t->dtdt_kind);
	}

	if (t->dtdt_flags & DIF_TF_BYREF) {
		(void) mdb_snprintf(buf, len,
		    "%s by ref (size %lu)",
		    kind, (ulong_t)t->dtdt_size);
	} else {
		(void) mdb_snprintf(buf, len, "%s (size %lu)",
		    kind, (ulong_t)t->dtdt_size);
	}

	return (buf);
}

static int
dis(uintptr_t addr, dtrace_difo_t *dp)
{
	static const struct opent {
		const char *op_name;
		void (*op_func)(const dtrace_difo_t *,
		    const char *, dif_instr_t);
	} optab[] = {
		{ "(illegal opcode)", dis_str },
		{ "or", dis_log },		/* DIF_OP_OR */
		{ "xor", dis_log },		/* DIF_OP_XOR */
		{ "and", dis_log },		/* DIF_OP_AND */
		{ "sll", dis_log },		/* DIF_OP_SLL */
		{ "srl", dis_log },		/* DIF_OP_SRL */
		{ "sub", dis_log },		/* DIF_OP_SUB */
		{ "add", dis_log },		/* DIF_OP_ADD */
		{ "mul", dis_log },		/* DIF_OP_MUL */
		{ "sdiv", dis_log },		/* DIF_OP_SDIV */
		{ "udiv", dis_log },		/* DIF_OP_UDIV */
		{ "srem", dis_log },		/* DIF_OP_SREM */
		{ "urem", dis_log },		/* DIF_OP_UREM */
		{ "not", dis_r1rd },		/* DIF_OP_NOT */
		{ "mov", dis_r1rd },		/* DIF_OP_MOV */
		{ "cmp", dis_cmp },		/* DIF_OP_CMP */
		{ "tst", dis_tst },		/* DIF_OP_TST */
		{ "ba", dis_branch },		/* DIF_OP_BA */
		{ "be", dis_branch },		/* DIF_OP_BE */
		{ "bne", dis_branch },		/* DIF_OP_BNE */
		{ "bg", dis_branch },		/* DIF_OP_BG */
		{ "bgu", dis_branch },		/* DIF_OP_BGU */
		{ "bge", dis_branch },		/* DIF_OP_BGE */
		{ "bgeu", dis_branch },		/* DIF_OP_BGEU */
		{ "bl", dis_branch },		/* DIF_OP_BL */
		{ "blu", dis_branch },		/* DIF_OP_BLU */
		{ "ble", dis_branch },		/* DIF_OP_BLE */
		{ "bleu", dis_branch },		/* DIF_OP_BLEU */
		{ "ldsb", dis_load },		/* DIF_OP_LDSB */
		{ "ldsh", dis_load },		/* DIF_OP_LDSH */
		{ "ldsw", dis_load },		/* DIF_OP_LDSW */
		{ "ldub", dis_load },		/* DIF_OP_LDUB */
		{ "lduh", dis_load },		/* DIF_OP_LDUH */
		{ "lduw", dis_load },		/* DIF_OP_LDUW */
		{ "ldx", dis_load },		/* DIF_OP_LDX */
		{ "ret", dis_ret },		/* DIF_OP_RET */
		{ "nop", dis_str },		/* DIF_OP_NOP */
		{ "setx", dis_setx },		/* DIF_OP_SETX */
		{ "sets", dis_sets },		/* DIF_OP_SETS */
		{ "scmp", dis_cmp },		/* DIF_OP_SCMP */
		{ "ldga", dis_lda },		/* DIF_OP_LDGA */
		{ "ldgs", dis_ldv },		/* DIF_OP_LDGS */
		{ "stgs", dis_stv },		/* DIF_OP_STGS */
		{ "ldta", dis_lda },		/* DIF_OP_LDTA */
		{ "ldts", dis_ldv },		/* DIF_OP_LDTS */
		{ "stts", dis_stv },		/* DIF_OP_STTS */
		{ "sra", dis_log },		/* DIF_OP_SRA */
		{ "call", dis_call },		/* DIF_OP_CALL */
		{ "pushtr", dis_pushts },	/* DIF_OP_PUSHTR */
		{ "pushtv", dis_pushts },	/* DIF_OP_PUSHTV */
		{ "popts", dis_str },		/* DIF_OP_POPTS */
		{ "flushts", dis_str },		/* DIF_OP_FLUSHTS */
		{ "ldgaa", dis_ldv },		/* DIF_OP_LDGAA */
		{ "ldtaa", dis_ldv },		/* DIF_OP_LDTAA */
		{ "stgaa", dis_stv },		/* DIF_OP_STGAA */
		{ "sttaa", dis_stv },		/* DIF_OP_STTAA */
		{ "ldls", dis_ldv },		/* DIF_OP_LDLS */
		{ "stls", dis_stv },		/* DIF_OP_STLS */
		{ "allocs", dis_r1rd },		/* DIF_OP_ALLOCS */
		{ "copys", dis_log },		/* DIF_OP_COPYS */
		{ "stb", dis_store },		/* DIF_OP_STB */
		{ "sth", dis_store },		/* DIF_OP_STH */
		{ "stw", dis_store },		/* DIF_OP_STW */
		{ "stx", dis_store },		/* DIF_OP_STX */
		{ "uldsb", dis_load },		/* DIF_OP_ULDSB */
		{ "uldsh", dis_load },		/* DIF_OP_ULDSH */
		{ "uldsw", dis_load },		/* DIF_OP_ULDSW */
		{ "uldub", dis_load },		/* DIF_OP_ULDUB */
		{ "ulduh", dis_load },		/* DIF_OP_ULDUH */
		{ "ulduw", dis_load },		/* DIF_OP_ULDUW */
		{ "uldx", dis_load },		/* DIF_OP_ULDX */
		{ "rldsb", dis_load },		/* DIF_OP_RLDSB */
		{ "rldsh", dis_load },		/* DIF_OP_RLDSH */
		{ "rldsw", dis_load },		/* DIF_OP_RLDSW */
		{ "rldub", dis_load },		/* DIF_OP_RLDUB */
		{ "rlduh", dis_load },		/* DIF_OP_RLDUH */
		{ "rlduw", dis_load },		/* DIF_OP_RLDUW */
		{ "rldx", dis_load },		/* DIF_OP_RLDX */
		{ "xlate", dis_xlate },		/* DIF_OP_XLATE */
		{ "xlarg", dis_xlate },		/* DIF_OP_XLARG */
	};

	dif_instr_t instr, opcode;
	const struct opent *op;

	if (mdb_vread(&instr, sizeof (dif_instr_t), addr) == -1) {
		mdb_warn("failed to read DIF instruction at %p", addr);
		return (DCMD_ERR);
	}

	opcode = DIF_INSTR_OP(instr);

	if (opcode >= sizeof (optab) / sizeof (optab[0]))
		opcode = 0; /* force invalid opcode message */

	op = &optab[opcode];
	mdb_printf("%0?p %08x ", addr, instr);
	op->op_func(dp, op->op_name, instr);
	mdb_printf("\n");
	mdb_set_dot(addr + sizeof (dif_instr_t));

	return (DCMD_OK);
}

/*ARGSUSED*/
int
difo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_difo_t difo, *dp = &difo;
	uintptr_t instr, limit;
	dtrace_difv_t *dvp;
	size_t varsize;
	ulong_t i;
	char type[64];
	char *str;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(dp, sizeof (dtrace_difo_t), addr) == -1) {
		mdb_warn("couldn't read dtrace_difo_t at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%<u>DIF Object 0x%p%</u> (refcnt=%d)\n\n",
	    addr, dp->dtdo_refcnt);
	mdb_printf("%<b>%-?s %-8s %s%</b>\n", "ADDR", "OPCODE", "INSTRUCTION");

	mdb_set_dot((uintmax_t)(uintptr_t)dp->dtdo_buf);
	limit = (uintptr_t)dp->dtdo_buf + dp->dtdo_len * sizeof (dif_instr_t);

	while ((instr = mdb_get_dot()) < limit)
		dis(instr, dp);

	if (dp->dtdo_varlen != 0) {
		mdb_printf("\n%<b>%-16s %-4s %-3s %-3s %-4s %s%</b>\n",
		    "NAME", "ID", "KND", "SCP", "FLAG", "TYPE");
	}

	varsize = sizeof (dtrace_difv_t) * dp->dtdo_varlen;
	dvp = mdb_alloc(varsize, UM_SLEEP | UM_GC);

	if (mdb_vread(dvp, varsize, (uintptr_t)dp->dtdo_vartab) == -1) {
		mdb_warn("couldn't read dtdo_vartab");
		return (DCMD_ERR);
	}

	str = mdb_alloc(dp->dtdo_strlen, UM_SLEEP | UM_GC);

	if (mdb_vread(str, dp->dtdo_strlen, (uintptr_t)dp->dtdo_strtab) == -1) {
		mdb_warn("couldn't read dtdo_strtab");
		return (DCMD_ERR);
	}

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dvp[i];
		char kind[4], scope[4], flags[16] = { 0 };

		switch (v->dtdv_kind) {
		case DIFV_KIND_ARRAY:
			(void) strcpy(kind, "arr");
			break;
		case DIFV_KIND_SCALAR:
			(void) strcpy(kind, "scl");
			break;
		default:
			(void) mdb_snprintf(kind, sizeof (kind),
			    "%u", v->dtdv_kind);
		}

		switch (v->dtdv_scope) {
		case DIFV_SCOPE_GLOBAL:
			(void) strcpy(scope, "glb");
			break;
		case DIFV_SCOPE_THREAD:
			(void) strcpy(scope, "tls");
			break;
		case DIFV_SCOPE_LOCAL:
			(void) strcpy(scope, "loc");
			break;
		default:
			(void) mdb_snprintf(scope, sizeof (scope),
			    "%u", v->dtdv_scope);
		}

		if (v->dtdv_flags & ~(DIFV_F_REF | DIFV_F_MOD)) {
			(void) mdb_snprintf(flags, sizeof (flags), "/0x%x",
			    v->dtdv_flags & ~(DIFV_F_REF | DIFV_F_MOD));
		}

		if (v->dtdv_flags & DIFV_F_REF)
			(void) strcat(flags, "/r");
		if (v->dtdv_flags & DIFV_F_MOD)
			(void) strcat(flags, "/w");

		mdb_printf("%-16s %-4x %-3s %-3s %-4s %s\n",
		    &str[v->dtdv_name],
		    v->dtdv_id, kind, scope, flags + 1,
		    dis_typestr(&v->dtdv_type, type, sizeof (type)));
	}

	mdb_printf("\n%<b>RETURN%</b>\n%s\n\n",
	    dis_typestr(&dp->dtdo_rtype, type, sizeof (type)));

	return (DCMD_OK);
}

/*ARGSUSED*/
int
difinstr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	return (dis(addr, NULL));
}

/*ARGSUSED*/
int
dof_hdr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dof_hdr_t h;

	if (argc != 0)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC))
		addr = 0; /* assume base of file in file target */

	if (mdb_vread(&h, sizeof (h), addr) != sizeof (h)) {
		mdb_warn("failed to read header at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("dofh_ident.id_magic = 0x%x, %c, %c, %c\n",
	    h.dofh_ident[DOF_ID_MAG0], h.dofh_ident[DOF_ID_MAG1],
	    h.dofh_ident[DOF_ID_MAG2], h.dofh_ident[DOF_ID_MAG3]);

	switch (h.dofh_ident[DOF_ID_MODEL]) {
	case DOF_MODEL_ILP32:
		mdb_printf("dofh_ident.id_model = ILP32\n");
		break;
	case DOF_MODEL_LP64:
		mdb_printf("dofh_ident.id_model = LP64\n");
		break;
	default:
		mdb_printf("dofh_ident.id_model = 0x%x\n",
		    h.dofh_ident[DOF_ID_MODEL]);
	}

	switch (h.dofh_ident[DOF_ID_ENCODING]) {
	case DOF_ENCODE_LSB:
		mdb_printf("dofh_ident.id_encoding = LSB\n");
		break;
	case DOF_ENCODE_MSB:
		mdb_printf("dofh_ident.id_encoding = MSB\n");
		break;
	default:
		mdb_printf("dofh_ident.id_encoding = 0x%x\n",
		    h.dofh_ident[DOF_ID_ENCODING]);
	}

	mdb_printf("dofh_ident.id_version = %u\n",
	    h.dofh_ident[DOF_ID_VERSION]);
	mdb_printf("dofh_ident.id_difvers = %u\n",
	    h.dofh_ident[DOF_ID_DIFVERS]);
	mdb_printf("dofh_ident.id_difireg = %u\n",
	    h.dofh_ident[DOF_ID_DIFIREG]);
	mdb_printf("dofh_ident.id_diftreg = %u\n",
	    h.dofh_ident[DOF_ID_DIFTREG]);

	mdb_printf("dofh_flags = 0x%x\n", h.dofh_flags);
	mdb_printf("dofh_hdrsize = %u\n", h.dofh_hdrsize);
	mdb_printf("dofh_secsize = %u\n", h.dofh_secsize);
	mdb_printf("dofh_secnum = %u\n", h.dofh_secnum);
	mdb_printf("dofh_secoff = %llu\n", h.dofh_secoff);
	mdb_printf("dofh_loadsz = %llu\n", h.dofh_loadsz);
	mdb_printf("dofh_filesz = %llu\n", h.dofh_filesz);

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
dof_sec_walk(uintptr_t addr, void *ignored, int *sec)
{
	mdb_printf("%3d ", (*sec)++);
	(void) dof_sec(addr, DCMD_ADDRSPEC | DCMD_LOOP, 0, NULL);
	return (WALK_NEXT);
}

/*ARGSUSED*/
int
dof_sec(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *name;
	dof_sec_t s;

	if (!(flags & DCMD_ADDRSPEC))
		mdb_printf("%<u>%-3s ", "NDX");

	if (!(flags & DCMD_ADDRSPEC) || DCMD_HDRSPEC(flags)) {
		mdb_printf("%<u>%?s %-10s %-5s %-5s %-5s %-6s %-5s%</u>\n",
		    "ADDR", "TYPE", "ALIGN", "FLAGS", "ENTSZ", "OFFSET",
		    "SIZE");
	}

	if (!(flags & DCMD_ADDRSPEC)) {
		int sec = 0;

		if (mdb_walk("dof_sec",
		    (mdb_walk_cb_t)dof_sec_walk, &sec) == -1) {
			mdb_warn("failed to walk dof_sec");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (argc != 0)
		return (DCMD_USAGE);

	if (mdb_vread(&s, sizeof (s), addr) != sizeof (s)) {
		mdb_warn("failed to read section header at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%?p ", addr);

	if ((name = dof_sec_name(s.dofs_type)) != NULL)
		mdb_printf("%-10s ", name);
	else
		mdb_printf("%-10u ", s.dofs_type);

	mdb_printf("%-5u %-#5x %-#5x %-6llx %-#5llx\n", s.dofs_align,
	    s.dofs_flags, s.dofs_entsize, s.dofs_offset, s.dofs_size);

	return (DCMD_OK);
}

int
dof_sec_walk_init(mdb_walk_state_t *wsp)
{
	dof_hdr_t h, *hp;
	size_t size;

	if (mdb_vread(&h, sizeof (h), wsp->walk_addr) != sizeof (h)) {
		mdb_warn("failed to read DOF header at %p", wsp->walk_addr);
		return (WALK_ERR);
	}

	size = sizeof (dof_hdr_t) + sizeof (dof_sec_t) * h.dofh_secnum;
	hp = mdb_alloc(size, UM_SLEEP);

	if (mdb_vread(hp, size, wsp->walk_addr) != size) {
		mdb_warn("failed to read DOF sections at %p", wsp->walk_addr);
		mdb_free(hp, size);
		return (WALK_ERR);
	}

	wsp->walk_arg = (void *)0;
	wsp->walk_data = hp;

	return (WALK_NEXT);
}

int
dof_sec_walk_step(mdb_walk_state_t *wsp)
{
	uint_t i = (uintptr_t)wsp->walk_arg;
	size_t off = sizeof (dof_hdr_t) + sizeof (dof_sec_t) * i;
	dof_hdr_t *hp = wsp->walk_data;
	dof_sec_t *sp = (dof_sec_t *)((uintptr_t)hp + off);

	if (i >= hp->dofh_secnum)
		return (WALK_DONE);

	wsp->walk_arg = (void *)(uintptr_t)(i + 1);
	return (wsp->walk_callback(wsp->walk_addr + off, sp, wsp->walk_cbdata));
}

void
dof_sec_walk_fini(mdb_walk_state_t *wsp)
{
	dof_hdr_t *hp = wsp->walk_data;
	mdb_free(hp, sizeof (dof_hdr_t) + sizeof (dof_sec_t) * hp->dofh_secnum);
}

/*ARGSUSED*/
int
dof_ecbdesc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dof_ecbdesc_t e;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&e, sizeof (e), addr) != sizeof (e)) {
		mdb_warn("failed to read ecbdesc at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("dofe_probes = %d\n", e.dofe_probes);
	mdb_printf("dofe_actions = %d\n", e.dofe_actions);
	mdb_printf("dofe_pred = %d\n", e.dofe_pred);
	mdb_printf("dofe_uarg = 0x%llx\n", e.dofe_uarg);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
dof_probedesc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dof_probedesc_t p;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&p, sizeof (p), addr) != sizeof (p)) {
		mdb_warn("failed to read probedesc at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("dofp_strtab = %d\n", p.dofp_strtab);
	mdb_printf("dofp_provider = %u\n", p.dofp_provider);
	mdb_printf("dofp_mod = %u\n", p.dofp_mod);
	mdb_printf("dofp_func = %u\n", p.dofp_func);
	mdb_printf("dofp_name = %u\n", p.dofp_name);
	mdb_printf("dofp_id = %u\n", p.dofp_id);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
dof_actdesc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dof_actdesc_t a;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&a, sizeof (a), addr) != sizeof (a)) {
		mdb_warn("failed to read actdesc at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("dofa_difo = %d\n", a.dofa_difo);
	mdb_printf("dofa_strtab = %d\n", a.dofa_strtab);
	mdb_printf("dofa_kind = %u\n", a.dofa_kind);
	mdb_printf("dofa_ntuple = %u\n", a.dofa_ntuple);
	mdb_printf("dofa_arg = 0x%llx\n", a.dofa_arg);
	mdb_printf("dofa_uarg = 0x%llx\n", a.dofa_uarg);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
dof_relohdr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dof_relohdr_t r;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&r, sizeof (r), addr) != sizeof (r)) {
		mdb_warn("failed to read relohdr at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("dofr_strtab = %d\n", r.dofr_strtab);
	mdb_printf("dofr_relsec = %d\n", r.dofr_relsec);
	mdb_printf("dofr_tgtsec = %d\n", r.dofr_tgtsec);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
dof_relodesc(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dof_relodesc_t r;

	if (argc != 0 || !(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&r, sizeof (r), addr) != sizeof (r)) {
		mdb_warn("failed to read relodesc at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("dofr_name = %u\n", r.dofr_name);
	mdb_printf("dofr_type = %u\n", r.dofr_type);
	mdb_printf("dofr_offset = 0x%llx\n", r.dofr_offset);
	mdb_printf("dofr_data = 0x%llx\n", r.dofr_data);

	return (DCMD_OK);
}

static int
dof_sect_strtab(uintptr_t addr, dof_sec_t *sec)
{
	char *strtab;
	size_t sz, i;

	sz = (size_t)sec->dofs_size;
	strtab = mdb_alloc(sz, UM_SLEEP | UM_GC);
	if (mdb_vread(strtab, sz, addr + sec->dofs_offset) != sz) {
		mdb_warn("failed to read string table");
		return (1);
	}

	mdb_printf("size = %lx\n", sz);

	for (i = 0; i < sz; i++) {
		if (strtab[i] == '\0')
			mdb_printf("\\0");
		else
			mdb_printf("%c", strtab[i]);
	}

	mdb_printf("\n");

	return (0);
}

static int
dof_sect_provider(dof_hdr_t *dofh, uintptr_t addr, dof_sec_t *sec,
    dof_sec_t *dofs)
{
	dof_provider_t pv;
	dof_probe_t *pb;
	char *strtab, *p;
	uint32_t *offs, *enoffs;
	uint8_t *args = NULL;
	size_t sz;
	int i, j;
	dof_stridx_t narg, xarg;

	sz = MIN(sec->dofs_size, sizeof (dof_provider_t));
	if (mdb_vread(&pv, sz, addr + sec->dofs_offset) != sz) {
		mdb_warn("failed to read DOF provider");
		return (-1);
	}

	sz = dofs[pv.dofpv_strtab].dofs_size;
	strtab = mdb_alloc(sz, UM_SLEEP | UM_GC);
	if (mdb_vread(strtab, sz, addr +
	    dofs[pv.dofpv_strtab].dofs_offset) != sz) {
		mdb_warn("failed to read string table");
		return (-1);
	}

	mdb_printf("%lx provider %s {\n", (ulong_t)(addr + sec->dofs_offset),
	    strtab + pv.dofpv_name);

	sz = dofs[pv.dofpv_prargs].dofs_size;
	if (sz != 0) {
		args = mdb_alloc(sz, UM_SLEEP | UM_GC);
		if (mdb_vread(args, sz, addr +
		    dofs[pv.dofpv_prargs].dofs_offset) != sz) {
			mdb_warn("failed to read args");
			return (-1);
		}
	}

	sz = dofs[pv.dofpv_proffs].dofs_size;
	offs = mdb_alloc(sz, UM_SLEEP | UM_GC);
	if (mdb_vread(offs, sz, addr + dofs[pv.dofpv_proffs].dofs_offset)
	    != sz) {
		mdb_warn("failed to read offsets");
		return (-1);
	}

	enoffs = NULL;
	if (dofh->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1 ||
	    pv.dofpv_prenoffs == 0) {
		sz = dofs[pv.dofpv_prenoffs].dofs_size;
		enoffs = mdb_alloc(sz, UM_SLEEP | UM_GC);
		if (mdb_vread(enoffs, sz, addr +
		    dofs[pv.dofpv_prenoffs].dofs_offset) != sz) {
			mdb_warn("failed to read is-enabled offsets");
			return (-1);
		}
	}

	sz = dofs[pv.dofpv_probes].dofs_size;
	p = mdb_alloc(sz, UM_SLEEP | UM_GC);
	if (mdb_vread(p, sz, addr + dofs[pv.dofpv_probes].dofs_offset) != sz) {
		mdb_warn("failed to read probes");
		return (-1);
	}

	(void) mdb_inc_indent(2);

	for (i = 0; i < sz / dofs[pv.dofpv_probes].dofs_entsize; i++) {
		pb = (dof_probe_t *)(uintptr_t)(p +
		    i * dofs[pv.dofpv_probes].dofs_entsize);

		mdb_printf("%lx probe %s:%s {\n", (ulong_t)(addr +
		    dofs[pv.dofpv_probes].dofs_offset +
		    i * dofs[pv.dofpv_probes].dofs_entsize),
		    strtab + pb->dofpr_func,
		    strtab + pb->dofpr_name);

		(void) mdb_inc_indent(2);
		mdb_printf("addr: %p\n", (ulong_t)pb->dofpr_addr);
		mdb_printf("offs: ");
		for (j = 0; j < pb->dofpr_noffs; j++) {
			mdb_printf("%s %x", "," + (j == 0),
			    offs[pb->dofpr_offidx + j]);
		}
		mdb_printf("\n");

		if (dofh->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1) {
			mdb_printf("enoffs: ");
			if (enoffs == NULL) {
				if (pb->dofpr_nenoffs != 0)
					mdb_printf("<error>");
			} else {
				for (j = 0; j < pb->dofpr_nenoffs; j++) {
					mdb_printf("%s %x", "," + (j == 0),
					    enoffs[pb->dofpr_enoffidx + j]);
				}
			}
			mdb_printf("\n");
		}

		mdb_printf("nargs:");
		narg = pb->dofpr_nargv;
		for (j = 0; j < pb->dofpr_nargc; j++) {
			mdb_printf("%s %s", "," + (j == 0), strtab + narg);
			narg += strlen(strtab + narg) + 1;
		}
		mdb_printf("\n");
		mdb_printf("xargs:");
		xarg = pb->dofpr_xargv;
		for (j = 0; j < pb->dofpr_xargc; j++) {
			mdb_printf("%s %s", "," + (j == 0), strtab + xarg);
			xarg += strlen(strtab + xarg) + 1;
		}
		mdb_printf("\n");
		mdb_printf("map:  ");
		for (j = 0; j < pb->dofpr_xargc; j++) {
			mdb_printf("%s %d->%d", "," + (j == 0),
			    args[pb->dofpr_argidx + j], j);
		}

		(void) mdb_dec_indent(2);
		mdb_printf("\n}\n");
	}

	(void) mdb_dec_indent(2);
	mdb_printf("}\n");

	return (0);
}

static int
dof_sect_prargs(uintptr_t addr, dof_sec_t *sec)
{
	int i;
	uint8_t arg;

	for (i = 0; i < sec->dofs_size; i++) {
		if (mdb_vread(&arg, sizeof (arg),
		    addr + sec->dofs_offset + i) != sizeof (arg)) {
			mdb_warn("failed to read argument");
			return (1);
		}

		mdb_printf("%d ", arg);

		if (i % 20 == 19)
			mdb_printf("\n");
	}

	mdb_printf("\n");

	return (0);
}

/*ARGSUSED*/
static int
dofdump(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dof_hdr_t dofh;
	dof_sec_t *dofs;
	const char *name;
	int i;

	if (mdb_vread(&dofh, sizeof (dof_hdr_t), addr) != sizeof (dof_hdr_t)) {
		mdb_warn("failed to read DOF header");
		return (DCMD_ERR);
	}

	dofs = mdb_alloc(sizeof (dof_sec_t) * dofh.dofh_secnum,
	    UM_SLEEP | UM_GC);

	for (i = 0; i < dofh.dofh_secnum; i++) {
		if (mdb_vread(&dofs[i], sizeof (dof_sec_t), dofh.dofh_secoff +
		    addr + i * dofh.dofh_secsize) != sizeof (dof_sec_t)) {
			mdb_warn("failed to read DOF sections");
			return (DCMD_ERR);
		}
	}

	for (i = 0; i < dofh.dofh_secnum; i++) {
		mdb_printf("%lx Section %d: ", (ulong_t)
		    (dofh.dofh_secoff + addr + i * dofh.dofh_secsize), i);

		if ((name = dof_sec_name(dofs[i].dofs_type)) != NULL)
			mdb_printf("%s\n", name);
		else
			mdb_printf("%u\n", dofs[i].dofs_type);

		(void) mdb_inc_indent(2);
		switch (dofs[i].dofs_type) {
		case DOF_SECT_PROVIDER:
			(void) dof_sect_provider(&dofh, addr, &dofs[i], dofs);
			break;
		case DOF_SECT_STRTAB:
			(void) dof_sect_strtab(addr, &dofs[i]);
			break;
		case DOF_SECT_PRARGS:
			(void) dof_sect_prargs(addr, &dofs[i]);
			break;
		}
		(void) mdb_dec_indent(2);

		mdb_printf("\n");
	}

	return (DCMD_OK);
}

static const mdb_dcmd_t common_dcmds[] = {
	{ "difinstr", ":", "disassemble a DIF instruction", difinstr },
	{ "difo", ":", "print a DIF object", difo },
	{ "dof_hdr", "?", "print a DOF header", dof_hdr },
	{ "dof_sec", ":", "print a DOF section header", dof_sec },
	{ "dof_ecbdesc", ":", "print a DOF ecbdesc", dof_ecbdesc },
	{ "dof_probedesc", ":", "print a DOF probedesc", dof_probedesc },
	{ "dof_actdesc", ":", "print a DOF actdesc", dof_actdesc },
	{ "dof_relohdr", ":", "print a DOF relocation header", dof_relohdr },
	{ "dof_relodesc", ":", "print a DOF relodesc", dof_relodesc },
	{ "dofdump", ":", "dump DOF", dofdump },
	{ NULL }
};

static const mdb_walker_t common_walkers[] = {
	{ "dof_sec", "walk DOF section header table given header address",
		dof_sec_walk_init, dof_sec_walk_step, dof_sec_walk_fini },
	{ NULL }
};

static mdb_modinfo_t modinfo = {
	MDB_API_VERSION, NULL, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	uint_t d = 0, kd = 0, w = 0, kw = 0;
	const mdb_walker_t *wp;
	const mdb_dcmd_t *dp;

	for (dp = common_dcmds; dp->dc_name != NULL; dp++)
		d++; /* count common dcmds */

	for (wp = common_walkers; wp->walk_name != NULL; wp++)
		w++; /* count common walkers */

#ifdef _KERNEL
	for (dp = kernel_dcmds; dp->dc_name != NULL; dp++)
		kd++; /* count kernel dcmds */

	for (wp = kernel_walkers; wp->walk_name != NULL; wp++)
		kw++; /* count common walkers */
#endif

	modinfo.mi_dcmds = mdb_zalloc(sizeof (*dp) * (d + kd + 1), UM_SLEEP);
	modinfo.mi_walkers = mdb_zalloc(sizeof (*wp) * (w + kw + 1), UM_SLEEP);

	bcopy(common_dcmds, (void *)modinfo.mi_dcmds, sizeof (*dp) * d);
	bcopy(common_walkers, (void *)modinfo.mi_walkers, sizeof (*wp) * w);

#ifdef _KERNEL
	bcopy(kernel_dcmds, (void *)
	    (modinfo.mi_dcmds + d), sizeof (*dp) * kd);
	bcopy(kernel_walkers, (void *)
	    (modinfo.mi_walkers + w), sizeof (*wp) * kw);
#endif
	return (&modinfo);
}

void
_mdb_fini(void)
{
	const mdb_walker_t *wp;
	const mdb_dcmd_t *dp;
	uint_t d = 0, w = 0;

	for (dp = modinfo.mi_dcmds; dp->dc_name != NULL; dp++)
		d++;

	for (wp = modinfo.mi_walkers; wp->walk_name != NULL; wp++)
		w++;

	mdb_free((void *)modinfo.mi_dcmds, sizeof (*dp) * (d + 1));
	mdb_free((void *)modinfo.mi_walkers, sizeof (*wp) * (w + 1));
}
