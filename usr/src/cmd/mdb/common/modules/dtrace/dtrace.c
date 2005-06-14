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

/*
 * explicitly define DTRACE_ERRDEBUG to pull in definition of dtrace_errhash_t
 * explicitly define _STDARG_H to avoid stdarg.h/varargs.h u/k defn conflict
 */
#define	DTRACE_ERRDEBUG
#define	_STDARG_H

#include <mdb/mdb_param.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/dtrace_impl.h>
#include <sys/vmem_impl.h>
#include <sys/ddi_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/kobj.h>
#include <dtrace.h>
#include <alloca.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>

#ifdef _LP64
#define	DIFO_ADDRWIDTH		11
#else
#define	DIFO_ADDRWIDTH		8
#endif

int dof_sec(uintptr_t, uint_t, int, const mdb_arg_t *);

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
	static struct {
		const char *name;
		int subr;
	} snames[] = {
		{ "rand",			DIF_SUBR_RAND },
		{ "mutex_owned",		DIF_SUBR_MUTEX_OWNED },
		{ "mutex_owner",		DIF_SUBR_MUTEX_OWNER },
		{ "mutex_type_adaptive",	DIF_SUBR_MUTEX_TYPE_ADAPTIVE },
		{ "mutex_type_spin",		DIF_SUBR_MUTEX_TYPE_SPIN },
		{ "rw_read_held",		DIF_SUBR_RW_READ_HELD },
		{ "rw_write_held",		DIF_SUBR_RW_WRITE_HELD },
		{ "rw_iswriter",		DIF_SUBR_RW_ISWRITER },
		{ "copyin",			DIF_SUBR_COPYIN },
		{ "copyinstr",			DIF_SUBR_COPYINSTR },
		{ "speculation",		DIF_SUBR_SPECULATION },
		{ "progenyof",			DIF_SUBR_PROGENYOF },
		{ "strlen",			DIF_SUBR_STRLEN },
		{ "copyout",			DIF_SUBR_COPYOUT },
		{ "copyoutstr",			DIF_SUBR_COPYOUTSTR },
		{ "alloca",			DIF_SUBR_ALLOCA },
		{ "bcopy",			DIF_SUBR_BCOPY },
		{ "copyinto",			DIF_SUBR_COPYINTO },
		{ "msgdsize",			DIF_SUBR_MSGDSIZE },
		{ "msgsize",			DIF_SUBR_MSGSIZE },
		{ "getmajor",			DIF_SUBR_GETMAJOR },
		{ "getminor",			DIF_SUBR_GETMINOR },
		{ "ddi_pathname",		DIF_SUBR_DDI_PATHNAME },
		{ "strjoin",			DIF_SUBR_STRJOIN },
		{ "lltostr",			DIF_SUBR_LLTOSTR },
		{ "basename",			DIF_SUBR_BASENAME },
		{ "dirname",			DIF_SUBR_DIRNAME },
		{ "cleanpath",			DIF_SUBR_CLEANPATH },
		{ "strchr",			DIF_SUBR_STRCHR },
		{ "strrchr",			DIF_SUBR_STRRCHR },
		{ "strstr",			DIF_SUBR_STRSTR },
		{ "strtok",			DIF_SUBR_STRTOK },
		{ "substr",			DIF_SUBR_SUBSTR },
		{ "index",			DIF_SUBR_INDEX },
		{ "rindex",			DIF_SUBR_RINDEX },
		{ NULL, 0 }
	};

	uint_t subr = DIF_INSTR_SUBR(instr), i;

	mdb_printf("%-4s DIF_SUBR(%u), %%r%u", name, subr, DIF_INSTR_RD(instr));

	for (i = 0; snames[i].name != NULL; i++) {
		if (subr == snames[i].subr) {
			mdb_printf("\t\t! %s", snames[i].name);
			return;
		}
	}
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
		mdb_printf("\t! %s", tnames[type]);
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
	mdb_printf("%0*p %08x ", DIFO_ADDRWIDTH, addr, instr);
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
	mdb_printf("%<b>%-*s %-8s %s%</b>\n", DIFO_ADDRWIDTH, "ADDR",
	    "OPCODE", "INSTRUCTION");

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
id2probe(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t probe = NULL;
	uintptr_t probes;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (addr == DTRACE_IDNONE || addr > UINT32_MAX)
		goto out;

	if (mdb_readvar(&probes, "dtrace_probes") == -1) {
		mdb_warn("failed to read 'dtrace_probes'");
		return (DCMD_ERR);
	}

	probes += (addr - 1) * sizeof (dtrace_probe_t *);

	if (mdb_vread(&probe, sizeof (uintptr_t), probes) == -1) {
		mdb_warn("failed to read dtrace_probes[%d]", addr - 1);
		return (DCMD_ERR);
	}

out:
	mdb_printf("%p\n", probe);
	return (DCMD_OK);
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

static const char *
dof_sec_typename(uint32_t type)
{
	static const char *const types[] = {
		"none", "comments", "source", "ecbdesc", "probedesc", "actdesc",
		"difohdr", "dif", "strtab", "vartab", "reltab", "typtab",
		"urelhdr", "krelhdr", "optdesc", "provider", "probes",
		"prargs", "proffs", "inttab", "utsname"
	};
	static char buf[32];

	if (type < sizeof (types) / sizeof (types[0]))
		return (types[type]);

	mdb_snprintf(buf, sizeof (buf), "%u", type);
	return (buf);
}

/*ARGSUSED*/
int
dof_sec(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
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
	mdb_printf("%-10s ", dof_sec_typename(s.dofs_type));

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

void
dtrace_help(void)
{

	mdb_printf("Given a dtrace_state_t structure that represents a "
	    "DTrace consumer, prints\n"
	    "dtrace(1M)-like output for in-kernel DTrace data.  (The "
	    "dtrace_state_t\n"
	    "structures for all DTrace consumers may be obtained by running "
	    "the \n"
	    "::dtrace_state dcmd.)   When data is present on multiple CPUs, "
	    "data are\n"
	    "presented in CPU order, with records within each CPU ordered "
	    "oldest to \n"
	    "youngest.  Options:\n\n"
	    "-c cpu     Only provide output for specified CPU.\n");
}

static int
dtracemdb_eprobe(dtrace_state_t *state, dtrace_eprobedesc_t *epd)
{
	dtrace_epid_t epid = epd->dtepd_epid;
	dtrace_probe_t probe;
	dtrace_ecb_t ecb;
	uintptr_t addr, paddr, ap;
	dtrace_action_t act;
	int nactions, nrecs;

	addr = (uintptr_t)state->dts_ecbs +
	    (epid - 1) * sizeof (dtrace_ecb_t *);

	if (mdb_vread(&addr, sizeof (addr), addr) == -1) {
		mdb_warn("failed to read ecb for epid %d", epid);
		return (-1);
	}

	if (addr == NULL) {
		mdb_warn("epid %d doesn't match an ecb\n", epid);
		return (-1);
	}

	if (mdb_vread(&ecb, sizeof (ecb), addr) == -1) {
		mdb_warn("failed to read ecb at %p", addr);
		return (-1);
	}

	paddr = (uintptr_t)ecb.dte_probe;

	if (mdb_vread(&probe, sizeof (probe), paddr) == -1) {
		mdb_warn("failed to read probe for ecb %p", addr);
		return (-1);
	}

	/*
	 * This is a little painful:  in order to find the number of actions,
	 * we need to first walk through them.
	 */
	for (ap = (uintptr_t)ecb.dte_action, nactions = 0; ap != NULL; ) {
		if (mdb_vread(&act, sizeof (act), ap) == -1) {
			mdb_warn("failed to read action %p on ecb %p",
			    ap, addr);
			return (-1);
		}

		if (!DTRACEACT_ISAGG(act.dta_kind) && !act.dta_intuple)
			nactions++;

		ap = (uintptr_t)act.dta_next;
	}

	nrecs = epd->dtepd_nrecs;
	epd->dtepd_nrecs = nactions;
	epd->dtepd_probeid = probe.dtpr_id;
	epd->dtepd_uarg = ecb.dte_uarg;
	epd->dtepd_size = ecb.dte_size;

	for (ap = (uintptr_t)ecb.dte_action, nactions = 0; ap != NULL; ) {
		if (mdb_vread(&act, sizeof (act), ap) == -1) {
			mdb_warn("failed to read action %p on ecb %p",
			    ap, addr);
			return (-1);
		}

		if (!DTRACEACT_ISAGG(act.dta_kind) && !act.dta_intuple) {
			if (nrecs-- == 0)
				break;

			epd->dtepd_rec[nactions++] = act.dta_rec;
		}

		ap = (uintptr_t)act.dta_next;
	}

	return (0);
}

/*ARGSUSED*/
static int
dtracemdb_probe(dtrace_state_t *state, dtrace_probedesc_t *pd)
{
	uintptr_t base, addr, paddr, praddr;
	int nprobes, i;
	dtrace_probe_t probe;
	dtrace_provider_t prov;

	if (pd->dtpd_id == DTRACE_IDNONE)
		pd->dtpd_id++;

	if (mdb_readvar(&base, "dtrace_probes") == -1) {
		mdb_warn("failed to read 'dtrace_probes'");
		return (-1);
	}

	if (mdb_readvar(&nprobes, "dtrace_nprobes") == -1) {
		mdb_warn("failed to read 'dtrace_nprobes'");
		return (-1);
	}

	for (i = pd->dtpd_id; i <= nprobes; i++) {
		addr = base + (i - 1) * sizeof (dtrace_probe_t *);

		if (mdb_vread(&paddr, sizeof (paddr), addr) == -1) {
			mdb_warn("couldn't read probe pointer at %p", addr);
			return (-1);
		}

		if (paddr != NULL)
			break;
	}

	if (paddr == NULL) {
		errno = ESRCH;
		return (-1);
	}

	if (mdb_vread(&probe, sizeof (probe), paddr) == -1) {
		mdb_warn("couldn't read probe at %p", paddr);
		return (-1);
	}

	pd->dtpd_id = probe.dtpr_id;

	if (mdb_vread(pd->dtpd_name, DTRACE_NAMELEN,
	    (uintptr_t)probe.dtpr_name) == -1) {
		mdb_warn("failed to read probe name for probe %p", paddr);
		return (-1);
	}

	if (mdb_vread(pd->dtpd_func, DTRACE_FUNCNAMELEN,
	    (uintptr_t)probe.dtpr_func) == -1) {
		mdb_warn("failed to read function name for probe %p", paddr);
		return (-1);
	}

	if (mdb_vread(pd->dtpd_mod, DTRACE_MODNAMELEN,
	    (uintptr_t)probe.dtpr_mod) == -1) {
		mdb_warn("failed to read module name for probe %p", paddr);
		return (-1);
	}

	praddr = (uintptr_t)probe.dtpr_provider;

	if (mdb_vread(&prov, sizeof (prov), praddr) == -1) {
		mdb_warn("failed to read provider for probe %p", paddr);
		return (-1);
	}

	if (mdb_vread(pd->dtpd_provider, DTRACE_PROVNAMELEN,
	    (uintptr_t)prov.dtpv_name) == -1) {
		mdb_warn("failed to read provider name for probe %p", paddr);
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
static int
dtracemdb_aggdesc(dtrace_state_t *state, dtrace_aggdesc_t *agd)
{
	dtrace_aggid_t aggid = agd->dtagd_id;
	dtrace_aggregation_t agg;
	dtrace_ecb_t ecb;
	uintptr_t addr, eaddr, ap, last;
	dtrace_action_t act;
	dtrace_recdesc_t *lrec;
	int nactions, nrecs;

	addr = (uintptr_t)state->dts_aggregations +
	    (aggid - 1) * sizeof (dtrace_aggregation_t *);

	if (mdb_vread(&addr, sizeof (addr), addr) == -1) {
		mdb_warn("failed to read aggregation for aggid %d", aggid);
		return (-1);
	}

	if (addr == NULL) {
		mdb_warn("aggid %d doesn't match an aggregation\n", aggid);
		return (-1);
	}

	if (mdb_vread(&agg, sizeof (agg), addr) == -1) {
		mdb_warn("failed to read aggregation at %p", addr);
		return (-1);
	}

	eaddr = (uintptr_t)agg.dtag_ecb;

	if (mdb_vread(&ecb, sizeof (ecb), eaddr) == -1) {
		mdb_warn("failed to read ecb for aggregation %p", addr);
		return (-1);
	}

	last = (uintptr_t)addr + offsetof(dtrace_aggregation_t, dtag_action);

	/*
	 * This is a little painful:  in order to find the number of actions,
	 * we need to first walk through them.
	 */
	ap = (uintptr_t)agg.dtag_first;
	nactions = 0;

	for (;;) {
		if (mdb_vread(&act, sizeof (act), ap) == -1) {
			mdb_warn("failed to read action %p on aggregation %p",
			    ap, addr);
			return (-1);
		}

		nactions++;

		if (ap == last)
			break;

		ap = (uintptr_t)act.dta_next;
	}

	lrec = &act.dta_rec;
	agd->dtagd_size = lrec->dtrd_offset + lrec->dtrd_size - agg.dtag_base;

	nrecs = agd->dtagd_nrecs;
	agd->dtagd_nrecs = nactions;
	agd->dtagd_epid = ecb.dte_epid;

	ap = (uintptr_t)agg.dtag_first;
	nactions = 0;

	for (;;) {
		dtrace_recdesc_t rec;

		if (mdb_vread(&act, sizeof (act), ap) == -1) {
			mdb_warn("failed to read action %p on aggregation %p",
			    ap, addr);
			return (-1);
		}

		if (nrecs-- == 0)
			break;

		rec = act.dta_rec;
		rec.dtrd_offset -= agg.dtag_base;
		rec.dtrd_uarg = 0;
		agd->dtagd_rec[nactions++] = rec;

		if (ap == last)
			break;

		ap = (uintptr_t)act.dta_next;
	}

	return (0);
}

static int
dtracemdb_bufsnap(dtrace_buffer_t *which, dtrace_bufdesc_t *desc)
{
	uintptr_t addr;
	size_t bufsize;
	dtrace_buffer_t buf;
	caddr_t data = desc->dtbd_data;
	processorid_t max_cpuid, cpu = desc->dtbd_cpu;

	if (mdb_readvar(&max_cpuid, "max_cpuid") == -1) {
		mdb_warn("failed to read 'max_cpuid'");
		errno = EIO;
		return (-1);
	}

	if (cpu < 0 || cpu > max_cpuid) {
		errno = EINVAL;
		return (-1);
	}

	addr = (uintptr_t)which + cpu * sizeof (dtrace_buffer_t);

	if (mdb_vread(&buf, sizeof (buf), addr) == -1) {
		mdb_warn("failed to read buffer description at %p", addr);
		errno = EIO;
		return (-1);
	}

	if (buf.dtb_tomax == NULL) {
		errno = ENOENT;
		return (-1);
	}

	if (buf.dtb_flags & DTRACEBUF_WRAPPED) {
		bufsize = buf.dtb_size;
	} else {
		bufsize = buf.dtb_offset;
	}

	if (mdb_vread(data, bufsize, (uintptr_t)buf.dtb_tomax) == -1) {
		mdb_warn("couldn't read buffer for CPU %d", cpu);
		errno = EIO;
		return (-1);
	}

	if (buf.dtb_offset > buf.dtb_size) {
		mdb_warn("buffer for CPU %d has corrupt offset\n", cpu);
		errno = EIO;
		return (-1);
	}

	if (buf.dtb_flags & DTRACEBUF_WRAPPED) {
		if (buf.dtb_xamot_offset > buf.dtb_size) {
			mdb_warn("ringbuffer for CPU %d has corrupt "
			    "wrapped offset\n", cpu);
			errno = EIO;
			return (-1);
		}

		/*
		 * If the ring buffer has wrapped, it needs to be polished.
		 * See the comment in dtrace_buffer_polish() for details.
		 */
		if (buf.dtb_offset < buf.dtb_xamot_offset) {
			bzero(data + buf.dtb_offset,
			    buf.dtb_xamot_offset - buf.dtb_offset);
		}

		if (buf.dtb_offset > buf.dtb_xamot_offset) {
			bzero(data + buf.dtb_offset,
			    buf.dtb_size - buf.dtb_offset);
			bzero(data, buf.dtb_xamot_offset);
		}

		desc->dtbd_oldest = buf.dtb_xamot_offset;
	} else {
		desc->dtbd_oldest = 0;
	}

	desc->dtbd_size = bufsize;
	desc->dtbd_drops = buf.dtb_drops;
	desc->dtbd_errors = buf.dtb_errors;

	return (0);
}

/*
 * This is essentially identical to its cousin in the kernel.
 */
static dof_hdr_t *
dtracemdb_dof_create(dtrace_state_t *state)
{
	dof_hdr_t *dof;
	dof_sec_t *sec;
	dof_optdesc_t *opt;
	int i, len = sizeof (dof_hdr_t) +
	    roundup(sizeof (dof_sec_t), sizeof (uint64_t)) +
	    sizeof (dof_optdesc_t) * DTRACEOPT_MAX;

	dof = mdb_zalloc(len, UM_SLEEP);
	dof->dofh_ident[DOF_ID_MAG0] = DOF_MAG_MAG0;
	dof->dofh_ident[DOF_ID_MAG1] = DOF_MAG_MAG1;
	dof->dofh_ident[DOF_ID_MAG2] = DOF_MAG_MAG2;
	dof->dofh_ident[DOF_ID_MAG3] = DOF_MAG_MAG3;

	dof->dofh_ident[DOF_ID_MODEL] = DOF_MODEL_NATIVE;
	dof->dofh_ident[DOF_ID_ENCODING] = DOF_ENCODE_NATIVE;
	dof->dofh_ident[DOF_ID_VERSION] = DOF_VERSION_1;
	dof->dofh_ident[DOF_ID_DIFVERS] = DIF_VERSION;
	dof->dofh_ident[DOF_ID_DIFIREG] = DIF_DIR_NREGS;
	dof->dofh_ident[DOF_ID_DIFTREG] = DIF_DTR_NREGS;

	dof->dofh_flags = 0;
	dof->dofh_hdrsize = sizeof (dof_hdr_t);
	dof->dofh_secsize = sizeof (dof_sec_t);
	dof->dofh_secnum = 1;	/* only DOF_SECT_OPTDESC */
	dof->dofh_secoff = sizeof (dof_hdr_t);
	dof->dofh_loadsz = len;
	dof->dofh_filesz = len;
	dof->dofh_pad = 0;

	/*
	 * Fill in the option section header...
	 */
	sec = (dof_sec_t *)((uintptr_t)dof + sizeof (dof_hdr_t));
	sec->dofs_type = DOF_SECT_OPTDESC;
	sec->dofs_align = sizeof (uint64_t);
	sec->dofs_flags = DOF_SECF_LOAD;
	sec->dofs_entsize = sizeof (dof_optdesc_t);

	opt = (dof_optdesc_t *)((uintptr_t)sec +
	    roundup(sizeof (dof_sec_t), sizeof (uint64_t)));

	sec->dofs_offset = (uintptr_t)opt - (uintptr_t)dof;
	sec->dofs_size = sizeof (dof_optdesc_t) * DTRACEOPT_MAX;

	for (i = 0; i < DTRACEOPT_MAX; i++) {
		opt[i].dofo_option = i;
		opt[i].dofo_strtab = DOF_SECIDX_NONE;
		opt[i].dofo_value = state->dts_options[i];
	}

	return (dof);
}

static int
dtracemdb_format(dtrace_state_t *state, dtrace_fmtdesc_t *desc)
{
	uintptr_t addr, faddr;
	char c;
	int len = 0;

	if (desc->dtfd_format == 0 || desc->dtfd_format > state->dts_nformats) {
		errno = EINVAL;
		return (-1);
	}

	faddr = (uintptr_t)state->dts_formats +
	    (desc->dtfd_format - 1) * sizeof (char *);

	if (mdb_vread(&addr, sizeof (addr), faddr) == -1) {
		mdb_warn("failed to read format string pointer at %p", faddr);
		return (-1);
	}

	do {
		if (mdb_vread(&c, sizeof (c), addr + len++) == -1) {
			mdb_warn("failed to read format string at %p", addr);
			return (-1);
		}
	} while (c != '\0');

	if (len > desc->dtfd_length) {
		desc->dtfd_length = len;
		return (0);
	}

	if (mdb_vread(desc->dtfd_string, len, addr) == -1) {
		mdb_warn("failed to reread format string at %p", addr);
		return (-1);
	}

	return (0);
}

static int
dtracemdb_status(dtrace_state_t *state, dtrace_status_t *status)
{
	dtrace_dstate_t *dstate;
	int i, j;
	uint64_t nerrs;
	uintptr_t addr;
	int ncpu;

	if (mdb_readvar(&ncpu, "_ncpu") == -1) {
		mdb_warn("failed to read '_ncpu'");
		return (DCMD_ERR);
	}

	bzero(status, sizeof (dtrace_status_t));

	if (state->dts_activity == DTRACE_ACTIVITY_INACTIVE) {
		errno = ENOENT;
		return (-1);
	}

	/*
	 * For the MDB backend, we never set dtst_exiting or dtst_filled.  This
	 * is by design:  we don't want the library to try to stop tracing,
	 * because it doesn't particularly mean anything.
	 */
	nerrs = state->dts_errors;
	dstate = &state->dts_vstate.dtvs_dynvars;

	for (i = 0; i < ncpu; i++) {
		dtrace_dstate_percpu_t dcpu;
		dtrace_buffer_t buf;

		addr = (uintptr_t)&dstate->dtds_percpu[i];

		if (mdb_vread(&dcpu, sizeof (dcpu), addr) == -1) {
			mdb_warn("failed to read per-CPU dstate at %p", addr);
			return (-1);
		}

		status->dtst_dyndrops += dcpu.dtdsc_drops;
		status->dtst_dyndrops_dirty += dcpu.dtdsc_dirty_drops;
		status->dtst_dyndrops_rinsing += dcpu.dtdsc_rinsing_drops;

		addr = (uintptr_t)&state->dts_buffer[i];

		if (mdb_vread(&buf, sizeof (buf), addr) == -1) {
			mdb_warn("failed to read per-CPU buffer at %p", addr);
			return (-1);
		}

		nerrs += buf.dtb_errors;

		for (j = 0; j < state->dts_nspeculations; j++) {
			dtrace_speculation_t spec;

			addr = (uintptr_t)&state->dts_speculations[j];

			if (mdb_vread(&spec, sizeof (spec), addr) == -1) {
				mdb_warn("failed to read "
				    "speculation at %p", addr);
				return (-1);
			}

			addr = (uintptr_t)&spec.dtsp_buffer[i];

			if (mdb_vread(&buf, sizeof (buf), addr) == -1) {
				mdb_warn("failed to read "
				    "speculative buffer at %p", addr);
				return (-1);
			}

			status->dtst_specdrops += buf.dtb_xamot_drops;
		}
	}

	status->dtst_specdrops_busy = state->dts_speculations_busy;
	status->dtst_specdrops_unavail = state->dts_speculations_unavail;
	status->dtst_errors = nerrs;

	return (0);
}

typedef struct dtracemdb_data {
	dtrace_state_t *dtmd_state;
	char *dtmd_symstr;
	char *dtmd_modstr;
	uintptr_t dtmd_addr;
} dtracemdb_data_t;

static int
dtracemdb_ioctl(void *varg, int cmd, void *arg)
{
	dtracemdb_data_t *data = varg;
	dtrace_state_t *state = data->dtmd_state;

	switch (cmd) {
	case DTRACEIOC_CONF: {
		dtrace_conf_t *conf = arg;

		bzero(conf, sizeof (conf));
		conf->dtc_difversion = DIF_VERSION;
		conf->dtc_difintregs = DIF_DIR_NREGS;
		conf->dtc_diftupregs = DIF_DTR_NREGS;
		conf->dtc_ctfmodel = CTF_MODEL_NATIVE;

		return (0);
	}

	case DTRACEIOC_DOFGET: {
		dof_hdr_t *hdr = arg, *dof;

		dof = dtracemdb_dof_create(state);
		bcopy(dof, hdr, MIN(hdr->dofh_loadsz, dof->dofh_loadsz));
		mdb_free(dof, dof->dofh_loadsz);

		return (0);
	}

	case DTRACEIOC_BUFSNAP:
		return (dtracemdb_bufsnap(state->dts_buffer, arg));

	case DTRACEIOC_AGGSNAP:
		return (dtracemdb_bufsnap(state->dts_aggbuffer, arg));

	case DTRACEIOC_AGGDESC:
		return (dtracemdb_aggdesc(state, arg));

	case DTRACEIOC_EPROBE:
		return (dtracemdb_eprobe(state, arg));

	case DTRACEIOC_PROBES:
		return (dtracemdb_probe(state, arg));

	case DTRACEIOC_FORMAT:
		return (dtracemdb_format(state, arg));

	case DTRACEIOC_STATUS:
		return (dtracemdb_status(state, arg));

	case DTRACEIOC_GO:
		*(processorid_t *)arg = -1;
		return (0);

	case DTRACEIOC_ENABLE:
		errno = ENOTTY; /* see dt_open.c:dtrace_go() */
		return (-1);

	case DTRACEIOC_PROVIDER:
	case DTRACEIOC_PROBEMATCH:
		errno = ESRCH;
		return (-1);

	default:
		mdb_warn("unexpected ioctl 0x%x (%s)\n", cmd,
		    cmd == DTRACEIOC_PROVIDER	? "DTRACEIOC_PROVIDER" :
		    cmd == DTRACEIOC_PROBES	? "DTRACEIOC_PROBES" :
		    cmd == DTRACEIOC_BUFSNAP	? "DTRACEIOC_BUFSNAP" :
		    cmd == DTRACEIOC_PROBEMATCH	? "DTRACEIOC_PROBEMATCH" :
		    cmd == DTRACEIOC_ENABLE	? "DTRACEIOC_ENABLE" :
		    cmd == DTRACEIOC_AGGSNAP	? "DTRACEIOC_AGGSNAP" :
		    cmd == DTRACEIOC_EPROBE	? "DTRACEIOC_EPROBE" :
		    cmd == DTRACEIOC_PROBEARG	? "DTRACEIOC_PROBEARG" :
		    cmd == DTRACEIOC_CONF	? "DTRACEIOC_CONF" :
		    cmd == DTRACEIOC_STATUS	? "DTRACEIOC_STATUS" :
		    cmd == DTRACEIOC_GO		? "DTRACEIOC_GO" :
		    cmd == DTRACEIOC_STOP	? "DTRACEIOC_STOP" :
		    cmd == DTRACEIOC_AGGDESC	? "DTRACEIOC_AGGDESC" :
		    cmd == DTRACEIOC_FORMAT	? "DTRACEIOC_FORMAT" :
		    cmd == DTRACEIOC_DOFGET	? "DTRACEIOC_DOFGET" :
		    cmd == DTRACEIOC_REPLICATE	? "DTRACEIOC_REPLICATE" :
		    "???");
		errno = ENXIO;
		return (-1);
	}
}

static int
dtracemdb_modctl(uintptr_t addr, const struct modctl *m, dtracemdb_data_t *data)
{
	struct module mod;

	if (m->mod_mp == NULL)
		return (WALK_NEXT);

	if (mdb_vread(&mod, sizeof (mod), (uintptr_t)m->mod_mp) == -1) {
		mdb_warn("couldn't read modctl %p's module", addr);
		return (WALK_NEXT);
	}

	if ((uintptr_t)mod.text > data->dtmd_addr)
		return (WALK_NEXT);

	if ((uintptr_t)mod.text + mod.text_size <= data->dtmd_addr)
		return (WALK_NEXT);

	if (mdb_readstr(data->dtmd_modstr, MDB_SYM_NAMLEN,
	    (uintptr_t)m->mod_modname) == -1)
		return (WALK_ERR);

	return (WALK_DONE);
}

static int
dtracemdb_lookup_by_addr(void *varg, GElf_Addr addr, GElf_Sym *symp,
    dtrace_syminfo_t *sip)
{
	dtracemdb_data_t *data = varg;

	if (data->dtmd_symstr == NULL) {
		data->dtmd_symstr = mdb_zalloc(MDB_SYM_NAMLEN,
		    UM_SLEEP | UM_GC);
	}

	if (data->dtmd_modstr == NULL) {
		data->dtmd_modstr = mdb_zalloc(MDB_SYM_NAMLEN,
		    UM_SLEEP | UM_GC);
	}

	if (symp != NULL) {
		if (mdb_lookup_by_addr(addr, MDB_SYM_FUZZY, data->dtmd_symstr,
		    MDB_SYM_NAMLEN, symp) == -1)
			return (-1);
	}

	if (sip != NULL) {
		data->dtmd_addr = addr;

		(void) strcpy(data->dtmd_modstr, "???");

		if (mdb_walk("modctl",
		    (mdb_walk_cb_t)dtracemdb_modctl, varg) == -1) {
			mdb_warn("couldn't walk 'modctl'");
			return (-1);
		}

		sip->dts_object = data->dtmd_modstr;
		sip->dts_id = 0;
		sip->dts_name = symp != NULL ? data->dtmd_symstr : NULL;
	}

	return (0);
}

/*ARGSUSED*/
static int
dtracemdb_stat(void *varg, processorid_t cpu)
{
	GElf_Sym sym;
	cpu_t c;
	uintptr_t caddr, addr;

	if (mdb_lookup_by_name("cpu", &sym) == -1) {
		mdb_warn("failed to find symbol for 'cpu'");
		return (-1);
	}

	if (cpu * sizeof (uintptr_t) > sym.st_size)
		return (-1);

	addr = (uintptr_t)sym.st_value + cpu * sizeof (uintptr_t);

	if (mdb_vread(&caddr, sizeof (caddr), addr) == -1) {
		mdb_warn("failed to read cpu[%d]", cpu);
		return (-1);
	}

	if (caddr == NULL)
		return (-1);

	if (mdb_vread(&c, sizeof (c), caddr) == -1) {
		mdb_warn("failed to read cpu at %p", caddr);
		return (-1);
	}

	if (c.cpu_flags & CPU_POWEROFF) {
		return (P_POWEROFF);
	} else if (c.cpu_flags & CPU_SPARE) {
		return (P_SPARE);
	} else if (c.cpu_flags & CPU_FAULTED) {
		return (P_FAULTED);
	} else if ((c.cpu_flags & (CPU_READY | CPU_OFFLINE)) != CPU_READY) {
		return (P_OFFLINE);
	} else if (c.cpu_flags & CPU_ENABLE) {
		return (P_ONLINE);
	} else {
		return (P_NOINTR);
	}
}

/*ARGSUSED*/
static long
dtracemdb_sysconf(void *varg, int name)
{
	int max_ncpus;
	processorid_t max_cpuid;

	switch (name) {
	case _SC_CPUID_MAX:
		if (mdb_readvar(&max_cpuid, "max_cpuid") == -1) {
			mdb_warn("failed to read 'max_cpuid'");
			return (-1);
		}

		return (max_cpuid);

	case _SC_NPROCESSORS_MAX:
		if (mdb_readvar(&max_ncpus, "max_ncpus") == -1) {
			mdb_warn("failed to read 'max_ncpus'");
			return (-1);
		}

		return (max_ncpus);

	default:
		mdb_warn("unexpected sysconf code %d\n", name);
		return (-1);
	}
}

const dtrace_vector_t dtrace_mdbops = {
	dtracemdb_ioctl,
	dtracemdb_lookup_by_addr,
	dtracemdb_stat,
	dtracemdb_sysconf
};

typedef struct dtrace_dcmddata {
	dtrace_hdl_t *dtdd_dtp;
	int dtdd_cpu;
	int dtdd_quiet;
	int dtdd_flowindent;
	int dtdd_heading;
} dtrace_dcmddata_t;

/*ARGSUSED*/
static int
dtrace_dcmdrec(const dtrace_probedata_t *data,
    const dtrace_recdesc_t *rec, void *arg)
{
	dtrace_dcmddata_t *dd = arg;

	if (rec == NULL) {
		/*
		 * We have processed the final record; output the newline if
		 * we're not in quiet mode.
		 */
		if (!dd->dtdd_quiet)
			mdb_printf("\n");

		return (DTRACE_CONSUME_NEXT);
	}

	return (DTRACE_CONSUME_THIS);
}

/*ARGSUSED*/
static int
dtrace_dcmdprobe(const dtrace_probedata_t *data, void *arg)
{
	dtrace_probedesc_t *pd = data->dtpda_pdesc;
	processorid_t cpu = data->dtpda_cpu;
	dtrace_dcmddata_t *dd = arg;
	char name[DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 2];

	if (dd->dtdd_cpu != -1UL && dd->dtdd_cpu != cpu)
		return (DTRACE_CONSUME_NEXT);

	if (dd->dtdd_heading == 0) {
		if (!dd->dtdd_flowindent) {
			if (!dd->dtdd_quiet) {
				mdb_printf("%3s %6s %32s\n",
				    "CPU", "ID", "FUNCTION:NAME");
			}
		} else {
			mdb_printf("%3s %-41s\n", "CPU", "FUNCTION");
		}
		dd->dtdd_heading = 1;
	}

	if (!dd->dtdd_flowindent) {
		if (!dd->dtdd_quiet) {
			(void) mdb_snprintf(name, sizeof (name), "%s:%s",
			    pd->dtpd_func, pd->dtpd_name);

			mdb_printf("%3d %6d %32s ", cpu, pd->dtpd_id, name);
		}
	} else {
		int indent = data->dtpda_indent;

		if (data->dtpda_flow == DTRACEFLOW_NONE) {
			(void) mdb_snprintf(name, sizeof (name), "%*s%s%s:%s",
			    indent, "", data->dtpda_prefix, pd->dtpd_func,
			    pd->dtpd_name);
		} else {
			(void) mdb_snprintf(name, sizeof (name), "%*s%s%s",
			    indent, "", data->dtpda_prefix, pd->dtpd_func);
		}

		mdb_printf("%3d %-41s ", cpu, name);
	}

	return (DTRACE_CONSUME_THIS);
}

/*ARGSUSED*/
static int
dtrace_dcmderr(dtrace_errdata_t *data, void *arg)
{
	mdb_warn(data->dteda_msg);
	return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
dtrace_dcmddrop(dtrace_dropdata_t *data, void *arg)
{
	mdb_warn(data->dtdda_msg);
	return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
dtrace_dcmdbuffered(dtrace_bufdata_t *bufdata, void *arg)
{
	mdb_printf("%s", bufdata->dtbda_buffered);
	return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
int
dtrace(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_state_t state;
	dtrace_hdl_t *dtp;
	int ncpu, err;
	uintptr_t c = -1UL;
	dtrace_dcmddata_t dd;
	dtrace_optval_t val;
	dtracemdb_data_t md;
	int rval = DCMD_ERR;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_getopts(argc, argv, 'c', MDB_OPT_UINTPTR, &c, NULL) != argc)
		return (DCMD_USAGE);

	if (mdb_readvar(&ncpu, "_ncpu") == -1) {
		mdb_warn("failed to read '_ncpu'");
		return (DCMD_ERR);
	}

	if (mdb_vread(&state, sizeof (state), addr) == -1) {
		mdb_warn("couldn't read dtrace_state_t at %p", addr);
		return (DCMD_ERR);
	}

	bzero(&md, sizeof (md));
	md.dtmd_state = &state;

	if ((dtp = dtrace_vopen(DTRACE_VERSION, DTRACE_O_NOSYS, &err,
	    &dtrace_mdbops, &md)) == NULL) {
		mdb_warn("failed to initialize dtrace: %s\n",
		    dtrace_errmsg(NULL, err));
		return (DCMD_ERR);
	}

	if (dtrace_go(dtp) != 0) {
		mdb_warn("failed to initialize dtrace: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	bzero(&dd, sizeof (dd));
	dd.dtdd_dtp = dtp;
	dd.dtdd_cpu = c;

	if (dtrace_getopt(dtp, "flowindent", &val) == -1) {
		mdb_warn("couldn't get 'flowindent' option: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	dd.dtdd_flowindent = (val != DTRACEOPT_UNSET);

	if (dtrace_getopt(dtp, "quiet", &val) == -1) {
		mdb_warn("couldn't get 'quiet' option: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	dd.dtdd_quiet = (val != DTRACEOPT_UNSET);

	if (dtrace_handle_err(dtp, dtrace_dcmderr, NULL) == -1) {
		mdb_warn("couldn't add err handler: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	if (dtrace_handle_drop(dtp, dtrace_dcmddrop, NULL) == -1) {
		mdb_warn("couldn't add drop handler: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	if (dtrace_handle_buffered(dtp, dtrace_dcmdbuffered, NULL) == -1) {
		mdb_warn("couldn't add buffered handler: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	if (dtrace_status(dtp) == -1) {
		mdb_warn("couldn't get status: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	if (dtrace_aggregate_snap(dtp) == -1) {
		mdb_warn("couldn't snapshot aggregation: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	if (dtrace_consume(dtp, NULL,
	    dtrace_dcmdprobe, dtrace_dcmdrec, &dd) == -1) {
		mdb_warn("couldn't consume DTrace buffers: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	}

	if (dtrace_aggregate_print(dtp, NULL, NULL) == -1) {
		mdb_warn("couldn't print aggregation: %s\n",
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
		goto err;
	}

	rval = DCMD_OK;
err:
	dtrace_close(dtp);
	return (rval);
}

static int
dtrace_errhash_cmp(const void *l, const void *r)
{
	uintptr_t lhs = *((uintptr_t *)l);
	uintptr_t rhs = *((uintptr_t *)r);
	dtrace_errhash_t lerr, rerr;
	char lmsg[256], rmsg[256];

	(void) mdb_vread(&lerr, sizeof (lerr), lhs);
	(void) mdb_vread(&rerr, sizeof (rerr), rhs);

	if (lerr.dter_msg == NULL)
		return (-1);

	if (rerr.dter_msg == NULL)
		return (1);

	(void) mdb_readstr(lmsg, sizeof (lmsg), (uintptr_t)lerr.dter_msg);
	(void) mdb_readstr(rmsg, sizeof (rmsg), (uintptr_t)rerr.dter_msg);

	return (strcmp(lmsg, rmsg));
}

int
dtrace_errhash_init(mdb_walk_state_t *wsp)
{
	GElf_Sym sym;
	uintptr_t *hash, addr;
	int i;

	if (wsp->walk_addr != NULL) {
		mdb_warn("dtrace_errhash walk only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_lookup_by_name("dtrace_errhash", &sym) == -1) {
		mdb_warn("couldn't find 'dtrace_errhash' (non-DEBUG kernel?)");
		return (WALK_ERR);
	}

	addr = (uintptr_t)sym.st_value;
	hash = mdb_alloc(DTRACE_ERRHASHSZ * sizeof (uintptr_t),
	    UM_SLEEP | UM_GC);

	for (i = 0; i < DTRACE_ERRHASHSZ; i++)
		hash[i] = addr + i * sizeof (dtrace_errhash_t);

	qsort(hash, DTRACE_ERRHASHSZ, sizeof (uintptr_t), dtrace_errhash_cmp);

	wsp->walk_addr = 0;
	wsp->walk_data = hash;

	return (WALK_NEXT);
}

int
dtrace_errhash_step(mdb_walk_state_t *wsp)
{
	int ndx = (int)wsp->walk_addr;
	uintptr_t *hash = wsp->walk_data;
	dtrace_errhash_t err;
	uintptr_t addr;

	if (ndx >= DTRACE_ERRHASHSZ)
		return (WALK_DONE);

	wsp->walk_addr = ndx + 1;
	addr = hash[ndx];

	if (mdb_vread(&err, sizeof (err), addr) == -1) {
		mdb_warn("failed to read dtrace_errhash_t at %p", addr);
		return (WALK_DONE);
	}

	if (err.dter_msg == NULL)
		return (WALK_NEXT);

	return (wsp->walk_callback(addr, &err, wsp->walk_cbdata));
}

/*ARGSUSED*/
int
dtrace_errhash(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_errhash_t err;
	char msg[256];

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("dtrace_errhash", "dtrace_errhash",
		    argc, argv) == -1) {
			mdb_warn("can't walk 'dtrace_errhash'");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%8s %s\n", "COUNT", "ERROR");

	if (mdb_vread(&err, sizeof (err), addr) == -1) {
		mdb_warn("failed to read dtrace_errhash_t at %p", addr);
		return (DCMD_ERR);
	}

	addr = (uintptr_t)err.dter_msg;

	if (mdb_readstr(msg, sizeof (msg), addr) == -1) {
		mdb_warn("failed to read error msg at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%8d %s", err.dter_count, msg);

	/*
	 * Some error messages include a newline -- only print the newline
	 * if the message doesn't have one.
	 */
	if (msg[strlen(msg) - 1] != '\n')
		mdb_printf("\n");

	return (DCMD_OK);
}

int
dtrace_helptrace_init(mdb_walk_state_t *wsp)
{
	uint32_t next;
	int enabled;

	if (wsp->walk_addr != NULL) {
		mdb_warn("dtrace_helptrace only supports global walks\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&enabled, "dtrace_helptrace_enabled") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_enabled'");
		return (WALK_ERR);
	}

	if (!enabled) {
		mdb_warn("helper tracing is not enabled\n");
		return (WALK_ERR);
	}

	if (mdb_readvar(&next, "dtrace_helptrace_next") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_next'");
		return (WALK_ERR);
	}

	wsp->walk_addr = next;

	return (WALK_NEXT);
}

int
dtrace_helptrace_step(mdb_walk_state_t *wsp)
{
	uint32_t next, size, nlocals, bufsize;
	uintptr_t buffer, addr;
	dtrace_helptrace_t *ht;
	int rval;

	if (mdb_readvar(&next, "dtrace_helptrace_next") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_next'");
		return (WALK_ERR);
	}

	if (mdb_readvar(&bufsize, "dtrace_helptrace_bufsize") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_bufsize'");
		return (WALK_ERR);
	}

	if (mdb_readvar(&buffer, "dtrace_helptrace_buffer") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_buffer'");
		return (WALK_ERR);
	}

	if (mdb_readvar(&nlocals, "dtrace_helptrace_nlocals") == -1) {
		mdb_warn("couldn't read 'dtrace_helptrace_nlocals'");
		return (WALK_ERR);
	}

	size = sizeof (dtrace_helptrace_t) +
	    nlocals * sizeof (uint64_t) - sizeof (uint64_t);

	if (wsp->walk_addr + size > bufsize) {
		if (next == 0)
			return (WALK_DONE);

		wsp->walk_addr = 0;
	}

	addr = buffer + wsp->walk_addr;
	ht = alloca(size);

	if (mdb_vread(ht, size, addr) == -1) {
		mdb_warn("couldn't read entry at %p", addr);
		return (WALK_ERR);
	}

	if (ht->dtht_helper != NULL) {
		rval = wsp->walk_callback(addr, ht, wsp->walk_cbdata);

		if (rval != WALK_NEXT)
			return (rval);
	}

	if (wsp->walk_addr < next && wsp->walk_addr + size >= next)
		return (WALK_DONE);

	wsp->walk_addr += size;
	return (WALK_NEXT);
}

int
dtrace_helptrace(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_helptrace_t help;
	dtrace_helper_action_t helper;
	char where[30];
	uint_t opt_v = FALSE;
	uintptr_t haddr;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("dtrace_helptrace", "dtrace_helptrace",
		    argc, argv) == -1) {
			mdb_warn("can't walk 'dtrace_helptrace'");
			return (DCMD_ERR);
		}

		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv, 'v',
	    MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf(" %?s %?s %12s %s\n",
		    "ADDR", "HELPER", "WHERE", "DIFO");
	}

	if (mdb_vread(&help, sizeof (help), addr) == -1) {
		mdb_warn("failed to read dtrace_helptrace_t at %p", addr);
		return (DCMD_ERR);
	}

	switch (help.dtht_where) {
	case 0:
		(void) mdb_snprintf(where, sizeof (where), "predicate");
		break;

	case DTRACE_HELPTRACE_NEXT:
		(void) mdb_snprintf(where, sizeof (where), "next");
		break;

	case DTRACE_HELPTRACE_DONE:
		(void) mdb_snprintf(where, sizeof (where), "done");
		break;

	case DTRACE_HELPTRACE_ERR:
		(void) mdb_snprintf(where, sizeof (where), "err");
		break;

	default:
		(void) mdb_snprintf(where, sizeof (where),
		    "action #%d", help.dtht_where);
		break;
	}

	mdb_printf(" %?p %?p %12s ", addr, help.dtht_helper, where);

	haddr = (uintptr_t)help.dtht_helper;

	if (mdb_vread(&helper, sizeof (helper), haddr) == -1) {
		/*
		 * We're not going to warn in this case -- we're just not going
		 * to print anything exciting.
		 */
		mdb_printf("???\n");
	} else {
		switch (help.dtht_where) {
		case 0:
			mdb_printf("%p\n", helper.dthp_predicate);
			break;

		case DTRACE_HELPTRACE_NEXT:
		case DTRACE_HELPTRACE_DONE:
		case DTRACE_HELPTRACE_ERR:
			mdb_printf("-\n");
			break;

		default:
			haddr = (uintptr_t)helper.dthp_actions +
			    (help.dtht_where - 1) * sizeof (uintptr_t);

			if (mdb_vread(&haddr, sizeof (haddr), haddr) == -1) {
				mdb_printf("???\n");
			} else {
				mdb_printf("%p\n", haddr);
			}
		}
	}

	if (opt_v) {
		int i;

		mdb_printf("%?s|\n%?s+--> %?s %4s %s\n", "", "",
		    "ADDR", "NDX", "VALUE");
		addr += sizeof (help) - sizeof (uint64_t);

		for (i = 0; i < help.dtht_nlocals; i++) {
			uint64_t val;

			if (mdb_vread(&val, sizeof (val), addr) == -1) {
				mdb_warn("couldn't read local at %p", addr);
				continue;
			}

			mdb_printf("%?s     %?p %4d %p\n", "", addr, i, val);
			addr += sizeof (uint64_t);
		}

		mdb_printf("\n");
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
dtrace_state_walk(uintptr_t addr, const vmem_seg_t *seg, minor_t *highest)
{
	if (seg->vs_end > *highest)
		*highest = seg->vs_end;

	return (WALK_NEXT);
}

typedef struct dtrace_state_walk {
	uintptr_t dtsw_softstate;
	minor_t dtsw_max;
	minor_t dtsw_current;
} dtrace_state_walk_t;

int
dtrace_state_init(mdb_walk_state_t *wsp)
{
	uintptr_t dtrace_minor;
	minor_t max = 0;
	dtrace_state_walk_t *dw;

	if (wsp->walk_addr != NULL) {
		mdb_warn("dtrace_state only supports global walks\n");
		return (WALK_ERR);
	}

	/*
	 * Find the dtrace_minor vmem arena and walk it to get the maximum
	 * minor number.
	 */
	if (mdb_readvar(&dtrace_minor, "dtrace_minor") == -1) {
		mdb_warn("failed to read 'dtrace_minor'");
		return (WALK_ERR);
	}

	if (mdb_pwalk("vmem_alloc", (mdb_walk_cb_t)dtrace_state_walk,
	    &max, dtrace_minor) == -1) {
		mdb_warn("couldn't walk 'vmem_alloc'");
		return (WALK_ERR);
	}

	dw = mdb_zalloc(sizeof (dtrace_state_walk_t), UM_SLEEP | UM_GC);
	dw->dtsw_current = 0;
	dw->dtsw_max = max;

	if (mdb_readvar(&dw->dtsw_softstate, "dtrace_softstate") == -1) {
		mdb_warn("failed to read 'dtrace_softstate'");
		return (DCMD_ERR);
	}

	wsp->walk_data = dw;

	return (WALK_NEXT);
}

int
dtrace_state_step(mdb_walk_state_t *wsp)
{
	dtrace_state_walk_t *dw = wsp->walk_data;
	uintptr_t statep;
	dtrace_state_t state;
	int rval;

	while (mdb_get_soft_state_byaddr(dw->dtsw_softstate, dw->dtsw_current,
	    &statep, NULL, 0) == -1) {
		if (dw->dtsw_current >= dw->dtsw_max)
			return (WALK_DONE);

		dw->dtsw_current++;
	}

	if (mdb_vread(&state, sizeof (state), statep) == -1) {
		mdb_warn("couldn't read dtrace_state_t at %p", statep);
		return (WALK_NEXT);
	}

	rval = wsp->walk_callback(statep, &state, wsp->walk_cbdata);
	dw->dtsw_current++;

	return (rval);
}

typedef struct dtrace_state_data {
	int dtsd_major;
	uintptr_t dtsd_proc;
	uintptr_t dtsd_softstate;
	uintptr_t dtsd_state;
} dtrace_state_data_t;

static int
dtrace_state_file(uintptr_t addr, struct file *f, dtrace_state_data_t *data)
{
	vnode_t vnode;
	proc_t proc;
	minor_t minor;
	uintptr_t statep;

	if (mdb_vread(&vnode, sizeof (vnode), (uintptr_t)f->f_vnode) == -1) {
		mdb_warn("couldn't read vnode at %p", (uintptr_t)f->f_vnode);
		return (WALK_NEXT);
	}

	if (getmajor(vnode.v_rdev) != data->dtsd_major)
		return (WALK_NEXT);

	minor = getminor(vnode.v_rdev);

	if (mdb_vread(&proc, sizeof (proc), data->dtsd_proc) == -1) {
		mdb_warn("failed to read proc at %p", data->dtsd_proc);
		return (WALK_NEXT);
	}

	if (mdb_get_soft_state_byaddr(data->dtsd_softstate, minor,
	    &statep, NULL, 0) == -1) {
		mdb_warn("failed to read softstate for minor %d", minor);
		return (WALK_NEXT);
	}

	if (statep != data->dtsd_state)
		return (WALK_NEXT);

	mdb_printf("%?p %5d %?p %-*s %?p\n", statep, minor,
	    data->dtsd_proc, MAXCOMLEN, proc.p_user.u_comm, addr);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
dtrace_state_proc(uintptr_t addr, void *ignored, dtrace_state_data_t *data)
{
	data->dtsd_proc = addr;

	if (mdb_pwalk("file",
	    (mdb_walk_cb_t)dtrace_state_file, data, addr) == -1) {
		mdb_warn("couldn't walk 'file' for proc %p", addr);
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

void
dtrace_state_help(void)
{
	mdb_printf("Given a dtrace_state_t structure, displays all "
	    /*CSTYLED*/
	    "consumers, or \"<anonymous>\"\nif the consumer is anonymous.  If "
	    "no state structure is provided, iterates\nover all state "
	    "structures.\n\n"
	    "Addresses in ADDR column may be provided to ::dtrace to obtain\n"
	    "dtrace(1M)-like output for in-kernel DTrace data.\n");
}

int
dtrace_state(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t devi;
	struct dev_info info;
	dtrace_state_data_t data;
	dtrace_anon_t anon;
	dtrace_state_t state;

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("dtrace_state",
		    "dtrace_state", argc, argv) == -1) {
			mdb_warn("can't walk dtrace_state");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%?s %5s %?s %-*s %?s\n", "ADDR", "MINOR", "PROC",
		    MAXCOMLEN, "NAME", "FILE");
	}

	/*
	 * First determine if this is anonymous state.
	 */
	if (mdb_readvar(&anon, "dtrace_anon") == -1) {
		mdb_warn("failed to read 'dtrace_anon'");
		return (DCMD_ERR);
	}

	if ((uintptr_t)anon.dta_state == addr) {
		if (mdb_vread(&state, sizeof (state), addr) == -1) {
			mdb_warn("failed to read anon at %p", addr);
			return (DCMD_ERR);
		}

		mdb_printf("%?p %5d %?s %-*s %?s\n", addr,
		    getminor(state.dts_dev), "-", MAXCOMLEN,
		    "<anonymous>", "-");

		return (DCMD_OK);
	}

	if (mdb_readvar(&devi, "dtrace_devi") == -1) {
		mdb_warn("failed to read 'dtrace_devi'");
		return (DCMD_ERR);
	}

	if (mdb_vread(&info, sizeof (struct dev_info), devi) == -1) {
		mdb_warn("failed to read 'dev_info'");
		return (DCMD_ERR);
	}

	data.dtsd_major = info.devi_major;

	if (mdb_readvar(&data.dtsd_softstate, "dtrace_softstate") == -1) {
		mdb_warn("failed to read 'dtrace_softstate'");
		return (DCMD_ERR);
	}

	data.dtsd_state = addr;

	/*
	 * Walk through all processes and all open files looking for this
	 * state.  It must be open somewhere...
	 */
	if (mdb_walk("proc", (mdb_walk_cb_t)dtrace_state_proc, &data) == -1) {
		mdb_warn("couldn't walk 'proc'");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

typedef struct dtrace_aggkey_data {
	uintptr_t *dtakd_hash;
	uintptr_t dtakd_hashsize;
	uintptr_t dtakd_next;
	uintptr_t dtakd_ndx;
} dtrace_aggkey_data_t;

int
dtrace_aggkey_init(mdb_walk_state_t *wsp)
{
	dtrace_buffer_t buf;
	uintptr_t addr;
	dtrace_aggbuffer_t agb;
	dtrace_aggkey_data_t *data;
	size_t hsize;

	if ((addr = wsp->walk_addr) == NULL) {
		mdb_warn("dtrace_aggkey walk needs aggregation buffer\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&buf, sizeof (buf), addr) == -1) {
		mdb_warn("failed to read aggregation buffer at %p", addr);
		return (WALK_ERR);
	}

	addr = (uintptr_t)buf.dtb_tomax +
	    buf.dtb_size - sizeof (dtrace_aggbuffer_t);

	if (mdb_vread(&agb, sizeof (agb), addr) == -1) {
		mdb_warn("failed to read dtrace_aggbuffer_t at %p", addr);
		return (WALK_ERR);
	}

	data = mdb_zalloc(sizeof (dtrace_aggkey_data_t), UM_SLEEP);

	data->dtakd_hashsize = agb.dtagb_hashsize;
	hsize = agb.dtagb_hashsize * sizeof (dtrace_aggkey_t *);
	data->dtakd_hash = mdb_alloc(hsize, UM_SLEEP);

	if (mdb_vread(data->dtakd_hash, hsize,
	    (uintptr_t)agb.dtagb_hash) == -1) {
		mdb_warn("failed to read hash at %p",
		    (uintptr_t)agb.dtagb_hash);
		mdb_free(data->dtakd_hash, hsize);
		mdb_free(data, sizeof (dtrace_aggkey_data_t));
		return (WALK_ERR);
	}

	wsp->walk_data = data;
	return (WALK_NEXT);
}

int
dtrace_aggkey_step(mdb_walk_state_t *wsp)
{
	dtrace_aggkey_data_t *data = wsp->walk_data;
	dtrace_aggkey_t key;
	uintptr_t addr;

	while ((addr = data->dtakd_next) == NULL) {
		if (data->dtakd_ndx == data->dtakd_hashsize)
			return (WALK_DONE);

		data->dtakd_next = data->dtakd_hash[data->dtakd_ndx++];
	}

	if (mdb_vread(&key, sizeof (key), addr) == -1) {
		mdb_warn("failed to read dtrace_aggkey_t at %p", addr);
		return (WALK_ERR);
	}

	data->dtakd_next = (uintptr_t)key.dtak_next;

	return (wsp->walk_callback(addr, &key, wsp->walk_cbdata));
}

void
dtrace_aggkey_fini(mdb_walk_state_t *wsp)
{
	dtrace_aggkey_data_t *data = wsp->walk_data;
	size_t hsize;

	hsize = data->dtakd_hashsize * sizeof (dtrace_aggkey_t *);
	mdb_free(data->dtakd_hash, hsize);
	mdb_free(data, sizeof (dtrace_aggkey_data_t));
}

typedef struct dtrace_dynvar_data {
	dtrace_dynhash_t *dtdvd_hash;
	uintptr_t dtdvd_hashsize;
	uintptr_t dtdvd_next;
	uintptr_t dtdvd_ndx;
} dtrace_dynvar_data_t;

int
dtrace_dynvar_init(mdb_walk_state_t *wsp)
{
	uintptr_t addr;
	dtrace_dstate_t dstate;
	dtrace_dynvar_data_t *data;
	size_t hsize;

	if ((addr = wsp->walk_addr) == NULL) {
		mdb_warn("dtrace_dynvar walk needs dtrace_dstate_t\n");
		return (WALK_ERR);
	}

	if (mdb_vread(&dstate, sizeof (dstate), addr) == -1) {
		mdb_warn("failed to read dynamic state at %p", addr);
		return (WALK_ERR);
	}

	data = mdb_zalloc(sizeof (dtrace_dynvar_data_t), UM_SLEEP);

	data->dtdvd_hashsize = dstate.dtds_hashsize;
	hsize = dstate.dtds_hashsize * sizeof (dtrace_dynhash_t);
	data->dtdvd_hash = mdb_alloc(hsize, UM_SLEEP);

	if (mdb_vread(data->dtdvd_hash, hsize,
	    (uintptr_t)dstate.dtds_hash) == -1) {
		mdb_warn("failed to read hash at %p",
		    (uintptr_t)dstate.dtds_hash);
		mdb_free(data->dtdvd_hash, hsize);
		mdb_free(data, sizeof (dtrace_dynvar_data_t));
		return (WALK_ERR);
	}

	wsp->walk_data = data;
	return (WALK_NEXT);
}

int
dtrace_dynvar_step(mdb_walk_state_t *wsp)
{
	dtrace_dynvar_data_t *data = wsp->walk_data;
	dtrace_dynvar_t dynvar, *dvar;
	size_t dvarsize;
	uintptr_t addr;
	int nkeys;

	while ((addr = data->dtdvd_next) == NULL) {
		if (data->dtdvd_ndx == data->dtdvd_hashsize)
			return (WALK_DONE);

		data->dtdvd_next =
		    (uintptr_t)data->dtdvd_hash[data->dtdvd_ndx++].dtdh_chain;
	}

	if (mdb_vread(&dynvar, sizeof (dynvar), addr) == -1) {
		mdb_warn("failed to read dtrace_dynvar_t at %p", addr);
		return (WALK_ERR);
	}

	/*
	 * Now we need to allocate the correct size.
	 */
	nkeys = dynvar.dtdv_tuple.dtt_nkeys;
	dvarsize = (uintptr_t)&dynvar.dtdv_tuple.dtt_key[nkeys] -
	    (uintptr_t)&dynvar;

	dvar = alloca(dvarsize);

	if (mdb_vread(dvar, dvarsize, addr) == -1) {
		mdb_warn("failed to read dtrace_dynvar_t at %p", addr);
		return (WALK_ERR);
	}

	data->dtdvd_next = (uintptr_t)dynvar.dtdv_next;

	return (wsp->walk_callback(addr, dvar, wsp->walk_cbdata));
}

void
dtrace_dynvar_fini(mdb_walk_state_t *wsp)
{
	dtrace_dynvar_data_t *data = wsp->walk_data;
	size_t hsize;

	hsize = data->dtdvd_hashsize * sizeof (dtrace_dynvar_t *);
	mdb_free(data->dtdvd_hash, hsize);
	mdb_free(data, sizeof (dtrace_dynvar_data_t));
}

typedef struct dtrace_hashstat_data {
	size_t *dthsd_counts;
	size_t dthsd_hashsize;
	char *dthsd_data;
	size_t dthsd_size;
	int dthsd_header;
} dtrace_hashstat_data_t;

typedef void (*dtrace_hashstat_func_t)(dtrace_hashstat_data_t *);

static void
dtrace_hashstat_additive(dtrace_hashstat_data_t *data)
{
	int i;
	int hval = 0;

	for (i = 0; i < data->dthsd_size; i++)
		hval += data->dthsd_data[i];

	data->dthsd_counts[hval % data->dthsd_hashsize]++;
}

static void
dtrace_hashstat_shifty(dtrace_hashstat_data_t *data)
{
	uint64_t hval = 0;
	int i;

	if (data->dthsd_size < sizeof (uint64_t)) {
		dtrace_hashstat_additive(data);
		return;
	}

	for (i = 0; i < data->dthsd_size; i += sizeof (uint64_t)) {
		/* LINTED - alignment */
		uint64_t val = *((uint64_t *)&data->dthsd_data[i]);

		hval += (val & ((1 << NBBY) - 1)) +
		    ((val >> NBBY) & ((1 << NBBY) - 1)) +
		    ((val >> (NBBY << 1)) & ((1 << NBBY) - 1)) +
		    ((val >> (NBBY << 2)) & ((1 << NBBY) - 1)) +
		    (val & USHRT_MAX) + (val >> (NBBY << 1) & USHRT_MAX);
	}

	data->dthsd_counts[hval % data->dthsd_hashsize]++;
}

static void
dtrace_hashstat_knuth(dtrace_hashstat_data_t *data)
{
	int i;
	int hval = data->dthsd_size;

	for (i = 0; i < data->dthsd_size; i++)
		hval = (hval << 4) ^ (hval >> 28) ^ data->dthsd_data[i];

	data->dthsd_counts[hval % data->dthsd_hashsize]++;
}

static void
dtrace_hashstat_oneatatime(dtrace_hashstat_data_t *data)
{
	int i;
	uint32_t hval = 0;

	for (i = 0; i < data->dthsd_size; i++) {
		hval += data->dthsd_data[i];
		hval += (hval << 10);
		hval ^= (hval >> 6);
	}

	hval += (hval << 3);
	hval ^= (hval >> 11);
	hval += (hval << 15);

	data->dthsd_counts[hval % data->dthsd_hashsize]++;
}

static void
dtrace_hashstat_fnv(dtrace_hashstat_data_t *data)
{
	static const uint32_t prime = 0x01000193;
	uint32_t hval = 0;
	int i;

	for (i = 0; i < data->dthsd_size; i++) {
		hval *= prime;
		hval ^= data->dthsd_data[i];
	}

	data->dthsd_counts[hval % data->dthsd_hashsize]++;
}

static void
dtrace_hashstat_stats(char *name, dtrace_hashstat_data_t *data)
{
	size_t nz = 0, i;
	int longest = 0;
	size_t ttl = 0;
	double sum = 0.0;
	double avg;
	uint_t util, stddev;

	if (!data->dthsd_header) {
		mdb_printf("%15s %11s %11s %11s %11s %11s\n", "NAME",
		    "HASHSIZE", "%UTIL", "LONGEST", "AVERAGE", "STDDEV");
		data->dthsd_header = 1;
	}

	for (i = 0; i < data->dthsd_hashsize; i++) {
		if (data->dthsd_counts[i] != 0) {
			nz++;

			if (data->dthsd_counts[i] > longest)
				longest = data->dthsd_counts[i];

			ttl += data->dthsd_counts[i];
		}
	}

	if (nz == 0) {
		mdb_printf("%15s %11d %11s %11s %11s %11s\n", name,
		    data->dthsd_hashsize, "-", "-", "-", "-");
		return;
	}

	avg = (double)ttl / (double)nz;

	for (i = 0; i < data->dthsd_hashsize; i++) {
		double delta = (double)data->dthsd_counts[i] - avg;

		if (data->dthsd_counts[i] == 0)
			continue;

		sum += delta * delta;
	}

	util = (nz * 1000) / data->dthsd_hashsize;
	stddev = (uint_t)sqrt(sum / (double)nz) * 10;

	mdb_printf("%15s %11d %9u.%1u %11d %11d %9u.%1u\n", name,
	    data->dthsd_hashsize, util / 10, util % 10, longest, ttl / nz,
	    stddev / 10, stddev % 10);
}

static struct dtrace_hashstat {
	char *dths_name;
	dtrace_hashstat_func_t dths_func;
} _dtrace_hashstat[] = {
	{ "<actual>", NULL },
	{ "additive", dtrace_hashstat_additive },
	{ "shifty", dtrace_hashstat_shifty },
	{ "knuth", dtrace_hashstat_knuth },
	{ "one-at-a-time", dtrace_hashstat_oneatatime },
	{ "fnv", dtrace_hashstat_fnv },
	{ NULL, 0 }
};

typedef struct dtrace_aggstat_data {
	dtrace_hashstat_data_t dtagsd_hash;
	dtrace_hashstat_func_t dtagsd_func;
} dtrace_aggstat_data_t;

static int
dtrace_aggstat_walk(uintptr_t addr, dtrace_aggkey_t *key,
    dtrace_aggstat_data_t *data)
{
	dtrace_hashstat_data_t *hdata = &data->dtagsd_hash;
	size_t size;

	if (data->dtagsd_func == NULL) {
		size_t bucket = key->dtak_hashval % hdata->dthsd_hashsize;

		hdata->dthsd_counts[bucket]++;
		return (WALK_NEXT);
	}

	/*
	 * We need to read the data.
	 */
	size = key->dtak_size - sizeof (dtrace_aggid_t);
	addr = (uintptr_t)key->dtak_data + sizeof (dtrace_aggid_t);
	hdata->dthsd_data = alloca(size);
	hdata->dthsd_size = size;

	if (mdb_vread(hdata->dthsd_data, size, addr) == -1) {
		mdb_warn("couldn't read data at %p", addr);
		return (WALK_ERR);
	}

	data->dtagsd_func(hdata);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
dtrace_aggstat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_buffer_t buf;
	uintptr_t aaddr;
	dtrace_aggbuffer_t agb;
	size_t hsize, i, actual, prime, evenpow;
	dtrace_aggstat_data_t data;
	dtrace_hashstat_data_t *hdata = &data.dtagsd_hash;

	bzero(&data, sizeof (data));

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&buf, sizeof (buf), addr) == -1) {
		mdb_warn("failed to read aggregation buffer at %p", addr);
		return (DCMD_ERR);
	}

	aaddr = (uintptr_t)buf.dtb_tomax +
	    buf.dtb_size - sizeof (dtrace_aggbuffer_t);

	if (mdb_vread(&agb, sizeof (agb), aaddr) == -1) {
		mdb_warn("failed to read dtrace_aggbuffer_t at %p", aaddr);
		return (DCMD_ERR);
	}

	hsize = (actual = agb.dtagb_hashsize) * sizeof (size_t);
	hdata->dthsd_counts = mdb_alloc(hsize, UM_SLEEP | UM_GC);

	/*
	 * Now pick the largest prime smaller than the hash size.  (If the
	 * existing size is prime, we'll pick a smaller prime just for the
	 * hell of it.)
	 */
	for (prime = agb.dtagb_hashsize - 1; prime > 7; prime--) {
		size_t limit = prime / 7;

		for (i = 2; i < limit; i++) {
			if ((prime % i) == 0)
				break;
		}

		if (i == limit)
			break;
	}

	/*
	 * And now we want to pick the largest power of two smaller than the
	 * hashsize.
	 */
	for (i = 0; (1 << i) < agb.dtagb_hashsize; i++)
		continue;

	evenpow = (1 << (i - 1));

	for (i = 0; _dtrace_hashstat[i].dths_name != NULL; i++) {
		data.dtagsd_func = _dtrace_hashstat[i].dths_func;

		hdata->dthsd_hashsize = actual;
		hsize = hdata->dthsd_hashsize * sizeof (size_t);
		bzero(hdata->dthsd_counts, hsize);

		if (mdb_pwalk("dtrace_aggkey",
		    (mdb_walk_cb_t)dtrace_aggstat_walk, &data, addr) == -1) {
			mdb_warn("failed to walk dtrace_aggkey at %p", addr);
			return (DCMD_ERR);
		}

		dtrace_hashstat_stats(_dtrace_hashstat[i].dths_name, hdata);

		/*
		 * If we were just printing the actual value, we won't try
		 * any of the sizing experiments.
		 */
		if (data.dtagsd_func == NULL)
			continue;

		hdata->dthsd_hashsize = prime;
		hsize = hdata->dthsd_hashsize * sizeof (size_t);
		bzero(hdata->dthsd_counts, hsize);

		if (mdb_pwalk("dtrace_aggkey",
		    (mdb_walk_cb_t)dtrace_aggstat_walk, &data, addr) == -1) {
			mdb_warn("failed to walk dtrace_aggkey at %p", addr);
			return (DCMD_ERR);
		}

		dtrace_hashstat_stats(_dtrace_hashstat[i].dths_name, hdata);

		hdata->dthsd_hashsize = evenpow;
		hsize = hdata->dthsd_hashsize * sizeof (size_t);
		bzero(hdata->dthsd_counts, hsize);

		if (mdb_pwalk("dtrace_aggkey",
		    (mdb_walk_cb_t)dtrace_aggstat_walk, &data, addr) == -1) {
			mdb_warn("failed to walk dtrace_aggkey at %p", addr);
			return (DCMD_ERR);
		}

		dtrace_hashstat_stats(_dtrace_hashstat[i].dths_name, hdata);
	}

	return (DCMD_OK);
}

/*ARGSUSED*/
static int
dtrace_dynstat_walk(uintptr_t addr, dtrace_dynvar_t *dynvar,
    dtrace_aggstat_data_t *data)
{
	dtrace_hashstat_data_t *hdata = &data->dtagsd_hash;
	dtrace_tuple_t *tuple = &dynvar->dtdv_tuple;
	dtrace_key_t *key = tuple->dtt_key;
	size_t size = 0, offs = 0;
	int i, nkeys = tuple->dtt_nkeys;
	char *buf;

	if (data->dtagsd_func == NULL) {
		size_t bucket = dynvar->dtdv_hashval % hdata->dthsd_hashsize;

		hdata->dthsd_counts[bucket]++;
		return (WALK_NEXT);
	}

	/*
	 * We want to hand the hashing algorithm a contiguous buffer.  First
	 * run through the tuple and determine the size.
	 */
	for (i = 0; i < nkeys; i++) {
		if (key[i].dttk_size == 0) {
			size += sizeof (uint64_t);
		} else {
			size += key[i].dttk_size;
		}
	}

	buf = alloca(size);

	/*
	 * Now go back through the tuple and copy the data into the buffer.
	 */
	for (i = 0; i < nkeys; i++) {
		if (key[i].dttk_size == 0) {
			bcopy(&key[i].dttk_value, &buf[offs],
			    sizeof (uint64_t));
			offs += sizeof (uint64_t);
		} else {
			if (mdb_vread(&buf[offs], key[i].dttk_size,
			    key[i].dttk_value) == -1) {
				mdb_warn("couldn't read tuple data at %p",
				    key[i].dttk_value);
				return (WALK_ERR);
			}

			offs += key[i].dttk_size;
		}
	}

	hdata->dthsd_data = buf;
	hdata->dthsd_size = size;

	data->dtagsd_func(hdata);

	return (WALK_NEXT);
}

/*ARGSUSED*/
int
dtrace_dynstat(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	dtrace_dstate_t dstate;
	size_t hsize, i, actual, prime;
	dtrace_aggstat_data_t data;
	dtrace_hashstat_data_t *hdata = &data.dtagsd_hash;

	bzero(&data, sizeof (data));

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (mdb_vread(&dstate, sizeof (dstate), addr) == -1) {
		mdb_warn("failed to read dynamic variable state at %p", addr);
		return (DCMD_ERR);
	}

	hsize = (actual = dstate.dtds_hashsize) * sizeof (size_t);
	hdata->dthsd_counts = mdb_alloc(hsize, UM_SLEEP | UM_GC);

	/*
	 * Now pick the largest prime smaller than the hash size.  (If the
	 * existing size is prime, we'll pick a smaller prime just for the
	 * hell of it.)
	 */
	for (prime = dstate.dtds_hashsize - 1; prime > 7; prime--) {
		size_t limit = prime / 7;

		for (i = 2; i < limit; i++) {
			if ((prime % i) == 0)
				break;
		}

		if (i == limit)
			break;
	}

	for (i = 0; _dtrace_hashstat[i].dths_name != NULL; i++) {
		data.dtagsd_func = _dtrace_hashstat[i].dths_func;

		hdata->dthsd_hashsize = actual;
		hsize = hdata->dthsd_hashsize * sizeof (size_t);
		bzero(hdata->dthsd_counts, hsize);

		if (mdb_pwalk("dtrace_dynvar",
		    (mdb_walk_cb_t)dtrace_dynstat_walk, &data, addr) == -1) {
			mdb_warn("failed to walk dtrace_dynvar at %p", addr);
			return (DCMD_ERR);
		}

		dtrace_hashstat_stats(_dtrace_hashstat[i].dths_name, hdata);

		/*
		 * If we were just printing the actual value, we won't try
		 * any of the sizing experiments.
		 */
		if (data.dtagsd_func == NULL)
			continue;

		hdata->dthsd_hashsize = prime;
		hsize = hdata->dthsd_hashsize * sizeof (size_t);
		bzero(hdata->dthsd_counts, hsize);

		if (mdb_pwalk("dtrace_dynvar",
		    (mdb_walk_cb_t)dtrace_dynstat_walk, &data, addr) == -1) {
			mdb_warn("failed to walk dtrace_aggkey at %p", addr);
			return (DCMD_ERR);
		}

		dtrace_hashstat_stats(_dtrace_hashstat[i].dths_name, hdata);
	}

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
dof_sect_provider(uintptr_t addr, dof_sec_t *sec, dof_sec_t *dofs)
{
	dof_provider_t pv;
	dof_probe_t *pb;
	char *strtab;
	uint32_t *offs;
	uint8_t *args = NULL;
	size_t sz;
	int i, j;
	dof_stridx_t narg, xarg;

	if (mdb_vread(&pv, sizeof (dof_provider_t),
	    addr + sec->dofs_offset) != sizeof (dof_provider_t)) {
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
		mdb_warn("failed to read offs");
		return (-1);
	}

	sz = dofs[pv.dofpv_probes].dofs_size;
	pb = mdb_alloc(sz, UM_SLEEP | UM_GC);
	if (mdb_vread(pb, sz, addr + dofs[pv.dofpv_probes].dofs_offset) != sz) {
		mdb_warn("failed to read probes");
		return (-1);
	}

	(void) mdb_inc_indent(2);

	for (i = 0; i < sz / dofs[pv.dofpv_probes].dofs_entsize; i++) {
		mdb_printf("%lx probe %s:%s {\n", (ulong_t)(addr +
		    dofs[pv.dofpv_probes].dofs_offset +
		    i * dofs[pv.dofpv_probes].dofs_entsize),
		    strtab + pb[i].dofpr_func,
		    strtab + pb[i].dofpr_name);

		(void) mdb_inc_indent(2);
		mdb_printf("addr: %p\n", (ulong_t)pb[i].dofpr_addr);
		mdb_printf("offs: ");
		for (j = 0; j < pb[i].dofpr_noffs; j++) {
			mdb_printf("%s %x", "," + (j == 0),
			    offs[pb[i].dofpr_offidx + j]);
		}
		mdb_printf("\n");

		mdb_printf("nargs:");
		narg = pb[i].dofpr_nargv;
		for (j = 0; j < pb[i].dofpr_nargc; j++) {
			mdb_printf("%s %s", "," + (j == 0), strtab + narg);
			narg += strlen(strtab + narg) + 1;
		}
		mdb_printf("\n");
		mdb_printf("xargs:");
		xarg = pb[i].dofpr_xargv;
		for (j = 0; j < pb[i].dofpr_xargc; j++) {
			mdb_printf("%s %s", "," + (j == 0), strtab + xarg);
			xarg += strlen(strtab + xarg) + 1;
		}
		mdb_printf("\n");
		mdb_printf("map:  ");
		for (j = 0; j < pb[i].dofpr_xargc; j++) {
			mdb_printf("%s %d->%d", "," + (j == 0),
			    args[pb[i].dofpr_argidx + j], j);
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
		mdb_printf("%lx Section %d: %s\n", (ulong_t)(dofh.dofh_secoff +
		    addr + i * dofh.dofh_secsize), i,
		    dof_sec_typename(dofs[i].dofs_type));

		(void) mdb_inc_indent(2);
		switch (dofs[i].dofs_type) {
		case DOF_SECT_PROVIDER:
			(void) dof_sect_provider(addr, &dofs[i], dofs);
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

static const mdb_dcmd_t dcmds[] = {
	{ "id2probe", ":", "translate a dtrace_id_t to a dtrace_probe_t",
	    id2probe },
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
	{ "dtrace", ":[-c cpu]", "print dtrace(1M)-like output",
	    dtrace, dtrace_help },
	{ "dtrace_errhash", ":", "print DTrace error hash", dtrace_errhash },
	{ "dtrace_helptrace", ":", "print DTrace helper trace",
	    dtrace_helptrace },
	{ "dtrace_state", ":", "print active DTrace consumers", dtrace_state,
	    dtrace_state_help },
	{ "dtrace_aggstat", ":",
	    "print DTrace aggregation hash statistics", dtrace_aggstat },
	{ "dtrace_dynstat", ":",
	    "print DTrace dynamic variable hash statistics", dtrace_dynstat },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "dof_sec", "walk DOF section header table given header address",
		dof_sec_walk_init, dof_sec_walk_step, dof_sec_walk_fini },
	{ "dtrace_errhash", "walk hash of DTrace error messasges",
		dtrace_errhash_init, dtrace_errhash_step },
	{ "dtrace_helptrace", "walk DTrace helper trace entries",
		dtrace_helptrace_init, dtrace_helptrace_step },
	{ "dtrace_state", "walk DTrace per-consumer softstate",
		dtrace_state_init, dtrace_state_step },
	{ "dtrace_aggkey", "walk DTrace aggregation keys",
		dtrace_aggkey_init, dtrace_aggkey_step, dtrace_aggkey_fini },
	{ "dtrace_dynvar", "walk DTrace dynamic variables",
		dtrace_dynvar_init, dtrace_dynvar_step, dtrace_dynvar_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
