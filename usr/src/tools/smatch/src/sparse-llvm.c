/*
 * Example usage:
 *	./sparse-llvm hello.c | llc | as -o hello.o
 */

#include <llvm-c/Core.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Analysis.h>
#include <llvm-c/Target.h>

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "symbol.h"
#include "expression.h"
#include "linearize.h"
#include "flow.h"

struct function {
	LLVMBuilderRef			builder;
	LLVMValueRef			fn;
	LLVMModuleRef			module;
};

static LLVMTypeRef symbol_type(struct symbol *sym);

static LLVMTypeRef func_return_type(struct symbol *sym)
{
	return symbol_type(sym->ctype.base_type);
}

static LLVMTypeRef sym_func_type(struct symbol *sym)
{
	int n_arg = symbol_list_size(sym->arguments);
	LLVMTypeRef *arg_type = calloc(n_arg, sizeof(LLVMTypeRef));
	LLVMTypeRef ret_type = func_return_type(sym);
	struct symbol *arg;
	int idx = 0;

	FOR_EACH_PTR(sym->arguments, arg) {
		struct symbol *arg_sym = arg->ctype.base_type;

		arg_type[idx++] = symbol_type(arg_sym);
	} END_FOR_EACH_PTR(arg);

	return LLVMFunctionType(ret_type, arg_type, n_arg, sym->variadic);
}

static LLVMTypeRef sym_array_type(struct symbol *sym)
{
	LLVMTypeRef elem_type;
	struct symbol *base_type;

	base_type = sym->ctype.base_type;
	/* empty struct is undefined [6.7.2.1(8)] */
	assert(base_type->bit_size > 0);

	elem_type = symbol_type(base_type);
	if (!elem_type)
		return NULL;

	return LLVMArrayType(elem_type, sym->bit_size / base_type->bit_size);
}

#define MAX_STRUCT_MEMBERS 64

static LLVMTypeRef sym_struct_type(struct symbol *sym)
{
	LLVMTypeRef elem_types[MAX_STRUCT_MEMBERS];
	struct symbol *member;
	char buffer[256];
	LLVMTypeRef ret;
	unsigned nr = 0;

	snprintf(buffer, sizeof(buffer), "struct.%s", sym->ident ? sym->ident->name : "anno");
	ret = LLVMStructCreateNamed(LLVMGetGlobalContext(), buffer);
	/* set ->aux to avoid recursion */
	sym->aux = ret;

	FOR_EACH_PTR(sym->symbol_list, member) {
		LLVMTypeRef member_type;

		assert(nr < MAX_STRUCT_MEMBERS);

		member_type = symbol_type(member);

		elem_types[nr++] = member_type; 
	} END_FOR_EACH_PTR(member);

	LLVMStructSetBody(ret, elem_types, nr, 0 /* packed? */); 
	return ret;
}

static LLVMTypeRef sym_union_type(struct symbol *sym)
{
	LLVMTypeRef elements;
	unsigned union_size;

	/*
	 * There's no union support in the LLVM API so we treat unions as
	 * opaque structs. The downside is that we lose type information on the
	 * members but as LLVM doesn't care, neither do we.
	 */
	union_size = sym->bit_size / 8;

	elements = LLVMArrayType(LLVMInt8Type(), union_size);

	return LLVMStructType(&elements, 1, 0 /* packed? */);
}

static LLVMTypeRef sym_ptr_type(struct symbol *sym)
{
	LLVMTypeRef type;

	/* 'void *' is treated like 'char *' */
	if (is_void_type(sym->ctype.base_type))
		type = LLVMInt8Type();
	else
		type = symbol_type(sym->ctype.base_type);

	return LLVMPointerType(type, 0);
}

static LLVMTypeRef sym_basetype_type(struct symbol *sym)
{
	LLVMTypeRef ret = NULL;

	if (is_float_type(sym)) {
		switch (sym->bit_size) {
		case 32:
			ret = LLVMFloatType();
			break;
		case 64:
			ret = LLVMDoubleType();
			break;
		case 80:
			ret = LLVMX86FP80Type();
			break;
		default:
			die("invalid bit size %d for type %d", sym->bit_size, sym->type);
			break;
		}
	} else {
		switch (sym->bit_size) {
		case -1:
			ret = LLVMVoidType();
			break;
		case 1:
			ret = LLVMInt1Type();
			break;
		case 8:
			ret = LLVMInt8Type();
			break;
		case 16:
			ret = LLVMInt16Type();
			break;
		case 32:
			ret = LLVMInt32Type();
			break;
		case 64:
			ret = LLVMInt64Type();
			break;
		default:
			die("invalid bit size %d for type %d", sym->bit_size, sym->type);
			break;
		}
	}

	return ret;
}

static LLVMTypeRef symbol_type(struct symbol *sym)
{
	LLVMTypeRef ret = NULL;

	/* don't cache the result for SYM_NODE */
	if (sym->type == SYM_NODE)
		return symbol_type(sym->ctype.base_type);

	if (sym->aux)
		return sym->aux;

	switch (sym->type) {
	case SYM_BITFIELD:
		ret = LLVMIntType(sym->bit_size);
		break;
	case SYM_RESTRICT:
	case SYM_ENUM:
		ret = symbol_type(sym->ctype.base_type);
		break;
	case SYM_BASETYPE:
		ret = sym_basetype_type(sym);
		break;
	case SYM_PTR:
		ret = sym_ptr_type(sym);
		break;
	case SYM_UNION:
		ret = sym_union_type(sym);
		break;
	case SYM_STRUCT:
		ret = sym_struct_type(sym);
		break;
	case SYM_ARRAY:
		ret = sym_array_type(sym);
		break;
	case SYM_FN:
		ret = sym_func_type(sym);
		break;
	default:
		assert(0);
	}

	/* cache the result */
	sym->aux = ret;
	return ret;
}

static LLVMTypeRef insn_symbol_type(struct instruction *insn)
{
	if (insn->type)
		return symbol_type(insn->type);

	switch (insn->size) {
		case 8:		return LLVMInt8Type();
		case 16:	return LLVMInt16Type();
		case 32:	return LLVMInt32Type();
		case 64:	return LLVMInt64Type();

		default:
			die("invalid bit size %d", insn->size);
			break;
	}

	return NULL;	/* not reached */
}

static LLVMLinkage data_linkage(struct symbol *sym)
{
	if (sym->ctype.modifiers & MOD_STATIC)
		return LLVMPrivateLinkage;

	return LLVMExternalLinkage;
}

static LLVMLinkage function_linkage(struct symbol *sym)
{
	if (sym->ctype.modifiers & MOD_STATIC)
		return LLVMInternalLinkage;

	return LLVMExternalLinkage;
}

#define MAX_PSEUDO_NAME 64

static const char *pseudo_name(pseudo_t pseudo, char *buf)
{
	switch (pseudo->type) {
	case PSEUDO_REG:
		snprintf(buf, MAX_PSEUDO_NAME, "R%d.", pseudo->nr);
		break;
	case PSEUDO_PHI:
		snprintf(buf, MAX_PSEUDO_NAME, "PHI%d.", pseudo->nr);
		break;
	case PSEUDO_SYM:
	case PSEUDO_VAL:
	case PSEUDO_ARG:
	case PSEUDO_VOID:
		buf[0] = '\0';
		break;
	case PSEUDO_UNDEF:
		assert(0);
		break;
	default:
		assert(0);
	}

	return buf;
}

static LLVMValueRef get_sym_value(LLVMModuleRef module, struct symbol *sym)
{
	const char *name = show_ident(sym->ident);
	LLVMTypeRef type = symbol_type(sym);
	LLVMValueRef result = NULL;
	struct expression *expr;

	assert(sym->bb_target == NULL);

	expr = sym->initializer;
	if (expr && !sym->ident) {
		switch (expr->type) {
		case EXPR_STRING: {
			const char *s = expr->string->data;
			LLVMValueRef indices[] = { LLVMConstInt(LLVMInt64Type(), 0, 0), LLVMConstInt(LLVMInt64Type(), 0, 0) };
			LLVMValueRef data;

			data = LLVMAddGlobal(module, LLVMArrayType(LLVMInt8Type(), strlen(s) + 1), ".str");
			LLVMSetLinkage(data, LLVMPrivateLinkage);
			LLVMSetGlobalConstant(data, 1);
			LLVMSetInitializer(data, LLVMConstString(strdup(s), strlen(s) + 1, true));

			result = LLVMConstGEP(data, indices, ARRAY_SIZE(indices));
			return result;
		}
		default:
			break;
		}
	}

	if (LLVMGetTypeKind(type) == LLVMFunctionTypeKind) {
		result = LLVMGetNamedFunction(module, name);
		if (!result)
			result = LLVMAddFunction(module, name, type);
	} else {
		result = LLVMGetNamedGlobal(module, name);
		if (!result)
			result = LLVMAddGlobal(module, type, name);
	}

	return result;
}

static LLVMValueRef constant_value(unsigned long long val, LLVMTypeRef dtype)
{
	LLVMValueRef result;

	switch (LLVMGetTypeKind(dtype)) {
	case LLVMPointerTypeKind:
		if (val != 0) {	 // for example: ... = (void*) 0x123;
			LLVMTypeRef itype = LLVMIntType(bits_in_pointer);
			result = LLVMConstInt(itype, val, 1);
			result = LLVMConstIntToPtr(result, dtype);
		} else {
			result = LLVMConstPointerNull(dtype);
		}
		break;
	case LLVMIntegerTypeKind:
		result = LLVMConstInt(dtype, val, 1);
		break;
	case LLVMArrayTypeKind:
	case LLVMStructTypeKind:
		if (val != 0)
			return NULL;
		result = LLVMConstNull(dtype);
		break;
	default:
		return NULL;
	}
	return result;
}

static LLVMValueRef val_to_value(unsigned long long val, struct symbol *ctype)
{
	LLVMValueRef result;
	LLVMTypeRef dtype;

	assert(ctype);
	dtype = symbol_type(ctype);
	result = constant_value(val, dtype);
	if (result)
		return result;
	sparse_error(ctype->pos, "no value possible for %s", show_typename(ctype));
	return LLVMGetUndef(symbol_type(ctype));
}

static LLVMValueRef pseudo_to_value(struct function *fn, struct symbol *ctype, pseudo_t pseudo)
{
	LLVMValueRef result = NULL;

	switch (pseudo->type) {
	case PSEUDO_REG:
		result = pseudo->priv;
		break;
	case PSEUDO_SYM:
		result = get_sym_value(fn->module, pseudo->sym);
		break;
	case PSEUDO_VAL:
		result = val_to_value(pseudo->value, ctype);
		break;
	case PSEUDO_ARG: {
		result = LLVMGetParam(fn->fn, pseudo->nr - 1);
		break;
	}
	case PSEUDO_PHI:
		result = pseudo->priv;
		break;
	case PSEUDO_VOID:
		result = NULL;
		break;
	case PSEUDO_UNDEF:
		result = LLVMGetUndef(symbol_type(ctype));
		break;
	default:
		assert(0);
	}

	return result;
}

static LLVMValueRef pseudo_to_rvalue(struct function *fn, struct symbol *ctype, pseudo_t pseudo)
{
	LLVMValueRef val = pseudo_to_value(fn, ctype, pseudo);
	LLVMTypeRef dtype = symbol_type(ctype);
	char name[MAX_PSEUDO_NAME];

	pseudo_name(pseudo, name);
	return LLVMBuildBitCast(fn->builder, val, dtype, name);
}

static LLVMValueRef value_to_ivalue(struct function *fn, struct symbol *ctype, LLVMValueRef val)
{
	const char *name = LLVMGetValueName(val);
	LLVMTypeRef dtype = symbol_type(ctype);

	if (LLVMGetTypeKind(LLVMTypeOf(val)) == LLVMPointerTypeKind) {
		LLVMTypeRef dtype = LLVMIntType(bits_in_pointer);
		val = LLVMBuildPtrToInt(fn->builder, val, dtype, name);
	}
	if (ctype && is_int_type(ctype)) {
		val = LLVMBuildIntCast(fn->builder, val, dtype, name);
	}
	return val;
}

static LLVMValueRef value_to_pvalue(struct function *fn, struct symbol *ctype, LLVMValueRef val)
{
	const char *name = LLVMGetValueName(val);
	LLVMTypeRef dtype = symbol_type(ctype);

	assert(is_ptr_type(ctype));
	switch (LLVMGetTypeKind(LLVMTypeOf(val))) {
	case LLVMIntegerTypeKind:
		val = LLVMBuildIntToPtr(fn->builder, val, dtype, name);
		break;
	case LLVMPointerTypeKind:
		val = LLVMBuildBitCast(fn->builder, val, dtype, name);
		break;
	default:
		break;
	}
	return val;
}

static LLVMValueRef adjust_type(struct function *fn, struct symbol *ctype, LLVMValueRef val)
{
	if (is_int_type(ctype))
		return value_to_ivalue(fn, ctype, val);
	if (is_ptr_type(ctype))
		return value_to_pvalue(fn, ctype, val);
	return val;
}

/*
 * Get the LLVMValue corresponding to the pseudo
 * and force the type corresponding to ctype.
 */
static LLVMValueRef get_operand(struct function *fn, struct symbol *ctype, pseudo_t pseudo)
{
	LLVMValueRef target = pseudo_to_value(fn, ctype, pseudo);
	return adjust_type(fn, ctype, target);
}

/*
 * Get the LLVMValue corresponding to the pseudo
 * and force the type corresponding to ctype but
 * map all pointers to intptr_t.
 */
static LLVMValueRef get_ioperand(struct function *fn, struct symbol *ctype, pseudo_t pseudo)
{
	LLVMValueRef target = pseudo_to_value(fn, ctype, pseudo);
	return value_to_ivalue(fn, ctype, target);
}

static LLVMValueRef calc_gep(LLVMBuilderRef builder, LLVMValueRef base, LLVMValueRef off)
{
	LLVMTypeRef type = LLVMTypeOf(base);
	unsigned int as = LLVMGetPointerAddressSpace(type);
	LLVMTypeRef bytep = LLVMPointerType(LLVMInt8Type(), as);
	LLVMValueRef addr;
	const char *name = LLVMGetValueName(off);

	/* convert base to char* type */
	base = LLVMBuildPointerCast(builder, base, bytep, name);
	/* addr = base + off */
	addr = LLVMBuildInBoundsGEP(builder, base, &off, 1, name);
	/* convert back to the actual pointer type */
	addr = LLVMBuildPointerCast(builder, addr, type, name);
	return addr;
}

static LLVMRealPredicate translate_fop(int opcode)
{
	static const LLVMRealPredicate trans_tbl[] = {
		[OP_FCMP_ORD]	= LLVMRealORD,
		[OP_FCMP_OEQ]	= LLVMRealOEQ,
		[OP_FCMP_ONE]	= LLVMRealONE,
		[OP_FCMP_OLE]	= LLVMRealOLE,
		[OP_FCMP_OGE]	= LLVMRealOGE,
		[OP_FCMP_OLT]	= LLVMRealOLT,
		[OP_FCMP_OGT]	= LLVMRealOGT,
		[OP_FCMP_UEQ]	= LLVMRealUEQ,
		[OP_FCMP_UNE]	= LLVMRealUNE,
		[OP_FCMP_ULE]	= LLVMRealULE,
		[OP_FCMP_UGE]	= LLVMRealUGE,
		[OP_FCMP_ULT]	= LLVMRealULT,
		[OP_FCMP_UGT]	= LLVMRealUGT,
		[OP_FCMP_UNO]	= LLVMRealUNO,
	};

	return trans_tbl[opcode];
}

static LLVMIntPredicate translate_op(int opcode)
{
	static const LLVMIntPredicate trans_tbl[] = {
		[OP_SET_EQ]	= LLVMIntEQ,
		[OP_SET_NE]	= LLVMIntNE,
		[OP_SET_LE]	= LLVMIntSLE,
		[OP_SET_GE]	= LLVMIntSGE,
		[OP_SET_LT]	= LLVMIntSLT,
		[OP_SET_GT]	= LLVMIntSGT,
		[OP_SET_B]	= LLVMIntULT,
		[OP_SET_A]	= LLVMIntUGT,
		[OP_SET_BE]	= LLVMIntULE,
		[OP_SET_AE]	= LLVMIntUGE,
	};

	return trans_tbl[opcode];
}

static void output_op_binary(struct function *fn, struct instruction *insn)
{
	LLVMValueRef lhs, rhs, target;
	char target_name[64];

	lhs = get_ioperand(fn, insn->type, insn->src1);
	rhs = get_ioperand(fn, insn->type, insn->src2);

	pseudo_name(insn->target, target_name);

	switch (insn->opcode) {
	/* Binary */
	case OP_ADD:
		target = LLVMBuildAdd(fn->builder, lhs, rhs, target_name);
		break;
	case OP_SUB:
		target = LLVMBuildSub(fn->builder, lhs, rhs, target_name);
		break;
	case OP_MUL:
		target = LLVMBuildMul(fn->builder, lhs, rhs, target_name);
		break;
	case OP_DIVU:
		target = LLVMBuildUDiv(fn->builder, lhs, rhs, target_name);
		break;
	case OP_DIVS:
		assert(!is_float_type(insn->type));
		target = LLVMBuildSDiv(fn->builder, lhs, rhs, target_name);
		break;
	case OP_MODU:
		assert(!is_float_type(insn->type));
		target = LLVMBuildURem(fn->builder, lhs, rhs, target_name);
		break;
	case OP_MODS:
		assert(!is_float_type(insn->type));
		target = LLVMBuildSRem(fn->builder, lhs, rhs, target_name);
		break;
	case OP_SHL:
		assert(!is_float_type(insn->type));
		target = LLVMBuildShl(fn->builder, lhs, rhs, target_name);
		break;
	case OP_LSR:
		assert(!is_float_type(insn->type));
		target = LLVMBuildLShr(fn->builder, lhs, rhs, target_name);
		break;
	case OP_ASR:
		assert(!is_float_type(insn->type));
		target = LLVMBuildAShr(fn->builder, lhs, rhs, target_name);
		break;

	/* floating-point */
	case OP_FADD:
		target = LLVMBuildFAdd(fn->builder, lhs, rhs, target_name);
		break;
	case OP_FSUB:
		target = LLVMBuildFSub(fn->builder, lhs, rhs, target_name);
		break;
	case OP_FMUL:
		target = LLVMBuildFMul(fn->builder, lhs, rhs, target_name);
		break;
	case OP_FDIV:
		target = LLVMBuildFDiv(fn->builder, lhs, rhs, target_name);
		break;
	
	/* Logical */
	case OP_AND:
		assert(!is_float_type(insn->type));
		target = LLVMBuildAnd(fn->builder, lhs, rhs, target_name);
		break;
	case OP_OR:
		assert(!is_float_type(insn->type));
		target = LLVMBuildOr(fn->builder, lhs, rhs, target_name);
		break;
	case OP_XOR:
		assert(!is_float_type(insn->type));
		target = LLVMBuildXor(fn->builder, lhs, rhs, target_name);
		break;
	default:
		assert(0);
		break;
	}

	target = adjust_type(fn, insn->type, target);
	insn->target->priv = target;
}

static void output_op_compare(struct function *fn, struct instruction *insn)
{
	LLVMValueRef lhs, rhs, target;
	char target_name[64];

	lhs = pseudo_to_value(fn, NULL, insn->src1);
	if (insn->src2->type == PSEUDO_VAL)
		rhs = constant_value(insn->src2->value, LLVMTypeOf(lhs));
	else
		rhs = pseudo_to_value(fn, NULL, insn->src2);
	if (!rhs)
		rhs = LLVMGetUndef(symbol_type(insn->type));

	pseudo_name(insn->target, target_name);

	LLVMTypeRef dst_type = insn_symbol_type(insn);

	switch  (LLVMGetTypeKind(LLVMTypeOf(lhs))) {
	case LLVMPointerTypeKind:
		lhs = value_to_pvalue(fn, &ptr_ctype, lhs);
		rhs = value_to_pvalue(fn, &ptr_ctype, rhs);
		/* fall through */

	case LLVMIntegerTypeKind: {
		LLVMIntPredicate op = translate_op(insn->opcode);

		if (LLVMGetTypeKind(LLVMTypeOf(rhs)) == LLVMPointerTypeKind) {
			LLVMTypeRef ltype = LLVMTypeOf(lhs);
			rhs = LLVMBuildPtrToInt(fn->builder, rhs, ltype, "");
		}
		target = LLVMBuildICmp(fn->builder, op, lhs, rhs, target_name);
		break;
	}
	case LLVMHalfTypeKind:
	case LLVMFloatTypeKind:
	case LLVMDoubleTypeKind:
	case LLVMX86_FP80TypeKind:
	case LLVMFP128TypeKind:
	case LLVMPPC_FP128TypeKind: {
		LLVMRealPredicate op = translate_fop(insn->opcode);

		target = LLVMBuildFCmp(fn->builder, op, lhs, rhs, target_name);
		break;
	}
	default:
		assert(0);
	}

	target = LLVMBuildZExt(fn->builder, target, dst_type, target_name);

	insn->target->priv = target;
}

static void output_op_ret(struct function *fn, struct instruction *insn)
{
	pseudo_t pseudo = insn->src;

	if (pseudo && pseudo != VOID) {
		LLVMValueRef result = get_operand(fn, insn->type, pseudo);
		LLVMBuildRet(fn->builder, result);
	} else
		LLVMBuildRetVoid(fn->builder);
}

static LLVMValueRef calc_memop_addr(struct function *fn, struct instruction *insn)
{
	LLVMTypeRef int_type, addr_type;
	LLVMValueRef src, off, addr;
	unsigned int as;

	/* int type large enough to hold a pointer */
	int_type = LLVMIntType(bits_in_pointer);
	off = LLVMConstInt(int_type, insn->offset, 0);

	/* convert src to the effective pointer type */
	src = pseudo_to_value(fn, insn->type, insn->src);
	as = LLVMGetPointerAddressSpace(LLVMTypeOf(src));
	addr_type = LLVMPointerType(insn_symbol_type(insn), as);
	src = LLVMBuildPointerCast(fn->builder, src, addr_type, LLVMGetValueName(src));

	/* addr = src + off */
	addr = calc_gep(fn->builder, src, off);
	return addr;
}


static void output_op_load(struct function *fn, struct instruction *insn)
{
	LLVMValueRef addr, target;
	char name[MAX_PSEUDO_NAME];

	addr = calc_memop_addr(fn, insn);

	/* perform load */
	pseudo_name(insn->target, name);
	target = LLVMBuildLoad(fn->builder, addr, name);

	insn->target->priv = target;
}

static void output_op_store(struct function *fn, struct instruction *insn)
{
	LLVMValueRef addr, target_in;

	addr = calc_memop_addr(fn, insn);

	target_in = pseudo_to_rvalue(fn, insn->type, insn->target);

	/* perform store */
	LLVMBuildStore(fn->builder, target_in, addr);
}

static LLVMValueRef bool_value(struct function *fn, LLVMValueRef value)
{
	if (LLVMTypeOf(value) != LLVMInt1Type())
		value = LLVMBuildIsNotNull(fn->builder, value, LLVMGetValueName(value));

	return value;
}

static void output_op_cbr(struct function *fn, struct instruction *br)
{
	LLVMValueRef cond = bool_value(fn,
			pseudo_to_value(fn, NULL, br->cond));

	LLVMBuildCondBr(fn->builder, cond,
			br->bb_true->priv,
			br->bb_false->priv);
}

static void output_op_br(struct function *fn, struct instruction *br)
{
	LLVMBuildBr(fn->builder, br->bb_true->priv);
}

static void output_op_sel(struct function *fn, struct instruction *insn)
{
	LLVMValueRef target, src1, src2, src3;
	char name[MAX_PSEUDO_NAME];

	src1 = bool_value(fn, pseudo_to_value(fn, NULL, insn->src1));
	src2 = get_operand(fn, insn->type, insn->src2);
	src3 = get_operand(fn, insn->type, insn->src3);

	pseudo_name(insn->target, name);
	target = LLVMBuildSelect(fn->builder, src1, src2, src3, name);

	insn->target->priv = adjust_type(fn, insn->type, target);
}

static void output_op_switch(struct function *fn, struct instruction *insn)
{
	LLVMValueRef sw_val, target;
	struct basic_block *def = NULL;
	struct multijmp *jmp;
	int n_jmp = 0;

	FOR_EACH_PTR(insn->multijmp_list, jmp) {
		if (jmp->begin <= jmp->end) {
			n_jmp += (jmp->end - jmp->begin) + 1;
		} else					/* default case */
			def = jmp->target;
	} END_FOR_EACH_PTR(jmp);

	sw_val = get_ioperand(fn, insn->type, insn->cond);
	target = LLVMBuildSwitch(fn->builder, sw_val,
				 def ? def->priv : NULL, n_jmp);

	FOR_EACH_PTR(insn->multijmp_list, jmp) {
		long long val;

		for (val = jmp->begin; val <= jmp->end; val++) {
			LLVMValueRef Val = val_to_value(val, insn->type);
			LLVMAddCase(target, Val, jmp->target->priv);
		}
	} END_FOR_EACH_PTR(jmp);
}

static void output_op_call(struct function *fn, struct instruction *insn)
{
	LLVMValueRef target, func;
	struct symbol *ctype;
	int n_arg = 0, i;
	struct pseudo *arg;
	LLVMValueRef *args;
	char name[64];

	n_arg = pseudo_list_size(insn->arguments);
	args = calloc(n_arg, sizeof(LLVMValueRef));

	PREPARE_PTR_LIST(insn->fntypes, ctype);
	if (insn->func->type == PSEUDO_REG || insn->func->type == PSEUDO_PHI)
		func = get_operand(fn, ctype, insn->func);
	else
		func = pseudo_to_value(fn, ctype, insn->func);
	i = 0;
	FOR_EACH_PTR(insn->arguments, arg) {
		NEXT_PTR_LIST(ctype);
		args[i++] = pseudo_to_rvalue(fn, ctype, arg);
	} END_FOR_EACH_PTR(arg);
	FINISH_PTR_LIST(ctype);

	pseudo_name(insn->target, name);
	target = LLVMBuildCall(fn->builder, func, args, n_arg, name);

	insn->target->priv = target;
}

static void output_op_phisrc(struct function *fn, struct instruction *insn)
{
	LLVMValueRef v;
	struct instruction *phi;

	assert(insn->target->priv == NULL);

	/* target = src */
	v = get_operand(fn, insn->type, insn->phi_src);

	FOR_EACH_PTR(insn->phi_users, phi) {
		LLVMValueRef load, ptr;

		assert(phi->opcode == OP_PHI);
		/* phi must be load from alloca */
		load = phi->target->priv;
		assert(LLVMGetInstructionOpcode(load) == LLVMLoad);
		ptr = LLVMGetOperand(load, 0);
		/* store v to alloca */
		LLVMBuildStore(fn->builder, v, ptr);
	} END_FOR_EACH_PTR(phi);
}

static void output_op_phi(struct function *fn, struct instruction *insn)
{
	LLVMValueRef load = insn->target->priv;

	/* forward load */
	assert(LLVMGetInstructionOpcode(load) == LLVMLoad);
	/* forward load has no parent block */
	assert(!LLVMGetInstructionParent(load));
	/* finalize load in current block  */
	LLVMInsertIntoBuilder(fn->builder, load);
}

static void output_op_ptrcast(struct function *fn, struct instruction *insn)
{
	LLVMValueRef src, target;
	LLVMTypeRef dtype;
	struct symbol *otype = insn->orig_type;
	LLVMOpcode op;
	char target_name[64];

	src = get_operand(fn, otype, insn->src);
	pseudo_name(insn->target, target_name);

	dtype = symbol_type(insn->type);
	switch (insn->opcode) {
	case OP_UTPTR:
	case OP_SEXT:			// FIXME
		assert(is_int_type(otype));
		assert(is_ptr_type(insn->type));
		op = LLVMIntToPtr;
		break;
	case OP_PTRTU:
		assert(is_ptr_type(otype));
		assert(is_int_type(insn->type));
		op = LLVMPtrToInt;
		break;
	case OP_PTRCAST:
	case OP_ZEXT:			// FIXME
		assert(is_ptr_type(otype));
		assert(is_ptr_type(insn->type));
		op = LLVMBitCast;
		break;
	default:
		assert(0);
	}

	target = LLVMBuildCast(fn->builder, op, src, dtype, target_name);
	insn->target->priv = target;
}

static void output_op_cast(struct function *fn, struct instruction *insn, LLVMOpcode op)
{
	LLVMValueRef src, target;
	LLVMTypeRef dtype;
	struct symbol *otype = insn->orig_type;
	char target_name[64];

	if (is_ptr_type(insn->type))	// cast to void* is OP_CAST ...
		return output_op_ptrcast(fn, insn);

	assert(is_int_type(insn->type));

	src = get_operand(fn, otype, insn->src);
	pseudo_name(insn->target, target_name);

	dtype = symbol_type(insn->type);
	if (is_ptr_type(otype)) {
		op = LLVMPtrToInt;
	} else if (is_float_type(otype)) {
		assert(op == LLVMFPToUI || op == LLVMFPToSI);
	} else if (is_int_type(otype)) {
		unsigned int width = otype->bit_size;
		if (insn->size < width)
			op = LLVMTrunc;
		else if (insn->size == width)
			op = LLVMBitCast;
	} else {
		assert(0);
	}

	target = LLVMBuildCast(fn->builder, op, src, dtype, target_name);
	insn->target->priv = target;
}

static void output_op_fpcast(struct function *fn, struct instruction *insn)
{
	LLVMTypeRef dtype = symbol_type(insn->type);
	LLVMValueRef src, target;
	struct symbol *otype = insn->orig_type;
	char name[64];

	assert(is_float_type(insn->type));

	pseudo_name(insn->target, name);
	src = get_operand(fn, otype, insn->src);
	switch (insn->opcode) {
	case OP_FCVTF:
		target = LLVMBuildFPCast(fn->builder, src, dtype, name);
		break;
	case OP_SCVTF:
		target = LLVMBuildSIToFP(fn->builder, src, dtype, name);
		break;
	case OP_UCVTF:
		target = LLVMBuildUIToFP(fn->builder, src, dtype, name);
		break;
	default:
		assert(0);
	}
	insn->target->priv = target;
}

static void output_op_setval(struct function *fn, struct instruction *insn)
{
	struct expression *val = insn->val;
	LLVMValueRef target;

	switch (val->type) {
	case EXPR_LABEL:
		target = LLVMBlockAddress(fn->fn, val->symbol->bb_target->priv);
		break;
	default:
		assert(0);
	}

	insn->target->priv = target;
}

static void output_op_setfval(struct function *fn, struct instruction *insn)
{
	LLVMTypeRef dtype = symbol_type(insn->type);
	LLVMValueRef target;

	target = LLVMConstReal(dtype, insn->fvalue);
	insn->target->priv = target;
}

static void output_insn(struct function *fn, struct instruction *insn)
{
	switch (insn->opcode) {
	case OP_RET:
		output_op_ret(fn, insn);
		break;
	case OP_BR:
		output_op_br(fn, insn);
		break;
	case OP_CBR:
		output_op_cbr(fn, insn);
		break;
	case OP_SYMADDR:
		assert(0);
		break;
	case OP_SETVAL:
		output_op_setval(fn, insn);
		break;
	case OP_SETFVAL:
		output_op_setfval(fn, insn);
		break;
	case OP_SWITCH:
		output_op_switch(fn, insn);
		break;
	case OP_COMPUTEDGOTO:
		assert(0);
		break;
	case OP_PHISOURCE:
		output_op_phisrc(fn, insn);
		break;
	case OP_PHI:
		output_op_phi(fn, insn);
		break;
	case OP_LOAD:
		output_op_load(fn, insn);
		break;
	case OP_STORE:
		output_op_store(fn, insn);
		break;
	case OP_INLINED_CALL:
		break;
	case OP_CALL:
		output_op_call(fn, insn);
		break;
	case OP_ZEXT:
		output_op_cast(fn, insn, LLVMZExt);
		break;
	case OP_SEXT:
		output_op_cast(fn, insn, LLVMSExt);
		break;
	case OP_TRUNC:
		output_op_cast(fn, insn, LLVMTrunc);
		break;
	case OP_FCVTU:
		output_op_cast(fn, insn, LLVMFPToUI);
		break;
	case OP_FCVTS:
		output_op_cast(fn, insn, LLVMFPToSI);
		break;
	case OP_UCVTF: case OP_SCVTF:
	case OP_FCVTF:
		output_op_fpcast(fn, insn);
		break;
	case OP_UTPTR:
	case OP_PTRTU:
	case OP_PTRCAST:
		output_op_ptrcast(fn, insn);
		break;
	case OP_BINARY ... OP_BINARY_END:
		output_op_binary(fn, insn);
		break;
	case OP_FPCMP ... OP_BINCMP_END:
		output_op_compare(fn, insn);
		break;
	case OP_SEL:
		output_op_sel(fn, insn);
		break;
	case OP_SLICE:
		assert(0);
		break;
	case OP_NOT: {
		LLVMValueRef src, target;
		char target_name[64];

		src = pseudo_to_value(fn, insn->type, insn->src);

		pseudo_name(insn->target, target_name);

		target = LLVMBuildNot(fn->builder, src, target_name);

		insn->target->priv = target;
		break;
	}
	case OP_FNEG:
	case OP_NEG: {
		LLVMValueRef src, target;
		char target_name[64];

		src = pseudo_to_value(fn, insn->type, insn->src);

		pseudo_name(insn->target, target_name);

		if (insn->opcode == OP_FNEG)
			target = LLVMBuildFNeg(fn->builder, src, target_name);
		else
			target = LLVMBuildNeg(fn->builder, src, target_name);

		insn->target->priv = target;
		break;
	}
	case OP_CONTEXT:
		assert(0);
		break;
	case OP_RANGE:
		assert(0);
		break;
	case OP_NOP:
		assert(0);
		break;
	case OP_DEATHNOTE:
		break;
	case OP_ASM:
		assert(0);
		break;
	case OP_COPY:
		assert(0);
		break;
	default:
		break;
	}
}

static void output_bb(struct function *fn, struct basic_block *bb)
{
	struct instruction *insn;

	FOR_EACH_PTR(bb->insns, insn) {
		if (!insn->bb)
			continue;

		output_insn(fn, insn);
	}
	END_FOR_EACH_PTR(insn);
}

#define MAX_ARGS	64

static void output_fn(LLVMModuleRef module, struct entrypoint *ep)
{
	struct symbol *sym = ep->name;
	struct symbol *base_type = sym->ctype.base_type;
	struct function function = { .module = module };
	struct basic_block *bb;
	int nr_args = 0;
	int i;

	function.fn = get_sym_value(module, sym);
	LLVMSetFunctionCallConv(function.fn, LLVMCCallConv);
	LLVMSetLinkage(function.fn, function_linkage(sym));

	function.builder = LLVMCreateBuilder();

	/* give a name to each argument */
	nr_args = symbol_list_size(base_type->arguments);
	for (i = 0; i < nr_args; i++) {
		char name[MAX_PSEUDO_NAME];
		LLVMValueRef arg;

		arg = LLVMGetParam(function.fn, i);
		snprintf(name, sizeof(name), "ARG%d.", i+1);
		LLVMSetValueName(arg, name);
	}

	/* create the BBs */
	FOR_EACH_PTR(ep->bbs, bb) {
		static int nr_bb;
		LLVMBasicBlockRef bbr;
		char bbname[32];
		struct instruction *insn;

		sprintf(bbname, "L%d", nr_bb++);
		bbr = LLVMAppendBasicBlock(function.fn, bbname);

		bb->priv = bbr;

		/* allocate alloca for each phi */
		FOR_EACH_PTR(bb->insns, insn) {
			LLVMBasicBlockRef entrybbr;
			LLVMTypeRef phi_type;
			LLVMValueRef ptr;

			if (!insn->bb || insn->opcode != OP_PHI)
				continue;
			/* insert alloca into entry block */
			entrybbr = LLVMGetEntryBasicBlock(function.fn);
			LLVMPositionBuilderAtEnd(function.builder, entrybbr);
			phi_type = insn_symbol_type(insn);
			ptr = LLVMBuildAlloca(function.builder, phi_type, "");
			/* emit forward load for phi */
			LLVMClearInsertionPosition(function.builder);
			insn->target->priv = LLVMBuildLoad(function.builder, ptr, "phi");
		} END_FOR_EACH_PTR(insn);
	}
	END_FOR_EACH_PTR(bb);

	FOR_EACH_PTR(ep->bbs, bb) {
		LLVMPositionBuilderAtEnd(function.builder, bb->priv);

		output_bb(&function, bb);
	}
	END_FOR_EACH_PTR(bb);
}

static LLVMValueRef output_data(LLVMModuleRef module, struct symbol *sym)
{
	struct expression *initializer = sym->initializer;
	LLVMValueRef initial_value;
	LLVMValueRef data;
	const char *name;

	if (initializer) {
		switch (initializer->type) {
		case EXPR_VALUE:
			initial_value = LLVMConstInt(symbol_type(sym), initializer->value, 1);
			break;
		case EXPR_FVALUE:
			initial_value = LLVMConstReal(symbol_type(sym), initializer->fvalue);
			break;
		case EXPR_SYMBOL: {
			struct symbol *sym = initializer->symbol;

			initial_value = LLVMGetNamedGlobal(module, show_ident(sym->ident));
			if (!initial_value)
				initial_value = output_data(module, sym);
			break;
		}
		case EXPR_STRING: {
			const char *s = initializer->string->data;

			initial_value = LLVMConstString(strdup(s), strlen(s) + 1, true);
			break;
		}
		default:
			warning(initializer->pos, "can't initialize type: %s", show_typename(sym));
			initial_value = NULL;
			break;
		}
	} else {
		LLVMTypeRef type = symbol_type(sym);

		initial_value = LLVMConstNull(type);
	}

	if (!initial_value)
		return NULL;

	name = sym->ident ? show_ident(sym->ident) : "" ;

	data = LLVMAddGlobal(module, LLVMTypeOf(initial_value), name);

	LLVMSetLinkage(data, data_linkage(sym));
	if (sym->ctype.modifiers & MOD_CONST)
		LLVMSetGlobalConstant(data, 1);
	if (sym->ctype.modifiers & MOD_TLS)
		LLVMSetThreadLocal(data, 1);
	if (sym->ctype.alignment)
		LLVMSetAlignment(data, sym->ctype.alignment);

	if (!(sym->ctype.modifiers & MOD_EXTERN))
		LLVMSetInitializer(data, initial_value);

	return data;
}

static int is_prototype(struct symbol *sym)
{
	if (sym->type == SYM_NODE)
		sym = sym->ctype.base_type;
	return sym && sym->type == SYM_FN && !sym->stmt;
}

static int compile(LLVMModuleRef module, struct symbol_list *list)
{
	struct symbol *sym;

	FOR_EACH_PTR(list, sym) {
		struct entrypoint *ep;
		expand_symbol(sym);

		if (is_prototype(sym)) {
			// this will do the LLVMAddFunction() we want
			get_sym_value(module, sym);
			continue;
		}

		ep = linearize_symbol(sym);
		if (ep)
			output_fn(module, ep);
		else
			output_data(module, sym);
	}
	END_FOR_EACH_PTR(sym);

	return 0;
}

#ifndef LLVM_DEFAULT_TARGET_TRIPLE
#define LLVM_DEFAULT_TARGET_TRIPLE LLVM_HOSTTRIPLE
#endif

#define X86_LINUX_LAYOUT \
	"e-p:32:32:32-i1:8:8-i8:8:8-i16:16:16-i32:32:32-" \
	"i64:32:64-f32:32:32-f64:32:64-v64:64:64-v128:128:128-" \
	"a0:0:64-f80:32:32-n8:16:32-S128"

#define X86_64_LINUX_LAYOUT \
	"e-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-" \
	"i64:64:64-f32:32:32-f64:64:64-v64:64:64-v128:128:128-" \
	"a0:0:64-s0:64:64-f80:128:128-n8:16:32:64-S128"

static void set_target(LLVMModuleRef module)
{
	char target[] = LLVM_DEFAULT_TARGET_TRIPLE;
	const char *arch, *vendor, *os, *env, *layout = NULL;
	char triple[256];

	arch = strtok(target, "-");
	vendor = strtok(NULL, "-");
	os = strtok(NULL, "-");
	env = strtok(NULL, "-");

	if (!os)
		return;
	if (!env)
		env = "unknown";

	if (!strcmp(arch, "x86_64") && !strcmp(os, "linux")) {
		if (arch_m64) {
			layout = X86_64_LINUX_LAYOUT;
		} else {
			arch = "i386";
			layout = X86_LINUX_LAYOUT;
		}
	}

	/* unsupported target */
	if (!layout)
		return;

	snprintf(triple, sizeof(triple), "%s-%s-%s-%s", arch, vendor, os, env);
	LLVMSetTarget(module, triple);
	LLVMSetDataLayout(module, layout);
}

int main(int argc, char **argv)
{
	struct string_list *filelist = NULL;
	struct symbol_list *symlist;
	LLVMModuleRef module;
	char *file;

	symlist = sparse_initialize(argc, argv, &filelist);

	module = LLVMModuleCreateWithName("sparse");
	set_target(module);

	compile(module, symlist);

	/* need ->phi_users */
	dbg_dead = 1;
	FOR_EACH_PTR(filelist, file) {
		symlist = sparse(file);
		if (die_if_error)
			return 1;
		compile(module, symlist);
	} END_FOR_EACH_PTR(file);

	LLVMVerifyModule(module, LLVMPrintMessageAction, NULL);

	LLVMWriteBitcodeToFD(module, STDOUT_FILENO, 0, 0);

	LLVMDisposeModule(module);

	report_stats();
	return 0;
}
