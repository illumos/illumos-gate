#ifndef OPCODE_H
#define OPCODE_H

#include "symbol.h"

enum opcode {
#define OPCODE(OP,NG,SW,TF,N,FL)  OP_##OP,
#define OPCODE_RANGE(OP,S,E)	OP_##OP = OP_##S, OP_##OP##_END = OP_##E,
#include "opcode.def"
#undef  OPCODE
#undef  OPCODE_RANGE
	OP_LAST,			/* keep this one last! */
};

extern const struct opcode_table {
	int	negate:8;
	int	swap:8;
	int	to_float:8;
	unsigned int arity:2;
	unsigned int flags:6;
#define			OPF_NONE	0
#define			OPF_TARGET	(1 << 0)
} opcode_table[];


static inline int opcode_float(int opcode, struct symbol *type)
{
	if (!type || !is_float_type(type))
		return opcode;
	return opcode_table[opcode].to_float;
}

#endif
