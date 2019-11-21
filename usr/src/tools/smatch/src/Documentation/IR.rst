.. default-domain:: ir

Sparse's Intermediate Representation
====================================

Instructions
~~~~~~~~~~~~

This document briefly describes which field of struct instruction is
used by which operation.

Some of those fields are used by almost all instructions,
some others are specific to only one or a few instructions.
The common ones are:

* .src1, .src2, .src3: (pseudo_t) operands of binops or ternary ops.
* .src: (pseudo_t) operand of unary ops (alias for .src1).
* .target: (pseudo_t) result of unary, binary & ternary ops, is
  sometimes used otherwise by some others instructions.
* .cond: (pseudo_t) input operands for condition (alias .src/.src1)
* .type: (symbol*) usually the type of .result, sometimes of the operands

Terminators
-----------
.. op:: OP_RET
	Return from subroutine.

	* .src : returned value (NULL if void)
	* .type: type of .src

.. op:: OP_BR
	Unconditional branch

	* .bb_true: destination basic block

.. op:: OP_CBR
	Conditional branch

	* .cond: condition
	* .type: type of .cond, must be an integral type
	* .bb_true, .bb_false: destination basic blocks

.. op:: OP_SWITCH
	Switch / multi-branch

	* .cond: condition
	* .type: type of .cond, must be an integral type
	* .multijmp_list: pairs of case-value - destination basic block

.. op:: OP_COMPUTEDGOTO
	Computed goto / branch to register

	* .src: address to branch to (void*)
	* .multijmp_list: list of possible destination basic blocks

Arithmetic binops
-----------------
They all follow the same signature:
	* .src1, .src1: operands (types must be compatible with .target)
	* .target: result of the operation (must be an integral type)
	* .type: type of .target

.. op:: OP_ADD
	Integer addition.

.. op:: OP_SUB
	Integer subtraction.

.. op:: OP_MUL
	Integer multiplication.

.. op:: OP_DIVU
	Integer unsigned division.

.. op:: OP_DIVS
	Integer signed division.

.. op:: OP_MODU
	Integer unsigned remainder.

.. op:: OP_MODS
	Integer signed remainder.

.. op:: OP_SHL
	Shift left (integer only)

.. op:: OP_LSR
	Logical Shift right (integer only)

.. op:: OP_ASR
	Arithmetic Shift right (integer only)

Floating-point binops
---------------------
They all follow the same signature:
	* .src1, .src1: operands (types must be compatible with .target)
	* .target: result of the operation (must be a floating-point type)
	* .type: type of .target

.. op:: OP_FADD
	Floating-point addition.

.. op:: OP_FSUB
	Floating-point subtraction.

.. op:: OP_FMUL
	Floating-point multiplication.

.. op:: OP_FDIV
	Floating-point division.

Logical ops
-----------
They all follow the same signature:
	* .src1, .src2: operands (types must be compatible with .target)
	* .target: result of the operation
	* .type: type of .target, must be an integral type

.. op:: OP_AND
	Logical AND

.. op:: OP_OR
	Logical OR

.. op:: OP_XOR
	Logical XOR

Integer compares
----------------
They all have the following signature:
	* .src1, .src2: operands (types must be compatible)
	* .target: result of the operation (0/1 valued integer)
	* .type: type of .target, must be an integral type

.. op:: OP_SET_EQ
	Compare equal.

.. op:: OP_SET_NE
	Compare not-equal.

.. op:: OP_SET_LE
	Compare less-than-or-equal (signed).

.. op:: OP_SET_GE
	Compare greater-than-or-equal (signed).

.. op:: OP_SET_LT
	Compare less-than (signed).

.. op:: OP_SET_GT
	Compare greater-than (signed).

.. op:: OP_SET_B
	Compare less-than (unsigned).

.. op:: OP_SET_A
	Compare greater-than (unsigned).

.. op:: OP_SET_BE
	Compare less-than-or-equal (unsigned).

.. op:: OP_SET_AE
	Compare greater-than-or-equal (unsigned).

Floating-point compares
-----------------------
They all have the same signature as the integer compares.

The usual 6 operations exist in two versions: 'ordered' and
'unordered'. These operations first check if any operand is a
NaN and if it is the case the ordered compares return false
and then unordered return true, otherwise the result of the
comparison, now guaranteed to be done on non-NaNs, is returned.

.. op:: OP_FCMP_OEQ
	Floating-point compare ordered equal

.. op:: OP_FCMP_ONE
	Floating-point compare ordered not-equal

.. op:: OP_FCMP_OLE
	Floating-point compare ordered less-than-or-equal

.. op:: OP_FCMP_OGE
	Floating-point compare ordered greater-or-equal

.. op:: OP_FCMP_OLT
	Floating-point compare ordered less-than

.. op:: OP_FCMP_OGT
	Floating-point compare ordered greater-than


.. op:: OP_FCMP_UEQ
	Floating-point compare unordered equal

.. op:: OP_FCMP_UNE
	Floating-point compare unordered not-equal

.. op:: OP_FCMP_ULE
	Floating-point compare unordered less-than-or-equal

.. op:: OP_FCMP_UGE
	Floating-point compare unordered greater-or-equal

.. op:: OP_FCMP_ULT
	Floating-point compare unordered less-than

.. op:: OP_FCMP_UGT
	Floating-point compare unordered greater-than


.. op:: OP_FCMP_ORD
	Floating-point compare ordered: return true if both operands are ordered
	(none of the operands are a NaN) and false otherwise.

.. op:: OP_FCMP_UNO
	Floating-point compare unordered: return false if no operands is ordered
	and true otherwise.

Unary ops
---------
.. op:: OP_NOT
	Logical not.

	* .src: operand (type must be compatible with .target)
	* .target: result of the operation
	* .type: type of .target, must be an integral type

.. op:: OP_NEG
	Integer negation.

	* .src: operand (type must be compatible with .target)
	* .target: result of the operation (must be an integral type)
	* .type: type of .target

.. op:: OP_FNEG
	Floating-point negation.

	* .src: operand (type must be compatible with .target)
	* .target: result of the operation (must be a floating-point type)
	* .type: type of .target

.. op:: OP_SYMADDR
	Create a pseudo corresponding to the address of a symbol.

	* .src: input symbol (must be a PSEUDO_SYM)
	* .target: symbol's address

.. op:: OP_COPY
	Copy (only needed after out-of-SSA).

	* .src: operand (type must be compatible with .target)
	* .target: result of the operation
	* .type: type of .target

Type conversions
----------------
They all have the following signature:
	* .src: source value
	* .orig_type: type of .src
	* .target: result value
	* .type: type of .target

Currently, a cast to a void pointer is treated like a cast to
an unsigned integer of the same size.

.. op:: OP_TRUNC
	Cast from integer to an integer of a smaller size.

.. op:: OP_SEXT
	Cast from integer to an integer of a bigger size with sign extension.

.. op:: OP_ZEXT
	Cast from integer to an integer of a bigger size with zero extension.

.. op:: OP_UTPTR
	Cast from pointer-sized unsigned integer to pointer type.

.. op:: OP_PTRTU
	Cast from pointer type to pointer-sized unsigned integer.

.. op:: OP_PTRCAST
	Cast between pointers.

.. op:: OP_FCVTU
	Conversion from float type to unsigned integer.

.. op:: OP_FCVTS
	Conversion from float type to signed integer.

.. op:: OP_UCVTF
	Conversion from unsigned integer to float type.

.. op:: OP_SCVTF
	Conversion from signed integer to float type.

.. op:: OP_FCVTF
	Conversion between float types.

Ternary ops
-----------
.. op:: OP_SEL
	* .src1: condition, must be of integral type
	* .src2, .src3: operands (types must be compatible with .target)
	* .target: result of the operation
	* .type: type of .target

.. op:: OP_RANGE
	Range/bounds checking (only used for an unused sparse extension).

	* .src1: value to be checked
	* .src2, src3: bound of the value (must be constants?)
	* .type: type of .src[123]?

Memory ops
----------
.. op:: OP_LOAD
	Load.

	* .src: base address to load from
	* .offset: address offset
	* .target: loaded value
	* .type: type of .target

.. op:: OP_STORE
	Store.

	* .src: base address to store to
	* .offset: address offset
	* .target: value to be stored
	* .type: type of .target

Others
------
.. op:: OP_SETFVAL
	Create a pseudo corresponding to a floating-point literal.

	* .fvalue: the literal's value (long double)
	* .target: the corresponding pseudo
	* .type: type of the literal & .target

.. op:: OP_SETVAL
	Create a pseudo corresponding to a string literal or a label-as-value.
	The value is given as an expression EXPR_STRING or EXPR_LABEL.

	* .val: (expression) input expression
	* .target: the resulting value
	* .type: type of .target, the value

.. op:: OP_PHI
	Phi-node (for SSA form).

	* .phi_list: phi-operands (type must be compatible with .target)
	* .target: "result"
	* .type: type of .target

.. op:: OP_PHISOURCE
	Phi-node source.
	Like OP_COPY but exclusively used to give a defining instructions
	(and thus also a type) to *all* OP_PHI operands.

	* .phi_src: operand (type must be compatible with .target, alias .src)
	* .target: the "result" PSEUDO_PHI
	* .type: type of .target
	* .phi_users: list of phi instructions using the target pseudo

.. op:: OP_CALL
	Function call.

	* .func: (pseudo_t) the function (can be a symbol or a "register",
	  alias .src))
	* .arguments: (pseudo_list) list of the associated arguments
	* .target: function return value (if any)
	* .type: type of .target
	* .fntypes: (symbol_list) list of the function's types: the first
	  entry is the full function type, the next ones are the type of
	  each arguments

.. op:: OP_INLINED_CALL
	Only used as an annotation to show that the instructions just above
	correspond to a function that have been inlined.

	* .func: (pseudo_t) the function (must be a symbol, alias .src))
	* .arguments: list of pseudos that where the function's arguments
	* .target: function return value (if any)
	* .type: type of .target

.. op:: OP_SLICE
	Extract a "slice" from an aggregate.

	* .base: (pseudo_t) aggregate (alias .src)
	* .from, .len: offet & size of the "slice" within the aggregate
	* .target: result
	* .type: type of .target

.. op:: OP_ASM
	Inlined assembly code.

	* .string: asm template
	* .asm_rules: asm constraints, rules

Sparse tagging (line numbers, context, whatever)
------------------------------------------------
.. op:: OP_CONTEXT
	Currently only used for lock/unlock tracking.

	* .context_expr: unused
	* .increment: (1 for locking, -1 for unlocking)
	* .check: (ignore the instruction if 0)

Misc ops
--------
.. op:: OP_ENTRY
	Function entry point (no associated semantic).

.. op:: OP_BADOP
	Invalid operation (should never be generated).

.. op:: OP_NOP
	No-op (should never be generated).

.. op:: OP_DEATHNOTE
	Annotation telling the pseudo will be death after the next
	instruction (other than some other annotation, that is).

.. # vim: tabstop=4
