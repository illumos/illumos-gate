/*
 * Copyright (C) 2017 Luc Van Oostenryck
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "opcode.h"

const struct opcode_table opcode_table[OP_LAST] = {
#define OPCODE(OP,NG,SW,TF,N,FL)	\
	[OP_##OP] = {			\
		.negate   = OP_##NG,	\
		.swap     = OP_##SW,	\
		.to_float = OP_##TF,	\
		.arity    = N,		\
		.flags    = FL,		\
	},
#define OPCODE_RANGE(OP,S,E)
#include "opcode.def"
#undef OPCODE
#undef OPCODE_RANGE
};
