/*
 * Copyright (c) 2017 Juniper Networks.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static errno_t e;
static const char *_RESTRICT_KYWD m;

void
h(const char *_RESTRICT_KYWD msg, void *_RESTRICT_KYWD ptr, errno_t error)
{
	e = error;
	m = msg;
}

int
main(void)
{
	char a;
	char b[3];

	/* null ptr */
	set_constraint_handler_s(ignore_handler_s);
	assert(memset_s(0, 1, 1, 1) != 0);

	/* smax > rmax */
	set_constraint_handler_s(ignore_handler_s);
	assert(memset_s(&b, RSIZE_MAX + 1, 1, 1) != 0);

	/* smax < 0 */
	set_constraint_handler_s(ignore_handler_s);
	assert(memset_s(&a, -1, 1, 1) != 0);

	/* normal */
	set_constraint_handler_s(ignore_handler_s);
	a = 3;
	assert(memset_s(&a, 1, 5, 1) == 0);
	assert(a == 5);

	/* n > rmax */
	set_constraint_handler_s(ignore_handler_s);
	assert(memset_s(&a, 1, 1, RSIZE_MAX + 1) != 0);

	/* n < 0 */
	set_constraint_handler_s(ignore_handler_s);
	assert(memset_s(&a, 1, 1, -1) != 0);

	/* n < smax */
	set_constraint_handler_s(ignore_handler_s);
	b[0] = 1; b[1] = 2; b[2] = 3;
	assert(memset_s(&b[0], 3, 9, 1) == 0);
	assert(b[0] == 9);
	assert(b[1] == 2);
	assert(b[2] == 3);

	/* n > smax, handler */
	set_constraint_handler_s(h);
	e = 0;
	m = NULL;
	b[0] = 1; b[1] = 2; b[2] = 3;
	assert(memset_s(&b[0], 1, 9, 3) != 0);
	assert(e > 0);
	assert(strcmp(m, "memset_s: n > smax") == 0);
	assert(b[0] == 9);
	assert(b[1] == 2);
	assert(b[2] == 3);

	/* smax > rmax, handler */
	set_constraint_handler_s(h);
	e = 0;
	m = NULL;
	assert(memset_s(&a, RSIZE_MAX + 1, 1, 1) != 0);
	assert(e > 0);
	assert(strcmp(m, "memset_s: smax > RSIZE_MAX") == 0);

	/* smax < 0, handler */
	set_constraint_handler_s(h);
	e = 0;
	m = NULL;
	assert(memset_s(&a, -1, 1, 1) != 0);
	assert(e > 0);
	assert(strcmp(m, "memset_s: smax > RSIZE_MAX") == 0);

	/* n > rmax, handler */
	set_constraint_handler_s(h);
	e = 0;
	m = NULL;
	assert(memset_s(&a, 1, 1, RSIZE_MAX + 1) != 0);
	assert(e > 0);
	assert(strcmp(m, "memset_s: n > RSIZE_MAX") == 0);

	/* n < 0, handler */
	set_constraint_handler_s(h);
	e = 0;
	m = NULL;
	assert(memset_s(&a, 1, 1, -1) != 0);
	assert(e > 0);
	assert(strcmp(m, "memset_s: n > RSIZE_MAX") == 0);

	return (0);
}
