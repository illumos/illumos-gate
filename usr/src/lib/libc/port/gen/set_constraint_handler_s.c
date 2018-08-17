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

/*
 * Copyright 2018 Nexenta Systems, Inc.
 */

#include "lint.h"

#include <sys/types.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <synch.h>
#include <thread.h>
#include <unistd.h>

#include "libc.h"

/*
 * Rationale recommends allocating new memory each time.
 */
static constraint_handler_t *_ch = NULL;
static mutex_t ch_lock = ERRORCHECKMUTEX;

constraint_handler_t
set_constraint_handler_s(constraint_handler_t handler)
{
	constraint_handler_t *new, *old, ret;

	new = malloc(sizeof (constraint_handler_t));
	if (new == NULL)
		return (NULL);
	*new = handler;
	mutex_enter(&ch_lock);
	old = _ch;
	_ch = new;
	mutex_exit(&ch_lock);
	if (old == NULL) {
		ret = NULL;
	} else {
		ret = *old;
		free(old);
	}
	return (ret);
}

/*ARGSUSED*/
void
abort_handler_s(const char *_RESTRICT_KYWD msg,
    void *_RESTRICT_KYWD ptr, errno_t error)
{
	common_panic("abort_handler_s: ", msg);
}

/*ARGSUSED*/
void
ignore_handler_s(const char *_RESTRICT_KYWD msg,
    void *_RESTRICT_KYWD ptr, errno_t error)
{
}

void
__throw_constraint_handler_s(const char *_RESTRICT_KYWD msg, errno_t error)
{
	constraint_handler_t ch;

	mutex_enter(&ch_lock);
	ch = (_ch != NULL) ? *_ch : NULL;
	mutex_exit(&ch_lock);
	if (ch != NULL) {
		ch(msg, NULL, error);
	} else {
		/*
		 * If current handler is NULL (there were no calls to
		 * set_constraint_handler_s(), or it was called with NULL
		 * pointer handler argument), call default constraint handler
		 * per K.3.6.1.1 points 4 and 5.
		 *
		 * This implementation defines abort_handler_s() as default.
		 */
		abort_handler_s(msg, NULL, error);
	}
}
