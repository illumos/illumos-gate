/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2001 Alexey Zelkin <phantom@FreeBSD.org>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "lint.h"
#include <stddef.h>
#include <errno.h>
#include "ldpart.h"
#include "lmessages.h"
#include "localeimpl.h"

#define	LCMESSAGES_SIZE_FULL (sizeof (struct lc_messages) / sizeof (char *))
#define	LCMESSAGES_SIZE_MIN \
	(offsetof(struct lc_messages, yesstr) / sizeof (char *))

static char empty[] = "";

struct lc_messages lc_messages_posix = {
	"^[yY]",	/* yesexpr */
	"^[nN]",	/* noexpr */
	"yes",		/* yesstr */
	"no"		/* nostr */
};

struct locdata __posix_messages_locdata = {
	.l_lname = "C",
	.l_data = { &lc_messages_posix }
};

struct locdata *
__lc_messages_load(const char *name)
{
	struct locdata *ldata;
	struct lc_messages *lmsgs;
	int ret;

	if ((ldata = __locdata_alloc(name, sizeof (*lmsgs))) == NULL)
		return (NULL);
	lmsgs = ldata->l_data[0];

	ret = __part_load_locale(name, (char **)&ldata->l_data[1],
	    "LC_MESSAGES", LCMESSAGES_SIZE_FULL, LCMESSAGES_SIZE_MIN,
	    (const char **)lmsgs);

	if (ret != _LDP_LOADED) {
		__locdata_free(ldata);
		errno = EINVAL;
		return (NULL);
	}

	if (lmsgs->yesstr == NULL)
		lmsgs->yesstr = empty;
	if (lmsgs->nostr == NULL)
		lmsgs->nostr = empty;

	return (ldata);
}
