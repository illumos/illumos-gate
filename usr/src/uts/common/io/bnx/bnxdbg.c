/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include "bnx.h"

#define	BNX_BUF_SIZE 256


void
debug_break(void *ctx)
{
	um_device_t *um = (um_device_t *)ctx;
	cmn_err(CE_PANIC, "-> %s panic <-", (um) ? um->dev_name : "(unknown)");
}


void
debug_msg(void *ctx, unsigned long level, char *file, unsigned long line,
    char *msg, ...)
{
	um_device_t *um = (um_device_t *)ctx;
	char buf[BNX_BUF_SIZE];
	va_list argp;

	*buf = '\0';

	if (um != NULL) {
		(void) snprintf(buf, BNX_BUF_SIZE, "%s %s:%lu ", um->dev_name,
		    file, line);
	} else {
		(void) snprintf(buf, BNX_BUF_SIZE, "%s:%lu ", file, line);
	}

	(void) strlcat(buf, msg, BNX_BUF_SIZE);

	va_start(argp, msg);
	vcmn_err(CE_WARN, buf, argp);
	va_end(argp);
}


void
debug_msgx(void *ctx, unsigned long level, char *msg, ...)
{
	um_device_t *um = (um_device_t *)ctx;
	char buf[BNX_BUF_SIZE];
	va_list argp;

	*buf = '\0';

	if (um != NULL) {
		(void) snprintf(buf, BNX_BUF_SIZE, "%s ", um->dev_name);
	}

	(void) strlcat(buf, msg, BNX_BUF_SIZE);

	va_start(argp, msg);
	vcmn_err(CE_WARN, buf, argp);
	va_end(argp);
}
