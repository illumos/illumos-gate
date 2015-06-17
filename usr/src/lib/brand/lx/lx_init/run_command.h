/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _RUN_COMMAND_H
#define	_RUN_COMMAND_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void run_command_line_cb(const char *);

extern int run_command(const char *, char *const [], char *const [], char *,
    size_t, run_command_line_cb *, int *);

#ifdef __cplusplus
}
#endif

#endif /* _RUN_COMMAND_H */
