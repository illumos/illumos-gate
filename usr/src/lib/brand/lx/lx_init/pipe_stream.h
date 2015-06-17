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

#ifndef _PIPE_STREAM_H
#define	_PIPE_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

typedef int pipe_stream_data_cb(const uint8_t *, size_t, void *, void *);
typedef void pipe_stream_eof_cb(void *, void *);
typedef void pipe_stream_error_cb(int, void *, void *);

typedef struct pipe_stream pipe_stream_t;
typedef struct pipe_stream_loop pipe_stream_loop_t;

extern int pipe_stream_loop_fini(pipe_stream_loop_t *);
extern int pipe_stream_loop_init(pipe_stream_loop_t **, size_t,
    pipe_stream_data_cb *, pipe_stream_eof_cb *, pipe_stream_error_cb *);

extern int pipe_stream_init(pipe_stream_loop_t *, pipe_stream_t **, void *,
    void *);
extern int pipe_stream_fini(pipe_stream_t *);

extern void pipe_stream_parent_afterfork(pipe_stream_t *);
extern int pipe_stream_child_afterfork(pipe_stream_t *, int);

extern boolean_t pipe_stream_loop_should_run(pipe_stream_loop_t *);
extern int pipe_stream_loop_run(pipe_stream_loop_t *);

#ifdef __cplusplus
}
#endif

#endif /* _PIPE_STREAM_H */
