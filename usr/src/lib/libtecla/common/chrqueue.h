#ifndef chrqueue_h
#define chrqueue_h

/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004 by Martin C. Shepherd.
 * 
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*-----------------------------------------------------------------------
 * This module implements a queue of characters to be processed in some
 * way. It is used by gl_get_line() to maintain a queue of characters
 * to be sent to a remote terminal. Characters are recorded in a
 * dynamically extensible list of fixed sized buffers.
 */

typedef struct GlCharQueue GlCharQueue;

/*
 * Create a new character queue.
 */
GlCharQueue *_new_GlCharQueue(void);

/*
 * Delete a redundant character queue.
 */
GlCharQueue *_del_GlCharQueue(GlCharQueue *cq);

/*
 * Append an array of n characters to a character queue.
 */
int _glq_append_chars(GlCharQueue *cq, const char *chars, int n,
		      GlWriteFn *write_fn, void *data);

/*
 * Clear a character queue.
 */
void _glq_empty_queue(GlCharQueue *cq);

/*
 * Return a count of the number of characters in the queue.
 */
int _glq_char_count(GlCharQueue *cq);

/*
 * A structure of the following type is used by _glq_peek_chars() to
 * return characters at the start of the queue.
 */
typedef struct {
  const char *buff;  /* A pointer to the first undeleted byte in the */
                     /*  first buffer of the queue. */
  int nbuff;         /* The number of characters in buff[] */
} GlCharQueueBuff;

/*
 * Enumerator values of the following type are returned by
 * _glq_flush_queue() to indicate the status of the flush operation.
 */
typedef enum {
  GLQ_FLUSH_DONE,   /* The flush operation completed successfully */
  GLQ_FLUSH_AGAIN,  /* The flush operation couldn't be completed on this */
                    /*  call. Call this function again when the output */
                    /*  channel can accept further output. */
  GLQ_FLUSH_ERROR   /* Unrecoverable error. */
} GlqFlushState;

/*
 * Transfer as much of the contents of a character queue to an output
 * channel as possible, returning before the queue is empty if the
 * write_fn() callback says that it can't currently write anymore.
 */
GlqFlushState _glq_flush_queue(GlCharQueue *cq, GlWriteFn *write_fn,
			       void *data);

/*
 * Provide information about the last error that occurred while calling
 * any of the above functions.
 */
const char *_glq_last_error(GlCharQueue *cq);

#endif
