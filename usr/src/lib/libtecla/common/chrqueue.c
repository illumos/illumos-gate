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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "ioutil.h"
#include "chrqueue.h"
#include "freelist.h"
#include "errmsg.h"

/*
 * Set the number of bytes allocated to each node of the list of
 * character buffers. This facility is designed principally as
 * an expandible I/O output buffer, so use the stdio buffer size
 * where available.
 */
#ifdef BUFSIZ
#define GL_CQ_SIZE BUFSIZ
#else
#define GL_CQ_SIZE 512
#endif

/*
 * The queue is contained in a list of fixed sized buffers. New nodes
 * are appended to this list as needed to accomodate newly added bytes.
 * Old nodes at the head of the list are removed as they are emptied.
 */
typedef struct CqCharBuff CqCharBuff;
struct CqCharBuff {
  CqCharBuff *next;          /* The next node in the list of buffers */
  char bytes[GL_CQ_SIZE];    /* The fixed size buffer of this node */
};

/*
 * Define the structure that is used to contain a list of character
 * buffers.
 */
struct GlCharQueue {
  ErrMsg *err;          /* A buffer in which to record error messages */
  FreeList *bufmem;     /* A free-list of CqCharBuff structures */
  struct {
    CqCharBuff *head;   /* The head of the list of output buffers */
    CqCharBuff *tail;   /* The tail of the list of output buffers */
  } buffers;
  int nflush;           /* The total number of characters that have been */
                        /*  flushed from the start of the queue since */
                        /*  _glq_empty_queue() was last called. */
  int ntotal;           /* The total number of characters that have been */
                        /*  appended to the queue since _glq_empty_queue() */
                        /*  was last called. */
};

/*.......................................................................
 * Create a new GlCharQueue object.
 *
 * Output:
 *  return  GlCharQueue *  The new object, or NULL on error.
 */
GlCharQueue *_new_GlCharQueue(void)
{
  GlCharQueue *cq;  /* The object to be returned */
/*
 * Allocate the container.
 */
  cq = malloc(sizeof(GlCharQueue));
  if(!cq) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to del_GlCharQueue().
 */
  cq->err = NULL;
  cq->bufmem = NULL;
  cq->buffers.head = NULL;
  cq->buffers.tail = NULL;
  cq->nflush = cq->ntotal = 0;
/*
 * Allocate a place to record error messages.
 */
  cq->err = _new_ErrMsg();
  if(!cq->err)
    return _del_GlCharQueue(cq);
/*
 * Allocate the freelist of CqCharBuff structures.
 */
  cq->bufmem = _new_FreeList(sizeof(CqCharBuff), 1);
  if(!cq->bufmem)
    return _del_GlCharQueue(cq);
  return cq;
}

/*.......................................................................
 * Delete a GlCharQueue object.
 *
 * Input:
 *  cq     GlCharQueue *  The object to be deleted.
 * Output:
 *  return GlCharQueue *  The deleted object (always NULL).
 */
GlCharQueue *_del_GlCharQueue(GlCharQueue *cq)
{
  if(cq) {
    cq->err = _del_ErrMsg(cq->err);
    cq->bufmem = _del_FreeList(cq->bufmem, 1);
    free(cq);
  };
  return NULL;
}

/*.......................................................................
 * Append an array of n characters to a character queue.
 *
 * Input:
 *  cq        GlCharQueue *  The queue to append to.
 *  chars      const char *  The array of n characters to be appended.
 *  n                 int    The number of characters in chars[].
 *  write_fn  GL_WRITE_FN *  The function to call to output characters,
 *                           or 0 to simply discard the contents of the
 *                           queue. This will be called whenever the
 *                           buffer becomes full. If it fails to release
 *                           any space, the buffer will be extended.
 *  data             void *  Anonymous data to pass to write_fn().
 * Output:
 *  return        int    The number of characters successfully
 *                       appended. This will only be < n on error.
 */
int _glq_append_chars(GlCharQueue *cq, const char *chars, int n,
		      GlWriteFn *write_fn, void *data)
{
  int ndone = 0;  /* The number of characters appended so far */
/*
 * Check the arguments.
 */
  if(!cq || !chars) {
    errno = EINVAL;
    return 0;
  };
/*
 * The appended characters may have to be split between multiple
 * buffers, so loop for each buffer.
 */
  while(ndone < n) {
    int ntodo;     /* The number of characters remaining to be appended */
    int nleft;     /* The amount of space remaining in cq->buffers.tail */
    int nnew;      /* The number of characters to append to cq->buffers.tail */
/*
 * Compute the offset at which the next character should be written
 * into the tail buffer segment.
 */
    int boff = cq->ntotal % GL_CQ_SIZE;
/*
 * Since we don't allocate a new buffer until we have at least one
 * character to write into it, if boff is 0 at this point, it means
 * that we hit the end of the tail buffer segment on the last append,
 * so we need to allocate a new one.
 *
 * If allocating this new node will require a call to malloc(), as
 * opposed to using a currently unused node in the freelist, first try
 * flushing the current contents of the buffer to the terminal. When
 * write_fn() uses blocking I/O, this stops the buffer size ever getting
 * bigger than a single buffer node. When it is non-blocking, it helps
 * to keep the amount of memory, but it isn't gauranteed to do so.
 */
    if(boff == 0 && _idle_FreeListNodes(cq->bufmem) == 0) {
      switch(_glq_flush_queue(cq, write_fn, data)) {
      case GLQ_FLUSH_DONE:
	break;
      case GLQ_FLUSH_AGAIN:
	errno = 0;          /* Don't confuse the caller */
	break;
      default:
	return ndone;       /* Error */
      };
      boff = cq->ntotal % GL_CQ_SIZE;
    };
/*
 * Since we don't allocate a new buffer until we have at least one
 * character to write into it, if boff is 0 at this point, it means
 * that we hit the end of the tail buffer segment on the last append,
 * so we need to allocate a new one.
 */
    if(boff == 0) {
/*
 * Allocate the new node.
 */
      CqCharBuff *node = (CqCharBuff *) _new_FreeListNode(cq->bufmem);
      if(!node) {
	_err_record_msg(cq->err, "Insufficient memory to buffer output.",
			END_ERR_MSG);
	return ndone;
      };
/*
 * Initialize the node.
 */
      node->next = NULL;
/*
 * Append the new node to the tail of the list.
 */
      if(cq->buffers.tail)
	cq->buffers.tail->next = node;
      else
	cq->buffers.head = node;
      cq->buffers.tail = node;
    };
/*
 * How much room is there for new characters in the current tail node?
 */
    nleft = GL_CQ_SIZE - boff;
/*
 * How many characters remain to be appended?
 */
    ntodo = n - ndone;
/*
 * How many characters should we append to the current tail node?
 */
    nnew = nleft < ntodo ? nleft : ntodo;
/*
 * Append the latest prefix of nnew characters.
 */
    memcpy(cq->buffers.tail->bytes + boff, chars + ndone, nnew);
    cq->ntotal += nnew;
    ndone += nnew;
  };
/*
 * Return the count of the number of characters successfully appended.
 */
  return ndone;
}

/*.......................................................................
 * Discard the contents of a queue of characters.
 *
 * Input:
 *  cq    GlCharQueue *  The queue to clear.
 */
void _glq_empty_queue(GlCharQueue *cq)
{
  if(cq) {
/*
 * Return all list nodes to their respective free-lists.
 */
    _rst_FreeList(cq->bufmem);
/*
 * Mark the lists as empty.
 */
    cq->buffers.head = cq->buffers.tail = NULL;
    cq->nflush = cq->ntotal = 0;
  };
}

/*.......................................................................
 * Return a count of the number of characters currently in the queue.
 *
 * Input:
 *  cq    GlCharQueue *  The queue of interest.
 * Output:
 *  return        int    The number of characters in the queue.
 */
int _glq_char_count(GlCharQueue *cq)
{
  return (cq && cq->buffers.head) ? (cq->ntotal - cq->nflush) : 0;
}

/*.......................................................................
 * Write as many characters as possible from the start of a character
 * queue via a given output callback function, removing those written
 * from the queue.
 *
 * Input:
 *  cq        GlCharQueue *  The queue to write characters from.
 *  write_fn  GL_WRITE_FN *  The function to call to output characters,
 *                           or 0 to simply discard the contents of the
 *                           queue.
 *  data             void *  Anonymous data to pass to write_fn().
 * Output:
 *  return   GlFlushState    The status of the flush operation:
 *                             GLQ_FLUSH_DONE  -  The flush operation
 *                                                completed successfully.
 *                             GLQ_FLUSH_AGAIN -  The flush operation
 *                                                couldn't be completed
 *                                                on this call. Call this
 *                                                function again when the
 *                                                output channel can accept
 *                                                further output.
 *                             GLQ_FLUSH_ERROR    Unrecoverable error.
 */
GlqFlushState _glq_flush_queue(GlCharQueue *cq, GlWriteFn *write_fn,
			       void *data)
{
/*
 * Check the arguments.
 */
  if(!cq) {
    errno = EINVAL;
    return GLQ_FLUSH_ERROR;
  };
/*
 * If possible keep writing until all of the chained buffers have been
 * emptied and removed from the list.
 */
  while(cq->buffers.head) {
/*
 * Are we looking at the only node in the list?
 */
    int is_tail = cq->buffers.head == cq->buffers.tail;
/*
 * How many characters more than an exact multiple of the buffer-segment
 * size have been added to the buffer so far?
 */
    int nmodulo = cq->ntotal % GL_CQ_SIZE;
/*
 * How many characters of the buffer segment at the head of the list
 * have been used? Note that this includes any characters that have
 * already been flushed. Also note that if nmodulo==0, this means that
 * the tail buffer segment is full. The reason for this is that we
 * don't allocate new tail buffer segments until there is at least one
 * character to be added to them.
 */
    int nhead = (!is_tail || nmodulo == 0) ? GL_CQ_SIZE : nmodulo;
/*
 * How many characters remain to be flushed from the buffer
 * at the head of the list?
 */
    int nbuff = nhead - (cq->nflush % GL_CQ_SIZE);
/*
 * Attempt to write this number.
 */
    int nnew = write_fn(data, cq->buffers.head->bytes +
			cq->nflush % GL_CQ_SIZE, nbuff);
/*
 * Was anything written?
 */
    if(nnew > 0) {
/*
 * Increment the count of the number of characters that have
 * been flushed from the head of the queue.
 */
      cq->nflush += nnew;
/*
 * If we succeded in writing all of the contents of the current
 * buffer segment, remove it from the queue.
 */
      if(nnew == nbuff) {
/*
 * If we just emptied the last node left in the list, then the queue is
 * now empty and should be reset.
 */
	if(is_tail) {
	  _glq_empty_queue(cq);
	} else {
/*
 * Get the node to be removed from the head of the list.
 */
	  CqCharBuff *node = cq->buffers.head;
/*
 * Make the node that follows it the new head of the queue.
 */
	  cq->buffers.head = node->next;
/*
 * Return it to the freelist.
 */
	  node = (CqCharBuff *) _del_FreeListNode(cq->bufmem, node);
	};
      };
/*
 * If the write blocked, request that this function be called again
 * when space to write next becomes available.
 */
    } else if(nnew==0) {
      return GLQ_FLUSH_AGAIN;
/*
 * I/O error.
 */
    } else {
      _err_record_msg(cq->err, "Error writing to terminal", END_ERR_MSG);
      return GLQ_FLUSH_ERROR;
    };
  };
/*
 * To get here the queue must now be empty.
 */
  return GLQ_FLUSH_DONE;
}

/*.......................................................................
 * Return extra information (ie. in addition to that provided by errno)
 * about the last error to occur in any of the public functions of this
 * module.
 *
 * Input:
 *  cq     GlCharQueue *  The container of the history list.
 * Output:
 *  return  const char *  A pointer to the internal buffer in which
 *                        the error message is temporarily stored.
 */
const char *_glq_last_error(GlCharQueue *cq)
{
  return cq ? _err_get_msg(cq->err) : "NULL GlCharQueue argument";
}
