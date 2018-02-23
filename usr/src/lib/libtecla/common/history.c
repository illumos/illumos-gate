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

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#include "ioutil.h"
#include "history.h"
#include "freelist.h"
#include "errmsg.h"

/*
 * History lines are split into sub-strings of GLH_SEG_SIZE
 * characters.  To avoid wasting space in the GlhLineSeg structure,
 * this should be a multiple of the size of a pointer.
 */
#define GLH_SEG_SIZE 16

/*
 * GlhLineSeg structures contain fixed sized segments of a larger
 * string. These are linked into lists to record strings, with all but
 * the last segment having GLH_SEG_SIZE characters. The last segment
 * of a string is terminated within the GLH_SEG_SIZE characters with a
 * '\0'.
 */
typedef struct GlhLineSeg GlhLineSeg;
struct GlhLineSeg {
  GlhLineSeg *next;     /* The next sub-string of the history line */
  char s[GLH_SEG_SIZE]; /* The sub-string. Beware that only the final */
                        /*  substring of a line, as indicated by 'next' */
                        /*  being NULL, is '\0' terminated. */
};

/*
 * History lines are recorded in a hash table, such that repeated
 * lines are stored just once.
 *
 * Start by defining the size of the hash table. This should be a
 * prime number.
 */
#define GLH_HASH_SIZE 113

typedef struct GlhHashBucket GlhHashBucket;

/*
 * Each history line will be represented in the hash table by a
 * structure of the following type.
 */
typedef struct GlhHashNode GlhHashNode;
struct GlhHashNode {
  GlhHashBucket *bucket; /* The parent hash-table bucket of this node */
  GlhHashNode *next;     /* The next in the list of nodes within the */
                         /*  parent hash-table bucket. */
  GlhLineSeg *head;      /* The list of sub-strings which make up a line */
  int len;               /* The length of the line, excluding any '\0' */
  int used;              /* The number of times this string is pointed to by */
                         /*  the time-ordered list of history lines. */
  int reported;          /* A flag that is used when searching to ensure that */
                         /*  a line isn't reported redundantly. */
};

/*
 * How many new GlhHashNode elements should be allocated at a time?
 */
#define GLH_HASH_INCR 50

static int _glh_is_line(GlhHashNode *hash, const char *line, size_t n);
static int _glh_line_matches_prefix(GlhHashNode *line, GlhHashNode *prefix);
static void _glh_return_line(GlhHashNode *hash, char *line, size_t dim);

/*
 * All history lines which hash to a given bucket in the hash table, are
 * recorded in a structure of the following type.
 */
struct GlhHashBucket {
  GlhHashNode *lines;  /* The list of history lines which fall in this bucket */
};

static GlhHashBucket *glh_find_bucket(GlHistory *glh, const char *line,
				      size_t n);
static GlhHashNode *glh_find_hash_node(GlhHashBucket *bucket, const char *line,
				       size_t n);

typedef struct {
  FreeList *node_mem;  /* A free-list of GlhHashNode structures */
  GlhHashBucket bucket[GLH_HASH_SIZE]; /* The buckets of the hash table */
} GlhLineHash;

/*
 * GlhLineNode's are used to record history lines in time order.
 */
typedef struct GlhLineNode GlhLineNode;
struct GlhLineNode {
  long id;             /* The unique identifier of this history line */
  time_t timestamp;    /* The time at which the line was archived */
  unsigned group;      /* The identifier of the history group to which the */
                       /*  the line belongs. */
  GlhLineNode *next;   /* The next youngest line in the list */
  GlhLineNode *prev;   /* The next oldest line in the list */
  GlhHashNode *line;   /* The hash-table entry of the history line */
};

/*
 * The number of GlhLineNode elements per freelist block.
 */
#define GLH_LINE_INCR 100

/*
 * Encapsulate the time-ordered list of historical lines.
 */
typedef struct {
  FreeList *node_mem;  /* A freelist of GlhLineNode objects */ 
  GlhLineNode *head;   /* The oldest line in the list */
  GlhLineNode *tail;   /* The newest line in the list */
} GlhLineList;

/*
 * The _glh_lookup_history() returns copies of history lines in a
 * dynamically allocated array. This array is initially allocated
 * GLH_LOOKUP_SIZE bytes. If subsequently this size turns out to be
 * too small, realloc() is used to increase its size to the required
 * size plus GLH_LOOKUP_MARGIN. The idea of the later parameter is to
 * reduce the number of realloc() operations needed.
 */
#define GLH_LBUF_SIZE 300
#define GLH_LBUF_MARGIN 100

/*
 * Encapsulate all of the resources needed to store historical input lines.
 */
struct GlHistory {
  ErrMsg *err;         /* The error-reporting buffer */
  GlhLineSeg *buffer;  /* An array of sub-line nodes to be partitioned */
                       /* into lists of sub-strings recording input lines. */
  int nbuff;           /* The allocated dimension of buffer[] */
  GlhLineSeg *unused;  /* The list of free nodes in buffer[] */
  GlhLineList list;    /* A time ordered list of history lines */
  GlhLineNode *recall; /* The last line recalled, or NULL if no recall */
                       /*  session is currently active. */
  GlhLineNode *id_node;/* The node at which the last ID search terminated */
  GlhLineHash hash;    /* A hash-table of reference-counted history lines */
  GlhHashNode *prefix; /* A pointer to a line containing the prefix that */
                       /*  is being searched for. Note that if prefix==NULL */
                       /*  and prefix_len>0, this means that no line in */
                       /*  the buffer starts with the requested prefix. */
  int prefix_len;      /* The length of the prefix being searched for. */
  char *lbuf;          /* The array in which _glh_lookup_history() returns */
                       /*  history lines */
  int lbuf_dim;        /* The allocated size of lbuf[] */
  int nbusy;           /* The number of line segments in buffer[] that are */
                       /*  currently being used to record sub-lines */
  int nfree;           /* The number of line segments in buffer that are */
                       /*  not currently being used to record sub-lines */
  unsigned long seq;   /* The next ID to assign to a line node */
  unsigned group;      /* The identifier of the current history group */
  int nline;           /* The number of lines currently in the history list */
  int max_lines;       /* Either -1 or a ceiling on the number of lines */
  int enable;          /* If false, ignore history additions and lookups */
};

#ifndef WITHOUT_FILE_SYSTEM
static int _glh_cant_load_history(GlHistory *glh, const char *filename,
				  int lineno, const char *message, FILE *fp);
static int _glh_cant_save_history(GlHistory *glh, const char *message,
				  const char *filename, FILE *fp);
static int _glh_write_timestamp(FILE *fp, time_t timestamp);
static int _glh_decode_timestamp(char *string, char **endp, time_t *timestamp);
#endif
static void _glh_discard_line(GlHistory *glh, GlhLineNode *node);
static GlhLineNode *_glh_find_id(GlHistory *glh, GlhLineID id);
static GlhHashNode *_glh_acquire_copy(GlHistory *glh, const char *line,
				      size_t n);
static GlhHashNode *_glh_discard_copy(GlHistory *glh, GlhHashNode *hnode);
static int _glh_prepare_for_recall(GlHistory *glh, char *line);

/*
 * The following structure and functions are used to iterate through
 * the characters of a segmented history line.
 */
typedef struct {
  GlhLineSeg *seg;  /* The line segment that the next character will */
                    /*  be returned from. */
  int posn;         /* The index in the above line segment, containing */
                    /*  the next unread character. */
  char c;           /* The current character in the input line */
} GlhLineStream;
static void glh_init_stream(GlhLineStream *str, GlhHashNode *line);
static void glh_step_stream(GlhLineStream *str);

/*
 * See if search prefix contains any globbing characters.
 */
static int glh_contains_glob(GlhHashNode *prefix);
/*
 * Match a line against a search pattern.
 */
static int glh_line_matches_glob(GlhLineStream *lstr, GlhLineStream *pstr);
static int glh_matches_range(char c, GlhLineStream *pstr);

/*.......................................................................
 * Create a line history maintenance object.
 *
 * Input:
 *  buflen     size_t    The number of bytes to allocate to the
 *                       buffer that is used to record all of the
 *                       most recent lines of user input that will fit.
 *                       If buflen==0, no buffer will be allocated.
 * Output:
 *  return  GlHistory *  The new object, or NULL on error.
 */
GlHistory *_new_GlHistory(size_t buflen)
{
  GlHistory *glh;  /* The object to be returned */
  int i;
/*
 * Allocate the container.
 */
  glh = (GlHistory *) malloc(sizeof(GlHistory));
  if(!glh) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to _del_GlHistory().
 */
  glh->err = NULL;
  glh->buffer = NULL;
  glh->nbuff = (buflen+GLH_SEG_SIZE-1) / GLH_SEG_SIZE;
  glh->unused = NULL;
  glh->list.node_mem = NULL;
  glh->list.head = glh->list.tail = NULL;
  glh->recall = NULL;
  glh->id_node = NULL;
  glh->hash.node_mem = NULL;
  for(i=0; i<GLH_HASH_SIZE; i++)
    glh->hash.bucket[i].lines = NULL;
  glh->prefix = NULL;
  glh->lbuf = NULL;
  glh->lbuf_dim = 0;
  glh->nbusy = 0;
  glh->nfree = glh->nbuff;
  glh->seq = 0;
  glh->group = 0;
  glh->nline = 0;
  glh->max_lines = -1;
  glh->enable = 1;
/*
 * Allocate a place to record error messages.
 */
  glh->err = _new_ErrMsg();
  if(!glh->err)
    return _del_GlHistory(glh);
/*
 * Allocate the buffer, if required.
 */
  if(glh->nbuff > 0) {
    glh->nbuff = glh->nfree;
    glh->buffer = (GlhLineSeg *) malloc(sizeof(GlhLineSeg) * glh->nbuff);
    if(!glh->buffer) {
      errno = ENOMEM;
      return _del_GlHistory(glh);
    };
/*
 * All nodes of the buffer are currently unused, so link them all into
 * a list and make glh->unused point to the head of this list.
 */
    glh->unused = glh->buffer;
    for(i=0; i<glh->nbuff-1; i++) {
      GlhLineSeg *seg = glh->unused + i;
      seg->next = seg + 1;
    };
    glh->unused[i].next = NULL;
  };
/*
 * Allocate the GlhLineNode freelist.
 */
  glh->list.node_mem = _new_FreeList(sizeof(GlhLineNode), GLH_LINE_INCR);
  if(!glh->list.node_mem)
    return _del_GlHistory(glh);
/*
 * Allocate the GlhHashNode freelist.
 */
  glh->hash.node_mem = _new_FreeList(sizeof(GlhLineNode), GLH_HASH_INCR);
  if(!glh->hash.node_mem)
    return _del_GlHistory(glh);
/*
 * Allocate the array that _glh_lookup_history() uses to return a
 * copy of a given history line. This will be resized when necessary.
 */
  glh->lbuf_dim = GLH_LBUF_SIZE;
  glh->lbuf = (char *) malloc(glh->lbuf_dim);
  if(!glh->lbuf) {
    errno = ENOMEM;
    return _del_GlHistory(glh);
  };
  return glh;
}

/*.......................................................................
 * Delete a GlHistory object.
 *
 * Input:
 *  glh    GlHistory *  The object to be deleted.
 * Output:
 *  return GlHistory *  The deleted object (always NULL).
 */
GlHistory *_del_GlHistory(GlHistory *glh)
{
  if(glh) {
/*
 * Delete the error-message buffer.
 */
    glh->err = _del_ErrMsg(glh->err);
/*
 * Delete the buffer.
 */
    if(glh->buffer) {
      free(glh->buffer);
      glh->buffer = NULL;
      glh->unused = NULL;
    };
/*
 * Delete the freelist of GlhLineNode's.
 */
    glh->list.node_mem = _del_FreeList(glh->list.node_mem, 1);
/*
 * The contents of the list were deleted by deleting the freelist.
 */
    glh->list.head = NULL;
    glh->list.tail = NULL;
/*
 * Delete the freelist of GlhHashNode's.
 */
    glh->hash.node_mem = _del_FreeList(glh->hash.node_mem, 1);
/*
 * Delete the lookup buffer.
 */
    if(glh->lbuf)
      free(glh->lbuf);
/*
 * Delete the container.
 */
    free(glh);
  };
  return NULL;
}

/*.......................................................................
 * Append a new line to the history list, deleting old lines to make
 * room, if needed.
 *
 * Input:
 *  glh  GlHistory *  The input-line history maintenance object.
 *  line      char *  The line to be archived.
 *  force      int    Unless this flag is non-zero, empty lines aren't
 *                    archived. This flag requests that the line be
 *                    archived regardless.
 * Output:
 *  return     int    0 - OK.
 *                    1 - Error.
 */
int _glh_add_history(GlHistory *glh, const char *line, int force)
{
  int slen;         /* The length of the line to be recorded (minus the '\0') */
  int empty;          /* True if the string is empty */
  const char *nlptr;  /* A pointer to a newline character in line[] */
  GlhHashNode *hnode; /* The hash-table node of the line */
  GlhLineNode *lnode; /* A node in the time-ordered list of lines */
  int i;
/*
 * Check the arguments.
 */
  if(!glh || !line) {
    errno = EINVAL;
    return 1;
  };
/*
 * Is history enabled?
 */
  if(!glh->enable || !glh->buffer || glh->max_lines == 0)
    return 0;
/*
 * Cancel any ongoing search.
 */
  if(_glh_cancel_search(glh))
    return 1;
/*
 * How long is the string to be recorded, being careful not to include
 * any terminating '\n' character.
 */
  nlptr = strchr(line, '\n');
  if(nlptr)
    slen = (nlptr - line);
  else
    slen = strlen(line);
/*
 * Is the line empty?
 */
  empty = 1;
  for(i=0; i<slen && empty; i++)
    empty = isspace((int)(unsigned char) line[i]);
/*
 * If the line is empty, don't add it to the buffer unless explicitly
 * told to.
 */
  if(empty && !force)
    return 0;
/*
 * Has an upper limit to the number of lines in the history list been
 * specified?
 */
  if(glh->max_lines >= 0) {
/*
 * If necessary, remove old lines until there is room to add one new
 * line without exceeding the specified line limit.
 */
    while(glh->nline > 0 && glh->nline >= glh->max_lines)
      _glh_discard_line(glh, glh->list.head);
/*
 * We can't archive the line if the maximum number of lines allowed is
 * zero.
 */
    if(glh->max_lines == 0)
      return 0;
  };
/*
 * Unless already stored, store a copy of the line in the history buffer,
 * then return a reference-counted hash-node pointer to this copy.
 */
  hnode = _glh_acquire_copy(glh, line, slen);
  if(!hnode) {
    _err_record_msg(glh->err, "No room to store history line", END_ERR_MSG);
    errno = ENOMEM;
    return 1;
  };
/*
 * Allocate a new node in the time-ordered list of lines.
 */
  lnode = (GlhLineNode *) _new_FreeListNode(glh->list.node_mem);
/*
 * If a new line-node couldn't be allocated, discard our copy of the
 * stored line before reporting the error.
 */
  if(!lnode) {
    hnode = _glh_discard_copy(glh, hnode);
    _err_record_msg(glh->err, "No room to store history line", END_ERR_MSG);
    errno = ENOMEM;
    return 1;
  };
/*
 * Record a pointer to the hash-table record of the line in the new
 * list node.
 */
  lnode->id = glh->seq++;
  lnode->timestamp = time(NULL);
  lnode->group = glh->group;
  lnode->line = hnode;
/*
 * Append the new node to the end of the time-ordered list.
 */
  if(glh->list.head)
    glh->list.tail->next = lnode;
  else
    glh->list.head = lnode;
  lnode->next = NULL;
  lnode->prev = glh->list.tail;
  glh->list.tail = lnode;
/*
 * Record the addition of a line to the list.
 */
  glh->nline++;
  return 0;
}

/*.......................................................................
 * Recall the next oldest line that has the search prefix last recorded
 * by _glh_search_prefix().
 *
 * Input:
 *  glh  GlHistory *  The input-line history maintenance object.
 *  line      char *  The input line buffer. On input this should contain
 *                    the current input line, and on output, if anything
 *                    was found, its contents will have been replaced
 *                    with the matching line.
 *  dim     size_t    The allocated dimension of the line buffer.
 * Output:
 *  return    char *  A pointer to line[0], or NULL if not found.
 */
char *_glh_find_backwards(GlHistory *glh, char *line, size_t dim)
{
  GlhLineNode *node;     /* The line location node being checked */
  GlhHashNode *old_line; /* The previous recalled line */
/*
 * Check the arguments.
 */
  if(!glh || !line) {
    if(glh)
      _err_record_msg(glh->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return NULL;
  };
/*
 * Is history enabled?
 */
  if(!glh->enable || !glh->buffer || glh->max_lines == 0)
    return NULL;
/*
 * Check the line dimensions.
 */
  if(dim < strlen(line) + 1) {
    _err_record_msg(glh->err, "'dim' argument inconsistent with strlen(line)",
		    END_ERR_MSG);
    errno = EINVAL;
    return NULL;
  };
/*
 * Preserve the input line if needed.
 */
  if(_glh_prepare_for_recall(glh, line))
    return NULL;
/*
 * From where should we start the search?
 */
  if(glh->recall) {
    node = glh->recall->prev;
    old_line = glh->recall->line;
  } else {
    node = glh->list.tail;
    old_line = NULL;
  };
/*
 * Search backwards through the list for the first match with the
 * prefix string that differs from the last line that was recalled.
 */
  while(node && (node->group != glh->group || node->line == old_line ||
	  !_glh_line_matches_prefix(node->line, glh->prefix)))
    node = node->prev;
/*
 * Was a matching line found?
 */
  if(node) {
/*
 * Recall the found node as the starting point for subsequent
 * searches.
 */
    glh->recall = node;
/*
 * Copy the matching line into the provided line buffer.
 */
    _glh_return_line(node->line, line, dim);
/*
 * Return it.
 */
    return line;
  };
/*
 * No match was found.
 */
  return NULL;
}

/*.......................................................................
 * Recall the next newest line that has the search prefix last recorded
 * by _glh_search_prefix().
 *
 * Input:
 *  glh  GlHistory *  The input-line history maintenance object.
 *  line      char *  The input line buffer. On input this should contain
 *                    the current input line, and on output, if anything
 *                    was found, its contents will have been replaced
 *                    with the matching line.
 *  dim     size_t    The allocated dimensions of the line buffer.
 * Output:
 *  return    char *  The line requested, or NULL if no matching line
 *                    was found.
 */
char *_glh_find_forwards(GlHistory *glh, char *line, size_t dim)
{
  GlhLineNode *node;     /* The line location node being checked */
  GlhHashNode *old_line; /* The previous recalled line */
/*
 * Check the arguments.
 */
  if(!glh || !line) {
    if(glh)
      _err_record_msg(glh->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return NULL;
  };
/*
 * Is history enabled?
 */
  if(!glh->enable || !glh->buffer || glh->max_lines == 0)
    return NULL;
/*
 * Check the line dimensions.
 */
  if(dim < strlen(line) + 1) {
    _err_record_msg(glh->err, "'dim' argument inconsistent with strlen(line)",
		    END_ERR_MSG);
    errno = EINVAL;
    return NULL;
  };
/*
 * From where should we start the search?
 */
  if(glh->recall) {
    node = glh->recall->next;
    old_line = glh->recall->line;
  } else {
    return NULL;
  };
/*
 * Search forwards through the list for the first match with the
 * prefix string.
 */
  while(node && (node->group != glh->group || node->line == old_line ||
	  !_glh_line_matches_prefix(node->line, glh->prefix)))
    node = node->next;
/*
 * Was a matching line found?
 */
  if(node) {
/*
 * Copy the matching line into the provided line buffer.
 */
    _glh_return_line(node->line, line, dim);
/*
 * Record the starting point of the next search.
 */
    glh->recall = node;
/*
 * If we just returned the line that was being entered when the search
 * session first started, cancel the search.
 */
    if(node == glh->list.tail)
      _glh_cancel_search(glh);
/*
 * Return the matching line to the user.
 */
    return line;
  };
/*
 * No match was found.
 */
  return NULL;
}

/*.......................................................................
 * If a search is in progress, cancel it.
 *
 * This involves discarding the line that was temporarily saved by
 * _glh_find_backwards() when the search was originally started,
 * and reseting the search iteration pointer to NULL.
 *
 * Input:
 *  glh  GlHistory *  The input-line history maintenance object.
 * Output:
 *  return     int    0 - OK.
 *                    1 - Error.
 */
int _glh_cancel_search(GlHistory *glh)
{
/*
 * Check the arguments.
 */
  if(!glh) {
    errno = EINVAL;
    return 1;
  };
/*
 * If there wasn't a search in progress, do nothing.
 */
  if(!glh->recall)
    return 0;
/*
 * Reset the search pointers. Note that it is essential to set
 * glh->recall to NULL before calling _glh_discard_line(), to avoid an
 * infinite recursion.
 */
  glh->recall = NULL;
/*
 * Delete the node of the preserved line.
 */
  _glh_discard_line(glh, glh->list.tail);
  return 0;
}

/*.......................................................................
 * Set the prefix of subsequent history searches.
 *
 * Input:
 *  glh    GlHistory *  The input-line history maintenance object.
 *  line  const char *  The command line who's prefix is to be used.
 *  prefix_len   int    The length of the prefix.
 * Output:
 *  return       int    0 - OK.
 *                      1 - Error.
 */
int _glh_search_prefix(GlHistory *glh, const char *line, int prefix_len)
{
/*
 * Check the arguments.
 */
  if(!glh) {
    errno = EINVAL;
    return 1;
  };
/*
 * Is history enabled?
 */
  if(!glh->enable || !glh->buffer || glh->max_lines == 0)
    return 0;
/*
 * Discard any existing prefix.
 */
  glh->prefix = _glh_discard_copy(glh, glh->prefix);
/*
 * Only store a copy of the prefix string if it isn't a zero-length string.
 */
  if(prefix_len > 0) {
/*
 * Get a reference-counted copy of the prefix from the history cache buffer.
 */
    glh->prefix = _glh_acquire_copy(glh, line, prefix_len);
/*
 * Was there insufficient buffer space?
 */
    if(!glh->prefix) {
      _err_record_msg(glh->err, "The search prefix is too long to store",
		      END_ERR_MSG);
      errno = ENOMEM;
      return 1;
    };
  };
  return 0;
}

/*.......................................................................
 * Recall the oldest recorded line.
 *
 * Input:
 *  glh  GlHistory *  The input-line history maintenance object.
 *  line      char *  The input line buffer. On input this should contain
 *                    the current input line, and on output, its contents
 *                    will have been replaced with the oldest line.
 *  dim     size_t    The allocated dimensions of the line buffer.
 * Output:
 *  return    char *  A pointer to line[0], or NULL if not found.
 */
char *_glh_oldest_line(GlHistory *glh, char *line, size_t dim)
{
  GlhLineNode *node; /* The line location node being checked */
/*
 * Check the arguments.
 */
  if(!glh || !line) {
    if(glh)
      _err_record_msg(glh->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return NULL;
  };
/*
 * Is history enabled?
 */
  if(!glh->enable || !glh->buffer || glh->max_lines == 0)
    return NULL;
/*
 * Check the line dimensions.
 */
  if(dim < strlen(line) + 1) {
    _err_record_msg(glh->err, "'dim' argument inconsistent with strlen(line)",
		    END_ERR_MSG);
    errno = EINVAL;
    return NULL;
  };
/*
 * Preserve the input line if needed.
 */
  if(_glh_prepare_for_recall(glh, line))
    return NULL;
/*
 * Locate the oldest line that belongs to the current group.
 */
  for(node=glh->list.head; node && node->group != glh->group; 
      node = node->next)
    ;
/*
 * No line found?
 */
  if(!node)
    return NULL;
/*
 * Record the above node as the starting point for subsequent
 * searches.
 */
  glh->recall = node;
/*
 * Copy the recalled line into the provided line buffer.
 */
  _glh_return_line(node->line, line, dim);
/*
 * If we just returned the line that was being entered when the search
 * session first started, cancel the search.
 */
  if(node == glh->list.tail)
    _glh_cancel_search(glh);
  return line;
}

/*.......................................................................
 * Recall the line that was being entered when the search started.
 *
 * Input:
 *  glh  GlHistory *  The input-line history maintenance object.
 *  line      char *  The input line buffer. On input this should contain
 *                    the current input line, and on output, its contents
 *                    will have been replaced with the line that was
 *                    being entered when the search was started.
 *  dim     size_t    The allocated dimensions of the line buffer.
 * Output:
 *  return    char *  A pointer to line[0], or NULL if not found.
 */
char *_glh_current_line(GlHistory *glh, char *line, size_t dim)
{
/*
 * Check the arguments.
 */
  if(!glh || !line) {
    if(glh)
      _err_record_msg(glh->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return NULL;
  };
/*
 * If history isn't enabled, or no history search has yet been started,
 * ignore the call.
 */
  if(!glh->enable || !glh->buffer || glh->max_lines == 0 || !glh->recall)
    return NULL;
/*
 * Check the line dimensions.
 */
  if(dim < strlen(line) + 1) {
    _err_record_msg(glh->err, "'dim' argument inconsistent with strlen(line)",
		    END_ERR_MSG);
    errno = EINVAL;
    return NULL;
  };
/*
 * Copy the recalled line into the provided line buffer.
 */
  _glh_return_line(glh->list.tail->line, line, dim);
/*
 * Since we have returned to the starting point of the search, cancel it.
 */
  _glh_cancel_search(glh);
  return line;
}

/*.......................................................................
 * Query the id of a history line offset by a given number of lines from
 * the one that is currently being recalled. If a recall session isn't
 * in progress, or the offset points outside the history list, 0 is
 * returned.
 *
 * Input:
 *  glh    GlHistory *  The input-line history maintenance object.
 *  offset       int    The line offset (0 for the current line, < 0
 *                      for an older line, > 0 for a newer line.
 * Output:
 *  return GlhLineID    The identifier of the line that is currently
 *                      being recalled, or 0 if no recall session is
 *                      currently in progress.
 */
GlhLineID _glh_line_id(GlHistory *glh, int offset)
{
  GlhLineNode *node; /* The line location node being checked */
/*
 * Is history enabled?
 */
  if(!glh->enable || !glh->buffer || glh->max_lines == 0)
    return 0;
/*
 * Search forward 'offset' lines to find the required line.
 */
  if(offset >= 0) {
    for(node=glh->recall; node && offset != 0; node=node->next) {
      if(node->group == glh->group)
	offset--;
    };
  } else {
    for(node=glh->recall; node && offset != 0; node=node->prev) {
      if(node->group == glh->group)
	offset++;
    };
  };
  return node ? node->id : 0;
}

/*.......................................................................
 * Recall a line by its history buffer ID. If the line is no longer
 * in the buffer, or the id is zero, NULL is returned.
 *
 * Input:
 *  glh  GlHistory *  The input-line history maintenance object.
 *  id   GlhLineID    The ID of the line to be returned.
 *  line      char *  The input line buffer. On input this should contain
 *                    the current input line, and on output, its contents
 *                    will have been replaced with the saved line.
 *  dim     size_t    The allocated dimensions of the line buffer.
 * Output:
 *  return    char *  A pointer to line[0], or NULL if not found.
 */
char *_glh_recall_line(GlHistory *glh, GlhLineID id, char *line, size_t dim)
{
  GlhLineNode *node; /* The line location node being checked */
/*
 * Is history enabled?
 */
  if(!glh->enable || !glh->buffer || glh->max_lines == 0)
    return NULL;
/*
 * Preserve the input line if needed.
 */
  if(_glh_prepare_for_recall(glh, line))
    return NULL;
/*
 * Search for the specified line.
 */
  node = _glh_find_id(glh, id);
/*
 * Not found?
 */
  if(!node || node->group != glh->group)
    return NULL;
/*
 * Record the node of the matching line as the starting point
 * for subsequent searches.
 */
  glh->recall = node;
/*
 * Copy the recalled line into the provided line buffer.
 */
  _glh_return_line(node->line, line, dim);
  return line;
}

/*.......................................................................
 * Save the current history in a specified file.
 *
 * Input:
 *  glh        GlHistory *  The input-line history maintenance object.
 *  filename  const char *  The name of the new file to record the
 *                          history in.
 *  comment   const char *  Extra information such as timestamps will
 *                          be recorded on a line started with this
 *                          string, the idea being that the file can
 *                          double as a command file. Specify "" if
 *                          you don't care.
 *  max_lines        int    The maximum number of lines to save, or -1
 *                          to save all of the lines in the history
 *                          list.
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error.
 */
int _glh_save_history(GlHistory *glh, const char *filename, const char *comment,
		      int max_lines)
{
#ifdef WITHOUT_FILE_SYSTEM
  _err_record_msg(glh->err, "Can't save history without filesystem access",
		  END_ERR_MSG);
  errno = EINVAL;
  return 1;
#else
  FILE *fp;          /* The output file */
  GlhLineNode *node; /* The line being saved */
  GlhLineNode *head; /* The head of the list of lines to be saved */
  GlhLineSeg *seg;   /* One segment of a line being saved */
/*
 * Check the arguments.
 */
  if(!glh || !filename || !comment) {
    if(glh)
      _err_record_msg(glh->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Attempt to open the specified file.
 */
  fp = fopen(filename, "w");
  if(!fp)
    return _glh_cant_save_history(glh, "Can't open", filename, NULL);
/*
 * If a ceiling on the number of lines to save was specified, count
 * that number of lines backwards, to find the first line to be saved.
 */
  head = NULL;
  if(max_lines >= 0) {
    for(head=glh->list.tail; head && --max_lines > 0; head=head->prev)
      ;
  };
  if(!head)
    head = glh->list.head;
/*
 * Write the contents of the history buffer to the history file, writing
 * associated data such as timestamps, to a line starting with the
 * specified comment string.
 */
  for(node=head; node; node=node->next) {
/*
 * Write peripheral information associated with the line, as a comment.
 */
    if(fprintf(fp, "%s ", comment) < 0 ||
       _glh_write_timestamp(fp, node->timestamp) ||
       fprintf(fp, " %u\n", node->group) < 0) {
      return _glh_cant_save_history(glh, "Error writing", filename, fp);
    };
/*
 * Write the history line.
 */
    for(seg=node->line->head; seg; seg=seg->next) {
      size_t slen = seg->next ? GLH_SEG_SIZE : strlen(seg->s);
      if(fwrite(seg->s, sizeof(char), slen, fp) != slen)
	return _glh_cant_save_history(glh, "Error writing", filename, fp);
    };
    fputc('\n', fp);
  };
/*
 * Close the history file.
 */
  if(fclose(fp) == EOF)
    return _glh_cant_save_history(glh, "Error writing", filename, NULL);
  return 0;
#endif
}

#ifndef WITHOUT_FILE_SYSTEM
/*.......................................................................
 * This is a private error return function of _glh_save_history(). It
 * composes an error report in the error buffer, composed using
 * sprintf("%s %s (%s)", message, filename, strerror(errno)). It then
 * closes fp and returns the error return code of _glh_save_history().
 *
 * Input:
 *  glh        GlHistory *  The input-line history maintenance object.
 *  message   const char *  A message to be followed by the filename.
 *  filename  const char *  The name of the offending output file.
 *  fp              FILE *  The stream to be closed (send NULL if not
 *                          open).
 * Output:
 *  return           int    Always 1.
 */
static int _glh_cant_save_history(GlHistory *glh, const char *message,
				  const char *filename, FILE *fp)
{
  _err_record_msg(glh->err, message, filename, " (",
		     strerror(errno), ")", END_ERR_MSG);
  if(fp)
    (void) fclose(fp);
  return 1;
}

/*.......................................................................
 * Write a timestamp to a given stdio stream, in the format
 * yyyymmddhhmmss
 *
 * Input:
 *  fp             FILE *  The stream to write to.
 *  timestamp    time_t    The timestamp to be written.
 * Output:
 *  return          int    0 - OK.
 *                         1 - Error.
 */
static int _glh_write_timestamp(FILE *fp, time_t timestamp)
{
  struct tm *t;  /* THe broken-down calendar time */
/*
 * Get the calendar components corresponding to the given timestamp.
 */
  if(timestamp < 0 || (t = localtime(&timestamp)) == NULL) {
    if(fprintf(fp, "?") < 0)
      return 1;
    return 0;
  };
/*
 * Write the calendar time as yyyymmddhhmmss.
 */
  if(fprintf(fp, "%04d%02d%02d%02d%02d%02d", t->tm_year + 1900, t->tm_mon + 1,
	     t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec) < 0)
    return 1;
  return 0;
}

#endif

/*.......................................................................
 * Restore previous history lines from a given file.
 *
 * Input:
 *  glh        GlHistory *  The input-line history maintenance object.
 *  filename  const char *  The name of the file to read from.
 *  comment   const char *  The same comment string that was passed to
 *                          _glh_save_history() when this file was
 *                          written.
 *  line            char *  A buffer into which lines can be read.
 *  dim            size_t   The allocated dimension of line[].
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error.
 */
int _glh_load_history(GlHistory *glh, const char *filename, const char *comment,
		      char *line, size_t dim)
{
#ifdef WITHOUT_FILE_SYSTEM
  _err_record_msg(glh->err, "Can't load history without filesystem access",
		  END_ERR_MSG);
  errno = EINVAL;
  return 1;
#else
  FILE *fp;            /* The output file */
  size_t comment_len;  /* The length of the comment string */
  time_t timestamp;    /* The timestamp of the history line */
  unsigned group;      /* The identifier of the history group to which */
                       /*  the line belongs. */
  int lineno;          /* The line number being read */
/*
 * Check the arguments.
 */
  if(!glh || !filename || !comment || !line) {
    if(glh)
      _err_record_msg(glh->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Measure the length of the comment string.
 */
  comment_len = strlen(comment);
/*
 * Clear the history list.
 */
  _glh_clear_history(glh, 1);
/*
 * Attempt to open the specified file. Don't treat it as an error
 * if the file doesn't exist.
 */
  fp = fopen(filename, "r");
  if(!fp)
    return 0;
/*
 * Attempt to read each line and preceding peripheral info, and add these
 * to the history list.
 */
  for(lineno=1; fgets(line, dim, fp) != NULL; lineno++) {
    char *lptr;          /* A pointer into the input line */
/*
 * Check that the line starts with the comment string.
 */
    if(strncmp(line, comment, comment_len) != 0) {
      return _glh_cant_load_history(glh, filename, lineno,
				    "Corrupt history parameter line", fp);
    };
/*
 * Skip spaces and tabs after the comment.
 */
    for(lptr=line+comment_len; *lptr && (*lptr==' ' || *lptr=='\t'); lptr++)
      ;
/*
 * The next word must be a timestamp.
 */
    if(_glh_decode_timestamp(lptr, &lptr, &timestamp)) {
      return _glh_cant_load_history(glh, filename, lineno,
				    "Corrupt timestamp", fp);
    };
/*
 * Skip spaces and tabs.
 */
    while(*lptr==' ' || *lptr=='\t')
      lptr++;
/*
 * The next word must be an unsigned integer group number.
 */
    group = (int) strtoul(lptr, &lptr, 10);
    if(*lptr != ' ' && *lptr != '\n') {
      return _glh_cant_load_history(glh, filename, lineno,
				    "Corrupt group id", fp);
    };
/*
 * Skip spaces and tabs.
 */
    while(*lptr==' ' || *lptr=='\t')
      lptr++;
/*
 * There shouldn't be anything left on the line.
 */
    if(*lptr != '\n') {
      return _glh_cant_load_history(glh, filename, lineno,
				    "Corrupt parameter line", fp);
    };
/*
 * Now read the history line itself.
 */
    lineno++;
    if(fgets(line, dim, fp) == NULL)
      return _glh_cant_load_history(glh, filename, lineno, "Read error", fp);
/*
 * Append the line to the history buffer.
 */
    if(_glh_add_history(glh, line, 1)) {
      return _glh_cant_load_history(glh, filename, lineno,
				    "Insufficient memory to record line", fp);
    };
/*
 * Record the group and timestamp information along with the line.
 */
    if(glh->list.tail) {
      glh->list.tail->timestamp = timestamp;
      glh->list.tail->group = group;
    };
  };
/*
 * Close the file.
 */
  (void) fclose(fp);
  return 0;
#endif
}

#ifndef WITHOUT_FILE_SYSTEM
/*.......................................................................
 * This is a private error return function of _glh_load_history().
 */
static int _glh_cant_load_history(GlHistory *glh, const char *filename,
				  int lineno, const char *message, FILE *fp)
{
  char lnum[20];
/*
 * Convert the line number to a string.
 */
  snprintf(lnum, sizeof(lnum), "%d", lineno);
/*
 * Render an error message.
 */
  _err_record_msg(glh->err, filename, ":", lnum, ":", message, END_ERR_MSG);
/*
 * Close the file.
 */
  if(fp)
    (void) fclose(fp);
  return 1;
}

/*.......................................................................
 * Read a timestamp from a string.
 *
 * Input:
 *  string    char *  The string to read from.
 * Input/Output:
 *  endp        char ** On output *endp will point to the next unprocessed
 *                      character in string[].
 *  timestamp time_t *  The timestamp will be assigned to *t.
 * Output:
 *  return       int    0 - OK.
 *                      1 - Error.
 */
static int _glh_decode_timestamp(char *string, char **endp, time_t *timestamp)
{
  unsigned year,month,day,hour,min,sec;  /* Calendar time components */
  struct tm t;
/*
 * There are 14 characters in the date format yyyymmddhhmmss.
 */
  enum {TSLEN=14};                    
  char timestr[TSLEN+1];   /* The timestamp part of the string */
/*
 * If the time wasn't available at the time that the line was recorded
 * it will have been written as "?". Check for this before trying
 * to read the timestamp.
 */
  if(string[0] == '\?') {
    *endp = string+1;
    *timestamp = -1;
    return 0;
  };
/*
 * The timestamp is expected to be written in the form yyyymmddhhmmss.
 */
  if(strlen(string) < TSLEN) {
    *endp = string;
    return 1;
  };
/*
 * Copy the timestamp out of the string.
 */
  strncpy(timestr, string, TSLEN);
  timestr[TSLEN] = '\0';
/*
 * Decode the timestamp.
 */
  if(sscanf(timestr, "%4u%2u%2u%2u%2u%2u", &year, &month, &day, &hour, &min,
	    &sec) != 6) {
    *endp = string;
    return 1;
  };
/*
 * Advance the string pointer over the successfully read timestamp.
 */
  *endp = string + TSLEN;
/*
 * Copy the read values into a struct tm.
 */
  t.tm_sec = sec;
  t.tm_min = min;
  t.tm_hour = hour;
  t.tm_mday = day;
  t.tm_wday = 0;
  t.tm_yday = 0;
  t.tm_mon = month - 1;
  t.tm_year = year - 1900;
  t.tm_isdst = -1;
/*
 * Convert the contents of the struct tm to a time_t.
 */
  *timestamp = mktime(&t);
  return 0;
}
#endif

/*.......................................................................
 * Switch history groups.
 *
 * Input:
 *  glh        GlHistory *  The input-line history maintenance object.
 *  group       unsigned    The new group identifier. This will be recorded
 *                          with subsequent history lines, and subsequent
 *                          history searches will only return lines with
 *                          this group identifier. This allows multiple
 *                          separate history lists to exist within
 *                          a single GlHistory object. Note that the
 *                          default group identifier is 0.
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error.
 */
int _glh_set_group(GlHistory *glh, unsigned group)
{
/*
 * Check the arguments.
 */
  if(!glh) {
    if(glh)
      _err_record_msg(glh->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Is the group being changed?
 */
  if(group != glh->group) {
/*
 * Cancel any ongoing search.
 */
    if(_glh_cancel_search(glh))
      return 1;
/*
 * Record the new group.
 */
    glh->group = group;
  };
  return 0;
}

/*.......................................................................
 * Query the current history group.
 *
 * Input:
 *  glh        GlHistory *  The input-line history maintenance object.
 * Output:
 *  return      unsigned    The group identifier.    
 */
int _glh_get_group(GlHistory *glh)
{
  return glh ? glh->group : 0;
}

/*.......................................................................
 * Display the contents of the history list.
 *
 * Input:
 *  glh       GlHistory *  The input-line history maintenance object.
 *  write_fn  GlWriteFn *  The function to call to write the line, or
 *                         0 to discard the output.
 *  data           void *  Anonymous data to pass to write_fn().
 *  fmt      const char *  A format string. This can contain arbitrary
 *                         characters, which are written verbatim, plus
 *                         any of the following format directives:
 *                          %D  -  The date, like 2001-11-20
 *                          %T  -  The time of day, like 23:59:59
 *                          %N  -  The sequential entry number of the
 *                                 line in the history buffer.
 *                          %G  -  The history group number of the line.
 *                          %%  -  A literal % character.
 *                          %H  -  The history line.
 *  all_groups      int    If true, display history lines from all
 *                         history groups. Otherwise only display
 *                         those of the current history group.
 *  max_lines       int    If max_lines is < 0, all available lines
 *                         are displayed. Otherwise only the most
 *                         recent max_lines lines will be displayed.
 * Output:
 *  return          int    0 - OK.
 *                         1 - Error.
 */
int _glh_show_history(GlHistory *glh, GlWriteFn *write_fn, void *data,
		      const char *fmt, int all_groups, int max_lines)
{
  GlhLineNode *node;     /* The line being displayed */
  GlhLineNode *oldest;   /* The oldest line to display */
  GlhLineSeg *seg;       /* One segment of a line being displayed */
  enum {TSMAX=32};       /* The maximum length of the date and time string */
  char buffer[TSMAX+1];  /* The buffer in which to write the date and time */
  int idlen;             /* The length of displayed ID strings */
  unsigned grpmax;       /* The maximum group number in the buffer */
  int grplen;            /* The number of characters needed to print grpmax */
  int len;               /* The length of a string to be written */
/*
 * Check the arguments.
 */
  if(!glh || !write_fn || !fmt) {
    if(glh)
      _err_record_msg(glh->err, "NULL argument(s)", END_ERR_MSG);
    errno = EINVAL;
    return 1;
  };
/*
 * Is history enabled?
 */
  if(!glh->enable || !glh->list.head)
    return 0;
/*
 * Work out the length to display ID numbers, choosing the length of
 * the biggest number in the buffer. Smaller numbers will be padded 
 * with leading zeroes if needed.
 */
  snprintf(buffer, sizeof(buffer), "%lu", (unsigned long) glh->list.tail->id);
  idlen = strlen(buffer);
/*
 * Find the largest group number.
 */
  grpmax = 0;
  for(node=glh->list.head; node; node=node->next) {
    if(node->group > grpmax)
      grpmax = node->group;
  };
/*
 * Find out how many characters are needed to display the group number.
 */
  snprintf(buffer, sizeof(buffer), "%u", (unsigned) grpmax);
  grplen = strlen(buffer);
/*
 * Find the node that follows the oldest line to be displayed.
 */
  if(max_lines < 0) {
    oldest = glh->list.head;
  } else if(max_lines==0) {
    return 0;
  } else {
    for(oldest=glh->list.tail; oldest; oldest=oldest->prev) {
      if((all_groups || oldest->group == glh->group) && --max_lines <= 0)
	break;
    };
/*
 * If the number of lines in the buffer doesn't exceed the specified
 * maximum, start from the oldest line in the buffer.
 */
    if(!oldest)
      oldest = glh->list.head;
  };
/*
 * List the history lines in increasing time order.
 */
  for(node=oldest; node; node=node->next) {
/*
 * Only display lines from the current history group, unless
 * told otherwise.
 */
    if(all_groups || node->group == glh->group) {
      const char *fptr;      /* A pointer into the format string */
      struct tm *t = NULL;   /* The broken time version of the timestamp */
/*
 * Work out the calendar representation of the node timestamp.
 */
      if(node->timestamp != (time_t) -1)
	t = localtime(&node->timestamp);
/*
 * Parse the format string.
 */
      fptr = fmt;
      while(*fptr) {
/*
 * Search for the start of the next format directive or the end of the string.
 */
	const char *start = fptr;
	while(*fptr && *fptr != '%')
	  fptr++;
/*
 * Display any literal characters that precede the located directive.
 */
	if(fptr > start) {
	  len = (int) (fptr - start);
	  if(write_fn(data, start, len) != len)
	    return 1;
	};
/*
 * Did we hit a new directive before the end of the line?
 */
	if(*fptr) {
/*
 * Obey the directive. Ignore unknown directives.
 */
	  switch(*++fptr) {
	  case 'D':          /* Display the date */
	    if(t && strftime(buffer, TSMAX, "%Y-%m-%d", t) != 0) {
	      len = strlen(buffer);
	      if(write_fn(data, buffer, len) != len)
		return 1;
	    };
	    break;
	  case 'T':          /* Display the time of day */
	    if(t && strftime(buffer, TSMAX, "%H:%M:%S", t) != 0) {
	      len = strlen(buffer);
	      if(write_fn(data, buffer, len) != len)
		return 1;
	    };
	    break;
	  case 'N':          /* Display the sequential entry number */
	    snprintf(buffer, sizeof(buffer), "%*lu", idlen, (unsigned long) node->id);
	    len = strlen(buffer);
	    if(write_fn(data, buffer, len) != len)
	      return 1;
	    break;
	  case 'G':
	    snprintf(buffer, sizeof(buffer), "%*u", grplen, (unsigned) node->group);
	    len = strlen(buffer);
	    if(write_fn(data, buffer, len) != len)
	      return 1;
	    break;
	  case 'H':          /* Display the history line */
	    for(seg=node->line->head; seg; seg=seg->next) {
	      len = seg->next ? GLH_SEG_SIZE : strlen(seg->s);
	      if(write_fn(data, seg->s, len) != len)
		return 1;
	    };
	    break;
	  case '%':          /* A literal % symbol */
	    if(write_fn(data, "%", 1) != 1)
	      return 1;
	    break;
	  };
/*
 * Skip the directive.
 */
	  if(*fptr)
	    fptr++;
	};
      };
    };
  };
  return 0;
}

/*.......................................................................
 * Change the size of the history buffer.
 *
 * Input:
 *  glh    GlHistory *  The input-line history maintenance object.
 *  bufsize   size_t    The number of bytes in the history buffer, or 0
 *                      to delete the buffer completely.
 * Output:
 *  return       int    0 - OK.
 *                      1 - Insufficient memory (the previous buffer
 *                          will have been retained). No error message
 *                          will be displayed.
 */
int _glh_resize_history(GlHistory *glh, size_t bufsize)
{
  int nbuff;     /* The number of segments in the new buffer */
  int i;
/*
 * Check the arguments.
 */
  if(!glh) {
    errno = EINVAL;
    return 1;
  };
/*
 * How many buffer segments does the requested buffer size correspond
 * to?
 */
  nbuff = (bufsize+GLH_SEG_SIZE-1) / GLH_SEG_SIZE;
/*
 * Has a different size than the current size been requested?
 */
  if(glh->nbuff != nbuff) {
/*
 * Cancel any ongoing search.
 */
    (void) _glh_cancel_search(glh);
/*
 * Create a wholly new buffer?
 */
    if(glh->nbuff == 0 && nbuff>0) {
      glh->buffer = (GlhLineSeg *) malloc(sizeof(GlhLineSeg) * nbuff);
      if(!glh->buffer)
	return 1;
      glh->nbuff = nbuff;
      glh->nfree = glh->nbuff;
      glh->nbusy = 0;
      glh->nline = 0;
/*
 * Link the currently unused nodes of the buffer into a list.
 */
      glh->unused = glh->buffer;
      for(i=0; i<glh->nbuff-1; i++) {
	GlhLineSeg *seg = glh->unused + i;
	seg->next = seg + 1;
      };
      glh->unused[i].next = NULL;
/*
 * Delete an existing buffer?
 */
    } else if(nbuff == 0) {
      _glh_clear_history(glh, 1);
      free(glh->buffer);
      glh->buffer = NULL;
      glh->unused = NULL;
      glh->nbuff = 0;
      glh->nfree = 0;
      glh->nbusy = 0;
      glh->nline = 0;
/*
 * Change from one finite buffer size to another?
 */
    } else {
      GlhLineSeg *buffer; /* The resized buffer */
      int nbusy;      /* The number of used line segments in the new buffer */
/*
 * Starting from the oldest line in the buffer, discard lines until
 * the buffer contains at most 'nbuff' used line segments.
 */
      while(glh->list.head && glh->nbusy > nbuff)
	_glh_discard_line(glh, glh->list.head);
/*
 * Attempt to allocate a new buffer.
 */
      buffer = (GlhLineSeg *) malloc(nbuff * sizeof(GlhLineSeg));
      if(!buffer) {
	errno = ENOMEM;
	return 1;
      };
/*
 * Copy the used segments of the old buffer to the start of the new buffer.
 */
      nbusy = 0;
      for(i=0; i<GLH_HASH_SIZE; i++) {
	GlhHashBucket *b = glh->hash.bucket + i;
	GlhHashNode *hnode;
	for(hnode=b->lines; hnode; hnode=hnode->next) {
	  GlhLineSeg *seg = hnode->head;
	  hnode->head = buffer + nbusy;
	  for( ; seg; seg=seg->next) {
	    buffer[nbusy] = *seg;
	    buffer[nbusy].next = seg->next ? &buffer[nbusy+1] : NULL;
	    nbusy++;
	  };
	};
      };
/*
 * Make a list of the new buffer's unused segments.
 */
      for(i=nbusy; i<nbuff-1; i++)
	buffer[i].next = &buffer[i+1];
      if(i < nbuff)
	buffer[i].next = NULL;
/*
 * Discard the old buffer.
 */
      free(glh->buffer);
/*
 * Install the new buffer.
 */
      glh->buffer = buffer;
      glh->nbuff = nbuff;
      glh->nbusy = nbusy;
      glh->nfree = nbuff - nbusy;
      glh->unused = glh->nfree > 0 ? (buffer + nbusy) : NULL;
    };
  };
  return 0;
}

/*.......................................................................
 * Set an upper limit to the number of lines that can be recorded in the
 * history list, or remove a previously specified limit.
 *
 * Input:
 *  glh    GlHistory *  The input-line history maintenance object.
 *  max_lines    int    The maximum number of lines to allow, or -1 to
 *                      cancel a previous limit and allow as many lines
 *                      as will fit in the current history buffer size.
 */
void _glh_limit_history(GlHistory *glh, int max_lines)
{
  if(!glh)
    return;
/*
 * Apply a new limit?
 */
  if(max_lines >= 0 && max_lines != glh->max_lines) {
/*
 * Count successively older lines until we reach the start of the
 * list, or until we have seen max_lines lines (at which point 'node'
 * will be line number max_lines+1).
 */
    int nline = 0;
    GlhLineNode *node;
    for(node=glh->list.tail; node && ++nline <= max_lines; node=node->prev)
      ;
/*
 * Discard any lines that exceed the limit.
 */
    if(node) {
      GlhLineNode *oldest = node->next;  /* The oldest line to be kept */
/*
 * Delete nodes from the head of the list until we reach the node that
 * is to be kept.
 */
      while(glh->list.head && glh->list.head != oldest)
	_glh_discard_line(glh, glh->list.head);
    };
  };
/*
 * Record the new limit.
 */
  glh->max_lines = max_lines;
  return;
}

/*.......................................................................
 * Discard either all history, or the history associated with the current
 * history group.
 *
 * Input:
 *  glh    GlHistory *  The input-line history maintenance object.
 *  all_groups   int    If true, clear all of the history. If false,
 *                      clear only the stored lines associated with the
 *                      currently selected history group.
 */
void _glh_clear_history(GlHistory *glh, int all_groups)
{
  int i;
/*
 * Check the arguments.
 */
  if(!glh)
    return;
/*
 * Cancel any ongoing search.
 */
  (void) _glh_cancel_search(glh);
/*
 * Delete all history lines regardless of group?
 */
  if(all_groups) {
/*
 * Claer the time-ordered list of lines.
 */
    _rst_FreeList(glh->list.node_mem);
    glh->list.head = glh->list.tail = NULL;
    glh->nline = 0;
    glh->id_node = NULL;
/*
 * Clear the hash table.
 */
    for(i=0; i<GLH_HASH_SIZE; i++)
      glh->hash.bucket[i].lines = NULL;
    _rst_FreeList(glh->hash.node_mem);
/*
 * Move all line segment nodes back onto the list of unused segments.
 */
    if(glh->buffer) {
      glh->unused = glh->buffer;
      for(i=0; i<glh->nbuff-1; i++) {
	GlhLineSeg *seg = glh->unused + i;
	seg->next = seg + 1;
      };
      glh->unused[i].next = NULL;
      glh->nfree = glh->nbuff;
      glh->nbusy = 0;
    } else {
      glh->unused = NULL;
      glh->nbusy = glh->nfree = 0;
    };
/*
 * Just delete lines of the current group?
 */
  } else {
    GlhLineNode *node;  /* The line node being checked */
    GlhLineNode *next;  /* The line node that follows 'node' */
/*
 * Search out and delete the line nodes of the current group.
 */
    for(node=glh->list.head; node; node=next) {
/*
 * Keep a record of the following node before we delete the current
 * node.
 */
      next = node->next;
/*
 * Discard this node?
 */
      if(node->group == glh->group)
	_glh_discard_line(glh, node);
    };
  };
  return;
}

/*.......................................................................
 * Temporarily enable or disable the history list.
 *
 * Input:
 *  glh    GlHistory *  The input-line history maintenance object.
 *  enable       int    If true, turn on the history mechanism. If
 *                      false, disable it.
 */
void _glh_toggle_history(GlHistory *glh, int enable)
{
  if(glh)
    glh->enable = enable;
}

/*.......................................................................
 * Discard a given archived input line.
 *
 * Input:
 *  glh      GlHistory *  The history container object.
 *  node   GlhLineNode *  The line to be discarded, specified via its
 *                        entry in the time-ordered list of historical
 *                        input lines.
 */
static void _glh_discard_line(GlHistory *glh, GlhLineNode *node)
{
/*
 * Remove the node from the linked list.
 */
  if(node->prev)
    node->prev->next = node->next;
  else
    glh->list.head = node->next;
  if(node->next)
    node->next->prev = node->prev;
  else
    glh->list.tail = node->prev;
/*
 * If we are deleting the node that is marked as the start point of the
 * last ID search, remove the cached starting point.
 */
  if(node == glh->id_node)
    glh->id_node = NULL;
/*
 * If we are deleting the node that is marked as the start point of the
 * next prefix search, cancel the search.
 */
  if(node == glh->recall)
    _glh_cancel_search(glh);
/*
 * Delete our copy of the line.
 */
  node->line = _glh_discard_copy(glh, node->line);
/*
 * Return the node to the freelist.
 */
  (void) _del_FreeListNode(glh->list.node_mem, node);
/*
 * Record the removal of a line from the list.
 */
  glh->nline--;
  return;
}

/*.......................................................................
 * Lookup the details of a given history line, given its id.
 *
 * Input:
 *  glh      GlHistory *  The input-line history maintenance object.
 *  id        GlLineID    The sequential number of the line.
 * Input/Output:
 *  line    const char ** A pointer to a copy of the history line will be
 *                        assigned to *line. Beware that this pointer may
 *                        be invalidated by the next call to any public
 *                        history function.
 *  group     unsigned *  The group membership of the line will be assigned
 *                        to *group.
 *  timestamp   time_t *  The timestamp of the line will be assigned to
 *                        *timestamp.
 * Output:
 *  return         int    0 - The requested line wasn't found.
 *                        1 - The line was found.
 */
int _glh_lookup_history(GlHistory *glh, GlhLineID id, const char **line,
			unsigned *group, time_t *timestamp)
{
  GlhLineNode *node; /* The located line location node */
/*
 * Check the arguments.
 */
  if(!glh)
    return 0;
/*
 * Search for the line that has the specified ID.
 */
  node = _glh_find_id(glh, id);
/*
 * Not found?
 */
  if(!node)
    return 0;
/*
 * Has the history line been requested?
 */
  if(line) {
/*
 * If necessary, reallocate the lookup buffer to accomodate the size of
 * a copy of the located line.
 */
    if(node->line->len + 1 > glh->lbuf_dim) {
      int lbuf_dim = node->line->len + 1;
      char *lbuf = realloc(glh->lbuf, lbuf_dim);
      if(!lbuf) {
	errno = ENOMEM;
	return 0;
      };
      glh->lbuf_dim = lbuf_dim;
      glh->lbuf = lbuf;
    };
/*
 * Copy the history line into the lookup buffer.
 */
    _glh_return_line(node->line, glh->lbuf, glh->lbuf_dim);
/*
 * Assign the lookup buffer as the returned line pointer.
 */
    *line = glh->lbuf;
  };    
/*
 * Does the caller want to know the group of the line?
 */
  if(group)
    *group = node->group;
/*
 * Does the caller want to know the timestamp of the line?
 */
  if(timestamp)
    *timestamp = node->timestamp;
  return 1;
}

/*.......................................................................
 * Lookup a node in the history list by its ID.
 *
 * Input:
 *  glh       GlHistory *  The input-line history maintenance object.
 *  id        GlhLineID    The ID of the line to be returned.
 * Output:
 *  return  GlhLIneNode *  The located node, or NULL if not found.
 */
static GlhLineNode *_glh_find_id(GlHistory *glh, GlhLineID id)
{
  GlhLineNode *node;  /* The node being checked */
/*
 * Is history enabled?
 */
  if(!glh->enable || !glh->list.head)
    return NULL;
/*
 * If possible, start at the end point of the last ID search.
 * Otherwise start from the head of the list.
 */
  node = glh->id_node;
  if(!node)
    node = glh->list.head;
/*
 * Search forwards from 'node'?
 */
  if(node->id < id) {
    while(node && node->id != id)
      node = node->next;
    glh->id_node = node ? node : glh->list.tail;
/*
 * Search backwards from 'node'?
 */
  } else {
    while(node && node->id != id)
      node = node->prev;
    glh->id_node = node ? node : glh->list.head;
  };
/*
 * Return the located node (this will be NULL if the ID wasn't found).
 */
  return node;
}

/*.......................................................................
 * Query the state of the history list. Note that any of the input/output
 * pointers can be specified as NULL.
 *
 * Input:
 *  glh         GlHistory *  The input-line history maintenance object.
 * Input/Output:
 *  enabled           int *  If history is enabled, *enabled will be
 *                           set to 1. Otherwise it will be assigned 0.
 *  group        unsigned *  The current history group ID will be assigned
 *                           to *group.
 *  max_lines         int *  The currently requested limit on the number
 *                           of history lines in the list, or -1 if
 *                           unlimited.
 */
void _glh_state_of_history(GlHistory *glh, int *enabled, unsigned *group,
			   int *max_lines)
{
  if(glh) {
    if(enabled)
     *enabled = glh->enable;
    if(group)
     *group = glh->group;
    if(max_lines)
     *max_lines = glh->max_lines;
  };
}

/*.......................................................................
 * Get the range of lines in the history buffer.
 *
 * Input:
 *  glh         GlHistory *  The input-line history maintenance object.
 * Input/Output:
 *  oldest  unsigned long *  The sequential entry number of the oldest
 *                           line in the history list will be assigned
 *                           to *oldest, unless there are no lines, in
 *                           which case 0 will be assigned.
 *  newest  unsigned long *  The sequential entry number of the newest
 *                           line in the history list will be assigned
 *                           to *newest, unless there are no lines, in
 *                           which case 0 will be assigned.
 *  nlines            int *  The number of lines currently in the history
 *                           list.
 */
void _glh_range_of_history(GlHistory *glh, unsigned long *oldest,
			   unsigned long *newest, int *nlines)
{
  if(glh) {
    if(oldest)
      *oldest = glh->list.head ? glh->list.head->id : 0;
    if(newest)
      *newest = glh->list.tail ? glh->list.tail->id : 0;
    if(nlines)
      *nlines = glh->nline;
  };
}

/*.......................................................................
 * Return the size of the history buffer and the amount of the
 * buffer that is currently in use.
 *
 * Input:
 *  glh      GlHistory *  The input-line history maintenance object.
 * Input/Output:
 *  buff_size   size_t *  The size of the history buffer (bytes).
 *  buff_used   size_t *  The amount of the history buffer that
 *                        is currently occupied (bytes).
 */
void _glh_size_of_history(GlHistory *glh, size_t *buff_size, size_t *buff_used)
{
  if(glh) {
    if(buff_size)
      *buff_size = (glh->nbusy + glh->nfree) * GLH_SEG_SIZE;
/*
 * Determine the amount of buffer space that is currently occupied.
 */
    if(buff_used)
      *buff_used = glh->nbusy * GLH_SEG_SIZE;
  };
}

/*.......................................................................
 * Return extra information (ie. in addition to that provided by errno)
 * about the last error to occur in any of the public functions of this
 * module.
 *
 * Input:
 *  glh      GlHistory *  The container of the history list.
 * Output:
 *  return  const char *  A pointer to the internal buffer in which
 *                        the error message is temporarily stored.
 */
const char *_glh_last_error(GlHistory *glh)
{
  return glh ? _err_get_msg(glh->err) : "NULL GlHistory argument";
}

/*.......................................................................
 * Unless already stored, store a copy of the line in the history buffer,
 * then return a reference-counted hash-node pointer to this copy.
 *
 * Input:
 *  glh       GlHistory *   The history maintenance buffer.
 *  line     const char *   The history line to be recorded.
 *  n            size_t     The length of the string, excluding any '\0'
 *                          terminator.
 * Output:
 *  return  GlhHashNode *   The hash-node containing the stored line, or
 *                          NULL on error.
 */
static GlhHashNode *_glh_acquire_copy(GlHistory *glh, const char *line,
				      size_t n)
{
  GlhHashBucket *bucket;   /* The hash-table bucket of the line */
  GlhHashNode *hnode;      /* The hash-table node of the line */
  int i;
/*
 * In which bucket should the line be recorded?
 */
  bucket = glh_find_bucket(glh, line, n);
/*
 * Is the line already recorded there?
 */
  hnode = glh_find_hash_node(bucket, line, n);
/*
 * If the line isn't recorded in the buffer yet, make room for it.
 */
  if(!hnode) {
    GlhLineSeg *seg;   /* A line segment */
    int offset;        /* An offset into line[] */
/*
 * How many string segments will be needed to record the new line,
 * including space for a '\0' terminator?
 */
    int nseg = ((n+1) + GLH_SEG_SIZE-1) /  GLH_SEG_SIZE;
/*
 * Discard the oldest history lines in the buffer until at least
 * 'nseg' segments have been freed up, or until we run out of buffer
 * space.
 */
    while(glh->nfree < nseg && glh->nbusy > 0)
      _glh_discard_line(glh, glh->list.head);
/*
 * If the buffer is smaller than the new line, don't attempt to truncate
 * it to fit. Simply don't archive it.
 */
    if(glh->nfree < nseg)
      return NULL;
/*
 * Record the line in the first 'nseg' segments of the list of unused segments.
 */
    offset = 0;
    for(i=0,seg=glh->unused; i<nseg-1; i++,seg=seg->next, offset+=GLH_SEG_SIZE)
      memcpy(seg->s, line + offset, GLH_SEG_SIZE);
    memcpy(seg->s, line + offset, n-offset);
    seg->s[n-offset] = '\0';
/*
 * Create a new hash-node for the line.
 */
    hnode = (GlhHashNode *) _new_FreeListNode(glh->hash.node_mem);
    if(!hnode)
      return NULL;
/*
 * Move the copy of the line from the list of unused segments to
 * the hash node.
 */
    hnode->head = glh->unused;
    glh->unused = seg->next;
    seg->next = NULL;
    glh->nbusy += nseg;
    glh->nfree -= nseg;
/*
 * Prepend the new hash node to the list within the associated bucket.
 */
    hnode->next = bucket->lines;
    bucket->lines = hnode;
/*
 * Initialize the rest of the members of the hash node.
 */
    hnode->len = n;
    hnode->reported = 0;
    hnode->used = 0;
    hnode->bucket = bucket;
  };
/*
 * Increment the reference count of the line.
 */
  hnode->used++;
  return hnode;
}

/*.......................................................................
 * Decrement the reference count of the history line of a given hash-node,
 * and if the count reaches zero, delete both the hash-node and the
 * buffered copy of the line.
 *
 * Input:
 *  glh      GlHistory *  The history container object.
 *  hnode  GlhHashNode *  The node to be removed.
 * Output:
 *  return GlhHashNode *  The deleted hash-node (ie. NULL).
 */
static GlhHashNode *_glh_discard_copy(GlHistory *glh, GlhHashNode *hnode)
{
  if(hnode) {
    GlhHashBucket *bucket = hnode->bucket;
/*
 * If decrementing the reference count of the hash-node doesn't reduce
 * the reference count to zero, then the line is still in use in another
 * object, so don't delete it yet. Return NULL to indicate that the caller's
 * access to the hash-node copy has been deleted.
 */
    if(--hnode->used >= 1)
      return NULL;
/*
 * Remove the hash-node from the list in its parent bucket.
 */
    if(bucket->lines == hnode) {
      bucket->lines = hnode->next;
    } else {
      GlhHashNode *prev;    /* The node which precedes hnode in the bucket */
      for(prev=bucket->lines; prev && prev->next != hnode; prev=prev->next)
	;
      if(prev)
	prev->next = hnode->next;
    };
    hnode->next = NULL;
/*
 * Return the line segments of the hash-node to the list of unused segments.
 */
    if(hnode->head) {
      GlhLineSeg *tail; /* The last node in the list of line segments */
      int nseg;         /* The number of segments being discarded */
/*
 * Get the last node of the list of line segments referenced in the hash-node,
 * while counting the number of line segments used.
 */
      for(nseg=1,tail=hnode->head; tail->next; nseg++,tail=tail->next)
	;
/*
 * Prepend the list of line segments used by the hash node to the
 * list of unused line segments.
 */
      tail->next = glh->unused;
      glh->unused = hnode->head;
      glh->nbusy -= nseg;
      glh->nfree += nseg;
    };
/*
 * Return the container of the hash-node to the freelist.
 */
    hnode = (GlhHashNode *) _del_FreeListNode(glh->hash.node_mem, hnode);
  };
  return NULL;
}

/*.......................................................................
 * Private function to locate the hash bucket associated with a given
 * history line.
 *
 * This uses a hash-function described in the dragon-book
 * ("Compilers - Principles, Techniques and Tools", by Aho, Sethi and
 *  Ullman; pub. Adison Wesley) page 435.
 *
 * Input:
 *  glh        GlHistory *   The history container object.
 *  line      const char *   The historical line to look up.
 *  n             size_t     The length of the line in line[], excluding
 *                           any '\0' terminator.
 * Output:
 *  return GlhHashBucket *   The located hash-bucket.
 */
static GlhHashBucket *glh_find_bucket(GlHistory *glh, const char *line,
				      size_t n)
{
  unsigned long h = 0L;
  int i;
  for(i=0; i<n; i++) {
    unsigned char c = line[i];
    h = 65599UL * h + c;  /* 65599 is a prime close to 2^16 */
  };
  return glh->hash.bucket + (h % GLH_HASH_SIZE);
}

/*.......................................................................
 * Find a given history line within a given hash-table bucket.
 *
 * Input:
 *  bucket  GlhHashBucket *  The hash-table bucket in which to search.
 *  line       const char *  The historical line to lookup.
 *  n             size_t     The length of the line in line[], excluding
 *                           any '\0' terminator.
 * Output:
 *  return    GlhHashNode *  The hash-table entry of the line, or NULL
 *                           if not found.
 */
static GlhHashNode *glh_find_hash_node(GlhHashBucket *bucket, const char *line,
				       size_t n)
{
  GlhHashNode *node;  /* A node in the list of lines in the bucket */
/*
 * Compare each of the lines in the list of lines, against 'line'.
 */
  for(node=bucket->lines; node; node=node->next) {
    if(_glh_is_line(node, line, n))
      return node;
  };
  return NULL;
}

/*.......................................................................
 * Return non-zero if a given string is equal to a given segmented line
 * node.
 *
 * Input:
 *  hash   GlhHashNode *   The hash-table entry of the line.
 *  line    const char *   The string to be compared to the segmented
 *                         line.
 *  n           size_t     The length of the line in line[], excluding
 *                         any '\0' terminator.
 * Output:
 *  return         int     0 - The lines differ.
 *                         1 - The lines are the same.
 */
static int _glh_is_line(GlhHashNode *hash, const char *line, size_t n)
{
  GlhLineSeg *seg;   /* A node in the list of line segments */
  int i;
/*
 * Do the two lines have the same length?
 */
  if(n != hash->len)
    return 0;
/*
 * Compare the characters of the segmented and unsegmented versions
 * of the line.
 */
  for(seg=hash->head; n>0 && seg; seg=seg->next) {
    const char *s = seg->s;
    for(i=0; n>0 && i<GLH_SEG_SIZE; i++,n--) {
      if(*line++ != *s++)
	return 0;
    };
  };
  return 1;
}

/*.......................................................................
 * Return non-zero if a given line has the specified segmented search
 * prefix.
 *
 * Input:
 *  line   GlhHashNode *   The line to be compared against the prefix.
 *  prefix GlhHashNode *   The search prefix, or NULL to match any string.
 * Output:
 *  return         int     0 - The line doesn't have the specified prefix.
 *                         1 - The line has the specified prefix.
 */
static int _glh_line_matches_prefix(GlhHashNode *line, GlhHashNode *prefix)
{
  GlhLineStream lstr; /* The stream that is used to traverse 'line' */
  GlhLineStream pstr; /* The stream that is used to traverse 'prefix' */
/*
 * When prefix==NULL, this means that the nul string
 * is to be matched, and this matches all lines.
 */
  if(!prefix)
    return 1;
/*
 * Wrap the two history lines that are to be compared in iterator
 * stream objects.
 */
  glh_init_stream(&lstr, line);
  glh_init_stream(&pstr, prefix);
/*
 * If the prefix contains a glob pattern, match the prefix as a glob
 * pattern.
 */
  if(glh_contains_glob(prefix))
    return glh_line_matches_glob(&lstr, &pstr);
/*
 * Is the prefix longer than the line being compared against it?
 */
  if(prefix->len > line->len)
    return 0;
/*
 * Compare the line to the prefix.
 */
  while(pstr.c != '\0' && pstr.c == lstr.c) {
    glh_step_stream(&lstr);
    glh_step_stream(&pstr);
  };
/*
 * Did we reach the end of the prefix string before finding
 * any differences?
 */
  return pstr.c == '\0';
}

/*.......................................................................
 * Copy a given history line into a specified output string.
 *
 * Input:
 *  hash  GlhHashNode    The hash-table entry of the history line to
 *                       be copied.
 *  line         char *  A copy of the history line.
 *  dim        size_t    The allocated dimension of the line buffer.
 */
static void _glh_return_line(GlhHashNode *hash, char *line, size_t dim)
{
  GlhLineSeg *seg;   /* A node in the list of line segments */
  int i;
  for(seg=hash->head; dim>0 && seg; seg=seg->next) {
    const char *s = seg->s;
    for(i=0; dim>0 && i<GLH_SEG_SIZE; i++,dim--)
      *line++ = *s++;
  };
/*
 * If the line wouldn't fit in the output buffer, replace the last character
 * with a '\0' terminator.
 */
  if(dim==0)
    line[-1] = '\0';
}

/*.......................................................................
 * This function should be called whenever a new line recall is
 * attempted.  It preserves a copy of the current input line in the
 * history list while other lines in the history list are being
 * returned.
 *
 * Input:
 *  glh  GlHistory *  The input-line history maintenance object.
 *  line      char *  The current contents of the input line buffer.
 * Output:
 *  return     int    0 - OK.
 *                    1 - Error.
 */
static int _glh_prepare_for_recall(GlHistory *glh, char *line)
{
/*
 * If a recall session has already been started, but we have returned
 * to the preserved copy of the input line, if the user has changed
 * this line, we should replace the preserved copy of the original
 * input line with the new one. To do this simply cancel the session,
 * so that a new session is started below.
 */
  if(glh->recall && glh->recall == glh->list.tail &&
     !_glh_is_line(glh->recall->line, line, strlen(line))) {
    _glh_cancel_search(glh);
  };
/*
 * If this is the first line recall of a new recall session, save the
 * current line for potential recall later, and mark it as the last
 * line recalled.
 */
  if(!glh->recall) {
    if(_glh_add_history(glh, line, 1))
      return 1;
    glh->recall = glh->list.tail;
/*
 * The above call to _glh_add_history() will have incremented the line
 * sequence number, after adding the line. Since we only want this to
 * to be incremented for permanently entered lines, decrement it again.
 */
    glh->seq--;
  };
  return 0;
}

/*.......................................................................
 * Return non-zero if a history search session is currently in progress.
 *
 * Input:
 *  glh  GlHistory *  The input-line history maintenance object.
 * Output:
 *  return     int    0 - No search is currently in progress.
 *                    1 - A search is in progress.
 */
int _glh_search_active(GlHistory *glh)
{
  return glh && glh->recall;
}

/*.......................................................................
 * Initialize a character iterator object to point to the start of a
 * given history line. The first character of the line will be placed
 * in str->c, and subsequent characters can be placed there by calling
 * glh_strep_stream().
 *
 * Input:
 *  str  GlhLineStream *  The iterator object to be initialized.
 *  line   GlhHashNode *  The history line to be iterated over (a
 *                        NULL value here, is interpretted as an
 *                        empty string by glh_step_stream()).
 */
static void glh_init_stream(GlhLineStream *str, GlhHashNode *line)
{
  str->seg = line ? line->head : NULL;
  str->posn = 0;
  str->c = str->seg ? str->seg->s[0] : '\0';
}

/*.......................................................................
 * Copy the next unread character in the line being iterated, in str->c.
 * Once the end of the history line has been reached, all futher calls
 * set str->c to '\0'.
 *
 * Input:
 *  str   GlhLineStream *  The history-line iterator to read from.
 */
static void glh_step_stream(GlhLineStream *str)
{
/*
 * Get the character from the current iterator position within the line.
 */
  str->c = str->seg ? str->seg->s[str->posn] : '\0';
/*
 * Unless we have reached the end of the string, move the iterator
 * to the position of the next character in the line.
 */
  if(str->c != '\0' && ++str->posn >= GLH_SEG_SIZE) {
    str->posn = 0;
    str->seg = str->seg->next;
  };
}

/*.......................................................................
 * Return non-zero if the specified search prefix contains any glob
 * wildcard characters.
 *
 * Input:
 *  prefix   GlhHashNode *  The search prefix.
 * Output:
 *  return           int    0 - The prefix doesn't contain any globbing
 *                              characters.
 *                          1 - The prefix contains at least one
 *                              globbing character.
 */
static int glh_contains_glob(GlhHashNode *prefix)
{
  GlhLineStream pstr; /* The stream that is used to traverse 'prefix' */
/*
 * Wrap a stream iterator around the prefix, so that we can traverse it
 * without worrying about line-segmentation.
 */
  glh_init_stream(&pstr, prefix);
/*
 * Search for unescaped wildcard characters.
 */
  while(pstr.c != '\0') {
    switch(pstr.c) {
    case '\\':                      /* Skip escaped characters */
      glh_step_stream(&pstr);
      break; 
    case '*': case '?': case '[':   /* A wildcard character? */
      return 1;
      break;
    };
    glh_step_stream(&pstr);
  };
/*
 * No wildcard characters were found.
 */
  return 0;
}

/*.......................................................................
 * Return non-zero if the history line matches a search prefix containing
 * a glob pattern.
 *
 * Input:
 *  lstr  GlhLineStream *  The iterator stream being used to traverse
 *                         the history line that is being matched.
 *  pstr  GlhLineStream *  The iterator stream being used to traverse
 *                         the pattern.
 * Output:
 *  return    int          0 - Doesn't match.
 *                         1 - The line matches the pattern.
 */
static int glh_line_matches_glob(GlhLineStream *lstr, GlhLineStream *pstr)
{
/*
 * Match each character of the pattern until we reach the end of the
 * pattern.
 */
  while(pstr->c != '\0') {
/*
 * Handle the next character of the pattern.
 */
    switch(pstr->c) {
/*
 * A match zero-or-more characters wildcard operator.
 */
    case '*':
/*
 * Skip the '*' character in the pattern.
 */
      glh_step_stream(pstr);
/*
 * If the pattern ends with the '*' wildcard, then the
 * rest of the line matches this.
 */
      if(pstr->c == '\0')
	return 1;
/*
 * Using the wildcard to match successively longer sections of
 * the remaining characters of the line, attempt to match
 * the tail of the line against the tail of the pattern.
 */
      while(lstr->c) {
	GlhLineStream old_lstr = *lstr;
	GlhLineStream old_pstr = *pstr;
	if(glh_line_matches_glob(lstr, pstr))
	  return 1;
/*
 * Restore the line and pattern iterators for a new try.
 */
	*lstr = old_lstr;
	*pstr = old_pstr;
/*
 * Prepare to try again, one character further into the line.
 */
	glh_step_stream(lstr);
      };
      return 0; /* The pattern following the '*' didn't match */
      break;
/*
 * A match-one-character wildcard operator.
 */
    case '?':
/*
 * If there is a character to be matched, skip it and advance the
 * pattern pointer.
 */
      if(lstr->c) {
	glh_step_stream(lstr);
	glh_step_stream(pstr);
/*
 * If we hit the end of the line, there is no character
 * matching the operator, so the pattern doesn't match.
 */
      } else {
        return 0;
      };
      break;
/*
 * A character range operator, with the character ranges enclosed
 * in matching square brackets.
 */
    case '[':
      glh_step_stream(pstr);  /* Skip the '[' character */
      if(!lstr->c || !glh_matches_range(lstr->c, pstr))
        return 0;
      glh_step_stream(lstr);  /* Skip the character that matched */
      break;
/*
 * A backslash in the pattern prevents the following character as
 * being seen as a special character.
 */
    case '\\':
      glh_step_stream(pstr);  /* Skip the backslash */
      /* Note fallthrough to default */
/*
 * A normal character to be matched explicitly.
 */
      /* FALLTHROUGH */
    default:
      if(lstr->c == pstr->c) {
	glh_step_stream(lstr);
	glh_step_stream(pstr);
      } else {
        return 0;
      };
      break;
    };
  };
/*
 * To get here, pattern must have been exhausted. The line only
 * matches the pattern if the line as also been exhausted.
 */
  return pstr->c == '\0' && lstr->c == '\0';
}

/*.......................................................................
 * Match a character range expression terminated by an unescaped close
 * square bracket.
 *
 * Input:
 *  c              char    The character to be matched with the range
 *                         pattern.
 *  pstr  GlhLineStream *  The iterator stream being used to traverse
 *                         the pattern.
 * Output:
 *  return          int    0 - Doesn't match.
 *                         1 - The character matched.
 */
static int glh_matches_range(char c, GlhLineStream *pstr)
{
  int invert = 0;              /* True to invert the sense of the match */
  int matched = 0;             /* True if the character matched the pattern */
  char lastc = '\0';           /* The previous character in the pattern */
/*
 * If the first character is a caret, the sense of the match is
 * inverted and only if the character isn't one of those in the
 * range, do we say that it matches.
 */
  if(pstr->c == '^') {
    glh_step_stream(pstr);
    invert = 1;
  };
/*
 * The hyphen is only a special character when it follows the first
 * character of the range (not including the caret).
 */
  if(pstr->c == '-') {
    glh_step_stream(pstr);
    if(c == '-')
      matched = 1;
/*
 * Skip other leading '-' characters since they make no sense.
 */
    while(pstr->c == '-')
      glh_step_stream(pstr);
  };
/*
 * The hyphen is only a special character when it follows the first
 * character of the range (not including the caret or a hyphen).
 */
  if(pstr->c == ']') {
    glh_step_stream(pstr);
    if(c == ']')
      matched = 1;
  };
/*
 * Having dealt with the characters that have special meanings at
 * the beginning of a character range expression, see if the
 * character matches any of the remaining characters of the range,
 * up until a terminating ']' character is seen.
 */
  while(!matched && pstr->c && pstr->c != ']') {
/*
 * Is this a range of characters signaled by the two end characters
 * separated by a hyphen?
 */
    if(pstr->c == '-') {
      glh_step_stream(pstr);  /* Skip the hyphen */
      if(pstr->c != ']') {
        if(c >= lastc && c <= pstr->c)
	  matched = 1;
      };
/*
 * A normal character to be compared directly.
 */
    } else if(pstr->c == c) {
      matched = 1;
    };
/*
 * Record and skip the character that we just processed.
 */
    lastc = pstr->c;
    if(pstr->c != ']')
      glh_step_stream(pstr);
  };
/*
 * Find the terminating ']'.
 */
  while(pstr->c && pstr->c != ']')
    glh_step_stream(pstr);
/*
 * Did we find a terminating ']'?
 */
  if(pstr->c == ']') {
/*
 * Skip the terminating ']'.
 */
    glh_step_stream(pstr);
/*
 * If the pattern started with a caret, invert the sense of the match.
 */
    if(invert)
      matched = !matched;
/*
 * If the pattern didn't end with a ']', then it doesn't match,
 * regardless of the value of the required sense of the match.
 */
  } else {
    matched = 0;
  };
  return matched;
}

