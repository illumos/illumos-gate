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
 * If file-system access is to be excluded, this module has no function,
 * so all of its code should be excluded.
 */
#ifndef WITHOUT_FILE_SYSTEM

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "freelist.h"
#include "direader.h"
#include "pathutil.h"
#include "homedir.h"
#include "stringrp.h"
#include "libtecla.h"
#include "ioutil.h"
#include "expand.h"
#include "errmsg.h"

/*
 * Specify the number of elements to extend the files[] array by
 * when it proves to be too small. This also sets the initial size
 * of the array.
 */
#define MATCH_BLK_FACT 256

/*
 * A list of directory iterators is maintained using nodes of the
 * following form.
 */
typedef struct DirNode DirNode;
struct DirNode {
  DirNode *next;       /* The next directory in the list */
  DirNode *prev;       /* The node that precedes this node in the list */
  DirReader *dr;       /* The directory reader object */
};

typedef struct {
  FreeList *mem;       /* Memory for DirNode list nodes */
  DirNode *head;       /* The head of the list of used and unused cache nodes */
  DirNode *next;       /* The next unused node between head and tail */
  DirNode *tail;       /* The tail of the list of unused cache nodes */
} DirCache;

/*
 * Specify how many directory cache nodes to allocate at a time.
 */
#define DIR_CACHE_BLK 20

/*
 * Set the maximum length allowed for usernames.
 */
#define USR_LEN 100

/*
 * Set the maximum length allowed for environment variable names.
 */
#define ENV_LEN 100

/*
 * Set the default number of spaces place between columns when listing
 * a set of expansions.
 */
#define EF_COL_SEP 2

struct ExpandFile {
  ErrMsg *err;            /* The error reporting buffer */
  StringGroup *sg;        /* A list of string segments in which */
                          /*  matching filenames are stored. */
  DirCache cache;         /* The cache of directory reader objects */
  PathName *path;         /* The pathname being matched */
  HomeDir *home;          /* Home-directory lookup object */
  int files_dim;          /* The allocated dimension of result.files[] */
  char usrnam[USR_LEN+1]; /* A user name */
  char envnam[ENV_LEN+1]; /* An environment variable name */
  FileExpansion result;   /* The container used to return the results of */
                          /*  expanding a path. */
};

static int ef_record_pathname(ExpandFile *ef, const char *pathname,
			      int remove_escapes);
static char *ef_cache_pathname(ExpandFile *ef, const char *pathname,
			       int remove_escapes);
static void ef_clear_files(ExpandFile *ef);

static DirNode *ef_open_dir(ExpandFile *ef, const char *pathname);
static DirNode *ef_close_dir(ExpandFile *ef, DirNode *node);
static char *ef_expand_special(ExpandFile *ef, const char *path, int pathlen);
static int ef_match_relative_pathname(ExpandFile *ef, DirReader *dr,
				      const char *pattern, int separate);
static int ef_matches_range(int c, const char *pattern, const char **endp);
static int ef_string_matches_pattern(const char *file, const char *pattern,
				      int xplicit, const char *nextp);
static int ef_cmp_strings(const void *v1, const void *v2);

/*
 * Encapsulate the formatting information needed to layout a
 * multi-column listing of expansions.
 */
typedef struct {
  int term_width;     /* The width of the terminal (characters) */
  int column_width;   /* The number of characters within in each column. */
  int ncol;           /* The number of columns needed */
  int nline;          /* The number of lines needed */
} EfListFormat;

/*
 * Given the current terminal width, and a list of file expansions,
 * determine how to best use the terminal width to display a multi-column
 * listing of expansions.
 */
static void ef_plan_listing(FileExpansion *result, int term_width,
			    EfListFormat *fmt);

/*
 * Display a given line of a multi-column list of file-expansions.
 */
static int ef_format_line(FileExpansion *result, EfListFormat *fmt, int lnum,
			  GlWriteFn *write_fn, void *data);

/*.......................................................................
 * Create the resources needed to expand filenames.
 *
 * Output:
 *  return  ExpandFile *  The new object, or NULL on error.
 */
ExpandFile *new_ExpandFile(void)
{
  ExpandFile *ef;  /* The object to be returned */
/*
 * Allocate the container.
 */
  ef = (ExpandFile *) malloc(sizeof(ExpandFile));
  if(!ef) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to del_ExpandFile().
 */
  ef->err = NULL;
  ef->sg = NULL;
  ef->cache.mem = NULL;
  ef->cache.head = NULL;
  ef->cache.next = NULL;
  ef->cache.tail = NULL;
  ef->path = NULL;
  ef->home = NULL;
  ef->result.files = NULL;
  ef->result.nfile = 0;
  ef->usrnam[0] = '\0';
  ef->envnam[0] = '\0';
/*
 * Allocate a place to record error messages.
 */
  ef->err = _new_ErrMsg();
  if(!ef->err)
    return del_ExpandFile(ef);
/*
 * Allocate a list of string segments for storing filenames.
 */
  ef->sg = _new_StringGroup(_pu_pathname_dim());
  if(!ef->sg)
    return del_ExpandFile(ef);
/*
 * Allocate a freelist for allocating directory cache nodes.
 */
  ef->cache.mem = _new_FreeList(sizeof(DirNode), DIR_CACHE_BLK);
  if(!ef->cache.mem)
    return del_ExpandFile(ef);
/*
 * Allocate a pathname buffer.
 */
  ef->path = _new_PathName();
  if(!ef->path)
    return del_ExpandFile(ef);
/*
 * Allocate an object for looking up home-directories.
 */
  ef->home = _new_HomeDir();
  if(!ef->home)
    return del_ExpandFile(ef);
/*
 * Allocate an array for files. This will be extended later if needed.
 */
  ef->files_dim = MATCH_BLK_FACT;
  ef->result.files = (char **) malloc(sizeof(ef->result.files[0]) *
				      ef->files_dim);
  if(!ef->result.files) {
    errno = ENOMEM;
    return del_ExpandFile(ef);
  };
  return ef;
}

/*.......................................................................
 * Delete a ExpandFile object.
 *
 * Input:
 *  ef     ExpandFile *  The object to be deleted.
 * Output:
 *  return ExpandFile *  The deleted object (always NULL).
 */
ExpandFile *del_ExpandFile(ExpandFile *ef)
{
  if(ef) {
    DirNode *dnode;
/*
 * Delete the string segments.
 */
    ef->sg = _del_StringGroup(ef->sg);
/*
 * Delete the cached directory readers.
 */
    for(dnode=ef->cache.head; dnode; dnode=dnode->next)
      dnode->dr = _del_DirReader(dnode->dr);
/*
 * Delete the memory from which the DirNode list was allocated, thus
 * deleting the list at the same time.
 */
    ef->cache.mem = _del_FreeList(ef->cache.mem, 1);
    ef->cache.head = ef->cache.tail = ef->cache.next = NULL;
/*
 * Delete the pathname buffer.
 */
    ef->path = _del_PathName(ef->path);
/*
 * Delete the home-directory lookup object.
 */
    ef->home = _del_HomeDir(ef->home);
/*
 * Delete the array of pointers to files.
 */
    if(ef->result.files) {
      free(ef->result.files);
      ef->result.files = NULL;
    };
/*
 * Delete the error report buffer.
 */
    ef->err = _del_ErrMsg(ef->err);
/*
 * Delete the container.
 */
    free(ef);
  };
  return NULL;
}

/*.......................................................................
 * Expand a pathname, converting ~user/ and ~/ patterns at the start
 * of the pathname to the corresponding home directories, replacing
 * $envvar with the value of the corresponding environment variable,
 * and then, if there are any wildcards, matching these against existing
 * filenames.
 *
 * If no errors occur, a container is returned containing the array of
 * files that resulted from the expansion. If there were no wildcards
 * in the input pathname, this will contain just the original pathname
 * after expansion of ~ and $ expressions. If there were any wildcards,
 * then the array will contain the files that matched them. Note that
 * if there were any wildcards but no existing files match them, this
 * is counted as an error and NULL is returned.
 *
 * The supported wildcards and their meanings are:
 *  *        -  Match any sequence of zero or more characters.
 *  ?        -  Match any single character.
 *  [chars]  -  Match any single character that appears in 'chars'.
 *              If 'chars' contains an expression of the form a-b,
 *              then any character between a and b, including a and b,
 *              matches. The '-' character looses its special meaning
 *              as a range specifier when it appears at the start
 *              of the sequence of characters.
 *  [^chars] -  The same as [chars] except that it matches any single
 *              character that doesn't appear in 'chars'.
 *
 * Wildcard expressions are applied to individual filename components.
 * They don't match across directory separators. A '.' character at
 * the beginning of a filename component must also be matched
 * explicitly by a '.' character in the input pathname, since these
 * are UNIX's hidden files.
 *
 * Input:
 *  ef         ExpandFile *  The pathname expansion resource object.
 *  path             char *  The path name to be expanded.
 *  pathlen           int    The length of the suffix of path[] that
 *                           constitutes the filename to be expanded,
 *                           or -1 to specify that the whole of the
 *                           path string should be used. Note that
 *                           regardless of the value of this argument,
 *                           path[] must contain a '\0' terminated
 *                           string, since this function checks that
 *                           pathlen isn't mistakenly too long.
 * Output:
 *  return  FileExpansion *  A pointer to a container within the given
 *                           ExpandFile object. This contains an array
 *                           of the pathnames that resulted from expanding
 *                           ~ and $ expressions and from matching any
 *                           wildcards, sorted into lexical order.
 *                           This container and its contents will be
 *                           recycled on subsequent calls, so if you need
 *                           to keep the results of two successive runs,
 *                           you will either have to allocate a private
 *                           copy of the array, or use two ExpandFile
 *                           objects.
 *
 *                           On error NULL is returned. A description
 *                           of the error can be acquired by calling the
 *                           ef_last_error() function.
 */
FileExpansion *ef_expand_file(ExpandFile *ef, const char *path, int pathlen)
{
  DirNode *dnode;       /* A directory-reader cache node */
  const char *dirname;  /* The name of the top level directory of the search */
  const char *pptr;     /* A pointer into path[] */
  int wild;             /* True if the path contains any wildcards */
/*
 * Check the arguments.
 */
  if(!ef || !path) {
    if(ef) {
      _err_record_msg(ef->err, "ef_expand_file: NULL path argument",
		      END_ERR_MSG);
    };
    errno = EINVAL;
    return NULL;
  };
/*
 * If the caller specified that the whole of path[] be matched,
 * work out the corresponding length.
 */
  if(pathlen < 0 || pathlen > strlen(path))
    pathlen = strlen(path);
/*
 * Discard previous expansion results.
 */
  ef_clear_files(ef);
/*
 * Preprocess the path, expanding ~/, ~user/ and $envvar references,
 * using ef->path as a work directory and returning a pointer to
 * a copy of the resulting pattern in the cache.
 */
  path = ef_expand_special(ef, path, pathlen);
  if(!path)
    return NULL;
/*
 * Clear the pathname buffer.
 */
  _pn_clear_path(ef->path);
/*
 * Does the pathname contain any wildcards?
 */
  for(wild=0,pptr=path; !wild && *pptr; pptr++) {
    switch(*pptr) {
    case '\\':                      /* Skip escaped characters */
      if(pptr[1])
	pptr++;
      break; 
    case '*': case '?': case '[':   /* A wildcard character? */
      wild = 1;
      break;
    };
  };
/*
 * If there are no wildcards to match, copy the current expanded
 * path into the output array, removing backslash escapes while doing so.
 */
  if(!wild) {
    if(ef_record_pathname(ef, path, 1))
      return NULL;
/*
 * Does the filename exist?
 */
    ef->result.exists = _pu_file_exists(ef->result.files[0]);
/*
 * Match wildcards against existing files.
 */
  } else {
/*
 * Only existing files that match the pattern will be returned in the
 * cache.
 */
    ef->result.exists = 1;
/*
 * Treat matching of the root-directory as a special case since it
 * isn't contained in a directory.
 */
    if(strcmp(path, FS_ROOT_DIR) == 0) {
      if(ef_record_pathname(ef, FS_ROOT_DIR, 0))
	return NULL;
    } else {
/*
 * What should the top level directory of the search be?
 */
      if(strncmp(path, FS_ROOT_DIR, FS_ROOT_DIR_LEN) == 0) {
	dirname = FS_ROOT_DIR;
	if(!_pn_append_to_path(ef->path, FS_ROOT_DIR, -1, 0)) {
	  _err_record_msg(ef->err, "Insufficient memory to record path",
			  END_ERR_MSG);
	  return NULL;
	};
	path += FS_ROOT_DIR_LEN;
      } else {
	dirname = FS_PWD;
      };
/*
 * Open the top-level directory of the search.
 */
      dnode = ef_open_dir(ef, dirname);
      if(!dnode)
	return NULL;
/*
 * Recursively match successive directory components of the path.
 */
      if(ef_match_relative_pathname(ef, dnode->dr, path, 0)) {
	dnode = ef_close_dir(ef, dnode);
	return NULL;
      };
/*
 * Cleanup.
 */
      dnode = ef_close_dir(ef, dnode);
    };
/*
 * No files matched?
 */
    if(ef->result.nfile < 1) {
      _err_record_msg(ef->err, "No files match", END_ERR_MSG);
      return NULL;
    };
/*
 * Sort the pathnames that matched.
 */
    qsort(ef->result.files, ef->result.nfile, sizeof(ef->result.files[0]),
	  ef_cmp_strings);
  };
/*
 * Return the result container.
 */
  return &ef->result;
}

/*.......................................................................
 * Attempt to recursively match the given pattern with the contents of
 * the current directory, descending sub-directories as needed.
 *
 * Input:
 *  ef      ExpandFile *  The pathname expansion resource object.
 *  dr       DirReader *  The directory reader object of the directory
 *                        to be searched.
 *  pattern const char *  The pattern to match with files in the current
 *                        directory.
 *  separate       int    When appending a filename from the specified
 *                        directory to ef->pathname, insert a directory
 *                        separator between the existing pathname and
 *                        the filename, unless separate is zero.
 * Output:
 *  return         int    0 - OK.
 *                        1 - Error.
 */
static int ef_match_relative_pathname(ExpandFile *ef, DirReader *dr,
				       const char *pattern, int separate)
{
  const char *nextp;  /* The pointer to the character that follows the part */
                      /*  of the pattern that is to be matched with files */
                      /*  in the current directory. */
  char *file;         /* The name of the file being matched */
  int pathlen;        /* The length of ef->pathname[] on entry to this */
                      /*  function */
/*
 * Record the current length of the pathname string recorded in
 * ef->pathname[].
 */
  pathlen = strlen(ef->path->name);
/*
 * Get a pointer to the character that follows the end of the part of
 * the pattern that should be matched to files within the current directory.
 * This will either point to a directory separator, or to the '\0' terminator
 * of the pattern string.
 */
  for(nextp=pattern; *nextp && strncmp(nextp, FS_DIR_SEP, FS_DIR_SEP_LEN) != 0;
      nextp++)
    ;
/*
 * Read each file from the directory, attempting to match it to the
 * current pattern.
 */
  while((file=_dr_next_file(dr)) != NULL) {
/*
 * Does the latest file match the pattern up to nextp?
 */
    if(ef_string_matches_pattern(file, pattern, file[0]=='.', nextp)) {
/*
 * Append the new directory entry to the current matching pathname.
 */
      if((separate && _pn_append_to_path(ef->path, FS_DIR_SEP, -1, 0)==NULL) ||
	 _pn_append_to_path(ef->path, file, -1, 0)==NULL) {
	_err_record_msg(ef->err, "Insufficient memory to record path",
			END_ERR_MSG);
	return 1;
      };
/*
 * If we have reached the end of the pattern, record the accumulated
 * pathname in the list of matching files.
 */
      if(*nextp == '\0') {
	if(ef_record_pathname(ef, ef->path->name, 0))
	  return 1;
/*
 * If the matching directory entry is a subdirectory, and the
 * next character of the pattern is a directory separator,
 * recursively call the current function to scan the sub-directory
 * for matches.
 */
      } else if(_pu_path_is_dir(ef->path->name) &&
		strncmp(nextp, FS_DIR_SEP, FS_DIR_SEP_LEN) == 0) {
/*
 * If the pattern finishes with the directory separator, then
 * record the pathame as matching.
 */
	if(nextp[FS_DIR_SEP_LEN] == '\0') {
	  if(ef_record_pathname(ef, ef->path->name, 0))
	    return 1;
/*
 * Match files within the directory.
 */
	} else {
	  DirNode *subdnode = ef_open_dir(ef, ef->path->name);
	  if(subdnode) {
	    if(ef_match_relative_pathname(ef, subdnode->dr,
					   nextp+FS_DIR_SEP_LEN, 1)) {
	      subdnode = ef_close_dir(ef, subdnode);
	      return 1;
	    };
	    subdnode = ef_close_dir(ef, subdnode);
	  };
	};
      };
/*
 * Remove the latest filename from the pathname string, so that
 * another matching file can be appended.
 */
      ef->path->name[pathlen] = '\0';
    };
  };
  return 0;
}

/*.......................................................................
 * Record a new matching filename.
 *
 * Input:
 *  ef        ExpandFile *  The filename-match resource object.
 *  pathname  const char *  The pathname to record.
 *  remove_escapes   int    If true, remove backslash escapes in the
 *                          recorded copy of the pathname.
 * Output:
 *  return           int     0 - OK.
 *                           1 - Error (ef->err will contain a
 *                                      description of the error).
 */
static int ef_record_pathname(ExpandFile *ef, const char *pathname,
			      int remove_escapes)
{
  char *copy;          /* The recorded copy of pathname[] */
/*
 * Attempt to make a copy of the pathname in the cache.
 */
  copy = ef_cache_pathname(ef, pathname, remove_escapes);
  if(!copy)
    return 1;
/*
 * If there isn't room to record a pointer to the recorded pathname in the
 * array of files, attempt to extend the array.
 */
  if(ef->result.nfile + 1 > ef->files_dim) {
    int files_dim = ef->files_dim + MATCH_BLK_FACT;
    char **files = (char **) realloc(ef->result.files,
				     files_dim * sizeof(files[0]));
    if(!files) {
      _err_record_msg(ef->err,
	     "Insufficient memory to record all of the matching filenames",
	     END_ERR_MSG);
      errno = ENOMEM;
      return 1;
    };
    ef->result.files = files;
    ef->files_dim = files_dim;
  };
/*
 * Record a pointer to the new match.
 */
  ef->result.files[ef->result.nfile++] = copy;
  return 0;
}

/*.......................................................................
 * Record a pathname in the cache.
 *
 * Input:
 *  ef       ExpandFile *  The filename-match resource object.
 *  pathname       char *  The pathname to record.
 *  remove_escapes  int    If true, remove backslash escapes in the
 *                         copy of the pathname.
 * Output:
 *  return         char *  The pointer to the copy of the pathname.
 *                         On error NULL is returned and a description
 *                         of the error is left in ef->err.
 */
static char *ef_cache_pathname(ExpandFile *ef, const char *pathname,
			       int remove_escapes)
{
  char *copy = _sg_store_string(ef->sg, pathname, remove_escapes);
  if(!copy)
    _err_record_msg(ef->err, "Insufficient memory to store pathname",
		    END_ERR_MSG);
  return copy;
}

/*.......................................................................
 * Clear the results of the previous expansion operation, ready for the
 * next.
 *
 * Input:
 *  ef    ExpandFile *  The pathname expansion resource object.
 */
static void ef_clear_files(ExpandFile *ef)
{
  _clr_StringGroup(ef->sg);
  _pn_clear_path(ef->path);
  ef->result.exists = 0;
  ef->result.nfile = 0;
  _err_clear_msg(ef->err);
  return;
}

/*.......................................................................
 * Get a new directory reader object from the cache.
 *
 * Input:
 *  ef        ExpandFile *  The pathname expansion resource object.
 *  pathname  const char *  The pathname of the directory.
 * Output:
 *  return       DirNode *  The cache entry of the new directory reader,
 *                          or NULL on error. On error, ef->err will
 *                          contain a description of the error.
 */
static DirNode *ef_open_dir(ExpandFile *ef, const char *pathname)
{
  char *errmsg = NULL;  /* An error message from a called function */
  DirNode *node;        /* The cache node used */
/*
 * Get the directory reader cache.
 */
  DirCache *cache = &ef->cache;
/*
 * Extend the cache if there are no free cache nodes.
 */
  if(!cache->next) {
    node = (DirNode *) _new_FreeListNode(cache->mem);
    if(!node) {
      _err_record_msg(ef->err, "Insufficient memory to open a new directory",
		      END_ERR_MSG);
      return NULL;
    };
/*
 * Initialize the cache node.
 */
    node->next = NULL;
    node->prev = NULL;
    node->dr = NULL;
/*
 * Allocate a directory reader object.
 */
    node->dr = _new_DirReader();
    if(!node->dr) {
      _err_record_msg(ef->err, "Insufficient memory to open a new directory",
		      END_ERR_MSG);
      node = (DirNode *) _del_FreeListNode(cache->mem, node);
      return NULL;
    };
/*
 * Append the node to the cache list.
 */
    node->prev = cache->tail;
    if(cache->tail)
      cache->tail->next = node;
    else
      cache->head = node;
    cache->next = cache->tail = node;
  };
/*
 * Get the first unused node, but don't remove it from the list yet.
 */
  node = cache->next;
/*
 * Attempt to open the specified directory.
 */
  if(_dr_open_dir(node->dr, pathname, &errmsg)) {
    _err_record_msg(ef->err, errmsg, END_ERR_MSG);
    return NULL;
  };
/*
 * Now that we have successfully opened the specified directory,
 * remove the cache node from the list, and relink the list around it.
 */
  cache->next = node->next;
  if(node->prev)
    node->prev->next = node->next;
  else
    cache->head = node->next;
  if(node->next)
    node->next->prev = node->prev;
  else
    cache->tail = node->prev;
  node->next = node->prev = NULL;
/*
 * Return the successfully initialized cache node to the caller.
 */
  return node;
}

/*.......................................................................
 * Return a directory reader object to the cache, after first closing
 * the directory that it was managing.
 *
 * Input:
 *  ef    ExpandFile *  The pathname expansion resource object.
 *  node     DirNode *  The cache entry of the directory reader, as returned
 *                      by ef_open_dir().
 * Output:
 *  return   DirNode *  The deleted DirNode (ie. allways NULL).
 */
static DirNode *ef_close_dir(ExpandFile *ef, DirNode *node)
{
/*
 * Get the directory reader cache.
 */
  DirCache *cache = &ef->cache;
/*
 * Close the directory.
 */
  _dr_close_dir(node->dr);
/*
 * Return the node to the tail of the cache list.
 */
  node->next = NULL;
  node->prev = cache->tail;
  if(cache->tail)
    cache->tail->next = node;
  else
    cache->head = cache->tail = node;
  if(!cache->next)
    cache->next = node;
  return NULL;
}

/*.......................................................................
 * Return non-zero if the specified file name matches a given glob
 * pattern.
 *
 * Input:
 *  file     const char *  The file-name component to be matched to the pattern.
 *  pattern  const char *  The start of the pattern to match against file[].
 *  xplicit         int    If non-zero, the first character must be matched
 *                         explicitly (ie. not with a wildcard).
 *  nextp    const char *  The pointer to the the character following the
 *                         end of the pattern in pattern[].
 * Output:
 *  return    int          0 - Doesn't match.
 *                         1 - The file-name string matches the pattern.
 */
static int ef_string_matches_pattern(const char *file, const char *pattern,
				      int xplicit, const char *nextp)
{
  const char *pptr = pattern; /* The pointer used to scan the pattern */
  const char *fptr = file;    /* The pointer used to scan the filename string */
/*
 * Match each character of the pattern in turn.
 */
  while(pptr < nextp) {
/*
 * Handle the next character of the pattern.
 */
    switch(*pptr) {
/*
 * A match zero-or-more characters wildcard operator.
 */
    case '*':
/*
 * Skip the '*' character in the pattern.
 */
      pptr++;
/*
 * If wildcards aren't allowed, the pattern doesn't match.
 */
      if(xplicit)
	return 0;
/*
 * If the pattern ends with a the '*' wildcard, then the
 * rest of the filename matches this.
 */
      if(pptr >= nextp)
	return 1;
/*
 * Using the wildcard to match successively longer sections of
 * the remaining characters of the filename, attempt to match
 * the tail of the filename against the tail of the pattern.
 */
      for( ; *fptr; fptr++) {
	if(ef_string_matches_pattern(fptr, pptr, 0, nextp))
	  return 1;
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
      if(!xplicit && *fptr) {
        fptr++;
        pptr++;
/*
 * If we hit the end of the filename string, there is no character
 * matching the operator, so the string doesn't match.
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
      if(xplicit || !ef_matches_range(*fptr++, ++pptr, &pptr))
        return 0;
      break;
/*
 * A backslash in the pattern prevents the following character as
 * being seen as a special character.
 */
    case '\\':
      pptr++;
      /* Note fallthrough to default */
/*
 * A normal character to be matched explicitly.
 */
      /* FALLTHROUGH */
    default:
      if(*fptr == *pptr) {
        fptr++;
        pptr++;
      } else {
        return 0;
      };
      break;
    };
/*
 * After passing the first character, turn off the explicit match
 * requirement.
 */
    xplicit = 0;
  };
/*
 * To get here the pattern must have been exhausted. If the filename
 * string matched, then the filename string must also have been
 * exhausted.
 */
  return *fptr == '\0';
}

/*.......................................................................
 * Match a character range expression terminated by an unescaped close
 * square bracket.
 *
 * Input:
 *  c               int     The character to be matched with the range
 *                          pattern.
 *  pattern  const char *   The range pattern to be matched (ie. after the
 *                          initiating '[' character).
 *  endp     const char **  On output a pointer to the character following the
 *                          range expression will be assigned to *endp.
 * Output:
 *  return          int     0 - Doesn't match.
 *                          1 - The character matched.
 */
static int ef_matches_range(int c, const char *pattern, const char **endp)
{
  const char *pptr = pattern;  /* The pointer used to scan the pattern */
  int invert = 0;              /* True to invert the sense of the match */
  int matched = 0;             /* True if the character matched the pattern */
/*
 * If the first character is a caret, the sense of the match is
 * inverted and only if the character isn't one of those in the
 * range, do we say that it matches.
 */
  if(*pptr == '^') {
    pptr++;
    invert = 1;
  };
/*
 * The hyphen is only a special character when it follows the first
 * character of the range (not including the caret).
 */
  if(*pptr == '-') {
    pptr++;
    if(c == '-') {
      *endp = pptr;
      matched = 1;
    };
/*
 * Skip other leading '-' characters since they make no sense.
 */
    while(*pptr == '-')
      pptr++;
  };
/*
 * The hyphen is only a special character when it follows the first
 * character of the range (not including the caret or a hyphen).
 */
  if(*pptr == ']') {
    pptr++;
    if(c == ']') {
      *endp = pptr;
      matched = 1;
    };
  };
/*
 * Having dealt with the characters that have special meanings at
 * the beginning of a character range expression, see if the
 * character matches any of the remaining characters of the range,
 * up until a terminating ']' character is seen.
 */
  while(!matched && *pptr && *pptr != ']') {
/*
 * Is this a range of characters signaled by the two end characters
 * separated by a hyphen?
 */
    if(*pptr == '-') {
      if(pptr[1] != ']') {
        if(c >= pptr[-1] && c <= pptr[1])
	  matched = 1;
	pptr += 2;
      };
/*
 * A normal character to be compared directly.
 */
    } else if(*pptr++ == c) {
      matched = 1;
    };
  };
/*
 * Find the terminating ']'.
 */
  while(*pptr && *pptr != ']')
    pptr++;
/*
 * Did we find a terminating ']'?
 */
  if(*pptr == ']') {
    *endp = pptr + 1;
    return matched ? !invert : invert;
  };
/*
 * If the pattern didn't end with a ']' then it doesn't match, regardless
 * of the value of the required sense of the match.
 */
  *endp = pptr;
  return 0;
}

/*.......................................................................
 * This is a qsort() comparison function used to sort strings.
 *
 * Input:
 *  v1, v2   void *  Pointers to the two strings to be compared.
 * Output:
 *  return    int    -1 -> v1 < v2.
 *                    0 -> v1 == v2
 *                    1 -> v1 > v2
 */
static int ef_cmp_strings(const void *v1, const void *v2)
{
  char * const *s1 = (char * const *) v1;
  char * const *s2 = (char * const *) v2;
  return strcmp(*s1, *s2);
}

/*.......................................................................
 * Preprocess a path, expanding ~/, ~user/ and $envvar references, using
 * ef->path as a work buffer, then copy the result into a cache entry,
 * and return a pointer to this copy.
 *
 * Input:
 *  ef    ExpandFile *  The resource object of the file matcher.
 *  pathlen      int    The length of the prefix of path[] to be expanded.
 * Output:
 *  return      char *  A pointer to a copy of the output path in the
 *                      cache. On error NULL is returned, and a description
 *                      of the error is left in ef->err.
 */
static char *ef_expand_special(ExpandFile *ef, const char *path, int pathlen)
{
  int spos;      /* The index of the start of the path segment that needs */
                 /*  to be copied from path[] to the output pathname. */
  int ppos;      /* The index of a character in path[] */
  char *pptr;    /* A pointer into the output path */
  int escaped;   /* True if the previous character was a '\' */
  int i;
/*
 * Clear the pathname buffer.
 */
  _pn_clear_path(ef->path);
/*
 * We need to perform two passes, one to expand environment variables
 * and a second to do tilde expansion. This caters for the case
 * where an initial dollar expansion yields a tilde expression.
 */
  escaped = 0;
  for(spos=ppos=0; ppos < pathlen; ppos++) {
    int c = path[ppos];
    if(escaped) {
      escaped = 0;
    } else if(c == '\\') {
      escaped = 1;
    } else if(c == '$') {
      int envlen;   /* The length of the environment variable */
      char *value;  /* The value of the environment variable */
/*
 * Record the preceding unrecorded part of the pathname.
 */
      if(spos < ppos && _pn_append_to_path(ef->path, path + spos, ppos-spos, 0)
	 == NULL) {
	_err_record_msg(ef->err, "Insufficient memory to expand path",
			END_ERR_MSG);
	return NULL;
      };
/*
 * Skip the dollar.
 */
      ppos++;
/*
 * Copy the environment variable name that follows the dollar into
 * ef->envnam[], stopping if a directory separator or end of string
 * is seen.
 */
      for(envlen=0; envlen<ENV_LEN && ppos < pathlen &&
	  strncmp(path + ppos, FS_DIR_SEP, FS_DIR_SEP_LEN); envlen++)
	ef->envnam[envlen] = path[ppos++];
/*
 * If the username overflowed the buffer, treat it as invalid (note that
 * on most unix systems only 8 characters are allowed in a username,
 * whereas our ENV_LEN is much bigger than that.
 */
      if(envlen >= ENV_LEN) {
	_err_record_msg(ef->err, "Environment variable name too long",
			END_ERR_MSG);
	return NULL;
      };
/*
 * Terminate the environment variable name.
 */
      ef->envnam[envlen] = '\0';
/*
 * Lookup the value of the environment variable.
 */
      value = getenv(ef->envnam);
      if(!value) {
	_err_record_msg(ef->err, "No expansion found for: $", ef->envnam,
			END_ERR_MSG);
	return NULL;
      };
/*
 * Copy the value of the environment variable into the output pathname.
 */
      if(_pn_append_to_path(ef->path, value, -1, 0) == NULL) {
	_err_record_msg(ef->err, "Insufficient memory to expand path",
			END_ERR_MSG);
	return NULL;
      };
/*
 * Record the start of the uncopied tail of the input pathname.
 */
      spos = ppos;
    };
  };
/*
 * Record the uncopied tail of the pathname.
 */
  if(spos < ppos && _pn_append_to_path(ef->path, path + spos, ppos-spos, 0)
     == NULL) {
    _err_record_msg(ef->err, "Insufficient memory to expand path", END_ERR_MSG);
    return NULL;
  };
/*
 * If the first character of the resulting pathname is a tilde,
 * then attempt to substitute the home directory of the specified user.
 */
  pptr = ef->path->name;
  if(*pptr == '~' && path[0] != '\\') {
    int usrlen;           /* The length of the username following the tilde */
    const char *homedir;  /* The home directory of the user */
    int homelen;          /* The length of the home directory string */
    int plen;             /* The current length of the path */
    int skip=0;           /* The number of characters to skip after the ~user */
/*
 * Get the current length of the output path.
 */
    plen = strlen(ef->path->name);
/*
 * Skip the tilde.
 */
    pptr++;
/*
 * Copy the optional username that follows the tilde into ef->usrnam[].
 */
    for(usrlen=0; usrlen<USR_LEN && *pptr &&
	strncmp(pptr, FS_DIR_SEP, FS_DIR_SEP_LEN); usrlen++)
      ef->usrnam[usrlen] = *pptr++;
/*
 * If the username overflowed the buffer, treat it as invalid (note that
 * on most unix systems only 8 characters are allowed in a username,
 * whereas our USR_LEN is much bigger than that.
 */
    if(usrlen >= USR_LEN) {
      _err_record_msg(ef->err, "Username too long", END_ERR_MSG);
      return NULL;
    };
/*
 * Terminate the username string.
 */
    ef->usrnam[usrlen] = '\0';
/*
 * Lookup the home directory of the user.
 */
    homedir = _hd_lookup_home_dir(ef->home, ef->usrnam);
    if(!homedir) {
      _err_record_msg(ef->err, _hd_last_home_dir_error(ef->home), END_ERR_MSG);
      return NULL;
    };
    homelen = strlen(homedir);
/*
 * ~user and ~ are usually followed by a directory separator to
 * separate them from the file contained in the home directory.
 * If the home directory is the root directory, then we don't want
 * to follow the home directory by a directory separator, so we must
 * erase it.
 */
    if(strcmp(homedir, FS_ROOT_DIR) == 0 &&
       strncmp(pptr, FS_DIR_SEP, FS_DIR_SEP_LEN) == 0) {
      skip = FS_DIR_SEP_LEN;
    };
/*
 * If needed, increase the size of the pathname buffer to allow it
 * to accomodate the home directory instead of the tilde expression.
 * Note that pptr may not be valid after this call.
 */
    if(_pn_resize_path(ef->path, plen - usrlen - 1 - skip + homelen)==NULL) {
      _err_record_msg(ef->err, "Insufficient memory to expand filename",
		      END_ERR_MSG);
      return NULL;
    };
/*
 * Move the part of the pathname that follows the tilde expression to
 * the end of where the home directory will need to be inserted.
 */
    memmove(ef->path->name + homelen,
	    ef->path->name + 1 + usrlen + skip, plen - usrlen - 1 - skip+1);
/*
 * Write the home directory at the beginning of the string.
 */
    for(i=0; i<homelen; i++)
      ef->path->name[i] = homedir[i];
  };
/*
 * Copy the result into the cache, and return a pointer to the copy.
 */
  return ef_cache_pathname(ef, ef->path->name, 0);
}

/*.......................................................................
 * Return a description of the last path-expansion error that occurred.
 *
 * Input:
 *  ef     ExpandFile *   The path-expansion resource object.
 * Output:
 *  return       char *   The description of the last error.
 */
const char *ef_last_error(ExpandFile *ef)
{
  return ef ? _err_get_msg(ef->err) : "NULL ExpandFile argument";
}

/*.......................................................................
 * Print out an array of matching files.
 *
 * Input:
 *  result  FileExpansion *   The container of the sorted array of
 *                            expansions.
 *  fp               FILE *   The output stream to write to.
 *  term_width        int     The width of the terminal.
 * Output:
 *  return            int     0 - OK.
 *                            1 - Error.
 */
int ef_list_expansions(FileExpansion *result, FILE *fp, int term_width)
{
  return _ef_output_expansions(result, _io_write_stdio, fp, term_width);
}

/*.......................................................................
 * Print out an array of matching files via a callback.
 *
 * Input:
 *  result  FileExpansion *  The container of the sorted array of
 *                           expansions.
 *  write_fn    GlWriteFn *  The function to call to write the
 *                           expansions or 0 to discard the output.
 *  data             void *  Anonymous data to pass to write_fn().
 *  term_width        int    The width of the terminal.
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int _ef_output_expansions(FileExpansion *result, GlWriteFn *write_fn,
			  void *data, int term_width)
{
  EfListFormat fmt; /* List formatting information */
  int lnum;          /* The sequential number of the line to print next */
/*
 * Not enough space to list anything?
 */
  if(term_width < 1)
    return 0;
/*
 * Do we have a callback to write via, and any expansions to be listed?
 */
  if(write_fn && result && result->nfile>0) {
/*
 * Work out how to arrange the listing into fixed sized columns.
 */
    ef_plan_listing(result, term_width, &fmt);
/*
 * Print the listing to the specified stream.
 */
    for(lnum=0; lnum < fmt.nline; lnum++) {
      if(ef_format_line(result, &fmt, lnum, write_fn, data))
	return 1;
    };
  };
  return 0;
}

/*.......................................................................
 * Work out how to arrange a given array of completions into a listing
 * of one or more fixed size columns.
 *
 * Input:
 *  result   FileExpansion *   The set of completions to be listed.
 *  term_width         int     The width of the terminal. A lower limit of
 *                             zero is quietly enforced.
 * Input/Output:
 *  fmt       EfListFormat *   The formatting information will be assigned
 *                             to the members of *fmt.
 */
static void ef_plan_listing(FileExpansion *result, int term_width,
			    EfListFormat *fmt)
{
  int maxlen;    /* The length of the longest matching string */
  int i;
/*
 * Ensure that term_width >= 0.
 */
  if(term_width < 0)
    term_width = 0;
/*
 * Start by assuming the worst case, that either nothing will fit
 * on the screen, or that there are no matches to be listed.
 */
  fmt->term_width = term_width;
  fmt->column_width = 0;
  fmt->nline = fmt->ncol = 0;
/*
 * Work out the maximum length of the matching strings.
 */
  maxlen = 0;
  for(i=0; i<result->nfile; i++) {
    int len = strlen(result->files[i]);
    if(len > maxlen)
      maxlen = len;
  };
/*
 * Nothing to list?
 */
  if(maxlen == 0)
    return;
/*
 * Split the available terminal width into columns of
 * maxlen + EF_COL_SEP characters.
 */
  fmt->column_width = maxlen;
  fmt->ncol = fmt->term_width / (fmt->column_width + EF_COL_SEP);
/*
 * If the column width is greater than the terminal width, zero columns
 * will have been selected. Set a lower limit of one column. Leave it
 * up to the caller how to deal with completions who's widths exceed
 * the available terminal width.
 */
  if(fmt->ncol < 1)
    fmt->ncol = 1;
/*
 * How many lines of output will be needed?
 */
  fmt->nline = (result->nfile + fmt->ncol - 1) / fmt->ncol;
  return;
}

/*.......................................................................
 * Render one line of a multi-column listing of completions, using a
 * callback function to pass the output to an arbitrary destination.
 *
 * Input:
 *  result   FileExpansion *  The container of the sorted array of
 *                            completions.
 *  fmt       EfListFormat *  Formatting information.
 *  lnum               int    The index of the line to print, starting
 *                            from 0, and incrementing until the return
 *                            value indicates that there is nothing more
 *                            to be printed.
 *  write_fn     GlWriteFn *  The function to call to write the line, or
 *                            0 to discard the output.
 *  data              void *  Anonymous data to pass to write_fn().
 * Output:
 *  return             int    0 - Line printed ok.
 *                            1 - Nothing to print.
 */
static int ef_format_line(FileExpansion *result, EfListFormat *fmt, int lnum,
			  GlWriteFn *write_fn, void *data)
{
  int col;             /* The index of the list column being output */
/*
 * If the line index is out of bounds, there is nothing to be written.
 */
  if(lnum < 0 || lnum >= fmt->nline)
    return 1;
/*
 * If no output function has been provided, return as though the line
 * had been printed.
 */
  if(!write_fn)
    return 0;
/*
 * Print the matches in 'ncol' columns, sorted in line order within each
 * column.
 */
  for(col=0; col < fmt->ncol; col++) {
    int m = col*fmt->nline + lnum;
/*
 * Is there another match to be written? Note that in general
 * the last line of a listing will have fewer filled columns
 * than the initial lines.
 */
    if(m < result->nfile) {
      char *file = result->files[m];
/*
 * How long are the completion and type-suffix strings?
 */
      int flen = strlen(file);
/*
 * Write the completion string.
 */
      if(write_fn(data, file, flen) != flen)
	return 1;
/*
 * If another column follows the current one, pad to its start with spaces.
 */
      if(col+1 < fmt->ncol) {
/*
 * The following constant string of spaces is used to pad the output.
 */
	static const char spaces[] = "                    ";
	static const int nspace = sizeof(spaces) - 1;
/*
 * Pad to the next column, using as few sub-strings of the spaces[]
 * array as possible.
 */
	int npad = fmt->column_width + EF_COL_SEP - flen;
	while(npad>0) {
	  int n = npad > nspace ? nspace : npad;
	  if(write_fn(data, spaces + nspace - n, n) != n)
	    return 1;
	  npad -= n;
	};
      };
    };
  };
/*
 * Start a new line.
 */
  {
    char s[] = "\r\n";
    int n = strlen(s);
    if(write_fn(data, s, n) != n)
      return 1;
  };
  return 0;
}

#endif  /* ifndef WITHOUT_FILE_SYSTEM */
