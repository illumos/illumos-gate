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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * If file-system access is to be excluded, this module has no function,
 * so all of its code should be excluded.
 */
#ifndef WITHOUT_FILE_SYSTEM

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "libtecla.h"
#include "pathutil.h"
#include "homedir.h"
#include "freelist.h"
#include "direader.h"
#include "stringrp.h"
#include "errmsg.h"

/*
 * The new_PcaPathConf() constructor sets the integer first member of
 * the returned object to the following magic number. This is then
 * checked for by pca_path_completions() as a sanity check.
 */
#define PPC_ID_CODE 4567

/*
 * A pointer to a structure of the following type can be passed to
 * the builtin path-completion callback function to modify its behavior.
 */
struct PcaPathConf {
  int id;          /* This is set to PPC_ID_CODE by new_PcaPathConf() */
  PathCache *pc;   /* The path-list cache in which to look up the executables */
  int escaped;     /* If non-zero, backslashes in the input line are */
                   /*  interpreted as escaping special characters and */
                   /*  spaces, and any special characters and spaces in */
                   /*  the listed completions will also be escaped with */
                   /*  added backslashes. This is the default behaviour. */
                   /* If zero, backslashes are interpreted as being */
                   /*  literal parts of the file name, and none are added */
                   /*  to the completion suffixes. */
  int file_start;  /* The index in the input line of the first character */
                   /*  of the file name. If you specify -1 here, */
                   /*  pca_path_completions() identifies the */
                   /*  the start of the file by looking backwards for */
                   /*  an unescaped space, or the beginning of the line. */
};

/*
 * Prepended to each chached filename is a character which contains
 * one of the following status codes. When a given filename (minus
 * this byte) is passed to the application's check_fn(), the result
 * is recorded in this byte, such that the next time it is looked
 * up, we don't have to call check_fn() again. These codes are cleared
 * whenever the path is scanned and whenever the check_fn() callback
 * is changed.
 */
typedef enum {
  PCA_F_ENIGMA='?', /* The file remains to be checked */
  PCA_F_WANTED='+', /* The file has been selected by the caller's callback */
  PCA_F_IGNORE='-'  /* The file has been rejected by the caller's callback */
} PcaFileStatus;

/*
 * Encapsulate the memory management objects which supply memoy for
 * the arrays of filenames.
 */
typedef struct {
  StringGroup *sg;       /* The memory used to record the names of files */
  size_t files_dim;      /* The allocated size of files[] */
  char **files;          /* Memory for 'files_dim' pointers to files */
  size_t nfiles;         /* The number of filenames currently in files[] */
} CacheMem;

static CacheMem *new_CacheMem(void);
static CacheMem *del_CacheMem(CacheMem *cm);
static void rst_CacheMem(CacheMem *cm);

/*
 * Lists of nodes of the following type are used to record the
 * names and contents of individual directories.
 */
typedef struct PathNode PathNode;
struct PathNode {
  PathNode *next;   /* The next directory in the path */
  int relative;     /* True if the directory is a relative pathname */
  CacheMem *mem;    /* The memory used to store dir[] and files[] */
  char *dir;        /* The directory pathname (stored in pc->sg) */
  int nfile;        /* The number of filenames stored in 'files' */
  char **files;     /* Files of interest in the current directory, */
                    /*  or NULL if dir[] is a relative pathname */
                    /*  who's contents can't be cached. This array */
                    /*  and its contents are taken from pc->abs_mem */
                    /*  or pc->rel_mem */
};

/*
 * Append a new node to the list of directories in the path.
 */
static int add_PathNode(PathCache *pc, const char *dirname);

/*
 * Set the maximum length allowed for usernames.
 * names.
 */
#define USR_LEN 100

/*
 * PathCache objects encapsulate the resources needed to record
 * files of interest from comma-separated lists of directories.
 */
struct PathCache {
  ErrMsg *err;           /* The error reporting buffer */
  FreeList *node_mem;    /* A free-list of PathNode objects */
  CacheMem *abs_mem;     /* Memory for the filenames of absolute paths */
  CacheMem *rel_mem;     /* Memory for the filenames of relative paths */
  PathNode *head;        /* The head of the list of directories in the */
                         /*  path, or NULL if no path has been scanned yet. */
  PathNode *tail;        /* The tail of the list of directories in the */
                         /*  path, or NULL if no path has been scanned yet. */
  PathName *path;        /* The fully qualified name of a file */
  HomeDir *home;         /* Home-directory lookup object */
  DirReader *dr;         /* A portable directory reader */
  CplFileConf *cfc;      /* Configuration parameters to pass to */
                         /*  cpl_file_completions() */
  CplCheckFn *check_fn;  /* The callback used to determine if a given */
                         /*  filename should be recorded in the cache. */
  void *data;            /* Annonymous data to be passed to pc->check_fn() */
  char usrnam[USR_LEN+1];/* The buffer used when reading the names of */
                         /*  users. */
};

/*
 * Empty the cache.
 */
static void pca_clear_cache(PathCache *pc);

/*
 * Read a username from string[] and record it in pc->usrnam[].
 */
static int pca_read_username(PathCache *pc, const char *string, int slen,
			     int literal, const char **nextp);

/*
 * Extract the next component of a colon separated list of directory
 * paths.
 */
static int pca_extract_dir(PathCache *pc, const char *path,
			   const char **nextp);

/*
 * Scan absolute directories for files of interest, recording their names
 * in mem->sg and recording pointers to these names in mem->files[].
 */
static int pca_scan_dir(PathCache *pc, const char *dirname, CacheMem *mem);

/*
 * A qsort() comparison function for comparing the cached filename
 * strings pointed to by two (char **) array elements. Note that
 * this ignores the initial cache-status byte of each filename.
 */
static int pca_cmp_matches(const void *v1, const void *v2);

/*
 * A qsort() comparison function for comparing a filename
 * against an element of an array of pointers to filename cache
 * entries.
 */
static int pca_cmp_file(const void *v1, const void *v2);

/*
 * Initialize a PcaPathConf configuration objects with the default
 * options.
 */
static int pca_init_PcaPathConf(PcaPathConf *ppc, PathCache *pc);

/*
 * Make a copy of a completion suffix, suitable for passing to
 * cpl_add_completion().
 */
static int pca_prepare_suffix(PathCache *pc, const char *suffix,
			      int add_escapes);

/*
 * Return non-zero if the specified string appears to start with a pathname.
 */
static int cpa_cmd_contains_path(const char *prefix, int prefix_len);

/*
 * Return a given prefix with escapes optionally removed.
 */
static const char *pca_prepare_prefix(PathCache *pc, const char *prefix,
				      size_t prefix_len, int escaped);

/*
 * If there is a tilde expression at the beginning of the specified path,
 * place the corresponding home directory into pc->path. Otherwise
 * just clear pc->path.
 */
static int pca_expand_tilde(PathCache *pc, const char *path, int pathlen,
			    int literal, const char **endp);

/*
 * Clear the filename status codes that are recorded before each filename
 * in the cache.
 */
static void pca_remove_marks(PathCache *pc);

/*
 * Specify how many PathNode's to allocate at a time.
 */
#define PATH_NODE_BLK 30

/*
 * Specify the amount by which the files[] arrays are to be extended
 * whenever they are found to be too small.
 */
#define FILES_BLK_FACT 256

/*.......................................................................
 * Create a new object who's function is to maintain a cache of
 * filenames found within a list of directories, and provide quick
 * lookup and completion of selected files in this cache.
 *
 * Output:
 *  return     PathCache *  The new, initially empty cache, or NULL
 *                          on error.
 */
PathCache *new_PathCache(void)
{
  PathCache *pc;  /* The object to be returned */
/*
 * Allocate the container.
 */
  pc = (PathCache *)malloc(sizeof(PathCache));
  if(!pc) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to del_PathCache().
 */
  pc->err = NULL;
  pc->node_mem = NULL;
  pc->abs_mem = NULL;
  pc->rel_mem = NULL;
  pc->head = NULL;
  pc->tail = NULL;
  pc->path = NULL;
  pc->home = NULL;
  pc->dr = NULL;
  pc->cfc = NULL;
  pc->check_fn = 0;
  pc->data = NULL;
  pc->usrnam[0] = '\0';
/*
 * Allocate a place to record error messages.
 */
  pc->err = _new_ErrMsg();
  if(!pc->err)
    return del_PathCache(pc);
/*
 * Allocate the freelist of directory list nodes.
 */
  pc->node_mem = _new_FreeList(sizeof(PathNode), PATH_NODE_BLK);
  if(!pc->node_mem)
    return del_PathCache(pc);
/*
 * Allocate memory for recording names of files in absolute paths.
 */
  pc->abs_mem = new_CacheMem();
  if(!pc->abs_mem)
    return del_PathCache(pc);
/*
 * Allocate memory for recording names of files in relative paths.
 */
  pc->rel_mem = new_CacheMem();
  if(!pc->rel_mem)
    return del_PathCache(pc);
/*
 * Allocate a pathname buffer.
 */
  pc->path = _new_PathName();
  if(!pc->path)
    return del_PathCache(pc);
/*
 * Allocate an object for looking up home-directories.
 */
  pc->home = _new_HomeDir();
  if(!pc->home)
    return del_PathCache(pc);
/*
 * Allocate an object for reading directories.
 */
  pc->dr = _new_DirReader();
  if(!pc->dr)
    return del_PathCache(pc);
/*
 * Allocate a cpl_file_completions() configuration object.
 */
  pc->cfc = new_CplFileConf();
  if(!pc->cfc)
    return del_PathCache(pc);
/*
 * Configure cpl_file_completions() to use check_fn() to select
 * files of interest.
 */
  cfc_set_check_fn(pc->cfc, pc->check_fn, pc->data);
/*
 * Return the cache, ready for use.
 */
  return pc;
}

/*.......................................................................
 * Delete a given cache of files, returning the resources that it
 * was using to the system.
 *
 * Input:
 *  pc      PathCache *  The cache to be deleted (can be NULL).
 * Output:
 *  return  PathCache *  The deleted object (ie. allways NULL).
 */
PathCache *del_PathCache(PathCache *pc)
{
  if(pc) {
/*
 * Delete the error message buffer.
 */
    pc->err = _del_ErrMsg(pc->err);
/*
 * Delete the memory of the list of path nodes.
 */
    pc->node_mem = _del_FreeList(pc->node_mem, 1);
/*
 * Delete the memory used to record filenames.
 */
    pc->abs_mem = del_CacheMem(pc->abs_mem);
    pc->rel_mem = del_CacheMem(pc->rel_mem);
/*
 * The list of PathNode's was already deleted when node_mem was
 * deleted.
 */
    pc->head = NULL;
    pc->tail = NULL;
/*
 * Delete the pathname buffer.
 */
    pc->path = _del_PathName(pc->path);
/*
 * Delete the home-directory lookup object.
 */
    pc->home = _del_HomeDir(pc->home);
/*
 * Delete the directory reader.
 */
    pc->dr = _del_DirReader(pc->dr);
/*
 * Delete the cpl_file_completions() config object.
 */
    pc->cfc = del_CplFileConf(pc->cfc);
/*
 * Delete the container.
 */
    free(pc);
  };
  return NULL;
}

/*.......................................................................
 * If you want subsequent calls to pca_lookup_file() and
 * pca_path_completions() to only return the filenames of certain
 * types of files, for example executables, or filenames ending in
 * ".ps", call this function to register a file-selection callback
 * function. This callback function takes the full pathname of a file,
 * plus application-specific data, and returns 1 if the file is of
 * interest, and zero otherwise.
 *
 * Input:
 *  pc         PathCache *  The filename cache.
 *  check_fn  CplCheckFn *  The function to call to see if the name of
 *                          a given file should be included in the
 *                          cache. This determines what type of files
 *                          will reside in the cache. To revert to
 *                          selecting all files, regardless of type,
 *                          pass 0 here.
 *  data            void *  You can pass a pointer to anything you
 *                          like here, including NULL. It will be
 *                          passed to your check_fn() callback
 *                          function, for its private use.
 */
void pca_set_check_fn(PathCache *pc, CplCheckFn *check_fn, void *data)
{
  if(pc) {
/*
 * If the callback or its data pointer have changed, clear the cached
 * statuses of files that were accepted or rejected by the previous
 * calback.
 */
    if(check_fn != pc->check_fn || data != pc->data)
      pca_remove_marks(pc);
/*
 * Record the new callback locally.
 */
    pc->check_fn = check_fn;
    pc->data = data;
/*
 * Configure cpl_file_completions() to use the same callback to
 * select files of interest.
 */
    cfc_set_check_fn(pc->cfc, check_fn, data);
  };
  return;
}

/*.......................................................................
 * Return a description of the last path-caching error that occurred.
 *
 * Input:
 *  pc     PathCache *   The filename cache that suffered the error.
 * Output:
 *  return      char *   The description of the last error.
 */
const char *pca_last_error(PathCache *pc)
{
  return pc ? _err_get_msg(pc->err) : "NULL PathCache argument";
}

/*.......................................................................
 * Discard all cached filenames.
 *
 * Input:
 *  pc   PathCache *  The cache to be cleared.
 */
static void pca_clear_cache(PathCache *pc)
{
  if(pc) {
/*
 * Return all path-nodes to the freelist.
 */
    _rst_FreeList(pc->node_mem);
    pc->head = pc->tail = NULL;
/*
 * Delete all filename strings.
 */
    rst_CacheMem(pc->abs_mem);
    rst_CacheMem(pc->rel_mem);
  };
  return;
}

/*.......................................................................
 * Build the list of files of interest contained in a given
 * colon-separated list of directories.
 *
 * Input:
 *  pc         PathCache *  The cache in which to store the names of
 *                          the files that are found in the list of
 *                          directories.
 *  path      const char *  A colon-separated list of directory
 *                          paths. Under UNIX, when searching for
 *                          executables, this should be the return
 *                          value of getenv("PATH").
 * Output:
 *  return           int    0 - OK.
 *                          1 - An error occurred. A description of
 *                              the error can be acquired by calling
 *                              pca_last_error(pc).
 */
int pca_scan_path(PathCache *pc, const char *path)
{
  const char *pptr; /* A pointer to the next unprocessed character in path[] */
  PathNode *node;   /* A node in the list of directory paths */
  char **fptr;      /* A pointer into pc->abs_mem->files[] */
/*
 * Check the arguments.
 */
  if(!pc)
    return 1;
/*
 * Clear the outdated contents of the cache.
 */
  pca_clear_cache(pc);
/*
 * If no path list was provided, there is nothing to be added to the
 * cache.
 */
  if(!path)
    return 0;
/*
 * Extract directories from the path list, expanding tilde expressions
 * on the fly into pc->pathname, then add them to the list of path
 * nodes, along with a sorted list of the filenames of interest that
 * the directories hold.
 */
  pptr = path;
  while(*pptr) {
/*
 * Extract the next pathname component into pc->path->name.
 */
    if(pca_extract_dir(pc, pptr, &pptr))
      return 1;
/*
 * Add a new node to the list of paths, containing both the
 * directory name and, if not a relative pathname, the list of
 * files of interest in the directory.
 */
    if(add_PathNode(pc, pc->path->name))
      return 1;
  };
/*
 * The file arrays in each absolute directory node are sections of
 * pc->abs_mem->files[]. Record pointers to the starts of each
 * of these sections in each directory node. Note that this couldn't
 * be done in add_PathNode(), because pc->abs_mem->files[] may
 * get reallocated in subsequent calls to add_PathNode(), thus
 * invalidating any pointers to it.
 */
  fptr = pc->abs_mem->files;
  for(node=pc->head; node; node=node->next) {
    node->files = fptr;
    fptr += node->nfile;
  };
  return 0;
}

/*.......................................................................
 * Extract the next directory path from a colon-separated list of
 * directories, expanding tilde home-directory expressions where needed.
 *
 * Input:
 *  pc      PathCache *   The cache of filenames.
 *  path   const char *   A pointer to the start of the next component
 *                        in the path list.
 * Input/Output:
 *  nextp  const char **  A pointer to the next unprocessed character
 *                        in path[] will be assigned to *nextp.
 * Output:
 *  return        int     0 - OK. The extracted path is in pc->path->name.
 *                        1 - Error. A description of the error will
 *                            have been left in pc->err.
 */
static int pca_extract_dir(PathCache *pc, const char *path, const char **nextp)
{
  const char *pptr;         /* A pointer into path[] */
  const char *sptr;         /* The path following tilde expansion */
  int escaped = 0;          /* True if the last character was a backslash */
/*
 * If there is a tilde expression at the beginning of the specified path,
 * place the corresponding home directory into pc->path. Otherwise
 * just clear pc->path.
 */
  if(pca_expand_tilde(pc, path, strlen(path), 0, &pptr))
    return 1;
/*
 * Keep a record of the current location in the path.
 */
  sptr = pptr;
/*
 * Locate the end of the directory name in the pathname string, stopping
 * when either the end of the string is reached, or an un-escaped colon
 * separator is seen.
 */
  while(*pptr && (escaped || *pptr != ':'))
    escaped = !escaped && *pptr++ == '\\';
/*
 * Append the rest of the directory path to the pathname buffer.
 */
  if(_pn_append_to_path(pc->path, sptr, pptr - sptr, 1) == NULL) {
    _err_record_msg(pc->err, "Insufficient memory to record directory name",
		    END_ERR_MSG);
    return 1;
  };
/*
 * To facilitate subsequently appending filenames to the directory
 * path name, make sure that the recorded directory name ends in a
 * directory separator.
 */
  {
    int dirlen = strlen(pc->path->name);
    if(dirlen < FS_DIR_SEP_LEN ||
       strncmp(pc->path->name + dirlen - FS_DIR_SEP_LEN, FS_DIR_SEP,
	       FS_DIR_SEP_LEN) != 0) {
      if(_pn_append_to_path(pc->path, FS_DIR_SEP, FS_DIR_SEP_LEN, 0) == NULL) {
	_err_record_msg(pc->err, "Insufficient memory to record directory name",
			END_ERR_MSG);
	return 1;
      };
    };
  };
/*
 * Skip the separator unless we have reached the end of the path.
 */
  if(*pptr==':')
    pptr++;
/*
 * Return the unprocessed tail of the path-list string.
 */
  *nextp = pptr;
  return 0;
}

/*.......................................................................
 * Read a username, stopping when a directory separator is seen, a colon
 * separator is seen, the end of the string is reached, or the username
 * buffer overflows.
 *
 * Input:
 *  pc   PathCache *   The cache of filenames.
 *  string    char *   The string who's prefix contains the name.
 *  slen       int     The max number of characters to read from string[].
 *  literal    int     If true, treat backslashes as literal characters
 *                     instead of escapes.
 * Input/Output:
 *  nextp     char **  A pointer to the next unprocessed character
 *                     in string[] will be assigned to *nextp.
 * Output:
 *  return     int     0 - OK. The username can be found in pc->usrnam.
 *                     1 - Error. A description of the error message
 *                         can be found in pc->err.
 */
static int pca_read_username(PathCache *pc, const char *string, int slen,
			     int literal, const char **nextp)
{
  int usrlen;         /* The number of characters in pc->usrnam[] */
  const char *sptr;   /* A pointer into string[] */
  int escaped = 0;    /* True if the last character was a backslash */
/*
 * Extract the username.
 */
  for(sptr=string,usrlen=0; usrlen < USR_LEN && (sptr-string) < slen; sptr++) {
/*
 * Stop if the end of the string is reached, or a directory separator
 * or un-escaped colon separator is seen.
 */
    if(!*sptr || strncmp(sptr, FS_DIR_SEP, FS_DIR_SEP_LEN)==0 ||
       (!escaped && *sptr == ':'))
      break;
/*
 * Escape the next character?
 */
    if(!literal && !escaped && *sptr == '\\') {
      escaped = 1;
    } else {
      escaped = 0;
      pc->usrnam[usrlen++] = *sptr;
    };
  };
/*
 * Did the username overflow the buffer?
 */
  if(usrlen >= USR_LEN) {
    _err_record_msg(pc->err, "Username too long", END_ERR_MSG);
    return 1;
  };
/*
 * Terminate the string.
 */
  pc->usrnam[usrlen] = '\0';
/*
 * Indicate where processing of the input string should continue.
 */
  *nextp = sptr;
  return 0;
}


/*.......................................................................
 * Create a new CacheMem object.
 *
 * Output:
 *  return  CacheMem *  The new object, or NULL on error.
 */
static CacheMem *new_CacheMem(void)
{
  CacheMem *cm;  /* The object to be returned */
/*
 * Allocate the container.
 */
  cm = (CacheMem *)malloc(sizeof(CacheMem));
  if(!cm) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to del_CacheMem().
 */
  cm->sg = NULL;
  cm->files_dim = 0;
  cm->files = NULL;
  cm->nfiles = 0;
/*
 * Allocate a list of string segments for storing filenames.
 */
  cm->sg = _new_StringGroup(_pu_pathname_dim());
  if(!cm->sg)
    return del_CacheMem(cm);
/*
 * Allocate an array of pointers to filenames.
 * This will be extended later if needed.
 */
  cm->files_dim = FILES_BLK_FACT;
  cm->files = (char **) malloc(sizeof(*cm->files) * cm->files_dim);
  if(!cm->files) {
    errno = ENOMEM;
    return del_CacheMem(cm);
  };
  return cm;
}

/*.......................................................................
 * Delete a CacheMem object.
 *
 * Input:
 *  cm   CacheMem *  The object to be deleted.
 * Output:
 *  return CacheMem *  The deleted object (always NULL).
 */
static CacheMem *del_CacheMem(CacheMem *cm)
{
  if(cm) {
/*
 * Delete the memory that was used to record filename strings.
 */
    cm->sg = _del_StringGroup(cm->sg);
/*
 * Delete the array of pointers to filenames.
 */
    cm->files_dim = 0;
    if(cm->files) {
      free(cm->files);
      cm->files = NULL;
    };
/*
 * Delete the container.
 */
    free(cm);
  };
  return NULL;
}

/*.......................................................................
 * Re-initialize the memory used to allocate filename strings.
 *
 * Input:
 *  cm     CacheMem *  The memory cache to be cleared.
 */
static void rst_CacheMem(CacheMem *cm)
{
  _clr_StringGroup(cm->sg);
  cm->nfiles = 0;
  return;
}

/*.......................................................................
 * Append a new directory node to the list of directories read from the
 * path.
 *
 * Input:
 *  pc        PathCache *  The filename cache.
 *  dirname  const char *  The name of the new directory.
 * Output:
 *  return          int    0 - OK.
 *                         1 - Error.
 */
static int add_PathNode(PathCache *pc, const char *dirname)
{
  PathNode *node;  /* The new directory list node */
  int relative;    /* True if dirname[] is a relative pathname */
/*
 * Have we been passed a relative pathname or an absolute pathname?
 */
  relative = strncmp(dirname, FS_ROOT_DIR, FS_ROOT_DIR_LEN) != 0;
/*
 * If it's an absolute pathname, ignore it if the corresponding
 * directory doesn't exist.
 */
  if(!relative && !_pu_path_is_dir(dirname))
    return 0;
/*
 * Allocate a new list node to record the specifics of the new directory.
 */
  node = (PathNode *) _new_FreeListNode(pc->node_mem);
  if(!node) {
    _err_record_msg(pc->err, "Insufficient memory to cache new directory.",
		    END_ERR_MSG);
    return 1;
  };
/*
 * Initialize the node.
 */
  node->next = NULL;
  node->relative = relative;
  node->mem = relative ? pc->rel_mem : pc->abs_mem;
  node->dir = NULL;
  node->nfile = 0;
  node->files = NULL;
/*
 * Make a copy of the directory pathname.
 */
  node->dir = _sg_store_string(pc->abs_mem->sg, dirname, 0);
  if(!node->dir) {
    _err_record_msg(pc->err, "Insufficient memory to store directory name.",
		    END_ERR_MSG);
    return 1;
  };
/*
 * Scan absolute directories for files of interest, recording their names
 * in node->mem->sg and appending pointers to these names to the
 * node->mem->files[] array.
 */
  if(!node->relative) {
    int nfile = node->nfile = pca_scan_dir(pc, node->dir, node->mem);
    if(nfile < 1) {  /* No files matched or an error occurred */
      node = (PathNode *) _del_FreeListNode(pc->node_mem, node);
      return nfile < 0;
    };
  };
/*
 * Append the new node to the list.
 */
  if(pc->head) {
    pc->tail->next = node;
    pc->tail = node;
  } else {
    pc->head = pc->tail = node;
  };
  return 0;
}

/*.......................................................................
 * Scan a given directory for files of interest, record their names
 * in mem->sg and append pointers to them to the mem->files[] array.
 *
 * Input:
 *  pc        PathCache *  The filename cache.
 *  dirname  const char *  The pathname of the directory to be scanned.
 *  mem        CacheMem *  The memory in which to store filenames of
 *                         interest.
 * Output:
 *  return          int    The number of files recorded, or -1 if a
 *                         memory error occurs. Note that the
 *                         inability to read the contents of the
 *                         directory is not counted as an error.
 */
static int pca_scan_dir(PathCache *pc, const char *dirname, CacheMem *mem)
{
  int nfile = 0;        /* The number of filenames recorded */
  const char *filename; /* The name of the file being looked at */
/*
 * Attempt to open the directory. If the directory can't be read then
 * there are no accessible files of interest in the directory.
 */
  if(_dr_open_dir(pc->dr, dirname, NULL))
    return 0;
/*
 * Record the names of all files in the directory in the cache.
 */
  while((filename = _dr_next_file(pc->dr))) {
    char *copy;        /* A copy of the filename */
/*
 * Make a temporary copy of the filename with an extra byte prepended.
 */
    _pn_clear_path(pc->path);
    if(_pn_append_to_path(pc->path, " ", 1, 0) == NULL ||
       _pn_append_to_path(pc->path, filename, -1, 1) == NULL) {
      _err_record_msg(pc->err, "Insufficient memory to record filename",
		      END_ERR_MSG);
      return -1;
    };
/*
 * Store the filename.
 */
    copy = _sg_store_string(mem->sg, pc->path->name, 0);
    if(!copy) {
      _err_record_msg(pc->err, "Insufficient memory to cache file name.",
		      END_ERR_MSG);
      return -1;
    };
/*
 * Mark the filename as unchecked.
 */
    copy[0] = PCA_F_ENIGMA;
/*
 * Make room to store a pointer to the copy in mem->files[].
 */
    if(mem->nfiles + 1 > mem->files_dim) {
      int needed = mem->files_dim + FILES_BLK_FACT;
      char **files = (char **) realloc(mem->files, sizeof(*mem->files)*needed);
      if(!files) {
	_err_record_msg(pc->err,
			"Insufficient memory to extend filename cache.",
			END_ERR_MSG);
	return 1;
      };
      mem->files = files;
      mem->files_dim = needed;
    };
/*
 * Record a pointer to the copy of the filename at the end of the files[]
 * array.
 */
    mem->files[mem->nfiles++] = copy;
/*
 * Keep a record of the number of files matched so far.
 */
    nfile++;
  };
/*
 * Sort the list of files into lexical order.
 */
  qsort(mem->files + mem->nfiles - nfile, nfile, sizeof(*mem->files),
	pca_cmp_matches);
/*
 * Return the number of files recorded in mem->files[].
 */
  return nfile;
}

/*.......................................................................
 * A qsort() comparison function for comparing the cached filename
 * strings pointed to by two (char **) array elements. Note that
 * this ignores the initial cache-status byte of each filename.
 *
 * Input:
 *  v1, v2   void *  Pointers to the pointers of two strings to be compared.
 * Output:
 *  return    int    -1 -> v1 < v2.
 *                    0 -> v1 == v2
 *                    1 -> v1 > v2
 */
static int pca_cmp_matches(const void *v1, const void *v2)
{
  const char **s1 = (const char **) v1;
  const char **s2 = (const char **) v2;
  return strcmp(*s1+1, *s2+1);
}

/*.......................................................................
 * Given the simple name of a file, search the cached list of files
 * in the order in which they where found in the list of directories
 * previously presented to pca_scan_path(), and return the pathname
 * of the first file which has this name. If a pathname to a file is
 * given instead of a simple filename, this is returned without being
 * looked up in the cache, but with any initial ~username expression
 * expanded, and optionally, unescaped backslashes removed.
 *
 * Input:
 *  pc     PathCache *  The cached list of files.
 *  name  const char *  The name of the file to lookup.
 *  name_len     int    The length of the filename string at the
 *                      beginning of name[], or -1 to indicate that
 *                      the filename occupies the whole of the
 *                      string.
 *  literal      int    If this argument is zero, lone backslashes
 *                      in name[] are ignored during comparison
 *                      with filenames in the cache, under the
 *                      assumption that they were in the input line
 *                      soley to escape the special significance of
 *                      characters like spaces. To have them treated
 *                      as normal characters, give this argument a
 *                      non-zero value, such as 1.
 * Output:
 *  return      char *  The pathname of the first matching file,
 *                      or NULL if not found. Note that the returned
 *                      pointer points to memory owned by *pc, and
 *                      will become invalid on the next call to any
 *                      function in the PathCache module.
 */
char *pca_lookup_file(PathCache *pc, const char *name, int name_len,
		      int literal)
{
  PathNode *node;   /* A node in the list of directories in the path */
  char **match;     /* A pointer to a matching filename string in the cache */
/*
 * Check the arguments.
 */
  if(!pc || !name || name_len==0)
    return NULL;
/*
 * If no length was specified, determine the length of the string to
 * be looked up.
 */
  if(name_len < 0)
    name_len = strlen(name);
/*
 * If the word starts with a ~username expression, the root directory,
 * of it contains any directory separators, then treat it isn't a simple
 * filename that can be looked up in the cache, but rather appears to
 * be the pathname of a file. If so, return a copy of this pathname with
 * escapes removed, if requested, and any initial ~username expression
 * expanded.
 */
  if(cpa_cmd_contains_path(name, name_len)) {
    const char *nptr;
    if(pca_expand_tilde(pc, name, name_len, literal, &nptr) || 
       _pn_append_to_path(pc->path, nptr, name_len - (nptr-name),
			  !literal) == NULL)
      return NULL;
    return pc->path->name;
  };
/*
 * Look up the specified filename in each of the directories of the path,
 * in the same order that they were listed in the path, and stop as soon
 * as an instance of the file is found.
 */
  for(node=pc->head; node; node=node->next) {
/*
 * If the directory of the latest node is a relative pathname,
 * scan it for files of interest.
 */
    if(node->relative) {
      rst_CacheMem(node->mem);
      if(pca_scan_dir(pc, node->dir, node->mem) < 1)
	continue;
      node->files = node->mem->files;
      node->nfile = node->mem->nfiles;
    };
/*
 * Copy the filename into a temporary buffer, while interpretting
 * escape characters if needed.
 */
    _pn_clear_path(pc->path);
    if(_pn_append_to_path(pc->path, name, name_len, !literal) == NULL)
      return NULL;
/*
 * Perform a binary search for the requested filename.
 */
    match = (char **)bsearch(pc->path->name, node->files, node->nfile,
		             sizeof(*node->files), pca_cmp_file);
    if(match) {
/*
 * Prepend the pathname in which the directory was found, which we have
 * guaranteed to end in a directory separator, to the located filename.
 */
      if(_pn_prepend_to_path(pc->path, node->dir, -1, 0) == NULL)
	return NULL;
/*
 * Return the matching pathname unless it is rejected by the application.
 */
      if(!pc->check_fn || (*match)[0] == PCA_F_WANTED ||
	 ((*match)[0]==PCA_F_ENIGMA && pc->check_fn(pc->data, pc->path->name))){
	(*match)[0] = PCA_F_WANTED;
	return pc->path->name;
      } else {
	*(match)[0] = PCA_F_IGNORE;
      };
    };
  };
/*
 * File not found.
 */
  return NULL;
}

/*.......................................................................
 * A qsort() comparison function for comparing a filename string to
 * a cached filename string pointed to by a (char **) array element.
 * This ignores the initial code byte at the start of the cached filename
 * string.
 *
 * Input:
 *  v1, v2   void *  Pointers to the pointers of two strings to be compared.
 * Output:
 *  return    int    -1 -> v1 < v2.
 *                    0 -> v1 == v2
 *                    1 -> v1 > v2
 */
static int pca_cmp_file(const void *v1, const void *v2)
{
  const char *file_name = (const char *) v1;
  const char **cache_name = (const char **) v2;
  return strcmp(file_name, *cache_name + 1);
}

/*.......................................................................
 * The PcaPathConf structure may have options added to it in the future.
 * To allow your application to be linked against a shared version of the
 * tecla library, without these additions causing your application to
 * crash, you should use new_PcaPathConf() to allocate such structures.
 * This will set all of the configuration options to their default values,
 * which you can then change before passing the structure to
 * pca_path_completions().
 *
 * Input:
 *  pc         PathCache *  The filename cache in which to look for
 *                          file name completions.
 * Output:
 *  return   PcaPathConf *  The new configuration structure, or NULL
 *                          on error. A descripition of the error
 *                          can be found by calling pca_last_error(pc).
 */
PcaPathConf *new_PcaPathConf(PathCache *pc)
{
  PcaPathConf *ppc;  /* The object to be returned */
/*
 * Check the arguments.
 */
  if(!pc)
    return NULL;
/*
 * Allocate the container.
 */
  ppc = (PcaPathConf *)malloc(sizeof(PcaPathConf));
  if(!ppc) {
    _err_record_msg(pc->err, "Insufficient memory.", END_ERR_MSG);
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to del_PcaPathConf().
 */
  if(pca_init_PcaPathConf(ppc, pc))
    return del_PcaPathConf(ppc);
  return ppc;
}

/*.......................................................................
 * Initialize a PcaPathConf configuration structure with defaults.
 *
 * Input:
 *  ppc   PcaPathConf *  The structre to be initialized.
 *  pc      PathCache *  The cache in which completions will be looked up.
 * Output:
 *  return        int    0 - OK.
 *                       1 - Error. A description of the error can be
 *                           obtained by calling pca_last_error(pc).
 */
static int pca_init_PcaPathConf(PcaPathConf *ppc, PathCache *pc)
{
/*
 * Check the arguments.
 */
  if(!pc)
    return 1;
/*
 * Set the default options.
 */
  ppc->id = PPC_ID_CODE;
  ppc->pc = pc;
  ppc->escaped = 1;
  ppc->file_start = -1;
  return 0;
}

/*.......................................................................
 * Delete a PcaPathConf object.
 *
 * Input:
 *  ppc    PcaPathConf *  The object to be deleted.
 * Output:
 *  return PcaPathConf *  The deleted object (always NULL).
 */
PcaPathConf *del_PcaPathConf(PcaPathConf *ppc)
{
  if(ppc) {
    ppc->pc = NULL;  /* It is up to the caller to delete the cache */
/*
 * Delete the container.
 */
    free(ppc);
  };
  return NULL;
}

/*.......................................................................
 * pca_path_completions() is a completion callback function for use
 * directly with cpl_complete_word() or gl_customize_completions(), or
 * indirectly from your own completion callback function. It requires
 * that a CpaPathArgs object be passed via its 'void *data' argument.
 */
CPL_MATCH_FN(pca_path_completions)
{
  PcaPathConf *ppc;       /* The configuration arguments */
  PathCache *pc;          /* The cache in which to look for completions */
  PathNode *node;         /* A node in the list of directories in the path */
  const char *filename;   /* The name of the file being looked at */
  const char *start_path; /* The pointer to the start of the pathname */
                          /*  in line[]. */
  int word_start;         /* The index in line[] corresponding to start_path */
  const char *prefix;     /* The file-name prefix being searched for */
  size_t prefix_len;      /* The length of the prefix being completed */
  int bot;                /* The lowest index of the array not searched yet */
  int top;                /* The highest index of the array not searched yet */
/*
 * Check the arguments.
 */
  if(!cpl)
    return 1;
  if(!line || word_end < 0 || !data) {
    cpl_record_error(cpl, "pca_path_completions: Invalid arguments.");
    return 1;
  };
/*
 * Get the configuration arguments.
 */
  ppc = (PcaPathConf *) data;
/*
 * Check that the callback data is a PcaPathConf structure returned
 * by new_PcaPathConf().
 */
  if(ppc->id != PPC_ID_CODE) {
    cpl_record_error(cpl,
		     "Invalid callback data passed to pca_path_completions()");
    return 1;
  };
/*
 * Get the filename cache.
 */
  pc = ppc->pc;
/*
 * Get the start of the file name. If not specified by the caller,
 * identify it by searching backwards in the input line for an
 * unescaped space or the start of the line.
 */
  if(ppc->file_start < 0) {
    start_path = _pu_start_of_path(line, word_end);
    if(!start_path) {
      cpl_record_error(cpl, "Unable to find the start of the file name.");
      return 1;
    };
  } else {
    start_path = line + ppc->file_start;
  };
/*
 * Get the index of the start of the word being completed.
 */
  word_start = start_path - line;
/*
 * Work out the length of the prefix that is bein completed.
 */
  prefix_len = word_end - word_start;
/*
 * If the word starts with a ~username expression or the root directory,
 * of it contains any directory separators, then completion must be
 * delegated to cpl_file_completions().
 */
  if(cpa_cmd_contains_path(start_path, prefix_len)) {
    cfc_file_start(pc->cfc, word_start);
    return cpl_file_completions(cpl, pc->cfc, line, word_end);
  };
/*
 * Look up the specified file name in each of the directories of the path,
 * in the same order that they were listed in the path, and stop as soon
 * as an instance of the file is found.
 */
  for(node=pc->head; node; node=node->next) {
/*
 * If the directory of the latest node is a relative pathname,
 * scan it for files of interest.
 */
    if(node->relative) {
      rst_CacheMem(node->mem);
      if(pca_scan_dir(pc, node->dir, node->mem) < 1)
	continue;
      node->files = node->mem->files;
      node->nfile = node->mem->nfiles;
    };
/*
 * If needed, make a copy of the file-name being matched, with
 * escapes removed. Note that we need to do this anew every loop
 * iteration, because the above call to pca_scan_dir() uses
 * pc->path.
 */
    prefix = pca_prepare_prefix(pc, start_path, prefix_len, ppc->escaped);
    if(!prefix)
      return 1;
/*
 * The directory entries are sorted, so we can perform a binary
 * search for an instance of the prefix being searched for.
 */
    bot = 0;
    top = node->nfile - 1;
    while(top >= bot) {
      int mid = (top + bot)/2;
      int test = strncmp(node->files[mid]+1, prefix, prefix_len);
      if(test > 0)
	top = mid - 1;
      else if(test < 0)
	bot = mid + 1;
      else {
	top = bot = mid;
	break;
      };
    };
/*
 * If we found a match, look to see if any of its neigbors also match.
 */
    if(top == bot) {
      while(--bot >= 0 && strncmp(node->files[bot]+1, prefix, prefix_len) == 0)
	;
      while(++top < node->nfile &&
	    strncmp(node->files[top]+1, prefix, prefix_len) == 0)
	;
/*
 * We will have gone one too far in each direction.
 */
      bot++;
      top--;
/*
 * Add the completions to the list after checking them against the
 * callers requirements.
 */
      for( ; bot<=top; bot++) {
	char *match = node->files[bot];
/*
 * Form the full pathname of the file.
 */
	_pn_clear_path(pc->path);
	if(_pn_append_to_path(pc->path, node->dir, -1, 0) == NULL ||
	   _pn_append_to_path(pc->path, match+1, -1, 0) == NULL) {
	  _err_record_msg(pc->err, "Insufficient memory to complete file name",
			  END_ERR_MSG);
	  return 1;
	};
/*
 * Should the file be included in the list of completions?
 */
	if(!pc->check_fn || match[0] == PCA_F_WANTED ||
	   (match[0]==PCA_F_ENIGMA && pc->check_fn(pc->data, pc->path->name))) {
	  match[0] = PCA_F_WANTED;
/*
 * Copy the completion suffix into the work pathname pc->path->name,
 * adding backslash escapes if needed.
 */
	  if(pca_prepare_suffix(pc, match + 1 + prefix_len,
				ppc->escaped))
	    return 1;
/*
 * Record the completion.
 */
	  if(cpl_add_completion(cpl, line, word_start, word_end, pc->path->name,
				"", " "))
	    return 1;
/*
 * The file was rejected by the application.
 */
	} else {
	  match[0] = PCA_F_IGNORE;
	};
      };
    };
  };
/*
 * We now need to search for subdirectories of the current directory which
 * have matching prefixes. First, if needed, make a copy of the word being
 * matched, with escapes removed.
 */
  prefix = pca_prepare_prefix(pc, start_path, prefix_len, ppc->escaped);
  if(!prefix)
    return 1;
/*
 * Now open the current directory.
 */
  if(_dr_open_dir(pc->dr, FS_PWD, NULL))
    return 0;
/*
 * Scan the current directory for sub-directories whos names start with
 * the prefix that we are completing.
 */
  while((filename = _dr_next_file(pc->dr))) {
/*
 * Does the latest filename match the prefix, and is it a directory?
 */
    if(strncmp(filename, prefix, prefix_len) == 0 && _pu_path_is_dir(filename)){
/*
 * Record the completion.
 */
      if(pca_prepare_suffix(pc, filename + prefix_len, ppc->escaped) ||
	 cpl_add_completion(cpl, line, word_start, word_end, pc->path->name,
			    FS_DIR_SEP, FS_DIR_SEP))
	return 1;
/*
 * The prefix in pc->path->name will have been overwritten by
 * pca_prepare_suffix(). Restore it here.
 */
      prefix = pca_prepare_prefix(pc, start_path, prefix_len, ppc->escaped);
      if(!prefix)
	return 1;
    };
  };
  _dr_close_dir(pc->dr);
  return 0;
}

/*.......................................................................
 * Using the work buffer pc->path, make a suitably escaped copy of a
 * given completion suffix, ready to be passed to cpl_add_completion().
 *
 * Input:
 *  pc      PathCache *  The filename cache resource object.
 *  suffix       char *  The suffix to be copied.
 *  add_escapes   int    If true, escape special characters.
 * Output:
 *  return        int    0 - OK.
 *                       1 - Error.
 */
static int pca_prepare_suffix(PathCache *pc, const char *suffix,
			      int add_escapes)
{
  const char *sptr; /* A pointer into suffix[] */
  int nbsl;         /* The number of backslashes to add to the suffix */
  int i;
/*
 * How long is the suffix?
 */
  int suffix_len = strlen(suffix);
/*
 * Clear the work buffer.
 */
  _pn_clear_path(pc->path);
/*
 * Count the number of backslashes that will have to be added to
 * escape spaces, tabs, backslashes and wildcard characters.
 */
  nbsl = 0;
  if(add_escapes) {
    for(sptr = suffix; *sptr; sptr++) {
      switch(*sptr) {
      case ' ': case '\t': case '\\': case '*': case '?': case '[':
	nbsl++;
	break;
      };
    };
  };
/*
 * Arrange for the output path buffer to have sufficient room for the
 * both the suffix and any backslashes that have to be inserted.
 */
  if(_pn_resize_path(pc->path, suffix_len + nbsl) == NULL) {
    _err_record_msg(pc->err, "Insufficient memory to complete file name",
		    END_ERR_MSG);
    return 1;
  };
/*
 * If the suffix doesn't need any escapes, copy it directly into the
 * work buffer.
 */
  if(nbsl==0) {
    strlcpy(pc->path->name, suffix, pc->path->dim);
  } else {
/*
 * Make a copy with special characters escaped?
 */
    if(nbsl > 0) {
      const char *src = suffix;
      char *dst = pc->path->name;
      for(i=0; i<suffix_len; i++) {
	switch(*src) {
	case ' ': case '\t': case '\\': case '*': case '?': case '[':
	  *dst++ = '\\';
	};
	*dst++ = *src++;
      };
      *dst = '\0';
    };
  };
  return 0;
}

/*.......................................................................
 * Return non-zero if the specified string appears to start with a pathname.
 *
 * Input:
 *  prefix  const char *  The filename prefix to check.
 *  prefix_len     int    The length of the prefix.
 * Output:
 *  return         int    0 - Doesn't start with a path name.
 *                        1 - Does start with a path name.
 */
static int cpa_cmd_contains_path(const char *prefix, int prefix_len)
{
  int i;
/*
 * If the filename starts with a ~, then this implies a ~username
 * expression, which constitutes a pathname.
 */
  if(*prefix == '~')
    return 1;
/*
 * If the filename starts with the root directory, then it obviously
 * starts with a pathname.
 */
  if(prefix_len >= FS_ROOT_DIR_LEN && 
     strncmp(prefix, FS_ROOT_DIR, FS_ROOT_DIR_LEN) == 0)
    return 1;
/*
 * Search the prefix for directory separators, returning as soon as
 * any are found, since their presence indicates that the filename
 * starts with a pathname specification (valid or otherwise).
 */
  for(i=0; i<prefix_len; i++) {
    if(prefix_len - i >= FS_DIR_SEP_LEN &&
       strncmp(prefix + i, FS_DIR_SEP, FS_DIR_SEP_LEN) == 0)
      return 1;
  };
/*
 * The file name doesn't appear to start with a pathname specification.
 */
  return 0;
}

/*.......................................................................
 * If needed make a new copy of the prefix being matched, in pc->path->name,
 * but with escapes removed. If no escapes are to be removed, simply return
 * the original prefix string.
 *
 * Input:
 *  pc      PathCache *   The cache being searched.
 *  prefix const char *   The prefix to be processed.
 *  prefix_len size_t     The length of the prefix.
 *  escaped       int     If true, return a copy with escapes removed.
 * Output:
 *  return const char *   The prepared prefix, or NULL on error, in
 *                        which case an error message will have been
 *                        left in pc->err.
 */
static const char *pca_prepare_prefix(PathCache *pc, const char *prefix,
				      size_t prefix_len, int escaped)
{
/*
 * Make a copy with escapes removed?
 */
  if(escaped) {
    _pn_clear_path(pc->path);
    if(_pn_append_to_path(pc->path, prefix, prefix_len, 1) == NULL) {
      _err_record_msg(pc->err, "Insufficient memory to complete filename",
		      END_ERR_MSG);
      return NULL;
    };
    return pc->path->name;
  };
  return prefix;
}

/*.......................................................................
 * If backslashes in the filename should be treated as literal
 * characters, call the following function with literal=1. Otherwise
 * the default is to treat them as escape characters, used for escaping
 * spaces etc..
 *
 * Input:
 *  ppc    PcaPathConf *  The pca_path_completions() configuration object
 *                        to be configured.
 *  literal        int    Pass non-zero here to enable literal interpretation
 *                        of backslashes. Pass 0 to turn off literal
 *                        interpretation.
 */
void ppc_literal_escapes(PcaPathConf *ppc, int literal)
{
  if(ppc)
    ppc->escaped = !literal;
}

/*.......................................................................
 * Call this function if you know where the index at which the
 * filename prefix starts in the input line. Otherwise by default,
 * or if you specify start_index to be -1, the filename is taken
 * to start after the first unescaped space preceding the cursor,
 * or the start of the line, which ever comes first.
 *
 * Input:
 *  ppc    PcaPathConf *  The pca_path_completions() configuration object
 *                        to be configured.
 *  start_index    int    The index of the start of the filename in
 *                        the input line, or -1 to select the default.
 */
void ppc_file_start(PcaPathConf *ppc, int start_index)
{
  if(ppc)
    ppc->file_start = start_index;
}

/*.......................................................................
 * Expand any ~user expression found at the start of a path, leaving
 * either an empty string in pc->path if there is no ~user expression,
 * or the corresponding home directory.
 *
 * Input:
 *  pc     PathCache *  The filename cache.
 *  path  const char *  The path to expand.
 *  pathlen      int    The max number of characters to look at in path[].
 *  literal      int    If true, treat backslashes as literal characters
 *                      instead of escapes.
 * Input/Output:
 *  endp  const char *  A pointer to the next unprocessed character in
 *                      path[] will be assigned to *endp.
 * Output:
 *  return       int    0 - OK
 *                      1 - Error (a description will have been placed
 *                                 in pc->err).
 */
static int pca_expand_tilde(PathCache *pc, const char *path, int pathlen,
			    int literal, const char **endp)
{
  const char *pptr = path;  /* A pointer into path[] */
  const char *homedir=NULL; /* A home directory */
/*
 * Clear the pathname buffer.
 */
  _pn_clear_path(pc->path);
/*
 * If the first character is a tilde, then perform home-directory
 * interpolation.
 */
  if(*pptr == '~') {
/*
 * Skip the tilde character and attempt to read the username that follows
 * it, into pc->usrnam[].
 */
    if(pca_read_username(pc, ++pptr, pathlen-1, literal, &pptr))
      return 1;
/*
 * Attempt to lookup the home directory of the user.
 */
    homedir = _hd_lookup_home_dir(pc->home, pc->usrnam);
    if(!homedir) {
      _err_record_msg(pc->err, _hd_last_home_dir_error(pc->home), END_ERR_MSG);
      return 1;
    };
/*
 * Append the home directory to the pathname string.
 */
    if(_pn_append_to_path(pc->path, homedir, -1, 0) == NULL) {
      _err_record_msg(pc->err,
		      "Insufficient memory for home directory expansion",
		      END_ERR_MSG);
      return 1;
    };
  };
/*
 * ~user and ~ are usually followed by a directory separator to
 * separate them from the file contained in the home directory.
 * If the home directory is the root directory, then we don't want
 * to follow the home directory by a directory separator, so we should
 * skip over it so that it doesn't get copied into the output pathname
 */
  if(homedir && strcmp(homedir, FS_ROOT_DIR) == 0 &&
     (pptr-path) + FS_DIR_SEP_LEN < pathlen &&
     strncmp(pptr, FS_DIR_SEP, FS_DIR_SEP_LEN) == 0) {
    pptr += FS_DIR_SEP_LEN;
  };
/*
 * Return a pointer to the next unprocessed character.
 */
  *endp = pptr;
  return 0;
}

/*.......................................................................
 * Clear the filename status codes that are recorded before each filename
 * in the cache.
 *
 * Input:
 *  pc     PathCache *  The filename cache.
 */
static void pca_remove_marks(PathCache *pc)
{
  PathNode *node;         /* A node in the list of directories in the path */
  int i;
/*
 * Traverse the absolute directories of the path, clearing the
 * filename status marks that precede each filename.
 */
  for(node=pc->head; node; node=node->next) {
    if(!node->relative) {
      for(i=0; i<node->nfile; i++)
	*node->files[i] = PCA_F_ENIGMA;
    };
  };
  return;
}

#endif  /* ifndef WITHOUT_FILE_SYSTEM */
