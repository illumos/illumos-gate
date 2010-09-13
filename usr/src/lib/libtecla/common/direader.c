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

/*
 * If file-system access is to be excluded, this module has no function,
 * so all of its code should be excluded.
 */
#ifndef WITHOUT_FILE_SYSTEM

/*
 * Standard includes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
 * Operating system includes.
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include "direader.h"
#include "errmsg.h"

/*
 * Use the reentrant POSIX threads version of readdir()?
 */
#if defined(PREFER_REENTRANT) && defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 199506L
#define USE_READDIR_R 1
#endif

/*
 * Objects of the following type are used to maintain the resources
 * needed to read directories.
 */
struct DirReader {
  ErrMsg *err;             /* The error reporting buffer */
  DIR *dir;                /* The directory stream (if open, NULL otherwise) */
  struct dirent *file;     /* The latest directory entry */
#ifdef USE_READDIR_R
  struct dirent *buffer;   /* A buffer used by the threaded version of */
                           /*  readdir() */
  int buffer_dim;          /* The allocated size of buffer[] */
#endif
};

static int _dr_path_is_dir(const char *pathname);

/*.......................................................................
 * Create a new DirReader object.
 *
 * Output:
 *  return  DirReader *  The new object, or NULL on error.
 */
DirReader *_new_DirReader(void)
{
  DirReader *dr;  /* The object to be returned */
/*
 * Allocate the container.
 */
  dr = (DirReader *) malloc(sizeof(DirReader));
  if(!dr) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to _del_DirReader().
 */
  dr->err = NULL;
  dr->dir = NULL;
  dr->file = NULL;
#ifdef USE_READDIR_R
  dr->buffer = NULL;
  dr->buffer_dim = 0;
#endif
/*
 * Allocate a place to record error messages.
 */
  dr->err = _new_ErrMsg();
  if(!dr->err)
    return _del_DirReader(dr);
  return dr;
}

/*.......................................................................
 * Delete a DirReader object.
 *
 * Input:
 *  dr     DirReader *  The object to be deleted.
 * Output:
 *  return DirReader *  The deleted object (always NULL).
 */
DirReader *_del_DirReader(DirReader *dr)
{
  if(dr) {
    _dr_close_dir(dr);
#ifdef USE_READDIR_R
    free(dr->buffer);
#endif
    dr->err = _del_ErrMsg(dr->err);
    free(dr);
  };
  return NULL;
}

/*.......................................................................
 * Open a new directory.
 *
 * Input:
 *  dr      DirReader *   The directory reader resource object.
 *  path   const char *   The directory to be opened.
 * Input/Output:
 *  errmsg       char **  If an error occurs and errmsg isn't NULL, a
 *                        pointer to an error description will be assigned
 *                        to *errmsg.
 * Output:
 *  return        int     0 - OK.
 *                        1 - Error (see *errmsg for a description).
 */
int _dr_open_dir(DirReader *dr, const char *path, char **errmsg)
{
  DIR *dir = NULL;   /* The directory stream */
/*
 * If a directory is already open, close it first.
 */
  (void) _dr_close_dir(dr);
/*
 * Is the path a directory?
 */
  if(!_dr_path_is_dir(path)) {
    if(errmsg) {
      _err_record_msg(dr->err, "Can't open directory: ", path, END_ERR_MSG);
      *errmsg = _err_get_msg(dr->err);
    };
    return 1;
  };
/*
 * Attempt to open the directory.
 */
  dir = opendir(path);
  if(!dir) {
    if(errmsg) {
      _err_record_msg(dr->err, "Can't open directory: ", path, END_ERR_MSG);
      *errmsg = _err_get_msg(dr->err);
    };
    return 1;
  };
/*
 * If using POSIX threads, allocate a buffer for readdir_r().
 */
#ifdef USE_READDIR_R
  {
    size_t size;
    int name_max = pathconf(path, _PC_NAME_MAX);
#ifdef NAME_MAX
    if(name_max < 0)
      name_max = NAME_MAX;
#endif
    if(name_max < 0) {
      if(errmsg) {
	_err_record_msg(dr->err, "Unable to deduce readdir() buffer size.",
			END_ERR_MSG);
	*errmsg = _err_get_msg(dr->err);
      };
      closedir(dir);
      return 1;
    };
/*
 * How big a buffer do we need to allocate?
 */
    size = sizeof(struct dirent) + name_max;
/*
 * Extend the buffer?
 */
    if(size > dr->buffer_dim || !dr->buffer) {
      struct dirent *buffer = (struct dirent *) (dr->buffer ?
						 realloc(dr->buffer, size) :
						 malloc(size));
      if(!buffer) {
	if(errmsg) {
	  _err_record_msg(dr->err, "Insufficient memory for readdir() buffer.",
			  END_ERR_MSG);
	  *errmsg = _err_get_msg(dr->err);
	};
	closedir(dir);
	errno = ENOMEM;
	return 1;
      };
      dr->buffer = buffer;
      dr->buffer_dim = size;
    };
  };
#endif
/*
 * Record the successfully opened directory.
 */
  dr->dir = dir;
  return 0;
}

/*.......................................................................
 * If the DirReader object is currently contains an open directory,
 * close it.
 *
 * Input:
 *  dr    DirReader *   The directory reader resource object.
 */
void _dr_close_dir(DirReader *dr)
{
  if(dr && dr->dir) {
    closedir(dr->dir);
    dr->dir = NULL;
    dr->file = NULL;
    _err_clear_msg(dr->err);
  };
}

/*.......................................................................
 * Read the next file from the directory opened with _dr_open_dir().
 *
 * Input:
 *  dr    DirReader *  The directory reader resource object.
 * Output:
 *  return     char *  The name of the new file, or NULL if we reached
 *                     the end of the directory.
 */
char *_dr_next_file(DirReader *dr)
{
/*
 * Are we currently reading a directory?
 */
  if(dr->dir) {
/*
 * Read the next directory entry.
 */
#ifdef USE_READDIR_R 
    if(readdir_r(dr->dir, dr->buffer, &dr->file) == 0 && dr->file)
      return dr->file->d_name;
#else
    dr->file = readdir(dr->dir);
    if(dr->file)
      return dr->file->d_name;
#endif
  };
/*
 * When the end of a directory is reached, close it.
 */
  _dr_close_dir(dr);
  return NULL;
}

/*.......................................................................
 * Return 1 if the specified pathname refers to a directory.
 *
 * Input:
 *  pathname  const char *  The path to test.
 * Output:
 *  return           int    0 - Not a directory.
 *                          1 - pathname[] refers to a directory.
 */
static int _dr_path_is_dir(const char *pathname)
{
  struct stat statbuf;    /* The file-statistics return buffer */
/*
 * Look up the file attributes.
 */
  if(stat(pathname, &statbuf) < 0)
    return 0;
/*
 * Is the file a directory?
 */
  return S_ISDIR(statbuf.st_mode) != 0;
}

#endif  /* ifndef WITHOUT_FILE_SYSTEM */
