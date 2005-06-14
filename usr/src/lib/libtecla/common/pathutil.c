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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "pathutil.h"

/*.......................................................................
 * Create a new PathName object.
 *
 * Output:
 *  return  PathName *  The new object, or NULL on error.
 */
PathName *_new_PathName(void)
{
  PathName *path;  /* The object to be returned */
/*
 * Allocate the container.
 */
  path = (PathName *) malloc(sizeof(PathName));
  if(!path) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to _del_PathName().
 */
  path->name = NULL;
  path->dim = 0;
/*
 * Figure out the maximum length of an expanded pathname.
 */
  path->dim = _pu_pathname_dim();
  if(path->dim == 0)
    return _del_PathName(path);
/*
 * Allocate the pathname buffer.
 */
  path->name = (char *)malloc(path->dim * sizeof(char));
  if(!path->name) {
    errno = ENOMEM;
    return _del_PathName(path);
  };
  return path;
}

/*.......................................................................
 * Delete a PathName object.
 *
 * Input:
 *  path   PathName *  The object to be deleted.
 * Output:
 *  return PathName *  The deleted object (always NULL).
 */
PathName *_del_PathName(PathName *path)
{
  if(path) {
    if(path->name)
      free(path->name);
    free(path);
  };
  return NULL;
}

/*.......................................................................
 * Return the pathname to a zero-length string.
 *
 * Input:
 *  path     PathName *  The pathname container.
 * Output:
 *  return       char *  The cleared pathname buffer, or NULL on error.
 */
char *_pn_clear_path(PathName *path)
{
/*
 * Check the arguments.
 */
  if(!path) {
    errno = EINVAL;
    return NULL;
  };
  path->name[0] = '\0';
  return path->name;
}

/*.......................................................................
 * Append a string to a pathname, increasing the size of the pathname
 * buffer if needed.
 *
 * Input:
 *  path        PathName *  The pathname container.
 *  string    const char *  The string to be appended to the pathname.
 *                          Note that regardless of the slen argument,
 *                          this should be a '\0' terminated string.
 *  slen             int    The maximum number of characters to append
 *                          from string[], or -1 to append the whole
 *                          string.
 *  remove_escapes   int    If true, remove the backslashes that escape
 *                          spaces, tabs, backslashes etc..
 * Output:
 *  return          char *  The pathname string path->name[], which may
 *                          have been reallocated, or NULL if there was
 *                          insufficient memory to extend the pathname.
 */
char *_pn_append_to_path(PathName *path, const char *string, int slen,
			int remove_escapes)
{
  int pathlen;     /* The length of the pathname */
  int i;
/*
 * Check the arguments.
 */
  if(!path || !string) {
    errno = EINVAL;
    return NULL;
  };
/*
 * Get the current length of the pathname.
 */
  pathlen = strlen(path->name);
/*
 * How many characters should be appended?
 */
  if(slen < 0 || slen > strlen(string))
    slen = strlen(string);
/*
 * Resize the pathname if needed.
 */
  if(!_pn_resize_path(path, pathlen + slen))
    return NULL;
/*
 * Append the string to the output pathname, removing any escape
 * characters found therein.
 */
  if(remove_escapes) {
    int is_escape = 0;
    for(i=0; i<slen; i++) {
      is_escape = !is_escape && string[i] == '\\';
      if(!is_escape)
	path->name[pathlen++] = string[i];
    };
/*
 * Terminate the string.
 */
    path->name[pathlen] = '\0';
  } else {
/*
 * Append the string directly to the pathname.
 */
    memcpy(path->name + pathlen, string, slen);
    path->name[pathlen + slen] = '\0';
  };
  return path->name;
}

/*.......................................................................
 * Prepend a string to a pathname, increasing the size of the pathname
 * buffer if needed.
 *
 * Input:
 *  path        PathName *  The pathname container.
 *  string    const char *  The string to be prepended to the pathname.
 *                          Note that regardless of the slen argument,
 *                          this should be a '\0' terminated string.
 *  slen             int    The maximum number of characters to prepend
 *                          from string[], or -1 to append the whole
 *                          string.
 *  remove_escapes   int    If true, remove the backslashes that escape
 *                          spaces, tabs, backslashes etc..
 * Output:
 *  return          char *  The pathname string path->name[], which may
 *                          have been reallocated, or NULL if there was
 *                          insufficient memory to extend the pathname.
 */
char *_pn_prepend_to_path(PathName *path, const char *string, int slen,
			  int remove_escapes)
{
  int pathlen;     /* The length of the pathname */
  int shift;       /* The number of characters to shift the suffix by */
  int i,j;
/*
 * Check the arguments.
 */
  if(!path || !string) {
    errno = EINVAL;
    return NULL;
  };
/*
 * Get the current length of the pathname.
 */
  pathlen = strlen(path->name);
/*
 * How many characters should be appended?
 */
  if(slen < 0 || slen > strlen(string))
    slen = strlen(string);
/*
 * Work out how far we need to shift the original path string to make
 * way for the new prefix. When removing escape characters, we need
 * final length of the new prefix, after unescaped backslashes have
 * been removed.
 */
  if(remove_escapes) {
    int is_escape = 0;
    for(shift=0,i=0; i<slen; i++) {
      is_escape = !is_escape && string[i] == '\\';
      if(!is_escape)
	shift++;
    };
  } else {
    shift = slen;
  };
/*
 * Resize the pathname if needed.
 */
  if(!_pn_resize_path(path, pathlen + shift))
    return NULL;
/*
 * Make room for the prefix at the beginning of the string.
 */
  memmove(path->name + shift, path->name, pathlen+1);
/*
 * Copy the new prefix into the vacated space at the beginning of the
 * output pathname, removing any escape characters if needed.
 */
  if(remove_escapes) {
    int is_escape = 0;
    for(i=j=0; i<slen; i++) {
      is_escape = !is_escape && string[i] == '\\';
      if(!is_escape)
	path->name[j++] = string[i];
    };
  } else {
    memcpy(path->name, string, slen);
  };
  return path->name;
}

/*.......................................................................
 * If needed reallocate a given pathname buffer to allow a string of
 * a given length to be stored in it.
 *
 * Input:
 *  path     PathName *  The pathname container object.
 *  length     size_t    The required length of the pathname buffer,
 *                       not including the terminating '\0'.
 * Output:
 *  return       char *  The pathname buffer, or NULL if there was
 *                       insufficient memory.
 */
char *_pn_resize_path(PathName *path, size_t length)
{
/*
 * Check the arguments.
 */
  if(!path) {
    errno = EINVAL;
    return NULL;
  };
/*
 * If the pathname buffer isn't large enough to accomodate a string
 * of the specified length, attempt to reallocate it with the new
 * size, plus space for a terminating '\0'. Also add a bit of
 * head room to prevent too many reallocations if the initial length
 * turned out to be very optimistic.
 */
  if(length + 1 > path->dim) {
    size_t dim =  length + 1 + PN_PATHNAME_INC;
    char *name = (char *) realloc(path->name, dim);
    if(!name)
      return NULL;
    path->name = name;
    path->dim = dim;
  };
  return path->name;
}

/*.......................................................................
 * Estimate the largest amount of space needed to store a pathname.
 *
 * Output:
 *  return size_t   The number of bytes needed, including space for the
 *                  terminating '\0'.
 */
size_t _pu_pathname_dim(void)
{
  int maxlen;   /* The return value excluding space for the '\0' */
/*
 * If the POSIX PATH_MAX macro is defined in limits.h, use it.
 */
#ifdef PATH_MAX
  maxlen = PATH_MAX;
/*
 * If we have pathconf, use it.
 */
#elif defined(_PC_PATH_MAX)
  errno = 0;
  maxlen = pathconf(FS_ROOT_DIR, _PC_PATH_MAX);
  if(maxlen <= 0 || errno)
    maxlen = MAX_PATHLEN_FALLBACK;
/*
 * None of the above approaches worked, so substitute our fallback
 * guess.
 */
#else
    maxlen = MAX_PATHLEN_FALLBACK;
#endif
/*
 * Return the amount of space needed to accomodate a pathname plus
 * a terminating '\0'.
 */
  return maxlen + 1;
}

/*.......................................................................
 * Return non-zero if the specified path name refers to a directory.
 *
 * Input:
 *  pathname  const char *  The path to test.
 * Output:
 *  return           int    0 - Not a directory.
 *                          1 - pathname[] refers to a directory.
 */
int _pu_path_is_dir(const char *pathname)
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

/*.......................................................................
 * Return non-zero if the specified path name refers to a regular file.
 *
 * Input:
 *  pathname  const char *  The path to test.
 * Output:
 *  return           int    0 - Not a regular file.
 *                          1 - pathname[] refers to a regular file.
 */
int _pu_path_is_file(const char *pathname)
{
  struct stat statbuf;    /* The file-statistics return buffer */
/*
 * Look up the file attributes.
 */
  if(stat(pathname, &statbuf) < 0)
    return 0;
/*
 * Is the file a regular file?
 */
  return S_ISREG(statbuf.st_mode) != 0;
}

/*.......................................................................
 * Return non-zero if the specified path name refers to an executable.
 *
 * Input:
 *  pathname  const char *  The path to test.
 * Output:
 *  return           int    0 - Not an executable file.
 *                          1 - pathname[] refers to an executable file.
 */
int _pu_path_is_exe(const char *pathname)
{
  struct stat statbuf;    /* The file-statistics return buffer */
/*
 * Look up the file attributes.
 */
  if(stat(pathname, &statbuf) < 0)
    return 0;
/*
 * Is the file a regular file which is executable by the current user.
 */
  return S_ISREG(statbuf.st_mode) != 0 &&
    (statbuf.st_mode & (S_IXOTH | S_IXGRP | S_IXUSR)) &&
    access(pathname, X_OK) == 0;
}

/*.......................................................................
 * Search backwards for the potential start of a filename. This
 * looks backwards from the specified index in a given string,
 * stopping at the first unescaped space or the start of the line.
 *
 * Input:
 *  string  const char *  The string to search backwards in.
 *  back_from      int    The index of the first character in string[]
 *                        that follows the pathname.
 * Output:
 *  return        char *  The pointer to the first character of
 *                        the potential pathname, or NULL on error.
 */
char *_pu_start_of_path(const char *string, int back_from)
{
  int i, j;
/*
 * Check the arguments.
 */
  if(!string || back_from < 0) {
    errno = EINVAL;
    return NULL;
  };
/*
 * Search backwards from the specified index.
 */
  for(i=back_from-1; i>=0; i--) {
    int c = string[i];
/*
 * Stop on unescaped spaces.
 */
    if(isspace((int)(unsigned char)c)) {
/*
 * The space can't be escaped if we are at the start of the line.
 */
      if(i==0)
        break;
/*
 * Find the extent of the escape characters which precedes the space.
 */
      for(j=i-1; j>=0 && string[j]=='\\'; j--)
	;
/*
 * If there isn't an odd number of escape characters before the space,
 * then the space isn't escaped.
 */
      if((i - 1 - j) % 2 == 0)
	break;
    };
  };
  return (char *)string + i + 1;
}

/*.......................................................................
 * Find the length of a potential filename starting from a given
 * point. This looks forwards from the specified index in a given string,
 * stopping at the first unescaped space or the end of the line.
 *
 * Input:
 *  string   const char *  The string to search backwards in.
 *  start_from      int    The index of the first character of the pathname
 *                         in string[].
 * Output:
 *  return         char *  The pointer to the character that follows
 *                         the potential pathname, or NULL on error.
 */
char *_pu_end_of_path(const char *string, int start_from)
{
  int c;             /* The character being examined */
  int escaped = 0;   /* True when the next character is escaped */
  int i;
/*
 * Check the arguments.
 */
  if(!string || start_from < 0) {
    errno = EINVAL;
    return NULL;
  };
/*
 * Search forwards from the specified index.
 */
  for(i=start_from; (c=string[i]) != '\0'; i++) {
    if(escaped) {
      escaped = 0;
    } else if(isspace(c)) {
      break;
    } else if(c == '\\') {
      escaped = 1;
    };
  };
  return (char *)string + i;
}

/*.......................................................................
 * Return non-zero if the specified path name refers to an existing file.
 *
 * Input:
 *  pathname   const char *  The path to test.
 * Output:
 *  return            int    0 - The file doesn't exist.
 *                           1 - The file does exist.
 */
int _pu_file_exists(const char *pathname)
{
  struct stat statbuf;
  return stat(pathname, &statbuf) == 0;
}

#endif  /* ifndef WITHOUT_FILE_SYSTEM */
