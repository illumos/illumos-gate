#ifndef pathutil_h
#define pathutil_h

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
 * The following object encapsulates a buffer designed to be used to
 * store pathnames. The pathname member of the object is initially
 * allocated with the size that _pu_pathname_dim() returns, and then
 * if this turns out to be pessimistic, the pathname can be reallocated
 * via calls to pb_append_to_path() and/or pb_resize_path().
 */
typedef struct {
  char *name;         /* The path buffer */
  size_t dim;         /* The current allocated size of buffer[] */
} PathName;

PathName *_new_PathName(void);
PathName *_del_PathName(PathName *path);

char *_pn_clear_path(PathName *path);
char *_pn_append_to_path(PathName *path, const char *string, int slen,
			int remove_escapes);
char *_pn_prepend_to_path(PathName *path, const char *string, int slen,
			  int remove_escapes);
char *_pn_resize_path(PathName *path, size_t length);

/*
 * Search backwards for the potential start of a filename. This
 * looks backwards from the specified index in a given string,
 * stopping at the first unescaped space or the start of the line.
 */
char *_pu_start_of_path(const char *string, int back_from);

/*
 * Find the end of a potential filename, starting from a given index
 * in the string. This looks forwards from the specified index in a
 * given string, stopping at the first unescaped space or the end
 * of the line.
 */
char *_pu_end_of_path(const char *string, int start_from);


/*
 * Return an estimate of the the length of the longest pathname
 * on the local system.
 */
size_t _pu_pathname_dim(void);

/*
 * Return non-zero if the specified path name refers to a directory.
 */
int _pu_path_is_dir(const char *pathname);

/*
 * Return non-zero if the specified path name refers to a regular file.
 */
int _pu_path_is_file(const char *pathname);

/*
 * Return non-zero if the specified path name refers to an executable.
 */
int _pu_path_is_exe(const char *pathname);

/*
 * Return non-zero if a file exists with the specified pathname.
 */
int _pu_file_exists(const char *pathname);

/*
 * If neither the POSIX PATH_MAX macro nor the pathconf() function
 * can be used to find out the maximum pathlength on the target
 * system, the following fallback maximum length is used.
 */
#define MAX_PATHLEN_FALLBACK 1024

/*
 * If the pathname buffer turns out to be too small, it will be extended
 * in chunks of the following amount (plus whatever is needed at the time).
 */
#define PN_PATHNAME_INC 100

/*
 * Define the special character-sequences of the filesystem.
 */
#define FS_ROOT_DIR "/"     /* The root directory */
#define FS_ROOT_DIR_LEN (sizeof(FS_ROOT_DIR) - 1)
#define FS_PWD "."          /* The current working directory */
#define FS_PWD_LEN (sizeof(FS_PWD_LEN) - 1)
#define FS_DIR_SEP "/"      /* The directory separator string */
#define FS_DIR_SEP_LEN (sizeof(FS_DIR_SEP) - 1)

#endif
