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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#include "pathutil.h"
#include "homedir.h"
#include "errmsg.h"

/*
 * Use the reentrant POSIX threads versions of the password lookup functions?
 */
#if defined(PREFER_REENTRANT) && defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 199506L
#define THREAD_COMPATIBLE 1
/*
 * Under Solaris we can use thr_main() to determine whether
 * threads are actually running, and thus when it is necessary
 * to avoid non-reentrant features.
 */
#if defined __sun && defined __SVR4
#include <thread.h>                      /* Solaris thr_main() */
#endif
#endif

/*
 * Provide a password buffer size fallback in case the max size reported
 * by sysconf() is said to be indeterminate.
 */
#define DEF_GETPW_R_SIZE_MAX 1024

/*
 * The resources needed to lookup and record a home directory are
 * maintained in objects of the following type.
 */
struct HomeDir {
  ErrMsg *err;             /* The error message report buffer */
  char *buffer;            /* A buffer for reading password entries and */
                           /*  directory paths. */
  int buflen;              /* The allocated size of buffer[] */
#ifdef THREAD_COMPATIBLE
  struct passwd pwd;       /* The password entry of a user */
#endif
};

static const char *hd_getpwd(HomeDir *home);

/*.......................................................................
 * Create a new HomeDir object.
 *
 * Output:
 *  return  HomeDir *  The new object, or NULL on error.
 */
HomeDir *_new_HomeDir(void)
{
  HomeDir *home;  /* The object to be returned */
  size_t pathlen; /* The estimated maximum size of a pathname */
/*
 * Allocate the container.
 */
  home = (HomeDir *) malloc(sizeof(HomeDir));
  if(!home) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to _del_HomeDir().
 */
  home->err = NULL;
  home->buffer = NULL;
  home->buflen = 0;
/*
 * Allocate a place to record error messages.
 */
  home->err = _new_ErrMsg();
  if(!home->err)
    return _del_HomeDir(home);
/*
 * Allocate the buffer that is used by the reentrant POSIX password-entry
 * lookup functions.
 */
#ifdef THREAD_COMPATIBLE
/*
 * Get the length of the buffer needed by the reentrant version
 * of getpwnam().
 */
#ifndef _SC_GETPW_R_SIZE_MAX
  home->buflen = DEF_GETPW_R_SIZE_MAX;
#else
  errno = 0;
  home->buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
/*
 * If the limit isn't available, substitute a suitably large fallback value.
 */
  if(home->buflen < 0 || errno)
    home->buflen = DEF_GETPW_R_SIZE_MAX;
#endif
#endif
/*
 * If the existing buffer length requirement is too restrictive to record
 * a pathname, increase its length.
 */
  pathlen = _pu_pathname_dim();
  if(pathlen > home->buflen)
    home->buflen = pathlen;
/*
 * Allocate a work buffer.
 */
  home->buffer = (char *) malloc(home->buflen);
  if(!home->buffer) {
    errno = ENOMEM;
    return _del_HomeDir(home);
  };
  return home;
}

/*.......................................................................
 * Delete a HomeDir object.
 *
 * Input:
 *  home   HomeDir *  The object to be deleted.
 * Output:
 *  return HomeDir *  The deleted object (always NULL).
 */
HomeDir *_del_HomeDir(HomeDir *home)
{
  if(home) {
    home->err = _del_ErrMsg(home->err);
    if(home->buffer)
      free(home->buffer);
    free(home);
  };
  return NULL;
}

/*.......................................................................
 * Lookup the home directory of a given user in the password file.
 *
 * Input:
 *  home      HomeDir *   The resources needed to lookup the home directory.
 *  user   const char *   The name of the user to lookup, or "" to lookup
 *                        the home directory of the person running the
 *                        program.
 * Output:
 *  return const char *   The home directory. If the library was compiled
 *                        with threads, this string is part of the HomeDir
 *                        object and will change on subsequent calls. If
 *                        the library wasn't compiled to be reentrant,
 *                        then the string is a pointer into a static string
 *                        in the C library and will change not only on
 *                        subsequent calls to this function, but also if
 *                        any calls are made to the C library password
 *                        file lookup functions. Thus to be safe, you should
 *                        make a copy of this string before calling any
 *                        other function that might do a password file
 *                        lookup.
 *
 *                        On error, NULL is returned and a description
 *                        of the error can be acquired by calling
 *                        _hd_last_home_dir_error().
 */
const char *_hd_lookup_home_dir(HomeDir *home, const char *user)
{
  const char *home_dir;   /* A pointer to the home directory of the user */
/*
 * If no username has been specified, arrange to lookup the current
 * user.
 */
  int login_user = !user || *user=='\0';
/*
 * Check the arguments.
 */
  if(!home) {
    errno = EINVAL;
    return NULL;
  };
/*
 * Handle the ksh "~+". This expands to the absolute path of the
 * current working directory.
 */
  if(!login_user && strcmp(user, "+") == 0) {
    home_dir = hd_getpwd(home);
    if(!home_dir) {
      _err_record_msg(home->err, "Can't determine current directory",
		      END_ERR_MSG);
      return NULL;
    }
    return home_dir;
  };
/*
 * When looking up the home directory of the current user, see if the
 * HOME environment variable is set, and if so, return its value.
 */
  if(login_user) {
    home_dir = getenv("HOME");
    if(home_dir)
      return home_dir;
  };
/*
 * Look up the password entry of the user.
 * First the POSIX threads version - this is painful!
 */
#ifdef THREAD_COMPATIBLE
  {
    struct passwd *ret; /* The returned pointer to pwd */
    int status;         /* The return value of getpwnam_r() */
/*
 * Look up the password entry of the specified user.
 */
    if(login_user)
      status = getpwuid_r(geteuid(), &home->pwd, home->buffer, home->buflen,
			  &ret);
    else
      status = getpwnam_r(user, &home->pwd, home->buffer, home->buflen, &ret);
    if(status || !ret) {
      _err_record_msg(home->err, "User '", user, "' doesn't exist.",
		      END_ERR_MSG);
      return NULL;
    };
/*
 * Get a pointer to the string that holds the home directory.
 */
    home_dir = home->pwd.pw_dir;
  };
/*
 * Now the classic unix version.
 */
#else
  {
    struct passwd *pwd = login_user ? getpwuid(geteuid()) : getpwnam(user);
    if(!pwd) {
      _err_record_msg(home->err, "User '", user, "' doesn't exist.",
		      END_ERR_MSG);
      return NULL;
    };
/*
 * Get a pointer to the home directory.
 */
    home_dir = pwd->pw_dir;
  };
#endif
  return home_dir;
}

/*.......................................................................
 * Return a description of the last error that caused _hd_lookup_home_dir()
 * to return NULL.
 *
 * Input:
 *  home   HomeDir *  The resources needed to record the home directory.
 * Output:
 *  return    char *  The description of the last error.
 */
const char *_hd_last_home_dir_error(HomeDir *home)
{
  return home ? _err_get_msg(home->err) : "NULL HomeDir argument";
}

/*.......................................................................
 * The _hd_scan_user_home_dirs() function calls a user-provided function
 * for each username known by the system, passing the function both
 * the name and the home directory of the user.
 *
 * Input:
 *  home             HomeDir *  The resource object for reading home
 *                              directories.
 *  prefix        const char *  Only information for usernames that
 *                              start with this prefix will be
 *                              returned. Note that the empty
 &                              string "", matches all usernames.
 *  data                void *  Anonymous data to be passed to the
 *                              callback function.
 *  callback_fn  HOME_DIR_FN(*) The function to call for each user.
 * Output:
 *  return               int    0 - Successful completion.
 *                              1 - An error occurred. A description
 *                                  of the error can be obtained by
 *                                  calling _hd_last_home_dir_error().
 */
int _hd_scan_user_home_dirs(HomeDir *home, const char *prefix,
			    void *data, HOME_DIR_FN(*callback_fn))
{
  int waserr = 0;       /* True after errors */
  int prefix_len;       /* The length of prefix[] */
/*
 * Check the arguments.
 */
  if(!home || !prefix || !callback_fn) {
    if(home) {
      _err_record_msg(home->err,
		      "_hd_scan_user_home_dirs: Missing callback function",
		      END_ERR_MSG);
    };
    return 1;
  };
/*
 * Get the length of the username prefix.
 */
  prefix_len = strlen(prefix);
/*
 * There are no reentrant versions of getpwent() etc for scanning
 * the password file, so disable username completion when the
 * library is compiled to be reentrant.
 */
#if defined(PREFER_REENTRANT) && defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 199506L
#if defined __sun && defined __SVR4
  if(0)
#else
  if(1)
#endif
  {
    struct passwd pwd_buffer;  /* A returned password entry */
    struct passwd *pwd;        /* A pointer to pwd_buffer */
    char buffer[512];          /* The buffer in which the string members of */
                               /* pwd_buffer are stored. */
/*
 * See if the prefix that is being completed is a complete username.
 */
    if(!waserr && getpwnam_r(prefix, &pwd_buffer, buffer, sizeof(buffer),
			     &pwd) == 0 && pwd != NULL) {
      waserr = callback_fn(data, pwd->pw_name, pwd->pw_dir,
			   _err_get_msg(home->err), ERR_MSG_LEN);
    };
/*
 * See if the username of the current user minimally matches the prefix.
 */
    if(!waserr && getpwuid_r(getuid(), &pwd_buffer, buffer, sizeof(buffer),
			     &pwd) == 0 && pwd != NULL &&
                             strncmp(prefix, pwd->pw_name, prefix_len)==0) {
      waserr = callback_fn(data, pwd->pw_name, pwd->pw_dir,
			   _err_get_msg(home->err), ERR_MSG_LEN);
    };
/*
 * Reentrancy not required?
 */
  } else
#endif
  {
    struct passwd pwd_buffer;  /* A returned password entry */
    struct passwd *pwd;   /* The pointer to the latest password entry */
/*
 * Open the password file.
 */
    setpwent();
/*
 * Read the contents of the password file, looking for usernames
 * that start with the specified prefix, and adding them to the
 * list of matches.
 */
#if defined __sun && defined __SVR4
    while((pwd = getpwent_r(&pwd_buffer, home->buffer, home->buflen)) != NULL && !waserr) {
#else
    while((pwd = getpwent()) != NULL && !waserr) {
#endif
      if(strncmp(prefix, pwd->pw_name, prefix_len) == 0) {
	waserr = callback_fn(data, pwd->pw_name, pwd->pw_dir,
			     _err_get_msg(home->err), ERR_MSG_LEN);
      };
    };
/*
 * Close the password file.
 */
    endpwent();
  };
/*
 * Under ksh ~+ stands for the absolute pathname of the current working
 * directory.
 */
  if(!waserr && strncmp(prefix, "+", prefix_len) == 0) {
    const char *pwd = hd_getpwd(home);
    if(pwd) {
      waserr = callback_fn(data, "+", pwd, _err_get_msg(home->err),ERR_MSG_LEN);
    } else {
      waserr = 1;
      _err_record_msg(home->err, "Can't determine current directory.",
		      END_ERR_MSG);
    };
  };
  return waserr;
}

/*.......................................................................
 * Return the value of getenv("PWD") if this points to the current
 * directory, or the return value of getcwd() otherwise. The reason for
 * prefering PWD over getcwd() is that the former preserves the history
 * of symbolic links that have been traversed to reach the current
 * directory. This function is designed to provide the equivalent
 * expansion of the ksh ~+ directive, which normally returns its value
 * of PWD.
 *
 * Input:
 *  home      HomeDir *  The resource object for reading home directories.
 * Output:
 *  return const char *  A pointer to either home->buffer, where the
 *                       pathname is recorded, the string returned by
 *                       getenv("PWD"), or NULL on error.
 */
static const char *hd_getpwd(HomeDir *home)
{
/*
 * Get the absolute path of the current working directory.
 */
  char *cwd = getcwd(home->buffer, home->buflen);
/*
 * Some shells set PWD with the path of the current working directory.
 * This will differ from cwd in that it won't have had symbolic links
 * expanded.
 */
  const char *pwd = getenv("PWD");
/*
 * If PWD was set, and it points to the same directory as cwd, return
 * its value. Note that it won't be the same if the current shell or
 * the current program has changed directories, after inheriting PWD
 * from a parent shell.
 */
  struct stat cwdstat, pwdstat;
  if(pwd && cwd && stat(cwd, &cwdstat)==0 && stat(pwd, &pwdstat)==0 &&
     cwdstat.st_dev == pwdstat.st_dev && cwdstat.st_ino == pwdstat.st_ino)
    return pwd;
/*
 * Also return pwd if getcwd() failed, since it represents the best
 * information that we have access to.
 */
  if(!cwd)
    return pwd;
/*
 * In the absence of a valid PWD, return cwd.
 */
  return cwd;
}

#endif  /* ifndef WITHOUT_FILE_SYSTEM */
