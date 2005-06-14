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

/*
 * Standard includes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

/*
 * Local includes.
 */
#include "libtecla.h"
#include "direader.h"
#include "homedir.h"
#include "pathutil.h"
#include "cplfile.h"
#include "errmsg.h"

/*
 * Set the maximum length allowed for usernames.
 * names.
 */
#define USR_LEN 100

/*
 * Set the maximum length allowed for environment variable names.
 */
#define ENV_LEN 100

/*
 * The resources needed to complete a filename are maintained in objects
 * of the following type.
 */
struct CompleteFile {
  ErrMsg *err;                 /* The error reporting buffer */
  DirReader *dr;               /* A directory reader */
  HomeDir *home;               /* A home directory expander */
  PathName *path;              /* The buffer in which to accumulate the path */
  PathName *buff;              /* A pathname work buffer */
  char usrnam[USR_LEN+1];      /* The buffer used when reading the names of */
                               /*  users. */
  char envnam[ENV_LEN+1];      /* The buffer used when reading the names of */
                               /*  environment variables. */
};

static int cf_expand_home_dir(CompleteFile *cf, const char *user);
static int cf_complete_username(CompleteFile *cf, WordCompletion *cpl,
				const char *prefix, const char *line,
				int word_start, int word_end, int escaped);
static HOME_DIR_FN(cf_homedir_callback);
static int cf_complete_entry(CompleteFile *cf, WordCompletion *cpl,
			     const char *line, int word_start, int word_end,
			     int escaped, CplCheckFn *check_fn,
			     void *check_data);
static char *cf_read_name(CompleteFile *cf, const char *type,
			  const char *string, int slen,
			  char *nambuf, int nammax);
static int cf_prepare_suffix(CompleteFile *cf, const char *suffix,
			     int add_escapes);

/*
 * A stack based object of the following type is used to pass data to the
 * cf_homedir_callback() function.
 */
typedef struct {
  CompleteFile *cf;    /* The file-completion resource object */
  WordCompletion *cpl; /* The string-completion rsource object */
  size_t prefix_len;   /* The length of the prefix being completed */
  const char *line;    /* The line from which the prefix was extracted */
  int word_start;      /* The index in line[] of the start of the username */
  int word_end;        /* The index in line[] following the end of the prefix */
  int escaped;         /* If true, add escapes to the completion suffixes */
} CfHomeArgs;

/*.......................................................................
 * Create a new file-completion object.
 *
 * Output:
 *  return  CompleteFile *  The new object, or NULL on error.
 */
CompleteFile *_new_CompleteFile(void)
{
  CompleteFile *cf;  /* The object to be returned */
/*
 * Allocate the container.
 */
  cf = (CompleteFile *) malloc(sizeof(CompleteFile));
  if(!cf) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to _del_CompleteFile().
 */
  cf->err = NULL;
  cf->dr = NULL;
  cf->home = NULL;
  cf->path = NULL;
  cf->buff = NULL;
  cf->usrnam[0] = '\0';
  cf->envnam[0] = '\0';
/*
 * Allocate a place to record error messages.
 */
  cf->err = _new_ErrMsg();
  if(!cf->err)
    return _del_CompleteFile(cf);
/*
 * Create the object that is used for reading directories.
 */
  cf->dr = _new_DirReader();
  if(!cf->dr)
    return _del_CompleteFile(cf);
/*
 * Create the object that is used to lookup home directories.
 */
  cf->home = _new_HomeDir();
  if(!cf->home)
    return _del_CompleteFile(cf);
/*
 * Create the buffer in which the completed pathname is accumulated.
 */
  cf->path = _new_PathName();
  if(!cf->path)
    return _del_CompleteFile(cf);
/*
 * Create a pathname work buffer.
 */
  cf->buff = _new_PathName();
  if(!cf->buff)
    return _del_CompleteFile(cf);
  return cf;
}

/*.......................................................................
 * Delete a file-completion object.
 *
 * Input:
 *  cf     CompleteFile *  The object to be deleted.
 * Output:
 *  return CompleteFile *  The deleted object (always NULL).
 */
CompleteFile *_del_CompleteFile(CompleteFile *cf)
{
  if(cf) {
    cf->err = _del_ErrMsg(cf->err);
    cf->dr = _del_DirReader(cf->dr);
    cf->home = _del_HomeDir(cf->home);
    cf->path = _del_PathName(cf->path);
    cf->buff = _del_PathName(cf->buff);
    free(cf);
  };
  return NULL;
}

/*.......................................................................
 * Look up the possible completions of the incomplete filename that
 * lies between specified indexes of a given command-line string.
 *
 * Input:
 *  cpl   WordCompletion *  The object in which to record the completions.
 *  cf      CompleteFile *  The filename-completion resource object.
 *  line      const char *  The string containing the incomplete filename.
 *  word_start       int    The index of the first character in line[]
 *                          of the incomplete filename.
 *  word_end         int    The index of the character in line[] that
 *                          follows the last character of the incomplete
 *                          filename.
 *  escaped          int    If true, backslashes in line[] are
 *                          interpreted as escaping the characters
 *                          that follow them, and any spaces, tabs,
 *                          backslashes, or wildcard characters in the
 *                          returned suffixes will be similarly escaped.
 *                          If false, backslashes will be interpreted as
 *                          literal parts of the file name, and no
 *                          backslashes will be added to the returned
 *                          suffixes.
 *  check_fn  CplCheckFn *  If not zero, this argument specifies a
 *                          function to call to ask whether a given
 *                          file should be included in the list
 *                          of completions.
 *  check_data      void *  Anonymous data to be passed to check_fn().
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error. A description of the error can be
 *                                     acquired by calling _cf_last_error(cf).
 */
int _cf_complete_file(WordCompletion *cpl, CompleteFile *cf,
		     const char *line, int word_start, int word_end,
		     int escaped, CplCheckFn *check_fn, void *check_data)
{
  const char *lptr; /* A pointer into line[] */
  int nleft;        /* The number of characters still to be processed */
                    /*  in line[]. */
/*
 * Check the arguments.
 */
  if(!cpl || !cf || !line || word_end < word_start) {
    if(cf) {
      _err_record_msg(cf->err, "_cf_complete_file: Invalid arguments",
		      END_ERR_MSG);
    };
    return 1;
  };
/*
 * Clear the buffer in which the filename will be constructed.
 */
  _pn_clear_path(cf->path);
/*
 * How many characters are to be processed?
 */
  nleft = word_end - word_start;
/*
 * Get a pointer to the start of the incomplete filename.
 */
  lptr = line + word_start;
/*
 * If the first character is a tilde, then perform home-directory
 * interpolation.
 */
  if(nleft > 0 && *lptr == '~') {
    int slen;
    if(!cf_read_name(cf, "User", ++lptr, --nleft, cf->usrnam, USR_LEN))
      return 1;
/*
 * Advance over the username in the input line.
 */
    slen = strlen(cf->usrnam);
    lptr += slen;
    nleft -= slen;
/*
 * If we haven't hit the end of the input string then we have a complete
 * username to translate to the corresponding home directory.
 */
    if(nleft > 0) {
      if(cf_expand_home_dir(cf, cf->usrnam))
	return 1;
/*
 * ~user and ~ are usually followed by a directory separator to
 * separate them from the file contained in the home directory.
 * If the home directory is the root directory, then we don't want
 * to follow the home directory by a directory separator, so we should
 * skip over it so that it doesn't get copied into the filename.
 */
      if(strcmp(cf->path->name, FS_ROOT_DIR) == 0 &&
	 strncmp(lptr, FS_DIR_SEP, FS_DIR_SEP_LEN) == 0) {
	lptr += FS_DIR_SEP_LEN;
	nleft -= FS_DIR_SEP_LEN;
      };
/*
 * If we have reached the end of the input string, then the username
 * may be incomplete, and we should attempt to complete it.
 */
    } else {
/*
 * Look up the possible completions of the username.
 */
      return cf_complete_username(cf, cpl, cf->usrnam, line, word_start+1,
				  word_end, escaped);
    };
  };
/*
 * Copy the rest of the path, stopping to expand $envvar expressions
 * where encountered.
 */
  while(nleft > 0) {
    int seglen;   /* The length of the next segment to be copied */
/*
 * Find the length of the next segment to be copied, stopping if an
 * unescaped '$' is seen, or the end of the path is reached.
 */
    for(seglen=0; seglen < nleft; seglen++) {
      int c = lptr[seglen];
      if(escaped && c == '\\')
	seglen++;
      else if(c == '$')
	break;
/*
 * We will be completing the last component of the file name,
 * so whenever a directory separator is seen, assume that it
 * might be the start of the last component, and mark the character
 * that follows it as the start of the name that is to be completed.
 */
      if(nleft >= FS_DIR_SEP_LEN &&
	 strncmp(lptr + seglen, FS_DIR_SEP, FS_DIR_SEP_LEN)==0) {
	word_start = (lptr + seglen) - line + FS_DIR_SEP_LEN;
      };
    };
/*
 * We have reached either the end of the filename or the start of
 * $environment_variable expression. Record the newly checked
 * segment of the filename in the output filename, removing
 * backslash-escapes where needed.
 */
    if(_pn_append_to_path(cf->path, lptr, seglen, escaped) == NULL) {
      _err_record_msg(cf->err, "Insufficient memory to complete filename",
		      END_ERR_MSG);
      return 1;
    };
    lptr += seglen;
    nleft -= seglen;
/*
 * If the above loop finished before we hit the end of the filename,
 * then this was because an unescaped $ was seen. In this case, interpolate
 * the value of the environment variable that follows it into the output
 * filename.
 */
    if(nleft > 0) {
      char *value;    /* The value of the environment variable */
      int vlen;       /* The length of the value string */
      int nlen;       /* The length of the environment variable name */
/*
 * Read the name of the environment variable.
 */
      if(!cf_read_name(cf, "Environment", ++lptr, --nleft, cf->envnam, ENV_LEN))
	return 1;
/*
 * Advance over the environment variable name in the input line.
 */
      nlen = strlen(cf->envnam);
      lptr += nlen;
      nleft -= nlen;
/*
 * Get the value of the environment variable.
 */
      value = getenv(cf->envnam);
      if(!value) {
	_err_record_msg(cf->err, "Unknown environment variable: ", cf->envnam,
			END_ERR_MSG);
	return 1;
      };
      vlen = strlen(value);
/*
 * If we are at the start of the filename and the first character of the
 * environment variable value is a '~', attempt home-directory
 * interpolation.
 */
      if(cf->path->name[0] == '\0' && value[0] == '~') {
	if(!cf_read_name(cf, "User", value+1, vlen-1, cf->usrnam, USR_LEN) ||
	   cf_expand_home_dir(cf, cf->usrnam))
	  return 1;
/*
 * If the home directory is the root directory, and the ~usrname expression
 * was followed by a directory separator, prevent the directory separator
 * from being appended to the root directory by skipping it in the
 * input line.
 */
	if(strcmp(cf->path->name, FS_ROOT_DIR) == 0 &&
	   strncmp(lptr, FS_DIR_SEP, FS_DIR_SEP_LEN) == 0) {
	  lptr += FS_DIR_SEP_LEN;
	  nleft -= FS_DIR_SEP_LEN;
	};
      } else {
/*
 * Append the value of the environment variable to the output path.
 */
	if(_pn_append_to_path(cf->path, value, strlen(value), escaped)==NULL) {
	  _err_record_msg(cf->err, "Insufficient memory to complete filename",
			  END_ERR_MSG);
	  return 1;
	};
/*
 * Prevent extra directory separators from being added.
 */
	if(nleft >= FS_DIR_SEP_LEN &&
	   strcmp(cf->path->name, FS_ROOT_DIR) == 0 &&
	   strncmp(lptr, FS_DIR_SEP, FS_DIR_SEP_LEN) == 0) {
	  lptr += FS_DIR_SEP_LEN;
	  nleft -= FS_DIR_SEP_LEN;
	} else if(vlen > FS_DIR_SEP_LEN &&
		  strcmp(value + vlen - FS_DIR_SEP_LEN, FS_DIR_SEP)==0) {
	  cf->path->name[vlen-FS_DIR_SEP_LEN] = '\0';
	};
      };
/*
 * If adding the environment variable didn't form a valid directory,
 * we can't complete the line, since there is no way to separate append
 * a partial filename to an environment variable reference without
 * that appended part of the name being seen later as part of the
 * environment variable name. Thus if the currently constructed path
 * isn't a directory, quite now with no completions having been
 * registered.
 */
      if(!_pu_path_is_dir(cf->path->name))
	return 0;
/*
 * For the reasons given above, if we have reached the end of the filename
 * with the expansion of an environment variable, the only allowed
 * completion involves the addition of a directory separator.
 */
      if(nleft == 0) {
	if(cpl_add_completion(cpl, line, lptr-line, word_end, FS_DIR_SEP,
			      "", "")) {
	  _err_record_msg(cf->err, cpl_last_error(cpl), END_ERR_MSG);
	  return 1;
	};
	return 0;
      };
    };
  };
/*
 * Complete the filename if possible.
 */
  return cf_complete_entry(cf, cpl, line, word_start, word_end, escaped,
			   check_fn, check_data);
}

/*.......................................................................
 * Return a description of the last path-completion error that occurred.
 *
 * Input:
 *  cf    CompleteFile *  The path-completion resource object.
 * Output:
 *  return  const char *  The description of the last error.
 */
const char *_cf_last_error(CompleteFile *cf)
{
  return cf ? _err_get_msg(cf->err) : "NULL CompleteFile argument";
}

/*.......................................................................
 * Lookup the home directory of the specified user, or the current user
 * if no name is specified, appending it to output pathname.
 *
 * Input:
 *  cf  CompleteFile *  The pathname completion resource object.
 *  user  const char *  The username to lookup, or "" to lookup the
 *                      current user.
 * Output:
 *  return        int    0 - OK.
 *                       1 - Error.
 */
static int cf_expand_home_dir(CompleteFile *cf, const char *user)
{
/*
 * Attempt to lookup the home directory.
 */
  const char *home_dir = _hd_lookup_home_dir(cf->home, user);
/*
 * Failed?
 */
  if(!home_dir) {
    _err_record_msg(cf->err, _hd_last_home_dir_error(cf->home), END_ERR_MSG);
    return 1;
  };
/*
 * Append the home directory to the pathname string.
 */
  if(_pn_append_to_path(cf->path, home_dir, -1, 0) == NULL) {
    _err_record_msg(cf->err, "Insufficient memory for home directory expansion",
		    END_ERR_MSG);
    return 1;
  };
  return 0;
}

/*.......................................................................
 * Lookup and report all completions of a given username prefix.
 *
 * Input:
 *  cf     CompleteFile *  The filename-completion resource object.
 *  cpl  WordCompletion *  The object in which to record the completions.
 *  prefix   const char *  The prefix of the usernames to lookup.
 *  line     const char *  The command-line in which the username appears.
 *  word_start      int    The index within line[] of the start of the
 *                         username that is being completed.
 *  word_end        int    The index within line[] of the character which
 *                         follows the incomplete username.
 *  escaped         int    True if the completions need to have special
 *                         characters escaped.
 * Output:
 *  return          int    0 - OK.
 *                         1 - Error.
 */
static int cf_complete_username(CompleteFile *cf, WordCompletion *cpl,
				const char *prefix, const char *line,
				int word_start, int word_end, int escaped)
{
/*
 * Set up a container of anonymous arguments to be sent to the
 * username-lookup iterator.
 */
  CfHomeArgs args;
  args.cf = cf;
  args.cpl = cpl;
  args.prefix_len = strlen(prefix);
  args.line = line;
  args.word_start = word_start;
  args.word_end = word_end;
  args.escaped = escaped;
/*
 * Iterate through the list of users, recording those which start
 * with the specified prefix.
 */
  if(_hd_scan_user_home_dirs(cf->home, prefix, &args, cf_homedir_callback)) {
    _err_record_msg(cf->err, _hd_last_home_dir_error(cf->home), END_ERR_MSG);
    return 1;
  };
  return 0;
}

/*.......................................................................
 * The user/home-directory scanner callback function (see homedir.h)
 * used by cf_complete_username().
 */
static HOME_DIR_FN(cf_homedir_callback)
{
/*
 * Get the file-completion resources from the anonymous data argument.
 */
  CfHomeArgs *args = (CfHomeArgs *) data;
  WordCompletion *cpl = args->cpl;
  CompleteFile *cf = args->cf;
/*
 * Copy the username into the pathname work buffer, adding backslash
 * escapes where needed.
 */
  if(cf_prepare_suffix(cf, usrnam+args->prefix_len, args->escaped)) {
    strncpy(errmsg, _err_get_msg(cf->err), maxerr);
    errmsg[maxerr] = '\0';
    return 1;
  };
/*
 * Report the completion suffix that was copied above.
 */
  if(cpl_add_completion(cpl, args->line, args->word_start, args->word_end,
			cf->buff->name, FS_DIR_SEP, FS_DIR_SEP)) {
    strncpy(errmsg, cpl_last_error(cpl), maxerr);
    errmsg[maxerr] = '\0';
    return 1;
  };
  return 0;
}

/*.......................................................................
 * Report possible completions of the filename in cf->path->name[].
 *
 * Input:
 *  cf      CompleteFile *  The file-completion resource object.
 *  cpl   WordCompletion *  The object in which to record the completions.
 *  line      const char *  The input line, as received by the callback
 *                          function.
 *  word_start       int    The index within line[] of the start of the
 *                          last component of the filename that is being
 *                          completed.
 *  word_end         int    The index within line[] of the character which
 *                          follows the incomplete filename.
 *  escaped          int    If true, escape special characters in the
 *                          completion suffixes.
 *  check_fn  CplCheckFn *  If not zero, this argument specifies a
 *                          function to call to ask whether a given
 *                          file should be included in the list
 *                          of completions.
 *  check_data      void *  Anonymous data to be passed to check_fn().
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error.
 */
static int cf_complete_entry(CompleteFile *cf, WordCompletion *cpl,
			     const char *line, int word_start, int word_end,
			     int escaped, CplCheckFn *check_fn,
			     void *check_data)
{
  const char *dirpath;   /* The name of the parent directory */
  int start;             /* The index of the start of the last filename */
                         /*  component in the transcribed filename. */
  const char *prefix;    /* The filename prefix to be completed */
  int prefix_len;        /* The length of the filename prefix */
  const char *file_name; /* The lastest filename being compared */
  int waserr = 0;        /* True after errors */
  int terminated=0;      /* True if the directory part had to be terminated */
/*
 * Get the pathname string and its current length.
 */
  char *pathname = cf->path->name;
  int pathlen = strlen(pathname);
/*
 * Locate the start of the final component of the pathname.
 */
  for(start=pathlen - 1; start >= 0 &&
      strncmp(pathname + start, FS_DIR_SEP, FS_DIR_SEP_LEN) != 0; start--)
    ;
/*
 * Is the parent directory the root directory?
 */
  if(start==0 ||
     (start < 0 && strncmp(pathname, FS_ROOT_DIR, FS_ROOT_DIR_LEN) == 0)) {
    dirpath = FS_ROOT_DIR;
    start += FS_ROOT_DIR_LEN;
/*
 * If we found a directory separator then the part which precedes the
 * last component is the name of the directory to be opened.
 */
  } else if(start > 0) {
/*
 * The _dr_open_dir() function requires the directory name to be '\0'
 * terminated, so temporarily do this by overwriting the first character
 * of the directory separator.
 */
    pathname[start] = '\0';
    dirpath = pathname;
    terminated = 1;
/*
 * We reached the start of the pathname before finding a directory
 * separator, so arrange to open the current working directory.
 */
  } else {
    start = 0;
    dirpath = FS_PWD;
  };
/*
 * Attempt to open the directory.
 */
  if(_dr_open_dir(cf->dr, dirpath, NULL)) {
    _err_record_msg(cf->err, "Can't open directory: ", dirpath, END_ERR_MSG);
    return 1;
  };
/*
 * If removed above, restore the directory separator and skip over it
 * to the start of the filename.
 */
  if(terminated) {
    memcpy(pathname + start, FS_DIR_SEP, FS_DIR_SEP_LEN);
    start += FS_DIR_SEP_LEN;
  };
/*
 * Get the filename prefix and its length.
 */
  prefix = pathname + start;
  prefix_len = strlen(prefix);
/*
 * Traverse the directory, looking for files who's prefixes match the
 * last component of the pathname.
 */
  while((file_name = _dr_next_file(cf->dr)) != NULL && !waserr) {
    int name_len = strlen(file_name);
/*
 * Is the latest filename a possible completion of the filename prefix?
 */
    if(name_len >= prefix_len && strncmp(prefix, file_name, prefix_len)==0) {
/*
 * When listing all files in a directory, don't list files that start
 * with '.'. This is how hidden files are denoted in UNIX.
 */
      if(prefix_len > 0 || file_name[0] != '.') {
/*
 * Copy the completion suffix into the work pathname cf->buff->name,
 * adding backslash escapes if needed.
 */
	if(cf_prepare_suffix(cf, file_name + prefix_len, escaped)) {
	  waserr = 1;
	} else {
/*
 * We want directories to be displayed with directory suffixes,
 * and other fully completed filenames to be followed by spaces.
 * To check the type of the file, append the current suffix
 * to the path being completed, check the filetype, then restore
 * the path to its original form.
 */
	  const char *cont_suffix = "";  /* The suffix to add if fully */
                                         /*  completed. */
	  const char *type_suffix = "";  /* The suffix to add when listing */
	  if(_pn_append_to_path(cf->path, file_name + prefix_len,
				-1, escaped) == NULL) {
	    _err_record_msg(cf->err,
			    "Insufficient memory to complete filename.",
			    END_ERR_MSG);
	    return 1;
	  };
/*
 * Specify suffixes according to the file type.
 */
	  if(_pu_path_is_dir(cf->path->name)) {
	    cont_suffix = FS_DIR_SEP;
	    type_suffix = FS_DIR_SEP;
	  } else if(!check_fn || check_fn(check_data, cf->path->name)) {
	    cont_suffix = " ";
	  } else {
	    cf->path->name[pathlen] = '\0';
	    continue;
	  };
/*
 * Remove the temporarily added suffix.
 */
	  cf->path->name[pathlen] = '\0';
/*
 * Record the latest completion.
 */
	  if(cpl_add_completion(cpl, line, word_start, word_end, cf->buff->name,
				type_suffix, cont_suffix))
	    waserr = 1;
	};
      };
    };
  };
/*
 * Close the directory.
 */
  _dr_close_dir(cf->dr);
  return waserr;
}

/*.......................................................................
 * Read a username or environment variable name, stopping when a directory
 * separator is seen, when the end of the string is reached, or the
 * output buffer overflows.
 *
 * Input:
 *  cf   CompleteFile *  The file-completion resource object.
 *  type         char *  The capitalized name of the type of name being read.
 *  string       char *  The string who's prefix contains the name.
 *  slen          int    The number of characters in string[].
 *  nambuf       char *  The output name buffer.
 *  nammax        int    The longest string that will fit in nambuf[], excluding
 *                       the '\0' terminator.
 * Output:
 *  return       char *  A pointer to nambuf on success. On error NULL is
 *                       returned and a description of the error is recorded
 *                       in cf->err.
 */
static char *cf_read_name(CompleteFile *cf, const char *type,
			  const char *string, int slen,
			  char *nambuf, int nammax)
{
  int namlen;         /* The number of characters in nambuf[] */
  const char *sptr;   /* A pointer into string[] */
/*
 * Work out the max number of characters that should be copied.
 */
  int nmax = nammax < slen ? nammax : slen;
/*
 * Get the environment variable name that follows the dollar.
 */
  for(sptr=string,namlen=0;
      namlen < nmax && (slen-namlen < FS_DIR_SEP_LEN ||
			strncmp(sptr, FS_DIR_SEP, FS_DIR_SEP_LEN) != 0);
      namlen++) {
    nambuf[namlen] = *sptr++;
  };
/*
 * Did the name overflow the buffer?
 */
  if(namlen >= nammax) {
    _err_record_msg(cf->err, type, " name too long", END_ERR_MSG);
    return NULL;
  };
/*
 * Terminate the string.
 */
  nambuf[namlen] = '\0';
  return nambuf;
}

/*.......................................................................
 * Using the work buffer cf->buff, make a suitably escaped copy of a
 * given completion suffix, ready to be passed to cpl_add_completion().
 *
 * Input:
 *  cf   CompleteFile *  The file-completion resource object.
 *  suffix       char *  The suffix to be copied.
 *  add_escapes   int    If true, escape special characters.
 * Output:
 *  return        int    0 - OK.
 *                       1 - Error.
 */
static int cf_prepare_suffix(CompleteFile *cf, const char *suffix,
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
  _pn_clear_path(cf->buff);
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
  if(_pn_resize_path(cf->buff, suffix_len + nbsl) == NULL) {
    _err_record_msg(cf->err, "Insufficient memory to complete filename",
		    END_ERR_MSG);
    return 1;
  };
/*
 * If the suffix doesn't need any escapes, copy it directly into the
 * work buffer.
 */
  if(nbsl==0) {
    strlcpy(cf->buff->name, suffix, cf->buff->dim);
  } else {
/*
 * Make a copy with special characters escaped?
 */
    if(nbsl > 0) {
      const char *src = suffix;
      char *dst = cf->buff->name;
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

#endif  /* ifndef WITHOUT_FILE_SYSTEM */
