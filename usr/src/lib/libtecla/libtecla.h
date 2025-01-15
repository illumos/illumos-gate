#ifndef libtecla_h
#define libtecla_h

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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>   /* FILE * */
#include <stdlib.h>  /* size_t */
#include <time.h>    /* time_t */
#include <signal.h>  /* struct sigaction */

/*
 * The following are the three components of the libtecla version number.
 * Note that it is better to use the libtecla_version() function than these
 * macros since the macros only tell you which version of the library your
 * code was compiled against, whereas the libtecla_version() function
 * tells you which version of the shared tecla library your program is
 * actually linked to.
 */
#define TECLA_MAJOR_VER 1
#define TECLA_MINOR_VER 6
#define TECLA_MICRO_VER 0

/*.......................................................................
 * Query the version number of the tecla library.
 *
 * Input:
 *  major    int *   The major version number of the library
 *                   will be assigned to *major. This number is
 *                   only incremented when a change to the library is
 *                   made that breaks binary (shared library) and/or
 *                   compilation backwards compatibility.
 *  minor    int *   The minor version number of the library
 *                   will be assigned to *minor. This number is
 *                   incremented whenever new functions are added to
 *                   the public API.
 *  micro    int *   The micro version number of the library will be
 *                   assigned to *micro. This number is incremented
 *                   whenever internal changes are made that don't
 *                   change the public API, such as bug fixes and
 *                   performance enhancements.
 */
void libtecla_version(int *major, int *minor, int *micro);

/*-----------------------------------------------------------------------
 * The getline module provides interactive command-line input, recall and
 * editing by users at terminals. See the gl_get_line(3TECLA) man page for
 * more details.
 *-----------------------------------------------------------------------*/

/*
 * Provide an opaque handle for the resource object that is defined in
 * getline.h.
 */
typedef struct GetLine GetLine;

/*
 * The following two functions are used to create and delete the
 * resource objects that are used by the gl_get_line() function.
 */
GetLine *new_GetLine(size_t linelen, size_t histlen);
GetLine *del_GetLine(GetLine *gl);

/*
 * Read a line into an internal buffer of gl.
 */
char *gl_get_line(GetLine *gl, const char *prompt, const char *start_line,
		  int start_pos);

/*.......................................................................
 * Prompt the user for a single-character reply.
 *
 * Input:
 *  gl       GetLine *  A resource object returned by new_GetLine().
 *  prompt      char *  The prompt to prefix the query with, or NULL
 *                      to reuse the previous prompt.
 *  defchar     char    The character to substitute if the
 *                      user simply hits return, or '\n' if you don't
 *                      need to substitute anything.
 * Output:
 *  return       int    The character that was read, or EOF if the read
 *                      had to be aborted (in which case you can call
 *                      gl_return_status() to find out why).
 */
int gl_query_char(GetLine *gl, const char *prompt, char defchar);

/*.......................................................................
 * Read a single uninterpretted character from the user, without
 * displaying anything.
 *
 * Input:
 *  gl     GetLine *  A resource object previously returned by
 *                    new_GetLine().
 * Output:
 *  return     int    The character that was read, or EOF if the read
 *                    had to be aborted (in which case you can call
 *                    gl_return_status() to find out why).
 */
int gl_read_char(GetLine *gl);

/*
 * Configure the application specific and/or user-specific behavior of
 * gl_get_line().
 */
int gl_configure_getline(GetLine *gl, const char *app_string,
			 const char *app_file, const char *user_file);

/*
 * The following enumerators specify the origin of a key binding, and
 * are listed in order of decreasing priority, such that user-specified
 * key-bindings take precedence over application default bindings.
 */
typedef enum {
  GL_USER_KEY,  /* A key-binding specified by the user */
  GL_APP_KEY    /* A key-binding specified by the application */
} GlKeyOrigin;

/*
 * Bind a key sequence to a given action. If action==NULL, unbind the
 * key-sequence.
 */
int gl_bind_keyseq(GetLine *gl, GlKeyOrigin origin, const char *keyseq,
		   const char *action);

/*-----------------------------------------------------------------------
 * The file-expansion module provides facilities for expanding ~user/ and
 * $envvar expressions, and for expanding glob-style wildcards.
 * See the ef_expand_file(3) man page for more details.
 *-----------------------------------------------------------------------*/

/*
 * ExpandFile objects contain the resources needed to expand pathnames.
 */
typedef struct ExpandFile ExpandFile;

/*
 * The following functions are used to create and delete the resource
 * objects that are used by the ef_expand_file() function.
 */
ExpandFile *new_ExpandFile(void);
ExpandFile *del_ExpandFile(ExpandFile *ef);

/*
 * A container of the following type is returned by ef_expand_file().
 */
typedef struct {
  int exists;       /* True if the files in files[] currently exist. */
                    /*  This only time that this may not be true is if */
                    /*  the input filename didn't contain any wildcards */
                    /*  and thus wasn't matched against existing files. */
                    /*  In this case the single entry in 'nfile' may not */
                    /*  refer to an existing file. */
  int nfile;        /* The number of files in files[] */
  char **files;     /* An array of 'nfile' filenames. */
} FileExpansion;

/*
 * The ef_expand_file() function expands a specified pathname, converting
 * ~user/ and ~/ patterns at the start of the pathname to the
 * corresponding home directories, replacing $envvar with the value of
 * the corresponding environment variable, and then, if there are any
 * wildcards, matching these against existing filenames.
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
 *  fe         ExpandFile *  The pathname expansion resource object.
 *  path       const char *  The path name to be expanded.
 *  pathlen           int    The length of the suffix of path[] that
 *                           constitutes the filename to be expanded,
 *                           or -1 to specify that the whole of the
 *                           path string should be used.
 * Output:
 *  return  FileExpansion *  A pointer to a results container within the
 *                           given ExpandFile object. This contains an
 *                           array of the pathnames that resulted from
 *                           expanding ~ and $ expressions and from
 *                           matching any wildcards, sorted into lexical
 *                           order.
 *
 *                           This container and its contents will be
 *                           recycled on subsequent calls, so if you need
 *                           to keep the results of two successive runs,
 *                           you will either have to allocate a private
 *                           copy of the array, or use two ExpandFile
 *                           objects.
 *
 *                           On error, NULL is returned. A description
 *                           of the error can be acquired by calling the
 *                           ef_last_error() function.
 */
FileExpansion *ef_expand_file(ExpandFile *ef, const char *path, int pathlen);

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
int ef_list_expansions(FileExpansion *result, FILE *fp, int term_width);

/*
 * The ef_last_error() function returns a description of the last error
 * that occurred in a call ef_expand_file(). Note that this message is
 * contained in an array which is allocated as part of *ef, and its
 * contents thus potentially change on every call to ef_expand_file().
 */
const char *ef_last_error(ExpandFile *ef);

/*-----------------------------------------------------------------------
 * The WordCompletion module is used for completing incomplete words, such
 * as filenames. Programs can use functions within this module to register
 * their own customized completion functions.
 *-----------------------------------------------------------------------*/

/*
 * Ambiguous completion matches are recorded in objects of the
 * following type.
 */
typedef struct WordCompletion WordCompletion;

/*
 * Create a new completion object.
 */
WordCompletion *new_WordCompletion(void);

/*
 * Delete a redundant completion object.
 */
WordCompletion *del_WordCompletion(WordCompletion *cpl);

/*.......................................................................
 * Callback functions declared and prototyped using the following macro
 * are called upon to return an array of possible completion suffixes
 * for the token that precedes a specified location in the given
 * input line. It is up to this function to figure out where the token
 * starts, and to call cpl_add_completion() to register each possible
 * completion before returning.
 *
 * Input:
 *  cpl  WordCompletion *  An opaque pointer to the object that will
 *                         contain the matches. This should be filled
 *                         via zero or more calls to cpl_add_completion().
 *  data           void *  The anonymous 'data' argument that was
 *                         passed to cpl_complete_word() or
 *                         gl_customize_completion()).
 *  line     const char *  The current input line.
 *  word_end        int    The index of the character in line[] which
 *                         follows the end of the token that is being
 *                         completed.
 * Output
 *  return          int    0 - OK.
 *                         1 - Error.
 */
#define CPL_MATCH_FN(fn) int (fn)(WordCompletion *cpl, void *data, \
                                  const char *line, int word_end)
typedef CPL_MATCH_FN(CplMatchFn);

/*.......................................................................
 * Optional callback functions declared and prototyped using the
 * following macro are called upon to return non-zero if a given
 * file, specified by its pathname, is to be included in a list of
 * completions.
 *
 * Input:
 *  data            void *  The application specified pointer which
 *                          was specified when this callback function
 *                          was registered. This can be used to have
 *                          anything you like passed to your callback.
 *  pathname  const char *  The pathname of the file to be checked to
 *                          see if it should be included in the list
 *                          of completions.
 * Output
 *  return           int    0 - Ignore this file.
 *                          1 - Do include this file in the list
 *                              of completions.
 */
#define CPL_CHECK_FN(fn) int (fn)(void *data, const char *pathname)
typedef CPL_CHECK_FN(CplCheckFn);

/*
 * You can use the following CplCheckFn callback function to only
 * have executables included in a list of completions.
 */
CPL_CHECK_FN(cpl_check_exe);

/*
 * cpl_file_completions() is the builtin filename completion callback
 * function. This can also be called by your own custom CPL_MATCH_FN()
 * callback functions. To do this pass on all of the arguments of your
 * custom callback function to cpl_file_completions(), with the exception
 * of the (void *data) argument. The data argument should either be passed
 * NULL to request the default behaviour of the file-completion function,
 * or be passed a pointer to a CplFileConf structure (see below). In the
 * latter case the contents of the structure modify the behavior of the
 * file-completer.
 */
CPL_MATCH_FN(cpl_file_completions);

/*
 * Objects of the following type can be used to change the default
 * behavior of the cpl_file_completions() callback function.
 */
typedef struct CplFileConf CplFileConf;

/*
 * If you want to change the behavior of the cpl_file_completions()
 * callback function, call the following function to allocate a
 * configuration object, then call one or more of the subsequent
 * functions to change any of the default configuration parameters
 * that you don't want. This function returns NULL when there is
 * insufficient memory.
 */
CplFileConf *new_CplFileConf(void);

/*
 * If backslashes in the prefix being passed to cpl_file_completions()
 * should be treated as literal characters, call the following function
 * with literal=1. Otherwise the default is to treat them as escape
 * characters which remove the special meanings of spaces etc..
 */
void cfc_literal_escapes(CplFileConf *cfc, int literal);

/*
 * Before calling cpl_file_completions(), call this function if you
 * know the index at which the filename prefix starts in the input line.
 * Otherwise by default, or if you specify start_index to be -1, the
 * filename is taken to start after the first unescaped space preceding
 * the cursor, or the start of the line, which ever comes first.
 */
void cfc_file_start(CplFileConf *cfc, int start_index);

/*
 * If you only want certain types of files to be included in the
 * list of completions, use the following function to specify a
 * callback function which will be called to ask whether a given file
 * should be included. The chk_data argument is will be passed to the
 * callback function whenever it is called and can be anything you want.
 */
void cfc_set_check_fn(CplFileConf *cfc, CplCheckFn *chk_fn, void *chk_data);

/*
 * The following function deletes a CplFileConf objects previously
 * returned by new_CplFileConf(). It always returns NULL.
 */
CplFileConf *del_CplFileConf(CplFileConf *cfc);

/*
 * The following configuration structure is deprecated. Do not change
 * its contents, since this will break any programs that still use it,
 * and don't use it in new programs. Instead use opaque CplFileConf
 * objects as described above. cpl_file_completions() figures out
 * what type of structure you pass it, by virtue of a magic int code
 * placed at the start of CplFileConf object by new_CplFileConf().
 */
typedef struct {
  int escaped;     /* Opposite to the argument of cfc_literal_escapes() */
  int file_start;  /* Equivalent to the argument of cfc_file_start() */
} CplFileArgs;
/*
 * This initializes the deprecated CplFileArgs structures.
 */
void cpl_init_FileArgs(CplFileArgs *cfa);

/*.......................................................................
 * When an error occurs while performing a completion, custom completion
 * callback functions should register a terse description of the error
 * by calling cpl_record_error(). This message will then be returned on
 * the next call to cpl_last_error() and used by getline to display an
 * error message to the user.
 *
 * Input:
 *  cpl  WordCompletion *  The string-completion resource object that was
 *                         originally passed to the callback.
 *  errmsg   const char *  The description of the error.
 */
void cpl_record_error(WordCompletion *cpl, const char *errmsg);

/*.......................................................................
 * This function can be used to replace the builtin filename-completion
 * function with one of the user's choice. The user's completion function
 * has the option of calling the builtin filename-completion function
 * if it believes that the token that it has been presented with is a
 * filename (see cpl_file_completions() above).
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  data             void *  This is passed to match_fn() whenever it is
 *                           called. It could, for example, point to a
 *                           symbol table that match_fn() would look up
 *                           matches in.
 *  match_fn   CplMatchFn *  The function that will identify the prefix
 *                           to be completed from the input line, and
 *                           report matching symbols.
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int gl_customize_completion(GetLine *gl, void *data, CplMatchFn *match_fn);

/*.......................................................................
 * This function allows you to install alternate completion action
 * functions or completion listing functions, or to change the
 * completion function of an existing action of the same type. This
 * should preferably be called before the first call to gl_get_line()
 * so that the name of the action becomes defined before the user's
 * configuration file is read.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  data             void *  This is passed to match_fn() whenever it is
 *                           called. It could, for example, point to a
 *                           symbol table that match_fn() would look up
 *                           matches in.
 *  match_fn   CplMatchFn *  The function that will identify the prefix
 *                           to be completed from the input line, and
 *                           report matching symbols.
 *  list_only         int    If non-zero, install an action that only lists
 *                           possible completions, rather than attempting
 *                           to perform the completion.
 *  name       const char *  The name with which users can refer to the
 *                           binding in tecla configuration files.
 *  keyseq     const char *  The key sequence with which to invoke
 *                           the binding. This should be specified in the
 *                           same manner as key-sequences in tecla
 *                           configuration files (eg. "M-^I").
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int gl_completion_action(GetLine *gl, void *data, CplMatchFn *match_fn,
			 int list_only, const char *name, const char *keyseq);

/*.......................................................................
 * Change the terminal (or stream) that getline interacts with.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  input_fp         FILE *  The stdio stream to read from.
 *  output_fp        FILE *  The stdio stream to write to.
 *  term       const char *  The terminal type. This can be NULL if
 *                           either or both of input_fp and output_fp don't
 *                           refer to a terminal. Otherwise it should refer
 *                           to an entry in the terminal information database.
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int gl_change_terminal(GetLine *gl, FILE *input_fp, FILE *output_fp,
		       const char *term);

/*.......................................................................
 * The following functions can be used to save and restore the contents
 * of the history buffer.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  filename   const char *  The name of the new file to write to.
 *  comment    const char *  Extra information such as timestamps will
 *                           be recorded on a line started with this
 *                           string, the idea being that the file can
 *                           double as a command file. Specify "" if
 *                           you don't care. Be sure to specify the
 *                           same string to both functions.
 *  max_lines         int    The maximum number of lines to save, or -1
 *                           to save all of the lines in the history
 *                           list.
 * Output:
 *  return            int     0 - OK.
 *                            1 - Error.
 */
int gl_save_history(GetLine *gl, const char *filename, const char *comment,
		    int max_lines);
int gl_load_history(GetLine *gl, const char *filename, const char *comment);

/*
 * Enumerate file-descriptor events that can be waited for.
 */
typedef enum {
  GLFD_READ,   /* Watch for data waiting to be read from a file descriptor */
  GLFD_WRITE,  /* Watch for ability to write to a file descriptor */
  GLFD_URGENT  /* Watch for urgent out-of-band data on the file descriptor */
} GlFdEvent;

/*
 * The following enumeration is used for the return status of file
 * descriptor event callbacks.
 */
typedef enum {
  GLFD_ABORT,    /* Cause gl_get_line() to abort with an error */
  GLFD_REFRESH,  /* Redraw the input line and continue waiting for input */
  GLFD_CONTINUE  /* Continue to wait for input, without redrawing the line */
} GlFdStatus;

/*.......................................................................
 * On systems that have the select() system call, while gl_get_line()
 * is waiting for terminal input, it can also be asked to listen for
 * activity on arbitrary file descriptors.  Callback functions of the
 * following type can be registered to be called when activity is
 * seen. If your callback needs to write to the terminal or use
 * signals, please see the gl_get_line(3) man page.
 *
 * Input:
 *  gl       GetLine *  The gl_get_line() resource object. You can use
 *                      this safely to call gl_watch_fd() or
 *                      gl_inactivity_timeout(). The effect of calling other
 *                      functions that take a gl argument is undefined,
 *                      and must be avoided.
 *  data        void *  A pointer to arbitrary callback data, as originally
 *                      registered with gl_watch_fd().
 *  fd           int    The file descriptor that has activity.
 *  event  GlFdEvent    The activity seen on the file descriptor. The
 *                      inclusion of this argument allows the same
 *                      callback to be registered for multiple events.
 * Output:
 *  return GlFdStatus   GLFD_ABORT    - Cause gl_get_line() to abort with
 *                                      an error (set errno if you need it).
 *                      GLFD_REFRESH  - Redraw the input line and continue
 *                                      waiting for input. Use this if you
 *                                      wrote something to the terminal.
 *                      GLFD_CONTINUE - Continue to wait for input, without
 *                                      redrawing the line.
 */
#define GL_FD_EVENT_FN(fn) GlFdStatus (fn)(GetLine *gl, void *data, int fd, \
					   GlFdEvent event)
typedef GL_FD_EVENT_FN(GlFdEventFn);

/*.......................................................................
 * Where possible, register a function and associated data to be called
 * whenever a specified event is seen on a file descriptor.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  fd                int    The file descriptor to watch.
 *  event       GlFdEvent    The type of activity to watch for.
 *  callback  GlFdEventFn *  The function to call when the specified
 *                           event occurs. Setting this to 0 removes
 *                           any existing callback.
 *  data             void *  A pointer to arbitrary data to pass to the
 *                           callback function.
 * Output:
 *  return            int    0 - OK.
 *                           1 - Either gl==NULL, or this facility isn't
 *                               available on the the host system
 *                               (ie. select() isn't available). No
 *                               error message is generated in the latter
 *                               case.
 */
int gl_watch_fd(GetLine *gl, int fd, GlFdEvent event,
		GlFdEventFn *callback, void *data);

/*
 * Enumerators from the following list are returned by activity
 * timeout callbacks registered by gl_inactivity_timeout(). They tell
 * gl_get_line() whether and how to procede.
 */
typedef enum {
  GLTO_ABORT,    /* Cause gl_get_line() to abort with an error */
  GLTO_REFRESH,  /* Redraw the input line and continue waiting for input */
  GLTO_CONTINUE  /* Continue to wait for input, without redrawing the line */
} GlAfterTimeout;

/*.......................................................................
 * On systems that have the select() system call, the application has
 * the option of providing a callback function of the following type,
 * which is called whenever no terminal input or other I/O activity is
 * seen for the timeout duration specified in the last call to
 * gl_inactivity_timeout().
 *
 * Input:
 *  gl            GetLine *  The gl_get_line() resource object. You can use
 *                           this safely to call gl_watch_fd() or
 *                           gl_inactivity_timeout(). The effect of calling other
 *                           functions that take a gl argument is undefined,
 *                           and must be avoided.
 *  data             void *  A pointer to arbitrary callback data, as
 *                           originally registered with gl_inactivity_timeout().
 * Output:
 *  return GlAfterTimeout    GLTO_ABORT    - Cause gl_get_line() to
 *                                           abort with an error (set
 *                                           errno if you need it).
 *                           GLTO_REFRESH  - Redraw the input line and
 *                                           continue waiting for
 *                                           input. Use this if you
 *                                           wrote something to the
 *                                           terminal.
 *                           GLTO_CONTINUE - Continue to wait for
 *                                           input, without redrawing
 *                                           the line.
 */
#define GL_TIMEOUT_FN(fn) GlAfterTimeout (fn)(GetLine *gl, void *data)
typedef GL_TIMEOUT_FN(GlTimeoutFn);

/*.......................................................................
 * On systems with the select() system call, the gl_inactivity_timeout()
 * function provides the option of setting (or cancelling) an
 * inactivity timeout. Inactivity, in this case, refers both to
 * terminal input received from the user, and to I/O on any file
 * descriptors registered by calls to gl_watch_fd(). If at any time,
 * no activity is seen for the requested time period, the specified
 * timeout callback function is called. On returning, this callback
 * returns a code which tells gl_get_line() what to do next. Note that
 * each call to gl_inactivity_timeout() replaces any previously installed
 * timeout callback, and that specifying a callback of 0, turns off
 * inactivity timing.
 *
 * Beware that although the timeout argument includes a nano-second
 * component, few computer clocks presently have resolutions finer
 * than a few milliseconds, so asking for less than a few milliseconds
 * is equivalent to zero on a lot of systems.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  callback  GlTimeoutFn *  The function to call when the inactivity
 *                           timeout is exceeded. To turn off
 *                           inactivity timeouts altogether, send 0.
 *  data             void *  A pointer to arbitrary data to pass to the
 *                           callback function.
 *  sec     unsigned long    The number of whole seconds in the timeout.
 *  nsec    unsigned long    The fractional number of seconds in the
 *                           timeout, expressed in nano-seconds (see
 *                           the caveat above).
 * Output:
 *  return            int    0 - OK.
 *                           1 - Either gl==NULL, or this facility isn't
 *                               available on the the host system
 *                               (ie. select() isn't available). No
 *                               error message is generated in the latter
 *                               case.
 */
int gl_inactivity_timeout(GetLine *gl, GlTimeoutFn *timeout_fn, void *data,
		   unsigned long sec, unsigned long nsec);

/*.......................................................................
 * Switch history streams. History streams represent separate history
 * lists recorded within a single history buffer. Different streams
 * are distinguished by integer identifiers chosen by the calling
 * appplicaton. Initially new_GetLine() sets the stream identifier to
 * 0. Whenever a new line is appended to the history list, the current
 * stream identifier is recorded with it, and history lookups only
 * consider lines marked with the current stream identifier.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  id     unsigned    The new history stream identifier.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
int gl_group_history(GetLine *gl, unsigned id);

/*.......................................................................
 * Display the contents of the history list.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  fp         FILE *  The stdio output stream to write to.
 *  fmt  const char *  A format string. This containing characters to be
 *                     written verbatim, plus any of the following
 *                     format directives:
 *                       %D  -  The date, formatted like 2001-11-20
 *                       %T  -  The time of day, formatted like 23:59:59
 *                       %N  -  The sequential entry number of the
 *                              line in the history buffer.
 *                       %G  -  The number of the history group that
 *                              the line belongs to.
 *                       %%  -  A literal % character.
 *                       %H  -  The history line itself.
 *                     Note that a '\n' newline character is not
 *                     appended by default.
 *  all_groups  int    If true, display history lines from all
 *                     history groups. Otherwise only display
 *                     those of the current history group.
 *  max_lines   int    If max_lines is < 0, all available lines
 *                     are displayed. Otherwise only the most
 *                     recent max_lines lines will be displayed.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
int gl_show_history(GetLine *gl, FILE *fp, const char *fmt, int all_groups,
		    int max_lines);

/*.......................................................................
 * Resize or delete the history buffer.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  bufsize  size_t    The number of bytes in the history buffer, or 0
 *                     to delete the buffer completely.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Insufficient memory (the previous buffer
 *                         will have been retained). No error message
 *                         will be displayed.
 */
int gl_resize_history(GetLine *gl, size_t bufsize);

/*.......................................................................
 * Set an upper limit to the number of lines that can be recorded in the
 * history list, or remove a previously specified limit.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  max_lines   int    The maximum number of lines to allow, or -1 to
 *                     cancel a previous limit and allow as many lines
 *                     as will fit in the current history buffer size.
 */
void gl_limit_history(GetLine *gl, int max_lines);

/*.......................................................................
 * Discard either all historical lines, or just those associated with the
 * current history group.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  all_groups  int    If true, clear all of the history. If false,
 *                     clear only the stored lines associated with the
 *                     currently selected history group.
 */
void gl_clear_history(GetLine *gl, int all_groups);

/*.......................................................................
 * Temporarily enable or disable the gl_get_line() history mechanism.
 *
 * Input:
 *  gl      GetLine *  The resource object of gl_get_line().
 *  enable      int    If true, turn on the history mechanism. If
 *                     false, disable it.
 */
void gl_toggle_history(GetLine *gl, int enable);

/*
 * Objects of the following type are returned by gl_terminal_size().
 */
typedef struct {
  int nline;        /* The terminal has nline lines */
  int ncolumn;      /* The terminal has ncolumn columns */
} GlTerminalSize;

/*.......................................................................
 * Update if necessary, and return the current size of the terminal.
 *
 * Input:
 *  gl            GetLine *  The resource object of gl_get_line().
 *  def_ncolumn       int    If the number of columns in the terminal
 *                           can't be determined, substitute this number.
 *  def_nline         int    If the number of lines in the terminal can't
 *                           be determined, substitute this number.
 * Output:
 *  return GlTerminalSize    The current terminal size.
 */
GlTerminalSize gl_terminal_size(GetLine *gl, int def_ncolumn, int def_nline);

/*.......................................................................
 * Tell gl_get_line() the current terminal size. Note that this is only
 * necessary on systems where changes in terminal size aren't reported
 * via SIGWINCH.
 *
 * Input:
 *  gl            GetLine *  The resource object of gl_get_line().
 *  ncolumn           int    The number of columns in the terminal.
 *  nline             int    The number of rows in the terminal.
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int gl_set_term_size(GetLine *gl, int ncolumn, int nline);

/*
 * The gl_lookup_history() function returns information in an
 * argument of the following type.
 */
typedef struct {
  const char *line;    /* The requested history line */
  unsigned group;      /* The history group to which the */
                       /*  line belongs. */
  time_t timestamp;    /* The date and time at which the */
                       /*  line was originally entered. */
} GlHistoryLine;

/*.......................................................................
 * Lookup a history line by its sequential number of entry in the
 * history buffer.
 *
 * Input:
 *  gl            GetLine *  The resource object of gl_get_line().
 *  id      unsigned long    The identification number of the line to
 *                           be returned, where 0 denotes the first line
 *                           that was entered in the history list, and
 *                           each subsequently added line has a number
 *                           one greater than the previous one. For
 *                           the range of lines currently in the list,
 *                           see the gl_range_of_history() function.
 * Input/Output:
 *  line    GlHistoryLine *  A pointer to the variable in which to
 *                           return the details of the line.
 * Output:
 *  return            int    0 - The line is no longer in the history
 *                               list, and *line has not been changed.
 *                           1 - The requested line can be found in
 *                               *line. Note that the string in
 *                               line->line is part of the history
 *                               buffer and will change, so a private
 *                               copy should be made if you wish to
 *                               use it after subsequent calls to any
 *                               functions that take gl as an argument.
 */
int gl_lookup_history(GetLine *gl, unsigned long id, GlHistoryLine *line);

/*
 * The gl_state_of_history() function returns information in an argument
 * of the following type.
 */
typedef struct {
  int enabled;     /* True if history is enabled */
  unsigned group;  /* The current history group */
  int max_lines;   /* The current upper limit on the number of lines */
                   /*  in the history list, or -1 if unlimited. */
} GlHistoryState;

/*.......................................................................
 * Query the state of the history list. Note that any of the input/output
 * pointers can be specified as NULL.
 *
 * Input:
 *  gl            GetLine *  The resource object of gl_get_line().
 * Input/Output:
 *  state  GlHistoryState *  A pointer to the variable in which to record
 *                           the return values.
 */
void gl_state_of_history(GetLine *gl, GlHistoryState *state);

/*
 * The gl_range_of_history() function returns information in an argument
 * of the following type.
 */
typedef struct {
  unsigned long oldest;  /* The sequential entry number of the oldest */
                         /*  line in the history list. */
  unsigned long newest;  /* The sequential entry number of the newest */
                         /*  line in the history list. */
  int nlines;            /* The number of lines in the history list */
} GlHistoryRange;

/*.......................................................................
 * Query the number and range of lines in the history buffer.
 *
 * Input:
 *  gl            GetLine *  The resource object of gl_get_line().
 *  range  GlHistoryRange *  A pointer to the variable in which to record
 *                           the return values. If range->nline=0, the
 *                           range of lines will be given as 0-0.
 */
void gl_range_of_history(GetLine *gl, GlHistoryRange *range);

/*
 * The gl_size_of_history() function returns information in an argument
 * of the following type.
 */
typedef struct {
  size_t size;      /* The size of the history buffer (bytes) */
  size_t used;      /* The number of bytes of the history buffer */
                    /*  that are currently occupied. */
} GlHistorySize;

/*.......................................................................
 * Return the size of the history buffer and the amount of the
 * buffer that is currently in use.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 * Input/Output:
 *  GlHistorySize size *  A pointer to the variable in which to return
 *                        the results.
 */
void gl_size_of_history(GetLine *gl, GlHistorySize *size);

/*.......................................................................
 * Enable or disable the automatic addition of newly entered lines to the
 * history list.
 *
 * Input:
 *  gl          GetLine *   The resource object of gl_get_line().
 *  enable          int     If true, subsequently entered lines will
 *                          automatically be added to the history list
 *                          before they are returned to the caller of
 *                          gl_get_line(). If 0, the choice of how and
 *                          when to archive lines in the history list,
 *                          is left up to the calling application, which
 *                          can do so via calls to gl_append_history().
 * Output:
 *  return          int     0 - OK.
 *                          1 - Error.
 */
int gl_automatic_history(GetLine *gl, int enable);

/*.......................................................................
 * Append a specified line to the history list.
 *
 * Input:
 *  gl          GetLine *   The resource object of gl_get_line().
 *  line     const char *   The line to be added.
 * Output:
 *  return          int     0 - OK.
 *                          1 - Error.
 */
int gl_append_history(GetLine *gl, const char *line);

/*.......................................................................
 * Specify whether text that users type should be displayed or hidden.
 * In the latter case, only the prompt is displayed, and the final
 * input line is not archived in the history list.
 *
 * Input:
 *  gl         GetLine *  The input-line history maintenance object.
 *  enable         int     0 - Disable echoing.
 *                         1 - Enable echoing.
 *                        -1 - Just query the mode without changing it.
 * Output:
 *  return         int    The echoing disposition that was in effect
 *                        before this function was called:
 *                         0 - Echoing was disabled.
 *                         1 - Echoing was enabled.
 */
int gl_echo_mode(GetLine *gl, int enable);

/*.......................................................................
 * This function can be called from gl_get_line() callbacks to have
 * the prompt changed when they return. It has no effect if gl_get_line()
 * is not currently being invoked.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 *  prompt  const char *  The new prompt.
 */
void gl_replace_prompt(GetLine *gl, const char *prompt);

/*
 * Enumerate the available prompt formatting styles.
 */
typedef enum {
  GL_LITERAL_PROMPT,   /* Display the prompt string literally */
  GL_FORMAT_PROMPT     /* The prompt string can contain any of the */
                       /* following formatting directives: */
                       /*   %B  -  Display subsequent characters */
                       /*          with a bold font. */
                       /*   %b  -  Stop displaying characters */
                       /*          with the bold font. */
                       /*   %U  -  Underline subsequent characters. */
                       /*   %u  -  Stop underlining characters. */
                       /*   %S  -  Highlight subsequent characters */
                       /*          (also known as standout mode). */
                       /*   %s  -  Stop highlighting characters */
                       /*   %%  -  Display a single % character. */
} GlPromptStyle;

/*.......................................................................
 * Specify whether to heed text attribute directives within prompt
 * strings.
 *
 * Input:
 *  gl           GetLine *  The resource object of gl_get_line().
 *  style  GlPromptStyle    The style of prompt (see the definition of
 *                          GlPromptStyle in libtecla.h for details).
 */
void gl_prompt_style(GetLine *gl, GlPromptStyle style);

/*.......................................................................
 * Remove a signal from the list of signals that gl_get_line() traps.
 *
 * Input:
 *  gl           GetLine *  The resource object of gl_get_line().
 *  signo            int    The number of the signal to be ignored.
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error.
 */
int gl_ignore_signal(GetLine *gl, int signo);

/*
 * A bitwise union of the following enumerators is passed to
 * gl_trap_signal() to specify the environment in which the
 * application's signal handler is to be called.
 */
typedef enum {
  GLS_RESTORE_SIG=1,  /* Restore the caller's signal environment */
                      /* while handling the signal. */
  GLS_RESTORE_TTY=2,  /* Restore the caller's terminal settings */
                      /* while handling the signal. */
  GLS_RESTORE_LINE=4, /* Move the cursor to the start of the next line */
  GLS_REDRAW_LINE=8,  /* Redraw the input line when the signal handler */
                      /*  returns. */
  GLS_UNBLOCK_SIG=16, /* Normally a signal who's delivery is found to */
                      /*  be blocked by the calling application is not */
                      /*  trapped by gl_get_line(). Including this flag */
                      /*  causes it to be temporarily unblocked and */
                      /*  trapped while gl_get_line() is executing. */
  GLS_DONT_FORWARD=32,/* Don't forward the signal to the signal handler */
                      /*  of the calling program. */
  GLS_RESTORE_ENV = GLS_RESTORE_SIG | GLS_RESTORE_TTY | GLS_REDRAW_LINE,
  GLS_SUSPEND_INPUT = GLS_RESTORE_ENV | GLS_RESTORE_LINE
} GlSignalFlags;

/*
 * The following enumerators are passed to gl_trap_signal() to tell
 * it what to do after the application's signal handler has been called.
 */
typedef enum {
  GLS_RETURN,      /* Return the line as though the user had pressed the */
                   /*  return key. */
  GLS_ABORT,       /* Cause gl_get_line() to return NULL */
  GLS_CONTINUE     /* After handling the signal, resume command line editing */
} GlAfterSignal;

/*.......................................................................
 * Tell gl_get_line() how to respond to a given signal. This can be used
 * both to override the default responses to signals that gl_get_line()
 * normally catches and to add new signals to the list that are to be
 * caught.
 *
 * Input:
 *  gl           GetLine *  The resource object of gl_get_line().
 *  signo            int    The number of the signal to be caught.
 *  flags       unsigned    A bitwise union of GlSignalFlags enumerators.
 *  after  GlAfterSignal    What to do after the application's signal
 *                          handler has been called.
 *  errno_value      int    The value to set errno to.
 * Output:
 *  return           int    0 - OK.
 *                          1 - Insufficient memory to record the
 *                              new signal disposition.
 */
int gl_trap_signal(GetLine *gl, int signo, unsigned flags,
		   GlAfterSignal after, int errno_value);

/*.......................................................................
 * By default, gl_get_line() doesn't trap signals that are blocked
 * when it is called. This default can be changed either on a
 * per-signal basis by calling gl_trap_signal(), or on a global basis
 * by calling this function. What this function does is add the
 * GLS_UNBLOCK_SIG flag to all signals that are currently configured
 * to be trapped by gl_get_line(), such that when subsequent calls to
 * gl_get_line() wait for I/O, these signals are temporarily
 * unblocked. This behavior is useful in non-blocking server-I/O mode,
 * where it is used to avoid race conditions related to handling these
 * signals externally to gl_get_line(). See the demonstration code in
 * demo3.c, or the gl_handle_signal() man page for further
 * information.
 *
 * Input:
 *  gl         GetLine *   The resource object of gl_get_line().
 */
void gl_catch_blocked(GetLine *gl);

/*.......................................................................
 * In server-I/O mode the terminal is left in raw mode between calls
 * to gl_get_line(), so it is necessary for the application to install
 * terminal restoring signal handlers for signals that could terminate
 * or suspend the process, plus a terminal reconfiguration handler to
 * be called when a process resumption signal is received, and finally
 * a handler to be called when a terminal-resize signal is received.
 *
 * Since there are many signals that by default terminate or suspend
 * processes, and different systems support different sub-sets of
 * these signals, this function provides a convenient wrapper around
 * sigaction() for assigning the specified handlers to all appropriate
 * signals. It also arranges that when any one of these signals is
 * being handled, all other catchable signals are blocked. This is
 * necessary so that the specified signal handlers can safely call
 * gl_raw_io(), gl_normal_io() and gl_update_size() without reentrancy
 * issues.
 *
 * Input:
 *  term_handler  void (*)(int)  The signal handler to invoke when
 *                               a process terminating signal is
 *                               received.
 *  susp_handler  void (*)(int)  The signal handler to invoke when
 *                               a process suspending signal is
 *                               received.
 *  cont_handler  void (*)(int)  The signal handler to invoke when
 *                               a process resumption signal is
 *                               received (ie. SIGCONT).
 *  size_handler  void (*)(int)  The signal handler to invoke when
 *                               a terminal-resize signal (ie. SIGWINCH)
 *                               is received.
 * Output:
 *  return                  int  0 - OK.
 *                               1 - Error.
 */
int gl_tty_signals(void (*term_handler)(int), void (*susp_handler)(int),
		   void (*cont_handler)(int), void (*size_handler)(int));

/*.......................................................................
 * Return the last signal that was caught by the most recent call to
 * gl_get_line(), or -1 if no signals were caught. This is useful if
 * gl_get_line() returns errno=EINTR and you need to find out what signal
 * caused it to abort.
 *
 * Input:
 *  gl           GetLine *  The resource object of gl_get_line().
 * Output:
 *  return           int    The last signal caught by the most recent
 *                          call to gl_get_line(), or -1 if no signals
 *                          were caught.
 */
int gl_last_signal(GetLine *gl);

/*.......................................................................
 * Return the signal mask used by gl_get_line(). This is the set of
 * signals that gl_get_line() is currently configured to trap.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 * Input/Output:
 *  set       sigset_t *  The set of signals will be returned in *set,
 *                        in the form of a signal process mask, as
 *                        used by sigaction(), sigprocmask(),
 *                        sigpending(), sigsuspend(), sigsetjmp() and
 *                        other standard POSIX signal-aware
 *                        functions.
 * Output:
 *  return         int    0 - OK.
 *                        1 - Error (examine errno for reason).
 */
int gl_list_signals(GetLine *gl, sigset_t *set);

/*.......................................................................
 * Respond to signals who's default effects have important
 * consequences to gl_get_line(). This is intended for use in
 * non-blocking server mode, where the external event loop is
 * responsible for catching signals. Signals that are handled include
 * those that by default terminate or suspend the process, and the
 * signal that indicates that the terminal size has changed. Note that
 * this function is not signal safe and should thus not be called from
 * a signal handler itself. See the gl_io_mode() man page for how it
 * should be used.
 *
 * In the case of signals that by default terminate or suspend
 * processes, command-line editing will be suspended, the terminal
 * returned to a usable state, then the default disposition of the
 * signal restored and the signal resent, in order to suspend or
 * terminate the process.  If the process subsequently resumes,
 * command-line editing is resumed.
 *
 * In the case of signals that indicate that the terminal has been
 * resized, the new size will be queried, and any input line that is
 * being edited will be redrawn to fit the new dimensions of the
 * terminal.
 *
 * Input:
 *  signo    int    The number of the signal to respond to.
 *  gl   GetLine *  The first element of an array of 'ngl' GetLine
 *                  objects.
 *  ngl      int    The number of elements in the gl[] array. Normally
 *                  this will be one.
 */
void gl_handle_signal(int signo, GetLine *gl, int ngl);

/*.......................................................................
 * Return extra information (ie. in addition to that provided by errno)
 * about the last error to occur in either gl_get_line() or its
 * associated public functions.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 * Input/Output:
 *  buff          char *  An optional output buffer. Note that if the
 *                        calling application calls any gl_*()
 *                        functions from signal handlers, it should
 *                        provide a buffer here, so that a copy of
 *                        the latest error message can safely be made
 *                        while signals are blocked.
 *  n           size_t    The allocated size of buff[].
 * Output:
 *  return  const char *  A pointer to the error message. This will
 *                        be the buff argument, unless buff==NULL, in
 *                        which case it will be a pointer to an
 *                        internal error buffer. In the latter case,
 *                        note that the contents of the returned buffer
 *                        will change on subsequent calls to any gl_*()
 *                        functions.
 */
const char *gl_error_message(GetLine *gl, char *buff, size_t n);

/*.......................................................................
 * Clear the terminal and leave the cursor at the home position.  In
 * server I/O mode, arrange for the input line to be redrawn from scratch
 * when gl_get_line() is next called.
 *
 * Input:
 *  gl          GetLine *   The resource object of gl_get_line().
 * Output:
 *  return          int     0 - OK.
 *                          1 - Error.
 */
int gl_erase_terminal(GetLine *gl);

/*.......................................................................
 * Display a left-justified string over multiple terminal lines,
 * taking account of the current width of the terminal. Optional
 * indentation and an optional prefix string can be specified to be
 * displayed at the start of each new terminal line used. Similarly,
 * an optional suffix can be specified to be displayed at the end of
 * each terminal line.  If needed, a single paragraph can be broken
 * across multiple calls.  Note that literal newlines in the input
 * string can be used to force a newline at any point and that you
 * should use this feature to explicitly end all paragraphs, including
 * at the end of the last string that you write. Note that when a new
 * line is started between two words that are separated by spaces,
 * those spaces are not output, whereas when a new line is started
 * because a newline character was found in the string, only the
 * spaces before the newline character are discarded.
 *
 * Input:
 *  gl         GetLine *  The resource object of gl_get_line().
 *  indentation    int    The number of spaces of indentation to write
 *                        at the beginning of each new terminal line.
 *  prefix  const char *  An optional prefix string to write after the
 *                        indentation margin at the start of each new
 *                        terminal line. You can specify NULL if no
 *                        prefix is required.
 *  suffix  const char *  An optional suffix string to draw at the end
 *                        of the terminal line. Spaces will be added
 *                        where necessary to ensure that the suffix ends
 *                        in the last column of the terminal line. If
 *                        no suffix is desired, specify NULL.
 *  fill_char      int    The padding character to use when indenting
 *                        the line or padding up to the suffix.
 *  def_width      int    If the terminal width isn't known, such as when
 *                        writing to a pipe or redirecting to a file,
 *                        this number specifies what width to assume.
 *  start          int    The number of characters already written to
 *                        the start of the current terminal line. This
 *                        is primarily used to allow individual
 *                        paragraphs to be written over multiple calls
 *                        to this function, but can also be used to
 *                        allow you to start the first line of a
 *                        paragraph with a different prefix or
 *                        indentation than those specified above.
 *  string  const char *  The string to be written.
 * Output:
 *  return         int    On error -1 is returned. Otherwise the
 *                        return value is the terminal column index at
 *                        which the cursor was left after writing the
 *                        final word in the string. Successful return
 *                        values can thus be passed verbatim to the
 *                        'start' arguments of subsequent calls to
 *                        gl_display_text() to allow the printing of a
 *                        paragraph to be broken across multiple calls
 *                        to gl_display_text().
 */
int gl_display_text(GetLine *gl, int indentation, const char *prefix,
		    const char *suffix, int fill_char, int def_width,
		    int start, const char *string);


/*
 * Enumerate the I/O modes supported by gl_get_line().
 */
typedef enum {
  GL_NORMAL_MODE,    /* Normal line-at-a-time mode using gl_get_line()'s */
                     /*  internal event loop. */
  GL_SERVER_MODE     /* Non-blocking server mode, driven by an external */
                     /*  event loop. */
} GlIOMode;

/*.......................................................................
 * Select the I/O mode to be used by gl_get_line().
 *
 * Input:
 *  gl         GetLine *         The resource object of gl_get_line().
 *  mode      GlIOMode           The I/O mode to establish. Note that
 *                               when server mode, the terminal is placed
 *                               in raw mode, as though gl_raw_io() had
 *                               been called.
 * Output:
 *  return                  int  0 - OK.
 *                               1 - Error.
 */
int gl_io_mode(GetLine *gl, GlIOMode mode);

/*.......................................................................
 * In server mode, this function configures the terminal for non-blocking
 * raw terminal I/O. In normal I/O mode it does nothing.
 *
 * Callers of this function must be careful to trap all signals that
 * terminate or suspend the program, and call gl_normal_io()
 * from the corresponding signal handlers in order to restore the
 * terminal to its original settings before the program is terminated
 * or suspended. They should also trap the SIGCONT signal to detect
 * when the program resumes, and ensure that its signal handler
 * call gl_raw_io() to redisplay the line and resume editing.
 *
 * Input:
 *  gl      GetLine *  The line editor resource object.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
int gl_raw_io(GetLine *gl);

/*.......................................................................
 * Restore the terminal to the state that it had when gl_raw_io() was
 * last called. After calling gl_raw_io(), this function must be called
 * before terminating or suspending the program, and before attempting
 * other uses of the terminal from within the program. See gl_raw_io()
 * for more details.
 *
 * Input:
 *  gl      GetLine *  The line editor resource object.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
int gl_normal_io(GetLine *gl);

/*.......................................................................
 * When in non-blocking server mode, this function can be used to abandon
 * the current incompletely entered input line, and prepare to start
 * editing a new line on the next call to gl_get_line().
 *
 * Input:
 *  gl      GetLine *  The line editor resource object.
 * Output:
 *  return      int    0 - OK.
 *                     1 - Error.
 */
void gl_abandon_line(GetLine *gl);

/*
 * Enumerators of the following type are used to report why
 * gl_get_line() returned. This is most useful in non-blocking
 * server mode, since in that mode a NULL return value can mean
 * either that an error occurred, or that I/O blocked.
 */
typedef enum {
  GLR_NEWLINE,  /* A new input line was returned */
  GLR_BLOCKED,  /* The terminal was in non-blocking mode, and input */
                /* or output would have blocked. */
  GLR_SIGNAL,   /* A signal caused gl_get_line() to return. */
  GLR_TIMEOUT,  /* An application timeout callback returned GLTO_ABORT */
  GLR_FDABORT,  /* An application I/O callack returned GLFD_ABORT */
  GLR_EOF,      /* End of file reached */
  GLR_ERROR     /* An unexpected error caused gl_get_line() to abort */
} GlReturnStatus;

/*.......................................................................
 * Ask gl_get_line() what caused it to return.
 *
 * Input:
 *  gl             GetLine *  The line editor resource object.
 * Output:
 *  return  GlReturnStatus    The return status of the last call to
 *                            gl_get_line().
 */
GlReturnStatus gl_return_status(GetLine *gl);

/*
 * Enumerate the types of I/O that gl_get_line() can be waiting for
 * in non-blocking sedrver I/O mode.
 */
typedef enum {
  GLP_READ,   /* gl_get_line() is waiting to write to the terminal */
  GLP_WRITE   /* gl_get_line() is waiting to read from the terminal */
} GlPendingIO;

/*.......................................................................
 * In non-blocking server-I/O mode, this function should be called
 * from the application's external event loop to see what type of
 * terminal I/O is being waited for by gl_get_line(), and thus what
 * direction of I/O to wait for with select() or poll().
 *
 * Input:
 *  gl          GetLine *  The resource object of gl_get_line().
 * Output:
 *  return  GlPendingIO    The type of pending I/O being waited for.
 */
GlPendingIO gl_pending_io(GetLine *gl);

/*
 * The following enumerators are returned by externally defined action
 * functions to tell gl_get_line() how to procede after the action
 * function returns.
 */
typedef enum {
  GLA_ABORT,     /* Cause gl_get_line() to return NULL */
  GLA_RETURN,    /* Return the line as though the user had pressed the */
                 /*  return key. */
  GLA_CONTINUE   /* Resume command-line editing */
} GlAfterAction;

/*.......................................................................
 * Functions of the following form implement external
 * application-specific action functions, which can then be bound to
 * sequences of terminal keys.
 *
 * Input:
 *  gl            GetLine *  The line editor resource object.
 *  data             void *  The anonymous 'data' argument that was
 *                           passed to gl_external_action() when the
 *                           callback function was registered.
 *  count             int    A positive repeat count specified by the user,
 *                           or 1 if not specified. Action functions should
 *                           ignore this if repeating the action multiple
 *                           times isn't appropriate. Alternatively they
 *                           can interpret it as a general numeric
 *                           argument.
 *  curpos         size_t    The position of the cursor within the input
 *                           line, expressed as the index of the
 *                           corresponding character within the line[]
 *                           array.
 *  line       const char *  A read-only copy of the current input line.
 * Output
 *  return  GlAfterAction    What should gl_get_line() do when the action
 *                           function returns?
 *                            GLA_ABORT    - Cause gl_get_line() to
 *                                           abort with an error (set
 *                                           errno if you need it).
 *                            GLA_RETURN   - Return the input line as
 *                                           though the user had typed
 *                                           the return key.
 *                            GLA_CONTINUE - Resume waiting for keyboard
 *                                           input.
 */
#define GL_ACTION_FN(fn) GlAfterAction (fn)(GetLine *gl, void *data, \
	      int count, size_t curpos, const char *line)

typedef GL_ACTION_FN(GlActionFn);

/*.......................................................................
 * Register an application-provided function as an action function.
 * This should preferably be called before the first call to gl_get_line()
 * so that the name of the action becomes defined before the user's
 * configuration file is read.
 *
 * Input:
 *  gl            GetLine *  The resource object of the command-line input
 *                           module.
 *  data             void *  Arbitrary application-specific callback
 *                           data to be passed to the callback
 *                           function, fn().
 *  fn         GlActionFn *  The application-specific function that
 *                           implements the action. This will be invoked
 *                           whenever the user presses any
 *                           key-sequence which is bound to this action.
 *  name       const char *  The name with which users can refer to the
 *                           binding in tecla configuration files.
 *  keyseq     const char *  The key sequence with which to invoke
 *                           the binding. This should be specified in the
 *                           same manner as key-sequences in tecla
 *                           configuration files (eg. "M-^I").
 * Output:
 *  return            int    0 - OK.
 *                           1 - Error.
 */
int gl_register_action(GetLine *gl, void *data, GlActionFn *fn,
                       const char *name, const char *keyseq);

/*.......................................................................
 * This function is designed to be called by CPL_MATCH_FN() callback
 * functions. It adds one possible completion of the token that is being
 * completed to an array of completions. If the completion needs any
 * special quoting to be valid when displayed in the input line, this
 * quoting must be included in the string.
 *
 * Input:
 *  cpl      WordCompletion *  The argument of the same name that was passed
 *                             to the calling CPL_MATCH_FN() callback function.
 *  line         const char *  The input line, as received by the callback
 *                             function.
 *  word_start          int    The index within line[] of the start of the
 *                             word that is being completed. If an empty
 *                             string is being completed, set this to be
 *                             the same as word_end.
 *  word_end            int    The index within line[] of the character which
 *                             follows the incomplete word, as received by the
 *                             callback function.
 *  suffix       const char *  The appropriately quoted string that could
 *                             be appended to the incomplete token to complete
 *                             it. A copy of this string will be allocated
 *                             internally.
 *  type_suffix  const char *  When listing multiple completions, gl_get_line()
 *                             appends this string to the completion to indicate
 *                             its type to the user. If not pertinent pass "".
 *                             Otherwise pass a literal or static string.
 *  cont_suffix  const char *  If this turns out to be the only completion,
 *                             gl_get_line() will append this string as
 *                             a continuation. For example, the builtin
 *                             file-completion callback registers a directory
 *                             separator here for directory matches, and a
 *                             space otherwise. If the match were a function
 *                             name you might want to append an open
 *                             parenthesis, etc.. If not relevant pass "".
 *                             Otherwise pass a literal or static string.
 * Output:
 *  return              int    0 - OK.
 *                             1 - Error.
 */
int cpl_add_completion(WordCompletion *cpl, const char *line,
		       int word_start, int word_end, const char *suffix,
		       const char *type_suffix, const char *cont_suffix);

/*
 * Each possible completion string is recorded in an array element of
 * the following type.
 */
typedef struct {
  char *completion;        /* The matching completion string */
  char *suffix;            /* The pointer into completion[] at which the */
                           /*  string was extended. */
  const char *type_suffix; /* A suffix to be added when listing completions */
                           /*  to indicate the type of the completion. */
} CplMatch;

/*
 * Completions are returned in a container of the following form.
 */
typedef struct {
  char *suffix;            /* The common initial part of all of the */
                           /*  completion suffixes. */
  const char *cont_suffix; /* Optional continuation string to be appended to */
                           /*  the sole completion when nmatch==1. */
  CplMatch *matches;       /* The array of possible completion strings, */
                           /*  sorted into lexical order. */
  int nmatch;              /* The number of elements in matches[] */
} CplMatches;

/*.......................................................................
 * Given an input line and the point at which completion is to be
 * attempted, return an array of possible completions.
 *
 * Input:
 *  cpl    WordCompletion *  The word-completion resource object.
 *  line       const char *  The current input line.
 *  word_end          int    The index of the character in line[] which
 *                           follows the end of the token that is being
 *                           completed.
 *  data             void *  Anonymous 'data' to be passed to match_fn().
 *  match_fn   CplMatchFn *  The function that will identify the prefix
 *                           to be completed from the input line, and
 *                           record completion suffixes.
 * Output:
 *  return     CplMatches *  The container of the array of possible
 *                           completions. The returned pointer refers
 *                           to a container owned by the parent Completion
 *                           object, and its contents thus potentially
 *                           change on every call to cpl_complete_word().
 */
CplMatches *cpl_complete_word(WordCompletion *cpl, const char *line,
			      int word_end, void *data,
			      CplMatchFn *match_fn);

/*.......................................................................
 * Recall the return value of the last call to cpl_complete_word().
 *
 * Input:
 *  cpl    WordCompletion *  The completion resource object.
 * Output:
 *  return     CplMatches *  The container of the array of possible
 *                           completions, as returned by the last call to
 *                           cpl_complete_word(). The returned pointer refers
 *                           to a container owned by the parent WordCompletion
 *                           object, and its contents thus potentially
 *                           change on every call to cpl_complete_word().
 *                           On error, either in the execution of this
 *                           function, or in the last call to
 *                           cpl_complete_word(), NULL is returned, and a
 *                           description of the error can be acquired by
 *                           calling cpl_last_error(cpl).
 */
CplMatches *cpl_recall_matches(WordCompletion *cpl);

/*.......................................................................
 * Print out an array of matching completions.
 *
 * Input:
 *  result  CplMatches *   The container of the sorted array of
 *                         completions.
 *  fp            FILE *   The output stream to write to.
 *  term_width     int     The width of the terminal.
 * Output:
 *  return         int     0 - OK.
 *                         1 - Error.
 */
int cpl_list_completions(CplMatches *result, FILE *fp, int term_width);

/*.......................................................................
 * Return a description of the error that occurred on the last call to
 * cpl_complete_word() or cpl_add_completion().
 *
 * Input:
 *  cpl   WordCompletion *  The string-completion resource object.
 * Output:
 *  return    const char *  The description of the last error.
 */
const char *cpl_last_error(WordCompletion *cpl);

/*
 * PathCache objects encapsulate the resources needed to record
 * files of interest from comma-separated lists of directories.
 */
typedef struct PathCache PathCache;

/*.......................................................................
 * Create an object who's function is to maintain a cache of filenames
 * found within a list of directories, and provide quick lookup and
 * completion of selected files in this cache.
 *
 * Output:
 *  return     PathCache *  The new, initially empty cache, or NULL
 *                          on error.
 */
PathCache *new_PathCache(void);

/*.......................................................................
 * Delete a given cache of files, returning the resources that it
 * was using to the system.
 *
 * Input:
 *  pc      PathCache *  The cache to be deleted (can be NULL).
 * Output:
 *  return  PathCache *  The deleted object (ie. allways NULL).
 */
PathCache *del_PathCache(PathCache *pc);

/*.......................................................................
 * Return a description of the last path-caching error that occurred.
 *
 * Input:
 *  pc     PathCache *   The filename cache that suffered the error.
 * Output:
 *  return      char *   The description of the last error.
 */
const char *pca_last_error(PathCache *pc);

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
 *                          1 - An error occurred.
 */
int pca_scan_path(PathCache *pc, const char *path);

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
void pca_set_check_fn(PathCache *pc, CplCheckFn *check_fn, void *data);

/*.......................................................................
 * Given the simple name of a file, search the cached list of files
 * in the order in which they where found in the list of directories
 * previously presented to pca_scan_path(), and return the pathname
 * of the first file which has this name.
 *
 * Input:
 *  pc     PathCache *  The cached list of files.
 *  name  const char *  The name of the file to lookup.
 *  name_len     int    The length of the filename substring at the
 *                      beginning of name[], or -1 to assume that the
 *                      filename occupies the whole of the string.
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
 *                      will become invalid on the next call.
 */
char *pca_lookup_file(PathCache *pc, const char *name, int name_len,
		      int literal);

/*
 * Objects of the following type can be used to change the default
 * behavior of the pca_path_completions() callback function.
 */
typedef struct PcaPathConf PcaPathConf;

/*
 * pca_path_completions() is a completion callback function for use directly
 * with cpl_complete_word() or gl_customize_completions(), or indirectly
 * from your own completion callback function. It requires that a PcaPathConf
 * object be passed via its 'void *data' argument (see below).
 */
CPL_MATCH_FN(pca_path_completions);

/*.......................................................................
 * Allocate and initialize a pca_path_completions() configuration object.
 *
 * Input:
 *  pc         PathCache *  The filename cache in which to look for
 *                          file name completions.
 * Output:
 *  return   PcaPathConf *  The new configuration structure, or NULL
 *                          on error.
 */
PcaPathConf *new_PcaPathConf(PathCache *pc);

/*.......................................................................
 * Deallocate memory, previously allocated by new_PcaPathConf().
 *
 * Input:
 *  ppc     PcaPathConf *  Any pointer previously returned by
 *                         new_PcaPathConf() [NULL is allowed].
 * Output:
 *  return  PcaPathConf *  The deleted structure (always NULL).
 */
PcaPathConf *del_PcaPathConf(PcaPathConf *ppc);

/*
 * If backslashes in the prefix being passed to pca_path_completions()
 * should be treated as literal characters, call the following function
 * with literal=1. Otherwise the default is to treat them as escape
 * characters which remove the special meanings of spaces etc..
 */
void ppc_literal_escapes(PcaPathConf *ppc, int literal);

/*
 * Before calling pca_path_completions, call this function if you know
 * the index at which the filename prefix starts in the input line.
 * Otherwise by default, or if you specify start_index to be -1, the
 * filename is taken to start after the first unescaped space preceding
 * the cursor, or the start of the line, whichever comes first.
 */
void ppc_file_start(PcaPathConf *ppc, int start_index);

#ifdef __cplusplus
}
#endif

#endif
