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
 * Standard includes.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/*
 * Local includes.
 */
#include "libtecla.h"
#include "ioutil.h"
#include "stringrp.h"
#include "pathutil.h"
#include "cplfile.h"
#include "cplmatch.h"
#include "errmsg.h"

/*
 * Specify the number of strings to allocate when the string free-list
 * is exhausted. This also sets the number of elements to expand the
 * matches[] array by whenever it is found to be too small.
 */
#define STR_BLK_FACT 100

/*
 * Set the default number of spaces place between columns when listing
 * a set of completions.
 */
#define CPL_COL_SEP 2

/*
 * Completion matches are recorded in containers of the following
 * type.
 */
struct WordCompletion {
  ErrMsg *err;            /* The error reporting buffer */
  StringGroup *sg;        /* Memory for a group of strings */
  int matches_dim;        /* The allocated size of result.matches[] */
  CplMatches result;      /* Completions to be returned to the caller */
#ifndef WITHOUT_FILE_SYSTEM
  CompleteFile *cf;       /* The resources used for filename completion */
#endif
};

static void cpl_sort_matches(WordCompletion *cpl);
static void cpl_zap_duplicates(WordCompletion *cpl);
static void cpl_clear_completions(WordCompletion *cpl);
static int cpl_cmp_matches(const void *v1, const void *v2);
static int cpl_cmp_suffixes(const void *v1, const void *v2);

/*
 * The new_CplFileConf() constructor sets the integer first member of
 * the returned object to the following magic number. On seeing this,
 * cpl_file_completions() knows when it is passed a valid CplFileConf
 * object.
 */
#define CFC_ID_CODE 4568

#ifndef WITHOUT_FILE_SYSTEM
/*
 * A pointer to a structure of the following type can be passed to
 * the builtin file-completion callback function to modify its behavior.
 */
struct CplFileConf {
  int id;             /* new_CplFileConf() sets this to CFC_ID_CODE */
  int escaped;        /* If none-zero, backslashes in the input line are */
                      /*  interpreted as escaping special characters and */
                      /*  spaces, and any special characters and spaces in */
                      /*  the listed completions will also be escaped with */
                      /*  added backslashes. This is the default behaviour. */
                      /* If zero, backslashes are interpreted as being */
                      /*  literal parts of the filename, and none are added */
                      /*  to the completion suffixes. */
  int file_start;     /* The index in the input line of the first character */
                      /*  of the filename. If you specify -1 here, */
                      /*  cpl_file_completions() identifies the */
                      /*  the start of the filename by looking backwards for */
                      /*  an unescaped space, or the beginning of the line. */
  CplCheckFn *chk_fn; /* If not zero, this argument specifies a */
                      /*  function to call to ask whether a given */
                      /*  file should be included in the list */
                      /*  of completions. */
  void *chk_data;     /* Anonymous data to be passed to check_fn(). */
};

static void cpl_init_FileConf(CplFileConf *cfc);

/*
 * When file-system access is being excluded, define a dummy structure
 * to satisfy the typedef in libtecla.h.
 */
#else
struct CplFileConf {int dummy;};
#endif

/*
 * Encapsulate the formatting information needed to layout a
 * multi-column listing of completions.
 */
typedef struct {
  int term_width;     /* The width of the terminal (characters) */
  int column_width;   /* The number of characters within in each column. */
  int ncol;           /* The number of columns needed */
  int nline;          /* The number of lines needed */
} CplListFormat;

/*
 * Given the current terminal width, and a list of completions, determine
 * how to best use the terminal width to display a multi-column listing
 * of completions.
 */
static void cpl_plan_listing(CplMatches *result, int term_width,
			     CplListFormat *fmt);

/*
 * Display a given line of a multi-column list of completions.
 */
static int cpl_format_line(CplMatches *result, CplListFormat *fmt, int lnum,
			   GlWriteFn *write_fn, void *data);

/*.......................................................................
 * Create a new string-completion object.
 *
 * Output:
 *  return    WordCompletion *  The new object, or NULL on error.
 */
WordCompletion *new_WordCompletion(void)
{
  WordCompletion *cpl;  /* The object to be returned */
/*
 * Allocate the container.
 */
  cpl = (WordCompletion *) malloc(sizeof(WordCompletion));
  if(!cpl) {
    errno = ENOMEM;
    return NULL;
  };
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to del_WordCompletion().
 */
  cpl->err = NULL;
  cpl->sg = NULL;
  cpl->matches_dim = 0;
  cpl->result.suffix = NULL;
  cpl->result.cont_suffix = NULL;
  cpl->result.matches = NULL;
  cpl->result.nmatch = 0;
#ifndef WITHOUT_FILE_SYSTEM
  cpl->cf = NULL;
#endif
/*
 * Allocate a place to record error messages.
 */
  cpl->err = _new_ErrMsg();
  if(!cpl->err)
    return del_WordCompletion(cpl);
/*
 * Allocate an object that allows a group of strings to be allocated
 * efficiently by placing many of them in contiguous string segments.
 */
#ifdef WITHOUT_FILE_SYSTEM
  cpl->sg = _new_StringGroup(MAX_PATHLEN_FALLBACK);
#else
  cpl->sg = _new_StringGroup(_pu_pathname_dim());
#endif
  if(!cpl->sg)
    return del_WordCompletion(cpl);
/*
 * Allocate an array for matching completions. This will be extended later
 * if needed.
 */
  cpl->matches_dim = STR_BLK_FACT;
  cpl->result.matches = (CplMatch *) malloc(sizeof(cpl->result.matches[0]) *
					    cpl->matches_dim);
  if(!cpl->result.matches) {
    errno = ENOMEM;
    return del_WordCompletion(cpl);
  };
/*
 * Allocate a filename-completion resource object.
 */
#ifndef WITHOUT_FILE_SYSTEM
  cpl->cf = _new_CompleteFile();
  if(!cpl->cf)
    return del_WordCompletion(cpl);
#endif
  return cpl;
}

/*.......................................................................
 * Delete a string-completion object.
 *
 * Input:
 *  cpl    WordCompletion *  The object to be deleted.
 * Output:
 *  return WordCompletion *  The deleted object (always NULL).
 */
WordCompletion *del_WordCompletion(WordCompletion *cpl)
{
  if(cpl) {
    cpl->err = _del_ErrMsg(cpl->err);
    cpl->sg = _del_StringGroup(cpl->sg);
    if(cpl->result.matches) {
      free(cpl->result.matches);
      cpl->result.matches = NULL;
#ifndef WITHOUT_FILE_SYSTEM
      cpl->cf = _del_CompleteFile(cpl->cf);
#endif
    };
    free(cpl);
  };
  return NULL;
}

/*.......................................................................
 * This function is designed to be called by CplMatchFn callback
 * functions. It adds one possible completion of the token that is being
 * completed to an array of completions. If the completion needs any
 * special quoting to be valid when displayed in the input line, this
 * quoting must be included in the string.
 *
 * Input:
 *  cpl     WordCompletion *  The argument of the same name that was passed
 *                            to the calling CplMatchFn callback function.
 *  line        const char *  The input line, as received by the callback
 *                            function.
 *  word_start         int    The index within line[] of the start of the
 *                            word that is being completed.
 *  word_end           int    The index within line[] of the character which
 *                            follows the incomplete word, as received by the
 *                            calling callback function.
 *  suffix      const char *  The appropriately quoted string that could
 *                            be appended to the incomplete token to complete
 *                            it. A copy of this string will be allocated
 *                            internally.
 *  type_suffix const char *  When listing multiple completions, gl_get_line()
 *                            appends this string to the completion to indicate
 *                            its type to the user. If not pertinent pass "".
 *                            Otherwise pass a literal or static string.
 *  cont_suffix const char *  If this turns out to be the only completion,
 *                            gl_get_line() will append this string as
 *                            a continuation. For example, the builtin
 *                            file-completion callback registers a directory
 *                            separator here for directory matches, and a
 *                            space otherwise. If the match were a function
 *                            name you might want to append an open
 *                            parenthesis, etc.. If not relevant pass "".
 *                            Otherwise pass a literal or static string.
 * Output:
 *  return             int    0 - OK.
 *                            1 - Error.
 */
int cpl_add_completion(WordCompletion *cpl, const char *line,
		       int word_start, int word_end, const char *suffix,
		       const char *type_suffix, const char *cont_suffix)
{
  CplMatch *match; /* The container of the new match */
  char *string;    /* A newly allocated copy of the completion string */
  size_t len;
/*
 * Check the arguments.
 */
  if(!cpl)
    return 1;
  if(!suffix)
    return 0;
  if(!type_suffix)
    type_suffix = "";
  if(!cont_suffix)
    cont_suffix = "";
/*
 * Do we need to extend the array of matches[]?
 */
  if(cpl->result.nmatch+1 > cpl->matches_dim) {
    int needed = cpl->matches_dim + STR_BLK_FACT;
    CplMatch *matches = (CplMatch *) realloc(cpl->result.matches,
			    sizeof(cpl->result.matches[0]) * needed);
    if(!matches) {
      _err_record_msg(cpl->err,
		      "Insufficient memory to extend array of matches.",
		      END_ERR_MSG);
      return 1;
    };
    cpl->result.matches = matches;
    cpl->matches_dim = needed;
  };
/*
 * Allocate memory to store the combined completion prefix and the
 * new suffix.
 */
  len = strlen(suffix);
  string = _sg_alloc_string(cpl->sg, word_end-word_start + len);
  if(!string) {
    _err_record_msg(cpl->err, "Insufficient memory to extend array of matches.",
		    END_ERR_MSG);
    return 1;
  };
/*
 * Compose the string.
 */
  strncpy(string, line + word_start, word_end - word_start);
  strlcpy(string + word_end - word_start, suffix, len + 1);
/*
 * Record the new match.
 */
  match = cpl->result.matches + cpl->result.nmatch++;
  match->completion = string;
  match->suffix = string + word_end - word_start;
  match->type_suffix = type_suffix;
/*
 * Record the continuation suffix.
 */
  cpl->result.cont_suffix = cont_suffix;
  return 0;
}

/*.......................................................................
 * Sort the array of matches.
 *
 * Input:
 *  cpl   WordCompletion *  The completion resource object.
 */
static void cpl_sort_matches(WordCompletion *cpl)
{
  qsort(cpl->result.matches, cpl->result.nmatch,
	sizeof(cpl->result.matches[0]), cpl_cmp_matches);
}

/*.......................................................................
 * This is a qsort() comparison function used to sort matches.
 *
 * Input:
 *  v1, v2   void *  Pointers to the two matches to be compared.
 * Output:
 *  return    int    -1 -> v1 < v2.
 *                    0 -> v1 == v2
 *                    1 -> v1 > v2
 */
static int cpl_cmp_matches(const void *v1, const void *v2)
{
  const CplMatch *m1 = (const CplMatch *) v1;
  const CplMatch *m2 = (const CplMatch *) v2;
  return strcmp(m1->completion, m2->completion);
}

/*.......................................................................
 * Sort the array of matches in order of their suffixes.
 *
 * Input:
 *  cpl   WordCompletion *  The completion resource object.
 */
static void cpl_sort_suffixes(WordCompletion *cpl)
{
  qsort(cpl->result.matches, cpl->result.nmatch,
	sizeof(cpl->result.matches[0]), cpl_cmp_suffixes);
}

/*.......................................................................
 * This is a qsort() comparison function used to sort matches in order of
 * their suffixes.
 *
 * Input:
 *  v1, v2   void *  Pointers to the two matches to be compared.
 * Output:
 *  return    int    -1 -> v1 < v2.
 *                    0 -> v1 == v2
 *                    1 -> v1 > v2
 */
static int cpl_cmp_suffixes(const void *v1, const void *v2)
{
  const CplMatch *m1 = (const CplMatch *) v1;
  const CplMatch *m2 = (const CplMatch *) v2;
  return strcmp(m1->suffix, m2->suffix);
}

/*.......................................................................
 * Find the common prefix of all of the matching completion matches,
 * and record a pointer to it in cpl->result.suffix. Note that this has
 * the side effect of sorting the matches into suffix order.
 *
 * Input:
 *  cpl   WordCompletion *  The completion resource object.
 * Output:
 *  return           int    0 - OK.
 *                          1 - Error.
 */
static int cpl_common_suffix(WordCompletion *cpl)
{
  CplMatches *result;       /* The result container */
  const char *first, *last; /* The first and last matching suffixes */
  int length;               /* The length of the common suffix */
/*
 * Get the container of the array of matching files.
 */
  result = &cpl->result;
/*
 * No matching completions?
 */
  if(result->nmatch < 1)
    return 0;
/*
 * Sort th matches into suffix order.
 */
  cpl_sort_suffixes(cpl);
/*
 * Given that the array of matches is sorted, the first and last
 * suffixes are those that differ most in their prefixes, so the common
 * prefix of these strings is the longest common prefix of all of the
 * suffixes.
 */
  first = result->matches[0].suffix;
  last = result->matches[result->nmatch - 1].suffix;
/*
 * Find the point at which the first and last matching strings
 * first difffer.
 */
  while(*first && *first == *last) {
    first++;
    last++;
  };
/*
 * How long is the common suffix?
 */
  length = first - result->matches[0].suffix;
/*
 * Allocate memory to record the common suffix.
 */
  result->suffix = _sg_alloc_string(cpl->sg, length);
  if(!result->suffix) {
    _err_record_msg(cpl->err,
		    "Insufficient memory to record common completion suffix.",
		    END_ERR_MSG);
    return 1;
  };
/*
 * Record the common suffix.
 */
  strncpy(result->suffix, result->matches[0].suffix, length);
  result->suffix[length] = '\0'; 
  return 0;
}

/*.......................................................................
 * Discard the contents of the array of possible completion matches.
 *
 * Input:
 *  cpl   WordCompletion *  The word-completion resource object.
 */
static void cpl_clear_completions(WordCompletion *cpl)
{
/*
 * Discard all of the strings.
 */
  _clr_StringGroup(cpl->sg);
/*
 * Record the fact that the array is now empty.
 */
  cpl->result.nmatch = 0;
  cpl->result.suffix = NULL;
  cpl->result.cont_suffix = "";
/*
 * Also clear the error message.
 */
  _err_clear_msg(cpl->err);
  return;
}

/*.......................................................................
 * Given an input line and the point at which it completion is to be
 * attempted, return an array of possible completions.
 *
 * Input:
 *  cpl    WordCompletion *  The completion resource object.
 *  line             char *  The current input line.
 *  word_end          int    The index of the character in line[] which
 *                           follows the end of the token that is being
 *                           completed.
 *  data             void *  Anonymous 'data' to be passed to match_fn().
 *  match_fn   CplMatchFn *  The function that will identify the prefix
 *                           to be completed from the input line, and
 *                           record completion matches.
 * Output:
 *  return     CplMatches *  The container of the array of possible
 *                           completions. The returned pointer refers
 *                           to a container owned by the parent WordCompletion
 *                           object, and its contents thus potentially
 *                           change on every call to cpl_matches().
 *                           On error, NULL is returned, and a description
 *                           of the error can be acquired by calling
 *                           cpl_last_error(cpl).
 */
CplMatches *cpl_complete_word(WordCompletion *cpl, const char *line,
			      int word_end, void *data, 
			      CplMatchFn *match_fn)
{
  int line_len;   /* The total length of the input line */
/*
 * How long is the input line?
 */
  line_len = strlen(line);
/*
 * Check the arguments.
 */
  if(!cpl || !line || !match_fn || word_end < 0 || word_end > line_len) {
    if(cpl) {
      _err_record_msg(cpl->err, "cpl_complete_word: Invalid arguments.",
		      END_ERR_MSG);
    };
    return NULL;
  };
/*
 * Clear the return container.
 */
  cpl_clear_completions(cpl);
/*
 * Have the matching function record possible completion matches in
 * cpl->result.matches.
 */
  if(match_fn(cpl, data, line, word_end)) {
    if(_err_get_msg(cpl->err)[0] == '\0')
      _err_record_msg(cpl->err, "Error completing word.", END_ERR_MSG);
    return NULL;
  };
/*
 * Record a copy of the common initial part of all of the prefixes
 * in cpl->result.common.
 */
  if(cpl_common_suffix(cpl))
    return NULL;
/*
 * Sort the matches into lexicographic order.
 */
  cpl_sort_matches(cpl);
/*
 * Discard any duplicate matches.
 */
  cpl_zap_duplicates(cpl);
/*
 * If there is more than one match, discard the continuation suffix.
 */
  if(cpl->result.nmatch > 1)
    cpl->result.cont_suffix = "";
/*
 * Return the array of matches.
 */
  return &cpl->result;
}

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
CplMatches *cpl_recall_matches(WordCompletion *cpl)
{
  return (!cpl || *_err_get_msg(cpl->err)!='\0') ? NULL : &cpl->result;
}

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
int cpl_list_completions(CplMatches *result, FILE *fp, int term_width)
{
  return _cpl_output_completions(result, _io_write_stdio, fp, term_width);
}

/*.......................................................................
 * Print an array of matching completions via a callback function.
 *
 * Input:
 *  result   CplMatches *  The container of the sorted array of
 *                         completions.
 *  write_fn  GlWriteFn *  The function to call to write the completions,
 *                         or 0 to discard the output.
 *  data           void *  Anonymous data to pass to write_fn().
 *  term_width      int    The width of the terminal.
 * Output:
 *  return          int     0 - OK.
 *                          1 - Error.
 */
int _cpl_output_completions(CplMatches *result, GlWriteFn *write_fn, void *data,
			    int term_width)
{
  CplListFormat fmt; /* List formatting information */
  int lnum;          /* The sequential number of the line to print next */
/*
 * Not enough space to list anything?
 */
  if(term_width < 1)
    return 0;
/*
 * Do we have a callback to write via, and any completions to be listed?
 */
  if(write_fn && result && result->nmatch>0) {
/*
 * Work out how to arrange the listing into fixed sized columns.
 */
    cpl_plan_listing(result, term_width, &fmt);
/*
 * Print the listing via the specified callback.
 */
    for(lnum=0; lnum < fmt.nline; lnum++) {
      if(cpl_format_line(result, &fmt, lnum, write_fn, data))
	return 1;
    };
  };
  return 0;
}

/*.......................................................................
 * Return a description of the string-completion error that occurred.
 *
 * Input:
 *  cpl   WordCompletion *  The string-completion resource object.
 * Output:
 *  return    const char *  The description of the last error.
 */
const char *cpl_last_error(WordCompletion *cpl)
{
  return cpl ? _err_get_msg(cpl->err) : "NULL WordCompletion argument";
}

/*.......................................................................
 * When an error occurs while performing a completion, you registerf a
 * terse description of the error by calling cpl_record_error(). This
 * message will then be returned on the next call to cpl_last_error().
 *
 * Input:
 *  cpl   WordCompletion *  The string-completion resource object that was
 *                          originally passed to the callback.
 *  errmsg    const char *  The description of the error.
 */
void cpl_record_error(WordCompletion *cpl, const char *errmsg)
{
  if(cpl && errmsg)
    _err_record_msg(cpl->err, errmsg, END_ERR_MSG);
}

/*.......................................................................
 * This is the builtin completion callback function which performs file
 * completion.
 *
 * Input:
 *  cpl  WordCompletion *  An opaque pointer to the object that will
 *                         contain the matches. This should be filled
 *                         via zero or more calls to cpl_add_completion().
 *  data           void *  Either NULL to request the default
 *                         file-completion behavior, or a pointer to a
 *                         CplFileConf structure, whose members specify
 *                         a different behavior.
 *  line           char *  The current input line.
 *  word_end        int    The index of the character in line[] which
 *                         follows the end of the token that is being
 *                         completed.
 * Output
 *  return          int    0 - OK.
 *                         1 - Error.
 */
CPL_MATCH_FN(cpl_file_completions)
{
#ifdef WITHOUT_FILE_SYSTEM
  return 0;
#else
  const char *start_path;  /* The pointer to the start of the pathname */
                           /*  in line[]. */
  CplFileConf *conf;       /* The new-style configuration object. */
/*
 * The following configuration object will be used if the caller didn't
 * provide one.
 */
  CplFileConf default_conf;
/*
 * This function can be called externally, so check its arguments.
 */
  if(!cpl)
    return 1;
  if(!line || word_end < 0) {
    _err_record_msg(cpl->err, "cpl_file_completions: Invalid arguments.",
		    END_ERR_MSG);
    return 1;
  };
/*
 * The 'data' argument is either a CplFileConf pointer, identifiable
 * by having an integer id code as its first member, or the deprecated
 * CplFileArgs pointer, or can be NULL to request the default
 * configuration.
 */
  if(data && *(int *)data == CFC_ID_CODE) {
    conf = (CplFileConf *) data;
  } else {
/*
 * Select the defaults.
 */
    conf = &default_conf;
    cpl_init_FileConf(&default_conf);
/*
 * If we have been passed an instance of the deprecated CplFileArgs
 * structure, copy its configuration parameters over the defaults.
 */
    if(data) {
      CplFileArgs *args = (CplFileArgs *) data;
      conf->escaped = args->escaped;
      conf->file_start = args->file_start;
    };
  };
/*
 * Get the start of the filename. If not specified by the caller
 * identify it by searching backwards in the input line for an
 * unescaped space or the start of the line.
 */
  if(conf->file_start < 0) {
    start_path = _pu_start_of_path(line, word_end);
    if(!start_path) {
      _err_record_msg(cpl->err, "Unable to find the start of the filename.",
		      END_ERR_MSG);
      return 1;
    };
  } else {
    start_path = line + conf->file_start;
  };
/*
 * Perform the completion.
 */
  if(_cf_complete_file(cpl, cpl->cf, line, start_path - line, word_end,
		      conf->escaped, conf->chk_fn, conf->chk_data)) {
    cpl_record_error(cpl, _cf_last_error(cpl->cf));
    return 1;
  };
  return 0;
#endif
}

/*.......................................................................
 * Initialize a CplFileArgs structure with default configuration
 * parameters. Note that the CplFileArgs configuration type is
 * deprecated. The opaque CplFileConf object should be used in future
 * applications.
 *
 * Input:
 *  cfa  CplFileArgs *  The configuration object of the
 *                      cpl_file_completions() callback.
 */
void cpl_init_FileArgs(CplFileArgs *cfa)
{
  if(cfa) {
    cfa->escaped = 1;
    cfa->file_start = -1;
  };
}

#ifndef WITHOUT_FILE_SYSTEM
/*.......................................................................
 * Initialize a CplFileConf structure with default configuration
 * parameters.
 *
 * Input:
 *  cfc  CplFileConf *  The configuration object of the
 *                      cpl_file_completions() callback.
 */
static void cpl_init_FileConf(CplFileConf *cfc)
{
  if(cfc) {
    cfc->id = CFC_ID_CODE;
    cfc->escaped = 1;
    cfc->file_start = -1;
    cfc->chk_fn = 0;
    cfc->chk_data = NULL;
  };
}
#endif

/*.......................................................................
 * Create a new CplFileConf object and initialize it with defaults.
 *
 * Output:
 *  return  CplFileConf *  The new object, or NULL on error.
 */
CplFileConf *new_CplFileConf(void)
{
#ifdef WITHOUT_FILE_SYSTEM
  errno = EINVAL;
  return NULL;
#else
  CplFileConf *cfc;  /* The object to be returned */
/*
 * Allocate the container.
 */
  cfc = (CplFileConf *)malloc(sizeof(CplFileConf));
  if(!cfc)
    return NULL;
/*
 * Before attempting any operation that might fail, initialize the
 * container at least up to the point at which it can safely be passed
 * to del_CplFileConf().
 */
  cpl_init_FileConf(cfc);
  return cfc;
#endif
}

/*.......................................................................
 * Delete a CplFileConf object.
 *
 * Input:
 *  cfc    CplFileConf *  The object to be deleted.
 * Output:
 *  return CplFileConf *  The deleted object (always NULL).
 */
CplFileConf *del_CplFileConf(CplFileConf *cfc)
{
#ifndef WITHOUT_FILE_SYSTEM
  if(cfc) {
/*
 * Delete the container.
 */
    free(cfc);
  };
#endif
  return NULL;
}

/*.......................................................................
 * If backslashes in the filename should be treated as literal
 * characters, call the following function with literal=1. Otherwise
 * the default is to treat them as escape characters, used for escaping
 * spaces etc..
 *
 * Input:
 *  cfc    CplFileConf *  The cpl_file_completions() configuration object
 *                        to be configured.
 *  literal        int    Pass non-zero here to enable literal interpretation
 *                        of backslashes. Pass 0 to turn off literal
 *                        interpretation.
 */
void cfc_literal_escapes(CplFileConf *cfc, int literal)
{
#ifndef WITHOUT_FILE_SYSTEM
  if(cfc)
    cfc->escaped = !literal;
#endif
}

/*.......................................................................
 * Call this function if you know where the index at which the
 * filename prefix starts in the input line. Otherwise by default,
 * or if you specify start_index to be -1, the filename is taken
 * to start after the first unescaped space preceding the cursor,
 * or the start of the line, which ever comes first.
 *
 * Input:
 *  cfc    CplFileConf *  The cpl_file_completions() configuration object
 *                        to be configured.
 *  start_index    int    The index of the start of the filename in
 *                        the input line, or -1 to select the default.
 */
void cfc_file_start(CplFileConf *cfc, int start_index)
{
#ifndef WITHOUT_FILE_SYSTEM
  if(cfc)
    cfc->file_start = start_index;
#endif
}

/*.......................................................................
 * If you only want certain types of files to be included in the
 * list of completions, you use the following function to specify a
 * callback function which will be called to ask whether a given file
 * should be included.
 *
 * Input:
 *  cfc    CplFileConf *  The cpl_file_completions() configuration object
 *                        to be configured.
 *  chk_fn  CplCheckFn *  Zero to disable filtering, or a pointer to a
 *                        function that returns 1 if a given file should
 *                        be included in the list of completions.
 *  chk_data      void *  Anonymous data to be passed to chk_fn()
 *                        every time that it is called.
 */
void cfc_set_check_fn(CplFileConf *cfc, CplCheckFn *chk_fn, void *chk_data)
{
#ifndef WITHOUT_FILE_SYSTEM
  if(cfc) {
    cfc->chk_fn = chk_fn;
    cfc->chk_data = chk_data;
  };
#endif
}

/*.......................................................................
 * The following CplCheckFn callback returns non-zero if the specified
 * filename is that of an executable.
 */
CPL_CHECK_FN(cpl_check_exe)
{
#ifdef WITHOUT_FILE_SYSTEM
  return 0;
#else
  return _pu_path_is_exe(pathname);
#endif
}

/*.......................................................................
 * Remove duplicates from a sorted array of matches.
 *
 * Input:
 *  cpl   WordCompletion *  The completion resource object.
 */
static void cpl_zap_duplicates(WordCompletion *cpl)
{
  CplMatch *matches;       /* The array of matches */
  int nmatch;              /* The number of elements in matches[] */
  const char *completion;  /* The completion string of the last unique match */
  const char *type_suffix; /* The type of the last unique match */
  int src;                 /* The index of the match being considered */
  int dst;                 /* The index at which to record the next */
                           /*  unique match. */
/*
 * Get the array of matches and the number of matches that it
 * contains.
 */
  matches = cpl->result.matches;
  nmatch = cpl->result.nmatch;
/*
 * No matches?
 */
  if(nmatch < 1)
    return;
/*
 * Initialize the comparison strings with the first match.
 */
  completion = matches[0].completion;
  type_suffix = matches[0].type_suffix;
/*
 * Go through the array of matches, copying each new unrecorded
 * match at the head of the array, while discarding duplicates.
 */
  for(src=dst=1; src<nmatch; src++) {
    CplMatch *match = matches + src;
    if(strcmp(completion, match->completion) != 0 ||
       strcmp(type_suffix, match->type_suffix) != 0) {
      if(src != dst)
	matches[dst] = *match;
      dst++;
      completion = match->completion;
      type_suffix = match->type_suffix;
    };
  };
/*
 * Record the number of unique matches that remain.
 */
  cpl->result.nmatch = dst;
  return;
}

/*.......................................................................
 * Work out how to arrange a given array of completions into a listing
 * of one or more fixed size columns.
 *
 * Input:
 *  result   CplMatches *   The set of completions to be listed.
 *  term_width      int     The width of the terminal. A lower limit of
 *                          zero is quietly enforced.
 * Input/Output:
 *  fmt   CplListFormat *   The formatting information will be assigned
 *                          to the members of *fmt.
 */
static void cpl_plan_listing(CplMatches *result, int term_width,
			     CplListFormat *fmt)
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
  for(i=0; i<result->nmatch; i++) {
    CplMatch *match = result->matches + i;
    int len = strlen(match->completion) + strlen(match->type_suffix);
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
 * maxlen + CPL_COL_SEP characters.
 */
  fmt->column_width = maxlen;
  fmt->ncol = fmt->term_width / (fmt->column_width + CPL_COL_SEP);
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
  fmt->nline = (result->nmatch + fmt->ncol - 1) / fmt->ncol;
  return;
}

/*.......................................................................
 * Render one line of a multi-column listing of completions, using a
 * callback function to pass the output to an arbitrary destination.
 *
 * Input:
 *  result      CplMatches *  The container of the sorted array of
 *                            completions.
 *  fmt      CplListFormat *  Formatting information.
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
static int cpl_format_line(CplMatches *result, CplListFormat *fmt, int lnum,
			   GlWriteFn *write_fn, void *data)
{
  int col;             /* The index of the list column being output */
/*
 * If the line index is out of bounds, there is nothing to be written.
 */
  if(lnum < 0 || lnum >= fmt->nline)
    return 1;
/*
 * If no output function has been provided, return as though the
 * line had been printed.
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
    if(m < result->nmatch) {
      CplMatch *match = result->matches + m;
/*
 * How long are the completion and type-suffix strings?
 */
      int clen = strlen(match->completion);
      int tlen = strlen(match->type_suffix);
/*
 * Write the completion string.
 */
      if(write_fn(data, match->completion, clen) != clen)
	return 1;
/*
 * Write the type suffix, if any.
 */
      if(tlen > 0 && write_fn(data, match->type_suffix, tlen) != tlen)
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
	int npad = fmt->column_width + CPL_COL_SEP - clen - tlen;
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
