/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <dirent.h>
#include <strings.h>
#include "filebench.h"
#include "auto_comp.h"

#define	VARNAME_MAXLEN	128
#define	FILENAME_MAXLEN	128
#define	MALLOC_STEP	64

#define	CSUF_CMD	" "
#define	CSUF_ARG	" "
#define	CSUF_LVARNAME	"="
#define	CSUF_RVARNAME	","
#define	CSUF_ATTRNAME	"="

#define	ATTR_LIST_SEP	','
#define	ATTR_ASSIGN_OP	'='
#define	VAR_ASSIGN_OP	'='
#define	VAR_PREFIX	'$'

#ifndef HAVE_BOOLEAN_T
typedef enum { B_FALSE, B_TRUE } boolean_t;
#endif

typedef char ac_fname_t[FILENAME_MAXLEN];

typedef struct ac_fname_cache {
	ac_fname_t	*fnc_buf;
	int		fnc_bufsize;
	time_t		fnc_mtime;
} ac_fname_cache_t;

typedef enum ac_match_result {
	MATCH_DONE,
	MATCH_CONT
} ac_match_result_t;

/*
 * We parse an user input line into multiple blank separated strings.
 * The last string is always the one user wants to complete, the other
 * preceding strings set up the context on how to complete the last one.
 *
 * ac_str_t repsents one such a string, which can be of the following
 * types:
 *
 *	STRTYPE_COMPLETE   - the string is one of the preceding strings.
 *	STRTYPE_INCOMPLETE - the string is the one being completed, user
 *			     has inputted at least one character for it.
 *	STRTYPE_NULL       - the string is the one being completed, user
 *			     has inputted nothing for it.
 *
 * ac_str_t structure has the following members:
 *
 * 	startp	- the start position of the string in the user input buffer
 * 	endp	- the end position of the string in the user input buffer
 *	strtype	- the type of the string. It can be of the following values:
 *		  STRTYPE_COMPLETE, STRTYPE_INCOMPLETE, STRTYPE_NULL,
 *		  and STRTYPE_INVALID.
 */

typedef enum ac_strtype {
	STRTYPE_COMPLETE,
	STRTYPE_INCOMPLETE,
	STRTYPE_NULL,
	STRTYPE_INVALID
} ac_strtype_t;

typedef struct ac_str {
	const char *startp;
	const char *endp;
	ac_strtype_t strtype;
} ac_str_t;

#define	STR_NUM	3

typedef struct ac_inputline {
	ac_str_t strs[STR_NUM];
} ac_inputline_t;

/*
 * ac_iter represents a general interface to access a list of values for
 * matching user input string. The structure has the following methods:
 *
 *	bind  - bind the iterator to a list, and save a pointer to user
 *		passed space in nlistpp.
 *	reset - reset internal index pointer to point to list head.
 *	get_nextstr - this is the method that does the real work. It
 *		walks through the list and returns string associated with
 *		the current item. It can also return some other thing the
 *		caller is interested via the user passed space pointed by
 *		nlistpp. In our case, that is a pointer to a list which
 *		contains all possible values for the next string in user
 *		input.
 *
 * It has the following data members:
 *
 *	listp   - a pointer to the list to be iterated through
 *	curp    - index pointer to maintain position when iterating
 *	nlistpp - a pointer to user passed space for returning a list of
 *		  values for the next string in user input
 */

typedef struct ac_iter {
	void	*listp;
	void	*curp;
	void	*nlistpp;
	void	(*bind)(struct ac_iter *, void *, void *);
	void	(*reset)(struct ac_iter *);
	const char   *(*get_nextstr)(struct ac_iter *);
} ac_iter_t;

/*
 * We consider a filebench command is composed of a sequence of tokens
 * (ie., command name, argument name, attribute name, etc.). Many of
 * these tokens have limited string values. These values, as well as
 * their dependencies, are used to complete user input string.
 *
 * There are the following tokens:
 *
 *	TOKTYPE_CMD	 - command name
 *	TOKTYPE_ARG	 - argument name
 *	TOKTYPE_ATTRNAME - attribute name
 *	TOKTYPE_ATTRVAL  - attribute value
 *	TOKTYPE_LVARNAME - variable name, used on left side of assign
 *			   operator
 *	TOKTYPE_RVARNAME - variable name, used on right side of assign
 *			   operator
 *	TOKTYPE_VARVAL	 - variable value
 *	TOKTYPE_LOADFILE - load file name
 *	TOKTYPE_ATTRLIST - pseudo token type for attribute list
 *	TOKTYPE_VARLIST  - pseudo token type for variable list
 *	TOKTYPE_NULL	 - pseudo token type for aborting auto-completion
 *
 * The reason why there are two different token types for variable name
 * is because, depending on its position, there are different requirements
 * on how to do completion and display matching results. See more details
 * in lvarname_iter and rvarname_iter definition.
 *
 * Attribute list and variable list are not really a single token. Instead
 * they contain multiple tokens, and thus have different requirements on
 * how to complete them. TOKTYPE_ATTRLIST and TOKTYPE_VARLIST are
 * introduced to to solve this issue. See more details below on
 * get_curtok() function in ac_tokinfo_t structure.
 *
 * ac_tokval_t represents a string value a token can have. The structure
 * also contains a pointer to a ac_tvlist_t structure, which represents
 * all possible values for the next token in the same command.
 *
 *	str    - the token's string value
 *	nlistp - a list which contains string values for the token
 *		 that follows
 *
 * ac_tvlist_t represents all possible values for a token. These values
 * are stored in an ac_tokval_t array. The structure also has a member
 * toktype, which is used to index an ac_tokinfo_t array to get the
 * information on how to access and use the associated value list.
 *
 *	vals	- a list of string values for this token
 *	toktype	- the token's type
 *
 * ac_tokinfo_t contains information on how to access and use the
 * string values of a specific token. Among them, the most important
 * thing is an iterator to access the value list. The reason to use
 * iterator is to encapsulate list implementation details. That is
 * necessary because some tokens have dynamic values(for example,
 * argument of load command), which cannot be predefined using
 * ac_tokval_t array.
 *
 * ac_tokinfo_t structure has the following members:
 *
 *	toktype	    - token type
 *	iter	    - iterator to access the token's value list
 *	cont_suffix - continuation suffix for this token. See note 1
 *		      below on what is continuation suffix.
 *	get_curtok  - a function to parse a multi-token user string.
 *		      It parse that string and returns the word being
 *		      completed and its token type. See note 2 below.
 *
 * Notes:
 *
 * 1) Continuation suffix is a convenient feature provided by libtecla.
 *    A continuation suffix is a string which is automatically appended
 *    to a fully completed string. For example, if a command name is
 *    fully completed, a blank space will be appended to it. This is
 *    very convenient because it not only saves typing, but also gives
 *    user an indication to continue.
 *
 * 2) get_curtok() function is a trick to support user input strings
 *    which have multiple tokens. Take attribute list as an example,
 *    although we defined a token type TOKTYPE_ATTRLIST for it, it is
 *    not a token actually, instead it contains multiple tokens like
 *    attribute name, attribute value, etc., and attribute value can
 *    be either a literal string or a variable name prefixed with a
 *    '$' sign. For this reason, get_curtok() function is needed to
 *    parse that string to get the word being completed and its token
 *    type so that we can match the word against with the proper value
 *    list.
 */

typedef enum ac_toktype {
	TOKTYPE_CMD,
	TOKTYPE_ARG,
	TOKTYPE_ATTRNAME,
	TOKTYPE_ATTRVAL,
	TOKTYPE_LVARNAME,
	TOKTYPE_RVARNAME,
	TOKTYPE_VARVAL,
	TOKTYPE_LOADFILE,
	TOKTYPE_ATTRLIST,
	TOKTYPE_VARLIST,
	TOKTYPE_NULL
} ac_toktype_t;

typedef ac_toktype_t (*ac_get_curtok_func_t)(ac_str_t *);

typedef struct ac_tokinfo {
	ac_toktype_t	toktype;
	ac_iter_t	*iter;
	char		*cont_suffix;
	ac_get_curtok_func_t	get_curtok;
} ac_tokinfo_t;

typedef struct ac_tokval {
	char		 *str;
	struct ac_tvlist *nlistp;
} ac_tokval_t;

typedef struct ac_tvlist {
	ac_tokval_t	*vals;
	ac_toktype_t	toktype;
} ac_tvlist_t;

/*
 * Variables and prototypes
 */

static void common_bind(ac_iter_t *, void *, void *);
static void common_reset(ac_iter_t *);
static void varname_bind(ac_iter_t *, void *, void *);
static void loadfile_bind(ac_iter_t *, void *, void *);
static const char *get_next_tokval(ac_iter_t *);
static const char *get_next_lvarname(ac_iter_t *);
static const char *get_next_rvarname(ac_iter_t *);
static const char *get_next_loadfile(ac_iter_t *);
static ac_toktype_t parse_attr_list(ac_str_t *);
static ac_toktype_t parse_var_list(ac_str_t *);

static ac_iter_t tokval_iter = {
	NULL,
	NULL,
	NULL,
	common_bind,
	common_reset,
	get_next_tokval
};

static ac_iter_t lvarname_iter = {
	NULL,
	NULL,
	NULL,
	varname_bind,
	common_reset,
	get_next_lvarname
};

static ac_iter_t rvarname_iter = {
	NULL,
	NULL,
	NULL,
	varname_bind,
	common_reset,
	get_next_rvarname
};

static ac_iter_t loadfile_iter = {
	NULL,
	NULL,
	NULL,
	loadfile_bind,
	common_reset,
	get_next_loadfile
};

/*
 * Note: We use toktype to index into this array, so for each toktype,
 *	 there must be one element in the array, and in the same order
 *	 as that toktype is defined in ac_toktype.
 */
static ac_tokinfo_t token_info[] = {
	{ TOKTYPE_CMD,	    &tokval_iter,   CSUF_CMD,	   NULL },
	{ TOKTYPE_ARG,	    &tokval_iter,   CSUF_ARG,	   NULL },
	{ TOKTYPE_ATTRNAME, &tokval_iter,   CSUF_ATTRNAME, NULL },
	{ TOKTYPE_ATTRVAL,  NULL,	    NULL,	   NULL },
	{ TOKTYPE_LVARNAME, &lvarname_iter, CSUF_LVARNAME, NULL },
	{ TOKTYPE_RVARNAME, &rvarname_iter, CSUF_RVARNAME, NULL },
	{ TOKTYPE_VARVAL,   NULL,	    NULL,	   NULL },
	{ TOKTYPE_LOADFILE, &loadfile_iter, CSUF_ARG,	   NULL },
	{ TOKTYPE_ATTRLIST, NULL,	    NULL,	   parse_attr_list },
	{ TOKTYPE_VARLIST,  NULL,	    NULL,	   parse_var_list },
	{ TOKTYPE_NULL,	    NULL,	    NULL,	   NULL }
};

static ac_tokval_t event_attrnames[] = {
	{ "rate",	NULL},
	{ NULL, 	NULL}
};

static ac_tvlist_t event_attrs = {
	event_attrnames,
	TOKTYPE_ATTRLIST
};

static ac_tokval_t file_attrnames[] = {
	{ "path",	NULL },
	{ "reuse",	NULL },
	{ "prealloc",	NULL },
	{ "paralloc",	NULL },
	{ NULL, 	NULL }
};

static ac_tvlist_t file_attrs = {
	file_attrnames,
	TOKTYPE_ATTRLIST
};

static ac_tokval_t fileset_attrnames[] = {
	{ "size",	NULL },
	{ "path",	NULL },
	{ "dirwidth",	NULL },
	{ "prealloc",	NULL },
	{ "filesizegamma",	NULL },
	{ "dirgamma",	NULL },
	{ "cached",	NULL },
	{ "entries",	NULL },
	{ NULL, 	NULL }
};

static ac_tvlist_t fileset_attrs = {
	fileset_attrnames,
	TOKTYPE_ATTRLIST
};

static ac_tokval_t process_attrnames[] = {
	{ "nice",	NULL },
	{ "instances",	NULL },
	{ NULL,		NULL }
};

static ac_tvlist_t process_attrs = {
	process_attrnames,
	TOKTYPE_ATTRLIST
};

static ac_tokval_t create_argnames[] = {
	{ "file",	NULL },
	{ "fileset",	NULL },
	{ "process",	NULL },
	{ NULL, 	NULL }
};

static ac_tvlist_t create_args = {
	create_argnames,
	TOKTYPE_ARG
};

static ac_tokval_t define_argnames[] = {
	{ "file", 	&file_attrs },
	{ "fileset",	&fileset_attrs },
	{ "process",	&process_attrs },
	{ NULL, 	NULL }
};

static ac_tvlist_t define_args = {
	define_argnames,
	TOKTYPE_ARG
};

static ac_tvlist_t load_args = {
	NULL,
	TOKTYPE_LOADFILE
};

static ac_tvlist_t set_args = {
	NULL,
	TOKTYPE_VARLIST
};

static ac_tokval_t shutdown_argnames[] = {
	{ "process",	NULL },
	{ NULL,		NULL }
};

static ac_tvlist_t shutdown_args = {
	shutdown_argnames,
	TOKTYPE_ARG
};

static ac_tokval_t stats_argnames[] = {
	{ "clear", 	NULL },
	{ "directory", 	NULL },
	{ "command",	NULL },
	{ "dump",	NULL },
	{ "xmldump",	NULL },
	{ NULL, 	NULL }
};

static ac_tvlist_t stats_args = {
	stats_argnames,
	TOKTYPE_ARG
};

static ac_tokval_t fb_cmdnames[] = {
	{ "create",	&create_args },
	{ "define",	&define_args },
	{ "debug",	NULL },
	{ "echo",	NULL },
	{ "eventgen",	&event_attrs },
	{ "foreach",	NULL },
	{ "help",	NULL },
	{ "list",	NULL },
	{ "load",	&load_args },
	{ "log",	NULL },
	{ "quit",	NULL },
	{ "run",	NULL },
	{ "set",	&set_args },
	{ "shutdown",	&shutdown_args },
	{ "sleep",	NULL },
	{ "stats",	&stats_args },
	{ "system",	NULL },
	{ "usage",	NULL },
	{ "vars",	NULL },
	{ NULL,		NULL },
};

static ac_tvlist_t fb_cmds = {
	fb_cmdnames,
	TOKTYPE_CMD
};

static ac_fname_cache_t loadnames = { NULL, 0, 0 };

static int search_loadfiles(ac_fname_cache_t *);
static void parse_user_input(const char *, int, ac_inputline_t *);
static int compare_string(ac_str_t *, const char *, boolean_t, const char **);
static ac_match_result_t match_string(WordCompletion *, const char *, int,
    ac_str_t *, ac_iter_t *, const char *);

/*
 * Bind the iterator to the passed list
 */
static void
common_bind(ac_iter_t *iterp, void *listp, void *nlistpp)
{
	iterp->listp = listp;
	iterp->nlistpp = nlistpp;
}

/*
 * Reset index pointer to point to list head
 */
static void
common_reset(ac_iter_t *iterp)
{
	iterp->curp = iterp->listp;
}

/*
 * Walk through an array of ac_tokval_t structures and return string
 * of each item.
 */
static const char *
get_next_tokval(ac_iter_t *iterp)
{
	ac_tokval_t *listp = iterp->listp;  /* list head */
	ac_tokval_t *curp = iterp->curp;  /* index pointer */
	/* user passed variable for returning value list for next token */
	ac_tvlist_t **nlistpp = iterp->nlistpp;
	const char *p;

	if (listp == NULL || curp == NULL)
		return (NULL);

	/* get the current item's string */
	p = curp->str;

	/*
	 * save the current item's address into a user passed variable
	 */
	if (nlistpp != NULL)
		*nlistpp = curp->nlistp;

	/* advance the index pointer */
	iterp->curp = ++curp;

	return (p);
}

/*
 * Bind the iterator to filebench_shm->shm_var_list
 */
/* ARGSUSED */
static void
varname_bind(ac_iter_t *iterp, void *listp, void * nlistpp)
{
	iterp->listp = filebench_shm->shm_var_list;
	iterp->nlistpp = nlistpp;
}

/*
 * Walk through a linked list of var_t type structures and return name
 * of each variable with a preceding '$' sign
 */
static const char *
get_next_lvarname(ac_iter_t *iterp)
{
	static char buf[VARNAME_MAXLEN];

	var_t *listp = iterp->listp;  /* list head */
	var_t *curp = iterp->curp;  /* index pointer */
	/* User passed variable for returning value list for next token */
	ac_tvlist_t **nlistpp = iterp->nlistpp;
	const char *p;

	if (listp == NULL || curp == NULL)
		return (NULL);

	/* Get current variable's name, copy it to buf, with a '$' prefix */
	p = curp->var_name;
	(void) snprintf(buf, sizeof (buf), "$%s", p);

	/* No information for the next input string */
	if (nlistpp != NULL)
		*nlistpp = NULL;

	/* Advance the index pointer */
	iterp->curp = curp->var_next;

	return (buf);
}

/*
 * Walk through a linked list of var_t type structures and return name
 * of each variable
 */
static const char *
get_next_rvarname(ac_iter_t *iterp)
{
	var_t *listp = iterp->listp;  /* list head */
	var_t *curp = iterp->curp;  /* index pointer */
	/* User passed variable for returning value list for next item */
	ac_tvlist_t **nlistpp = iterp->nlistpp;
	const char *p;

	if (listp == NULL || curp == NULL)
		return (NULL);

	/* Get current variable's name */
	p = curp->var_name;

	/* No information for the next input string */
	if (nlistpp != NULL)
		*nlistpp = NULL;

	/* Advance the index pointer */
	iterp->curp = curp->var_next;

	return (p);
}

/*
 * Bind the iterator to loadnames.fnc_buf, which is an ac_fname_t array
 * and contains up-to-date workload file names. The function calls
 * search_loadfiles() to update the cache before the binding.
 */
/* ARGSUSED */
static void
loadfile_bind(ac_iter_t *iterp, void *listp, void * nlistpp)
{
	/* Check loadfile name cache, update it if needed */
	(void) search_loadfiles(&loadnames);

	iterp->listp = loadnames.fnc_buf;
	iterp->nlistpp = nlistpp;
}

/*
 * Walk through a string(ac_fname_t, more exactly) array and return each
 * string, until a NULL iterm is encountered.
 */
static const char *
get_next_loadfile(ac_iter_t *iterp)
{
	ac_fname_t *listp = iterp->listp; /* list head */
	ac_fname_t *curp = iterp->curp; /* index pointer */
	/* User passed variable for returning value list for next item */
	ac_tvlist_t **nlistpp = iterp->nlistpp;
	const char *p;

	if (listp == NULL || curp == NULL)
		return (NULL);

	/*
	 * Get current file name. If an NULL item is encountered, it means
	 * this is the end of the list. In that case, we need to set p to
	 * NULL to indicate to the caller that the end of the list is reached.
	 */
	p = (char *)curp;
	if (*p == NULL)
		p = NULL;

	/* No information for the next input string */
	if (nlistpp != NULL)
		*nlistpp = NULL;

	/* Advance the index pointer */
	iterp->curp = ++curp;

	return (p);
}

/*
 * Search for available workload files in workload direcotry and
 * update workload name cache.
 */
static int
search_loadfiles(ac_fname_cache_t *fnamecache)
{
	DIR *dirp;
	struct dirent *fp;
	struct stat dstat;
	time_t mtime;
	ac_fname_t *buf;
	int bufsize = MALLOC_STEP;
	int len, i;

	if (stat(FILEBENCHDIR"/workloads", &dstat) != 0)
		return (-1);
	mtime = dstat.st_mtime;

	/* Return if there is no change since last time */
	if (mtime == fnamecache->fnc_mtime)
		return (0);

	/* Get loadfile names and cache it */
	if ((buf = malloc(sizeof (ac_fname_t) * bufsize)) == NULL)
		return (-1);
	if ((dirp = opendir(FILEBENCHDIR"/workloads")) == NULL)
		return (-1);
	i = 0;
	while ((fp = readdir(dirp)) != NULL) {
		len = strlen(fp->d_name);
		if (len <= 2 || (fp->d_name)[len - 2] != '.' ||
		    (fp->d_name)[len - 1] != 'f')
			continue;

		if (i == bufsize) {
			bufsize += MALLOC_STEP;
			if ((buf = realloc(buf, sizeof (ac_fname_t) *
			    bufsize)) == NULL)
				return (-1);
		}

		(void) snprintf(buf[i], FILENAME_MAXLEN, "%s", fp->d_name);
		if (len -2 <= FILENAME_MAXLEN - 1) {
			/* Remove .f suffix in file name */
			buf[i][len -2] = NULL;
		}
		i++;
	}
	/* Added a NULL iterm as the array's terminator */
	buf[i][0] = NULL;

	if (fnamecache->fnc_bufsize != 0)
		free(fnamecache->fnc_buf);
	fnamecache->fnc_buf = buf;
	fnamecache->fnc_bufsize = bufsize;
	fnamecache->fnc_mtime = mtime;

	return (0);
}

/*
 * Parse user input line into a list of blank separated strings, and
 * save the result in the passed ac_inputline_t structure. line and word_end
 * parameters are passed from libtecla library. line points to user input
 * buffer, and word_end is the index of the last character of user input.
 */
/* ARGSUSED */
static void
parse_user_input(const char *line, int word_end, ac_inputline_t *input)
{
	const char *p = line;
	int i;

	/* Reset all fileds */
	for (i = 0; i < STR_NUM; i++) {
		input->strs[i].startp = NULL;
		input->strs[i].endp = NULL;
		input->strs[i].strtype = STRTYPE_INVALID;
	}

	/*
	 * Parse user input. We don't use word_end to do boundary checking,
	 * instead we take advantage of the fact that the passed line
	 * parameter is always terminated by '\0'.
	 */
	for (i = 0; i < STR_NUM; i++) {
		/* Skip leading blank spaces */
		while (*p == ' ')
			p++;

		if (*p == NULL) {
			/*
			 * User input nothing for the string being input
			 * before he pressed TAB. We use STR_NULL flag
			 * to indicate this so that match_str() will list
			 * all available candidates.
			 */
			input->strs[i].startp = p;
			input->strs[i].strtype = STRTYPE_NULL;
			return;
		}

		/* Recoard the start and end of the string */
		input->strs[i].startp = p;
		while ((*p != ' ') && (*p != NULL))
			p++;
		input->strs[i].endp = p - 1;

		if (*p == NULL) {
			input->strs[i].strtype = STRTYPE_INCOMPLETE;
			return;
		} else {
			/* The string is followed by a blank space */
			input->strs[i].strtype = STRTYPE_COMPLETE;
		}
	}
}

/*
 * Parse an input string which is an attribue list, get the current word
 * user wants to complete, and return its token type.
 *
 * An atribute list has the following format:
 *
 * 	name1=val,name2=$var,...
 *
 * The function modifies the passed acstr string on success to point to
 * the word being completed.
 */
static ac_toktype_t
parse_attr_list(ac_str_t *acstr)
{
	const char *p;

	if (acstr->strtype == STRTYPE_COMPLETE) {
		/*
		 * User has input a complete string for attribute list
		 * return TOKTYPE_NULL to abort the matching.
		 */
		return (TOKTYPE_ATTRLIST);
	} else if (acstr->strtype == STRTYPE_NULL) {
		/*
		 * User haven't input anything for the attribute list,
		 * he must be trying to list all attribute names.
		 */
		return (TOKTYPE_ATTRNAME);
	}

	/*
	 * The string may contain multiple comma separated "name=value"
	 * items. Try to find the last one and move startp to point to it.
	 */
	for (p = acstr->endp; p >= acstr->startp && *p != ATTR_LIST_SEP; p--) {}

	if (p == acstr->endp) {
		/*
		 * The last character of the string is ',', which means
		 * user is trying to list all attribute names.
		 */
		acstr->startp = p + 1;
		acstr->strtype = STRTYPE_NULL;
		return (TOKTYPE_ATTRNAME);
	} else if (p > acstr->startp) {
		/*
		 * Found ',' between starp and endp, move startp pointer
		 * to point to the last item.
		 */
		acstr->startp = p + 1;
	}

	/*
	 * Now startp points to the last "name=value" item. Search in
	 * the characters user has input for this item:
	 *
	 *   a) if there isn't '=' character, user is inputting attribute name
	 *   b) if there is a '=' character and it is followed by a '$',
	 *	user is inputting variable name
	 *   c) if there is a '=' character and it isn't followed by a '$',
	 *	user is inputting a literal string as attribute value.
	 */
	for (p = acstr->startp; p <= acstr->endp; p++) {
		if (*p == ATTR_ASSIGN_OP) {
			/* Found "=" operator in the string */
			if (*(p + 1) == VAR_PREFIX) {
				acstr->startp = p + 2;
				if (*acstr->startp != NULL)
					acstr->strtype = STRTYPE_INCOMPLETE;
				else
					acstr->strtype = STRTYPE_NULL;
				return (TOKTYPE_RVARNAME);
			} else {
				return (TOKTYPE_ATTRVAL);
			}
		}
	}

	/* Didn't find '=' operator, the string must be an attribute name */
	return (TOKTYPE_ATTRNAME);
}

/*
 * Parse an input string which is a variable list, get the current word
 * user wants to complete, and return its token type.
 *
 * A varaible list has the following format:
 *
 *	$varname=value
 *
 * The function modifies the passed acstr string on success to point to
 * the word being completed.
 */
static ac_toktype_t
parse_var_list(ac_str_t *acstr)
{
	const char *p;

	if (acstr->strtype == STRTYPE_COMPLETE) {
		/*
		 * User has input a complete string for var list
		 * return TOKTYPE_NULL to abort the matching.
		 */
		return (TOKTYPE_NULL);
	} else if (acstr->strtype == STRTYPE_NULL) {
		/*
		 * User haven't input anything for the attribute list,
		 * he must be trying to list all available var names.
		 */
		return (TOKTYPE_LVARNAME);
	}

	/*
	 * Search in what user has input:
	 *
	 *   a) if there isn't a '=' character, user is inputting var name
	 *   b) if there is a '=' character, user is inputting var value
	 */
	for (p = acstr->startp; p <= acstr->endp; p++) {
		if (*p == VAR_ASSIGN_OP)
			return (TOKTYPE_VARVAL);
	}

	/* Didn't find '=' operator, user must be inputting an var name */
	return (TOKTYPE_LVARNAME);
}

/*
 * Compare two strings acstr and str. acstr is a string of ac_str_t type,
 * str is a normal string. If issub is B_TRUE, the function checks if
 * acstr is a sub-string of str, starting from index 0; otherwise it checks
 * if acstr and str are exactly the same.
 *
 * The function returns 0 on success and -1 on failure. When it succeeds,
 * it also set restp to point to the rest part of the normal string.
 */
static int
compare_string(ac_str_t *acstr, const char *str, boolean_t issub,
    const char **restp)
{
	const char *p, *q;

	for (p = acstr->startp, q = str; (p <= acstr->endp) && (*q != '\0');
	    p++, q++) {
		if (*p != *q)
			return (-1);
	}

	if (p == acstr->endp + 1) {
		if (*q == '\0' || issub == B_TRUE) {
			if (restp != NULL)
				*restp = q;
			return (0);
		}
	}

	return (-1);
}

/*
 * Use the passed iterp iterator to access a list of string values to
 * look for those matches with acstr, an user input string to be completed.
 *
 * cpl, line, work_end, and cont_suffix are parameters needed by
 * cpl_add_completion(), which adds matched entries to libtecla.
 *
 * Since user input line may have multiple strings, the function is
 * expected to be called multiple times to match those strings one
 * by one until the last one is reached.
 *
 * The multi-step matching process also means the function should provide
 * a way to indicate to the caller whether to continue or abort the
 * whole matching process. The function does that with the following
 * return values:
 *
 *    MATCH_DONE - the matching for the whole user input is done. This
 *		   can mean either some items are found or none is found.
 *		   In either case, the caller shouldn't continue to
 *		   match the rest strings, either because there is
 *		   no strings left, or because the matching for the
 *		   current string failed so there is no need to check
 *		   further.
 *    MATCH_CONT - the matching for the current string succeeds, but
 *		   user needs to continue to match the rest strings.
 */
static ac_match_result_t
match_string(WordCompletion *cpl, const char *line, int word_end,
    ac_str_t *acstr, ac_iter_t *iterp, const char *cont_suffix)
{
	const char *str, *restp;

	iterp->reset(iterp);

	if (acstr->strtype == STRTYPE_COMPLETE) {
		while ((str = iterp->get_nextstr(iterp)) != NULL) {
			if (!compare_string(acstr, str, B_FALSE, NULL)) {
				/* Continue to check rest strings */
				return (MATCH_CONT);
			}
		}
	} else if (acstr->strtype == STRTYPE_NULL) {
		/* User input nothing. List all available strings */
		while ((str = iterp->get_nextstr(iterp)) != NULL) {
			(void) cpl_add_completion(cpl, line,
			    acstr->startp - line, word_end, str,
			    NULL, cont_suffix);
		}
	} else if (acstr->strtype == STRTYPE_INCOMPLETE) {
		while ((str = iterp->get_nextstr(iterp)) != NULL) {
			if (!compare_string(acstr, str, B_TRUE, &restp)) {
				/* It matches! Add it. */
				(void) cpl_add_completion(cpl, line,
				    acstr->startp - line, word_end, restp,
				    NULL, cont_suffix);
			}
		}
	}

	return (MATCH_DONE);
}

/*
 * This is the interface between filebench and libtecla for auto-
 * completion. It is called by libtecla whenever user initiates a
 * auto-completion request(ie., pressing TAB key).
 *
 * The function calls parse_user_input() to parse user input into
 * multiple strings, then it calls match_string() to match each
 * string in user input in sequence until either the last string
 * is reached and completed or the the matching fails.
 */
/* ARGSUSED */
CPL_MATCH_FN(command_complete)
{
	ac_inputline_t inputline;
	ac_tvlist_t *clistp = &fb_cmds, *nlistp;
	ac_toktype_t toktype;
	ac_iter_t *iterp;
	char *cont_suffix;
	ac_get_curtok_func_t get_curtok;
	int i, ret;

	/* Parse user input and save the result in inputline variable. */
	parse_user_input(line, word_end, &inputline);

	/*
	 * Match each string in user input against the proper token's
	 * value list, and continue the loop until either the last string
	 * is reached and completed or the matching aborts.
	 */
	for (i = 0; i < STR_NUM &&
	    inputline.strs[i].strtype != STRTYPE_INVALID && clistp != NULL;
	    i++) {
		toktype = clistp->toktype;

		/*
		 * If the current stirng can contain multiple tokens, modify
		 * the stirng to point to the word being input and return
		 * its token type.
		 */
		get_curtok = token_info[toktype].get_curtok;
		if (get_curtok != NULL)
			toktype = (*get_curtok)(&inputline.strs[i]);

		iterp = token_info[toktype].iter;
		cont_suffix = token_info[toktype].cont_suffix;
		/* Return if there is no completion info for the token */
		if (iterp == NULL)
			break;

		iterp->bind(iterp, clistp->vals, &nlistp);
		/* Match user string against the token's list */
		ret = match_string(cpl, line, word_end, &inputline.strs[i],
		    iterp, cont_suffix);
		if (ret == MATCH_DONE)
			return (0);
		clistp = nlistp;
	}

	return (0);
}
