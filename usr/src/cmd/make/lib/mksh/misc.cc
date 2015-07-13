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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


/*
 *	misc.cc
 *
 *	This file contains various unclassified routines. Some main groups:
 *		getname
 *		Memory allocation
 *		String handling
 *		Property handling
 *		Error message handling
 *		Make internal state dumping
 *		main routine support
 */

/*
 * Included files
 */
#include <bsd/bsd.h>		/* bsd_signal() */
#include <mksh/i18n.h>		/* get_char_semantics_value() */
#include <mksh/misc.h>
#include <stdarg.h>		/* va_list, va_start(), va_end() */
#include <stdlib.h>		/* mbstowcs() */
#include <sys/signal.h>		/* SIG_DFL */
#include <sys/wait.h>		/* wait() */

#include <string.h>		/* strerror() */
#include <libintl.h>


/*
 * Defined macros
 */

/*
 * typedefs & structs
 */

/*
 * Static variables
 */
extern "C" {
	void		(*sigivalue)(int) = SIG_DFL;
	void		(*sigqvalue)(int) = SIG_DFL;
	void		(*sigtvalue)(int) = SIG_DFL;
	void		(*sighvalue)(int) = SIG_DFL;
}

long	getname_bytes_count = 0;
long	getname_names_count = 0;
long	getname_struct_count = 0;

long	freename_bytes_count = 0;
long	freename_names_count = 0;
long	freename_struct_count = 0;

long	expandstring_count = 0;
long	getwstring_count = 0;

/*
 * File table of contents
 */
static void	expand_string(register String string, register int length);

#define	FATAL_ERROR_MSG_SIZE 200

/*
 *	getmem(size)
 *
 *	malloc() version that checks the returned value.
 *
 *	Return value:
 *				The memory chunk we allocated
 *
 *	Parameters:
 *		size		The size of the chunk we need
 *
 *	Global variables used:
 */
char *
getmem(register int size)
{
	register char          *result = (char *) malloc((unsigned) size);
	if (result == NULL) {
		char buf[FATAL_ERROR_MSG_SIZE];
		sprintf(buf, "*** Error: malloc(%d) failed: %s\n", size, strerror(errno));
		strcat(buf, gettext("mksh: Fatal error: Out of memory\n"));
		fputs(buf, stderr);
		exit_status = 1;
		exit(1);
	}
	return result;
}

/*
 *	retmem(p)
 *
 *	Cover funtion for free() to make it possible to insert advises.
 *
 *	Parameters:
 *		p		The memory block to free
 *
 *	Global variables used:
 */
void
retmem(wchar_t *p)
{
	(void) free((char *) p);
}

void
retmem_mb(caddr_t p)
{
	(void) free(p);
}

/*
 *	getname_fn(name, len, dont_enter)
 *
 *	Hash a name string to the corresponding nameblock.
 *
 *	Return value:
 *				The Name block for the string
 *
 *	Parameters:
 *		name		The string we want to internalize
 *		len		The length of that string
 *		dont_enter	Don't enter the name if it does not exist
 *
 *	Global variables used:
 *		funny		The vector of semantic tags for characters
 *		hashtab		The hashtable used for the nametable
 */
Name
getname_fn(wchar_t *name, register int len, register Boolean dont_enter, register Boolean * foundp)
{
	register int		length;
	register wchar_t	*cap = name;
	register Name		np;
	static Name_rec		empty_Name;
	char			*tmp_mbs_buffer = NULL;
	char			*mbs_name = mbs_buffer;

	/*
	 * First figure out how long the string is.
	 * If the len argument is -1 we count the chars here.
	 */
	if (len == FIND_LENGTH) {
		length = wcslen(name);
	} else {
		length = len;
	}

	Wstring ws;
	ws.init(name, length);
	if (length >= MAXPATHLEN) {
		mbs_name = tmp_mbs_buffer = getmem((length * MB_LEN_MAX) + 1);
	}
	(void) wcstombs(mbs_name, ws.get_string(), (length * MB_LEN_MAX) + 1);

	/* Look for the string */
	if (dont_enter || (foundp != 0)) {
		np = hashtab.lookup(mbs_name);
		if (foundp != 0) {
			*foundp = (np != 0) ? true : false;
		}
		if ((np != 0) || dont_enter) {
			if(tmp_mbs_buffer != NULL) {
				retmem_mb(tmp_mbs_buffer);
			}
			return np;
		} else {
			np = ALLOC(Name);
		}
	} else {
		Boolean found;
		np = hashtab.insert(mbs_name, found);
		if (found) {
			if(tmp_mbs_buffer != NULL) {
				retmem_mb(tmp_mbs_buffer);
			}
			return np;
		}
	}
	getname_struct_count += sizeof(struct _Name);
	*np = empty_Name;

	np->string_mb = strdup(mbs_name);
	if(tmp_mbs_buffer != NULL) {
		retmem_mb(tmp_mbs_buffer);
		mbs_name = tmp_mbs_buffer = NULL;
	}
	getname_bytes_count += strlen(np->string_mb) + 1;
	/* Fill in the new Name */
	np->stat.time = file_no_time;
	np->hash.length = length;
	/* Scan the namestring to classify it */
	for (cap = name, len = 0; --length >= 0;) {
		len |= get_char_semantics_value(*cap++);
	}
	np->dollar = BOOLEAN((len & (int) dollar_sem) != 0);
	np->meta = BOOLEAN((len & (int) meta_sem) != 0);
	np->percent = BOOLEAN((len & (int) percent_sem) != 0);
	np->wildcard = BOOLEAN((len & (int) wildcard_sem) != 0);
	np->colon = BOOLEAN((len & (int) colon_sem) != 0);
	np->parenleft = BOOLEAN((len & (int) parenleft_sem) != 0);
	getname_names_count++;
	return np;
}

void
store_name(Name name)
{
	hashtab.insert(name);
}

void
free_name(Name name)
{
	freename_names_count++;
	freename_struct_count += sizeof(struct _Name);
	freename_bytes_count += strlen(name->string_mb) + 1;
	retmem_mb(name->string_mb);
	for (Property next, p = name->prop; p != NULL; p = next) {
		next = p->next;
		free(p);
	}
	free(name);
}

/*
 *	enable_interrupt(handler)
 *
 *	This routine sets a new interrupt handler for the signals make
 *	wants to deal with.
 *
 *	Parameters:
 *		handler		The function installed as interrupt handler
 *
 *	Static variables used:
 *		sigivalue	The original signal handler
 *		sigqvalue	The original signal handler
 *		sigtvalue	The original signal handler
 *		sighvalue	The original signal handler
 */
void
enable_interrupt(register void (*handler) (int))
{
	if (sigivalue != SIG_IGN) {
		(void) bsd_signal(SIGINT, (SIG_PF) handler);
	}
	if (sigqvalue != SIG_IGN) {
		(void) bsd_signal(SIGQUIT, (SIG_PF) handler);
	}
	if (sigtvalue != SIG_IGN) {
		(void) bsd_signal(SIGTERM, (SIG_PF) handler);
	}
	if (sighvalue != SIG_IGN) {
		(void) bsd_signal(SIGHUP, (SIG_PF) handler);
	}
}

/*
 *	setup_char_semantics()
 *
 *	Load the vector char_semantics[] with lexical markers
 *
 *	Parameters:
 *
 *	Global variables used:
 *		char_semantics	The vector of character semantics that we set
 */
void
setup_char_semantics(void)
{
	const char	*s;
	wchar_t		wc_buffer[1];
	int		entry;

	if (svr4) {
		s = "@-";
	} else {
		s = "=@-?!+";
	}
	for (s; MBTOWC(wc_buffer, s); s++) {
		entry = get_char_semantics_entry(*wc_buffer);
		char_semantics[entry] |= (int) command_prefix_sem;
	}
	char_semantics[dollar_char_entry] |= (int) dollar_sem;
	for (s = "#|=^();&<>*?[]:$`'\"\\\n"; MBTOWC(wc_buffer, s); s++) {
		entry = get_char_semantics_entry(*wc_buffer);
		char_semantics[entry] |= (int) meta_sem;
	}
	char_semantics[percent_char_entry] |= (int) percent_sem;
	for (s = "@*<%?^"; MBTOWC(wc_buffer, s); s++) {
		entry = get_char_semantics_entry(*wc_buffer);
		char_semantics[entry] |= (int) special_macro_sem;
	}
	for (s = "?[*"; MBTOWC(wc_buffer, s); s++) {
		entry = get_char_semantics_entry(*wc_buffer);
		char_semantics[entry] |= (int) wildcard_sem;
	}
	char_semantics[colon_char_entry] |= (int) colon_sem;
	char_semantics[parenleft_char_entry] |= (int) parenleft_sem;
}

/*
 *	errmsg(errnum)
 *
 *	Return the error message for a system call error
 *
 *	Return value:
 *				An error message string
 *
 *	Parameters:
 *		errnum		The number of the error we want to describe
 *
 *	Global variables used:
 *		sys_errlist	A vector of error messages
 *		sys_nerr	The size of sys_errlist
 */
char *
errmsg(int errnum)
{

	extern int		sys_nerr;
	char			*errbuf;

	if ((errnum < 0) || (errnum > sys_nerr)) {
		errbuf = getmem(6+1+11+1);
		(void) sprintf(errbuf, gettext("Error %d"), errnum);
		return errbuf;
	} else {
		return strerror(errnum);

	}
}

static char static_buf[MAXPATHLEN*3];

/*
 *	fatal_mksh(format, args...)
 *
 *	Print a message and die
 *
 *	Parameters:
 *		format		printf type format string
 *		args		Arguments to match the format
 */
/*VARARGS*/
void
fatal_mksh(const char *message, ...)
{
	va_list args;
	char    *buf = static_buf;
	char	*mksh_fat_err = gettext("mksh: Fatal error: ");
	char	*cur_wrk_dir = gettext("Current working directory: ");
	int	mksh_fat_err_len = strlen(mksh_fat_err);

	va_start(args, message);
	(void) fflush(stdout);
	(void) strcpy(buf, mksh_fat_err);
	size_t buf_len = vsnprintf(static_buf + mksh_fat_err_len,
				   sizeof(static_buf) - mksh_fat_err_len,
				   message, args)
			+ mksh_fat_err_len
			+ strlen(cur_wrk_dir)
			+ strlen(get_current_path_mksh())
			+ 3; // "\n\n"
	va_end(args);
	if (buf_len >= sizeof(static_buf)) {
		buf = getmem(buf_len);
		(void) strcpy(buf, mksh_fat_err);
		va_start(args, message);
		(void) vsprintf(buf + mksh_fat_err_len, message, args);
		va_end(args);
	}
	(void) strcat(buf, "\n");
/*
	if (report_pwd) {
 */
	if (1) {
		(void) strcat(buf, cur_wrk_dir);
		(void) strcat(buf, get_current_path_mksh());
		(void) strcat(buf, "\n");
	}
	(void) fputs(buf, stderr);
	(void) fflush(stderr);
	if (buf != static_buf) {
		retmem_mb(buf);
	}
	exit_status = 1;
	exit(1);
}

/*
 *	fatal_reader_mksh(format, args...)
 *
 *	Parameters:
 *		format		printf style format string
 *		args		arguments to match the format
 */
/*VARARGS*/
void
fatal_reader_mksh(const char * pattern, ...)
{
	va_list args;
	char	message[1000];

	va_start(args, pattern);
/*
	if (file_being_read != NULL) {
		WCSTOMBS(mbs_buffer, file_being_read);
		if (line_number != 0) {
			(void) sprintf(message,
				       gettext("%s, line %d: %s"),
				       mbs_buffer,
				       line_number,
				       pattern);
		} else {
			(void) sprintf(message,
				       "%s: %s",
				       mbs_buffer,
				       pattern);
		}
		pattern = message;
	}
 */

	(void) fflush(stdout);
	(void) fprintf(stderr, gettext("mksh: Fatal error in reader: "));
	(void) vfprintf(stderr, pattern, args);
	(void) fprintf(stderr, "\n");
	va_end(args);

/*
	if (temp_file_name != NULL) {
		(void) fprintf(stderr,
			       gettext("mksh: Temp-file %s not removed\n"),
			       temp_file_name->string_mb);
		temp_file_name = NULL;
	}
 */

/*
	if (report_pwd) {
 */
	if (1) {
		(void) fprintf(stderr,
			       gettext("Current working directory %s\n"),
			       get_current_path_mksh());
	}
	(void) fflush(stderr);
	exit_status = 1;
	exit(1);
}

/*
 *	warning_mksh(format, args...)
 *
 *	Print a message and continue.
 *
 *	Parameters:
 *		format		printf type format string
 *		args		Arguments to match the format
 */
/*VARARGS*/
void
warning_mksh(char * message, ...)
{
	va_list args;

	va_start(args, message);
	(void) fflush(stdout);
	(void) fprintf(stderr, gettext("mksh: Warning: "));
	(void) vfprintf(stderr, message, args);
	(void) fprintf(stderr, "\n");
	va_end(args);
/*
	if (report_pwd) {
 */
	if (1) {
		(void) fprintf(stderr,
			       gettext("Current working directory %s\n"),
			       get_current_path_mksh());
	}
	(void) fflush(stderr);
}

/*
 *	get_current_path_mksh()
 *
 *	Stuff current_path with the current path if it isnt there already.
 *
 *	Parameters:
 *
 *	Global variables used:
 */
char *
get_current_path_mksh(void)
{
	char			pwd[(MAXPATHLEN * MB_LEN_MAX)];
	static char		*current_path;

	if (current_path == NULL) {
		getcwd(pwd, sizeof(pwd));
		if (pwd[0] == (int) nul_char) {
			pwd[0] = (int) slash_char;
			pwd[1] = (int) nul_char;
		}
		current_path = strdup(pwd);
	}
	return current_path;
}

/*
 *	append_prop(target, type)
 *
 *	Create a new property and append it to the property list of a Name.
 *
 *	Return value:
 *				A new property block for the target
 *
 *	Parameters:
 *		target		The target that wants a new property
 *		type		The type of property being requested
 *
 *	Global variables used:
 */
Property
append_prop(register Name target, register Property_id type)
{
	register Property	*insert = &target->prop;
	register Property	prop = *insert;
	register int		size;

	switch (type) {
	case conditional_prop:
		size = sizeof (struct Conditional);
		break;
	case line_prop:
		size = sizeof (struct Line);
		break;
	case macro_prop:
		size = sizeof (struct _Macro);
		break;
	case makefile_prop:
		size = sizeof (struct Makefile);
		break;
	case member_prop:
		size = sizeof (struct Member);
		break;
	case recursive_prop:
		size = sizeof (struct Recursive);
		break;
	case sccs_prop:
		size = sizeof (struct Sccs);
		break;
	case suffix_prop:
		size = sizeof (struct Suffix);
		break;
	case target_prop:
		size = sizeof (struct Target);
		break;
	case time_prop:
		size = sizeof (struct STime);
		break;
	case vpath_alias_prop:
		size = sizeof (struct Vpath_alias);
		break;
	case long_member_name_prop:
		size = sizeof (struct Long_member_name);
		break;
	case macro_append_prop:
		size = sizeof (struct _Macro_appendix);
		break;
	case env_mem_prop:
		size = sizeof (struct _Env_mem);
		break;
	default:
		fatal_mksh(gettext("Internal error. Unknown prop type %d"), type);
	}
	for (; prop != NULL; insert = &prop->next, prop = *insert);
	size += PROPERTY_HEAD_SIZE;
	*insert = prop = (Property) getmem(size);
	memset((char *) prop, 0, size);
	prop->type = type;
	prop->next = NULL;
	return prop;
}

/*
 *	maybe_append_prop(target, type)
 *
 *	Append a property to the Name if none of this type exists
 *	else return the one already there
 *
 *	Return value:
 *				A property of the requested type for the target
 *
 *	Parameters:
 *		target		The target that wants a new property
 *		type		The type of property being requested
 *
 *	Global variables used:
 */
Property
maybe_append_prop(register Name target, register Property_id type)
{
	register Property	prop;

	if ((prop = get_prop(target->prop, type)) != NULL) {
		return prop;
	}
	return append_prop(target, type);
}

/*
 *	get_prop(start, type)
 *
 *	Scan the property list of a Name to find the next property
 *	of a given type.
 *
 *	Return value:
 *				The first property of the type, if any left
 *
 *	Parameters:
 *		start		The first property block to check for type
 *		type		The type of property block we need
 *
 *	Global variables used:
 */
Property
get_prop(register Property start, register Property_id type)
{
	for (; start != NULL; start = start->next) {
		if (start->type == type) {
			return start;
		}
	}
	return NULL;
}

/*
 *	append_string(from, to, length)
 *
 *	Append a C string to a make string expanding it if nessecary
 *
 *	Parameters:
 *		from		The source (C style) string
 *		to		The destination (make style) string
 *		length		The length of the from string
 *
 *	Global variables used:
 */
void
append_string(register wchar_t *from, register String to, register int length)
{
	if (length == FIND_LENGTH) {
		length = wcslen(from);
	}
	if (to->buffer.start == NULL) {
		expand_string(to, 32 + length);
	}
	if (to->buffer.end - to->text.p <= length) {
		expand_string(to,
			      (to->buffer.end - to->buffer.start) * 2 +
			      length);
	}
	if (length > 0) {
		(void) wcsncpy(to->text.p, from, length);
		to->text.p += length;
	}
	*(to->text.p) = (int) nul_char;
}

wchar_t * get_wstring(char *from) {
	if(from == NULL) {
		return NULL;
	}
	getwstring_count++;
	wchar_t * wcbuf = ALLOC_WC(strlen(from) + 1);
	mbstowcs(wcbuf, from, strlen(from)+1);
	return wcbuf;
}

void
append_string(register char *from, register String to, register int length)
{
	if (length == FIND_LENGTH) {
		length = strlen(from);
	}
	if (to->buffer.start == NULL) {
		expand_string(to, 32 + length);
	}
	if (to->buffer.end - to->text.p <= length) {
		expand_string(to,
			      (to->buffer.end - to->buffer.start) * 2 +
			      length);
	}
	if (length > 0) {
		(void) mbstowcs(to->text.p, from, length);
		to->text.p += length;
	}
	*(to->text.p) = (int) nul_char;
}

/*
 *	expand_string(string, length)
 *
 *	Allocate more memory for strings that run out of space.
 *
 *	Parameters:
 *		string		The make style string we want to expand
 *		length		The new length we need
 *
 *	Global variables used:
 */
static void
expand_string(register String string, register int length)
{
	register wchar_t	*p;

	if (string->buffer.start == NULL) {
		/* For strings that have no memory allocated */
		string->buffer.start =
		  string->text.p =
		    string->text.end =
		      ALLOC_WC(length);
		string->buffer.end = string->buffer.start + length;
		string->text.p[0] = (int) nul_char;
		string->free_after_use = true;
		expandstring_count++;
		return;
	}
	if (string->buffer.end - string->buffer.start >= length) {
		/* If we really don't need more memory. */
		return;
	}
	/*
	 * Get more memory, copy the string and free the old buffer if
	 * it is was malloc()'ed.
	 */
	expandstring_count++;
	p = ALLOC_WC(length);
	(void) wcscpy(p, string->buffer.start);
	string->text.p = p + (string->text.p - string->buffer.start);
	string->text.end = p + (string->text.end - string->buffer.start);
	string->buffer.end = p + length;
	if (string->free_after_use) {
		retmem(string->buffer.start);
	}
	string->buffer.start = p;
	string->free_after_use = true;
}

/*
 *	append_char(from, to)
 *
 *	Append one char to a make string expanding it if nessecary
 *
 *	Parameters:
 *		from		Single character to append to string
 *		to		The destination (make style) string
 *
 *	Global variables used:
 */
void
append_char(wchar_t from, register String to)
{
	if (to->buffer.start == NULL) {
		expand_string(to, 32);
	}
	if (to->buffer.end - to->text.p <= 2) {
		expand_string(to, to->buffer.end - to->buffer.start + 32);
	}
	*(to->text.p)++ = from;
	*(to->text.p) = (int) nul_char;
}

/*
 *	handle_interrupt_mksh()
 *
 *	This is where C-C traps are caught.
 */
void
handle_interrupt_mksh(int)
{
	(void) fflush(stdout);
	/* Make sure the processes running under us terminate first. */
	if (childPid > 0) {
		kill(childPid, SIGTERM);
		childPid = -1;
	}
	while (wait((int *) NULL) != -1);
	exit_status = 2;
	exit(2);
}

/*
 *	setup_interrupt()
 *
 *	This routine saves the original interrupt handler pointers
 *
 *	Parameters:
 *
 *	Static variables used:
 *		sigivalue	The original signal handler
 *		sigqvalue	The original signal handler
 *		sigtvalue	The original signal handler
 *		sighvalue	The original signal handler
 */
void
setup_interrupt(register void (*handler) (int))
{
	sigivalue = bsd_signal(SIGINT, SIG_IGN);
	sigqvalue = bsd_signal(SIGQUIT, SIG_IGN);
	sigtvalue = bsd_signal(SIGTERM, SIG_IGN);
	sighvalue = bsd_signal(SIGHUP, SIG_IGN);
	enable_interrupt(handler);
}


void
mbstowcs_with_check(wchar_t *pwcs, const char *s, size_t n)
{
	if(mbstowcs(pwcs, s, n) == -1) {
		fatal_mksh(gettext("The string `%s' is not valid in current locale"), s);
	}
}



Wstring::Wstring()
{
	INIT_STRING_FROM_STACK(string, string_buf);
}

Wstring::Wstring(struct _Name * name)
{
	INIT_STRING_FROM_STACK(string, string_buf);
	append_string(name->string_mb, &string, name->hash.length);
}

Wstring::~Wstring()
{
	if(string.free_after_use) {
		retmem(string.buffer.start);
	}
}

void
Wstring::init(struct _Name * name)
{
	if(string.free_after_use) {
		retmem(string.buffer.start);
	}
	INIT_STRING_FROM_STACK(string, string_buf);
	append_string(name->string_mb, &string, name->hash.length);
}

void
Wstring::init(wchar_t * name, unsigned length)
{
	INIT_STRING_FROM_STACK(string, string_buf);
	append_string(name, &string, length);
	string.buffer.start[length] = 0;
}

Boolean
Wstring::equaln(wchar_t * str, unsigned length)
{
	return (Boolean)IS_WEQUALN(string.buffer.start, str, length);
}

Boolean
Wstring::equaln(Wstring * str, unsigned length)
{
	return (Boolean)IS_WEQUALN(string.buffer.start, str->string.buffer.start, length);
}

Boolean
Wstring::equal(wchar_t * str, unsigned off, unsigned length)
{
	return (Boolean)IS_WEQUALN(string.buffer.start + off, str, length);
}

Boolean
Wstring::equal(wchar_t * str, unsigned off)
{
	return (Boolean)IS_WEQUAL(string.buffer.start + off, str);
}

Boolean
Wstring::equal(wchar_t * str)
{
	return equal(str, 0);
}

Boolean
Wstring::equal(Wstring * str, unsigned off, unsigned length)
{
	return (Boolean)IS_WEQUALN(string.buffer.start + off, str->string.buffer.start, length);
}

Boolean
Wstring::equal(Wstring * str)
{
	return equal(str, 0);
}

Boolean
Wstring::equal(Wstring * str, unsigned off)
{
	return (Boolean)IS_WEQUAL(string.buffer.start + off, str->string.buffer.start);
}

void
Wstring::append_to_str(struct _String * str, unsigned off, unsigned length)
{
	append_string(string.buffer.start + off, str, length);
}

Name
Name_set::lookup(const char *key)
{
	for (entry *node = root; node != 0;) {
		int res = strcmp(key, node->name->string_mb);
		if (res < 0) {
			node = node->left;
		} else if (res > 0) {
			node = node->right;
		} else {
			return node->name;
		}
	}
	return 0;
}

Name
Name_set::insert(const char *key, Boolean &found)
{
	Name	name = 0;

	if (root != 0) {
		for (entry *node = root; name == 0;) {
			int res = strcmp(key, node->name->string_mb);
			if (res < 0) {
				if (node->left != 0) {
					node = node->left;
				} else {
					found = false;
					name = ALLOC(Name);

					node->left = new entry(name, node);
					rebalance(node);
				}
			} else if (res > 0) {
				if (node->right != 0) {
					node = node->right;
				} else {
					found = false;
					name = ALLOC(Name);

					node->right = new entry(name, node);
					rebalance(node);
				}
			} else {
				found = true;
				name = node->name;
			}
		}
	} else {
		found = false;
		name = ALLOC(Name);

		root = new entry(name, 0);
	}
	return name;
}

void
Name_set::insert(Name name) {
	if (root != 0) {
		for (entry *node = root;;) {
			int res = strcmp(name->string_mb, node->name->string_mb);
			if (res < 0) {
				if (node->left != 0) {
					node = node->left;
				} else {
					node->left = new entry(name, node);
					rebalance(node);
					break;
				}
			} else if (res > 0) {
				if (node->right != 0) {
					node = node->right;
				} else {
					node->right = new entry(name, node);
					rebalance(node);
					break;
				}
			} else {
				// should be an error: inserting already existing name
				break;
			}
		}
	} else {
		root = new entry(name, 0);
	}
}

void
Name_set::rebalance(Name_set::entry *node) {
	for (; node != 0; node = node->parent) {
		entry *right = node->right;
		entry *left = node->left;

		unsigned rdepth = (right != 0) ? right->depth : 0;
		unsigned ldepth = (left != 0) ? left->depth : 0;

		if (ldepth > rdepth + 1) {
			if ((node->left = left->right) != 0) {
				left->right->parent = node;
			}
			if ((left->parent = node->parent) != 0) {
				if (node == node->parent->right) {
					node->parent->right = left;
				} else {
					node->parent->left = left;
				}
			} else {
				root = left;
			}
			left->right = node;
			node->parent = left;

			node->setup_depth();
			node = left;
		} else if (rdepth > ldepth + 1) {
			if ((node->right = right->left) != 0) {
				right->left->parent = node;
			}
			if ((right->parent = node->parent) != 0) {
				if (node == node->parent->right) {
					node->parent->right = right;
				} else {
					node->parent->left = right;
				}
			} else {
				root = right;
			}
			right->left = node;
			node->parent = right;

			node->setup_depth();
			node = right;
		}
		node->setup_depth();
	}
}

Name_set::iterator
Name_set::begin() const {
	for (entry *node = root; node != 0; node = node->left) {
		if (node->left == 0) {
			return iterator(node);
		}
	}
	return iterator();
}

Name_set::iterator&
Name_set::iterator::operator++() {
	if (node != 0) {
		if (node->right != 0) {
			node = node->right;
			while (node->left != 0) {
				node = node->left;
			}
		} else {
			while ((node->parent != 0) && (node->parent->right == node)) {
				node = node->parent;
			}
			node = node->parent;
		}
	}
	return *this;
}
