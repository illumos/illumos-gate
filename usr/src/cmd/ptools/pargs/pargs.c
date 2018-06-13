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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * pargs examines and prints the arguments (argv), environment (environ),
 * and auxiliary vector of another process.
 *
 * This utility is made more complex because it must run in internationalized
 * environments.  The two key cases for pargs to manage are:
 *
 * 1. pargs and target run in the same locale: pargs must respect the
 * locale, but this case is straightforward.  Care is taken to correctly
 * use wide characters in order to print results properly.
 *
 * 2. pargs and target run in different locales: in this case, pargs examines
 * the string having assumed the victim's locale.  Unprintable (but valid)
 * characters are escaped.  Next, iconv(3c) is used to convert between the
 * target and pargs codeset.  Finally, a second pass to escape unprintable
 * (but valid) characters is made.
 *
 * In any case in which characters are encountered which are not valid in
 * their purported locale, the string "fails" and is treated as a traditional
 * 7-bit ASCII encoded string, and escaped accordingly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <wchar.h>
#include <iconv.h>
#include <langinfo.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/auxv.h>
#include <sys/archsystm.h>
#include <sys/proc.h>
#include <sys/elf.h>
#include <libproc.h>
#include <wctype.h>
#include <widec.h>
#include <elfcap.h>

typedef struct pargs_data {
	struct ps_prochandle *pd_proc;	/* target proc handle */
	psinfo_t *pd_psinfo;		/* target psinfo */
	char *pd_locale;		/* target process locale */
	int pd_conv_flags;		/* flags governing string conversion */
	iconv_t pd_iconv;		/* iconv conversion descriptor */
	size_t pd_argc;
	uintptr_t *pd_argv;
	char **pd_argv_strs;
	size_t pd_envc;
	size_t pd_env_space;
	uintptr_t *pd_envp;
	char **pd_envp_strs;
	size_t pd_auxc;
	auxv_t *pd_auxv;
	char **pd_auxv_strs;
	char *pd_execname;
} pargs_data_t;

#define	CONV_USE_ICONV		0x01
#define	CONV_STRICT_ASCII	0x02

static char *command;
static int dmodel;

#define	EXTRACT_BUFSZ 128		/* extract_string() initial size */
#define	ENV_CHUNK 16			/* #env ptrs to read at a time */

static jmp_buf env;			/* malloc failure handling */

static void *
safe_zalloc(size_t size)
{
	void *p;

	/*
	 * If the malloc fails we longjmp out to allow the code to Prelease()
	 * a stopped victim if needed.
	 */
	if ((p = malloc(size)) == NULL) {
		longjmp(env, errno);
	}

	bzero(p, size);
	return (p);
}

static char *
safe_strdup(const char *s1)
{
	char	*s2;

	s2 = safe_zalloc(strlen(s1) + 1);
	(void) strcpy(s2, s1);
	return (s2);
}

/*
 * Given a wchar_t which might represent an 'escapable' sequence (see
 * formats(5)), return the base ascii character needed to print that
 * sequence.
 *
 * The comparisons performed may look suspect at first, but all are valid;
 * the characters below all appear in the "Portable Character Set."  The
 * Single Unix Spec says: "The wide-character value for each member of the
 * Portable Character Set will equal its value when used as the lone
 * character in an integer character constant."
 */
static uchar_t
get_interp_char(wchar_t wc)
{
	switch (wc) {
	case L'\a':
		return ('a');
	case L'\b':
		return ('b');
	case L'\f':
		return ('f');
	case L'\n':
		return ('n');
	case L'\r':
		return ('r');
	case L'\t':
		return ('t');
	case L'\v':
		return ('v');
	case L'\\':
		return ('\\');
	}
	return ('\0');
}

static char *
unctrl_str_strict_ascii(const char *src, int escape_slash, int *unprintable)
{
	uchar_t *uc, *ucp, c, ic;
	uc = ucp = safe_zalloc((strlen(src) * 4) + 1);
	while ((c = *src++) != '\0') {
		/*
		 * Call get_interp_char *first*, since \ will otherwise not
		 * be escaped as \\.
		 */
		if ((ic = get_interp_char((wchar_t)c)) != '\0') {
			if (escape_slash || ic != '\\')
				*ucp++ = '\\';
			*ucp++ = ic;
		} else if (isascii(c) && isprint(c)) {
			*ucp++ = c;
		} else {
			*ucp++ = '\\';
			*ucp++ = ((c >> 6) & 7) + '0';
			*ucp++ = ((c >> 3) & 7) + '0';
			*ucp++ = (c & 7) + '0';
			*unprintable = 1;
		}
	}
	*ucp = '\0';
	return ((char *)uc);
}

/*
 * Convert control characters as described in format(5) to their readable
 * representation; special care is taken to handle multibyte character sets.
 *
 * If escape_slash is true, escaping of '\' occurs.  The first time a string
 * is unctrl'd, this should be '1'.  Subsequent iterations over the same
 * string should set escape_slash to 0.  Otherwise you'll wind up with
 * \ --> \\ --> \\\\.
 */
static char *
unctrl_str(const char *src, int escape_slash, int *unprintable)
{
	wchar_t wc;
	wchar_t *wide_src, *wide_srcp;
	wchar_t *wide_dest, *wide_destp;
	char *uc;
	size_t srcbufsz = strlen(src) + 1;
	size_t destbufsz = srcbufsz * 4;
	size_t srclen, destlen;

	wide_srcp = wide_src = safe_zalloc(srcbufsz * sizeof (wchar_t));
	wide_destp = wide_dest = safe_zalloc(destbufsz * sizeof (wchar_t));

	if ((srclen = mbstowcs(wide_src, src, srcbufsz - 1)) == (size_t)-1) {
		/*
		 * We can't trust the string, since in the locale in which
		 * this call is operating, the string contains an invalid
		 * multibyte sequence.  There isn't much to do here, so
		 * convert the string byte by byte to wide characters, as
		 * if it came from a C locale (char) string.  This isn't
		 * perfect, but at least the characters will make it to
		 * the screen.
		 */
		free(wide_src);
		free(wide_dest);
		return (unctrl_str_strict_ascii(src, escape_slash,
		    unprintable));
	}
	if (srclen == (srcbufsz - 1)) {
		wide_src[srclen] = L'\0';
	}

	while ((wc = *wide_srcp++) != L'\0') {
		char cvt_buf[MB_LEN_MAX];
		int len, i;
		char c = get_interp_char(wc);

		if ((c != '\0') && (escape_slash || c != '\\')) {
			/*
			 * Print "interpreted version" (\n, \a, etc).
			 */
			*wide_destp++ = L'\\';
			*wide_destp++ = (wchar_t)c;
			continue;
		}

		if (iswprint(wc)) {
			*wide_destp++ = wc;
			continue;
		}

		/*
		 * Convert the wide char back into (potentially several)
		 * multibyte characters, then escape out each of those bytes.
		 */
		bzero(cvt_buf, sizeof (cvt_buf));
		if ((len = wctomb(cvt_buf, wc)) == -1) {
			/*
			 * This is a totally invalid wide char; discard it.
			 */
			continue;
		}
		for (i = 0; i < len; i++) {
			uchar_t c = cvt_buf[i];
			*wide_destp++ = L'\\';
			*wide_destp++ = (wchar_t)('0' + ((c >> 6) & 7));
			*wide_destp++ = (wchar_t)('0' + ((c >> 3) & 7));
			*wide_destp++ = (wchar_t)('0' + (c & 7));
			*unprintable = 1;
		}
	}

	*wide_destp = '\0';
	destlen = (wide_destp - wide_dest) * MB_CUR_MAX + 1;
	uc = safe_zalloc(destlen);
	if (wcstombs(uc, wide_dest, destlen) == (size_t)-1) {
		/* If we've gotten this far, wcstombs shouldn't fail... */
		(void) fprintf(stderr, "%s: wcstombs failed unexpectedly: %s\n",
		    command, strerror(errno));
		exit(1);
	} else {
		char *tmp;
		/*
		 * Try to save memory; don't waste 3 * strlen in the
		 * common case.
		 */
		tmp = safe_strdup(uc);
		free(uc);
		uc = tmp;
	}
	free(wide_dest);
	free(wide_src);
	return (uc);
}

/*
 * These functions determine which characters are safe to be left unquoted.
 * Rather than starting with every printable character and subtracting out the
 * shell metacharacters, we take the more conservative approach of starting with
 * a set of safe characters and adding those few common punctuation characters
 * which are known to be safe.  The rules are:
 *
 *	If this is a printable character (graph), and not punctuation, it is
 *	safe to leave unquoted.
 *
 *	If it's one of the known hard-coded safe characters, it's also safe to
 *	leave unquoted.
 *
 *	Otherwise, the entire argument must be quoted.
 *
 * This will cause some strings to be unnecessarily quoted, but it is safer than
 * having a character unintentionally interpreted by the shell.
 */
static int
issafe_ascii(char c)
{
	return (isalnum(c) || strchr("_.-/@:,", c) != NULL);
}

static int
issafe(wchar_t wc)
{
	return ((iswgraph(wc) && !iswpunct(wc)) ||
	    wschr(L"_.-/@:,", wc) != NULL);
}

/*ARGSUSED*/
static char *
quote_string_ascii(pargs_data_t *datap, char *src)
{
	char *dst;
	int quote_count = 0;
	int need_quote = 0;
	char *srcp, *dstp;
	size_t dstlen;

	for (srcp = src; *srcp != '\0'; srcp++) {
		if (!issafe_ascii(*srcp)) {
			need_quote = 1;
			if (*srcp == '\'')
				quote_count++;
		}
	}

	if (!need_quote)
		return (src);

	/*
	 * The only character we care about here is a single quote.  All the
	 * other unprintable characters (and backslashes) will have been dealt
	 * with by unctrl_str().  We make the following subtitution when we
	 * encounter a single quote:
	 *
	 *	' = '"'"'
	 *
	 * In addition, we put single quotes around the entire argument.  For
	 * example:
	 *
	 *	foo'bar = 'foo'"'"'bar'
	 */
	dstlen = strlen(src) + 3 + 4 * quote_count;
	dst = safe_zalloc(dstlen);

	dstp = dst;
	*dstp++ = '\'';
	for (srcp = src; *srcp != '\0'; srcp++, dstp++) {
		*dstp = *srcp;

		if (*srcp == '\'') {
			dstp[1] = '"';
			dstp[2] = '\'';
			dstp[3] = '"';
			dstp[4] = '\'';
			dstp += 4;
		}
	}
	*dstp++ = '\'';
	*dstp = '\0';

	free(src);

	return (dst);
}

static char *
quote_string(pargs_data_t *datap, char *src)
{
	wchar_t *wide_src, *wide_srcp;
	wchar_t *wide_dest, *wide_destp;
	char *uc;
	size_t srcbufsz = strlen(src) + 1;
	size_t srclen;
	size_t destbufsz;
	size_t destlen;
	int quote_count = 0;
	int need_quote = 0;

	if (datap->pd_conv_flags & CONV_STRICT_ASCII)
		return (quote_string_ascii(datap, src));

	wide_srcp = wide_src = safe_zalloc(srcbufsz * sizeof (wchar_t));

	if ((srclen = mbstowcs(wide_src, src, srcbufsz - 1)) == (size_t)-1) {
		free(wide_src);
		return (quote_string_ascii(datap, src));
	}

	if (srclen == srcbufsz - 1)
		wide_src[srclen] = L'\0';

	for (wide_srcp = wide_src; *wide_srcp != '\0'; wide_srcp++) {
		if (!issafe(*wide_srcp)) {
			need_quote = 1;
			if (*wide_srcp == L'\'')
				quote_count++;
		}
	}

	if (!need_quote) {
		free(wide_src);
		return (src);
	}

	/*
	 * See comment for quote_string_ascii(), above.
	 */
	destbufsz = srcbufsz + 3 + 4 * quote_count;
	wide_destp = wide_dest = safe_zalloc(destbufsz * sizeof (wchar_t));

	*wide_destp++ = L'\'';
	for (wide_srcp = wide_src; *wide_srcp != L'\0';
	    wide_srcp++, wide_destp++) {
		*wide_destp = *wide_srcp;

		if (*wide_srcp == L'\'') {
			wide_destp[1] = L'"';
			wide_destp[2] = L'\'';
			wide_destp[3] = L'"';
			wide_destp[4] = L'\'';
			wide_destp += 4;
		}
	}
	*wide_destp++ = L'\'';
	*wide_destp = L'\0';

	destlen = destbufsz * MB_CUR_MAX + 1;
	uc = safe_zalloc(destlen);
	if (wcstombs(uc, wide_dest, destlen) == (size_t)-1) {
		/* If we've gotten this far, wcstombs shouldn't fail... */
		(void) fprintf(stderr, "%s: wcstombs failed unexpectedly: %s\n",
		    command, strerror(errno));
		exit(1);
	}

	free(wide_dest);
	free(wide_src);

	return (uc);
}


/*
 * Determine the locale of the target process by traversing its environment,
 * making only one pass for efficiency's sake; stash the result in
 * datap->pd_locale.
 *
 * It's possible that the process has called setlocale() to change its
 * locale to something different, but we mostly care about making a good
 * guess as to the locale at exec(2) time.
 */
static void
lookup_locale(pargs_data_t *datap)
{
	int i, j, composite = 0;
	size_t	len = 0;
	char	*pd_locale;
	char	*lc_all = NULL, *lang = NULL;
	char	*lcs[] = { NULL, NULL, NULL, NULL, NULL, NULL };
	static const char *cat_names[] = {
		"LC_CTYPE=",	"LC_NUMERIC=",	"LC_TIME=",
		"LC_COLLATE=",	"LC_MONETARY=",	"LC_MESSAGES="
	};

	for (i = 0; i < datap->pd_envc; i++) {
		char *s = datap->pd_envp_strs[i];

		if (s == NULL)
			continue;

		if (strncmp("LC_ALL=", s, strlen("LC_ALL=")) == 0) {
			/*
			 * Minor optimization-- if we find LC_ALL we're done.
			 */
			lc_all = s + strlen("LC_ALL=");
			break;
		}
		for (j = 0; j <= _LastCategory; j++) {
			if (strncmp(cat_names[j], s,
			    strlen(cat_names[j])) == 0) {
				lcs[j] = s + strlen(cat_names[j]);
			}
		}
		if (strncmp("LANG=", s, strlen("LANG=")) == 0) {
			lang = s + strlen("LANG=");
		}
	}

	if (lc_all && (*lc_all == '\0'))
		lc_all = NULL;
	if (lang && (*lang == '\0'))
		lang = NULL;

	for (i = 0; i <= _LastCategory; i++) {
		if (lc_all != NULL) {
			lcs[i] = lc_all;
		} else if (lcs[i] != NULL) {
			lcs[i] = lcs[i];
		} else if (lang != NULL) {
			lcs[i] = lang;
		} else {
			lcs[i] = "C";
		}
		if ((i > 0) && (lcs[i] != lcs[i-1]))
			composite++;

		len += 1 + strlen(lcs[i]);	/* 1 extra byte for '/' */
	}

	if (composite == 0) {
		/* simple locale */
		pd_locale = safe_strdup(lcs[0]);
	} else {
		/* composite locale */
		pd_locale = safe_zalloc(len + 1);
		(void) snprintf(pd_locale, len + 1, "/%s/%s/%s/%s/%s/%s",
		    lcs[0], lcs[1], lcs[2], lcs[3], lcs[4], lcs[5]);
	}
	datap->pd_locale = pd_locale;
}

/*
 * Pull a string from the victim, regardless of size; this routine allocates
 * memory for the string which must be freed by the caller.
 */
static char *
extract_string(pargs_data_t *datap, uintptr_t addr)
{
	int size = EXTRACT_BUFSZ;
	char *result;

	result = safe_zalloc(size);

	for (;;) {
		if (Pread_string(datap->pd_proc, result, size, addr) < 0) {
			free(result);
			return (NULL);
		} else if (strlen(result) == (size - 1)) {
			free(result);
			size *= 2;
			result = safe_zalloc(size);
		} else {
			break;
		}
	}
	return (result);
}

/*
 * Utility function to read an array of pointers from the victim, adjusting
 * for victim data model; returns the number of bytes successfully read.
 */
static ssize_t
read_ptr_array(pargs_data_t *datap, uintptr_t offset, uintptr_t *buf,
    size_t nelems)
{
	ssize_t res;

	if (dmodel == PR_MODEL_NATIVE) {
		res = Pread(datap->pd_proc, buf, nelems * sizeof (uintptr_t),
		    offset);
	} else {
		int i;
		uint32_t *arr32 = safe_zalloc(nelems * sizeof (uint32_t));

		res = Pread(datap->pd_proc, arr32, nelems * sizeof (uint32_t),
		    offset);
		if (res > 0) {
			for (i = 0; i < nelems; i++)
				buf[i] = arr32[i];
		}
		free(arr32);
	}
	return (res);
}

/*
 * Extract the argv array from the victim; store the pointer values in
 * datap->pd_argv and the extracted strings in datap->pd_argv_strs.
 */
static void
get_args(pargs_data_t *datap)
{
	size_t argc = datap->pd_psinfo->pr_argc;
	uintptr_t argvoff = datap->pd_psinfo->pr_argv;
	int i;

	datap->pd_argc = argc;
	datap->pd_argv = safe_zalloc(argc * sizeof (uintptr_t));

	if (read_ptr_array(datap, argvoff, datap->pd_argv, argc) <= 0) {
		free(datap->pd_argv);
		datap->pd_argv = NULL;
		return;
	}

	datap->pd_argv_strs = safe_zalloc(argc * sizeof (char *));
	for (i = 0; i < argc; i++) {
		if (datap->pd_argv[i] == 0)
			continue;
		datap->pd_argv_strs[i] = extract_string(datap,
		    datap->pd_argv[i]);
	}
}

/*ARGSUSED*/
static int
build_env(void *data, struct ps_prochandle *pr, uintptr_t addr, const char *str)
{
	pargs_data_t *datap = data;

	if (datap->pd_envp != NULL) {
		if (datap->pd_envc == datap->pd_env_space) {
			/*
			 * Not enough space for storing the env (it has more
			 * items than before).  Try to grow both arrays.
			 */
			void *new = realloc(datap->pd_envp,
			    sizeof (uintptr_t) * datap->pd_env_space * 2);
			if (new == NULL)
				return (1);
			datap->pd_envp = new;

			new = realloc(datap->pd_envp_strs,
			    sizeof (char *) * datap->pd_env_space * 2);
			if (new == NULL)
				return (1);
			datap->pd_envp_strs = new;

			datap->pd_env_space *= 2;
		}

		datap->pd_envp[datap->pd_envc] = addr;
		if (str == NULL)
			datap->pd_envp_strs[datap->pd_envc] = NULL;
		else
			datap->pd_envp_strs[datap->pd_envc] = strdup(str);
	}

	datap->pd_envc++;

	return (0);
}

static void
get_env(pargs_data_t *datap)
{
	struct ps_prochandle *pr = datap->pd_proc;

	datap->pd_envc = 0;
	(void) Penv_iter(pr, build_env, datap);

	/* We must allocate space for at least one entry */
	datap->pd_env_space = datap->pd_envc != 0 ? datap->pd_envc : 1;
	datap->pd_envp = safe_zalloc(sizeof (uintptr_t) * datap->pd_env_space);
	datap->pd_envp_strs =
	    safe_zalloc(sizeof (char *) * datap->pd_env_space);

	datap->pd_envc = 0;
	(void) Penv_iter(pr, build_env, datap);
}

/*
 * The following at_* routines are used to decode data from the aux vector.
 */

/*ARGSUSED*/
static void
at_null(long val, char *instr, size_t n, char *str)
{
	str[0] = '\0';
}

/*ARGSUSED*/
static void
at_str(long val, char *instr, size_t n, char *str)
{
	str[0] = '\0';
	if (instr != NULL) {
		(void) strlcpy(str, instr, n);
	}
}

/*
 * Note: Don't forget to add a corresponding case to isainfo(1).
 */

#define	FMT_AV(s, n, hwcap, mask, name)				\
	if ((hwcap) & (mask))					\
		(void) snprintf(s, n, "%s" name " | ", s)

/*ARGSUSED*/
static void
at_hwcap(long val, char *instr, size_t n, char *str)
{
#if defined(__sparc) || defined(__sparcv9)
	(void) elfcap_hw1_to_str(ELFCAP_STYLE_UC, val, str, n,
	    ELFCAP_FMT_PIPSPACE, EM_SPARC);

#elif defined(__i386) || defined(__amd64)
	(void) elfcap_hw1_to_str(ELFCAP_STYLE_UC, val, str, n,
	    ELFCAP_FMT_PIPSPACE, EM_386);
#else
#error	"port me"
#endif
}

/*ARGSUSED*/
static void
at_hwcap2(long val, char *instr, size_t n, char *str)
{
#if defined(__sparc) || defined(__sparcv9)
	(void) elfcap_hw2_to_str(ELFCAP_STYLE_UC, val, str, n,
	    ELFCAP_FMT_PIPSPACE, EM_SPARC);

#elif defined(__i386) || defined(__amd64)
	(void) elfcap_hw2_to_str(ELFCAP_STYLE_UC, val, str, n,
	    ELFCAP_FMT_PIPSPACE, EM_386);
#else
#error	"port me"
#endif
}


/*ARGSUSED*/
static void
at_uid(long val, char *instr, size_t n, char *str)
{
	struct passwd *pw = getpwuid((uid_t)val);

	if ((pw == NULL) || (pw->pw_name == NULL))
		str[0] = '\0';
	else
		(void) snprintf(str, n, "%lu(%s)", val, pw->pw_name);
}


/*ARGSUSED*/
static void
at_gid(long val, char *instr, size_t n, char *str)
{
	struct group *gr = getgrgid((gid_t)val);

	if ((gr == NULL) || (gr->gr_name == NULL))
		str[0] = '\0';
	else
		(void) snprintf(str, n, "%lu(%s)", val, gr->gr_name);
}

static struct auxfl {
	int af_flag;
	const char *af_name;
} auxfl[] = {
	{ AF_SUN_SETUGID,	"setugid" },
};

/*ARGSUSED*/
static void
at_flags(long val, char *instr, size_t n, char *str)
{
	int i;

	*str = '\0';

	for (i = 0; i < sizeof (auxfl)/sizeof (struct auxfl); i++) {
		if ((val & auxfl[i].af_flag) != 0) {
			if (*str != '\0')
				(void) strlcat(str, ",", n);
			(void) strlcat(str, auxfl[i].af_name, n);
		}
	}
}

#define	MAX_AT_NAME_LEN	15

struct aux_id {
	int aux_type;
	const char *aux_name;
	void (*aux_decode)(long, char *, size_t, char *);
};

static struct aux_id aux_arr[] = {
	{ AT_NULL,		"AT_NULL",		at_null	},
	{ AT_IGNORE,		"AT_IGNORE",		at_null	},
	{ AT_EXECFD,		"AT_EXECFD",		at_null	},
	{ AT_PHDR,		"AT_PHDR",		at_null	},
	{ AT_PHENT,		"AT_PHENT",		at_null	},
	{ AT_PHNUM,		"AT_PHNUM",		at_null	},
	{ AT_PAGESZ,		"AT_PAGESZ",		at_null	},
	{ AT_BASE,		"AT_BASE",		at_null	},
	{ AT_FLAGS,		"AT_FLAGS",		at_null	},
	{ AT_ENTRY,		"AT_ENTRY",		at_null	},
	{ AT_SUN_UID,		"AT_SUN_UID",		at_uid	},
	{ AT_SUN_RUID,		"AT_SUN_RUID",		at_uid	},
	{ AT_SUN_GID,		"AT_SUN_GID",		at_gid	},
	{ AT_SUN_RGID,		"AT_SUN_RGID",		at_gid	},
	{ AT_SUN_LDELF,		"AT_SUN_LDELF",		at_null	},
	{ AT_SUN_LDSHDR,	"AT_SUN_LDSHDR",	at_null	},
	{ AT_SUN_LDNAME,	"AT_SUN_LDNAME",	at_null	},
	{ AT_SUN_LPAGESZ,	"AT_SUN_LPAGESZ",	at_null	},
	{ AT_SUN_PLATFORM,	"AT_SUN_PLATFORM",	at_str	},
	{ AT_SUN_EXECNAME,	"AT_SUN_EXECNAME",	at_str	},
	{ AT_SUN_HWCAP,		"AT_SUN_HWCAP",		at_hwcap },
	{ AT_SUN_HWCAP2,	"AT_SUN_HWCAP2",	at_hwcap2 },
	{ AT_SUN_IFLUSH,	"AT_SUN_IFLUSH",	at_null	},
	{ AT_SUN_CPU,		"AT_SUN_CPU",		at_null	},
	{ AT_SUN_MMU,		"AT_SUN_MMU",		at_null	},
	{ AT_SUN_LDDATA,	"AT_SUN_LDDATA",	at_null	},
	{ AT_SUN_AUXFLAGS,	"AT_SUN_AUXFLAGS",	at_flags },
	{ AT_SUN_EMULATOR,	"AT_SUN_EMULATOR",	at_str	},
	{ AT_SUN_BRANDNAME,	"AT_SUN_BRANDNAME",	at_str	},
	{ AT_SUN_BRAND_AUX1,	"AT_SUN_BRAND_AUX1",	at_null	},
	{ AT_SUN_BRAND_AUX2,	"AT_SUN_BRAND_AUX2",	at_null	},
	{ AT_SUN_BRAND_AUX3,	"AT_SUN_BRAND_AUX3",	at_null	},
	{ AT_SUN_COMMPAGE,	"AT_SUN_COMMPAGE",	at_null	},
	{ AT_SUN_FPTYPE,	"AT_SUN_FPTYPE",	at_null },
	{ AT_SUN_FPSIZE,	"AT_SUN_FPSIZE",	at_null }
};

#define	N_AT_ENTS (sizeof (aux_arr) / sizeof (struct aux_id))

/*
 * Return the aux_id entry for the given aux type; returns NULL if not found.
 */
static struct aux_id *
aux_find(int type)
{
	int i;

	for (i = 0; i < N_AT_ENTS; i++) {
		if (type == aux_arr[i].aux_type)
			return (&aux_arr[i]);
	}

	return (NULL);
}

static void
get_auxv(pargs_data_t *datap)
{
	int i;
	const auxv_t *auxvp;

	/*
	 * Fetch the aux vector from the target process.
	 */
	if (ps_pauxv(datap->pd_proc, &auxvp) != PS_OK)
		return;

	for (i = 0; auxvp[i].a_type != AT_NULL; i++)
		continue;

	datap->pd_auxc = i;
	datap->pd_auxv = safe_zalloc(i * sizeof (auxv_t));
	bcopy(auxvp, datap->pd_auxv, i * sizeof (auxv_t));

	datap->pd_auxv_strs = safe_zalloc(datap->pd_auxc * sizeof (char *));
	for (i = 0; i < datap->pd_auxc; i++) {
		struct aux_id *aux = aux_find(datap->pd_auxv[i].a_type);

		/*
		 * Grab strings for those entries which have a string-decoder.
		 */
		if ((aux != NULL) && (aux->aux_decode == at_str)) {
			datap->pd_auxv_strs[i] =
			    extract_string(datap, datap->pd_auxv[i].a_un.a_val);
		}
	}
}

/*
 * Prepare to convert characters in the victim's character set into user's
 * character set.
 */
static void
setup_conversions(pargs_data_t *datap, int *diflocale)
{
	char *mylocale = NULL, *mycharset = NULL;
	char *targetlocale = NULL, *targetcharset = NULL;

	mycharset = safe_strdup(nl_langinfo(CODESET));

	mylocale = setlocale(LC_CTYPE, NULL);
	if ((mylocale == NULL) || (strcmp(mylocale, "") == 0))
		mylocale = "C";
	mylocale = safe_strdup(mylocale);

	if (datap->pd_conv_flags & CONV_STRICT_ASCII)
		goto done;

	/*
	 * If the target's locale is "C" or "POSIX", go fast.
	 */
	if ((strcmp(datap->pd_locale, "C") == 0) ||
	    (strcmp(datap->pd_locale, "POSIX") == 0)) {
		datap->pd_conv_flags |= CONV_STRICT_ASCII;
		goto done;
	}

	/*
	 * Switch to the victim's locale, and discover its character set.
	 */
	if (setlocale(LC_ALL, datap->pd_locale) == NULL) {
		(void) fprintf(stderr,
		    "%s: Couldn't determine locale of target process.\n",
		    command);
		(void) fprintf(stderr,
		    "%s: Some strings may not be displayed properly.\n",
		    command);
		goto done;
	}

	/*
	 * Get LC_CTYPE part of target's locale, and its codeset.
	 */
	targetlocale = safe_strdup(setlocale(LC_CTYPE, NULL));
	targetcharset = safe_strdup(nl_langinfo(CODESET));

	/*
	 * Now go fully back to the pargs user's locale.
	 */
	(void) setlocale(LC_ALL, "");

	/*
	 * It's safe to bail here if the lc_ctype of the locales are the
	 * same-- we know that their encodings and characters sets are the same.
	 */
	if (strcmp(targetlocale, mylocale) == 0)
		goto done;

	*diflocale = 1;

	/*
	 * If the codeset of the victim matches our codeset then iconv need
	 * not be involved.
	 */
	if (strcmp(mycharset, targetcharset) == 0)
		goto done;

	if ((datap->pd_iconv = iconv_open(mycharset, targetcharset))
	    == (iconv_t)-1) {
		/*
		 * EINVAL indicates there was no conversion available
		 * from victim charset to mycharset
		 */
		if (errno != EINVAL) {
			(void) fprintf(stderr,
			    "%s: failed to initialize iconv: %s\n",
			    command, strerror(errno));
			exit(1);
		}
		datap->pd_conv_flags |= CONV_STRICT_ASCII;
	} else {
		datap->pd_conv_flags |= CONV_USE_ICONV;
	}
done:
	free(mycharset);
	free(mylocale);
	free(targetcharset);
	free(targetlocale);
}

static void
cleanup_conversions(pargs_data_t *datap)
{
	if (datap->pd_conv_flags & CONV_USE_ICONV) {
		(void) iconv_close(datap->pd_iconv);
	}
}

static char *
convert_run_iconv(pargs_data_t *datap, const char *str)
{
	size_t inleft, outleft, bufsz = 64;
	char *outstr, *outstrptr;
	const char *instrptr;

	for (;;) {
		outstrptr = outstr = safe_zalloc(bufsz + 1);
		outleft = bufsz;

		/*
		 * Generate the "initial shift state" sequence, placing that
		 * at the head of the string.
		 */
		inleft = 0;
		(void) iconv(datap->pd_iconv, NULL, &inleft,
		    &outstrptr, &outleft);

		inleft = strlen(str);
		instrptr = str;
		if (iconv(datap->pd_iconv, &instrptr, &inleft, &outstrptr,
		    &outleft) != (size_t)-1) {
			/*
			 * Outstr must be null terminated upon exit from
			 * iconv().
			 */
			*(outstr + (bufsz - outleft)) = '\0';
			break;
		} else if (errno == E2BIG) {
			bufsz *= 2;
			free(outstr);
		} else if ((errno == EILSEQ) || (errno == EINVAL)) {
			free(outstr);
			return (NULL);
		} else {
			/*
			 * iconv() could in theory return EBADF, but that
			 * shouldn't happen.
			 */
			(void) fprintf(stderr,
			    "%s: iconv(3C) failed unexpectedly: %s\n",
			    command, strerror(errno));

			exit(1);
		}
	}
	return (outstr);
}

/*
 * Returns a freshly allocated string converted to the local character set,
 * removed of unprintable characters.
 */
static char *
convert_str(pargs_data_t *datap, const char *str, int *unprintable)
{
	char *retstr, *tmp;

	if (datap->pd_conv_flags & CONV_STRICT_ASCII) {
		retstr = unctrl_str_strict_ascii(str, 1, unprintable);
		return (retstr);
	}

	if ((datap->pd_conv_flags & CONV_USE_ICONV) == 0) {
		/*
		 * If we aren't using iconv(), convert control chars in
		 * the string in pargs' locale, since that is the display
		 * locale.
		 */
		retstr = unctrl_str(str, 1, unprintable);
		return (retstr);
	}

	/*
	 * The logic here is a bit (ahem) tricky.  Start by converting
	 * unprintable characters *in the target's locale*.  This should
	 * eliminate a variety of unprintable or illegal characters-- in
	 * short, it should leave us with something which iconv() won't
	 * have trouble with.
	 *
	 * After allowing iconv to convert characters as needed, run unctrl
	 * again in pargs' locale-- This time to make sure that any
	 * characters which aren't printable according to the *current*
	 * locale (independent of the current codeset) get taken care of.
	 * Without this second stage, we might (for example) fail to
	 * properly handle characters converted into the 646 character set
	 * (which are 8-bits wide), but which must be displayed in the C
	 * locale (which uses 646, but whose printable characters are a
	 * subset of the 7-bit characters).
	 *
	 * Note that assuming the victim's locale using LC_ALL will be
	 * problematic when pargs' messages are internationalized in the
	 * future (and it calls textdomain(3C)).  In this case, any
	 * error message fprintf'd in unctrl_str() will be in the wrong
	 * LC_MESSAGES class.  We'll cross that bridge when we come to it.
	 */
	(void) setlocale(LC_ALL, datap->pd_locale);
	retstr = unctrl_str(str, 1, unprintable);
	(void) setlocale(LC_ALL, "");

	tmp = retstr;
	if ((retstr = convert_run_iconv(datap, retstr)) == NULL) {
		/*
		 * In this (rare but real) case, the iconv() failed even
		 * though we unctrl'd the string.  Treat the original string
		 * (str) as a C locale string and strip it that way.
		 */
		free(tmp);
		return (unctrl_str_strict_ascii(str, 0, unprintable));
	}

	free(tmp);
	tmp = retstr;
	/*
	 * Run unctrl_str, but make sure not to escape \ characters, which
	 * may have resulted from the first round of unctrl.
	 */
	retstr = unctrl_str(retstr, 0, unprintable);
	free(tmp);
	return (retstr);
}


static void
convert_array(pargs_data_t *datap, char **arr, size_t count, int *unprintable)
{
	int i;
	char *tmp;

	if (arr == NULL)
		return;

	for (i = 0; i < count; i++) {
		if ((tmp = arr[i]) == NULL)
			continue;
		arr[i] = convert_str(datap, arr[i], unprintable);
		free(tmp);
	}
}

/*
 * Free data allocated during the gathering phase.
 */
static void
free_data(pargs_data_t *datap)
{
	int i;

	for (i = 0; i < datap->pd_argc; i++)
		free(datap->pd_argv_strs[i]);
	free(datap->pd_argv);
	free(datap->pd_argv_strs);

	for (i = 0; i < datap->pd_envc; i++)
		free(datap->pd_envp_strs[i]);
	free(datap->pd_envp);
	free(datap->pd_envp_strs);

	for (i = 0; i < datap->pd_auxc; i++)
		free(datap->pd_auxv_strs[i]);
	free(datap->pd_auxv);
	free(datap->pd_auxv_strs);
}

static void
print_args(pargs_data_t *datap)
{
	int i;

	if (datap->pd_argv == NULL) {
		(void) fprintf(stderr, "%s: failed to read argv[]\n", command);
		return;
	}

	for (i = 0; i < datap->pd_argc; i++) {
		(void) printf("argv[%d]: ", i);
		if (datap->pd_argv[i] == NULL) {
			(void) printf("<NULL>\n");
		} else if (datap->pd_argv_strs[i] == NULL) {
			(void) printf("<0x%0*lx>\n",
			    (dmodel == PR_MODEL_LP64)? 16 : 8,
			    (long)datap->pd_argv[i]);
		} else {
			(void) printf("%s\n", datap->pd_argv_strs[i]);
		}
	}
}

static void
print_env(pargs_data_t *datap)
{
	int i;

	if (datap->pd_envp == NULL) {
		(void) fprintf(stderr, "%s: failed to read envp[]\n", command);
		return;
	}

	for (i = 0; i < datap->pd_envc; i++) {
		(void) printf("envp[%d]: ", i);
		if (datap->pd_envp[i] == 0) {
			break;
		} else if (datap->pd_envp_strs[i] == NULL) {
			(void) printf("<0x%0*lx>\n",
			    (dmodel == PR_MODEL_LP64)? 16 : 8,
			    (long)datap->pd_envp[i]);
		} else {
			(void) printf("%s\n", datap->pd_envp_strs[i]);
		}
	}
}

static int
print_cmdline(pargs_data_t *datap)
{
	int i;

	/*
	 * Go through and check to see if we have valid data.  If not, print
	 * an error message and bail.
	 */
	for (i = 0; i < datap->pd_argc; i++) {
		if (datap->pd_argv == NULL || datap->pd_argv[i] == NULL ||
		    datap->pd_argv_strs[i] == NULL) {
			(void) fprintf(stderr, "%s: target has corrupted "
			    "argument list\n", command);
			return (1);
		}

		datap->pd_argv_strs[i] =
		    quote_string(datap, datap->pd_argv_strs[i]);
	}

	if (datap->pd_execname == NULL) {
		(void) fprintf(stderr, "%s: cannot determine name of "
		    "executable\n", command);
		return (1);
	}

	(void) printf("%s ", datap->pd_execname);

	for (i = 1; i < datap->pd_argc; i++)
		(void) printf("%s ", datap->pd_argv_strs[i]);

	(void) printf("\n");

	return (0);
}

static void
print_auxv(pargs_data_t *datap)
{
	int i;
	const auxv_t *pa;

	/*
	 * Print the names and values of all the aux vector entries.
	 */
	for (i = 0; i < datap->pd_auxc; i++) {
		char type[32];
		char decode[PATH_MAX];
		struct aux_id *aux;
		long v;
		pa = &datap->pd_auxv[i];

		aux = aux_find(pa->a_type);
		v = (long)pa->a_un.a_val;

		if (aux != NULL) {
			/*
			 * Fetch aux vector type string and decoded
			 * representation of the value.
			 */
			(void) strlcpy(type, aux->aux_name, sizeof (type));
			aux->aux_decode(v, datap->pd_auxv_strs[i],
			    sizeof (decode), decode);
		} else {
			(void) snprintf(type, sizeof (type), "%d", pa->a_type);
			decode[0] = '\0';
		}

		(void) printf("%-*s 0x%0*lx %s\n", MAX_AT_NAME_LEN, type,
		    (dmodel == PR_MODEL_LP64)? 16 : 8, v, decode);
	}
}

int
main(int argc, char *argv[])
{
	int aflag = 0, cflag = 0, eflag = 0, xflag = 0, lflag = 0;
	int errflg = 0, retc = 0;
	int opt;
	int error = 1;
	core_content_t content = 0;

	(void) setlocale(LC_ALL, "");

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	while ((opt = getopt(argc, argv, "acelxF")) != EOF) {
		switch (opt) {
		case 'a':		/* show process arguments */
			content |= CC_CONTENT_STACK;
			aflag++;
			break;
		case 'c':		/* force 7-bit ascii */
			cflag++;
			break;
		case 'e':		/* show environment variables */
			content |= CC_CONTENT_STACK;
			eflag++;
			break;
		case 'l':
			lflag++;
			aflag++;	/* -l implies -a */
			break;
		case 'x':		/* show aux vector entries */
			xflag++;
			break;
		case 'F':
			/*
			 * Since we open the process read-only, there is no need
			 * for the -F flag.  It's a documented flag, so we
			 * consume it silently.
			 */
			break;
		default:
			errflg++;
			break;
		}
	}

	/* -a is the default if no options are specified */
	if ((aflag + eflag + xflag + lflag) == 0) {
		aflag++;
		content |= CC_CONTENT_STACK;
	}

	/* -l cannot be used with the -x or -e flags */
	if (lflag && (xflag || eflag)) {
		(void) fprintf(stderr, "-l is incompatible with -x and -e\n");
		errflg++;
	}

	argc -= optind;
	argv += optind;

	if (errflg || argc <= 0) {
		(void) fprintf(stderr,
		    "usage:  %s [-aceFlx] { pid | core } ...\n"
		    "  (show process arguments and environment)\n"
		    "  -a: show process arguments (default)\n"
		    "  -c: interpret characters as 7-bit ascii regardless of "
		    "locale\n"
		    "  -e: show environment variables\n"
		    "  -F: force grabbing of the target process\n"
		    "  -l: display arguments as command line\n"
		    "  -x: show aux vector entries\n", command);
		return (2);
	}

	while (argc-- > 0) {
		char *arg;
		int gret, r;
		psinfo_t psinfo;
		char *psargs_conv;
		struct ps_prochandle *Pr;
		pargs_data_t datap;
		char *info;
		size_t info_sz;
		int pstate;
		char execname[PATH_MAX];
		int unprintable;
		int diflocale;

		(void) fflush(stdout);
		arg = *argv++;

		/*
		 * Suppress extra blanks lines if we've encountered processes
		 * which can't be opened.
		 */
		if (error == 0) {
			(void) printf("\n");
		}
		error = 0;

		/*
		 * First grab just the psinfo information, in case this
		 * process is a zombie (in which case proc_arg_grab() will
		 * fail).  If so, print a nice message and continue.
		 */
		if (proc_arg_psinfo(arg, PR_ARG_ANY, &psinfo,
		    &gret) == -1) {
			(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
			    command, arg, Pgrab_error(gret));
			retc++;
			error = 1;
			continue;
		}

		if (psinfo.pr_nlwp == 0) {
			(void) printf("%d: <defunct>\n", (int)psinfo.pr_pid);
			continue;
		}

		/*
		 * If process is a "system" process (like pageout), just
		 * print its psargs and continue on.
		 */
		if (psinfo.pr_size == 0 && psinfo.pr_rssize == 0) {
			proc_unctrl_psinfo(&psinfo);
			if (!lflag)
				(void) printf("%d: ", (int)psinfo.pr_pid);
			(void) printf("%s\n", psinfo.pr_psargs);
			continue;
		}

		/*
		 * Open the process readonly, since we do not need to write to
		 * the control file.
		 */
		if ((Pr = proc_arg_grab(arg, PR_ARG_ANY, PGRAB_RDONLY,
		    &gret)) == NULL) {
			(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
			    command, arg, Pgrab_error(gret));
			retc++;
			error = 1;
			continue;
		}

		pstate = Pstate(Pr);

		if (pstate == PS_DEAD &&
		    (Pcontent(Pr) & content) != content) {
			(void) fprintf(stderr, "%s: core '%s' has "
			    "insufficient content\n", command, arg);
			retc++;
			continue;
		}

		/*
		 * If malloc() fails, we return here so that we can let go
		 * of the victim, restore our locale, print a message,
		 * then exit.
		 */
		if ((r = setjmp(env)) != 0) {
			Prelease(Pr, 0);
			(void) setlocale(LC_ALL, "");
			(void) fprintf(stderr, "%s: out of memory: %s\n",
			    command, strerror(r));
			return (1);
		}

		dmodel = Pstatus(Pr)->pr_dmodel;
		bzero(&datap, sizeof (datap));
		bcopy(Ppsinfo(Pr), &psinfo, sizeof (psinfo_t));
		datap.pd_proc = Pr;
		datap.pd_psinfo = &psinfo;

		if (cflag)
			datap.pd_conv_flags |= CONV_STRICT_ASCII;

		/*
		 * Strip control characters, then record process summary in
		 * a buffer, since we don't want to print anything out until
		 * after we release the process.
		 */

		/*
		 * The process is neither a system process nor defunct.
		 *
		 * Do printing and post-processing (like name lookups) after
		 * gathering the raw data from the process and releasing it.
		 * This way, we don't deadlock on (for example) name lookup
		 * if we grabbed the nscd and do 'pargs -x'.
		 *
		 * We always fetch the environment of the target, so that we
		 * can make an educated guess about its locale.
		 */
		get_env(&datap);
		if (aflag != 0)
			get_args(&datap);
		if (xflag != 0)
			get_auxv(&datap);

		/*
		 * If malloc() fails after this poiint, we return here to
		 * restore our locale and print a message.  If we don't
		 * reset this, we might erroneously try to Prelease a process
		 * twice.
		 */
		if ((r = setjmp(env)) != 0) {
			(void) setlocale(LC_ALL, "");
			(void) fprintf(stderr, "%s: out of memory: %s\n",
			    command, strerror(r));
			return (1);
		}

		/*
		 * For the -l option, we need a proper name for this executable
		 * before we release it.
		 */
		if (lflag)
			datap.pd_execname = Pexecname(Pr, execname,
			    sizeof (execname));

		Prelease(Pr, 0);

		/*
		 * Crawl through the environment to determine the locale of
		 * the target.
		 */
		lookup_locale(&datap);
		diflocale = 0;
		setup_conversions(&datap, &diflocale);

		if (lflag != 0) {
			unprintable = 0;
			convert_array(&datap, datap.pd_argv_strs,
			    datap.pd_argc, &unprintable);
			if (diflocale)
				(void) fprintf(stderr, "%s: Warning, target "
				    "locale differs from current locale\n",
				    command);
			else if (unprintable)
				(void) fprintf(stderr, "%s: Warning, command "
				    "line contains unprintable characters\n",
				    command);

			retc += print_cmdline(&datap);
		} else {
			psargs_conv = convert_str(&datap, psinfo.pr_psargs,
			    &unprintable);
			info_sz = strlen(psargs_conv) + MAXPATHLEN + 32 + 1;
			info = malloc(info_sz);
			if (pstate == PS_DEAD) {
				(void) snprintf(info, info_sz,
				    "core '%s' of %d:\t%s\n",
				    arg, (int)psinfo.pr_pid, psargs_conv);
			} else {
				(void) snprintf(info, info_sz, "%d:\t%s\n",
				    (int)psinfo.pr_pid, psargs_conv);
			}
			(void) printf("%s", info);
			free(info);
			free(psargs_conv);

			if (aflag != 0) {
				convert_array(&datap, datap.pd_argv_strs,
				    datap.pd_argc, &unprintable);
				print_args(&datap);
				if (eflag || xflag)
					(void) printf("\n");
			}

			if (eflag != 0) {
				convert_array(&datap, datap.pd_envp_strs,
				    datap.pd_envc, &unprintable);
				print_env(&datap);
				if (xflag)
					(void) printf("\n");
			}

			if (xflag != 0) {
				convert_array(&datap, datap.pd_auxv_strs,
				    datap.pd_auxc, &unprintable);
				print_auxv(&datap);
			}
		}

		cleanup_conversions(&datap);
		free_data(&datap);
	}

	return (retc != 0 ? 1 : 0);
}
