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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Dump an elf file.
 */
#include	<sys/param.h>
#include	<fcntl.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<libelf.h>
#include	<link.h>
#include	<stdarg.h>
#include	<unistd.h>
#include	<libgen.h>
#include	<libintl.h>
#include	<locale.h>
#include	<errno.h>
#include	<strings.h>
#include	<debug.h>
#include	<conv.h>
#include	<msg.h>
#include	<_elfdump.h>

const Cache	cache_init = {NULL, NULL, NULL, NULL, 0};



/* MATCH is  used to retain information about -N and -I options */
typedef enum {
	MATCH_T_NAME,		/* Record contains a name */
	MATCH_T_NDX,		/* Record contains a single index */
	MATCH_T_RANGE		/* Record contains an index range */
} MATCH_T;

typedef struct _match {
	struct _match	*next;		/* Pointer to next item in list */
	MATCH_T		type;
	union {
		const char	*name;	/* MATCH_T_NAME */
		struct {		/* MATCH_T_NDX and MATCH_T_RANGE */
			int	start;
			int	end;	/* Only for MATCH_T_RANGE */
		} ndx;
	} value;
} MATCH;

/* List of MATCH records used by match() to implement -N and -I options */
static MATCH *match_list = NULL;

const char *
_elfdump_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}

/*
 * Determine whether a symbol name should be demangled.
 */
const char *
demangle(const char *name, uint_t flags)
{
	if (flags & FLG_DEMANGLE)
		return (Elf_demangle_name(name));
	else
		return ((char *)name);
}

/*
 * Define our own standard error routine.
 */
void
failure(const char *file, const char *func)
{
	(void) fprintf(stderr, MSG_INTL(MSG_ERR_FAILURE),
	    file, func, elf_errmsg(elf_errno()));
}

/*
 * The full usage message
 */
static void
detail_usage()
{
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL1));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL2));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL3));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL4));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL5));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL6));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL7));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL8));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL9));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL10));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL11));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL12));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL13));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL14));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL15));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL16));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL17));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL18));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL19));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL20));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL21));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL22));
	(void) fprintf(stderr, MSG_INTL(MSG_USAGE_DETAIL23));
}

/*
 * Convert the ASCII representation of an index, or index range, into
 * binary form, and store it in rec:
 *
 *	index: An positive or 0 valued integer
 *	range: Two indexes, separated by a ':' character, denoting
 *		a range of allowed values. If the second value is omitted,
 *		any values equal to or greater than the first will match.
 *
 * exit:
 *	On success, *rec is filled in with a MATCH_T_NDX or MATCH_T_RANGE
 *	value, and this function returns (1). On failure, the contents
 *	of *rec are undefined, and (0) is returned.
 */
int
process_index_opt(const char *str, MATCH *rec)
{
#define	SKIP_BLANK for (; *str && isspace(*str); str++)

	char	*endptr;

	rec->value.ndx.start = strtol(str, &endptr, 10);
	/* Value must use some of the input, and be 0 or positive */
	if ((str == endptr) || (rec->value.ndx.start < 0))
		return (0);
	str = endptr;

	SKIP_BLANK;
	if (*str != ':') {
		rec->type = MATCH_T_NDX;
	} else {
		str++;					/* Skip the ':' */
		rec->type = MATCH_T_RANGE;
		SKIP_BLANK;
		if (*str == '\0') {
			rec->value.ndx.end = -1;	/* Indicates "to end" */
		} else {
			rec->value.ndx.end = strtol(str, &endptr, 10);
			if ((str == endptr) || (rec->value.ndx.end < 0))
				return (0);
			str = endptr;
			SKIP_BLANK;
		}
	}

	/* Syntax error if anything is left over */
	if (*str != '\0')
		return (0);

	return (1);

#undef	SKIP_BLANK
}

/*
 * Returns True (1) if the item with the given name or index should
 * be displayed, and False (0) if it should not be.
 *
 * entry:
 *	strict - A strict match requires an explicit match to
 *		a user specified -I or -N option. A non-strict match
 *		succeeds if the match list is empty.
 *	name - Name of item under consideration, or NULL if the name
 *		should not be considered.
 *	ndx - if (ndx >= 0) index of item under consideration.
 *		A negative value indicates that the item has no index.
 *
 * exit:
 *	True will be returned if the given name/index matches those given
 *	by one of the -N or -I command line options, or if no such option
 *	was used in the command invocation.
 */
int
match(int strict, const char *name, int ndx)
{
	MATCH *list;

	/* If no match options were specified, allow everything */
	if (!strict && (match_list == NULL))
		return (1);

	/* Run through the match records and check for a hit */
	for (list = match_list; list; list = list->next) {
		switch (list->type) {
		case MATCH_T_NAME:
			if ((name != NULL) &&
			    (strcmp(list->value.name, name) == 0))
				return (1);
			break;
		case MATCH_T_NDX:
			if (ndx == list->value.ndx.start)
				return (1);
			break;
		case MATCH_T_RANGE:
			/*
			 * A range end value less than 0 means that any value
			 * above the start is acceptible.
			 */
			if ((ndx >= list->value.ndx.start) &&
			    ((list->value.ndx.end < 0) ||
			    (ndx <= list->value.ndx.end)))
				return (1);
			break;
		}
	}

	/* Nothing matched */
	return (0);
}

/*
 * Add an entry to match_list for use by match().
 *
 * Return True (1) for success. On failure, an error is written
 * to stderr, and False (0) is returned.
 */
static int
add_match_record(char *argv0, MATCH *data)
{
	MATCH *rec;
	MATCH *list;

	if ((rec = malloc(sizeof (*rec))) == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_MALLOC),
		    basename(argv0), strerror(err));
		return (0);
	}

	*rec = *data;

	/* Insert at end of match_list */
	if (match_list == NULL) {
		match_list = rec;
	} else {
		for (list = match_list; list->next != NULL; list = list->next)
			;
		list->next = rec;
	}

	rec->next = NULL;
	return (1);
}

static void
decide(const char *file, Elf *elf, uint_t flags, int wfd)
{
	if (gelf_getclass(elf) == ELFCLASS64)
		regular64(file, elf, flags, wfd);
	else
		regular32(file, elf, flags, wfd);
}

static void
archive(const char *file, int fd, Elf *elf, uint_t flags, int wfd)
{
	Elf_Cmd		cmd = ELF_C_READ;
	Elf_Arhdr	*arhdr;
	Elf		*_elf = 0;
	size_t		ptr;
	Elf_Arsym	*arsym = 0;

	/*
	 * Determine if the archive symbol table itself is required.
	 */
	if ((flags & FLG_SYMBOLS) && match(0, MSG_ORIG(MSG_ELF_ARSYM), -1)) {
		/*
		 * Get the archive symbol table.
		 */
		if (((arsym = elf_getarsym(elf, &ptr)) == 0) && elf_errno()) {
			/*
			 * The arsym could be 0 even though there was no error.
			 * Print the error message only when there was
			 * real error from elf_getarsym().
			 */
			failure(file, MSG_ORIG(MSG_ELF_GETARSYM));
			return;
		}
	}

	/*
	 * Print the archive symbol table only when the archive symbol
	 * table exists and it was requested to print.
	 */
	if (arsym) {
		size_t		cnt;
		char		index[MAXNDXSIZE];
		size_t		offset = 0, _offset = 0;

		/*
		 * Print out all the symbol entries.
		 */
		dbg_print(0, MSG_INTL(MSG_ARCHIVE_SYMTAB));
		dbg_print(0, MSG_INTL(MSG_ARCHIVE_FIELDS));

		for (cnt = 0; cnt < ptr; cnt++, arsym++) {
			/*
			 * For each object obtain an elf descriptor so that we
			 * can establish the members name.  Note, we have had
			 * archives where the archive header has not been
			 * obtainable so be lenient with errors.
			 */
			if ((offset == 0) || ((arsym->as_off != 0) &&
			    (arsym->as_off != _offset))) {

				if (_elf)
					(void) elf_end(_elf);

				if (elf_rand(elf, arsym->as_off) !=
				    arsym->as_off) {
					failure(file, MSG_ORIG(MSG_ELF_RAND));
					arhdr = 0;
				} else if ((_elf = elf_begin(fd,
				    ELF_C_READ, elf)) == 0) {
					failure(file, MSG_ORIG(MSG_ELF_BEGIN));
					arhdr = 0;
				} else if ((arhdr = elf_getarhdr(_elf)) == 0) {
					failure(file,
					    MSG_ORIG(MSG_ELF_GETARHDR));
					arhdr = 0;
				}

				_offset = arsym->as_off;
				if (offset == 0)
					offset = _offset;
			}

			(void) snprintf(index, MAXNDXSIZE,
			    MSG_ORIG(MSG_FMT_INDEX), EC_XWORD(cnt));
			if (arsym->as_off)
				dbg_print(0, MSG_ORIG(MSG_FMT_ARSYM1), index,
				    /* LINTED */
				    (int)arsym->as_off, arhdr ? arhdr->ar_name :
				    MSG_INTL(MSG_STR_UNKNOWN), (arsym->as_name ?
				    demangle(arsym->as_name, flags) :
				    MSG_INTL(MSG_STR_NULL)));
			else
				dbg_print(0, MSG_ORIG(MSG_FMT_ARSYM2), index,
				    /* LINTED */
				    (int)arsym->as_off);
		}

		if (_elf)
			(void) elf_end(_elf);

		/*
		 * If we only need the archive symbol table return.
		 */
		if ((flags & FLG_SYMBOLS) &&
		    match(1, MSG_ORIG(MSG_ELF_ARSYM), -1))
			return;

		/*
		 * Reset elf descriptor in preparation for processing each
		 * member.
		 */
		if (offset)
			(void) elf_rand(elf, offset);
	}

	/*
	 * Process each object within the archive.
	 */
	while ((_elf = elf_begin(fd, cmd, elf)) != NULL) {
		char	name[MAXPATHLEN];

		if ((arhdr = elf_getarhdr(_elf)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_GETARHDR));
			return;
		}
		if (*arhdr->ar_name != '/') {
			(void) snprintf(name, MAXPATHLEN,
			    MSG_ORIG(MSG_FMT_ARNAME), file, arhdr->ar_name);
			dbg_print(0, MSG_ORIG(MSG_FMT_NLSTR), name);

			switch (elf_kind(_elf)) {
			case ELF_K_AR:
				archive(name, fd, _elf, flags, wfd);
				break;
			case ELF_K_ELF:
				decide(name, _elf, flags, wfd);
				break;
			default:
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_BADFILE), name);
				break;
			}
		}

		cmd = elf_next(_elf);
		(void) elf_end(_elf);
	}
}

int
main(int argc, char **argv, char **envp)
{
	Elf		*elf;
	int		var, fd, wfd = 0;
	char		*wname = 0;
	uint_t		flags = 0;
	MATCH		match_data;

	/*
	 * If we're on a 64-bit kernel, try to exec a full 64-bit version of
	 * the binary.  If successful, conv_check_native() won't return.
	 */
	(void) conv_check_native(argv, envp);

	/*
	 * Establish locale.
	 */
	(void) setlocale(LC_MESSAGES, MSG_ORIG(MSG_STR_EMPTY));
	(void) textdomain(MSG_ORIG(MSG_SUNW_OST_SGS));

	(void) setvbuf(stdout, NULL, _IOLBF, 0);
	(void) setvbuf(stderr, NULL, _IOLBF, 0);

	opterr = 0;
	while ((var = getopt(argc, argv, MSG_ORIG(MSG_STR_OPTIONS))) != EOF) {
		switch (var) {
		case 'C':
			flags |= FLG_DEMANGLE;
			break;
		case 'c':
			flags |= FLG_SHDR;
			break;
		case 'd':
			flags |= FLG_DYNAMIC;
			break;
		case 'e':
			flags |= FLG_EHDR;
			break;
		case 'G':
			flags |= FLG_GOT;
			break;
		case 'g':
			flags |= FLG_GROUP;
			break;
		case 'H':
			flags |= FLG_CAP;
			break;
		case 'h':
			flags |= FLG_HASH;
			break;
		case 'I':
			if (!process_index_opt(optarg, &match_data)) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_USAGE_BRIEF),
				    basename(argv[0]));
				return (1);
			}
			if (!add_match_record(argv[0], &match_data))
				return (1);
			break;
		case 'i':
			flags |= FLG_INTERP;
			break;
		case 'k':
			flags |= FLG_CHECKSUM;
			break;
		case 'l':
			flags |= FLG_LONGNAME;
			break;
		case 'm':
			flags |= FLG_MOVE;
			break;
		case 'N':
			match_data.type = MATCH_T_NAME;
			match_data.value.name = optarg;
			if (!add_match_record(argv[0], &match_data))
				return (1);
			break;
		case 'n':
			flags |= FLG_NOTE;
			break;
		case 'p':
			flags |= FLG_PHDR;
			break;
		case 'r':
			flags |= FLG_RELOC;
			break;
		case 'S':
			flags |= FLG_SORT;
			break;
		case 's':
			flags |= FLG_SYMBOLS;
			break;
		case 'u':
			flags |= FLG_UNWIND;
			break;
		case 'v':
			flags |= FLG_VERSIONS;
			break;
		case 'w':
			wname = optarg;
			break;
		case 'y':
			flags |= FLG_SYMINFO;
			break;
		case '?':
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF),
			    basename(argv[0]));
			detail_usage();
			return (1);
		default:
			break;
		}
	}

	/*
	 * Validate any arguments.
	 */
	if ((flags & ~(FLG_DEMANGLE | FLG_LONGNAME)) == 0) {
		if (!wname && (match_list == NULL)) {
			flags |= FLG_EVERYTHING;
		} else if (!wname || (match_list == NULL)) {
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF),
			    basename(argv[0]));
			return (1);
		}
	}

	if ((var = argc - optind) == 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_USAGE_BRIEF),
		    basename(argv[0]));
		return (1);
	}

	/*
	 * If the -l/-C option is specified, set up the liblddbg.so.
	 */
	if (flags & FLG_LONGNAME)
		dbg_desc->d_extra |= DBG_E_LONG;
	if (flags & FLG_DEMANGLE)
		dbg_desc->d_extra |= DBG_E_DEMANGLE;

	/*
	 * If the -w option has indicated an output file open it.  It's
	 * arguable whether this option has much use when multiple files are
	 * being processed.
	 */
	if (wname) {
		if ((wfd = open(wname, (O_RDWR | O_CREAT | O_TRUNC),
		    0666)) < 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_OPEN),
			    wname, strerror(err));
			wfd = 0;
		}
	}

	/*
	 * Open the input file and initialize the elf interface.
	 */
	for (; optind < argc; optind++) {
		const char	*file = argv[optind];

		if ((fd = open(argv[optind], O_RDONLY)) == -1) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_OPEN),
			    file, strerror(err));
			continue;
		}
		(void) elf_version(EV_CURRENT);
		if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
			failure(file, MSG_ORIG(MSG_ELF_BEGIN));
			(void) close(fd);
			continue;
		}

		if (var > 1)
			dbg_print(0, MSG_ORIG(MSG_FMT_NLSTRNL), file);

		switch (elf_kind(elf)) {
		case ELF_K_AR:
			archive(file, fd, elf, flags, wfd);
			break;
		case ELF_K_ELF:
			decide(file, elf, flags, wfd);
			break;
		default:
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_BADFILE), file);
			break;
		}

		(void) close(fd);
		(void) elf_end(elf);
	}

	if (wfd)
		(void) close(wfd);
	return (0);
}
