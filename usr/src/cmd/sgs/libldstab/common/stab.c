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

/*
 * This file contains all functions relating to stab processing.  The
 * stab table is compressed by eliminating duplicate include file entries.
 */
#include <stdio.h>
#include <string.h>
#include <stab.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/param.h>
#include <errno.h>
#include <libintl.h>
#include "libld.h"
#include "msg.h"


/*
 * With the 5.x compiler, stab.h changed struct nlist into
 * struct stab and got rid of it's embeded unions.
 */
#if __SUNPRO_C >= 0x500 || defined(__GNUC__)
#define	nlist	stab
#else
#define	n_strx	n_un.n_strx
#endif


/*
 * Data structure that holds persistent data that sbfocus_symbol & sbfocus_close
 * needs. Passing in a pointer to this struct makes them re-entrant.
 */
typedef struct sbld_tag {
	FILE	*fd;
	int	failed;
} *Sbld, Sbld_rec;


extern Sbld_rec		sb_data;
extern const char	*out_fname, *in_fname;
extern Half 		out_e_type;
extern void		sbfocus_symbol(Sbld, const char *, const char *,
			    const char *);

#if	!defined(_ELF64)

/*
 * holds information needed by sbfocus_symbol and sbfocus_close.
 */
Sbld_rec	sb_data = { NULL, 0 };

/*
 * holds information out the output file being created.
 */
const char	*out_fname = NULL;
const char	*in_fname = NULL;	/* current input file */
Half 		out_e_type = ET_NONE;

/*
 *  Signal handler is called when a SIGPIPE is encountered.  This would
 *  happen in case `sbfocus' did not exist and `ld' is writing down a
 *  pipe with no reader.  Trap signal and set failed field so that no
 *  more subsequent writes occur.
 */
static void
sigpipe_handler()
{
	sb_data.failed = 1;
}

/*
 * sbfocus_symbol() will write one symbol to a pipe that has the program
 * "sbfocus" at the receiving end. If the program has not been started yet,
 * it is started, and the pipe established. "sbfocus" is started with the
 * function arguments "type" and "name" as its arguments, in that order.
 *
 * sbfocus_symbol() should be called with four arguments:
 *	data	Pointer to a Sbld struct that the caller has allocated in
 *		permanent storage. It must be the same struct for all related
 *		calls to sbfocus_symbol().
 *	name	This is the string name of the library/executable being built.
 *	type	A string, should be one of:
 *			"-x": Building an executable or shared object
 *			"-r": Concatenating object files
 *	symbol	The string that should be written to "sbfocus". If this
 *		argument is NULL "sbfocus" is started, but no symbol is
 *		written to it.
 */
void
sbfocus_symbol(Sbld data, const char *name, const char *type,
    const char *symbol)
{
	int	fd[2], err;

	if (data->failed) {
		return;
	}

	(void) signal(SIGPIPE, (void (*)(int)) sigpipe_handler);

	if (data->fd == NULL) {
		data->failed = 0;
		(void) pipe(fd);

		switch (fork()) {
		case -1:
			err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_FORK),
			    in_fname, strerror(err),
			    MSG_INTL(MSG_STAB_NOSBROW));
			data->failed = 1;
			(void) close(fd[0]);
			(void) close(fd[1]);
			return;

		/*
		 * Child process
		 */
		case 0:
			(void) close(fd[1]);
			(void) dup2(fd[0], fileno(stdin));
			(void) close(fd[0]);
			(void) execlp(MSG_ORIG(MSG_STR_SBFOCUS),
			    MSG_ORIG(MSG_STR_SBFOCUS), type, name, 0);

			err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_EXEC),
			    in_fname, MSG_ORIG(MSG_STR_SBFOCUS),
			    strerror(err), MSG_INTL(MSG_STAB_NOSBROW));
			exit(-1);

		/*
		 * Parent process
		 */
		default:
			(void) close(fd[0]);
			data->fd = fdopen(fd[1], MSG_ORIG(MSG_STR_W));
			break;
		}
	}
	if (symbol != NULL) {
		(void) fputs(symbol, data->fd);
		(void) putc('\n', data->fd);
	}
}
#endif /* !defined(_ELF64) */


static Xword
pass1_stabindex(const Elf_Data *s_data, const Elf_Data *str_data,
		const size_t cwd_len, const size_t name_len)
{
	struct nlist	*elem;
	struct nlist	*last = NULL;
	size_t		i;
	size_t		str_offset = 0;
	size_t		new_size = 0;
	size_t		first_object = 1;
	size_t		any_obj = 0;
	size_t		num_elem;
	/*
	 * The processing of the stab table happens in two passes.
	 *
	 * first pass: calculate if any change is needed and if so, how much
	 * the string table needs to be expanded by.
	 */
	num_elem = s_data->d_size / sizeof (struct nlist);
	for (i = 0; i < num_elem; i++) {
		char 	*str;

		elem = (struct nlist *)s_data->d_buf + i;
		switch (elem->n_type) {
		case 0:
			if (last)
				str_offset += last->n_value;
			last = elem;
			break;
		case N_OBJ:
			str = (char *)str_data->d_buf + str_offset +
			    elem->n_strx;

			if ((*str == '\0') && first_object) {
				/*
				 * This is a 'CWD' N_OBJ
				 *
				 * we only record the 'cwd' once in each
				 * stringtable.  so - we only need to add
				 * it's length once to the new_size
				 */
				if (any_obj == 0) {
					any_obj++;
					new_size += cwd_len + 1;
				} /* if */
				first_object = 0;
			} /* if */
			else if (*str == '\0') {
				/*
				 * This is a 'object_name' N_OBJ
				 */
				new_size += name_len + 1;
				first_object = 1;
			} /* else if */
			break;
		default:
			/* no-op */
			break;
		} /* switch */
	} /* for */
	/*LINTED*/
	return ((Xword) new_size);
} /* pass1_stabindex */


static int
pass2_stabindex(Elf_Data *s_data, Elf_Data *str_data, const char *name,
		size_t name_len, size_t cwd_pos, size_t free_pos)
{
	struct nlist	*elem;
	struct nlist	*last = NULL;
	size_t		i;
	size_t		str_offset = 0;
	size_t		first_object = 1;
	size_t		num_elem;
	/*
	 * The processing of the stab table happens in two passes.
	 *
	 * first pass: calculate if any change is needed and if so, how much
	 * the string table needs to be expanded by.
	 */
	num_elem = s_data->d_size / sizeof (struct nlist);
	for (i = 0; i < num_elem; i++) {
		char 	*str;

		elem = (struct nlist *)s_data->d_buf + i;
		switch (elem->n_type) {
		case 0:
			if (last)
				str_offset += last->n_value;
			last = elem;
			break;
		case N_OBJ:
			str = (char *)str_data->d_buf + str_offset +
			    elem->n_strx;

			if ((*str == '\0') && first_object) {
				/*
				 * This is a 'CWD' N_OBJ
				 *
				 * We point it at the CWD entry that we've
				 * already placed in the new string_table.
				 */
				/*LINTED*/
				elem->n_strx = (unsigned)(cwd_pos - str_offset);
				first_object = 0;
			} /* if */
			else if (*str == '\0') {
				/*
				 * This is a 'object_name' N_OBJ.
				 *
				 * Append the object name to the string table
				 * and set the elem->n_un.n_strx to point
				 * to it.
				 */
				(void) strcpy((char *)str_data->d_buf +
				    free_pos, name);
				/*LINTED*/
				elem->n_strx = (unsigned)(free_pos -
				    str_offset);
				free_pos += name_len + 1;
				first_object = 1;
			} /* if */
			break;
		default:
			break;
		} /* switch */
	} /* for */

	/*LINTED*/
	last->n_value = (unsigned)(str_data->d_size - str_offset);

	return (1);
} /* pass2_stabindex() */


/*
 * find_scn()
 *
 *	Find a section in elf that matches the supplied section name,
 *	type, and flags.
 *
 * Returns:
 *		section number if found
 *		 0 - if no matching section found
 *		-1 - if error
 *
 *	If shdr is a non-null pointer it will be set to the section header
 *	that was found.
 */
static size_t
find_scn(Elf *elf, const char *elf_strtab, const char *name,
	const Word sh_type, const Xword sh_flags, Elf_Scn **ret_scn)
{
	Elf_Scn		*scn = NULL;
	Shdr		*scn_shdr;

	while ((scn = elf_nextscn(elf, scn)) != 0) {
		if ((scn_shdr = elf_getshdr(scn)) == NULL)
			return ((size_t)-1);
		if ((scn_shdr->sh_type == sh_type) &&
		    (scn_shdr->sh_flags == sh_flags) &&
		    (strcmp(elf_strtab + scn_shdr->sh_name, name) == 0)) {
			size_t scn_ndx;
			/*
			 * we've got a match
			 */
			if ((scn_ndx = elf_ndxscn(scn)) == SHN_UNDEF)
				return ((size_t)-1);
			if (ret_scn)
				*ret_scn = scn;
			return (scn_ndx);
		} /* if */
	} /* while */

	/*
	 * no match found
	 */
	return (0);
} /* find_scn() */


static Elf_Data *
get_str_data(Elf *elf, const char *strtab, const char *name, Shdr *shdr)
{
	Elf_Scn		*str_scn;
	Elf_Data	*str_data;

	/*
	 * The stab's string table can be found through the
	 * shdr->sh_link value.
	 */
	if (shdr->sh_link == 0) {
		/*
		 * Normally the sh_link field should point to the
		 * required strtab.  But if it's not filled in (which
		 * means something goofed somewhere) we will try to look
		 * it up from the elf file itself.
		 */
		size_t	strscn_ndx;

		strscn_ndx = find_scn(elf, strtab, name, SHT_STRTAB,
		    shdr->sh_flags, &str_scn);
		if (strscn_ndx == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_STAB_MISTBL),
			    in_fname);
			return ((Elf_Data *)S_ERROR);
		} else if (strscn_ndx == (size_t)-1) {
			(void) fprintf(stderr, MSG_INTL(MSG_STAB_BADTBL),
			    in_fname);
			return ((Elf_Data *)S_ERROR);
		}
	} else {
		if ((str_scn = elf_getscn(elf, shdr->sh_link)) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETSCN),
			    in_fname, elf_errmsg(0));
			return ((Elf_Data *)S_ERROR);
		}
	}

	if ((str_data = elf_getdata(str_scn, NULL)) == NULL) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETDATA), in_fname,
		    elf_errmsg(0));
		return ((Elf_Data *)S_ERROR);
	}

	return (str_data);
}




/*
 * We examine all the stab's looking for pairs of N_OBJ's who's
 * string pointers (elem->n_un.n_strx) points to a null string.
 * When we find a pair we set the first string pointing to the
 * CWD and we set the second string to the file object name (*name).
 *
 * The stab's string table will have to be expanded to hold
 * these new enties.
 */
static void
process_stabindex(Elf *elf, const char *elf_strtab, const char *strtab_name,
    Shdr *shdr, Elf_Data *s_data)
{
	Elf_Data	*str_data;
	static char	*cwd = NULL;
	static size_t 	cwd_len;
	size_t 		new_size;
	size_t 		cwd_pos;
	size_t 		name_len;
	Elf_Void	*data;

	if ((str_data = get_str_data(elf, elf_strtab, strtab_name,
	    shdr)) == (Elf_Data *)S_ERROR)
		return;

	if (cwd == NULL) {
		if ((cwd = getcwd(NULL, MAXPATHLEN)) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_GETCWD),
			    in_fname, strerror(errno));
			return;
		}
		cwd_len = strlen(cwd);
	}
	name_len = strlen(in_fname);

	new_size = pass1_stabindex(s_data, str_data, cwd_len, name_len);

	if (new_size == 0)
		/* no changes are needed */
		return;
	/*
	 * The .stab.index data buffer must be updated so a new copy is
	 * allocated.  The original is read-only.
	 */
	if ((data = malloc(s_data->d_size)) == 0)
		return;
	(void) memcpy(data, s_data->d_buf, s_data->d_size);
	s_data->d_buf = data;

	/*
	 * Allocate a new .stab.indexstr that is big enough to hold the new
	 * entries that we will need to place into it.
	 *
	 * Then append the 'cwd' onto the end of the current data.
	 */
	if ((data = malloc(str_data->d_size + new_size)) == 0)
		return;
	(void) memcpy(data, str_data->d_buf, str_data->d_size);
	cwd_pos = str_data->d_size;
	(void) strcpy((char *)data + cwd_pos, cwd);
	str_data->d_buf = data;
	str_data->d_size = str_data->d_size + new_size;

	(void) pass2_stabindex(s_data, str_data, in_fname, name_len, cwd_pos,
	    cwd_pos + cwd_len + 1);
}


static void
process_stabsbfocus(Elf *elf, const char *elf_strtab,
    const char *strtab_name, Shdr *shdr, Elf_Data *s_data,
    const char *out_name, Half etype)
{
	Elf_Data	*str_data;
	struct nlist	*elem, *last = NULL;
	size_t		i, str_offset = 0, num_elem;

	if ((str_data = get_str_data(elf, elf_strtab, strtab_name,
	    shdr)) == (Elf_Data *)S_ERROR)
		return;

	num_elem = s_data->d_size / sizeof (struct nlist);
	for (i = 0; i < num_elem; i++) {
		const char	*type, *str;

		elem = (struct nlist *)s_data->d_buf + i;
		switch (elem->n_type) {
		case 0:
			if (last)
				str_offset += last->n_value;
			last = elem;
			break;
		case N_BROWS:
			str = (char *)str_data->d_buf + elem->n_strx +
			    str_offset;
			if (etype == ET_REL)
				type = MSG_ORIG(MSG_STR_DASHR);
			else
				type = MSG_ORIG(MSG_STR_DASHX);
			sbfocus_symbol(&sb_data, out_name, type, str);
			break;
		default:
			/* no-op */
			break;
		}
	}
}


/* ARGSUSED2 */
void
#if	defined(_ELF64)
ld_start64(const char *out_name, const Half etype, const char *caller)
#else
ld_start(const char *out_name, const Half etype, const char *caller)
#endif
{
	out_fname = out_name;
	out_e_type = etype;
}


/* ARGSUSED1 */
void
#if	defined(_ELF64)
ld_file64(const char *name, const Elf_Kind kind, int flags, Elf *elf)
#else
ld_file(const char *name, const Elf_Kind kind, int flags, Elf *elf)
#endif
{
	in_fname = name;
}


/*
 * ld_section()
 *
 * Args:
 *	name	- pointer to name of current section being processed.
 *	shdr	- pointer to Section Header of current in-file being
 *		  processed.
 *	s_data	- pointer to Section Data structure of current in-file
 *		  being processed.
 *	elf	- pointer to elf structure for current in-file being
 *		  processed
 */
/* ARGSUSED2 */
void
#if	defined(_ELF64)
ld_section64(const char *scn_name, Shdr *shdr, Word scnndx,
#else
ld_section(const char *scn_name, Shdr *shdr, Word scnndx,
#endif
	Elf_Data *s_data, Elf *elf)
{
	Ehdr		*ehdr;
	Elf_Data	*str_data;
	Elf_Scn		*str_scn;
	char		*strtab;

	ehdr = elf_getehdr(elf);
	if ((ehdr->e_type != ET_DYN) && (shdr->sh_type == SHT_PROGBITS)) {
		/*
		 * this is a minor optimization for speed.  If it's not a
		 * stab string we aren't going to strcmp() it.
		 */
		if ((scn_name[1] == 's') &&
		    (scn_name[2] == 't') &&
		    (scn_name[3] == 'a') &&
		    (scn_name[4] == 'b')) {
			Word	shstrndx;

			/*
			 * If 'extended sections' are in use, then
			 *	e_shstrndx == Shdr[0].sh_link
			 */
			if (ehdr->e_shstrndx == SHN_XINDEX) {
				Elf_Scn	*scn0;
				Shdr	*shdr0;
				scn0 = elf_getscn(elf, 0);
				shdr0 = elf_getshdr(scn0);
				shstrndx = shdr0->sh_link;
			} else
				shstrndx = ehdr->e_shstrndx;

			str_scn = elf_getscn(elf, shstrndx);
			str_data = elf_getdata(str_scn, NULL);
			strtab = str_data->d_buf;

			if (strcmp(scn_name, MSG_ORIG(MSG_SCN_STAB)) == 0) {
				/*
				 * Process .stab
				 */
				process_stabsbfocus(elf, strtab,
				    MSG_ORIG(MSG_SCN_STABSTR), shdr,
				    s_data, out_fname, out_e_type);
			} else if (strcmp(scn_name,
			    MSG_ORIG(MSG_SCN_STABINDEX)) == 0) {
				/*
				 * Process .stab.index
				 */
				process_stabindex(elf, strtab,
				    MSG_ORIG(MSG_SCN_STABINDEXSTR), shdr,
				    s_data);
			} else if (strcmp(scn_name,
			    MSG_ORIG(MSG_SCN_STABSBFOCUS)) == 0) {
				/*
				 * Process .stab.sbfocus
				 */
				process_stabsbfocus(elf, strtab,
				    MSG_ORIG(MSG_SCN_STABSBFOCUSTR), shdr,
				    s_data, out_fname, out_e_type);
			}
		}
	}
}

/*
 * Null atexit() routine, causes dlsym() to pass and thus no dlerror() message
 * generation.
 */
/* ARGSUSED */
void
#if	defined(_ELF64)
ld_atexit64(int status)
#else
ld_atexit(int status)
#endif
{
}

#if	!defined(_ELF64)
/*
 * Messaging support - funnel everything through dgettext().
 */

const char *
_libldstab_msg(Msg mid)
{
	return (dgettext(MSG_ORIG(MSG_SUNW_OST_SGS), MSG_ORIG(mid)));
}
#endif
