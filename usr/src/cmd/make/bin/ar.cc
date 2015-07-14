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
 *	ar.c
 *
 *	Deal with the lib.a(member.o) and lib.a((entry-point)) notations
 *
 * Look inside archives for notations a(b) and a((b))
 *	a(b)	is file member   b  in archive a
 *	a((b))	is entry point   b  in object archive a
 *
 * For 6.0, create a make which can understand all archive
 * formats.  This is kind of tricky, and <ar.h> isnt any help.
 */

/*
 * Included files
 */
#include <alloca.h>		/* alloca() */
#include <ar.h>
#include <errno.h>		/* errno */
#include <fcntl.h>		/* open() */
#include <libintl.h>
#include <mk/defs.h>
#include <mksh/misc.h>		/* retmem_mb() */

struct ranlib {
	union {
		off_t	ran_strx;	/* string table index of */
		char	*ran_name;	/* symbol defined by */
	}	ran_un;
	off_t	ran_off;		/* library member at this offset */
};

#include <unistd.h>		/* close() */


/*
 * Defined macros
 */
#ifndef S5EMUL
#undef BITSPERBYTE
#define BITSPERBYTE	8
#endif

/*
 * Defines for all the different archive formats.  See next comment
 * block for justification for not using <ar.h>s versions.
 */
#define AR_5_MAGIC		"<ar>"		/* 5.0 format magic string */
#define AR_5_MAGIC_LENGTH	4		/* 5.0 format string length */

#define AR_PORT_MAGIC		"!<arch>\n"	/* Port. (6.0) magic string */
#define AR_PORT_MAGIC_LENGTH	8		/* Port. (6.0) string length */
#define AR_PORT_END_MAGIC	"`\n"		/* Port. (6.0) end of header */
#define AR_PORT_WORD		4		/* Port. (6.0) 'word' length */

/*
 * typedefs & structs
 */
/*
 * These are the archive file headers for the formats.  Note
 * that it really doesnt matter if these structures are defined
 * here.  They are correct as of the respective archive format
 * releases.  If the archive format is changed, then since backwards
 * compatability is the desired behavior, a new structure is added
 * to the list.
 */
typedef struct {	/* 5.0 ar header format: vax family; 3b family */
	char			ar_magic[AR_5_MAGIC_LENGTH];	/* AR_5_MAGIC*/
	char			ar_name[16];	/* Space terminated */
	char			ar_date[AR_PORT_WORD];	/* sgetl() accessed */
	char			ar_syms[AR_PORT_WORD];	/* sgetl() accessed */
}			Arh_5;

typedef struct {	/* 5.0 ar symbol format: vax family; 3b family */
	char			sym_name[8];	/* Space terminated */
	char			sym_ptr[AR_PORT_WORD];	/* sgetl() accessed */
}			Ars_5;

typedef struct {	/* 5.0 ar member format: vax family; 3b family */
	char			arf_name[16];	/* Space terminated */
	char			arf_date[AR_PORT_WORD];	/* sgetl() accessed */
	char			arf_uid[AR_PORT_WORD];	/* sgetl() accessed */
	char			arf_gid[AR_PORT_WORD];	/* sgetl() accessed */
	char			arf_mode[AR_PORT_WORD];	/* sgetl() accessed */
	char			arf_size[AR_PORT_WORD];	/* sgetl() accessed */
}			Arf_5;

typedef struct {	/* Portable (6.0) ar format: vax family; 3b family */
	char			ar_name[16];	/* Space terminated */
	/* left-adjusted fields; decimal ascii; blank filled */
	char			ar_date[12];	
	char			ar_uid[6];
	char			ar_gid[6];
	char			ar_mode[8];	/* octal ascii */
	char			ar_size[10];
	/* special end-of-header string (AR_PORT_END_MAGIC) */
	char			ar_fmag[2];	
}			Ar_port;

enum ar_type {
		AR_5,
		AR_PORT
};

typedef unsigned int ar_port_word; // must be 4-bytes long

typedef struct {
	FILE			*fd;
	/* to distiguish ar format */
	enum ar_type		type;
	/* where first ar member header is at */
	long			first_ar_mem;
	/* where the symbol lookup starts */
	long			sym_begin;
	/* the number of symbols available */
	long			num_symbols;
	/* length of symbol directory file */
	long			sym_size;
	Arh_5			arh_5;
	Ars_5			ars_5;
	Arf_5			arf_5;
	Ar_port			ar_port;
}			Ar;

/*
 * Static variables
 */

/*
 * File table of contents
 */
extern	timestruc_t&	read_archive(register Name target);
static	Boolean		open_archive(char *filename, register Ar *arp);
static	void		close_archive(register Ar *arp);
static	Boolean		read_archive_dir(register Ar *arp, Name library, char **long_names_table);
static	void		translate_entry(register Ar *arp, Name target, register Property member, char **long_names_table);
static	long		sgetl(char *);

/*
 *	read_archive(target)
 *
 *	Read the contents of an ar file.
 *
 *	Return value:
 *				The time the member was created
 *
 *	Parameters:
 *		target		The member to find time for
 *
 *	Global variables used:
 *		empty_name 	The Name ""
 */

int read_member_header (Ar_port *header, FILE *fd, char* filename);
int process_long_names_member (register Ar *arp, char **long_names_table, char *filename);

timestruc_t&
read_archive(register Name target)
{
	register Property       member;
	wchar_t			*slash;
	String_rec		true_member_name;
	wchar_t			buffer[STRING_BUFFER_LENGTH];
	register Name		true_member = NULL;
	Ar                      ar;
	char			*long_names_table = NULL; /* Table of long
							     member names */

	member = get_prop(target->prop, member_prop);
	/*
	 * Check if the member has directory component.
	 * If so, remove the dir and see if we know the date.
	 */
	if (member->body.member.member != NULL) {
		Wstring member_string(member->body.member.member);
		wchar_t * wcb = member_string.get_string();
		if((slash = (wchar_t *) wcsrchr(wcb, (int) slash_char)) != NULL) {
			INIT_STRING_FROM_STACK(true_member_name, buffer);
			append_string(member->body.member.library->string_mb,
				      &true_member_name,
				      FIND_LENGTH);
			append_char((int) parenleft_char, &true_member_name);
			append_string(slash + 1, &true_member_name, FIND_LENGTH);
			append_char((int) parenright_char, &true_member_name);
			true_member = GETNAME(true_member_name.buffer.start,
					      FIND_LENGTH);
			if (true_member->stat.time != file_no_time) {
				target->stat.time = true_member->stat.time;
				return target->stat.time;
			}
		}
	}
	if (open_archive(member->body.member.library->string_mb, &ar) == failed) {
		if (errno == ENOENT) {
			target->stat.stat_errno = ENOENT;
			close_archive(&ar);
			if (member->body.member.member == NULL) {
				member->body.member.member = empty_name;
			}
			return target->stat.time = file_doesnt_exist;
		} else {
			fatal(gettext("Can't access archive `%s': %s"),
			      member->body.member.library->string_mb,
			      errmsg(errno));
		}
	}
	if (target->stat.time == file_no_time) {
		if (read_archive_dir(&ar, member->body.member.library, 
				     &long_names_table)
		    == failed){
			fatal(gettext("Can't access archive `%s': %s"),
			      member->body.member.library->string_mb,
			      errmsg(errno));
		}
	}
	if (member->body.member.entry != NULL) {
		translate_entry(&ar, target, member,&long_names_table);
	}
	close_archive(&ar);
	if (long_names_table) {
		retmem_mb(long_names_table);
	}
	if (true_member != NULL) {
		target->stat.time = true_member->stat.time;
	}
	if (target->stat.time == file_no_time) {
		target->stat.time = file_doesnt_exist;
	}
	return target->stat.time;
}

/*
 *	open_archive(filename, arp)
 *
 *	Return value:
 *				Indicates if open failed or not
 *
 *	Parameters:
 *		filename	The name of the archive we need to read
 *		arp		Pointer to ar file description block
 *
 *	Global variables used:
 */
static Boolean
open_archive(char *filename, register Ar *arp)
{
	int			fd;
	char			mag_5[AR_5_MAGIC_LENGTH];
	char			mag_port[AR_PORT_MAGIC_LENGTH];
	char			buffer[4];

	arp->fd = NULL;
	fd = open_vroot(filename, O_RDONLY, 0, NULL, VROOT_DEFAULT);
	if ((fd < 0) || ((arp->fd = fdopen(fd, "r")) == NULL)) {
		return failed;
	}
	(void) fcntl(fileno(arp->fd), F_SETFD, 1);

	if (fread(mag_port, AR_PORT_MAGIC_LENGTH, 1, arp->fd) != 1) {
		return failed;
	}
	if (IS_EQUALN(mag_port, AR_PORT_MAGIC, AR_PORT_MAGIC_LENGTH)) {
		arp->type = AR_PORT;
		/*
		 * Read in first member header to find out if there is 
		 * a symbol definition table.
		 */

		int ret = read_member_header(&arp->ar_port, arp->fd, filename);
		if (ret == failed) {
			return failed;
		} else if(ret == -1) {
			/* There is no member header - empty archive */
			arp->sym_size = arp->num_symbols = arp->sym_begin = 0L;
			arp->first_ar_mem = ftell(arp->fd);
			return succeeded;
		}
		/*
		 * The following values are the default if there is 
		 * no symbol directory and long member names.
		 */
		arp->sym_size = arp->num_symbols = arp->sym_begin = 0L;
		arp->first_ar_mem = ftell(arp->fd) - (long) sizeof (Ar_port);

		/*
		 * Do we have a symbol table? A symbol table is always
		 * the first member in an archive. In 4.1.x it has the 
		 * name __.SYMDEF, in SVr4, it has the name "/        "
		 */
/*
		MBSTOWCS(wcs_buffer, "/               ");
		if (IS_WEQUALN(arp->ar_port.ar_name, wcs_buffer, 16)) {
 */
		if (IS_EQUALN(arp->ar_port.ar_name,
			      "/               ",
			      16)) {
			if (sscanf(arp->ar_port.ar_size,
				   "%ld",
				   &arp->sym_size) != 1) {
				return failed;
			}
			arp->sym_size += (arp->sym_size & 1); /* round up */
			if (fread(buffer, sizeof buffer, 1, arp->fd) != 1) {
				return failed;
			}
			arp->num_symbols = sgetl(buffer);
			arp->sym_begin = ftell(arp->fd);
			arp->first_ar_mem = arp->sym_begin +
						arp->sym_size - sizeof buffer;
		}
		return succeeded;
	}
	fatal(gettext("`%s' is not an archive"), filename);
	/* NOTREACHED */
	return failed;
}


/*
 *	close_archive(arp)
 *
 *	Parameters:
 *		arp		Pointer to ar file description block
 *
 *	Global variables used:
 */
static void
close_archive(register Ar *arp)
{
	if (arp->fd != NULL) {
		(void) fclose(arp->fd);
	}
}

/*
 *	read_archive_dir(arp, library, long_names_table)
 *
 *	Reads the directory of an archive and enters all
 *	the members into the make symboltable in lib(member) format
 *	with their dates.
 *
 *	Parameters:
 *		arp		Pointer to ar file description block
 *		library		Name of lib to enter members for.
 *				Used to form "lib(member)" string.
 *		long_names_table table that contains list of members
 * 				with names > 15 characters long
 *
 *	Global variables used:
 */
static Boolean
read_archive_dir(register Ar *arp, Name library, char **long_names_table)
{
	wchar_t			*name_string;
	wchar_t			*member_string;
	register long		len;
	register wchar_t	*p;
	register char		*q;
	register Name		name;
	Property		member;
	long			ptr;
	long			date;

	int			offset;

	/*
	 * If any of the members has a name > 15 chars,
	 * it will be found here.
	 */
	if (process_long_names_member(arp, long_names_table, library->string_mb) == failed) {
		return failed;
	}
	name_string = ALLOC_WC((int) (library->hash.length +
				      (int) ar_member_name_len * 2));
	(void) mbstowcs(name_string, library->string_mb, (int) library->hash.length);
	member_string = name_string + library->hash.length;
	*member_string++ = (int) parenleft_char;

	if (fseek(arp->fd, arp->first_ar_mem, 0) != 0) {
		goto read_error;
	}
	/* Read the directory using the appropriate format */
	switch (arp->type) {
	case AR_5:
	    for (;;) {
		if (fread((char *) &arp->arf_5, sizeof arp->arf_5, 1, arp->fd)
		    != 1) {
			if (feof(arp->fd)) {
				return succeeded;
			}
			break;
		}
		len = sizeof arp->arf_5.arf_name;
		for (p = member_string, q = arp->arf_5.arf_name;
		     (len > 0) && (*q != (int) nul_char) && !isspace(*q);
		     ) {
			MBTOWC(p, q);
			p++;
			q++;
		}
		*p++ = (int) parenright_char;
		*p = (int) nul_char;
		name = GETNAME(name_string, FIND_LENGTH);
		/*
		 * [tolik] Fix for dmake bug 1234018.
		 * If name->stat.time is already set, then it should not
		 * be changed. (D)make propogates time stamp for one
		 * member, and when it calls exists() for another member,
		 * the first one may be changed.
		 */
		if(name->stat.time == file_no_time) {
			name->stat.time.tv_sec = sgetl(arp->arf_5.arf_date);
			name->stat.time.tv_nsec = LONG_MAX;
		}
		name->is_member = library->is_member;
		member = maybe_append_prop(name, member_prop);
		member->body.member.library = library;
		*--p = (int) nul_char;
		if (member->body.member.member == NULL) {
			member->body.member.member =
			  GETNAME(member_string, FIND_LENGTH);
		}
		ptr = sgetl(arp->arf_5.arf_size);
		ptr += (ptr & 1);
		if (fseek(arp->fd, ptr, 1) != 0) {
			goto read_error;
		}
	    }
	    break;
	case AR_PORT:
	    for (;;) {
		    if ((fread((char *) &arp->ar_port,
			       sizeof arp->ar_port,
			       1,
			       arp->fd) != 1) ||
			!IS_EQUALN(arp->ar_port.ar_fmag,
				   AR_PORT_END_MAGIC,
				   sizeof arp->ar_port.ar_fmag)) {
			    if (feof(arp->fd)) {
				    return succeeded;
			    }
			    fatal(
				gettext("Read error in archive `%s': invalid archive file member header at 0x%x"),
				library->string_mb,
				ftell(arp->fd)
			    );
		    }
		    /* If it's a long name, retrieve it from long name table */
		    if (arp->ar_port.ar_name[0] == '/') {
			    /*
			     * "len" is used for hashing the string.
			     * We're using "ar_member_name_len" instead of
			     * the actual name length since it's the longest
			     * string the "ar" command can handle at this
			     * point.
			     */
			    len = ar_member_name_len;
			    sscanf(arp->ar_port.ar_name + 1,
				   "%ld",
				   &offset);
			    q = *long_names_table + offset;
		    } else {
			    q = arp->ar_port.ar_name;	
			    len = sizeof arp->ar_port.ar_name;
		    }
		    
		    for (p = member_string;
			 (len > 0) &&
			 (*q != (int) nul_char) &&
			 !isspace(*q) &&
			 (*q != (int) slash_char);
			 ) {
			    MBTOWC(p, q);
			    p++;
			    q++;
		    }
		    *p++ = (int) parenright_char;
		    *p = (int) nul_char;
		    name = GETNAME(name_string, FIND_LENGTH);
		    name->is_member = library->is_member;
		    member = maybe_append_prop(name, member_prop);
		    member->body.member.library = library;
		    *--p = (int) nul_char;
		    if (member->body.member.member == NULL) {
			    member->body.member.member =
			      GETNAME(member_string, FIND_LENGTH);
		    }
		    if (sscanf(arp->ar_port.ar_date, "%ld", &date) != 1) {
			    WCSTOMBS(mbs_buffer, name_string);
			    fatal(gettext("Bad date field for member `%s' in archive `%s'"),
				  mbs_buffer,
				  library->string_mb);
		    }
		    /*
		     * [tolik] Fix for dmake bug 1234018.
		     */
		    if(name->stat.time == file_no_time) {
		   	name->stat.time.tv_sec = date;
		   	name->stat.time.tv_nsec = LONG_MAX;
		    }
		    if (sscanf(arp->ar_port.ar_size, "%ld", &ptr) != 1) {
			    WCSTOMBS(mbs_buffer, name_string);
			    fatal(gettext("Bad size field for member `%s' in archive `%s'"),
				  mbs_buffer,
				  library->string_mb);
		    }
		    ptr += (ptr & 1);
		    if (fseek(arp->fd, ptr, 1) != 0) {
			    goto read_error;
		    }	
	    }
	    break;
	}

	/* Only here if fread() [or IS_EQUALN()] failed and not at EOF */
read_error:
	fatal(gettext("Read error in archive `%s': %s"),
	      library->string_mb,
	      errmsg(errno));
	    /* NOTREACHED */
}


/*
 *	process_long_names_member(arp)
 *
 *	If the archive contains members with names longer
 *	than 15 characters, then it has a special member
 *	with the name "//        " that contains a table
 *	of null-terminated long names. This member
 *	is always the first member, after the symbol table
 *	if it exists.
 *
 *	Parameters:
 *		arp		Pointer to ar file description block
 *
 *	Global variables used:
 */
int
process_long_names_member(register Ar *arp, char **long_names_table, char *filename)
{  
	Ar_port			*ar_member_header;
	int			table_size;

	if (fseek(arp->fd, arp->first_ar_mem, 0) != 0) {
		return failed;
	}
	if ((ar_member_header = 
	     (Ar_port *) alloca((int) sizeof(Ar_port))) == NULL){
		perror(gettext("memory allocation failure"));
		return failed;
	} 
	int ret = read_member_header(ar_member_header, arp->fd, filename);
	if (ret == failed) {
		return failed;
	} else if(ret == -1) {
		/* There is no member header - empty archive */
		return succeeded;
	}
	/* Do we have special member containing long names? */
	if (IS_EQUALN(ar_member_header->ar_name, 
		      "//              ",
		      16)){
		if (sscanf(ar_member_header->ar_size,
			   "%ld",
			   &table_size) != 1) {
			return failed;
		}
		*long_names_table = (char *) malloc(table_size);
		/* Read the list of long member names into the table */
		if (fread(*long_names_table, table_size, 1, arp->fd) != 1) {
			return failed;
		}
		arp->first_ar_mem = ftell(arp->fd);
	}
	return succeeded;
}

/*
 *	translate_entry(arp, target, member)
 *
 *	Finds the member for one lib.a((entry))
 *
 *	Parameters:
 *		arp		Pointer to ar file description block
 *		target		Target to find member name for
 *		member		Property to fill in with info
 *
 *	Global variables used:
 */
static void
translate_entry(register Ar *arp, Name target, register Property member, char **long_names_table)
{
	register int		len;
	register int		i;
	wchar_t			*member_string;
	ar_port_word		*offs;
	int			strtablen;
	char			*syms;		 /* string table */
	char			*csym;		 /* string table */
	ar_port_word		*offend;	 /* end of offsets table */
	int			date;
	register wchar_t	*ap;
	register char		*hp;
	int			maxs;
	int			offset;
	char		buffer[4];

	if (arp->sym_begin == 0L || arp->num_symbols == 0L) {
		fatal(gettext("Cannot find symbol `%s' in archive `%s'"),
		      member->body.member.entry->string_mb,
		      member->body.member.library->string_mb);
	}

	if (fseek(arp->fd, arp->sym_begin, 0) != 0) {
		goto read_error;
	}
	member_string = ALLOC_WC((int) ((int) ar_member_name_len * 2));

	switch (arp->type) {
	case AR_5:
		if ((len = member->body.member.entry->hash.length) > 8) {
			len = 8;
		}
		for (i = 0; i < arp->num_symbols; i++) {
			if (fread((char *) &arp->ars_5,
				  sizeof arp->ars_5,
				  1,
				  arp->fd) != 1) {
				goto read_error;
			}
			if (IS_EQUALN(arp->ars_5.sym_name,
				      member->body.member.entry->string_mb,
				      len)) {
				if ((fseek(arp->fd,
					   sgetl(arp->ars_5.sym_ptr),
					   0) != 0) ||
				    (fread((char *) &arp->arf_5,
					   sizeof arp->arf_5,
					   1,
					   arp->fd) != 1)) {
					goto read_error;
				}
				MBSTOWCS(wcs_buffer, arp->arf_5.arf_name);
				(void) wcsncpy(member_string,
					      wcs_buffer,
					      wcslen(wcs_buffer));
				member_string[sizeof(arp->arf_5.arf_name)] =
								(int) nul_char;
				member->body.member.member =
					GETNAME(member_string, FIND_LENGTH);
				target->stat.time.tv_sec = sgetl(arp->arf_5.arf_date);
				target->stat.time.tv_nsec = LONG_MAX;
				return;
			}
		}
		break;
	case AR_PORT:
		offs = (ar_port_word *) alloca((int) (arp->num_symbols * AR_PORT_WORD));
		if (fread((char *) offs,
			  AR_PORT_WORD,
			  (int) arp->num_symbols,
			  arp->fd) != arp->num_symbols) {
			goto read_error;
		}

		for(i=0;i<arp->num_symbols;i++) {
			*((int*)buffer)=offs[i];
			offs[i]=(ar_port_word)sgetl(buffer);
		}

		strtablen=arp->sym_size-4-(int) (arp->num_symbols * AR_PORT_WORD);
		syms = (char *) alloca(strtablen);
		if (fread(syms,
			  sizeof (char),
			  strtablen,
			  arp->fd) != strtablen) {
			goto read_error;
		}
		offend = &offs[arp->num_symbols];
		while (offs < offend) {
			maxs = strlen(member->body.member.entry->string_mb);
			if(strlen(syms) > maxs)
				maxs = strlen(syms);
			if (IS_EQUALN(syms,
				      member->body.member.entry->string_mb,
				      maxs)) {
				if (fseek(arp->fd,
					  (long) *offs,
					  0) != 0) {
					goto read_error;
				}
				if ((fread((char *) &arp->ar_port,
					   sizeof arp->ar_port,
					   1,
					   arp->fd) != 1) ||
				    !IS_EQUALN(arp->ar_port.ar_fmag,
					       AR_PORT_END_MAGIC,
					       sizeof arp->ar_port.ar_fmag)) {
					goto read_error;
				}
				if (sscanf(arp->ar_port.ar_date,
					   "%ld",
					   &date) != 1) {
					fatal(gettext("Bad date field for member `%s' in archive `%s'"),
					      arp->ar_port.ar_name,
					      target->string_mb);
				}
		    /* If it's a long name, retrieve it from long name table */
		    if (arp->ar_port.ar_name[0] == '/') {
			    sscanf(arp->ar_port.ar_name + 1,
				   "%ld",
				   &offset);
			    len = ar_member_name_len;
			    hp = *long_names_table + offset;
		    } else {
			    len = sizeof arp->ar_port.ar_name;
			    hp = arp->ar_port.ar_name;	
		    }
				ap = member_string;
				while (*hp &&
				       (*hp != (int) slash_char) &&
				       (ap < &member_string[len])) {
					MBTOWC(ap, hp);
					ap++;
					hp++;
				}
				*ap = (int) nul_char;
				member->body.member.member =
					GETNAME(member_string, FIND_LENGTH);
				target->stat.time.tv_sec = date;
				target->stat.time.tv_nsec = LONG_MAX;
				return;
			}
			offs++;
			while(*syms!='\0') syms++;
			syms++;
		}
	}
	fatal(gettext("Cannot find symbol `%s' in archive `%s'"),
	      member->body.member.entry->string_mb,
	      member->body.member.library->string_mb);
	/*NOTREACHED*/

read_error:
	if (ferror(arp->fd)) {
		fatal(gettext("Read error in archive `%s': %s"),
		      member->body.member.library->string_mb,
		      errmsg(errno));
	} else {
		fatal(gettext("Read error in archive `%s': Premature EOF"),
		      member->body.member.library->string_mb);
	}
}

/*
 *	sgetl(buffer)
 *
 *	The intent here is to provide a means to make the value of
 *	bytes in an io-buffer correspond to the value of a long
 *	in the memory while doing the io a long at a time.
 *	Files written and read in this way are machine-independent.
 *
 *	Return value:
 *				Long int read from buffer
 *	Parameters:
 *		buffer		buffer we need to read long int from
 *
 *	Global variables used:
 */
static long
sgetl(register char *buffer)
{
	register long		w = 0;
	register int		i = BITSPERBYTE * AR_PORT_WORD;

	while ((i -= BITSPERBYTE) >= 0) {
		w |= (long) ((unsigned char) *buffer++) << i;
	}
	return w;
}


/*
 *	read_member_header(header, fd, filename)
 *
 *	reads the member header for the 4.1.x and SVr4 archives.
 *
 *	Return value:
 *				fails if read error or member
 * 				header is not the right format
 *	Parameters:
 *		header		There's one before each archive member
 *		fd		file descriptor for the archive file.
 *
 *	Global variables used:
 */
int 
read_member_header(Ar_port *header, FILE *fd, char* filename)
{
	int num = fread((char *) header, sizeof (Ar_port), 1, fd);
	if (num != 1 && feof(fd)) {
		/* There is no member header - empty archive */
		return -1;
	}
	if ((num != 1) ||
	    !IS_EQUALN(
		AR_PORT_END_MAGIC,
		header->ar_fmag,
		sizeof (header->ar_fmag)
	    )
	) {
		fatal(
			gettext("Read error in archive `%s': invalid archive file member header at 0x%x"),
			filename,
			ftell(fd)
		);
	}
	return succeeded;
}

