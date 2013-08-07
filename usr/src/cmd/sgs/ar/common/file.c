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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 */

#include <sys/sendfile.h>
#include "inc.h"
#include "gelf.h"

/*
 * List of archive members, accessed globally by cmd and file.
 */
ARFILE	*listhead, *listend;

/*
 * Type used to manage string tables. Archives can have two of these:
 *
 * sym_strtbl: String table included at the end of the symbol table
 *	archive member, following the offset array.
 *
 * long_strtbl: String table used to hold member names that exceed 15
 *	characters in length, found in the long names archive member.
 */
typedef struct {
	char	*base;		/* Base of string table memory */
	size_t	used;		/* # bytes used from allocation */
	size_t	size;		/* Size of allocation */
} ARSTRTBL;

static ARSTRTBL	sym_strtbl;
static ARSTRTBL	long_strtbl;


/*
 * Name and file descriptor used when creating a new archive.
 * If this variable references an open file when exit_cleanup()
 * executes, it will close and remove the file, preventing incomplete
 * temporary files from being left behind in the case of a failure
 * or interruption.
 */
static struct {
	int		fd;	/* -1, or open file descriptor */
	const char	*path;	/* Path to open file */
} ar_outfile;

/*
 * The ar file format requires objects to be padded to an even size.
 * We do that, but it turns out to be beneficial to go farther.
 *
 * ld(1) accesses archives by mmapping them into memory. If the mapped
 * objects (member data) have the proper alignment, we can access them
 * directly. If the data alignment is wrong, libelf "slides" them over the
 * archive header to correct the misalignment. This is expensive in time
 * (to copy memory) and space (it causes swap to be allocated by the system
 * to back the now-modified pages). Hence, we really want to ensure that
 * the alignment is right.
 *
 * We used to align 32-bit objects at 4-byte boundaries, and 64-bit objects
 * at 8-byte. More recently, an elf section type has appeared that has
 * 8-byte alignment requirements (SUNW_move) even in 32-bit objects. So,
 * the current strategy is to align all objects to 8-bytes.
 *
 * There are two important things to consider when setting this value:
 *	1) If a new elf section that ld(1) accesses in memory appears
 *	   with a greater than 8-byte alignment requirement, this value
 *	   will need to be raised. Or, alternatively, the entire approach may
 *	   need reconsideration.
 *	2) The size of this padding must be smaller than the size of the
 *	   smallest possible ELF section. Otherwise, the logic contained
 *	   in recover_padding() can be tricked.
 */
#define	PADSZ 8

/*
 * Forward Declarations
 */
static void		arwrite(const char *, int, const char *, size_t);
static size_t		mklong_tab();
static size_t		mksymtab(const char *, ARFILEP **, int *);
static const char	*make_tmpname(const char *);
static size_t		sizeof_symtbl(size_t, int, size_t);
static void		savelongname(ARFILE *);
static void		savename(char *);
static int		search_sym_tab(const char *, ARFILE *, Elf *,
			    Elf_Scn *, size_t *, ARFILEP **, size_t *);
static size_t		sizeofmembers(size_t);
static char		*sputl32(uint32_t, char *);
static char		*sputl64(uint64_t, char *);
static void		strtbl_pad(ARSTRTBL *, size_t, int);
static char		*trimslash(char *s);
static void		writesymtab(const char *, int fd, size_t, ARFILEP *,
			    size_t);


/*
 * Function to be called on exit to clean up incomplete new archive.
 */
static void
exit_cleanup(void)
{
	if (ar_outfile.fd != -1) {
		/* Both of these system calls are Async-Signal-Safe */
		(void)  close(ar_outfile.fd);
		(void) unlink(ar_outfile.path);
	}
}

/*
 * Open an existing archive.
 */
int
getaf(Cmd_info *cmd_info)
{
	Elf_Cmd cmd;
	int fd;
	char *arnam = cmd_info->arnam;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, MSG_INTL(MSG_ELF_VERSION),
		    elf_errmsg(-1));
		exit(1);
	}

	if ((cmd_info->afd = fd = open(arnam, O_RDONLY)) == -1) {
		int err = errno;

		if (err == ENOENT) {
			/* archive does not exist yet, may have to create one */
			return (fd);
		} else {
			/* problem other than "does not exist" */
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
			    arnam, strerror(err));
			exit(1);
		}
	}

	cmd = ELF_C_READ;
	cmd_info->arf = elf_begin(fd, cmd, (Elf *)0);

	if (elf_kind(cmd_info->arf) != ELF_K_AR) {
		(void) fprintf(stderr, MSG_INTL(MSG_NOT_ARCHIVE), arnam);
		if (cmd_info->opt_flgs & (a_FLAG | b_FLAG))
			(void) fprintf(stderr, MSG_INTL(MSG_USAGE_06),
			    cmd_info->ponam);
		exit(1);
	}
	return (fd);
}

/*
 * Given a value, and a pad alignment, return the number of bytes
 * required to pad the value to the next alignment boundary.
 */
static size_t
pad(size_t n, size_t align)
{
	size_t r;

	r = n % align;
	if (r)
		r = align - r;

	return (r);
}

/*
 * If the current archive item is an ELF object, then ar(1) may have added
 * newline padding at the end in order to bring the following object
 * into PADSZ alignment within the file. This padding cannot be
 * distinguished from data using the information kept in the member header.
 * This routine examines the objects, using knowledge of
 * ELF and how our tools lay out objects to determine whether padding was
 * added to an archive item. If so, it adjusts the st_size and
 * st_padding fields of the file argument to reflect it.
 */
static void
recover_padding(Elf *elf, ARFILE *file)
{
	size_t		extent;
	size_t		padding;
	size_t		shnum;
	GElf_Ehdr	ehdr;


	/* ar(1) only pads objects, so bail if not looking at one */
	if (gelf_getclass(elf) == ELFCLASSNONE)
		return;

	/*
	 * libelf always puts the section header array at the end
	 * of the object, and all of our compilers and other tools
	 * use libelf or follow this convention. So, it is extremely
	 * likely that the section header array is at the end of this
	 * object: Find the address at the end of the array and compare
	 * it to the archive ar_size. If they are within PADSZ bytes, then
	 * we've found the end, and the difference is padding (We assume
	 * that no ELF section can fit into PADSZ bytes).
	 */
	if (elf_getshdrnum(elf, &shnum) == -1)
		return;

	extent = gelf_getehdr(elf, &ehdr)
	    ? (ehdr.e_shoff + (shnum * ehdr.e_shentsize)) : 0;

	/*
	 * If the extent exceeds the end of the archive member
	 * (negative padding), then we don't know what is going on
	 * and simply leave things alone.
	 */
	if (extent > file->ar_size)
		return;

	padding = file->ar_size - extent;
	if (padding >= PADSZ) {
		/*
		 * The section header array is not at the end of the object.
		 * Traverse the section headers and look for the one with
		 * the highest used address. If this address is within
		 * PADSZ bytes of ar_size, then this is the end of the object.
		 */
		Elf_Scn *scn = NULL;

		do {
			scn = elf_nextscn(elf, scn);
			if (scn) {
				GElf_Shdr shdr;

				if (gelf_getshdr(scn, &shdr)) {
					size_t t;

					t = shdr.sh_offset + shdr.sh_size;
					if (t > extent)
						extent = t;
				}
			}
		} while (scn);

		if (extent > file->ar_size)
			return;
		padding = file->ar_size - extent;
	}

	/*
	 * Now, test the padding. We only act on padding in the range
	 * (0 < pad < PADSZ) (ar(1) will never add more than this). A pad
	 * of 0 requires no action, and any other size above (PADSZ-1) means
	 * that we don't understand the layout of this object, and as such,
	 * cannot do anything.
	 *
	 * If the padding is in range, and the raw data for the
	 * object is available, then we perform one additional sanity
	 * check before moving forward: ar(1) always pads with newline
	 * characters. If anything else is seen, it is not padding so
	 * leave it alone.
	 */
	if (padding < PADSZ) {
		if (file->ar_contents) {
			size_t cnt = padding;
			char *p = file->ar_contents + extent;

			while (cnt--) {
				if (*p++ != '\n') {   /* No padding */
					padding = 0;
					break;
				}
			}
		}

		/* Remove the padding from the size */
		file->ar_size -= padding;
		file->ar_padding = padding;
	}
}

/*
 * Each call to getfile() returns the next unread archive member
 * from the archive opened by getaf(). Returns NULL if no more
 * archive members are left.
 */
ARFILE *
getfile(Cmd_info *cmd_info)
{
	Elf_Arhdr *mem_header = NULL;
	ARFILE	*file;
	char *tmp_rawname, *file_rawname;
	Elf *elf;
	char *arnam = cmd_info->arnam;
	int fd = cmd_info->afd;
	Elf *arf = cmd_info->arf;

	if (fd == -1)
		return (NULL); /* the archive doesn't exist */

	while (mem_header == NULL) {
		if ((elf = elf_begin(fd, ELF_C_READ, arf)) == 0)
			return (NULL);  /* archive is empty or have hit end */

		if ((mem_header = elf_getarhdr(elf)) == NULL) {
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_MALARCHIVE),
			    arnam, EC_XWORD(elf_getbase(elf)), elf_errmsg(-1));
			exit(1);
		}

		/* Ignore special members like the symbol and string tables */
		if (mem_header->ar_name[0] == '/') {
			(void) elf_next(elf);
			(void) elf_end(elf);
			mem_header = NULL;
		}
	}

	/*
	 * NOTE:
	 *	The mem_header->ar_name[] is set to a NULL string
	 *	if the archive member header has some error.
	 *	(See elf_getarhdr() man page.)
	 *	It is set to NULL for example, the ar command reads
	 *	the archive files created by SunOS 4.1 system.
	 *	See c block comment in cmd.c, "Incompatible Archive Header".
	 */
	file = newfile();
	(void) strncpy(file->ar_name, mem_header->ar_name, SNAME);

	if ((file->ar_longname = malloc(strlen(mem_header->ar_name) + 1))
	    == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_MALLOC), strerror(err));
		exit(1);
	}
	(void) strcpy(file->ar_longname, mem_header->ar_name);
	if ((file->ar_rawname = malloc(strlen(mem_header->ar_rawname) + 1))
	    == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_MALLOC), strerror(err));
		exit(1);
	}
	tmp_rawname = mem_header->ar_rawname;
	file_rawname = file->ar_rawname;
	while (!isspace(*tmp_rawname) &&
	    ((*file_rawname = *tmp_rawname) != '\0')) {
		file_rawname++;
		tmp_rawname++;
	}
	if (!(*tmp_rawname == '\0'))
		*file_rawname = '\0';

	file->ar_date = mem_header->ar_date;
	file->ar_uid  = mem_header->ar_uid;
	file->ar_gid  = mem_header->ar_gid;
	file->ar_mode = (unsigned long) mem_header->ar_mode;
	file->ar_size = mem_header->ar_size;

	/* reverse logic */
	if ((cmd_info->opt_flgs & (t_FLAG | s_FLAG)) != t_FLAG) {
		size_t ptr;
		file->ar_flag = F_ELFRAW;
		if ((file->ar_contents = elf_rawfile(elf, &ptr))
		    == NULL) {
			if (ptr != 0) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ELF_RAWFILE), elf_errmsg(-1));
				exit(1);
			}
		}
		file->ar_elf = elf;
	}

	recover_padding(elf, file);

	(void) elf_next(elf);
	return (file);
}

/*
 * Allocate a new archive member descriptor and add it to the list.
 */
ARFILE *
newfile(void)
{
	static ARFILE	*buffer =  NULL;
	static size_t	count = 0;
	ARFILE		*fileptr;

	if (count == 0) {
		if ((buffer = (ARFILE *) calloc(CHUNK, sizeof (ARFILE)))
		    == NULL) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_MALLOC),
			    strerror(err));
			exit(1);
		}
		count = CHUNK;
	}
	count--;
	fileptr = buffer++;

	if (listhead)
		listend->ar_next = fileptr;
	else
		listhead = fileptr;
	listend = fileptr;
	return (fileptr);
}

static char *
trimslash(char *s)
{
	static char buf[SNAME];

	(void) strncpy(buf, trim(s), SNAME - 2);
	buf[SNAME - 2] = '\0';
	return (strcat(buf, MSG_ORIG(MSG_STR_SLASH)));
}

char *
trim(char *s)
{
	char *p1, *p2;

	for (p1 = s; *p1; p1++)
		;
	while (p1 > s) {
		if (*--p1 != '/')
			break;
		*p1 = 0;
	}
	p2 = s;
	for (p1 = s; *p1; p1++)
		if (*p1 == '/')
			p2 = p1 + 1;
	return (p2);
}


/*
 * Find all the global symbols exported by ELF archive members, and
 * build a list associating each one with the archive member that
 * provides it.
 *
 * exit:
 *	*symlist is set to the list of symbols. If any ELF object was
 *	found, *found_obj is set to TRUE (1). Returns the number of symbols
 *	located.
 */
static size_t
mksymtab(const char *arname, ARFILEP **symlist, int *found_obj)
{
	ARFILE		*fptr;
	size_t		mem_offset = 0;
	Elf 		*elf;
	Elf_Scn		*scn;
	GElf_Ehdr	ehdr;
	int		newfd;
	size_t		nsyms = 0;
	int		class = 0;
	Elf_Data	*data;
	size_t		num_errs = 0;

	newfd = 0;
	for (fptr = listhead; fptr; fptr = fptr->ar_next) {
		/* determine if file is coming from the archive or not */
		if ((fptr->ar_elf != NULL) && (fptr->ar_pathname == NULL)) {
			/*
			 * I can use the saved elf descriptor.
			 */
			elf = fptr->ar_elf;
		} else if ((fptr->ar_elf == NULL) &&
		    (fptr->ar_pathname != NULL)) {
#ifdef _LP64
			/*
			 * The archive member header ar_size field is 10
			 * decimal digits, sufficient to represent a 32-bit
			 * value, but not a 64-bit one. Hence, we reject
			 * attempts to insert a member larger than 4GB.
			 *
			 * One obvious way to extend the format without altering
			 * the ar_hdr struct is to use the same mechanism used
			 * for ar_name: Put the size string into the long name
			 * string table and write a string /xxx into ar_size,
			 * where xxx is the string table offset.
			 *
			 * At the time of this writing (June 2010), the largest
			 * relocatable objects are measured in 10s or 100s
			 * of megabytes, so we still have many years to go
			 * before this becomes limiting. By that time, it may
			 * turn out that a completely new archive format is
			 * a better solution, as the current format has many
			 * warts and inefficiencies. In the meantime, we
			 * won't burden the current implementation with support
			 * for a bandaid feature that will have little use.
			 */
			if (fptr->ar_size > 0xffffffff) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ERR_MEMBER4G),
				    fptr->ar_pathname);
				num_errs++;
				continue;
			}
#endif
			if ((newfd  =
			    open(fptr->ar_pathname, O_RDONLY)) == -1) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
				    fptr->ar_pathname, strerror(err));
				num_errs++;
				continue;
			}

			if ((elf = elf_begin(newfd,
			    ELF_C_READ, (Elf *)0)) == 0) {
				(void) fprintf(stderr,
				    MSG_INTL(MSG_ELF_BEGIN_FILE),
				    fptr->ar_pathname, elf_errmsg(-1));
				(void) close(newfd);
				newfd = 0;
				num_errs++;
				continue;
			}
			if (elf_kind(elf) == ELF_K_AR) {
				if (newfd) {
					(void) close(newfd);
					newfd = 0;
				}
				(void) elf_end(elf);
				continue;
			}
		} else {
			(void) fprintf(stderr, MSG_INTL(MSG_INTERNAL_01));
			exit(1);
		}
		if (gelf_getehdr(elf, &ehdr) != 0) {
			size_t shstrndx = 0;
			if ((class = gelf_getclass(elf)) == ELFCLASS64) {
				fptr->ar_flag |= F_CLASS64;
			} else if (class == ELFCLASS32)
				fptr->ar_flag |= F_CLASS32;

			if (elf_getshdrstrndx(elf, &shstrndx) == -1) {
				if (fptr->ar_pathname != NULL) {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ELF_GETSHSTRNDX_FILE),
					    fptr->ar_pathname, elf_errmsg(-1));
				} else {
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ELF_GETSHSTRNDX_AR),
					    arname, fptr->ar_longname,
					    elf_errmsg(-1));
				}
				num_errs++;
				if (newfd) {
					(void) close(newfd);
					newfd = 0;
				}
				(void) elf_end(elf);
				continue;
			}

			scn = elf_getscn(elf, shstrndx);
			if (scn == NULL) {
				if (fptr->ar_pathname != NULL)
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ELF_GETSCN_FILE),
					    fptr->ar_pathname, elf_errmsg(-1));
				else
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ELF_GETSCN_AR),
					    arname, fptr->ar_longname,
					    elf_errmsg(-1));
				num_errs++;
				if (newfd) {
					(void) close(newfd);
					newfd = 0;
				}
				(void) elf_end(elf);
				continue;
			}

			data = 0;
			data = elf_getdata(scn, data);
			if (data == NULL) {
				if (fptr->ar_pathname != NULL)
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ELF_GETDATA_FILE),
					    fptr->ar_pathname, elf_errmsg(-1));
				else
					(void) fprintf(stderr,
					    MSG_INTL(MSG_ELF_GETDATA_AR),
					    arname, fptr->ar_longname,
					    elf_errmsg(-1));
				num_errs++;
				if (newfd) {
					(void) close(newfd);
					newfd = 0;
				}
				(void) elf_end(elf);
				continue;
			}
			if (data->d_size == 0) {
				if (fptr->ar_pathname != NULL)
					(void) fprintf(stderr,
					    MSG_INTL(MSG_W_ELF_NODATA_FILE),
					    fptr->ar_pathname);
				else
					(void) fprintf(stderr,
					    MSG_INTL(MSG_W_ELF_NODATA_AR),
					    arname, fptr->ar_longname);
				if (newfd) {
					(void) close(newfd);
					newfd = 0;
				}
				(void) elf_end(elf);
				num_errs++;
				continue;
			}

			/* loop through sections to find symbol table */
			scn = 0;
			while ((scn = elf_nextscn(elf, scn)) != 0) {
				GElf_Shdr shdr;
				if (gelf_getshdr(scn, &shdr) == NULL) {
					/* BEGIN CSTYLED */
					if (fptr->ar_pathname != NULL)
					    (void) fprintf(stderr,
						MSG_INTL(MSG_ELF_GETDATA_FILE),
						fptr->ar_pathname,
						elf_errmsg(-1));
					else
					    (void) fprintf(stderr,
						MSG_INTL(MSG_ELF_GETDATA_AR),
						arname, fptr->ar_longname,
						elf_errmsg(-1));
					/* END CSTYLED */
					if (newfd) {
						(void) close(newfd);
						newfd = 0;
					}
					num_errs++;
					(void) elf_end(elf);
					continue;
				}
				*found_obj = 1;
				if (shdr.sh_type == SHT_SYMTAB) {
					if (search_sym_tab(arname, fptr, elf,
					    scn, &nsyms, symlist,
					    &num_errs) == -1) {
						if (newfd) {
							(void) close(newfd);
							newfd = 0;
						}
						continue;
					}
				}
			}
		}
		mem_offset += sizeof (struct ar_hdr) + fptr->ar_size;
		if (fptr->ar_size & 01)
			mem_offset++;
		(void) elf_end(elf);
		if (newfd) {
			(void) close(newfd);
			newfd = 0;
		}
	}
	if (num_errs)
		exit(1);

	if (found_obj) {
		if (nsyms == 0) {
			/*
			 * It is possible, though rare, to have ELF objects
			 * that do not export any global symbols. Presumably
			 * such objects operate via their .init/.fini
			 * sections. In this case, we produce an empty
			 * symbol table, so that applications that rely
			 * on a successful call to elf_getarsym() to determine
			 * if ELF objects are present will succeed. To do this,
			 * we require a small empty symbol string table.
			 */
			strtbl_pad(&sym_strtbl, 4, '\0');
		} else {
			/*
			 * Historical behavior is to pad string tables
			 * to a multiple of 4.
			 */
			strtbl_pad(&sym_strtbl, pad(sym_strtbl.used, 4), '\0');
		}

	}

	return (nsyms);
}

/*
 * Output a member header.
 */
/*ARGSUSED*/
static void
write_member_header(const char *filename, int fd, int is_elf,
    const char *name, time_t timestamp, uid_t uid, gid_t gid, mode_t mode,
    size_t size)
{
	char	buf[sizeof (struct ar_hdr) + 1];
	int	len;

	len = snprintf(buf, sizeof (buf), MSG_ORIG(MSG_MH_FORMAT), name,
	    EC_WORD(timestamp), EC_WORD(uid), EC_WORD(gid), EC_WORD(mode),
	    EC_XWORD(size), ARFMAG);

	/*
	 * If snprintf() reports that it needed more space than we gave
	 * it, it means that the caller fed us a long name, which is a
	 * fatal internal error.
	 */
	if (len != sizeof (struct ar_hdr)) {
		(void) fprintf(stderr, MSG_INTL(MSG_INTERNAL_02));
		exit(1);
	}

	arwrite(filename, fd, buf, len);

	/*
	 * We inject inter-member padding to ensure that ELF object
	 * member data is aligned on PADSZ. If this is a debug build,
	 * verify that the computations were right.
	 */
	assert(!is_elf || (pad(lseek(fd, 0, SEEK_CUR), PADSZ) == 0));
}

/*
 * Write the archive symbol table member to the output archive file.
 *
 * note:
 *	sizeofmembers() must have been called to establish member offset
 *	and padding values before writesymtab() is used.
 */
static void
writesymtab(const char *filename, int fd, size_t nsyms, ARFILEP *symlist,
    size_t eltsize)
{
	size_t	i, j;
	ARFILEP	*ptr;
	size_t	tblsize;
	char	*buf, *dst;
	int	is64 = (eltsize == 8);

	/*
	 * We require a buffer large enough to hold a symbol table count,
	 * plus one offset for each symbol.
	 */
	tblsize = (nsyms + 1) * eltsize;
	if ((buf = dst = malloc(tblsize)) == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_MALLOC), strerror(err));
		exit(1);
	}

	write_member_header(filename, fd, 0,
	    (is64 ? MSG_ORIG(MSG_STR_SYM64) : MSG_ORIG(MSG_STR_SLASH)),
	    time(0), 0, 0, 0, tblsize + sym_strtbl.used);

	dst = is64 ? sputl64(nsyms, dst) : sputl32(nsyms, dst);

	for (i = 0, j = SYMCHUNK, ptr = symlist; i < nsyms; i++, j--, ptr++) {
		if (!j) {
			j = SYMCHUNK;
			ptr = (ARFILEP *)*ptr;
		}
		dst = is64 ? sputl64((*ptr)->ar_offset, dst) :
		    sputl32((*ptr)->ar_offset, dst);
	}
	arwrite(filename, fd, buf, tblsize);
	free(buf);
	arwrite(filename, fd, sym_strtbl.base, sym_strtbl.used);
}

/*
 * Grow the size of the given string table so that there is room
 * for at least need bytes.
 *
 * entry:
 *	strtbl - String table to grow
 *	need - Amount of space required by caller
 */
static void
strtbl_alloc(ARSTRTBL *strtbl, size_t need)
{
#define	STRTBL_INITSZ	8196

	/*
	 * On 32-bit systems, we require a larger integer type in order
	 * to avoid overflow and wraparound when doing our computations.
	 */
	uint64_t	need64 = need;
	uint64_t	used64 = strtbl->used;
	uint64_t	size64 = strtbl->size;
	uint64_t	target = need64 + used64;

	int		sys32, tbl32;

	if (target <= size64)
		return;

	/*
	 * Detect 32-bit system. We might usually do this with the preprocessor,
	 * but it can serve as a predicate in tests that also apply to 64-bit
	 * systems.
	 */
	sys32 = (sizeof (size_t) == 4);

	/*
	 * The symbol string table can be larger than 32-bits on a 64-bit
	 * system. However, the long name table must stay below that limit.
	 * The reason for this is that there is not enough room in the ar_name
	 * field of the member header to represent 64-bit offsets.
	 */
	tbl32 = (strtbl == &long_strtbl);

	/*
	 * If request is larger than 4GB and we can't do it because we
	 * are a 32-bit program, or because the table is format limited,
	 * we can go no further.
	 */
	if ((target > 0xffffffff) && (sys32 || tbl32))
		goto limit_fail;

	/* Default starting size */
	if (strtbl->base == NULL)
		size64 = STRTBL_INITSZ;

	/*
	 * Our strategy is to double the size until we find a size that
	 * exceeds the request. However, if this table cannot exceed 4GB,
	 * then once we exceed 2GB, we switch to a strategy of taking the
	 * current request and rounding it up to STRTBL_INITSZ.
	 */
	while (target > size64) {
		if ((target > 0x7fffffff) && (sys32 || tbl32)) {
			size64 = ((target + STRTBL_INITSZ) / STRTBL_INITSZ) *
			    STRTBL_INITSZ;

			/*
			 * If we are so close to the line that this small
			 * increment exceeds 4GB, give it up.
			 */
			if ((size64 > 0xffffffff) && (sys32 || tbl32))
				goto limit_fail;

			break;
		}

		size64 *= 2;
	}

	strtbl->base = realloc(strtbl->base, size64);
	if (strtbl->base == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_MALLOC), strerror(err));
		exit(1);
	}
	strtbl->size = (size_t)size64;
	return;

limit_fail:
	/*
	 * Control comes here if we are unable to allocate more than 4GB of
	 * memory for the string table due to one of the following reasons:
	 *
	 * - A 32-bit process is attempting to be larger than 4GB
	 *
	 * - A 64-bit process is attempting to grow the long names string
	 *	table beyond the ar format limit of 32-bits.
	 */
	if (sys32)
		(void) fprintf(stderr, MSG_INTL(MSG_MALLOC), strerror(ENOMEM));
	else
		(void) fprintf(stderr, MSG_INTL(MSG_ERR_LONGSTRTBLSZ));
	exit(1);

#undef STRTBL_INITSZ
}

/*
 * Add the specified number of pad characters to the end of the
 * given string table.
 *
 * entry:
 *	strtbl - String table to pad
 *	n - # of pad characters to add
 *	ch - Pad character to use
 */
static void
strtbl_pad(ARSTRTBL *strtbl, size_t n, int ch)
{
	if (n == 0)
		return;

	if ((n + strtbl->used) > strtbl->size)
		strtbl_alloc(strtbl, n);

	while (n--)
		strtbl->base[strtbl->used++] = ch;
}

/*
 * Enter a symbol name into the symbol string table.
 */
static void
savename(char *symbol)
{
	size_t need;

	need = strlen(symbol) + 1;
	if ((need + sym_strtbl.used) > sym_strtbl.size)
		strtbl_alloc(&sym_strtbl, need);

	(void) strcpy(sym_strtbl.base + sym_strtbl.used, symbol);
	sym_strtbl.used += need;
}

/*
 * Prepare an archive member with a long (>15 characters) name for
 * the output archive.
 *
 * entry:
 *	fptr - pointer to archive member with long name
 *
 * exit:
 *	The long name is entered into the long name string table,
 *	and fptr->ar_name has been replaced with the special /xxx
 *	name used to indicate that the real name is in the string table
 *	at offset xxx.
 */
static void
savelongname(ARFILE *fptr)
{
	size_t	len, need;
	char	*p;

	/* Size of new item to add */
	len = strlen(fptr->ar_longname);
	need = len + 2;

	/* Ensure there's room */
	if ((need + long_strtbl.used) > long_strtbl.size)
		strtbl_alloc(&long_strtbl, need);

	/*
	 * Generate the index string to be written into the member header
	 *
	 * This will not overflow the ar_name field because that field is
	 * 16 characters in size, and a 32-bit unsigned value can be formatted
	 * in 10 characters. Allowing a character for the leading '/', and one
	 * for the NULL termination, that leaves us with 4 extra spaces.
	 */
	(void) snprintf(fptr->ar_name, sizeof (fptr->ar_name),
	    MSG_ORIG(MSG_FMT_LLINT), EC_XWORD(long_strtbl.used));

	/*
	 * Enter long name into reserved spot, terminated with a slash
	 * and a newline character.
	 */
	p = long_strtbl.base + long_strtbl.used;
	long_strtbl.used += need;
	(void) strcpy(p, fptr->ar_longname);
	p += len;
	*p++ = '/';
	*p++ = '\n';
}

/*
 * Determine if the archive we're about to write will exceed the
 * 32-bit limit of 4GB.
 *
 * entry:
 *      mksymtab() and mklong_tab() have been called to set up
 *	the string tables.
 *
 * exit:
 *	Returns TRUE (1) if the 64-bit symbol table is needed, and
 *	FALSE (0) otherwise.
 *
 */
static int
require64(size_t nsyms, int found_obj, size_t longnames)
{
	ARFILE		*fptr;
	uint64_t	size;

	/*
	 * If there are more than 4GB symbols, we have to use
	 * the 64-bit form. Note that longnames cannot exceed 4GB
	 * because that symbol table is limited to a length of 4GB by
	 * the archive format.
	 */
	if (nsyms > 0xffffffff)
		return (1);

	/*
	 * Make a worst case estimate for the size of the resulting
	 * archive by assuming full padding between members.
	 */
	size = 	SARMAG;
	if (longnames)
		size += sizeof (struct ar_hdr) + long_strtbl.used + PADSZ;

	if (found_obj)
		size += sizeof_symtbl(nsyms, found_obj, 4) + PADSZ;

	if (size > 0xffffffff)
		return (1);

	for (fptr = listhead; fptr; fptr = fptr->ar_next) {
		size += sizeof (struct ar_hdr) + fptr->ar_size + PADSZ;

		if (size > 0xffffffff)
			return (1);
	}

	/* 32-bit symbol table will suffice */
	return (0);
}

void
writefile(Cmd_info *cmd_info)
{
	ARFILE		*fptr;
	ARFILEP		*symlist = 0;
	size_t		longnames;
	size_t		nsyms;
	int		new_archive = 0;
	char		*name = cmd_info->arnam;
	size_t		arsize;	/* Size of magic # and special members */
	size_t		symtbl_eltsize = 4;
	int		found_obj = 0;
	int		fd;
	off_t		off;
	struct stat	stbuf, ar_stbuf;
	char		pad_bytes[PADSZ];
	size_t		pad_cnt;
	int		is_elf;

	/*
	 * Gather the list of symbols and associate each one to the
	 * ARFILE descriptor of the object it belongs to. At the same
	 * time, tag each ELF object with the appropriate F_CLASSxx
	 * flag.
	 */
	nsyms = mksymtab(name, &symlist, &found_obj);

	/* Generate the string table for long member names */
	longnames = mklong_tab();

	/*
	 * Will this archive exceed 4GB? If we're a 32-bit process, we can't
	 * do it. If we're a 64-bit process, then we'll have to use a
	 * 64-bit symbol table.
	 */
	if (require64(nsyms, found_obj, longnames)) {
#ifdef _LP64
		symtbl_eltsize = 8;
#else
		(void) fprintf(stderr, MSG_INTL(MSG_TOOBIG4G));
		exit(1);
#endif
	}

	/*
	 * If the user requested it, use the 64-bit symbol table even if
	 * a 32-bit one would suffice. 32-bit tables are more portable and
	 * take up less room, so this feature is primarily for testing.
	 */
	if (cmd_info->opt_flgs & S_FLAG)
		symtbl_eltsize = 8;

	/*
	 * If the first non-special archive member is an ELF object, then we
	 * need to arrange for its data to have an alignment of PADSZ. The
	 * preceeding special member will be the symbol table, or the long
	 * name string table. We pad the string table that precedes the
	 * ELF member in order to achive the desired alignment.
	 */
	is_elf = listhead && (listhead->ar_flag & (F_CLASS32 | F_CLASS64));
	arsize = SARMAG;
	if (found_obj) {
		arsize += sizeof_symtbl(nsyms, found_obj, symtbl_eltsize);
		if (is_elf && (longnames == 0)) {
			pad_cnt = pad(arsize + sizeof (struct ar_hdr), PADSZ);
			strtbl_pad(&sym_strtbl, pad_cnt, '\0');
			arsize += pad_cnt;
		}
	}
	if (longnames > 0) {
		arsize += sizeof (struct ar_hdr) + long_strtbl.used;
		if (is_elf) {
			pad_cnt = pad(arsize + sizeof (struct ar_hdr), PADSZ);
			strtbl_pad(&long_strtbl, pad_cnt, '\0');
			arsize += pad_cnt;
		}
	}

	/*
	 * For each user visible (non-special) archive member, determine
	 * the header offset, and the size of any required padding.
	 */
	(void) sizeofmembers(arsize);

	/*
	 * Is this a new archive, or are we updating an existing one?
	 *
	 * A subtlety here is that POSIX says we are not supposed
	 * to replace a non-writable file. The only 100% reliable test
	 * against this is to open the file for non-destructive
	 * write access. If the open succeeds, we are clear to
	 * replace it, and if not, then the error generated is
	 * the error we need to report.
	 */
	if ((fd = open(name, O_RDWR)) < 0) {
		int	err = errno;

		if (err != ENOENT) {
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
			    name, strerror(err));
			exit(1);
		}
		new_archive = 1;
		if ((cmd_info->opt_flgs & c_FLAG) == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_BER_MES_CREATE),
			    cmd_info->arnam);
		}
	} else {
		/* Capture mode and owner information to apply to replacement */
		if (fstat(fd, &ar_stbuf) < 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_STAT),
			    name, strerror(err));
			(void) close(fd);
			exit(1);
		}
		(void) close(fd);
		new_archive = 0;
	}


	/*
	 * Register exit handler function to clean up after us if we exit
	 * before completing the new archive. atexit() is defined as
	 * only being able to fail due to memory exhaustion.
	 */
	if (atexit(exit_cleanup) != 0) {
		(void) fprintf(stderr, MSG_INTL(MSG_MALLOC), strerror(ENOMEM));
		exit(1);
	}

	/*
	 * If a new archive, create it in place. If updating an archive,
	 * create the replacement under a temporary name and then rename it
	 * into place.
	 */
	ar_outfile.path = new_archive ? name : make_tmpname(name);
	ar_outfile.fd = open(ar_outfile.path, O_RDWR|O_CREAT|O_LARGEFILE, 0666);
	if (ar_outfile.fd == -1) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
		    ar_outfile.path, strerror(err));
		exit(1);
	}

	/* Output magic string */
	arwrite(name, ar_outfile.fd, ARMAG, SARMAG);

	/*
	 * The symbol table member is always first if present. Note that
	 * writesymtab() uses the member offsets computed by sizeofmembers()
	 * above.
	 */
	if (found_obj)
		writesymtab(name, ar_outfile.fd, nsyms, symlist,
		    symtbl_eltsize);

	if (longnames) {
		write_member_header(name, ar_outfile.fd, 0,
		    MSG_ORIG(MSG_STR_DSLASH), time(0), 0, 0, 0,
		    long_strtbl.used);
		arwrite(name, ar_outfile.fd, long_strtbl.base,
		    long_strtbl.used);
	}

	/*
	 * The accuracy of the symbol table depends on our having calculated
	 * the size of the archive accurately to this point. If this is a
	 * debug build, verify it.
	 */
	assert(arsize == lseek(ar_outfile.fd, 0, SEEK_CUR));

#ifndef XPG4
	if (cmd_info->opt_flgs & v_FLAG) {
		(void) fprintf(stderr, MSG_INTL(MSG_BER_MES_WRITE),
		    cmd_info->arnam);
	}
#endif

	/*
	 * Fill pad_bytes array with newline characters. This array
	 * is used to supply padding bytes at the end of ELF objects.
	 * There can never be more tha PADSZ such bytes, so this number
	 * will always suffice.
	 */
	for (pad_cnt = 0; pad_cnt < PADSZ; pad_cnt++)
		pad_bytes[pad_cnt] = '\n';

	for (fptr = listhead; fptr; fptr = fptr->ar_next) {
		/*
		 * We computed the expected offset for each ELF member and
		 * used those offsets to fill the symbol table. If this is
		 * a debug build, verify that the computed offset was right.
		 */
		is_elf = (fptr->ar_flag & (F_CLASS32 | F_CLASS64)) != 0;
		assert(!is_elf ||
		    (fptr->ar_offset == lseek(ar_outfile.fd, 0, SEEK_CUR)));

		/*
		 * NOTE:
		 * The mem_header->ar_name[] is set to a NULL string
		 * if the archive member header has some error.
		 * (See elf_getarhdr() man page.)
		 * It is set to NULL for example, the ar command reads
		 * the archive files created by SunOS 4.1 system.
		 * See c block comment in cmd.c, "Incompatible Archive Header".
		 */
		if (fptr->ar_name[0] == 0) {
			fptr->ar_longname = fptr->ar_rawname;
			(void) strncpy(fptr->ar_name, fptr->ar_rawname, SNAME);
		}
		write_member_header(name, ar_outfile.fd, is_elf,
		    (strlen(fptr->ar_longname) <= (unsigned)SNAME-2) ?
		    trimslash(fptr->ar_longname) : fptr->ar_name,
		    EC_WORD(fptr->ar_date), fptr->ar_uid, fptr->ar_gid,
		    fptr->ar_mode, fptr->ar_size + fptr->ar_padding);


		if ((fptr->ar_flag & F_ELFRAW) == 0) {
			/*
			 * The file doesn't come from the archive, and is
			 * therefore not already in memory(fptr->ar_contents)
			 * so open it and do a direct file-to-file transfer of
			 * its contents. We use the sendfile() system call
			 * to make the kernel do the transfer, so we don't have
			 * to buffer data in process, and we trust that the
			 * kernel will use an optimal transfer strategy.
			 */
			if ((fd = open(fptr->ar_pathname, O_RDONLY)) == -1) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
				    fptr->ar_longname, strerror(err));
				exit(1);
			}
			if (stat(fptr->ar_pathname, &stbuf) < 0) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
				    fptr->ar_longname, strerror(err));
				(void) close(fd);
				exit(1);
			}
			off = 0;
			if (sendfile(ar_outfile.fd, fd, &off,
			    stbuf.st_size) != stbuf.st_size) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_SYS_WRITE),
				    name, strerror(err));
				exit(2);
			}
			(void) close(fd);
		} else {
			/* Archive member is in memory. Write it out */
			arwrite(name, ar_outfile.fd, fptr->ar_contents,
			    fptr->ar_size);
		}

		/*
		 * All archive members are padded to at least a boundary of 2.
		 * The expression ((fptr->ar_size & 0x1) != 0) yields 1 for
		 * odd boundaries, and 0 for even ones. To this, we add
		 * whatever padding is needed for ELF objects.
		 */
		pad_cnt = ((fptr->ar_size & 0x1) != 0) + fptr->ar_padding;
		if (pad_cnt > 0)
			arwrite(name, ar_outfile.fd, pad_bytes, pad_cnt);
	}

	/*
	 * All archive output is done.
	 */
	if (close(ar_outfile.fd) < 0) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_CLOSE), ar_outfile.path,
		    strerror(err));
		exit(1);
	}
	ar_outfile.fd = -1;	/* Prevent removal on exit */
	(void) elf_end(cmd_info->arf);
	(void) close(cmd_info->afd);

	/*
	 * If updating an existing archive, rename the new version on
	 * top of the original.
	 */
	if (!new_archive) {
		/*
		 * Prevent the replacement of the original archive from
		 * being interrupted, to lower the possibility of an
		 * interrupt destroying a pre-existing archive.
		 */
		establish_sighandler(SIG_IGN);

		if (rename(ar_outfile.path, name) < 0) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_RENAME),
			    ar_outfile.path, name, strerror(err));
			(void) unlink(ar_outfile.path);
			exit(1);
		}
		(void) chmod(name, ar_stbuf.st_mode & 0777);
		if (chown(name, ar_stbuf.st_uid, ar_stbuf.st_gid) >= 0)
			(void) chmod(name, ar_stbuf.st_mode & 07777);

	}
}

/*
 * Examine all the archive members, enter any member names longer than
 * 15 characters into the long name string table, and count the number
 * of names found.
 *
 * Returns the size of the resulting archive member, including the
 * member header.
 */
static size_t
mklong_tab(void)
{
	ARFILE  *fptr;
	size_t longnames = 0;

	for (fptr = listhead; fptr; fptr = fptr->ar_next) {
		if (strlen(fptr->ar_longname) >= (unsigned)SNAME-1) {
			longnames++;
			savelongname(fptr);
		}
	}

	/* round up table that keeps the long filenames */
	if (longnames > 0)
		strtbl_pad(&long_strtbl, pad(long_strtbl.used, 4), '\n');

	return (longnames);
}

/*
 * Write 32/64-bit words into buffer in archive symbol table
 * standard byte order (MSB).
 */
static char *
sputl32(uint32_t n, char *cp)
{
	*cp++ = n >> 24;
	*cp++ = n >> 16;
	*cp++ = n >> 8;

	*cp++ = n & 255;

	return (cp);
}

static char *
sputl64(uint64_t n, char *cp)
{
	*cp++ = n >> 56;
	*cp++ = n >> 48;
	*cp++ = n >> 40;
	*cp++ = n >> 32;

	*cp++ = n >> 24;
	*cp++ = n >> 16;
	*cp++ = n >> 8;

	*cp++ = n & 255;

	return (cp);
}

static int
search_sym_tab(const char *arname, ARFILE *fptr, Elf *elf, Elf_Scn *scn,
	size_t *nsyms, ARFILEP **symlist, size_t *num_errs)
{
	Elf_Data *str_data, *sym_data; /* string table, symbol table */
	Elf_Scn *str_scn;
	GElf_Sxword no_of_symbols;
	GElf_Shdr shdr;
	int counter;
	int str_shtype;
	char *symname;
	static ARFILEP *sym_ptr = 0;
	static ARFILEP *nextsym = NULL;
	static int syms_left = 0;
	char *fname = fptr->ar_pathname;

	(void) gelf_getshdr(scn, &shdr);
	str_scn = elf_getscn(elf, shdr.sh_link); /* index for string table */
	if (str_scn == NULL) {
		if (fname != NULL)
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETDATA_FILE),
			    fname, elf_errmsg(-1));
		else
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETDATA_AR),
			    arname, fptr->ar_longname, elf_errmsg(-1));
		(*num_errs)++;
		return (-1);
	}

	no_of_symbols = shdr.sh_size / shdr.sh_entsize;
	if (no_of_symbols == -1) {
		(void) fprintf(stderr, MSG_INTL(MSG_SYMTAB_01));
		return (-1);
	}

	(void) gelf_getshdr(str_scn, &shdr);
	str_shtype = shdr.sh_type;
	if (str_shtype == -1) {
		if (fname != NULL)
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETDATA_FILE),
			    fname, elf_errmsg(-1));
		else
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_GETDATA_AR),
			    arname, fptr->ar_longname, elf_errmsg(-1));
		(*num_errs)++;
		return (-1);
	}

	/* This test must happen before testing the string table. */
	if (no_of_symbols == 1)
		return (0);	/* no symbols; 0th symbol is the non-symbol */

	if (str_shtype != SHT_STRTAB) {
		if (fname != NULL)
			(void) fprintf(stderr, MSG_INTL(MSG_SYMTAB_NOSTR_FILE),
			    fname);
		else
			(void) fprintf(stderr, MSG_INTL(MSG_SYMTAB_NOSTR_AR),
			    arname, fptr->ar_longname);
		return (0);
	}
	str_data = 0;
	if ((str_data = elf_getdata(str_scn, str_data)) == 0) {
		if (fname != NULL)
			(void) fprintf(stderr, MSG_INTL(MSG_SYMTAB_NODAT_FILE),
			    fname);
		else
			(void) fprintf(stderr, MSG_INTL(MSG_SYMTAB_NODAT_AR),
			    arname, fptr->ar_longname);
		return (0);
	}
	if (str_data->d_size == 0) {
		if (fname != NULL)
			(void) fprintf(stderr, MSG_INTL(MSG_SYMTAB_ZDAT_FILE),
			    fname);
		else
			(void) fprintf(stderr, MSG_INTL(MSG_SYMTAB_ZDAT_AR),
			    arname, fptr->ar_longname);
		return (0);
	}
	sym_data = 0;
	if ((sym_data = elf_getdata(scn, sym_data)) == NULL) {
		if (fname != NULL)
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_LIB_FILE),
			    fname, elf_errmsg(-1));
		else
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_LIB_AR),
			    arname, fptr->ar_longname, elf_errmsg(-1));
		return (0);
	}

	/* start at 1, first symbol entry is ignored */
	for (counter = 1; counter < no_of_symbols; counter++) {
		GElf_Sym sym;
		(void) gelf_getsym(sym_data, counter, &sym);

		symname = (char *)(str_data->d_buf) + sym.st_name;

		if (((GELF_ST_BIND(sym.st_info) == STB_GLOBAL) ||
		    (GELF_ST_BIND(sym.st_info) == STB_WEAK)) &&
		    (sym.st_shndx != SHN_UNDEF)) {
			if (!syms_left) {
				sym_ptr = malloc((SYMCHUNK+1)
				    * sizeof (ARFILEP));
				if (sym_ptr == NULL) {
					int err = errno;
					(void) fprintf(stderr,
					    MSG_INTL(MSG_MALLOC),
					    strerror(err));
					exit(1);
				}
				syms_left = SYMCHUNK;
				if (nextsym)
					*nextsym = (ARFILEP)sym_ptr;
				else
					*symlist = sym_ptr;
				nextsym = sym_ptr;
			}
			sym_ptr = nextsym;
			nextsym++;
			syms_left--;
			(*nsyms)++;
			*sym_ptr = fptr;
			savename(symname);	/* put name in the archiver's */
						/* symbol table string table */
		}
	}
	return (0);
}

/*
 * Get the output file size
 */
static size_t
sizeofmembers(size_t psum)
{
	size_t	sum = 0;
	ARFILE	*fptr;
	size_t	hdrsize = sizeof (struct ar_hdr);

	for (fptr = listhead; fptr; fptr = fptr->ar_next) {
		fptr->ar_offset = psum + sum;
		sum += fptr->ar_size;
		if (fptr->ar_size & 01)
			sum++;
		sum += hdrsize;

		/*
		 * If the current item, and the next item are both ELF
		 * objects, then add padding to current item so that the
		 * data in the next item will have PADSZ alignment.
		 *
		 * In any other case, set the padding to 0. If the
		 * item comes from another archive, it may be carrying
		 * a non-zero padding value from that archive that does
		 * not apply to the one we are about to build.
		 */
		if ((fptr->ar_flag & (F_CLASS32 | F_CLASS64)) &&
		    fptr->ar_next &&
		    (fptr->ar_next->ar_flag & (F_CLASS32 | F_CLASS64))) {
			fptr->ar_padding = pad(psum + sum + hdrsize, PADSZ);
			sum += fptr->ar_padding;
		} else {
			fptr->ar_padding = 0;
		}
	}
	return (sum);
}

/*
 * Compute the size of the symbol table archive member.
 *
 * entry:
 *	nsyms - # of symbols in the table
 *	found_obj - TRUE if the archive contains any ELF objects
 *	eltsize - Size of the integer type to use for the symbol
 *		table. 4 for 32-bit tables, and 8 for 64-bit tables.
 */
static size_t
sizeof_symtbl(size_t nsyms, int found_obj, size_t eltsize)
{
	size_t sum = 0;

	if (found_obj) {
		/* Member header, symbol count, and one slot per symbol */
		sum += sizeof (struct ar_hdr) + ((nsyms + 1) * eltsize);
		sum += sym_strtbl.used;
	}

	return (sum);
}

static void
arwrite(const char *name, int nfd, const char *dst, size_t size) {
	if (write(nfd, dst, size) != size) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_WRITE),
		    name, strerror(err));
		exit(2);
	}
}

static const char *
make_tmpname(const char *filename) {
	char	*slash, *tmpname;
	size_t	prefix_cnt = 0;

	/*
	 * If there is a path prefix in front of the filename, we
	 * want to put the temporary file in the same directory.
	 * Determine the length of the path.
	 */
	slash = strrchr(filename, '/');
	if (slash != NULL)
		prefix_cnt = slash - filename + 1;
	tmpname = malloc(prefix_cnt + MSG_STR_MKTEMP_SIZE + 1);
	if (tmpname == NULL) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_MALLOC), strerror(err));
		exit(1);
	}

	if (prefix_cnt > 0)
		(void) strncpy(tmpname, filename, prefix_cnt);
	(void) strcpy(tmpname + prefix_cnt, MSG_ORIG(MSG_STR_MKTEMP));
	(void) mktemp(tmpname);

	return (tmpname);
}
