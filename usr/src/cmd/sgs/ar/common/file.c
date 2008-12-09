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
 *	Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 */

#include "gelf.h"
#include "inc.h"
#include "extern.h"

static char *str_base;	/* start of string table for names */
static char *str_top;	/* pointer to next available location */
static char *str_base1, *str_top1;
static int pad_symtab;	/* # of bytes by which to pad symbol table */


/*
 * The ar file format requires objects to be padded to an even size.
 * We do that, but it turns out to be beneficial to go farther.
 *
 * ld(1) accesses archives by mmapping them into memory. If the mapped
 * objects have the proper alignment, we can access them directly. If the
 * alignment is wrong, libelf "slides" them so that they are also accessible.
 * This  is expensive in time (to copy memory) and space (it causes swap
 * to be allocated by the system to back the now-modified pages). Hence, we
 * really want to ensure that the alignment is right.
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
 * Function Prototypes
 */
static long mklong_tab(int *);
static char *trimslash(char *s);

static long mksymtab(ARFILEP **, int *);
static int writesymtab(char *, long, ARFILEP *);
static void savename(char *);
static void savelongname(ARFILE *, char *);
static void sputl(long, char *);

static char *writelargefile(Cmd_info *cmd_info, long long_tab_size,
    int longnames, ARFILEP *symlist, long nsyms, int found_obj,
    int new_archive);

static int sizeofmembers();
static int sizeofnewarchive(int, int);

static int search_sym_tab(ARFILE *, Elf *, Elf_Scn *,
	long *, ARFILEP **, int *);


int
getaf(Cmd_info *cmd_info)
{
	Elf_Cmd cmd;
	int fd;
	char *arnam = cmd_info->arnam;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		error_message(ELF_VERSION_ERROR,
		    LIBELF_ERROR, elf_errmsg(-1));
		exit(1);
	}

	if ((cmd_info->afd = fd = open(arnam, O_RDONLY)) == -1) {
		if (errno == ENOENT) {
			/* archive does not exist yet, may have to create one */
			return (fd);
		} else {
			/* problem other than "does not exist" */
			error_message(SYS_OPEN_ERROR,
			    SYSTEM_ERROR, strerror(errno), arnam);
			exit(1);
		}
	}

	cmd = ELF_C_READ;
	cmd_info->arf = elf_begin(fd, cmd, (Elf *)0);

	if (elf_kind(cmd_info->arf) != ELF_K_AR) {
		error_message(NOT_ARCHIVE_ERROR,
		    PLAIN_ERROR, (char *)0, arnam);
		if (opt_FLAG(cmd_info, a_FLAG) || opt_FLAG(cmd_info, b_FLAG))
			error_message(USAGE_06_ERROR,
			    PLAIN_ERROR, (char *)0, cmd_info->ponam);
		exit(1);
	}
	return (fd);
}

/*
 * Given a size, return the number of bytes required to round it
 * up to the next PADSZ boundary.
 */
static int
pad(int n)
{
	int r;

	r = n % PADSZ;
	if (r)
		r = PADSZ - r;

	return (r);
}

/*
 * If the current archive item is an object, then ar(1) may have added
 * newline padding at the end in order to bring the following object
 * into PADSZ alignment within the file. This padding cannot be
 * distinguished from data using the information kept in the ar headers.
 * This routine examines the objects, using knowledge of
 * ELF and how our tools lay out objects to determine whether padding was
 * added to an archive item. If so, it adjusts the st_size and
 * st_padding fields of the file argument to reflect it.
 */
static void
recover_padding(Elf *elf, ARFILE *file)
{
	long extent;
	long padding;
	GElf_Ehdr ehdr;


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
	extent = gelf_getehdr(elf, &ehdr)
	    ? (ehdr.e_shoff + (ehdr.e_shnum * ehdr.e_shentsize)) : 0;
	padding = file->ar_size - extent;

	if ((padding < 0) || (padding >= PADSZ)) {
		/*
		 * The section header array is not at the end of the object.
		 * Traverse the section headers and look for the one with
		 * the highest used address. If this address is within
		 * PADSZ bytes of ar_size, then this is the end of the object.
		 */
		Elf_Scn *scn = 0;

		do {
			scn = elf_nextscn(elf, scn);
			if (scn) {
				GElf_Shdr shdr;

				if (gelf_getshdr(scn, &shdr)) {
					long t = shdr.sh_offset + shdr.sh_size;
					if (t > extent)
						extent = t;
				}
			}
		} while (scn);
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
	if ((padding > 0) && (padding < PADSZ)) {
		if (file->ar_contents) {
			long cnt = padding;
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

ARFILE *
getfile(Cmd_info *cmd_info)
{
	Elf_Arhdr *mem_header;
	ARFILE	*file;
	char *tmp_rawname, *file_rawname;
	Elf *elf;
	char *arnam = cmd_info->arnam;
	int fd = cmd_info->afd;
	Elf *arf = cmd_info->arf;

	if (fd == -1)
		return (NULL); /* the archive doesn't exist */

	if ((elf = elf_begin(fd, ELF_C_READ, arf)) == 0)
		return (NULL);  /* the archive is empty or have hit the end */

	if ((mem_header = elf_getarhdr(elf)) == NULL) {
		error_message(ELF_MALARCHIVE_ERROR,
		    LIBELF_ERROR, elf_errmsg(-1),
		    arnam, elf_getbase(elf));
		exit(1);
	}

	/* zip past special members like the symbol and string table members */

	while (strncmp(mem_header->ar_name, "/", 1) == 0 ||
	    strncmp(mem_header->ar_name, "//", 2) == 0) {
		(void) elf_next(elf);
		(void) elf_end(elf);
		if ((elf = elf_begin(fd, ELF_C_READ, arf)) == 0)
			return (NULL);
			/* the archive is empty or have hit the end */
		if ((mem_header = elf_getarhdr(elf)) == NULL) {
			error_message(ELF_MALARCHIVE_ERROR,
			    LIBELF_ERROR, elf_errmsg(-1),
			    arnam, elf_getbase(elf));
			exit(0);
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

	if ((file->ar_longname
	    = malloc(strlen(mem_header->ar_name) + 1))
	    == NULL) {
		error_message(MALLOC_ERROR,
		    PLAIN_ERROR, (char *)0);
		exit(1);
	}
	(void) strcpy(file->ar_longname, mem_header->ar_name);
	if ((file->ar_rawname
	    = malloc(strlen(mem_header->ar_rawname) + 1))
	    == NULL) {
		error_message(MALLOC_ERROR,
		    PLAIN_ERROR, (char *)0);
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
	if (!(opt_FLAG(cmd_info, t_FLAG) && !opt_FLAG(cmd_info, s_FLAG))) {
		size_t ptr;
		file->ar_flag = F_ELFRAW;
		if ((file->ar_contents = elf_rawfile(elf, &ptr))
		    == NULL) {
			if (ptr != 0) {
				error_message(ELF_RAWFILE_ERROR,
				    LIBELF_ERROR, elf_errmsg(-1));
				exit(1);
			}
		}
		file->ar_elf = elf;
	}

	recover_padding(elf, file);

	(void) elf_next(elf);
	return (file);
}

ARFILE *
newfile(void)
{
	static ARFILE	*buffer =  NULL;
	static int	count = 0;
	ARFILE	*fileptr;

	if (count == 0) {
		if ((buffer = (ARFILE *) calloc(CHUNK, sizeof (ARFILE)))
		    == NULL) {
			error_message(MALLOC_ERROR,
			    PLAIN_ERROR, (char *)0);
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
	return (strcat(buf, "/"));
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


static long
mksymtab(ARFILEP **symlist, int *found_obj)
{
	ARFILE	*fptr;
	long	mem_offset = 0;
	Elf *elf;
	Elf_Scn	*scn;
	GElf_Ehdr ehdr;
	int newfd;
	long nsyms = 0;
	int class = 0;
	Elf_Data *data;
	int num_errs = 0;

	newfd = 0;
	for (fptr = listhead; fptr; fptr = fptr->ar_next) {
		/* determine if file is coming from the archive or not */
		if ((fptr->ar_elf != 0) && (fptr->ar_pathname == NULL)) {
			/*
			 * I can use the saved elf descriptor.
			 */
			elf = fptr->ar_elf;
		} else if ((fptr->ar_elf == 0) &&
		    (fptr->ar_pathname != NULL)) {
			if ((newfd  =
			    open(fptr->ar_pathname, O_RDONLY)) == -1) {
				error_message(SYS_OPEN_ERROR,
				    SYSTEM_ERROR, strerror(errno),
				    fptr->ar_pathname);
				num_errs++;
				continue;
			}

			if ((elf = elf_begin(newfd,
			    ELF_C_READ, (Elf *)0)) == 0) {
				if (fptr->ar_pathname != NULL)
					error_message(ELF_BEGIN_02_ERROR,
					    LIBELF_ERROR, elf_errmsg(-1),
					    fptr->ar_pathname);
				else
					error_message(ELF_BEGIN_03_ERROR,
					    LIBELF_ERROR, elf_errmsg(-1));
				(void) close(newfd);
				newfd = 0;
				num_errs++;
				continue;
			}
			if (elf_kind(elf) == ELF_K_AR) {
				if (fptr->ar_pathname != NULL)
					error_message(ARCHIVE_IN_ARCHIVE_ERROR,
					    PLAIN_ERROR, (char *)0,
					    fptr->ar_pathname);
				else
					error_message(ARCHIVE_USAGE_ERROR,
					    PLAIN_ERROR, (char *)0);
				if (newfd) {
					(void) close(newfd);
					newfd = 0;
				}
				(void) elf_end(elf);
				continue;
			}
		} else {
			error_message(INTERNAL_01_ERROR,
			    PLAIN_ERROR, (char *)0);
			exit(1);
		}
		if (gelf_getehdr(elf, &ehdr) != 0) {
			if ((class = gelf_getclass(elf)) == ELFCLASS64) {
				fptr->ar_flag |= F_CLASS64;
			} else if (class == ELFCLASS32)
				fptr->ar_flag |= F_CLASS32;
			scn = elf_getscn(elf, ehdr.e_shstrndx);
			if (scn == NULL) {
				if (fptr->ar_pathname != NULL)
					error_message(ELF_GETSCN_01_ERROR,
					    LIBELF_ERROR, elf_errmsg(-1),
					    fptr->ar_pathname);
				else
					error_message(ELF_GETSCN_02_ERROR,
					    LIBELF_ERROR, elf_errmsg(-1));
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
					error_message(ELF_GETDATA_01_ERROR,
					    LIBELF_ERROR, elf_errmsg(-1),
					    fptr->ar_pathname);
				else
					error_message(ELF_GETDATA_02_ERROR,
					    LIBELF_ERROR, elf_errmsg(-1));
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
					error_message(W_ELF_NO_DATA_01_ERROR,
					    PLAIN_ERROR, (char *)0,
					    fptr->ar_pathname);
				else
					error_message(W_ELF_NO_DATA_02_ERROR,
					    PLAIN_ERROR, (char *)0);
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
					if (fptr->ar_pathname != NULL)
						error_message(
						    ELF_GETDATA_01_ERROR,
						    LIBELF_ERROR,
						    elf_errmsg(-1),
						    fptr->ar_pathname);
					else
						error_message(
						    ELF_GETDATA_02_ERROR,
						    LIBELF_ERROR,
						    elf_errmsg(-1));
					if (newfd) {
						(void) close(newfd);
						newfd = 0;
					}
					num_errs++;
					(void) elf_end(elf);
					continue;
				}
				*found_obj = 1;
				if (shdr.sh_type == SHT_SYMTAB)
					if (search_sym_tab(fptr, elf,
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
		mem_offset += sizeof (struct ar_hdr) + fptr->ar_size;
		if (fptr->ar_size & 01)
			mem_offset++;
		(void) elf_end(elf);
		if (newfd) {
			(void) close(newfd);
			newfd = 0;
		}
	} /* for */
	if (num_errs)
		exit(1);
	return (nsyms);
}

/*
 * This routine writes an archive symbol table for the
 * output archive file. The symbol table is built if
 * there was at least one object file specified.
 * In rare case, there could be no symbol.
 * In this case, str_top and str_base can not be used to
 * make the string table. So the routine adjust the size
 * and make a dummy string table. String table is needed
 * by elf_getarsym().
 */
static int
writesymtab(char *dst, long nsyms, ARFILEP *symlist)
{
	char	buf1[sizeof (struct ar_hdr) + 1];
	char	*buf2, *bptr;
	int	i, j;
	ARFILEP	*ptr;
	long	sym_tab_size = 0;
	int sum = 0;

	/*
	 * patch up archive pointers and write the symbol entries
	 */
	while ((str_top - str_base) & 03)	/* round up string table */
		*str_top++ = '\0';
	sym_tab_size = (nsyms +1) * 4 + sizeof (char) * (str_top - str_base);
	if (nsyms == 0)
		sym_tab_size += 4;
	sym_tab_size += pad_symtab;

	(void) sprintf(buf1, FORMAT, SYMDIRNAME, time(0), (unsigned)0,
	    (unsigned)0, (unsigned)0, (long)sym_tab_size, ARFMAG);

	if (strlen(buf1) != sizeof (struct ar_hdr)) {
		error_message(INTERNAL_02_ERROR);
		exit(1);
	}

	if ((buf2 = malloc(4 * (nsyms + 1))) == NULL) {
		error_message(MALLOC_ERROR);
		error_message(DIAG_01_ERROR, errno);
		exit(1);
	}
	sputl(nsyms, buf2);
	bptr = buf2 + 4;

	for (i = 0, j = SYMCHUNK, ptr = symlist; i < nsyms; i++, j--, ptr++) {
		if (!j) {
			j = SYMCHUNK;
			ptr = (ARFILEP *)*ptr;
		}
		sputl((*ptr)->ar_offset, bptr);
		bptr += 4;
	}
	(void) memcpy(dst, buf1, sizeof (struct ar_hdr));
	dst += sizeof (struct ar_hdr);
	sum += sizeof (struct ar_hdr);

	(void) memcpy(dst, buf2, (nsyms + 1) * 4);
	dst += (nsyms + 1)*4;
	sum += (nsyms + 1)*4;

	if (nsyms != 0) {
		(void) memcpy(dst, str_base, (str_top - str_base));
		dst += str_top - str_base;
		sum += str_top - str_base;
	} else {
		/*
		 * Writing a dummy string table.
		 */
		int i;
		for (i = 0; i < 4; i++)
			*dst++ = 0;
		sum += 4;
	}

	/*
	 * The first member file is an ELF object. We need to make
	 * sure it will be placed at the PADSZ byte boundary.
	 */
	if (pad_symtab) {
		int i;
		for (i = 0; i < pad_symtab; i++)
			*dst++ = 0;
		sum += pad_symtab;
	}

	free(buf2);
	return (sum);
}

static void
savename(char *symbol)
{
	static int str_length = BUFSIZ * 5;
	char *p, *s;
	unsigned int i;
	int diff;

	diff = 0;
	if (str_base == (char *)0) {
		/* no space allocated yet */
		if ((str_base = malloc((unsigned)str_length)) == NULL) {
			error_message(MALLOC_ERROR,
			    PLAIN_ERROR, (char *)0);
			exit(1);
		}
		str_top = str_base;
	}

	p = str_top;
	str_top += strlen(symbol) + 1;

	if (str_top > str_base + str_length) {
		char *old_base = str_base;

		do
			str_length += BUFSIZ * 2;
		while (str_top > str_base + str_length)
			;
		if ((str_base = (char *)realloc(str_base, str_length)) ==
		    NULL) {
			error_message(MALLOC_ERROR,
			    PLAIN_ERROR, (char *)0);
			exit(1);
		}
		/*
		 * Re-adjust other pointers
		 */
		diff = str_base - old_base;
		p += diff;
	}
	for (i = 0, s = symbol; i < strlen(symbol) && *s != '\0'; i++) {
		*p++ = *s++;
	}
	*p++ = '\0';
	str_top = p;
}

static void
savelongname(ARFILE *fptr, char *ptr_index)
{
	static int str_length = BUFSIZ * 5;
	char *p, *s;
	unsigned int i;
	int diff;
	static int bytes_used;
	int index;
	char	ptr_index1[SNAME-1];

	diff = 0;
	if (str_base1 == (char *)0) {
		/* no space allocated yet */
		if ((str_base1 = malloc((unsigned)str_length))
		    == NULL) {
			error_message(MALLOC_ERROR,
			    PLAIN_ERROR, (char *)0);
			exit(1);
		}
		str_top1 = str_base1;
	}

	p = str_top1;
	str_top1 += strlen(fptr->ar_longname) + 2;

	index = bytes_used;
	(void) sprintf(ptr_index1, "%d", index); /* holds digits */
	(void) sprintf(ptr_index, FNFORMAT, SYMDIRNAME);
	ptr_index[1] = '\0';
	(void) strcat(ptr_index, ptr_index1);
	(void) strcpy(fptr->ar_name, ptr_index);
	bytes_used += strlen(fptr->ar_longname) + 2;

	if (str_top1 > str_base1 + str_length) {
		char *old_base = str_base1;

		do
			str_length += BUFSIZ * 2;
		while (str_top1 > str_base1 + str_length)
			;
		if ((str_base1 = (char *)realloc(str_base1, str_length))
		    == NULL) {
			error_message(MALLOC_ERROR,
			    PLAIN_ERROR, (char *)0);
			exit(1);
		}
		/*
		 * Re-adjust other pointers
		 */
		diff = str_base1 - old_base;
		p += diff;
	}
	for (i = 0, s = fptr->ar_longname;
	    i < strlen(fptr->ar_longname) && *s != '\0'; i++) {
		*p++ = *s++;
	}
	*p++ = '/';
	*p++ = '\n';
	str_top1 = p;
}

char *
writefile(Cmd_info *cmd_info)
{
	ARFILE	* fptr;
	ARFILEP *symlist = 0;
	int i;
	int longnames = 0;
	long long_tab_size = 0;
	long nsyms;
	int new_archive = 0;
	char *name = cmd_info->arnam;
	int arsize;
	char *dst;
	char *tmp_dst;
	int nfd;
	int found_obj = 0;

	long_tab_size = mklong_tab(&longnames);
	nsyms = mksymtab(&symlist, &found_obj);

	for (i = 0; signum[i]; i++)
		/* started writing, cannot interrupt */
		(void) signal(signum[i], SIG_IGN);


	/* Is this a new archive? */
	if ((access(cmd_info->arnam,  0)  < 0) && (errno == ENOENT)) {
		new_archive = 1;
		if (!opt_FLAG(cmd_info, c_FLAG)) {
			error_message(BER_MES_CREATE_ERROR,
			    PLAIN_ERROR, (char *)0, cmd_info->arnam);
		}
	} else
		new_archive = 0;

	/*
	 * Calculate the size of the new archive
	 */
	arsize = sizeofnewarchive(nsyms, longnames);

	/*
	 * Dummy symtab ?
	 */
	if (nsyms == 0 && found_obj != 0)
		/*
		 * 4 + 4 = First 4 bytes to keep the number of symbols.
		 *	   The second 4 bytes for string table.
		 */
		arsize += sizeof (struct ar_hdr) + 4 + 4;

	if (arsize > AR_MAX_BYTES_IN_MEM) {
		tmp_dst = dst = NULL;
	} else {
		tmp_dst = dst = malloc(arsize);
	}
	if (dst == NULL) {
		return writelargefile(cmd_info, long_tab_size,
		    longnames, symlist, nsyms, found_obj, new_archive);
	}

	(void) memcpy(tmp_dst, ARMAG, SARMAG);
	tmp_dst += SARMAG;

	if (nsyms || found_obj != 0) {
		int diff;
		diff = writesymtab(tmp_dst, nsyms, symlist);
		tmp_dst += diff;
	}

	if (longnames) {
		(void) sprintf(tmp_dst, FORMAT, LONGDIRNAME, time(0),
		    (unsigned)0, (unsigned)0, (unsigned)0,
		    (long)long_tab_size, ARFMAG);
		tmp_dst += sizeof (struct ar_hdr);
		(void) memcpy(tmp_dst, str_base1, str_top1 - str_base1);
		tmp_dst += str_top1 - str_base1;
	}
	for (fptr = listhead; fptr; fptr = fptr->ar_next) {

	/*
	 * NOTE:
	 *	The mem_header->ar_name[] is set to a NULL string
	 *	if the archive member header has some error.
	 *	(See elf_getarhdr() man page.)
	 *	It is set to NULL for example, the ar command reads
	 *	the archive files created by SunOS 4.1 system.
	 *	See c block comment in cmd.c, "Incompatible Archive Header".
	 */
		if (fptr->ar_name[0] == 0) {
			fptr->ar_longname = fptr->ar_rawname;
			(void) strncpy(fptr->ar_name, fptr->ar_rawname, SNAME);
		}
		if (strlen(fptr->ar_longname) <= (unsigned)SNAME-2)
			(void) sprintf(tmp_dst, FNFORMAT,
			    trimslash(fptr->ar_longname));
		else
			(void) sprintf(tmp_dst, FNFORMAT, fptr->ar_name);
		(void) sprintf(tmp_dst+16, TLFORMAT, fptr->ar_date,
		    (unsigned)fptr->ar_uid, (unsigned)fptr->ar_gid,
		    (unsigned)fptr->ar_mode, fptr->ar_size + fptr->ar_padding,
		    ARFMAG);

		tmp_dst += sizeof (struct ar_hdr);

		if (!(fptr->ar_flag & F_MALLOCED) &&
		    !(fptr->ar_flag & F_MMAPED) &&
		    !(fptr->ar_flag & F_ELFRAW)) {
		/* file was not read in fptr->ar_contents during 'cmd' */
		/* do it now */
			FILE *f;
			f = fopen(fptr->ar_pathname, "r");
			if (f == NULL) {
				error_message(SYS_OPEN_ERROR,
				    SYSTEM_ERROR, strerror(errno),
				    fptr->ar_longname);
				exit(1);
			} else {
				if (fread(tmp_dst, sizeof (char),
				    fptr->ar_size, f) != fptr->ar_size) {
					error_message(SYS_READ_ERROR,
					    SYSTEM_ERROR, strerror(errno),
					    fptr->ar_longname);
					exit(1);
				}
			}
			(void) fclose(f);
		} else {
			(void) memcpy(tmp_dst, fptr->ar_contents,
			    fptr->ar_size);
			if (fptr->ar_flag & F_MALLOCED) {
				(void) free(fptr->ar_contents);
				fptr->ar_flag &= ~(F_MALLOCED);
			}
		}
		tmp_dst += fptr->ar_size;

		if (fptr->ar_size & 0x1) {
			(void) memcpy(tmp_dst, "\n", 1);
			tmp_dst++;
		}

		if (fptr->ar_padding) {
			int i = fptr->ar_padding;
			while (i) {
				*tmp_dst++ = '\n';
				--i;
			}
		}
	}

	/*
	 * All preparation for writing is done.
	 */
	(void) elf_end(cmd_info->arf);
	(void) close(cmd_info->afd);

	/*
	 * Write out to the file
	 */
	if (new_archive) {
		/*
		 * create a new file
		 */
		nfd = creat(name, 0666);
		if (nfd == -1) {
			error_message(SYS_CREATE_01_ERROR,
			    SYSTEM_ERROR, strerror(errno), name);
			exit(1);
		}
	} else {
		/*
		 * Open the new file
		 */
		nfd = open(name, O_RDWR|O_TRUNC);
		if (nfd == -1) {
			error_message(SYS_WRITE_02_ERROR,
			    SYSTEM_ERROR, strerror(errno), name);
			exit(1);
		}
	}
#ifndef XPG4
	if (opt_FLAG(cmd_info, v_FLAG)) {
		error_message(BER_MES_WRITE_ERROR,
		    PLAIN_ERROR, (char *)0, cmd_info->arnam);
	}
#endif
	if (write(nfd, dst, arsize) != arsize) {
		error_message(SYS_WRITE_04_ERROR,
		    SYSTEM_ERROR, strerror(errno), name);
		if (!new_archive)
			error_message(WARN_USER_ERROR,
			    PLAIN_ERROR, (char *)0);
		exit(2);
	}
	return (dst);
}

static long
mklong_tab(int *longnames)
{
	ARFILE  *fptr;
	char ptr_index[SNAME+1];
	long ret = 0;

	for (fptr = listhead; fptr; fptr = fptr->ar_next) {
		if (strlen(fptr->ar_longname) >= (unsigned)SNAME-1) {
			(*longnames)++;
			savelongname(fptr, ptr_index);
			(void) strcpy(fptr->ar_name, ptr_index);
		}
	}
	if (*longnames) {
		/* round up table that keeps the long filenames */
		while ((str_top1 - str_base1) & 03)
			*str_top1++ = '\n';
		ret = sizeof (char) * (str_top1 - str_base1);
	}
	return (ret);
}

/* Put bytes in archive header in machine independent order.  */

static void
sputl(long n, char *cp)
{
	*cp++ = n >> 24;
	*cp++ = n >> 16;
	*cp++ = n >> 8;

	*cp++ = n & 255;
}

static int
search_sym_tab(ARFILE *fptr, Elf *elf, Elf_Scn *scn,
	long *nsyms, ARFILEP **symlist, int *num_errs)
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
			error_message(ELF_GETDATA_01_ERROR,
			    LIBELF_ERROR, elf_errmsg(-1),
			    fname);
		else
			error_message(ELF_GETDATA_02_ERROR,
			    LIBELF_ERROR, elf_errmsg(-1));
		(*num_errs)++;
		return (-1);
	}

	no_of_symbols = shdr.sh_size / shdr.sh_entsize;
	if (no_of_symbols == -1) {
		error_message(SYMTAB_01_ERROR,
		    PLAIN_ERROR, (char *)0);
		return (-1);
	}

	(void) gelf_getshdr(str_scn, &shdr);
	str_shtype = shdr.sh_type;
	if (str_shtype == -1) {
		if (fname != NULL)
			error_message(ELF_GETDATA_01_ERROR,
			    LIBELF_ERROR, elf_errmsg(-1), fname);
		else
			error_message(ELF_GETDATA_02_ERROR,
			    LIBELF_ERROR, elf_errmsg(-1));
		(*num_errs)++;
		return (-1);
	}

	/* This test must happen before testing the string table. */
	if (no_of_symbols == 1)
		return (0);	/* no symbols; 0th symbol is the non-symbol */

	if (str_shtype != SHT_STRTAB) {
		if (fname != NULL)
			error_message(SYMTAB_02_ERROR,
			    PLAIN_ERROR, (char *)0,
			    fname);
		else
			error_message(SYMTAB_03_ERROR,
			    PLAIN_ERROR, (char *)0);
		return (0);
	}
	str_data = 0;
	if ((str_data = elf_getdata(str_scn, str_data)) == 0) {
		if (fname != NULL)
			error_message(SYMTAB_04_ERROR,
			    PLAIN_ERROR, (char *)0,
			    fname);
		else
			error_message(SYMTAB_05_ERROR,
			    PLAIN_ERROR, (char *)0);
		return (0);
	}
	if (str_data->d_size == 0) {
		if (fname != NULL)
			error_message(SYMTAB_06_ERROR,
			    PLAIN_ERROR, (char *)0,
			    fname);
		else
			error_message(SYMTAB_07_ERROR,
			    PLAIN_ERROR, (char *)0);
		return (0);
	}
	sym_data = 0;
	if ((sym_data = elf_getdata(scn, sym_data)) == NULL) {
		if (fname != NULL)
			error_message(ELF_01_ERROR,
			    LIBELF_ERROR, elf_errmsg(-1),
			    fname, elf_errmsg(-1));
		else
			error_message(ELF_02_ERROR,
			    LIBELF_ERROR, elf_errmsg(-1),
			    elf_errmsg(-1));
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
					error_message(MALLOC_ERROR,
					    PLAIN_ERROR, (char *)0);
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
static int
sizeofmembers(int psum)
{
	int sum = 0;
	ARFILE *fptr;
	int hdrsize = sizeof (struct ar_hdr);

	for (fptr = listhead; fptr; fptr = fptr->ar_next) {
		fptr->ar_offset = psum + sum;
		sum += fptr->ar_size;
		if (fptr->ar_size & 01)
			sum++;
		sum += hdrsize;

		/*
		 * If the current item, and the next item are both ELF
		 * objects, then add padding to current item so that the
		 * next item will have PADSZ alignment.
		 *
		 * In any other case, set the padding to 0. If the
		 * item comes from another archive, it may be carrying
		 * a non-zero padding value from that archive that does
		 * not apply to the one we are about to build.
		 */
		if ((fptr->ar_flag & (F_CLASS32 | F_CLASS64)) &&
		    fptr->ar_next &&
		    (fptr->ar_next->ar_flag & (F_CLASS32 | F_CLASS64))) {
			fptr->ar_padding = pad(psum + sum + hdrsize);
			sum += fptr->ar_padding;
		} else {
			fptr->ar_padding = 0;
		}
	}
	return (sum);
}

static int
sizeofnewarchiveheader(int nsyms, int longnames)
{
	int sum = 0;

	sum += SARMAG;

	if (nsyms) {
		char *top = (char *)str_top;
		char *base = (char *)str_base;

		while ((top - base) & 03)
			top++;
		sum += sizeof (struct ar_hdr);
		sum += (nsyms + 1) * 4;
		sum += top - base;
	}

	if (longnames) {
		sum += sizeof (struct ar_hdr);
		sum += str_top1 - str_base1;
	}

	/*
	 * If the first member file is an ELF object,
	 * we have to ensure the member contents will align
	 * on PADSZ byte boundary.
	 */
	if (listhead && (listhead->ar_flag & (F_CLASS32 | F_CLASS64))) {
		pad_symtab = pad(sum + sizeof (struct ar_hdr));
		sum += pad_symtab;
	}

	return (sum);
}

static int
sizeofnewarchive(int nsyms, int longnames)
{
	int sum;

	sum = sizeofnewarchiveheader(nsyms, longnames);
	sum += sizeofmembers(sum);
	return (sum);
}

static void
arwrite(char *name, int nfd, char *dst, int size) {
	if (write(nfd, dst, size) != size) {
		error_message(SYS_WRITE_04_ERROR,
		    SYSTEM_ERROR, strerror(errno), name);
		exit(2);
	}
}

static char *
make_tmpname(char *filename) {
	static char template[] = "arXXXXXX";
	char *tmpname;
	char *slash = strrchr(filename, '/');

	if (slash != (char *)NULL) {
		char c;

		c = *slash;
		*slash = 0;
		tmpname = (char *)malloc(strlen(filename) +
			sizeof (template) + 2);
		(void) strcpy(tmpname, filename);
		(void) strcat(tmpname, "/");
		(void) strcat(tmpname, template);
		(void) mktemp(tmpname);
		*slash = c;
	} else {
		tmpname = malloc(sizeof (template));
		(void) strcpy(tmpname, template);
		(void) mktemp(tmpname);
	}
	return (tmpname);
}

static int
ar_copy(char *from, char *to) {
	int fromfd, tofd, nread;
	int saved;
	char buf[8192];

	fromfd = open(from, O_RDONLY);
	if (fromfd < 0)
		return (-1);
	tofd = open(to, O_CREAT | O_WRONLY | O_TRUNC, 0777);
	if (tofd < 0) {
		saved = errno;
		(void) close(fromfd);
		errno = saved;
		return (-1);
	}
	while ((nread = read(fromfd, buf, sizeof (buf))) > 0) {
		if (write(tofd, buf, nread) != nread) {
			saved = errno;
			(void) close(fromfd);
			(void) close(tofd);
			errno = saved;
			return (-1);
		}
	}
	saved = errno;
	(void) close(fromfd);
	(void) close(tofd);
	if (nread < 0) {
		errno = saved;
		return (-1);
	}
	return (0);
}

static int
ar_rename(char *from, char *to)
{
	int exists;
	struct stat s;
	int ret = 0;

	exists = lstat(to, &s) == 0;

	if (! exists || (!S_ISLNK(s.st_mode) && s.st_nlink == 1)) {
		ret = rename(from, to);
		if (ret == 0) {
			if (exists) {
				(void) chmod(to, s.st_mode & 0777);
				if (chown(to, s.st_uid, s.st_gid) >= 0)
					(void) chmod(to, s.st_mode & 07777);
				}
		} else {
			(void) unlink(from);
		}
	} else {
		ret = ar_copy(from, to);
		(void) unlink(from);
	}
	return (ret);
}

static char *
writelargefile(Cmd_info *cmd_info, long long_tab_size, int longnames,
	ARFILEP *symlist, long nsyms, int found_obj, int new_archive)
{
	ARFILE	* fptr;
	char *name = cmd_info->arnam;
	int arsize;
	char *dst;
	char *tmp_dst;
	int nfd;
	char  *new_name;
	FILE *f;
	struct stat stbuf;

	new_name = make_tmpname(name);

	if (new_archive) {
		nfd = open(name, O_RDWR|O_CREAT|O_LARGEFILE, 0666);
		if (nfd == -1) {
			error_message(SYS_CREATE_01_ERROR,
			    SYSTEM_ERROR, strerror(errno), name);
			exit(1);
		}
	} else {
		nfd = open(new_name, O_RDWR|O_CREAT|O_LARGEFILE, 0666);
		if (nfd == -1) {
			error_message(SYS_WRITE_02_ERROR,
			    SYSTEM_ERROR, strerror(errno), name);
			exit(1);
		}
	}

	arsize = sizeofnewarchiveheader(nsyms, longnames);
	if (nsyms == 0 && found_obj != 0)
		arsize += sizeof (struct ar_hdr) + 4 + 4;
	if (arsize < 2048) {
		arsize = 2048;
	}
	dst = tmp_dst = (char *)malloc(arsize);
	(void) memcpy(tmp_dst, ARMAG, SARMAG);
	tmp_dst += SARMAG;

	if (nsyms || found_obj != 0) {
		int diff;
		diff = writesymtab(tmp_dst, nsyms, symlist);
		tmp_dst += diff;
	}

	if (longnames) {
		(void) sprintf(tmp_dst, FORMAT, LONGDIRNAME, time(0),
		    (unsigned)0, (unsigned)0, (unsigned)0,
		    (long)long_tab_size, ARFMAG);
		tmp_dst += sizeof (struct ar_hdr);
		(void) memcpy(tmp_dst, str_base1, str_top1 - str_base1);
		tmp_dst += str_top1 - str_base1;
	}
#ifndef XPG4
	if (opt_FLAG(cmd_info, v_FLAG)) {
		error_message(BER_MES_WRITE_ERROR,
		    PLAIN_ERROR, (char *)0,
		    cmd_info->arnam);
	}
#endif
	arwrite(name, nfd, dst, (int)(tmp_dst - dst));

	for (fptr = listhead; fptr; fptr = fptr->ar_next) {
		if (fptr->ar_name[0] == 0) {
			fptr->ar_longname = fptr->ar_rawname;
			(void) strncpy(fptr->ar_name, fptr->ar_rawname, SNAME);
		}
		if (strlen(fptr->ar_longname) <= (unsigned)SNAME-2)
			(void) sprintf(dst, FNFORMAT,
			    trimslash(fptr->ar_longname));
		else
			(void) sprintf(dst, FNFORMAT, fptr->ar_name);
		(void) sprintf(dst+16, TLFORMAT, fptr->ar_date,
		    (unsigned)fptr->ar_uid, (unsigned)fptr->ar_gid,
		    (unsigned)fptr->ar_mode, fptr->ar_size + fptr->ar_padding,
		    ARFMAG);
		arwrite(name, nfd, dst, sizeof (struct ar_hdr));

		if (!(fptr->ar_flag & F_MALLOCED) &&
		    !(fptr->ar_flag & F_MMAPED) &&
		    !(fptr->ar_flag & F_ELFRAW)) {
			f = fopen(fptr->ar_pathname, "r");
			if (stat(fptr->ar_pathname, &stbuf) < 0) {
				(void) fclose(f);
				f = NULL;
			}
			if (f == NULL) {
				error_message(SYS_OPEN_ERROR,
				    SYSTEM_ERROR, strerror(errno),
				    fptr->ar_longname);
				exit(1);
			} else {
				if ((fptr->ar_contents = (char *)
				    malloc(ROUNDUP(stbuf.st_size))) == NULL) {
					error_message(MALLOC_ERROR,
					    PLAIN_ERROR, (char *)0);
					exit(1);
				}
				if (fread(fptr->ar_contents,
				    sizeof (char),
				    stbuf.st_size, f) != stbuf.st_size) {
					error_message(SYS_READ_ERROR,
					    SYSTEM_ERROR, strerror(errno),
					    fptr->ar_longname);
					exit(1);
				}
			}
			arwrite(name, nfd, fptr->ar_contents, fptr->ar_size);
			(void) fclose(f);
			free(fptr->ar_contents);
		} else {
			arwrite(name, nfd, fptr->ar_contents, fptr->ar_size);
			if (fptr->ar_flag & F_MALLOCED) {
				(void) free(fptr->ar_contents);
				fptr->ar_flag &= ~(F_MALLOCED);
			}
		}

		if (fptr->ar_size & 0x1) {
			arwrite(name, nfd, "\n", 1);
		}

		if (fptr->ar_padding) {
			int i = fptr->ar_padding;
			while (i) {
				arwrite(name, nfd, "\n", 1);
				--i;
			}
		}
	}

	/*
	 * All preparation for writing is done.
	 */
	(void) elf_end(cmd_info->arf);
	(void) close(cmd_info->afd);

	if (!new_archive) {
		(void) ar_rename(new_name, name);
	}

	return (dst);
}
