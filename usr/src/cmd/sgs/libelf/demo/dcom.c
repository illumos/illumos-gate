/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * dcom: Delete Comment
 *
 * This program demonstrates the use of libelf interface to
 * copy the contents of one ELF file to create a new one.
 * dcom creates a new ELF file using elf_begin(ELF_C_WRITE).
 *
 * In order to delete a section from an ELF file you must
 * instead create a new ELF file and copy all but the 'selected'
 * sections to the new ELF file.  This is because libelf is
 * unable to delete any sections from an ELF file, it can
 * only add them.
 *
 * NOTE: While this program works fine for simple ELF objects,
 * as they get more complex it may not properly update all of the
 * fields required.  This program is *only* an example of how
 * to do this and not a complete program in itself.
 */


#include <stdio.h>
#include <libelf.h>
#include <gelf.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>


static const char *CommentStr = ".comment";

/*
 * Build a temporary file name that is in the
 * same directory as the elf file being processed.
 */
static char *
mkname(const char *bname)
{
	char	*ptr;
	char	buffer[MAXPATHLEN];

	ptr = strcpy(buffer, bname);
	ptr += strlen(buffer);
	while (ptr >= buffer) {
		if (*ptr == '/') {
			*(ptr + 1) = '\0';
			break;
		}
		ptr--;
	}
	if (ptr < buffer) {
		buffer[0] = '.';
		buffer[1] = '\0';
	}
	return (tempnam(buffer, 0));
}



static void
delete_comment(Elf *elf, int fd, const char *file)
{
	GElf_Ehdr	ehdr;
	Elf_Scn		*scn = 0;
	char		*tfile;
	Elf		*telf;
	int		tfd;
	GElf_Ehdr	tehdr;
	GElf_Phdr	phdr;
	GElf_Phdr	tphdr;
	size_t		shstrndx;
	size_t		shnum;
	size_t		phnum;
	int		*shndx;
	int		ndx = 1;
	int		off = 0;
	struct stat	sbuf;

	if (gelf_getehdr(elf, &ehdr) == 0) {
		(void) fprintf(stderr, "%s: elf_getehdr() failed: %s\n",
			file, elf_errmsg(0));
		return;
	}

	if (elf_getshnum(elf, &shnum) == 0) {
		(void) fprintf(stderr, "%s: elf_getshnum() failed: %s\n",
			file, elf_errmsg(0));
		return;
	}

	if (elf_getshstrndx(elf, &shstrndx) == 0) {
		(void) fprintf(stderr, "%s: elf_getshstrndx() failed: %s\n",
			file, elf_errmsg(0));
		return;
	}

	if (elf_getphnum(elf, &phnum) == 0) {
		(void) fprintf(stderr, "%s: elf_getphnum() failed: %s\n",
			file, elf_errmsg(0));
		return;
	}

	/*
	 * shndx is an array used to map the current section
	 * indexes to the new section indexes.
	 */
	shndx = calloc(shnum, sizeof (int));

	while ((scn = elf_nextscn(elf, scn)) != 0) {
		GElf_Shdr	shdr;

		/*
		 * Do a string compare to examine each section header
		 * to see if it is a ".comment" section.  If it is then
		 * this is the section we want to process.
		 */
		if (gelf_getshdr(scn, &shdr) == 0) {
			(void) fprintf(stderr,
				"%s: elf_getshdr() failed: %s\n",
				file, elf_errmsg(0));
			free(shndx);
			return;
		}
		if (strcmp(CommentStr, elf_strptr(elf, shstrndx,
		    shdr.sh_name)) == 0) {
			shndx[ndx] = -1;
			off++;

			/*
			 * If the .comment section is part of a loadable
			 * segment then it can not be delted from the
			 * ELF file.
			 */
			if (shdr.sh_addr != 0) {
				(void) printf("%s: .comment section is "
					"part of a loadable segment, it "
					"cannot be deleted.\n", file);
				free(shndx);
				return;
			}
		} else
			shndx[ndx] = ndx - off;
		ndx++;
	}

	/*
	 * obtain a unique file name and open a file descriptor
	 * pointing to that file.
	 */
	tfile = mkname(file);
	if ((tfd = open(tfile, O_RDWR | O_CREAT, 0600)) == -1) {
		perror("temp open");
		return;
	}

	/*
	 * Create a new ELF to duplicate the ELF file into.
	 */
	if ((telf = elf_begin(tfd, ELF_C_WRITE, 0)) == 0) {
		(void) fprintf(stderr, "elf_begin(ELF_C_WRITE) failed: %s\n",
		    elf_errmsg(0));
		return;
	}

	if (gelf_newehdr(telf, gelf_getclass(elf)) == 0) {
		(void) fprintf(stderr, "%s: elf_newehdr() failed: %s\n",
			file, elf_errmsg(0));
		free(shndx);
		return;
	}
	if (gelf_getehdr(telf, &tehdr) == 0) {
		(void) fprintf(stderr, "%s: elf_getehdr() failed: %s\n",
			file, elf_errmsg(0));
		free(shndx);
		return;
	}

	scn = 0;
	ndx = 1;
	while ((scn = elf_nextscn(elf, scn)) != 0) {
		Elf_Scn *	tscn;
		Elf_Data *	data;
		Elf_Data *	tdata;
		GElf_Shdr	shdr;
		GElf_Shdr	tshdr;

		if (shndx[ndx] == -1) {
			ndx++;
			continue;
		}

		/*
		 * Duplicate all but the .comment section in the
		 * new file.
		 */
		if (gelf_getshdr(scn, &shdr) == 0) {
			(void) fprintf(stderr,
				"%s: elf_getshdr() failed: %s\n",
				file, elf_errmsg(0));
			free(shndx);
			return;
		}
		if ((tscn = elf_newscn(telf)) == 0) {
			(void) fprintf(stderr,
				"%s: elf_newscn() failed: %s\n",
				file, elf_errmsg(0));
			free(shndx);
			return;
		}
		if (gelf_getshdr(tscn, &tshdr) == 0) {
			(void) fprintf(stderr,
				"%s: elf_getshdr() failed: %s\n",
				file, elf_errmsg(0));
			free(shndx);
			return;
		}
		tshdr = shdr;
		tshdr.sh_link = shndx[shdr.sh_link];

		/*
		 * The relocation sections sh_info field also contains
		 * a section index that needs to be adjusted.  This is
		 * the only section who's sh_info field contains
		 * a section index according to the ABI.
		 *
		 * If their are non-ABI sections who's sh_info field
		 * contains section indexes they will not properly
		 * be updated by this routine.
		 */
		if (shdr.sh_type == SHT_REL)
			tshdr.sh_info = shndx[ndx];

		/*
		 * Flush the changes to the underlying elf32 or elf64
		 * section header.
		 */
		gelf_update_shdr(tscn, &tshdr);

		if ((data = elf_getdata(scn, 0)) == 0) {
			(void) fprintf(stderr,
				"%s: elf_getdata() failed: %s\n",
				file, elf_errmsg(0));
			free(shndx);
			return;
		}
		if ((tdata = elf_newdata(tscn)) == 0) {
			(void) fprintf(stderr,
				"%s: elf_newdata() failed: %s\n",
				file, elf_errmsg(0));
			free(shndx);
			return;
		}
		*tdata = *data;
		ndx++;
	}

	tehdr = ehdr;
	if (shndx[shstrndx] < SHN_LORESERVE)
		tehdr.e_shstrndx = shndx[shstrndx];
	else {
		Elf_Scn		*_scn;
		GElf_Shdr	shdr0;
		/*
		 * 'ELF Extended Sections' are enabled - we must
		 * store the shstrndx in Shdr[0].sh_link
		 */
		if ((_scn = elf_getscn(telf, 0)) == 0) {
			(void) fprintf(stderr,
				"%s: elf_getscn() failed: %s\n",
				file, elf_errmsg(0));
			free(shndx);
			return;
		}
		if (gelf_getshdr(_scn, &shdr0) == 0) {
			(void) fprintf(stderr,
				"%s: elf_getshdr() failed: %s\n",
				file, elf_errmsg(0));
			free(shndx);
			return;
		}
		tehdr.e_shstrndx = SHN_XINDEX;
		shdr0.sh_link = shndx[shstrndx];
		gelf_update_shdr(_scn, &shdr0);
	}
	gelf_update_ehdr(telf, &tehdr);

	free(shndx);

	/*
	 * Duplicate all program headers contained in the ELF file.
	 */
	if (phnum != 0) {
		if (gelf_newphdr(telf, phnum) == 0) {
			(void) fprintf(stderr,
				"%s: elf_newphdr() failed: %s\n",
				file, elf_errmsg(0));
			return;
		}
		for (ndx = 0; ndx < (int)phnum; ndx++) {
			if (gelf_getphdr(elf, ndx, &phdr) == 0 ||
			    gelf_getphdr(telf, ndx, &tphdr) == 0) {
				(void) fprintf(stderr,
					"%s: elf_getphdr() failed: %s\n",
					file, elf_errmsg(0));
				return;
			}
			tphdr = phdr;
			gelf_update_phdr(telf, ndx, &tphdr);
		}
	}

	/*
	 * The new Elf file has now been fully described to libelf.
	 * elf_update() will construct the new Elf file and write
	 * it out to disk.
	 */
	if (elf_update(telf, ELF_C_WRITE) == -1) {
		(void) fprintf(stderr, "elf_update() failed: %s\n",
			elf_errmsg(0));
		(void) elf_end(telf);
		(void) close(tfd);
		return;
	}
	(void) elf_end(telf);

	/*
	 * set new files permissions to the original files
	 * permissions.
	 */
	(void) fstat(fd, &sbuf);
	(void) fchmod(tfd, sbuf.st_mode);

	(void) close(tfd);

	/*
	 * delete the original file and rename the new file
	 * to the orignal file.
	 */
	(void) rename(tfile, file);
}


int
main(int argc, char ** argv)
{
	int	i;

	if (argc < 2) {
		(void) printf("usage: %s elf_file ...\n", argv[0]);
		return (1);
	}

	/*
	 * Initialize the elf library, must be called before elf_begin()
	 * can be called.
	 */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		(void) fprintf(stderr, "elf_version() failed: %s\n",
			elf_errmsg(0));
		return (1);
	}

	for (i = 1; i < argc; i++) {
		int	fd;
		Elf	*elf;
		char	*elf_fname;

		elf_fname = argv[i];

		if ((fd = open(elf_fname, O_RDONLY)) == -1) {
			perror("open");
			continue;
		}

		/*
		 * Attempt to open an Elf descriptor Read/Write
		 * for each file.
		 */
		if ((elf = elf_begin(fd, ELF_C_READ, 0)) == NULL) {
			(void) fprintf(stderr, "elf_begin() failed: %s\n",
			    elf_errmsg(0));
			(void) close(fd);
			continue;
		}

		/*
		 * Determine what kind of elf file this is:
		 */
		if (elf_kind(elf) != ELF_K_ELF) {
			/*
			 * can only delete comment sections from
			 * ELF files.
			 */
			(void) printf("%s not of type ELF_K_ELF.  "
				"elf_kind == %d\n",
				elf_fname, elf_kind(elf));
		} else
			delete_comment(elf, fd, elf_fname);

		(void) elf_end(elf);
		(void) close(fd);
	}

	return (0);
}
