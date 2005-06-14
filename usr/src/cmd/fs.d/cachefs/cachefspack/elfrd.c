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
 * Copyright (c) 1996-1997, by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdio.h>
#include <fcntl.h>
#include <link.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <search.h>

#include "libelf.h"
#include "elfrd.h"

extern int verbose;
extern char *mstrdup(const char *);
extern void *mmalloc(size_t size);

/*
 * Given the name of an executable and a function call the function for
 * all shared objects needed to link the executable. The function will only
 * be called once. A list of filenames for which the function has been called
 * is maintained, this is used to exclude filenames.
 */
void
process_executable(char *pathname, int (*func)(char *, char *, DIR *, int))
{
	struct sobj *get_share_obj(char *, struct libpath *, int);
	struct sobj *sop;
	struct sobj *psop;

#ifdef DEBUG
	printf("process_executable: pathname = %s\n", pathname);
	fflush(stdout);
#endif /* debug */
	sop = get_share_obj(pathname, &libp_hd, GSO_ADDEXCLD);
#ifdef DEBUG
	printf("process_executable: sop = %x\n", sop);
	fflush(stdout);
#endif /* debug */
	if (verbose) {
		if ((int)sop < 0)  {
			fprintf(stderr,
			    gettext(
			    "cachefspack: unable to get shared objects - %s\n"),
			    pathname);
		}
	}
	if ((int)sop > 0) {
		while (sop->so_next != (struct sobj *)0) {
#ifdef DEBUG
			printf("process_executable: sop->so_name = %s\n",
			    sop->so_name);
			fflush(stdout);
#endif /* DEBUG */
			func_dir_path(sop->so_name, func);

			psop = sop;
			sop = sop->so_next;
			free(psop->so_name);
			free(psop);
		}
	}
}

/*
 * Given the name of an executable, a list of directories to use in the
 * library search and a list of library names to exclude, return all
 * shared object needed by the executable.
 *
 * RETURNS: A pointer to a list of shared objects
 */
struct sobj *
get_share_obj(char *fpath, struct libpath *libpath, int flag)
{
	static int name_cnt = 0;
	static struct sobj *so, *hd_so;
	static int depth = 0;
	static struct libpath *rpath, hd_rpath;
	int found_file = 0;
	int error;
	int fd;
	Elf *elfp;
	Elf32_Ehdr *Ehdr;
	Elf_Scn *scn;
	Elf32_Shdr *shdr;
	Elf32_Dyn *dyn;
	size_t	dynsz;
	char *name;
	void * get_scndata();
	struct sobj *alloc_sobj();
	struct sobj *add_so();
	char pathtmp[MAXPATHLEN];
	ENTRY hitem, *hitemp;
	int fileopn;
	int elfbgn = 0;
	Elf_Kind file_type;
	int buf;

	/*
	 * Open a file and perform necessary operations to find the sections
	 * in an elf format file. If the specified file is not elf format
	 * return an error.
	 */
	depth++;
	if (depth == 1) {
		/*
		 * Find the ending exclude shared object element.
		 */
		rpath = &hd_rpath;
#ifdef DEBUG
		printf("dbg: rpath = %x\n", rpath);
#endif /* DEBUG */
		rpath->lp_path = " ";
		rpath->lp_next = (struct libpath *)0;
		rpath->lp_level = 0;
	}

	fileopn = 0;
	error = ERR_NOERROR;
	fd = open(fpath, O_RDONLY);
	if (fd < 0) {
		error = ERR_NOFILE;
		goto out;
	}
	fileopn = 1;
/* work around */
/*
 * elf_begin() core dumps when passed a file descriptor for a file
 * which does not have read permission, but was opened RDONLY because the
 * user doing the open was root. To avoid this problem, make sure we can
 * read the first byte of the file. If we can't, skip the file. This is a
 * temporary workaround until elf_begin() is fixed.
 */
	if (read(fd, &buf, sizeof (buf)) < 0) {
#ifdef DEBUG
		printf("read failed\n");
		fflush(stdout);
#endif /* DEBUG */
		error = ERR_NOFILE;
		goto out;
	}
	lseek(fd, 0, SEEK_SET);
/* work around end */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		error = ERR_NOELFVER;
		goto out;
	}
	elfbgn = 0;
	if ((elfp = elf_begin(fd,  ELF_C_READ, (Elf *)0)) == NULL) {
		error = ERR_NOELFBEG;
		goto out;
	}
	elfbgn = 1;
	file_type = elf_kind(elfp);
#ifdef DEBUG
	printf("file_type = %x\n", file_type);
	fflush(stdout);
#endif /* DEBUG */

	if (file_type != ELF_K_ELF) {
		goto out;
	}
	if ((Ehdr = elf32_getehdr(elfp)) == NULL) {
		error = ERR_NOELFBEG;
		goto out;
	}
#ifdef DEBUG
	printf("dbg: depth = %d\n", depth);
#endif /* DEBUG */
	/*
	 * Scan all sections of the elf file to locate the dynamic section
	 */
	scn = 0;
	while ((scn = elf_nextscn(elfp, scn)) != 0) {
		if ((shdr = elf32_getshdr(scn)) == NULL) {
			error = ERR_NOELFSHD;
			goto out;
		}
		if (shdr->sh_type != SHT_DYNAMIC) {
			continue;
		}
		/*
		 * The first pass of the dynamic section locates all
		 * directories specified by "ld -R..". A stack is created
		 * for the search, this allows shared libraries, dependant
		 * on other shared libraries, built with "ld -R" to work
		 * properly.
		 *
		 */
		if ((dyn = (Elf32_Dyn *)get_scndata(scn, &dynsz)) == 0) {
			error = ERR_NOELFSDT;
			goto out;
		}
		while (dyn->d_tag != DT_NULL) {
			if (dyn->d_tag == DT_RPATH) {
				name = (char *)elf_strptr(elfp,
				    (size_t)shdr->sh_link, dyn->d_un.d_ptr);
#ifdef DEBUG
				printf("DT_RPATH: name = %s\n", name);
#endif /* DEBUG */
				rpath = stk_libpath(rpath, name, depth);
			}
			dyn++;
		}
		/*
		 * Find all needed shared objects. Do this recursively
		 * so libraries dependant on other libraries are found.
		 * Also, try a list of libraries to exclude. Since
		 * this routine is used by cachefspack, it is only neccessary
		 * to pack a library once. For example, libc is used by lots
		 * of commands, we need not return its name to cachefspack
		 * except the first time we find it.
		 */
		if ((dyn = (Elf32_Dyn *)get_scndata(scn, &dynsz)) == 0) {
			error = ERR_NOELFSDT;
			goto out;
		}
		for (; dyn->d_tag != DT_NULL; dyn++) {
			if (dyn->d_tag == DT_NEEDED) {
				name = (char *)elf_strptr(elfp,
				    (size_t)shdr->sh_link, dyn->d_un.d_ptr);
				if (name != 0) {
#ifdef DEBUG
					printf("chk: %s\n", name);
					fflush(stdout);
#endif /* DEBUG */
					found_file = libsrch(name, libpath,
					    pathtmp);
#ifdef DEBUG
					printf("dbg:  1 found_file = %d\n",
					    found_file);
					fflush(stdout);
#endif /* DEBUG */
					if (!found_file) {
						found_file = libsrch(name,
						    rpath, pathtmp);
					}
#ifdef DEBUG
					printf("dbg:  2 found_file = %d\n",
					    found_file);
					fflush(stdout);
#endif /* DEBUG */
					if (!found_file) {
						continue;
					}
					if (name_cnt == 0) {
						so = alloc_sobj();
						hd_so = so;
					}
					/*
					 * See if file already in list
					 */
					hitem.key = mstrdup(pathtmp);
					hitem.data = 0;
					hitemp = hsearch(hitem, FIND);
					if (hitemp != NULL) {
#ifdef DEBUG
						printf("found so: %s\n",
						    pathtmp);
						printf("hitemp.key = %s\n",
						    hitemp->key);
#endif /* DEBUG */
						continue;
					}
#ifdef DEBUG
					printf("do : %s\n", pathtmp);
					fflush(stdout);
#endif /* DEBUG */
					name_cnt++;
					so = add_so(so, pathtmp);
					if (flag & GSO_ADDEXCLD) {
#ifdef DEBUG
						printf("adding so: %s\n",
						    pathtmp);
#endif /* DEBUG */
						hitem.key = mstrdup(pathtmp);
						hitem.data = 0;
						if (hsearch(hitem, ENTER) ==
						    NULL) {
							error = ERR_HASHFULL;
							goto out;
						}
					}
					get_share_obj(pathtmp, libpath, flag);
				} else {
					if (name_cnt > 0) {
						goto out;
					} else {
						error = ERR_NOELFNAM;
						goto out;
					}
				}
			}
		}
	}

out:
#ifdef DEBUG
	printf("error = %x\n", error);
	fflush(stdout);
#endif /* DEBUG */
	depth--;
#ifdef DEBUG
	printf("ret: depth = %d\n", depth);
	fflush(stdout);
#endif /* DEBUG */
	if (fileopn) {
		close(fd);
		if (elfbgn) {
			if ((error != ERR_NOFILE) && (error != ERR_NOELFVER)) {
				elf_end(elfp);
			}
		}
	}
	if (name_cnt == 0) {
		return ((struct sobj *)ERR_NOERROR);
	}
	while (rpath->lp_level > depth) {
#ifdef DEBUG
		printf("ret: rpath->lp_level = %d\n", rpath->lp_level);
		fflush(stdout);
#endif /* DEBUG */
		rpath = pop_libpath(rpath);
	}
	if (depth == 0) {
		name_cnt = 0;
	}
	if (error == ERR_NOERROR) {
		return (hd_so);
	} else {
		return ((struct sobj *)error);
	}
}


/*
 * Get the section descriptor and set the size of the
 * data returned.  Data is byte-order converted.
 */

void *
get_scndata(fd_scn, size)
Elf_Scn *fd_scn;
size_t    *size;
{
	Elf_Data *p_data;

	p_data = 0;
	if ((p_data = elf_getdata(fd_scn, p_data)) == 0 ||
		p_data->d_size == 0)
	{
		return (NULL);
	}

	*size = p_data->d_size;
	return (p_data->d_buf);
}

/*
 * Allocate a shared object structure
 *
 * RETURNS: A pointer to the allocated structure
 */
struct sobj *
alloc_sobj()
{
	struct sobj *so;
	so = (struct sobj *)mmalloc(sizeof (struct sobj));
	so->so_name = " ";
	so->so_next = (struct sobj *)0;
	return (so);
}


/*
 * Add an object to a shared object list
 *
 * RETURNS: The tail of the shared object list
 */
struct sobj *
add_so(struct sobj *so, char *path)
{
	if (so == (struct sobj *)0) {
		so = alloc_sobj();
	}
	so->so_name = mstrdup(path);
	so->so_next = alloc_sobj();
	so = so->so_next;
	return (so);
}

/*
 * Determine if name concatenated with a library directory path yields
 * a file name that exists.
 *
 * RETURNS: True(1) or False(0)
 *	    if true - fullpath arg contains a pointer to the full path name
 *			of the file
 */
int
libsrch(char *name, struct libpath *libpath, char *fullpath)
{
	struct stat64 statbuf;
	struct libpath *lp;

#ifdef DEBUG
	printf("libsrch: libpath = %x\n", libpath);
	fflush(stdout);
#endif /* DEBUG */
	lp = libpath;
	if (lp == NULL) {
		return (0);
	}
#ifdef DEBUG
	printf("libsrch: 1 lp->lp_next = %x\n", lp->lp_next);
	fflush(stdout);
#endif /* DEBUG */
	while (lp->lp_next != (struct libpath *)0) {
		strcpy(fullpath, lp->lp_path);
		strcat(fullpath, "/");
		strcat(fullpath, name);
		lp = lp->lp_next;
#ifdef DEBUG
		printf("libsrch: 2 lp->lp_next = %x\n", lp->lp_next);
		fflush(stdout);
#endif /* DEBUG */
		/*
		 * stat - if file break
		 */
		if (stat64(fullpath, &statbuf)
		    == 0) {
#ifdef DEBUG
			printf("libsrch: found - %s\n", fullpath);
			fflush(stdout);
#endif /* DEBUG */
			return (1);
		}
	}
#ifdef DEBUG
	printf("libsrch: NOT found - %s\n", name);
	fflush(stdout);
#endif /* DEBUG */
	return (0);
}

/*
 * Add path to the libpath list(add at the tail of the list).
 *
 * RETURNS: The new tail of the list
 */
struct libpath *
add_libpath(struct libpath *lp, char *path, int level)
{
	char *s;

	lp->lp_level = level;
	s = mstrdup(path);
	if (s != (char *)0) {
		lp->lp_path = s;
	}
	lp->lp_next = (struct libpath *)mmalloc(sizeof (struct libpath));
	lp = lp->lp_next;
	lp->lp_next = (struct libpath *)0;
	lp->lp_level = 0;
	lp->lp_path = " ";
	return (lp);
}

/*
 * Add directory/directories in name to libpath stack(as head of the stack)
 * at the level specified.
 *
 * RETURNS: the new head of the stack
 */
struct libpath *
stk_libpath(struct libpath *hd, char *name, int level)
{
	struct libpath *lp, *prev_lp;
	char *s, *t;
	char *tok;
	char *freeit;

#ifdef DEBUG
	printf("stk_libpath: name = %s\n", name);
	fflush(stdout);
#endif /* DEBUG */
	s = mstrdup(name);
	freeit = s;
	prev_lp = hd;
	while (1) {
		tok = strtok(s, ":");
		if (tok == (char *)NULL)
		    break;
		s = (char *)0;
		lp = (struct libpath *)mmalloc(sizeof (struct libpath));
		lp->lp_level = level;
		t = mstrdup(tok);
		lp->lp_path = t;
		lp->lp_next = prev_lp;
		prev_lp = lp;
	}
#ifdef DEBUG
	printf("stk_libpath: lp = %x\n", lp);
	fflush(stdout);
#endif /* DEBUG */
	free(freeit);
	return (lp);
}

/*
 * Free up a libpath stack entry.
 *
 * RETURNS: the new head of the stack
 */
struct libpath *
pop_libpath(struct libpath *lp)
{
	struct libpath *tlp;

	tlp = lp;
	lp = lp->lp_next;
	free(tlp->lp_path);
	free(tlp);
	return (lp);
}

/*
 * Crack the LD_LIBRARY_PATH environment variable. Make a list of libraries
 * to search.
 */
void
get_libsrch_path(struct libpath *libhd)
{
	char *s;
	char *tok = (char *) 1;
	struct libpath *lp;

	lp = libhd;
	s = getenv("LD_LIBRARY_PATH");
	if (s != (char *)NULL) {
		while (1) {
			tok = strtok(s, ":");
			if (tok == (char *) NULL)
				break;
			s = (char *) 0;
			lp = add_libpath(lp, tok, 0);
		}
	}
	add_libpath(lp, "/usr/lib", 0);
}


#ifdef DEBUG
prt_sop_lst(struct sobj *sop, char * str)
{
	printf("\n\n\n%s - sop = %x\n", str, sop);
	fflush(stdout);
	if ((int)sop < 0)  {
		fprintf(stderr, "get_share_obj: failed\n");
		exit(1);
	}

	if ((int)sop > 0) {
		while (sop->so_next != (struct sobj *) 0) {
			printf("sop->so_name = %s\n", sop->so_name);
			sop = sop->so_next;
		}
	}
}
#endif /* DEBUG */
