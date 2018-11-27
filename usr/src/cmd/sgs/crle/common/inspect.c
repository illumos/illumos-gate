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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Routines to add file and directory entries into the internal configuration
 * information.  This information is maintained in a number of hash tables which
 * after completion of input file processing will be processed and written to
 * the output configuration file.
 *
 * Each hash table is defined via a Hash_tbl structure.  These are organized:
 *
 *  c_strtbl	contains a hash entry for every file, directory, pathname and
 *		alternative path (dldump(3dl) image) processed.
 *		c_strsize and c_objnum maintain the size and count of the
 *		strings added to this table and are used to size the output
 *		configuration file.
 *
 *  c_inotbls	contains a list of inode hash tables.  Each element of the list
 *		identifies a unique device.  Thus, for each file processed its
 *		st_dev and st_ino are used to assign its entry to the correct
 *		hash table.
 *
 *		Each directory processed is assigned a unique id (c_dirnum)
 *		which insures each file also becomes uniquely identified.
 *
 * All file and directory additions come through the inspect() entry point.
 */

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<dirent.h>
#include	<_libelf.h>
#include	<errno.h>
#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<limits.h>
#include	"machdep.h"
#include	"sgs.h"
#include	"rtc.h"
#include	"_crle.h"
#include	"msg.h"

/*
 * Add an alternative pathname for an object.  Although a configuration file
 * may contain several pathnames that resolve to the same real file, there can
 * only be one real file.  Consequently, there can only be one alternative.
 * For multiple pathnames that resolve to the same real file, multiple alter-
 * natives may be specified.  Always take the alternative for the real file
 * over any others.
 */
static int
enteralt(Crle_desc *crle, const char *path, const char *file, Half flags,
    Hash_obj *obj)
{
	const char	*fmt;
	char		alter[PATH_MAX];
	size_t		altsz;

	if (obj->o_alter) {
		/*
		 * If an alternative has already been captured, only override
		 * it if the specified file is the real file.
		 */
		if (strcmp(path, obj->o_path))
			return (1);
	}

	/*
	 * Create an alternative pathname from the file and object destination
	 * directory.  If we're dumping an alternative don't allow it to
	 * override the original.
	 */
	if (flags & RTC_OBJ_DUMP) {
		char	_alter[PATH_MAX];

		(void) strlcpy(alter, crle->c_objdir, sizeof (alter));
		(void) realpath(alter, _alter);
		(void) snprintf(alter, PATH_MAX, MSG_ORIG(MSG_FMT_PATH),
		    _alter, file);
		if (strcmp(alter, obj->o_path) == 0) {
			(void) printf(MSG_INTL(MSG_ARG_ALT), crle->c_name,
			    obj->o_path);
			return (0);
		}
		obj->o_flags |= RTC_OBJ_DUMP;
	} else {
		(void) snprintf(alter, PATH_MAX, MSG_ORIG(MSG_FMT_PATH),
		    crle->c_objdir, file);
	}
	obj->o_flags |= RTC_OBJ_ALTER;

	/*
	 * If we're overriding an existing alternative with the real path, free
	 * up any previous alternative.
	 */
	if (obj->o_alter) {
		crle->c_strsize -= strlen(alter) + 1;
		fmt = MSG_INTL(MSG_DIA_ALTUPDATE);
	} else {
		fmt = MSG_INTL(MSG_DIA_ALTCREATE);
	}

	/*
	 * Allocate the new alternative and update the string table size.
	 */
	altsz = strlen(alter) + 1;
	if ((obj->o_alter = malloc(altsz)) == NULL)
		return (0);
	(void) strcpy(obj->o_alter, alter);

	crle->c_strsize += altsz;

	if (crle->c_flags & CRLE_VERBOSE)
		(void) printf(fmt, alter, obj->o_path);

	return (1);
}


/*
 * Establish an inode hash entry, this is unique for each dev hash table, and
 * establishes the unique object descriptor.
 */
static Hash_ent *
enterino(Crle_desc *crle, const char *name, struct stat *status, Half flags)
{
	Hash_ent	*ent;
	Hash_obj	*obj;
	Hash_tbl	*tbl;
	Aliste		idx;
	Addr		ino = (Addr)status->st_ino;
	ulong_t		dev = status->st_dev;
	Lword		info;
	int		found = 0;

	/*
	 * For configuration file verification we retain information about the
	 * file or directory.
	 */
	if (flags & RTC_OBJ_DIRENT)
		info = (Lword)status->st_mtime;
	else
		info = (Lword)status->st_size;

	/*
	 * Determine the objects device number and establish a hash table for
	 * for this devices inodes.
	 */
	for (APLIST_TRAVERSE(crle->c_inotbls, idx, tbl)) {
		if (tbl->t_ident == dev) {
			found = 1;
			break;
		}
	}
	if (found == 0) {
		if ((tbl = make_hash(crle->c_inobkts, HASH_INT, dev)) == NULL)
			return (NULL);
		if (aplist_append(&crle->c_inotbls, tbl, AL_CNT_CRLE) == NULL)
			return (NULL);
	}

	/*
	 * Reuse or add this new object to the inode hash table.
	 */
	if ((ent = get_hash(tbl, ino, 0,
	    (HASH_FND_ENT | HASH_ADD_ENT))) == NULL)
		return (NULL);

	/*
	 * If an object descriptor doesn't yet exist create one.
	 */
	if ((obj = ent->e_obj) == NULL) {
		if ((obj = calloc(sizeof (Hash_obj), 1)) == NULL)
			return (NULL);
		obj->o_tbl = tbl;
		obj->o_flags = flags;
		obj->o_info = info;

		/*
		 * Reallocate the objects name, as it might have been composed
		 * and passed to us on the stack.
		 */
		if ((obj->o_path = strdup(name)) == NULL)
			return (NULL);

		/*
		 * Assign this object to the original ino hash entry.
		 */
		ent->e_obj = obj;
	}
	return (ent);
}

/*
 * Basic directory entry, establishes entry information, updated global counts
 * and provides any diagnostics.
 */
static int
_enterdir(Crle_desc *crle, const char *dir, Hash_ent *ent, Hash_obj *obj)
{
	size_t	size = strlen(dir) + 1;
	char	*ndir;

	/*
	 * Establish this hash entries key (which is the directory name itself),
	 * assign the next available directory number, and its object.
	 */
	if ((ndir = malloc(size)) == NULL)
		return (0);
	(void) strcpy(ndir, dir);

	ent->e_key = (Addr)ndir;
	ent->e_id = crle->c_dirnum++;
	ent->e_obj = obj;

	/*
	 * Update string table information.  We add a dummy filename for each
	 * real directory so as to have a null terminated file table array for
	 * this directory.
	 */
	crle->c_strsize += size;
	crle->c_hashstrnum++;
	crle->c_filenum++;

	/*
	 * Provide any diagnostics.
	 */
	if (crle->c_flags & CRLE_VERBOSE) {
		const char	*fmt;

		if (obj->o_flags & RTC_OBJ_NOEXIST)
			fmt = MSG_INTL(MSG_DIA_NOEXIST);
		else
			fmt = MSG_INTL(MSG_DIA_DIR);

		(void) printf(fmt, ent->e_id, dir);
	}
	return (1);
}

/*
 * Establish a string hash entry for a directory.
 */
static Hash_ent *
enterdir(Crle_desc *crle, const char *odir, Half flags, struct stat *status)
{
	Hash_tbl	*stbl = crle->c_strtbl;
	Hash_ent	*ent;
	Hash_obj	*obj;
	char		rdir[PATH_MAX], *ndir;

	/*
	 * Establish the directories real name, this is the name that will be
	 * recorded in the object identifier.
	 */
	if (realpath(odir, rdir) == NULL)
		return (NULL);

	if (strcmp(odir, rdir))
		ndir = rdir;
	else
		ndir = (char *)odir;

	/*
	 * If we're not dealing with an all-entries directory (i.e., we're
	 * recording this directory because of its explicitly specified
	 * filename) leave off any filename specific attributes.
	 */
	if ((flags & RTC_OBJ_ALLENTS) == 0)
		flags &= ~(RTC_OBJ_ALTER | RTC_OBJ_DUMP | RTC_OBJ_GROUP);
	flags |= RTC_OBJ_DIRENT;

	/*
	 * Establish a inode table entry, and the objects unique descriptor.
	 */
	if ((ent = enterino(crle, ndir, status, flags)) == NULL)
		return (NULL);
	obj = ent->e_obj;

	/*
	 * Create a string table entry for the real directory.
	 */
	if ((ent = get_hash(stbl, (Addr)ndir, 0,
	    (HASH_FND_ENT | HASH_ADD_ENT))) == NULL)
		return (NULL);

	/*
	 * If this is a new entry reassign the directory name and assign a
	 * unique directory id.
	 */
	if (ent->e_id == 0) {
		if (_enterdir(crle, ndir, ent, obj) == 0)
			return (NULL);
	}

	/*
	 * If the directory name supplied is different than the real name we've
	 * just entered, continue to create an entry for it.
	 */
	if (ndir == odir)
		return (ent);

	/*
	 * Create a string table entry for this real directory.
	 */
	if ((ent = get_hash(stbl, (Addr)odir, 0,
	    (HASH_FND_ENT | HASH_ADD_ENT))) == NULL)
		return (NULL);

	/*
	 * If this is a new entry reassign the directory name and assign a
	 * unique directory id.
	 */
	if (ent->e_id == 0) {
		if (_enterdir(crle, odir, ent, obj) == 0)
			return (NULL);
	}

	return (ent);
}

/*
 * Establish a non-existent directory entry.  There is no inode entry created
 * for this, just a directory and its associated object.
 */
static Hash_ent *
enternoexistdir(Crle_desc *crle, const char *dir)
{
	Hash_ent	*ent;

	/*
	 * Reuse or add this new non-existent directory to the string table.
	 */
	if ((ent = get_hash(crle->c_strtbl, (Addr)dir, 0,
	    (HASH_FND_ENT | HASH_ADD_ENT))) == NULL)
		return (NULL);

	/*
	 * If this is a new entry, assign both the object and the directory
	 * entry information.
	 */
	if (ent->e_id == 0) {
		Hash_obj *	obj;

		if ((obj = calloc(sizeof (Hash_obj), 1)) == NULL)
			return (NULL);
		obj->o_flags = (RTC_OBJ_NOEXIST | RTC_OBJ_DIRENT);

		if (_enterdir(crle, dir, ent, obj) == 0)
			return (NULL);
	}
	return (ent);
}


/*
 * Basic file entry, establishes entry information, updated global counts
 * and provides any diagnostics.
 */
static int
_enterfile(Crle_desc *crle, const char *file, int off, Hash_ent *fent,
    Hash_ent *rent, Hash_ent *dent, Hash_obj *obj)
{
	size_t	size = strlen(file) + 1;
	char	*nfile;

	/*
	 * If this is a full file name reallocate it, as it might have been
	 * composed and passed to us on the stack.  Otherwise reuse the original
	 * directory name to satisfy the filename, here we record the offset of
	 * the file in the directory name so that we can reduce the string table
	 * in the final configuration file.
	 */
	if (off == 0) {
		if ((nfile = malloc(size)) == NULL)
			return (0);
		(void) strcpy(nfile, file);
	} else {
		nfile = (char *)file;
	}

	fent->e_key = (Addr)nfile;
	fent->e_off = off;

	/*
	 * Assign directory and directory id, and any real (full) path
	 * association.
	 */
	fent->e_dir = dent;
	fent->e_id = dent->e_id;
	fent->e_path = rent;

	/*
	 * Increment the file count for this directory.
	 */
	dent->e_cnt++;

	/*
	 * Assign this object to the new string hash entry.
	 */
	fent->e_obj = obj;

	/*
	 * Update string table information.
	 */
	crle->c_strsize += size;
	crle->c_hashstrnum++;
	crle->c_filenum++;

	/*
	 * Provide any diagnostics.
	 */
	if (crle->c_flags & CRLE_VERBOSE)
		(void) printf(MSG_INTL(MSG_DIA_FILE), fent->e_id, nfile);

	return (1);
}


/*
 * Establish a non-existent file entry.  There is no inode entry created for
 * this, just the files full and simple name, and its associated object.
 */
static Hash_ent *
enternoexistfile(Crle_desc *crle, const char *path, const char *file,
    Hash_ent *dent)
{
	Hash_ent	*rent, *ent;
	Hash_obj	*obj;
	int		off;

	/*
	 * Create a string table entry for the full filename.
	 */
	if ((rent = get_hash(crle->c_strtbl, (Addr)path, 0,
	    (HASH_FND_ENT | HASH_ADD_ENT))) == NULL)
		return (NULL);

	/*
	 * If this is a new entry, assign both the object and the full filename
	 * entry information.
	 */
	if (rent->e_id == 0) {
		if ((obj = calloc(sizeof (Hash_obj), 1)) == NULL)
			return (NULL);
		obj->o_flags = RTC_OBJ_NOEXIST;

		if (_enterfile(crle, path, 0, rent, 0, dent, obj) == 0)
			return (NULL);
	}
	obj = rent->e_obj;
	if ((obj->o_path = strdup(path)) == NULL)
		return (NULL);

	/*
	 * Express the filename in terms of the full pathname.  By reusing the
	 * name within the full filename we can reduce the overall string table
	 * size in the output configuration file.
	 */
	off = file - path;
	file = (char *)rent->e_key + off;

	/*
	 * Create a entry for the individual file within this directory.
	 */
	if ((ent = get_hash(crle->c_strtbl, (Addr)file, dent->e_id,
	    (HASH_FND_ENT | HASH_ADD_ENT))) == NULL)
		return (NULL);

	if (ent->e_id == 0) {
		if (_enterfile(crle, file, off, ent, rent, dent, obj) == 0)
			return (NULL);
	}
	return (ent);
}


/*
 * Establish a string hash entry for a file.
 */
static Hash_ent *
enterfile(Crle_desc *crle, const char *opath, const char *ofile, Half flags,
    Hash_ent *odent, struct stat *status)
{
	Hash_tbl	*stbl = crle->c_strtbl;
	Hash_ent	*ent, *rent, *ndent = odent;
	Hash_obj	*obj;
	size_t		size;
	char		rpath[PATH_MAX], *npath, *nfile;
	int		off;

	/*
	 * Establish the files real name, this is the name that will be
	 * recorded in the object identifier.
	 */
	if (realpath(opath, rpath) == NULL)
		return (NULL);

	if (strcmp(opath, rpath)) {
		npath = rpath;
		if (nfile = strrchr(npath, '/'))
			nfile++;
		else
			nfile = npath;

		/*
		 * Determine if the real pathname has a different directory to
		 * the original passed to us.
		 */
		size = nfile - npath;
		if (strncmp(opath, npath, size)) {
			char		_npath[PATH_MAX];
			struct stat	_status;

			(void) strncpy(_npath, npath, size);
			_npath[size - 1] = '\0';

			(void) stat(_npath, &_status);
			if ((ndent = enterdir(crle, _npath, flags,
			    &_status)) == NULL)
				return (NULL);
		}
	} else {
		npath = (char *)opath;
		nfile = (char *)ofile;
	}

	/*
	 * Establish an inode table entry, and the objects unique descriptor.
	 */
	if ((ent = enterino(crle, npath, status, flags)) == NULL)
		return (NULL);
	obj = ent->e_obj;

	/*
	 * Create a string table entry for the full filename.
	 */
	if ((rent = get_hash(stbl, (Addr)npath, 0,
	    (HASH_FND_ENT | HASH_ADD_ENT))) == NULL)
		return (NULL);
	if (rent->e_id == 0) {
		if (_enterfile(crle, npath, 0, rent, 0, ndent, obj) == 0)
			return (NULL);
	}

	/*
	 * Identify this entry and its directory as real paths.  If dldump(3dl)
	 * processing is required this flag is checked, as we only need to dump
	 * the real pathname.  Many other objects may point to the same
	 * alternative, but only one needs to be dumped.  In addition, during
	 * ld.so.1 validation, only this directory and file need be checked.
	 */
	rent->e_flags |= RTC_OBJ_REALPTH;
	ndent->e_flags |= RTC_OBJ_REALPTH;

	/*
	 * Express the filename in terms of the full pathname.  By reusing the
	 * name within the full filename we can reduce the overall string table
	 * size in the output configuration file.
	 */
	off = nfile - npath;
	nfile = (char *)rent->e_key + off;

	/*
	 * Create a entry for the individual file within this directory.
	 */
	if ((ent = get_hash(stbl, (Addr)nfile, ndent->e_id,
	    (HASH_FND_ENT | HASH_ADD_ENT))) == NULL)
		return (NULL);
	if (ent->e_id == 0) {
		if (_enterfile(crle, nfile, off, ent, rent, ndent, obj) == 0)
			return (NULL);
	}

	/*
	 * If the original path name is not equivalent to the real path name,
	 * then we had an alias (typically it's a symlink).  Add the path name
	 * to the string hash table and reference the object data structure.
	 */
	if (nfile == ofile)
		return (ent);

	/*
	 * Establish an inode table entry, and the objects unique descriptor.
	 */
	if ((ent = enterino(crle, opath, status, 0)) == NULL)
		return (NULL);
	obj = ent->e_obj;

	/*
	 * Create a string table entry for the full filename.
	 */
	if ((rent = get_hash(stbl, (Addr)opath, 0,
	    (HASH_FND_ENT | HASH_ADD_ENT))) == NULL)
		return (NULL);
	if (rent->e_id == 0) {
		if (_enterfile(crle, opath, 0, rent, 0, odent, obj) == 0)
			return (NULL);
	}

	/*
	 * Express the filename in terms of the full pathname.  By reusing the
	 * name within the full filename we can reduce the overall string table
	 * size in the output configuration file.
	 */
	off = ofile - opath;
	ofile = (char *)rent->e_key + off;

	/*
	 * Create a entry for the individual file within this directory.
	 */
	if ((ent = get_hash(stbl, (Addr)ofile, odent->e_id,
	    (HASH_FND_ENT | HASH_ADD_ENT))) == NULL)
		return (NULL);
	if (ent->e_id == 0) {
		if (_enterfile(crle, ofile, off, ent, rent, odent, obj) == 0)
			return (NULL);
	}

	return (ent);
}

/*
 * Add a file to configuration information.
 */
static int
inspect_file(Crle_desc *crle, const char *path, const char *file, Half flags,
    Hash_ent *dent, struct stat *status, int error)
{
	Hash_ent	*ent;
	Hash_obj	*obj;
	int		fd;
	Elf		*elf;
	GElf_Ehdr	ehdr;
	GElf_Xword	dyflags = 0;
	Aliste		idx;
	Hash_tbl	*tbl;
	Addr		ino = (Addr)status->st_ino;

	/*
	 * Determine whether this file (inode) has already been processed.
	 */
	for (APLIST_TRAVERSE(crle->c_inotbls, idx, tbl)) {
		if (tbl->t_ident != status->st_dev)
			continue;

		if ((ent = get_hash(tbl, ino, 0, HASH_FND_ENT)) == NULL)
			break;

		/*
		 * This files inode object does exist, make sure it has a file
		 * entry for this directory.
		 */
		if ((ent = enterfile(crle, path, file, flags, dent,
		    status)) == NULL)
			return (error);
		obj = ent->e_obj;

		/*
		 * If an alternative has been asked for, and one has not yet
		 * been established, create one.
		 */
		if ((flags & RTC_OBJ_ALTER) &&
		    ((obj->o_flags & RTC_OBJ_NOALTER) == 0)) {
			if (enteralt(crle, path, file, flags, obj) == 0)
				return (error);
		}
		return (0);
	}

	/*
	 * This is a new file, determine if it's a valid ELF file.
	 */
	if ((fd = open(path, O_RDONLY, 0)) == -1) {
		if (error) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
			    crle->c_name, path, strerror(err));
		}
		return (error);
	}

	/*
	 * Obtain an ELF descriptor and determine if we have a shared object.
	 */
	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
		if (error)
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_BEGIN),
			    crle->c_name, path, elf_errmsg(-1));
		(void) close(fd);
		return (error);
	}
	if ((elf_kind(elf) != ELF_K_ELF) ||
	    (gelf_getehdr(elf, &ehdr) == NULL) ||
	    (!((ehdr.e_type == ET_EXEC) || (ehdr.e_type == ET_DYN))) ||
	    (!((ehdr.e_ident[EI_CLASS] == M_CLASS) ||
	    (ehdr.e_machine == M_MACH)))) {
		if (error)
			(void) fprintf(stderr, MSG_INTL(MSG_ELF_TYPE),
			    crle->c_name, path);
		(void) close(fd);
		(void) elf_end(elf);
		return (error);
	}

	(void) close(fd);

	/*
	 * If we're generating alternative objects find this objects DT_FLAGS
	 * to insure it isn't marked as non-dumpable (libdl.so.1 falls into
	 * this category).
	 */
	if (flags & RTC_OBJ_DUMP)
		dyflags = _gelf_getdyndtflags_1(elf);

	/*
	 * Dynamic executables can be examined to determine their dependencies,
	 * dldump(3dl) their dependencies, and may even be dldump(3dl)'ed
	 * themselves.
	 *
	 * If we come across an executable while searching a directory
	 * (error == 0) it is ignored.
	 */
	if (ehdr.e_type == ET_EXEC) {
		if (error == 0) {
			(void) elf_end(elf);
			return (0);
		}

		/*
		 * If we're not dumping the application itself, or we've not
		 * asked to gather its dependencies then its rather useless.
		 */
		if ((flags & (RTC_OBJ_GROUP | RTC_OBJ_DUMP)) == 0) {
			(void) fprintf(stderr, MSG_INTL(MSG_GEN_INVFILE),
			    crle->c_name, path);
			(void) elf_end(elf);
			return (error);
		}

		/*
		 * If we're dumping the application under RTLD_REL_EXEC then the
		 * configuration file becomes specific to this application, so
		 * make sure we haven't been here before.
		 */
		if (crle->c_app && (flags & RTC_OBJ_DUMP) &&
		    (crle->c_dlflags & RTLD_REL_EXEC)) {
			(void) fprintf(stderr, MSG_INTL(MSG_ARG_MODE),
			    crle->c_name, crle->c_app, path);
			(void) elf_end(elf);
			return (error);
		}
	}

	/*
	 * Enter the file in the string hash table.
	 */
	if ((ent = enterfile(crle, path, file, flags, dent, status)) == NULL) {
		(void) elf_end(elf);
		return (error);
	}
	obj = ent->e_obj;

	if (flags & RTC_OBJ_ALTER) {
		/*
		 * If this object is marked as non-dumpable make sure we don't
		 * create a dldump(3dl) alternative.  A user requested
		 * alternative is acceptable.
		 */
		if ((flags & RTC_OBJ_DUMP) && (dyflags & DF_1_NODUMP)) {
			obj->o_flags |= RTC_OBJ_NOALTER;
			obj->o_flags &= ~(RTC_OBJ_ALTER | RTC_OBJ_DUMP);
		} else {
			if (enteralt(crle, path, file, flags, obj) == 0) {
				(void) elf_end(elf);
				return (error);
			}
		}
	}

	/*
	 * Executables are recorded in the configuration file either to allow
	 * for the configuration files update, or may indicate that the
	 * configuration file is specific to their use.
	 */
	if (ehdr.e_type == ET_EXEC) {
		obj->o_flags |= RTC_OBJ_EXEC;

		if ((flags & RTC_OBJ_DUMP) &&
		    (crle->c_dlflags & RTLD_REL_EXEC)) {
			/*
			 * Get the reallocated pathname rather than using the
			 * original (the original might be from an existing
			 * configuration file being updated, in which case the
			 * pointer will be unmapped before we get to use it).
			 */
			ent = get_hash(crle->c_strtbl, (Addr)path, 0,
			    HASH_FND_ENT);

			obj->o_flags |= RTC_OBJ_APP;
			crle->c_app = (char *)ent->e_key;
		}
	}

	/*
	 * If we've been asked to process this object as a group determine its
	 * dependencies.
	 */
	if (flags & RTC_OBJ_GROUP) {
		if (depend(crle, path, flags, &ehdr)) {
			(void) elf_end(elf);
			return (error);
		}
	}

	(void) elf_end(elf);
	return (0);
}

/*
 * Add a directory to configuration information.
 */
static int
inspect_dir(Crle_desc *crle, const char *name, Half flags, struct stat *status)
{
	Hash_tbl	*stbl = crle->c_strtbl;
	DIR		*dir;
	struct dirent	*dirent;
	Hash_ent	*ent;
	int		error = 0;
	struct stat	_status;
	char		path[PATH_MAX], * dst;
	const char	*src;

	/*
	 * Determine whether we've already visited this directory to process
	 * all its entries.
	 */
	if ((ent = get_hash(stbl, (Addr)name, 0, HASH_FND_ENT)) != NULL) {
		if (ent->e_obj->o_flags & RTC_OBJ_ALLENTS)
			return (0);
	} else {
		/*
		 * Create a directory hash entry.
		 */
		if ((ent = enterdir(crle, name, (flags | RTC_OBJ_ALLENTS),
		    status)) == NULL)
			return (1);
	}
	ent->e_obj->o_flags |= RTC_OBJ_ALLENTS;

	/*
	 * Establish the pathname buffer.
	 */
	for (dst = path, dst--, src = name; *src; src++)
		*++dst = *src;
	if (*dst++ != '/')
		*dst++ = '/';

	/*
	 * Access the directory in preparation for reading its entries.
	 */
	if ((dir = opendir(name)) == NULL)
		return (1);

	/*
	 * Read each entry from the directory looking for ELF files.
	 */
	while ((dirent = readdir(dir)) != NULL) {
		const char	*file = dirent->d_name;
		char		*_dst;

		/*
		 * Ignore "." and ".." entries.
		 */
		if ((file[0] == '.') && ((file[1] == '\0') ||
		    ((file[1] == '.') && (file[2] == '\0'))))
			continue;

		/*
		 * Complete full pathname, and reassign file to the new path.
		 */
		for (_dst = dst, src = file, file = dst; *src; _dst++, src++)
			*_dst = *src;
		*_dst = '\0';

		if (stat(path, &_status) == -1)
			continue;

		if ((_status.st_mode & S_IFMT) != S_IFREG)
			continue;

		if (inspect_file(crle, path, file, flags, ent, &_status, 0)) {
			error = 1;
			break;
		}
	}
	return (error);
}

/*
 * Inspect a file/dir name.  A stat(name) results in the following actions:
 *
 * The name doesn't exist:
 *	The name is assummed to be a non-existent directory and a directory
 *	cache entry is created to indicate this.
 *
 * The name is a directory:
 *	The directory is searched for appropriate files.
 *
 * The name is a file:
 *	The file is processed and added to the cache if appropriate.
 */
int
inspect(Crle_desc *crle, const char *name, Half flags)
{
	Hash_ent	*ent;
	const char	*file, *dir;
	struct stat	status;
	char		_name[PATH_MAX], _dir[PATH_MAX];
	Half		nflags = flags & ~RTC_OBJ_CMDLINE;
	int		noexist;

	/*
	 * If this is the first time through here establish a string table
	 * cache.
	 */
	if (crle->c_dirnum == 0) {
		if ((crle->c_strtbl = make_hash(crle->c_strbkts,
		    HASH_STR, 0)) == NULL)
			return (1);
		crle->c_dirnum = 1;
	}

	if (crle->c_flags & CRLE_VERBOSE)
		(void) printf(MSG_INTL(MSG_DIA_INSPECT), name);

	/*
	 * Determine whether the name exists.
	 */
	if ((noexist = stat(name, &status)) != 0) {
		if (errno != ENOENT) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_STAT),
			    crle->c_name, name, strerror(err));
			return (1);
		} else {
			/*
			 * If we've been asked to create an alternative object
			 * assume the object is a file and create a valid
			 * alternative entry.  This allows the creation of
			 * alternatives for files that might not yet be
			 * installed.
			 *
			 * Otherwise we have no idea whether the name specified
			 * is a file or directory, so we assume a directory and
			 * establish an object descriptor to mark this as
			 * non-existent. This allows us to mark things like
			 * platform specific directories as non-existent.
			 */
			if ((flags & (RTC_OBJ_DUMP | RTC_OBJ_ALTER)) !=
			    RTC_OBJ_ALTER) {
				if ((ent = enternoexistdir(crle, name)) == NULL)
					return (1);
				ent->e_flags |= flags;
				return (0);
			}
		}
	}

	/*
	 * Determine whether we're dealing with a directory or a file.
	 */
	if ((noexist == 0) && ((status.st_mode & S_IFMT) == S_IFDIR)) {
		/*
		 * Process the directory name to collect its shared objects into
		 * the configuration file.
		 */
		if (inspect_dir(crle, name, nflags, &status))
			return (1);

		ent = get_hash(crle->c_strtbl, (Addr)name, 0, HASH_FND_ENT);
		ent->e_flags |= flags;
		return (0);
	}

	/*
	 * If this isn't a regular file we might as well bail now.  Note that
	 * even if it is, we might still reject the file if it's not ELF later
	 * in inspect_file().
	 */
	if ((noexist == 0) && ((status.st_mode & S_IFMT) != S_IFREG)) {
		(void) fprintf(stderr, MSG_INTL(MSG_GEN_INVFILE), crle->c_name,
		    name);
		return (1);
	}

	/*
	 * Break the pathname into directory and filename components.
	 */
	if ((file = strrchr(name, '/')) == NULL) {
		dir = MSG_ORIG(MSG_DIR_DOT);
		(void) strcpy(_name, MSG_ORIG(MSG_PTH_DOT));
		(void) strcpy(&_name[MSG_PTH_DOT_SIZE], name);
		name = (const char *)_name;
		file = (const char *)&_name[MSG_PTH_DOT_SIZE];
	} else {
		size_t	off = file - name;

		if (file == name) {
			dir = MSG_ORIG(MSG_DIR_ROOT);
		} else {
			(void) strncpy(_dir, name, off);
			_dir[off] = '\0';
			dir = (const char *)_dir;
		}
		file++;
	}

	/*
	 * Determine whether we've already visited this directory and if not
	 * create it.
	 */
	if ((ent = get_hash(crle->c_strtbl,
	    (Addr)dir, 0, HASH_FND_ENT)) == NULL) {
		struct stat	_status;

		if (stat(dir, &_status) != 0) {
			if (errno != ENOENT) {
				int err = errno;
				(void) fprintf(stderr, MSG_INTL(MSG_SYS_STAT),
				    crle->c_name, name, strerror(err));
				return (1);
			} else {
				/*
				 * Note that this directory will be tagged as
				 * having an alternative - not that the
				 * directory does, but supposedly it contains
				 * a file that does.
				 */
				if ((ent = enternoexistdir(crle, dir)) == NULL)
					return (1);
				ent->e_flags |= nflags;
			}
		} else {
			if ((ent = enterdir(crle, dir, nflags,
			    &_status)) == NULL)
				return (1);
		}
	}

	/*
	 * Regardless of whether we've already processed this file (say from
	 * an RTC_OBJ_ALLENTS which we could determine from the above), continue
	 * to inspect the file.  It may require alternatives or something that
	 * hadn't be specified from the directory entry.
	 */
	if (noexist) {
		if ((ent = enternoexistfile(crle, name, file, ent)) == NULL)
			return (1);
		ent->e_flags |= nflags;
		if (enteralt(crle, name, file, flags, ent->e_obj) == 0)
			return (1);
	} else {
		if (inspect_file(crle, name, file, nflags, ent, &status, 1))
			return (1);
	}

	/*
	 * Make sure to propagate any RTC_OBJ_CMDLINE flag.
	 */
	if (ent = get_hash(crle->c_strtbl, (Addr)name, 0, HASH_FND_ENT))
		ent->e_flags |= (flags & RTC_OBJ_CMDLINE);

	return (0);
}
