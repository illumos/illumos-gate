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

#include	<sys/mman.h>
#include	<sys/types.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<errno.h>
#include	<stdio.h>
#include	<string.h>
#include	"rtc.h"
#include	"_crle.h"
#include	"msg.h"


#define	MAXNBKTS 10007

static const int hashsize[] = {
	3,	7,	13,	31,	53,	67,	83,	97,
	101,	151,	211,	251,	307,	353,	401,	457,	503,
	557,	601,	653,	701,	751,	809,	859,	907,	953,
	1009,	1103,	1201,	1301,	1409,	1511,	1601,	1709,	1801,
	1901,	2003,	2111,	2203,	2309,	2411,	2503,	2609,	2707,
	2801,	2903,	3001,	3109,	3203,	3301,	3407,	3511,	3607,
	3701,	3803,	3907,	4001,	5003,   6101,   7001,   8101,   9001,
	MAXNBKTS
};

/*
 * Generate a configuration file from the internal configuration information.
 * (very link-editor like).
 */
int
genconfig(Crle_desc *crle)
{
	int		ndx, bkt;
	size_t		size, hashoff = 0, stroff = 0, objoff = 0;
	size_t		diroff = 0, fileoff = 0, envoff = 0;
	size_t		fltroff = 0, flteoff = 0;
	Addr		addr;
	Rtc_id		*id;
	Rtc_head	*head;
	Word		*hashtbl, *hashbkt, *hashchn, hashbkts = 0;
	char		*strtbl, *_strtbl;
	Rtc_obj		*objtbl;
	Rtc_dir		*dirtbl;
	Rtc_file	*filetbl;
	Rtc_env		*envtbl;
	Rtc_fltr	*fltrtbl;
	Rtc_flte	*fltetbl, * _fltetbl;
	Hash_tbl	*stbl = crle->c_strtbl;
	Hash_ent	*ent;

	/*
	 * Establish the size of the configuration file.
	 */
	size = S_ROUND(sizeof (Rtc_head), sizeof (Word));

	if (crle->c_hashstrnum) {
		hashoff = size;

		/*
		 * Increment the hash string number to account for an initial
		 * null entry.  Indexes start at 1 to simplify hash lookup.
		 */
		crle->c_hashstrnum++;

		/*
		 * Determine the hash table size.  Establish the number of
		 * buckets from the number of strings, the number of chains is
		 * equivalent to the number of objects, and two entries for the
		 * nbucket and nchain entries.
		 */
		for (ndx = 0; ndx < (sizeof (hashsize) / sizeof (int)); ndx++) {
			if (crle->c_hashstrnum > hashsize[ndx])
				continue;
			hashbkts = hashsize[ndx];
			break;
		}
		if (hashbkts == 0)
			hashbkts = MAXNBKTS;
		size += ((2 + hashbkts + crle->c_hashstrnum) * sizeof (Word));
		size = S_ROUND(size, sizeof (Lword));
		objoff = size;

		/*
		 * Add the object table size (account for an 8-byte alignment
		 * requirement for each object).
		 */
		size += (crle->c_hashstrnum *
		    S_ROUND(sizeof (Rtc_obj), sizeof (Lword)));

		/*
		 * Add the file descriptor arrays.
		 */
		fileoff = size;
		size += S_ROUND((crle->c_filenum * sizeof (Rtc_file)),
		    sizeof (Word));

		/*
		 * Add the directory descriptor array.
		 */
		diroff = size;
		size += S_ROUND((crle->c_dirnum * sizeof (Rtc_dir)),
		    sizeof (Word));
	}

	/*
	 * Add any environment string array (insure zero last entry).
	 */
	if (crle->c_envnum) {
		envoff = size;
		size += S_ROUND(((crle->c_envnum + 1) * sizeof (Rtc_env)),
		    sizeof (Word));
	}

	/*
	 * Add any filter/filtee association arrays (insure zero last entry for
	 * the filter array, the filtee arrays are already accounted for).
	 */
	if (crle->c_fltrnum) {
		fltroff = size;
		size += S_ROUND(((crle->c_fltrnum + 1) * sizeof (Rtc_fltr)),
		    sizeof (Word));
		flteoff = size;
		size += S_ROUND((crle->c_fltenum * sizeof (Rtc_flte)),
		    sizeof (Word));
	}

	/*
	 * Add the string table size (this may contain library and/or secure
	 * path strings, in addition to any directory/file strings).
	 */
	if (crle->c_strsize) {
		stroff = size;
		size += S_ROUND(crle->c_strsize, sizeof (Word));
	}

	/* Account for addition of Rtc_id block at the start */
	if (crle->c_flags & CRLE_ADDID)
		size += sizeof (Rtc_id);

	/*
	 * Truncate our temporary file now that we know its size and map it.
	 */
	if (ftruncate(crle->c_tempfd, size) == -1) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_TRUNC),
		    crle->c_name, crle->c_tempname, strerror(err));
		(void) close(crle->c_tempfd);
		return (1);
	}
	if ((addr = (Addr)mmap(0, size, (PROT_READ | PROT_WRITE), MAP_SHARED,
	    crle->c_tempfd, 0)) == (Addr)-1) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_MMAP),
		    crle->c_name, crle->c_tempname, strerror(err));
		(void) close(crle->c_tempfd);
		return (1);
	}

	/*
	 * Save the mapped files info for possible dldump(3C) updates.
	 */
	crle->c_tempaddr = addr;
	crle->c_tempsize = size;

	/*
	 * Rtc_id goes at the top, followed by the Rtc_head. We base
	 * all offset calculations relative to Rtc_head, not from
	 * the top of the file. This eases backwards compatability to
	 * older versons that lacked the Rtc_id at the top.
	 */
	if (crle->c_flags & CRLE_ADDID) {
		/* The contents of the Rtc_id are all known at compile time */
		static const Rtc_id id_template = {
			RTC_ID_MAG0, RTC_ID_MAG1, RTC_ID_MAG2, RTC_ID_MAG3,
			M_CLASS, M_DATA, M_MACH,
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0 } };

		id = (Rtc_id *) addr;
		*id = id_template;	/* Fill in the Rtc_id data */
		addr += sizeof (Rtc_id);
	} else {
		id = NULL;
	}
	crle->c_tempheadaddr = addr;
	head = (Rtc_head *)addr;

	/*
	 * Establish the real address of each of the structures within the file.
	 */
	head->ch_hash = hashoff;
	/* LINTED */
	hashtbl = (Word *)(CAST_PTRINT(char *, head->ch_hash) + addr);

	head->ch_obj = objoff;
	/* LINTED */
	objtbl = (Rtc_obj *)(CAST_PTRINT(char *, head->ch_obj) + addr);
	objtbl = (Rtc_obj *)S_ROUND((uintptr_t)(objtbl + 1), sizeof (Lword));

	head->ch_file = fileoff;
	/* LINTED */
	filetbl = (Rtc_file *)(CAST_PTRINT(char *, head->ch_file) + addr);

	head->ch_dir = diroff;
	/* LINTED */
	dirtbl = (Rtc_dir *)(CAST_PTRINT(char *, head->ch_dir) + addr);

	head->ch_env = envoff;
	/* LINTED */
	envtbl = (Rtc_env *)(CAST_PTRINT(char *, head->ch_env) + addr);

	head->ch_fltr = fltroff;
	/* LINTED */
	fltrtbl = (Rtc_fltr *)(CAST_PTRINT(char *, head->ch_fltr) + addr);
	head->ch_flte = flteoff;
	/* LINTED */
	fltetbl = _fltetbl = (Rtc_flte *)(CAST_PTRINT(char *, head->ch_flte) +
	    addr);

	head->ch_str = stroff;
	strtbl = _strtbl = (char *)(CAST_PTRINT(char *, head->ch_str) + addr);

	/*
	 * Fill in additional basic header information.
	 */
	head->ch_version = RTC_VER_CURRENT;

	if (crle->c_flags & CRLE_ALTER)
		head->ch_cnflags |= RTC_HDR_ALTER;
	if (crle->c_flags & CRLE_DUMP) {
		head->ch_cnflags |= RTC_HDR_IGNORE;
		head->ch_dlflags = crle->c_dlflags;
	}
#ifdef _ELF64
	head->ch_cnflags |= RTC_HDR_64;
#endif

	head->ch_cnflags |= RTC_HDR_UPM;
	/*
	 * If we have a hash table then there are directory and file entries
	 * to process.
	 */
	if (crle->c_hashstrnum) {
		hashtbl[0] = hashbkts;
		hashtbl[1] = crle->c_hashstrnum;
		hashbkt = &hashtbl[2];
		hashchn = &hashtbl[2 + hashbkts];

		/*
		 * Insure all hash chain and directory/filename table entries
		 * are cleared.
		 */
		(void) memset(hashchn, 0, (crle->c_hashstrnum * sizeof (Word)));
		(void) memset(dirtbl, 0, (strtbl - (char *)dirtbl));

		/*
		 * Loop through the current string table list inspecting only
		 * directories.
		 */
		for (ndx = 1, bkt = 0; bkt < stbl->t_size; bkt++) {
			for (ent = stbl->t_entry[bkt]; ent; ent = ent->e_next) {
				Word		hashval;
				Hash_obj	*obj = ent->e_obj;
				char		*dir = (char *)ent->e_key;
				Rtc_dir		*_dirtbl;

				/*
				 * Skip any empty and non-directory entries.
				 */
				if ((obj == NULL) ||
				    ((obj->o_flags & RTC_OBJ_DIRENT) == 0))
					continue;

				/*
				 * Assign basic object attributes.
				 */
				objtbl->co_hash = ent->e_hash;
				objtbl->co_id = ent->e_id;
				objtbl->co_flags = obj->o_flags | ent->e_flags;
				objtbl->co_info = obj->o_info;

				ent->e_cobj = objtbl;

				/*
				 * Assign the directory name (from its key),
				 * and copy its name to the string table.
				 */
				objtbl->co_name = (Addr)(_strtbl - strtbl);
				(void) strcpy(_strtbl, dir);
				_strtbl += strlen(dir) + 1;

				/*
				 * Establish an entry in the directory table and
				 * reserve space for its associated filename
				 * entries (note, we add a trailing null file
				 * entry to simplify later inspection of the
				 * final configuration file.
				 */
				_dirtbl = &dirtbl[ent->e_id - 1];
				_dirtbl->cd_file =
				    CAST_PTRINT(Word, ((char *)filetbl- addr));
				_dirtbl->cd_obj =
				    CAST_PTRINT(Word, ((char *)objtbl - addr));

				/* LINTED */
				filetbl = (Rtc_file *)((char *)filetbl +
				    ((ent->e_cnt + 1) * sizeof (Rtc_file)));

				/*
				 * Add this object to the hash table.
				 */
				hashval = ent->e_hash % hashbkts;
				hashchn[ndx] = hashbkt[hashval];
				hashbkt[hashval] = ndx++;

				/*
				 * Increment Rt_obj pointer (make sure pointer
				 * falls on an 8-byte boundary).
				 */
				objtbl =
				    (Rtc_obj *)S_ROUND((uintptr_t)(objtbl + 1),
				    sizeof (Lword));
			}
		}

		/*
		 * Now collect all pathnames.  These are typically full
		 * pathnames, but may also be relative.  Simple filenames are
		 * recorded as offsets into these pathnames, thus we need to
		 * establish the new pathname first.
		 */
		for (bkt = 0; bkt < stbl->t_size; bkt++) {
			for (ent = stbl->t_entry[bkt]; ent; ent = ent->e_next) {
				Word		hashval;
				Hash_obj	*obj = ent->e_obj;
				char		*file = (char *)ent->e_key;
				char		*_str;
				Rtc_dir		*_dirtbl;
				Rtc_file	*_filetbl;
				int		_id;

				/*
				 * Skip empty and directory entries, and any
				 * simple filename entries.
				 */
				if ((obj == NULL) ||
				    (obj->o_flags & RTC_OBJ_DIRENT) ||
				    (ent->e_off))
					continue;

				/*
				 * Assign basic object attributes.
				 */
				objtbl->co_hash = ent->e_hash;
				objtbl->co_id = ent->e_id;
				objtbl->co_flags = obj->o_flags | ent->e_flags;
				objtbl->co_info = obj->o_info;

				ent->e_cobj = objtbl;

				/*
				 * Assign the file name (from its key),
				 * and copy its name to the string table.
				 */
				objtbl->co_name = (Addr)(_strtbl - strtbl);
				(void) strcpy(_strtbl, file);
				_strtbl += strlen(file) + 1;

				/*
				 * Add this file to its associated directory.
				 */
				_dirtbl = &dirtbl[ent->e_id - 1];
				/* LINTED */
				_filetbl = (Rtc_file *)(CAST_PTRINT(char *,
				    _dirtbl->cd_file) + addr);

				_id = --ent->e_dir->e_cnt;
				_filetbl[_id].cf_obj =
				    CAST_PTRINT(Word, ((char *)objtbl - addr));

				/*
				 * If object has an alternative, record it in
				 * the string table and assign the alternate
				 * pointer.  The new alternative offset is
				 * retained for reuse in other filename entries.
				 */
				if ((objtbl->co_flags & RTC_OBJ_ALTER) &&
				    (obj->o_calter == 0)) {
					_str = obj->o_alter;
					objtbl->co_alter = obj->o_calter =
					    (Addr)(_strtbl - strtbl);
					(void) strcpy(_strtbl, _str);
					_strtbl += strlen(_str) + 1;
				} else
					objtbl->co_alter = obj->o_calter;

				/*
				 * If object identifies the specific application
				 * for which this cache is relevant, record it
				 * in the header.
				 */
				if ((objtbl->co_flags &
				    (RTC_OBJ_APP | RTC_OBJ_REALPTH)) ==
				    (RTC_OBJ_APP | RTC_OBJ_REALPTH))
					head->ch_app = _filetbl[_id].cf_obj;

				/*
				 * Add this object to the hash table.
				 */
				hashval = ent->e_hash % hashbkts;
				hashchn[ndx] = hashbkt[hashval];
				hashbkt[hashval] = ndx++;

				/*
				 * Increment Rt_obj pointer (make sure pointer
				 * falls on an 8-byte boundary).
				 */
				objtbl = (Rtc_obj *)
				    S_ROUND((uintptr_t)(objtbl + 1),
				    sizeof (Lword));
			}
		}

		/*
		 * Finally pick off any simple filenames.
		 */
		for (bkt = 0; bkt < stbl->t_size; bkt++) {
			for (ent = stbl->t_entry[bkt]; ent; ent = ent->e_next) {
				Word		hashval;
				Hash_obj *	obj = ent->e_obj;
				Rtc_dir *	_dirtbl;
				Rtc_file *	_filetbl;
				int		_id;

				/*
				 * Skip everything except simple filenames.
				 */
				if (ent->e_off == 0)
					continue;

				/*
				 * Assign basic object attributes.
				 */
				objtbl->co_hash = ent->e_hash;
				objtbl->co_id = ent->e_id;
				objtbl->co_flags = obj->o_flags | ent->e_flags;
				objtbl->co_info = obj->o_info;
				objtbl->co_alter = obj->o_calter;

				ent->e_cobj = objtbl;

				/*
				 * Assign the file name from its full name.
				 */
				objtbl->co_name = (Addr)(CAST_PTRINT(char *,
				    ent->e_path->e_cobj->co_name) + ent->e_off);

				/*
				 * Add this file to its associated directory.
				 */
				_dirtbl = &dirtbl[ent->e_id - 1];
				/* LINTED */
				_filetbl = (Rtc_file *)
				    (CAST_PTRINT(char *, _dirtbl->cd_file) +
				    addr);

				_id = --ent->e_dir->e_cnt;
				_filetbl[_id].cf_obj =
				    CAST_PTRINT(Word, ((char *)objtbl - addr));

				/*
				 * Add this object to the hash table.
				 */
				hashval = ent->e_hash % hashbkts;
				hashchn[ndx] = hashbkt[hashval];
				hashbkt[hashval] = ndx++;

				/*
				 * Increment Rt_obj pointer (make sure pointer
				 * falls on an 8-byte boundary).
				 */
				objtbl = (Rtc_obj *)
				    S_ROUND((uintptr_t)(objtbl + 1),
				    sizeof (Lword));
			}
		}
	}

	/*
	 * Add any library, or secure path definitions.
	 */
	if (crle->c_edlibpath) {
		head->ch_edlibpath = head->ch_str + (_strtbl - strtbl);

		(void) strcpy(_strtbl, crle->c_edlibpath);
		_strtbl += strlen((char *)crle->c_edlibpath) + 1;
	} else
		head->ch_edlibpath = 0;

	/*
	 * a.out is no longer supported, but remains in the crle file
	 * format
	 */
	head->ch_adlibpath = 0;

	if (crle->c_eslibpath) {
		head->ch_eslibpath = head->ch_str + (_strtbl - strtbl);

		(void) strcpy(_strtbl, crle->c_eslibpath);
		_strtbl += strlen((char *)crle->c_eslibpath) + 1;
	} else
		head->ch_eslibpath = 0;

	/*
	 * a.out is no longer supported, but remains in the crle file
	 * format
	 */
	head->ch_aslibpath = 0;

	/*
	 * Add any environment variable entries.
	 */
	if (crle->c_envnum) {
		Env_desc	*env;
		Aliste		idx;

		for (APLIST_TRAVERSE(crle->c_env, idx, env)) {
			envtbl->env_str = head->ch_str + (_strtbl - strtbl);
			envtbl->env_flags = env->e_flags;

			(void) strcpy(_strtbl, env->e_str);
			_strtbl += env->e_totsz;

			envtbl++;
		}
		envtbl->env_str = 0;
		envtbl->env_flags = 0;
	}

	/*
	 * Add any filter/filtee association entries.
	 */
	if (crle->c_fltrnum) {
		Flt_desc	*flt;
		Aliste		idx1;

		for (APLIST_TRAVERSE(crle->c_flt, idx1, flt)) {
			Hash_ent	*flte;
			Aliste		idx2;

			/*
			 * Establish the filter name, and filtee string, as
			 * offsets into the configuration files string table.
			 * Establish the filtee as the offset into the filtee
			 * table.
			 */
			fltrtbl->fr_filter = flt->f_fent->e_cobj->co_name;
			fltrtbl->fr_string = _strtbl - strtbl;
			(void) strcpy(_strtbl, flt->f_str);
			_strtbl += flt->f_strsz;
			fltrtbl->fr_filtee = (Word)
			    ((uintptr_t)_fltetbl - (uintptr_t)fltetbl);

			for (APLIST_TRAVERSE(flt->f_filtee, idx2, flte)) {
				/*
				 * Establish the filtee name as the offset into
				 * the configuration files string table.
				 */
				_fltetbl->fe_filtee = flte->e_cobj->co_name;
				_fltetbl++;
			}
			_fltetbl->fe_filtee = 0;
			_fltetbl++, fltrtbl++;
		}
		fltrtbl->fr_filter = 0;
		fltrtbl->fr_filtee = 0;
	}

	/*
	 * Flush everything out.
	 */
	(void) close(crle->c_tempfd);
	if (msync((void *)crle->c_tempaddr, crle->c_tempsize, MS_ASYNC) == -1) {
		int err = errno;
		(void) fprintf(stderr, MSG_INTL(MSG_SYS_TRUNC),
		    crle->c_name, crle->c_tempname, strerror(err));
		return (1);
	}

	return (0);
}

/*
 * Update a configuration file.  If dldump()'ed images have been created then
 * the memory reservation of those images is added to the configuration file.
 * The temporary file is then moved into its final resting place.
 */
int
updateconfig(Crle_desc * crle)
{
	Rtc_head *head = (Rtc_head *)crle->c_tempheadaddr;

	if (crle->c_flags & CRLE_DUMP) {
		head->ch_cnflags &= ~RTC_HDR_IGNORE;

		if (msync((void *)crle->c_tempaddr, crle->c_tempsize,
		    MS_ASYNC) == -1) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_TRUNC),
			    crle->c_name, crle->c_tempname, strerror(err));
			return (1);
		}
	}

	/*
	 * If an original configuration file exists, remove it.
	 */
	if (crle->c_flags & CRLE_EXISTS)
		(void) unlink(crle->c_confil);

	/*
	 * Move the config file to its final resting place.  If the two files
	 * exist on the same filesystem a rename is sufficient.
	 */
	if (crle->c_flags & CRLE_DIFFDEV) {
		int	fd;

		if ((fd = open(crle->c_confil, (O_RDWR | O_CREAT | O_TRUNC),
		    0666)) == -1) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_OPEN),
			    crle->c_name, crle->c_confil, strerror(err));
			return (1);
		}
		if (write(fd, (void *)crle->c_tempaddr, crle->c_tempsize) !=
		    crle->c_tempsize) {
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_SYS_WRITE),
			    crle->c_name, crle->c_confil, strerror(err));
			return (1);
		}
		(void) close(fd);
		(void) unlink(crle->c_tempname);
	} else
		(void) rename(crle->c_tempname, crle->c_confil);

	return (0);
}
