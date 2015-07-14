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
 * Copyright 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	files.c
 *
 *	Various file related routines:
 *		Figure out if file exists
 *		Wildcard resolution for directory reader
 *		Directory reader
 */


/*
 * Included files
 */
#include <dirent.h>		/* opendir() */
#include <errno.h>		/* errno */
#include <mk/defs.h>
#include <mksh/macro.h>		/* getvar() */
#include <mksh/misc.h>		/* get_prop(), append_prop() */
#include <sys/stat.h>		/* lstat() */
#include <libintl.h>

/*
 * Defined macros
 */

/*
 * typedefs & structs
 */

/*
 * Static variables
 */

/*
 * File table of contents
 */
extern	timestruc_t&	exists(register Name target);
extern  void		set_target_stat(register Name target, struct stat buf);
static	timestruc_t&	vpath_exists(register Name target);
static	Name		enter_file_name(wchar_t *name_string, wchar_t *library);
static	Boolean		star_match(register char *string, register char *pattern);
static	Boolean		amatch(register wchar_t *string, register wchar_t *pattern);
  
/*
 *	exists(target)
 *
 *	Figure out the timestamp for one target.
 *
 *	Return value:
 *				The time the target was created
 *
 *	Parameters:
 *		target		The target to check
 *
 *	Global variables used:
 *		debug_level	Should we trace the stat call?
 *		recursion_level	Used for tracing
 *		vpath_defined	Was the variable VPATH defined in environment?
 */
timestruc_t&
exists(register Name target)
{
	struct stat		buf;
	register int		result;

	/* We cache stat information. */
	if (target->stat.time != file_no_time) {
		return target->stat.time;
	}

	/*
	 * If the target is a member, we have to extract the time
	 * from the archive.
	 */
	if (target->is_member &&
	    (get_prop(target->prop, member_prop) != NULL)) {
		return read_archive(target);
	}

	if (debug_level > 1) {
		(void) printf("%*sstat(%s)\n",
		              recursion_level,
		              "",
		              target->string_mb);
	}

	result = lstat_vroot(target->string_mb, &buf, NULL, VROOT_DEFAULT);
	if ((result != -1) && ((buf.st_mode & S_IFMT) == S_IFLNK)) {
                /*
		 * If the file is a symbolic link, we remember that
		 * and then we get the status for the refd file.
		 */
                target->stat.is_sym_link = true;
                result = stat_vroot(target->string_mb, &buf, NULL, VROOT_DEFAULT);
        } else {
                target->stat.is_sym_link = false;
	}

	if (result < 0) {
		target->stat.time = file_doesnt_exist;
		target->stat.stat_errno = errno;
		if ((errno == ENOENT) &&
		    vpath_defined &&
/* azv, fixing bug 1262942, VPATH works with a leaf name
 * but not a directory name.
 */
		    (target->string_mb[0] != (int) slash_char) ) {
/* BID_1214655 */
/* azv */
			vpath_exists(target);
			// return vpath_exists(target);
		}
	} else {
		/* Save all the information we need about the file */
		target->stat.stat_errno = 0;
		target->stat.is_file = true;
		target->stat.mode = buf.st_mode & 0777;
		target->stat.size = buf.st_size;
		target->stat.is_dir =
		  BOOLEAN((buf.st_mode & S_IFMT) == S_IFDIR);
		if (target->stat.is_dir) {
			target->stat.time = file_is_dir;
		} else {
			/* target->stat.time = buf.st_mtime; */
/* BID_1129806 */
/* vis@nbsp.nsk.su */
			target->stat.time = MAX(buf.st_mtim, file_min_time);
		}
	}
	if ((target->colon_splits > 0) &&
	    (get_prop(target->prop, time_prop) == NULL)) {
		append_prop(target, time_prop)->body.time.time =
		  target->stat.time;
	}
	return target->stat.time;
}

/*
 *	set_target_stat( target, buf)
 *
 *	Called by exists() to set some stat fields in the Name structure
 *	to those read by the stat_vroot() call (from disk).
 *
 *	Parameters:
 *		target		The target whose stat field is set
 *		buf		stat values (on disk) of the file
 *				represented by target.
 */
void
set_target_stat(register Name target, struct stat buf)
{
	target->stat.stat_errno = 0;
	target->stat.is_file = true;
	target->stat.mode = buf.st_mode & 0777;
	target->stat.size = buf.st_size;
	target->stat.is_dir =
	  BOOLEAN((buf.st_mode & S_IFMT) == S_IFDIR);
	if (target->stat.is_dir) {
		target->stat.time = file_is_dir;
	} else {
		/* target->stat.time = buf.st_mtime; */
/* BID_1129806 */
/* vis@nbsp.nsk.su */
		target->stat.time = MAX(buf.st_mtim, file_min_time);
	}
}


/*
 *	vpath_exists(target)
 *
 *	Called if exists() discovers that there is a VPATH defined.
 *	This function stats the VPATH translation of the target.
 *
 *	Return value:
 *				The time the target was created
 *
 *	Parameters:
 *		target		The target to check
 *
 *	Global variables used:
 *		vpath_name	The Name "VPATH", used to get macro value
 */
static timestruc_t&
vpath_exists(register Name target)
{
	wchar_t			*vpath;
	wchar_t			file_name[MAXPATHLEN];
	wchar_t			*name_p;
	Name			alias;

	/*
	 * To avoid recursive search through VPATH when exists(alias) is called
	 */
	vpath_defined = false;

	Wstring wcb(getvar(vpath_name));
	Wstring wcb1(target);

	vpath = wcb.get_string();

	while (*vpath != (int) nul_char) {
		name_p = file_name;
		while ((*vpath != (int) colon_char) &&
		       (*vpath != (int) nul_char)) {
			*name_p++ = *vpath++;
		}
		*name_p++ = (int) slash_char;
		(void) wcscpy(name_p, wcb1.get_string());
		alias = GETNAME(file_name, FIND_LENGTH);
		if (exists(alias) != file_doesnt_exist) {
			target->stat.is_file = true;
			target->stat.mode = alias->stat.mode;
			target->stat.size = alias->stat.size;
			target->stat.is_dir = alias->stat.is_dir;
			target->stat.time = alias->stat.time;
			maybe_append_prop(target, vpath_alias_prop)->
						body.vpath_alias.alias = alias;
			target->has_vpath_alias_prop = true;
			vpath_defined = true;
			return alias->stat.time;
		}
		while ((*vpath != (int) nul_char) &&
		       ((*vpath == (int) colon_char) || iswspace(*vpath))) {
			vpath++;
		}
	}
	/*
	 * Restore vpath_defined
	 */
	vpath_defined = true;
	return target->stat.time;
}

/*
 *	read_dir(dir, pattern, line, library)
 *
 *	Used to enter the contents of directories into makes namespace.
 *	Presence of a file is important when scanning for implicit rules.
 *	read_dir() is also used to expand wildcards in dependency lists.
 *
 *	Return value:
 *				Non-0 if we found files to match the pattern
 *
 *	Parameters:
 *		dir		Path to the directory to read
 *		pattern		Pattern for that files should match or NULL
 *		line		When we scan using a pattern we enter files
 *				we find as dependencies for this line
 *		library		If we scan for "lib.a(<wildcard-member>)"
 *
 *	Global variables used:
 *		debug_level	Should we trace the dir reading?
 *		dot		The Name ".", compared against
 *		sccs_dir_path	The path to the SCCS dir (from PROJECTDIR)
 *		vpath_defined	Was the variable VPATH defined in environment?
 *		vpath_name	The Name "VPATH", use to get macro value
 */
int
read_dir(Name dir, wchar_t *pattern, Property line, wchar_t *library)
{
	wchar_t			file_name[MAXPATHLEN];
	wchar_t			*file_name_p = file_name;
	Name			file;
	wchar_t			plain_file_name[MAXPATHLEN];
	wchar_t			*plain_file_name_p;
	Name			plain_file;
	wchar_t			tmp_wcs_buffer[MAXPATHLEN];
	DIR			*dir_fd;
	int			m_local_dependency=0;
#define d_fileno d_ino
        register struct dirent  *dp;
	wchar_t			*vpath = NULL;
	wchar_t			*p;
	int			result = 0;

	if(dir->hash.length >= MAXPATHLEN) {
		return 0;
	}

	Wstring wcb(dir);
	Wstring vps;

	/* A directory is only read once unless we need to expand wildcards. */
	if (pattern == NULL) {
		if (dir->has_read_dir) {
			return 0;
		}
		dir->has_read_dir = true;
	}
	/* Check if VPATH is active and setup list if it is. */
	if (vpath_defined && (dir == dot)) {
		vps.init(getvar(vpath_name));
		vpath = vps.get_string();
	}

	/*
	 * Prepare the string where we build the full name of the
	 * files in the directory.
	 */
	if ((dir->hash.length > 1) || (wcb.get_string()[0] != (int) period_char)) {
		(void) wcscpy(file_name, wcb.get_string());
		MBSTOWCS(wcs_buffer, "/");
		(void) wcscat(file_name, wcs_buffer);
		file_name_p = file_name + wcslen(file_name);
	}

	/* Open the directory. */
vpath_loop:
	dir_fd = opendir(dir->string_mb);
	if (dir_fd == NULL) {
		return 0;
	}

	/* Read all the directory entries. */
	while ((dp = readdir(dir_fd)) != NULL) {
		/* We ignore "." and ".." */
		if ((dp->d_fileno == 0) ||
		    ((dp->d_name[0] == (int) period_char) &&
		     ((dp->d_name[1] == 0) ||
		      ((dp->d_name[1] == (int) period_char) &&
		       (dp->d_name[2] == 0))))) {
			continue;
		}
		/*
		 * Build the full name of the file using whatever
		 * path supplied to the function.
		 */
		MBSTOWCS(tmp_wcs_buffer, dp->d_name);
		(void) wcscpy(file_name_p, tmp_wcs_buffer);
		file = enter_file_name(file_name, library);
		if ((pattern != NULL) && amatch(tmp_wcs_buffer, pattern)) {
			/*
			 * If we are expanding a wildcard pattern, we
			 * enter the file as a dependency for the target.
			 */
			if (debug_level > 0){
				WCSTOMBS(mbs_buffer, pattern);
				(void) printf(gettext("'%s: %s' due to %s expansion\n"),
					      line->body.line.target->string_mb,
					      file->string_mb,
					      mbs_buffer);
			}
			enter_dependency(line, file, false);
			result++;
		} else {
			/*
			 * If the file has an SCCS/s. file,
			 * we will detect that later on.
			 */
			file->stat.has_sccs = NO_SCCS;
		/*
		 * If this is an s. file, we also enter it as if it
		 * existed in the plain directory.
		 */
		if ((dp->d_name[0] == 's') &&
		    (dp->d_name[1] == (int) period_char)) {
	
			MBSTOWCS(tmp_wcs_buffer, dp->d_name + 2);
			plain_file_name_p = plain_file_name;
			(void) wcscpy(plain_file_name_p, tmp_wcs_buffer);
			plain_file = GETNAME(plain_file_name, FIND_LENGTH);
			plain_file->stat.is_file = true;
			plain_file->stat.has_sccs = HAS_SCCS;
			/*
			 * Enter the s. file as a dependency for the
			 * plain file.
			 */
			maybe_append_prop(plain_file, sccs_prop)->
			  body.sccs.file = file;
			MBSTOWCS(tmp_wcs_buffer, dp->d_name + 2);
			if ((pattern != NULL) &&
			    amatch(tmp_wcs_buffer, pattern)) {
				if (debug_level > 0) {
					WCSTOMBS(mbs_buffer, pattern);
					(void) printf(gettext("'%s: %s' due to %s expansion\n"),
						      line->body.line.target->
						      string_mb,
						      plain_file->string_mb,
						      mbs_buffer);
				}
				enter_dependency(line, plain_file, false);
				result++;
			}
		}
	      }
	}
	(void) closedir(dir_fd);
	if ((vpath != NULL) && (*vpath != (int) nul_char)) {
		while ((*vpath != (int) nul_char) &&
		       (iswspace(*vpath) || (*vpath == (int) colon_char))) {
			vpath++;
		}
		p = vpath;
		while ((*vpath != (int) colon_char) &&
		       (*vpath != (int) nul_char)) {
			vpath++;
		}
		if (vpath > p) {
			dir = GETNAME(p, vpath - p);
			goto vpath_loop;
		}
	}
/*
 * look into SCCS directory only if it's not svr4. For svr4 dont do that.
 */

/*
 * Now read the SCCS directory.
 * Files in the SCSC directory are considered to be part of the set of
 * files in the plain directory. They are also entered in their own right.
 * Prepare the string where we build the true name of the SCCS files.
 */
	(void) wcsncpy(plain_file_name,
		      file_name,
		      file_name_p - file_name);
	plain_file_name[file_name_p - file_name] = 0;
	plain_file_name_p = plain_file_name + wcslen(plain_file_name);

        if(!svr4) {

	  if (sccs_dir_path != NULL) {
		wchar_t		tmp_wchar;
		wchar_t		path[MAXPATHLEN];
		char		mb_path[MAXPATHLEN];

		if (file_name_p - file_name > 0) {
			tmp_wchar = *file_name_p;
			*file_name_p = 0;
			WCSTOMBS(mbs_buffer, file_name);
			(void) sprintf(mb_path, "%s/%s/SCCS",
				        sccs_dir_path,
				        mbs_buffer);
			*file_name_p = tmp_wchar;
		} else {
			(void) sprintf(mb_path, "%s/SCCS", sccs_dir_path);
		}
		MBSTOWCS(path, mb_path);
		(void) wcscpy(file_name, path);
	  } else {
		MBSTOWCS(wcs_buffer, "SCCS");
		(void) wcscpy(file_name_p, wcs_buffer);
	  }
	} else {
		MBSTOWCS(wcs_buffer, ".");
		(void) wcscpy(file_name_p, wcs_buffer);
	}
	/* Internalize the constructed SCCS dir name. */
	(void) exists(dir = GETNAME(file_name, FIND_LENGTH));
	/* Just give up if the directory file doesnt exist. */
	if (!dir->stat.is_file) {
		return result;
	}
	/* Open the directory. */
	dir_fd = opendir(dir->string_mb);
	if (dir_fd == NULL) {
		return result;
	}
	MBSTOWCS(wcs_buffer, "/");
	(void) wcscat(file_name, wcs_buffer);
	file_name_p = file_name + wcslen(file_name);

	while ((dp = readdir(dir_fd)) != NULL) {
		if ((dp->d_fileno == 0) ||
		    ((dp->d_name[0] == (int) period_char) &&
		     ((dp->d_name[1] == 0) ||
		      ((dp->d_name[1] == (int) period_char) &&
		       (dp->d_name[2] == 0))))) {
			continue;
		}
		/* Construct and internalize the true name of the SCCS file. */
		MBSTOWCS(wcs_buffer, dp->d_name);
		(void) wcscpy(file_name_p, wcs_buffer);
		file = GETNAME(file_name, FIND_LENGTH);
		file->stat.is_file = true;
		file->stat.has_sccs = NO_SCCS;
		/*
		 * If this is an s. file, we also enter it as if it
		 * existed in the plain directory.
		 */
		if ((dp->d_name[0] == 's') &&
		    (dp->d_name[1] == (int) period_char)) {
	
			MBSTOWCS(wcs_buffer, dp->d_name + 2);
			(void) wcscpy(plain_file_name_p, wcs_buffer);
			plain_file = GETNAME(plain_file_name, FIND_LENGTH);
			plain_file->stat.is_file = true;
			plain_file->stat.has_sccs = HAS_SCCS;
				/* if sccs dependency is already set,skip */
			if(plain_file->prop) {
				Property sprop = get_prop(plain_file->prop,sccs_prop);
				if(sprop != NULL) {
					if (sprop->body.sccs.file) {
						goto try_pattern;
					}
				}
			}

			/*
			 * Enter the s. file as a dependency for the
			 * plain file.
			 */
			maybe_append_prop(plain_file, sccs_prop)->
			  body.sccs.file = file;
try_pattern:
			MBSTOWCS(tmp_wcs_buffer, dp->d_name + 2);
			if ((pattern != NULL) &&
			    amatch(tmp_wcs_buffer, pattern)) {
				if (debug_level > 0) {
					WCSTOMBS(mbs_buffer, pattern);
					(void) printf(gettext("'%s: %s' due to %s expansion\n"),
						      line->body.line.target->
						      string_mb,
						      plain_file->string_mb,
						      mbs_buffer);
				}
				enter_dependency(line, plain_file, false);
				result++;
			}
		}
	}
	(void) closedir(dir_fd);

	return result;
}

/*
 *	enter_file_name(name_string, library)
 *
 *	Helper function for read_dir().
 *
 *	Return value:
 *				The Name that was entered
 *
 *	Parameters:
 *		name_string	Name of the file we want to enter
 *		library		The library it is a member of, if any
 *
 *	Global variables used:
 */
static Name
enter_file_name(wchar_t *name_string, wchar_t *library)
{
	wchar_t		buffer[STRING_BUFFER_LENGTH];
	String_rec	lib_name;
	Name		name;
	Property	prop;

	if (library == NULL) {
		name = GETNAME(name_string, FIND_LENGTH);
		name->stat.is_file = true;
		return name;
	}

	INIT_STRING_FROM_STACK(lib_name, buffer);
	append_string(library, &lib_name, FIND_LENGTH);
	append_char((int) parenleft_char, &lib_name);
	append_string(name_string, &lib_name, FIND_LENGTH);
	append_char((int) parenright_char, &lib_name);

	name = GETNAME(lib_name.buffer.start, FIND_LENGTH);
	name->stat.is_file = true;
	name->is_member = true;
	prop = maybe_append_prop(name, member_prop);
	prop->body.member.library = GETNAME(library, FIND_LENGTH);
	prop->body.member.library->stat.is_file = true;
	prop->body.member.entry = NULL;
	prop->body.member.member = GETNAME(name_string, FIND_LENGTH);
	prop->body.member.member->stat.is_file = true;
	return name;
}

/*
 *	star_match(string, pattern)
 *
 *	This is a regular shell type wildcard pattern matcher
 *	It is used when xpanding wildcards in dependency lists
 *
 *	Return value:
 *				Indication if the string matched the pattern
 *
 *	Parameters:
 *		string		String to match
 *		pattern		Pattern to match it against
 *
 *	Global variables used:
 */
static Boolean
star_match(register wchar_t *string, register wchar_t *pattern)
{
	register int		pattern_ch;

	switch (*pattern) {
	case 0:
		return succeeded;
	case bracketleft_char:
	case question_char:
	case asterisk_char:
		while (*string) {
			if (amatch(string++, pattern)) {
				return succeeded;
			}
		}
		break;
	default:
		pattern_ch = (int) *pattern++;
		while (*string) {
			if ((*string++ == pattern_ch) &&
			    amatch(string, pattern)) {
				return succeeded;
			}
		}
		break;
	}
	return failed;
}

/*
 *	amatch(string, pattern)
 *
 *	Helper function for shell pattern matching
 *
 *	Return value:
 *				Indication if the string matched the pattern
 *
 *	Parameters:
 *		string		String to match
 *		pattern		Pattern to match it against
 *
 *	Global variables used:
 */
static Boolean
amatch(register wchar_t *string, register wchar_t *pattern)
{
	register long		lower_bound;
	register long		string_ch;
	register long		pattern_ch;
	register int		k;

top:
	for (; 1; pattern++, string++) {
		lower_bound = 017777777777;
		string_ch = *string;
		switch (pattern_ch = *pattern) {
		case bracketleft_char:
			k = 0;
			while ((pattern_ch = *++pattern) != 0) {
				switch (pattern_ch) {
				case bracketright_char:
					if (!k) {
						return failed;
					}
					string++;
					pattern++;
					goto top;
				case hyphen_char:
					k |= (lower_bound <= string_ch) &&
					     (string_ch <=
					      (pattern_ch = pattern[1]));
				default:
					if (string_ch ==
					    (lower_bound = pattern_ch)) {
						k++;
					}
				}
			}
			return failed;
		case asterisk_char:
			return star_match(string, ++pattern);
		case 0:
			return BOOLEAN(!string_ch);
		case question_char:
			if (string_ch == 0) {
				return failed;
			}
			break;
		default:
			if (pattern_ch != string_ch) {
				return failed;
			}
			break;
		}
	}
	/* NOTREACHED */
}

