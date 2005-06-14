#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * prof_file.c ---- routines that manipulate an individual profile file.
 */

#include <autoconf.h>

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>

#include "prof_int.h"

#ifndef NO_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifndef NO_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <errno.h>


#if defined(_MSDOS) || defined(_WIN32)
#include <io.h>
#define HAVE_STAT	
#define stat _stat
#endif

#ifndef PROFILE_USES_PATHS
#include <FSp_fopen.h>

static OSErr GetMacOSTempFilespec (
	const	FSSpec*	inFilespec,
			FSSpec*	outFilespec);

#endif

static int rw_access(filespec)
	profile_filespec_t filespec;
{
#ifdef HAVE_ACCESS
	if (access(filespec, W_OK) == 0)
		return 1;
	else
		return 0;
#else
	/*
	 * We're on a substandard OS that doesn't support access.  So
	 * we kludge a test using stdio routines, and hope fopen
	 * checks the r/w permissions.
	 */
	FILE	*f;

#ifdef PROFILE_USES_PATHS
	f = fopen(filespec, "r+");
#else
	f = FSp_fopen(&filespec, "r+");
#endif
	if (f) {
		fclose(f);
		return 1;
	}
	return 0;
#endif
}

errcode_t profile_open_file(filespec, ret_prof)
	const_profile_filespec_t filespec;
	prf_file_t *ret_prof;
{
	prf_file_t	prf;
	errcode_t	retval;
	char		*home_env = 0;
	int		len;

	prf = (prf_file_t) malloc(sizeof(struct _prf_file_t));
	if (!prf)
		return ENOMEM;
	memset(prf, 0, sizeof(struct _prf_file_t));
		
#ifndef macintosh
	len = strlen(filespec)+1;
	if (filespec[0] == '~' && filespec[1] == '/') {
		home_env = getenv("HOME");
		if (home_env)
			len += strlen(home_env);
	}
	prf->filespec = (char *) malloc(len);
	if (!prf->filespec) {
		free(prf);
		return ENOMEM;
	}
	if (home_env) {
		strcpy(prf->filespec, home_env);
		strcat(prf->filespec, filespec+1);
	} else
		strcpy(prf->filespec, filespec);
	prf->magic = PROF_MAGIC_FILE;
#else
	prf->filespec = filespec;
	prf->magic = PROF_MAGIC_FILE;
#endif

	retval = profile_update_file(prf);
	if (retval) {
		profile_close_file(prf);
		return retval;
	}

	*ret_prof = prf;
	return 0;
}

errcode_t profile_update_file(prf)
	prf_file_t prf;
{
	errcode_t retval;
#ifdef HAVE_STAT
	struct stat st;
#endif
	FILE *f;

#ifdef HAVE_STAT
	if (stat(prf->filespec, &st))
		return errno;
	if (st.st_mtime == prf->timestamp)
		return 0;
	if (prf->root) {
		profile_free_node(prf->root);
		prf->root = 0;
	}
	if (prf->comment) {
		free(prf->comment);
		prf->comment = 0;
	}
#else
	/*
	 * If we don't have the stat() call, assume that our in-core
	 * memory image is correct.  That is, we won't reread the
	 * profile file if it changes.
	 */
	if (prf->root)
		return 0;
#endif
	errno = 0;
#ifdef PROFILE_USES_PATHS
	f = fopen(prf->filespec, "r");
#else
	f = FSp_fopen (&prf->filespec, "r");
#endif
	if (f == NULL) {
		retval = errno;
		if (retval == 0)
			retval = ENOENT;
		return retval;
	}
	prf->upd_serial++;
	prf->flags = 0;
	if (rw_access(prf->filespec))
		prf->flags |= PROFILE_FILE_RW;
	retval = profile_parse_file(f, &prf->root);
	fclose(f);
	if (retval)
		return retval;
#ifdef HAVE_STAT
	prf->timestamp = st.st_mtime;
#endif
	return 0;
}

#ifndef PROFILE_USES_PATHS
OSErr GetMacOSTempFilespec (
	const	FSSpec*	inFileSpec,
			FSSpec*	outFileSpec)
{
	OSErr	err;
	
	err = FindFolder (inFileSpec -> vRefNum, kTemporaryFolderType,
		kCreateFolder, &(outFileSpec -> vRefNum), &(outFileSpec -> parID));
	if (err != noErr)
		return err;
		
	BlockMoveData (&(inFileSpec -> name), &(outFileSpec -> name), StrLength (inFileSpec -> name) + 1);
	return noErr;
}
#endif


errcode_t profile_flush_file(prf)
	prf_file_t prf;
{
	FILE		*f;
	profile_filespec_t new_file;
	profile_filespec_t old_file;
	errcode_t	retval = 0;
	
	if (!prf || prf->magic != PROF_MAGIC_FILE)
		return PROF_MAGIC_FILE;
	
	if ((prf->flags & PROFILE_FILE_DIRTY) == 0)
		return 0;

	retval = ENOMEM;
	
#ifdef PROFILE_USES_PATHS
	new_file = old_file = 0;
	new_file = (char *) malloc(strlen(prf->filespec) + 5);
	if (!new_file)
		goto errout;
	old_file = (char *) malloc(strlen(prf->filespec) + 5);
	if (!old_file)
		goto errout;

	sprintf(new_file, "%s.$$$", prf->filespec);
	sprintf(old_file, "%s.bak", prf->filespec);

	errno = 0;

	f = fopen(new_file, "w");
#else
	/* On MacOS, we do this by writing to a new file and then atomically
	swapping the files with a file system call */
	GetMacOSTempFilespec (&prf->filespec, &new_file);
	f = FSp_fopen (&new_file, "w");
#endif
	
	if (!f) {
		retval = errno;
		if (retval == 0)
			retval = PROF_FAIL_OPEN;
		goto errout;
	}

	profile_write_tree_file(prf->root, f);
	if (fclose(f) != 0) {
		retval = errno;
		goto errout;
	}

#ifdef PROFILE_USES_PATHS
	unlink(old_file);
	if (rename(prf->filespec, old_file)) {
		retval = errno;
		goto errout;
	}
	if (rename(new_file, prf->filespec)) {
		retval = errno;
		rename(old_file, prf->filespec); /* back out... */
		goto errout;
	}
#else
	{
		OSErr err = FSpExchangeFiles (&prf->filespec, &new_file);
		if (err != noErr) {
			retval = ENFILE;
			goto errout;
		}
		FSpDelete (&new_file);
	}
#endif


	prf->flags = 0;
	if (rw_access(prf->filespec))
		prf->flags |= PROFILE_FILE_RW;
	retval = 0;
	
errout:
#ifdef PROFILE_USES_PATHS
	if (new_file)
		free(new_file);
	if (old_file)
		free(old_file);
#endif
	return retval;
}


void profile_free_file(prf)
	prf_file_t prf;
{
#ifdef PROFILE_USES_PATHS
	if (prf->filespec)
		free(prf->filespec);
#endif
	if (prf->root)
		profile_free_node(prf->root);
	if (prf->comment)
		free(prf->comment);
	prf->magic = 0;
	free(prf);

	return;
}

errcode_t profile_close_file(prf)
	prf_file_t prf;
{
	errcode_t	retval;
	
	retval = profile_flush_file(prf);
	if (retval)
		return retval;
	profile_free_file(prf);
	return 0;
}

