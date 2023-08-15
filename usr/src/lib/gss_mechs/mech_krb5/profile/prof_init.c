/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * prof_init.c --- routines that manipulate the user-visible profile_t
 * 	object.
 */

#include "prof_int.h"

#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <errno.h>

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif
typedef int32_t prof_int32;

errcode_t KRB5_CALLCONV
profile_init(const_profile_filespec_t *files, profile_t *ret_profile)
{
	const_profile_filespec_t *fs;
	profile_t profile;
	prf_file_t  new_file, last = 0;
	errcode_t retval = 0;

	profile = malloc(sizeof(struct _profile_t));
	if (!profile)
		return ENOMEM;
	memset(profile, 0, sizeof(struct _profile_t));
	profile->magic = PROF_MAGIC_PROFILE;

        /* if the filenames list is not specified return an empty profile */
        if ( files ) {
	    for (fs = files; !PROFILE_LAST_FILESPEC(*fs); fs++) {
		retval = profile_open_file(*fs, &new_file);
		/* if this file is missing, skip to the next */
		if (retval == ENOENT || retval == EACCES) {
			continue;
		}
		if (retval) {
			profile_release(profile);
			return retval;
		}
		if (last)
			last->next = new_file;
		else
			profile->first_file = new_file;
		last = new_file;
	    }
	    /*
	     * If last is still null after the loop, then all the files were
	     * missing, so return the appropriate error.
	     */
	    if (!last) {
		profile_release(profile);
		return ENOENT;
	    }
	}

        *ret_profile = profile;
        return 0;
}

#define COUNT_LINKED_LIST(COUNT, PTYPE, START, FIELD)	\
	{						\
	    int cll_counter = 0;			\
	    PTYPE cll_ptr = (START);			\
	    while (cll_ptr != NULL) {			\
		cll_counter++;				\
		cll_ptr = cll_ptr->FIELD;		\
	    }						\
	    (COUNT) = cll_counter;			\
	}

errcode_t KRB5_CALLCONV
profile_copy(profile_t old_profile, profile_t *new_profile)
{
    size_t size, i;
    const_profile_filespec_t *files;
    prf_file_t file;
    errcode_t err;

    /* The fields we care about are read-only after creation, so
       no locking is needed.  */
    COUNT_LINKED_LIST (size, prf_file_t, old_profile->first_file, next);
    files = malloc ((size+1) * sizeof(*files));
    if (files == NULL)
	return errno;
    for (i = 0, file = old_profile->first_file; i < size; i++, file = file->next)
	files[i] = file->data->filespec;
    files[size] = NULL;
    err = profile_init (files, new_profile);
    free (files);
    return err;
}

errcode_t KRB5_CALLCONV
profile_init_path(const_profile_filespec_list_t filepath,
		  profile_t *ret_profile)
{
	int n_entries, i;
	unsigned int ent_len;
	const char *s, *t;
	profile_filespec_t *filenames;
	errcode_t retval;

	/* count the distinct filename components */
	for(s = filepath, n_entries = 1; *s; s++) {
		if (*s == ':')
			n_entries++;
	}

	/* the array is NULL terminated */
	filenames = (profile_filespec_t*) malloc((n_entries+1) * sizeof(char*));
	if (filenames == 0)
		return ENOMEM;

	/* measure, copy, and skip each one */
	/* Solaris Kerberos */
	for(s = filepath, i=0; ((t = strchr(s, ':')) != NULL) ||
			((t=s+strlen(s)) != NULL); s=t+1, i++) {
		ent_len = t-s;
		filenames[i] = (char*) malloc(ent_len + 1);
		if (filenames[i] == 0) {
			/* if malloc fails, free the ones that worked */
			while(--i >= 0) free(filenames[i]);
                        free(filenames);
			return ENOMEM;
		}
		strncpy(filenames[i], s, ent_len);
		filenames[i][ent_len] = 0;
		if (*t == 0) {
			i++;
			break;
		}
	}
	/* cap the array */
	filenames[i] = 0;

	retval = profile_init((const_profile_filespec_t *) filenames,
			      ret_profile);

	/* count back down and free the entries */
	while(--i >= 0) free(filenames[i]);
	free(filenames);

	return retval;
}

errcode_t KRB5_CALLCONV
profile_is_writable(profile_t profile, int *writable)
{
    if (!profile || profile->magic != PROF_MAGIC_PROFILE)
        return PROF_MAGIC_PROFILE;

    if (!writable)
        return EINVAL;

    if (profile->first_file)
        *writable = (profile->first_file->data->flags & PROFILE_FILE_RW);

    return 0;
}

errcode_t KRB5_CALLCONV
profile_is_modified(profile_t profile, int *modified)
{
    if (!profile || profile->magic != PROF_MAGIC_PROFILE)
        return PROF_MAGIC_PROFILE;

    if (!modified)
        return EINVAL;

    if (profile->first_file)
        *modified = (profile->first_file->data->flags & PROFILE_FILE_DIRTY);

    return 0;
}

errcode_t KRB5_CALLCONV
profile_flush(profile_t profile)
{
	if (!profile || profile->magic != PROF_MAGIC_PROFILE)
		return PROF_MAGIC_PROFILE;

	if (profile->first_file)
		return profile_flush_file(profile->first_file);

	return 0;
}

errcode_t KRB5_CALLCONV
profile_flush_to_file(profile_t profile, const_profile_filespec_t outfile)
{
	if (!profile || profile->magic != PROF_MAGIC_PROFILE)
		return PROF_MAGIC_PROFILE;

	if (profile->first_file)
		return profile_flush_file_to_file(profile->first_file,
						  outfile);

	return 0;
}

errcode_t KRB5_CALLCONV
profile_flush_to_buffer(profile_t profile, char **buf)
{
    return profile_flush_file_data_to_buffer(profile->first_file->data, buf);
}

void KRB5_CALLCONV
profile_free_buffer(profile_t profile, char *buf)
{
    free(buf);
}

void KRB5_CALLCONV
profile_abandon(profile_t profile)
{
	prf_file_t	p, next;

	if (!profile || profile->magic != PROF_MAGIC_PROFILE)
		return;

	for (p = profile->first_file; p; p = next) {
		next = p->next;
		profile_free_file(p);
	}
	profile->magic = 0;
	free(profile);
}

void KRB5_CALLCONV
profile_release(profile_t profile)
{
	prf_file_t	p, next;

	if (!profile || profile->magic != PROF_MAGIC_PROFILE)
		return;

	for (p = profile->first_file; p; p = next) {
		next = p->next;
		profile_close_file(p);
	}
	profile->magic = 0;
	free(profile);
}

/*
 * Here begins the profile serialization functions.
 */
/*ARGSUSED*/
errcode_t profile_ser_size(const char *unused, profile_t profile,
			   size_t *sizep)
{
    size_t	required;
    prf_file_t	pfp;

    required = 3*sizeof(prof_int32);
    for (pfp = profile->first_file; pfp; pfp = pfp->next) {
	required += sizeof(prof_int32);
	required += strlen(pfp->data->filespec);
    }
    *sizep += required;
    return 0;
}

static void pack_int32(prof_int32 oval, unsigned char **bufpp, size_t *remainp)
{
    (*bufpp)[0] = (unsigned char) ((oval >> 24) & 0xff);
    (*bufpp)[1] = (unsigned char) ((oval >> 16) & 0xff);
    (*bufpp)[2] = (unsigned char) ((oval >> 8) & 0xff);
    (*bufpp)[3] = (unsigned char) (oval & 0xff);
    *bufpp += sizeof(prof_int32);
    *remainp -= sizeof(prof_int32);
}

errcode_t profile_ser_externalize(const char *unused, profile_t profile,
				  unsigned char **bufpp, size_t *remainp)
{
    errcode_t		retval;
    size_t		required;
    unsigned char	*bp;
    size_t		remain;
    prf_file_t		pfp;
    prof_int32		fcount, slen;

    required = 0;
    bp = *bufpp;
    remain = *remainp;
    retval = EINVAL;
    if (profile) {
	retval = ENOMEM;
	(void) profile_ser_size(unused, profile, &required);
	if (required <= remain) {
	    fcount = 0;
	    for (pfp = profile->first_file; pfp; pfp = pfp->next)
		fcount++;
	    pack_int32(PROF_MAGIC_PROFILE, &bp, &remain);
	    pack_int32(fcount, &bp, &remain);
	    for (pfp = profile->first_file; pfp; pfp = pfp->next) {
		slen = (prof_int32) strlen(pfp->data->filespec);
		pack_int32(slen, &bp, &remain);
		if (slen) {
		    memcpy(bp, pfp->data->filespec, (size_t) slen);
		    bp += slen;
		    remain -= (size_t) slen;
		}
	    }
	    pack_int32(PROF_MAGIC_PROFILE, &bp, &remain);
	    retval = 0;
	    *bufpp = bp;
	    *remainp = remain;
	}
    }
    return(retval);
}

static int unpack_int32(prof_int32 *intp, unsigned char **bufpp,
			size_t *remainp)
{
    if (*remainp >= sizeof(prof_int32)) {
	*intp = (((prof_int32) (*bufpp)[0] << 24) |
		 ((prof_int32) (*bufpp)[1] << 16) |
		 ((prof_int32) (*bufpp)[2] << 8) |
		 ((prof_int32) (*bufpp)[3]));
	*bufpp += sizeof(prof_int32);
	*remainp -= sizeof(prof_int32);
	return 0;
    }
    else
	return 1;
}

/*ARGSUSED*/
errcode_t profile_ser_internalize(const char *unused, profile_t *profilep,
				  unsigned char **bufpp, size_t *remainp)
{
	errcode_t		retval;
	unsigned char	*bp;
	size_t		remain;
	int			i;
	prof_int32		fcount, tmp;
	profile_filespec_t		*flist = 0;

	bp = *bufpp;
	remain = *remainp;

	if (remain >= 12)
		(void) unpack_int32(&tmp, &bp, &remain);
	else
		tmp = 0;

	if (tmp != PROF_MAGIC_PROFILE) {
		retval = EINVAL;
		goto cleanup;
	}

	(void) unpack_int32(&fcount, &bp, &remain);
	retval = ENOMEM;

	flist = (profile_filespec_t *) malloc(sizeof(profile_filespec_t) * (fcount + 1));
	if (!flist)
		goto cleanup;

	memset(flist, 0, sizeof(char *) * (fcount+1));
	for (i=0; i<fcount; i++) {
		if (!unpack_int32(&tmp, &bp, &remain)) {
			flist[i] = (char *) malloc((size_t) (tmp+1));
			if (!flist[i])
				goto cleanup;
			memcpy(flist[i], bp, (size_t) tmp);
			flist[i][tmp] = '\0';
			bp += tmp;
			remain -= (size_t) tmp;
		}
	}

	if (unpack_int32(&tmp, &bp, &remain) ||
	    (tmp != PROF_MAGIC_PROFILE)) {
		retval = EINVAL;
		goto cleanup;
	}

	if ((retval = profile_init((const_profile_filespec_t *) flist,
				   profilep)))
		goto cleanup;

	*bufpp = bp;
	*remainp = remain;

cleanup:
	if (flist) {
		for (i=0; i<fcount; i++) {
			if (flist[i])
				free(flist[i]);
		}
		free(flist);
	}
	return(retval);
}


errcode_t
profile_get_options_boolean(profile, section, options)
    profile_t		profile;
    char **		section;
    profile_options_boolean *options;
{
    char ** actual_section;
    char * value = NULL;
    errcode_t retval = 0;
    int i, max_i;

    for (max_i = 0; section[max_i]; max_i++);
    if (actual_section = (char **)malloc((max_i + 2) * sizeof(char *))) {
        for (actual_section[max_i + 1] = NULL, i = 0; section[i]; i++)
	    actual_section[i] = section[i];

	for (i = 0; options[i].name; i++) {
	    if (options[i].found) continue;
	    actual_section[max_i] = options[i].name;
	    retval = profile_get_value(profile, (const char **) actual_section,
                                       (const char **)&value);
	    if (retval && (retval != PROF_NO_RELATION) &&
	       (retval != PROF_NO_SECTION)) {
		free(actual_section);
		return(retval);
	    }
	    if ((retval == 0) && value) {
		/*
		 * Any string other than true will turn off the
		 *option
		 */
		if (strncmp(value,"true",4) == 0)
		    *(options[i].value) = 1;
		else
		    *(options[i].value) = 0;
		options[i].found = 1;

		}
	}
	free(actual_section);
    } else {
	retval = ENOMEM;
    }
    return(retval);
}

errcode_t
profile_get_options_string(profile, section, options)
    profile_t		profile;
    char **		section;
    profile_option_strings *options;
{
    char ** actual_section;
    char * value = NULL;
    errcode_t retval = 0;
    int i, max_i;

    for (max_i = 0; section[max_i]; max_i++);
    if (actual_section = (char **)malloc((max_i + 2) * sizeof(char *))) {
        for (actual_section[max_i + 1] = NULL, i = 0; section[i]; i++)
	    actual_section[i] = section[i];

	for (i = 0; options[i].name; i++) {
	    if (options[i].found) continue;
	    actual_section[max_i] = options[i].name;
	    retval = profile_get_value(profile, (const char **) actual_section,
                                       (const char **)&value);
	    if (retval && (retval != PROF_NO_RELATION) &&
	       (retval != PROF_NO_SECTION)) {
		free(actual_section);
		return(retval);
	    }
	    if ((retval == 0) && value) {
		*options[i].value = malloc(strlen(value)+1);
		if (*options[i].value == 0)
			retval = ENOMEM;
		strcpy(*options[i].value, value);
	        options[i].found = 1;
    	    } else
		*options[i].value = 0;
	}
	free(actual_section);
    } else {
	retval = ENOMEM;
    }
    return(retval);
}
