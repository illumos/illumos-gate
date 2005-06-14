#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * prof_set.c --- routines that expose the public interfaces for
 * 	inserting, updating and deleting items from the profile.
 *
 * WARNING: These routines only look at the first file opened in the
 * profile.  It's not clear how to handle multiple files, actually.
 * In the future it may be necessary to modify this public interface,
 * or possibly add higher level functions to support this correctly.
 *
 * WARNING: We're not yet doing locking yet, either.  
 *
 */

#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <errno.h>

#include "prof_int.h"

static errcode_t rw_setup(profile)
	profile_t	profile;
{
   	prf_file_t	file;
	errcode_t	retval;

	if (!profile)
		return PROF_NO_PROFILE;

	if (profile->magic != PROF_MAGIC_PROFILE)
		return PROF_MAGIC_PROFILE;

	file = profile->first_file;
	if (!(file->flags & PROFILE_FILE_RW))
		return PROF_READ_ONLY;

	/* Don't update the file if we've already made modifications */
	if (file->flags & PROFILE_FILE_DIRTY)
		return 0;
			
	retval = profile_update_file(file);
	
	return retval;
}


/* 
 * Delete or update a particular child node 
 * 
 * ADL - 2/23/99, rewritten TYT 2/25/99
 */
KRB5_DLLIMP errcode_t KRB5_CALLCONV
profile_update_relation(profile, names, old_value, new_value)
	profile_t	profile;
	const char	**names;
	const char	*old_value;
	const char	*new_value;
{	
	errcode_t	retval;
	struct profile_node *section, *node;
	void		*state;
	const char	**cpp;

	retval = rw_setup(profile);
	if (retval)
		return retval;
	
	if (names == 0 || names[0] == 0 || names[1] == 0)
		return PROF_BAD_NAMESET;

	if (!old_value || !*old_value)
		return PROF_EINVAL;

	section = profile->first_file->root;
	for (cpp = names; cpp[1]; cpp++) {
		state = 0;
		retval = profile_find_node(section, *cpp, 0, 1,
					   &state, &section);
		if (retval)
			return retval;
	}

	state = 0;
	retval = profile_find_node(section, *cpp, old_value, 0, &state, &node);
	if (retval)
		return retval;

	if (new_value)
		retval = profile_set_relation_value(node, new_value);
	else
		retval = profile_remove_node(node);
	if (retval)
		return retval;

	profile->first_file->flags |= PROFILE_FILE_DIRTY;
	
	return 0;
}

/* 
 * Clear a particular all of the relations with a specific name.
 * 
 * TYT - 2/25/99
 */
KRB5_DLLIMP errcode_t KRB5_CALLCONV
profile_clear_relation(profile, names)
	profile_t	profile;
	const char	**names;
{	
	errcode_t	retval;
	struct profile_node *section, *node;
	void		*state;
	const char	**cpp;
	
	retval = rw_setup(profile);
	if (retval)
		return retval;
	
	if (names == 0 || names[0] == 0 || names[1] == 0)
		return PROF_BAD_NAMESET;

	section = profile->first_file->root;
	for (cpp = names; cpp[1]; cpp++) {
		state = 0;
		retval = profile_find_node(section, *cpp, 0, 1,
					   &state, &section);
		if (retval)
			return retval;
	}

	state = 0;
	do {
		retval = profile_find_node(section, *cpp, 0, 0, &state, &node);
		if (retval)
			return retval;
		retval = profile_remove_node(node);
		if (retval)
			return retval;
	} while (state);

	profile->first_file->flags |= PROFILE_FILE_DIRTY;
	
	return 0;
}

/* 
 * Rename a particular section; if the new_section name is NULL,
 * delete it.
 * 
 * ADL - 2/23/99, rewritten TYT 2/25/99
 */
KRB5_DLLIMP errcode_t KRB5_CALLCONV
profile_rename_section(profile, names, new_name)
	profile_t	profile;
	const char	**names;
	const char	*new_name;
{	
	errcode_t	retval;
	struct profile_node *section, *node;
	void		*state;
	const char	**cpp;
	
	retval = rw_setup(profile);
	if (retval)
		return retval;
	
	if (names == 0 || names[0] == 0 || names[1] == 0)
		return PROF_BAD_NAMESET;

	section = profile->first_file->root;
	for (cpp = names; cpp[1]; cpp++) {
		state = 0;
		retval = profile_find_node(section, *cpp, 0, 1,
					   &state, &section);
		if (retval)
			return retval;
	}

	state = 0;
	retval = profile_find_node(section, *cpp, 0, 1, &state, &node);
	if (retval)
		return retval;

	if (new_name)
		retval = profile_rename_node(node, new_name);
	else
		retval = profile_remove_node(node);
	if (retval)
		return retval;

	profile->first_file->flags |= PROFILE_FILE_DIRTY;
	
	return 0;
}

/*
 * Insert a new relation.  If the new_value argument is NULL, then
 * create a new section instead.
 *
 * Note: if the intermediate sections do not exist, this function will
 * automatically create them.
 *
 * ADL - 2/23/99, rewritten TYT 2/25/99
 */
KRB5_DLLIMP errcode_t KRB5_CALLCONV
profile_add_relation(profile, names, new_value)
	profile_t	profile;
	const char  	**names;
	const char	*new_value; 
{
	errcode_t	retval;
    	struct profile_node *section;
	const char 	**cpp;
	void		*state;

	retval = rw_setup(profile);
	if (retval)
		return retval;
	
	if (names == 0 || names[0] == 0 || names[1] == 0)
		return PROF_BAD_NAMESET;

	section = profile->first_file->root;
	for (cpp = names; cpp[1]; cpp++) {
		state = 0;
		retval = profile_find_node(section, *cpp, 0, 1,
					   &state, &section);
		if (retval == PROF_NO_SECTION)
			retval = profile_add_node(section, *cpp, 0, &section);
		if (retval)
			return retval;
	}

	if (new_value == 0) {
		retval = profile_find_node(section, *cpp, 0, 1, &state, 0);
		if (retval == 0)
			return PROF_EXISTS;
		else if (retval != PROF_NO_SECTION)
			return retval;
	}

	retval = profile_add_node(section, *cpp, new_value, 0);
	if (retval)
		return retval;

	profile->first_file->flags |= PROFILE_FILE_DIRTY;
	
	return 0;
}

