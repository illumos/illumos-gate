/*
 * prof_get.c --- routines that expose the public interfaces for
 * 	querying items from the profile.
 *
 */

#include "prof_int.h"
#include <stdio.h>
#include <string.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <errno.h>
#include <limits.h>

/*
 * These functions --- init_list(), end_list(), and add_to_list() are
 * internal functions used to build up a null-terminated char ** list
 * of strings to be returned by functions like profile_get_values.
 *
 * The profile_string_list structure is used for internal booking
 * purposes to build up the list, which is returned in *ret_list by
 * the end_list() function.
 *
 * The publicly exported interface for freeing char** list is
 * profile_free_list().
 */

struct profile_string_list {
	char	**list;
	int	num;
	int	max;
};

/*
 * Initialize the string list abstraction.
 */
static errcode_t init_list(struct profile_string_list *list)
{
	list->num = 0;
	list->max = 10;
	list->list = malloc(list->max * sizeof(char *));
	if (list->list == 0)
		return ENOMEM;
	list->list[0] = 0;
	return 0;
}

/*
 * Free any memory left over in the string abstraction, returning the
 * built up list in *ret_list if it is non-null.
 */
static void end_list(struct profile_string_list *list, char ***ret_list)
{
	char	**cp;

	if (list == 0)
		return;

	if (ret_list) {
		*ret_list = list->list;
		return;
	} else {
		for (cp = list->list; *cp; cp++)
			free(*cp);
		free(list->list);
	}
	list->num = list->max = 0;
	list->list = 0;
}

/*
 * Add a string to the list.
 */
static errcode_t add_to_list(struct profile_string_list *list, const char *str)
{
	char 	*newstr, **newlist;
	int	newmax;
	
	if (list->num+1 >= list->max) {
		newmax = list->max + 10;
		newlist = realloc(list->list, newmax * sizeof(char *));
		if (newlist == 0)
			return ENOMEM;
		list->max = newmax;
		list->list = newlist;
	}
	newstr = malloc(strlen(str)+1);
	if (newstr == 0)
		return ENOMEM;
	strcpy(newstr, str);

	list->list[list->num++] = newstr;
	list->list[list->num] = 0;
	return 0;
}

/*
 * Return TRUE if the string is already a member of the list.
 */
static int is_list_member(struct profile_string_list *list, const char *str)
{
	char **cpp;

	if (!list->list)
		return 0;

	for (cpp = list->list; *cpp; cpp++) {
		if (!strcmp(*cpp, str))
			return 1;
	}
	return 0;
}	
	
/*
 * This function frees a null-terminated list as returned by
 * profile_get_values.
 */
void KRB5_CALLCONV profile_free_list(char **list)
{
    char	**cp;

    if (list == 0)
	    return;
    
    for (cp = list; *cp; cp++)
	free(*cp);
    free(list);
}

errcode_t KRB5_CALLCONV
profile_get_values(profile_t profile, const char *const *names,
		   char ***ret_values)
{
	errcode_t		retval;
	void			*state;
	char			*value;
	struct profile_string_list values;

	if ((retval = profile_node_iterator_create(profile, names,
						   PROFILE_ITER_RELATIONS_ONLY,
						   &state)))
		return retval;

	if ((retval = init_list(&values)))
		return retval;

	do {
		if ((retval = profile_node_iterator(&state, 0, 0, &value)))
			goto cleanup;
		if (value)
			add_to_list(&values, value);
	} while (state);

	if (values.num == 0) {
		retval = PROF_NO_RELATION;
		goto cleanup;
	}

	end_list(&values, ret_values);
	return 0;
	
cleanup:
	end_list(&values, 0);
	return retval;
}

/*
 * This function only gets the first value from the file; it is a
 * helper function for profile_get_string, profile_get_integer, etc.
 */
errcode_t profile_get_value(profile_t profile, const char **names,
			    const char **ret_value)
{
	errcode_t		retval;
	void			*state;
	char			*value;

	if ((retval = profile_node_iterator_create(profile, names,
						   PROFILE_ITER_RELATIONS_ONLY,
						   &state)))
		return retval;

	if ((retval = profile_node_iterator(&state, 0, 0, &value)))
		goto cleanup;

	if (value)
		*ret_value = value;
	else
		retval = PROF_NO_RELATION;
	
cleanup:
	profile_node_iterator_free(&state);
	return retval;
}

errcode_t KRB5_CALLCONV
profile_get_string(profile_t profile, const char *name, const char *subname,
		   const char *subsubname, const char *def_val,
		   char **ret_string)
{
	const char	*value;
	errcode_t	retval;
	const char	*names[4];

	if (profile) {
		names[0] = name;
		names[1] = subname;
		names[2] = subsubname;
		names[3] = 0;
		retval = profile_get_value(profile, names, &value);
		if (retval == PROF_NO_SECTION || retval == PROF_NO_RELATION)
			value = def_val;
		else if (retval)
			return retval;
	} else
		value = def_val;
    
	if (value) {
		*ret_string = malloc(strlen(value)+1);
		if (*ret_string == 0)
			return ENOMEM;
		strcpy(*ret_string, value);
	} else
		*ret_string = 0;
	return 0;
}

errcode_t KRB5_CALLCONV
profile_get_integer(profile_t profile, const char *name, const char *subname,
		    const char *subsubname, int def_val, int *ret_int)
{
	const char	*value;
	errcode_t	retval;
	const char	*names[4];
	char            *end_value;
	long		ret_long;

	*ret_int = def_val;
	if (profile == 0)
		return 0;

	names[0] = name;
	names[1] = subname;
	names[2] = subsubname;
	names[3] = 0;
	retval = profile_get_value(profile, names, &value);
	if (retval == PROF_NO_SECTION || retval == PROF_NO_RELATION) {
		*ret_int = def_val;
		return 0;
	} else if (retval)
		return retval;

	if (value[0] == 0)
	    /* Empty string is no good.  */
	    return PROF_BAD_INTEGER;
	errno = 0;
	ret_long = strtol (value, &end_value, 10);

	/* Overflow or underflow.  */
	if ((ret_long == LONG_MIN || ret_long == LONG_MAX) && errno != 0)
	    return PROF_BAD_INTEGER;
	/* Value outside "int" range.  */
	if ((long) (int) ret_long != ret_long)
	    return PROF_BAD_INTEGER;
	/* Garbage in string.  */
	if (end_value != value + strlen (value))
	    return PROF_BAD_INTEGER;
	
   
	*ret_int = ret_long;
	return 0;
}

static const char *const conf_yes[] = {
    "y", "yes", "true", "t", "1", "on",
    0,
};

static const char *const conf_no[] = {
    "n", "no", "false", "nil", "0", "off",
    0,
};

static errcode_t
profile_parse_boolean(const char *s, int *ret_boolean)
{
    const char *const *p;
    
    if (ret_boolean == NULL)
    	return PROF_EINVAL;

    for(p=conf_yes; *p; p++) {
		if (!strcasecmp(*p,s)) {
			*ret_boolean = 1;
	    	return 0;
		}
    }

    for(p=conf_no; *p; p++) {
		if (!strcasecmp(*p,s)) {
			*ret_boolean = 0;
			return 0;
		}
    }
	
	return PROF_BAD_BOOLEAN;
}

errcode_t KRB5_CALLCONV
profile_get_boolean(profile_t profile, const char *name, const char *subname,
		    const char *subsubname, int def_val, int *ret_boolean)
{
	const char	*value;
	errcode_t	retval;
	const char	*names[4];

	if (profile == 0) {
		*ret_boolean = def_val;
		return 0;
	}

	names[0] = name;
	names[1] = subname;
	names[2] = subsubname;
	names[3] = 0;
	retval = profile_get_value(profile, names, &value);
	if (retval == PROF_NO_SECTION || retval == PROF_NO_RELATION) {
		*ret_boolean = def_val;
		return 0;
	} else if (retval)
		return retval;
   
	return profile_parse_boolean (value, ret_boolean);
}

/*
 * This function will return the list of the names of subections in the
 * under the specified section name.
 */
errcode_t KRB5_CALLCONV
profile_get_subsection_names(profile_t profile, const char **names,
			     char ***ret_names)
{
	errcode_t		retval;
	void			*state;
	char			*name;
	struct profile_string_list values;

	if ((retval = profile_node_iterator_create(profile, names,
		   PROFILE_ITER_LIST_SECTION | PROFILE_ITER_SECTIONS_ONLY,
		   &state)))
		return retval;

	if ((retval = init_list(&values)))
		return retval;

	do {
		if ((retval = profile_node_iterator(&state, 0, &name, 0)))
			goto cleanup;
		if (name)
			add_to_list(&values, name);
	} while (state);

	end_list(&values, ret_names);
	return 0;
	
cleanup:
	end_list(&values, 0);
	return retval;
}

/*
 * This function will return the list of the names of relations in the
 * under the specified section name.
 */
errcode_t KRB5_CALLCONV
profile_get_relation_names(profile_t profile, const char **names,
			   char ***ret_names)
{
	errcode_t		retval;
	void			*state;
	char			*name;
	struct profile_string_list values;

	if ((retval = profile_node_iterator_create(profile, names,
		   PROFILE_ITER_LIST_SECTION | PROFILE_ITER_RELATIONS_ONLY,
		   &state)))
		return retval;

	if ((retval = init_list(&values)))
		return retval;

	do {
		if ((retval = profile_node_iterator(&state, 0, &name, 0)))
			goto cleanup;
		if (name && !is_list_member(&values, name))
			add_to_list(&values, name);
	} while (state);

	end_list(&values, ret_names);
	return 0;
	
cleanup:
	end_list(&values, 0);
	return retval;
}

errcode_t KRB5_CALLCONV
profile_iterator_create(profile_t profile, const char *const *names, int flags,
			void **ret_iter)
{
	return profile_node_iterator_create(profile, names, flags, ret_iter);
}

void KRB5_CALLCONV
profile_iterator_free(void **iter_p)
{
	profile_node_iterator_free(iter_p);
}

errcode_t KRB5_CALLCONV
profile_iterator(void **iter_p, char **ret_name, char **ret_value)
{
	char *name, *value;
	errcode_t	retval;
	
	retval = profile_node_iterator(iter_p, 0, &name, &value);
	if (retval)
		return retval;

	if (ret_name) {
		if (name) {
			*ret_name = malloc(strlen(name)+1);
			if (!*ret_name)
				return ENOMEM;
			strcpy(*ret_name, name);
		} else
			*ret_name = 0;
	}
	if (ret_value) {
		if (value) {
			*ret_value = malloc(strlen(value)+1);
			if (!*ret_value) {
				if (ret_name) {
					free(*ret_name);
					*ret_name = 0;
				}
				return ENOMEM;
			}
			strcpy(*ret_value, value);
		} else
			*ret_value = 0;
	}
	return 0;
}

void KRB5_CALLCONV
profile_release_string(char *str)
{
	free(str);
}
