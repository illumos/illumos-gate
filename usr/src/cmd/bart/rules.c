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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <dirent.h>
#include <fnmatch.h>
#include <string.h>
#include "bart.h"

static int count_slashes(const char *);
static struct rule *gen_rulestruct(void);
static struct tree_modifier *gen_tree_modifier(void);
static struct dir_component *gen_dir_component(void);
static void init_rule(uint_t, struct rule *);
static void add_modifier(struct rule *, char *);
static struct rule *add_subtree_rule(char *, char *, int, int *);
static struct rule *add_single_rule(char *);
static void dirs_cleanup(struct dir_component *);
static void add_dir(struct dir_component **, char *);
static char *lex(FILE *);
static int match_subtree(const char *, char *);
static struct rule *get_last_entry(boolean_t);

static int	lex_linenum;	/* line number in current input file	*/
static struct rule	*first_rule = NULL, *current_rule = NULL;

/*
 * This function is responsible for validating whether or not a given file
 * should be cataloged, based upon the modifiers for a subtree.
 * For example, a line in the rules file: '/home/nickiso *.c' should only
 * catalog the C files (based upon pattern matching) in the subtree
 * '/home/nickiso'.
 *
 * exclude_fname depends on having the modifiers be pre-sorted to put
 * negative directory modifiers first, so that the logic does
 * not need to save complex state information.  This is valid because
 * we are only cataloging things that meet all modifiers (AND logic.)
 *
 * Returns:
 * NO_EXCLUDE
 * EXCLUDE_SKIP
 * EXCLUDE_PRUNE
 */
int
exclude_fname(const char *fname, char fname_type, struct rule *rule_ptr)
{
	char	*pattern, *ptr, *fname_ptr, saved_char;
	char 	fname_cp[PATH_MAX], pattern_cp[PATH_MAX];
	int	num_pattern_slash,  i, num_fname_slash, slashes_to_adv;
	struct  tree_modifier   *mod_ptr;

	/*
	 * If this is create and there are no modifiers, bail.
	 * This will have to change once create handles multiple rules
	 * during walk.
	 */
	if (rule_ptr->modifiers == NULL)
		if (rule_ptr->attr_list == 0)
			return (EXCLUDE_PRUNE);
		else
			return (NO_EXCLUDE);
	/*
	 * Walk through all the modifiers until its they are exhausted OR
	 * until the file should definitely be excluded.
	 */
	for (mod_ptr = rule_ptr->modifiers; mod_ptr != NULL;
	    mod_ptr = mod_ptr->next) {
		/* leading !'s were processed in add_modifier */
		pattern = mod_ptr->mod_str;
		if (mod_ptr->is_dir == B_FALSE) {
			/*
			 * Pattern is a file pattern.
			 *
			 * In the case when a user is trying to filter on
			 * a file pattern and the entry is a directory,
			 * this is not a match.
			 *
			 * If a match is required, skip this file.  If
			 * a match is forbidden, keep looking at modifiers.
			 */
			if (fname_type == 'D') {
				if (mod_ptr->include == B_TRUE)
					return (EXCLUDE_SKIP);
				else
					continue;
			}

			/*
			 * Match patterns against filenames.
			 * Need to be able to handle multi-level patterns,
			 * eg. "SCCS/<star-wildcard>.c", which means
			 * 'only match C files under SCCS directories.
			 *
			 * Determine the number of levels in the filename and
			 * in the pattern.
			 */
			num_pattern_slash = count_slashes(pattern);
			num_fname_slash = count_slashes(fname);

			/* Check for trivial exclude condition */
			if (num_pattern_slash > num_fname_slash) {
				if (mod_ptr->include == B_TRUE)
					return (EXCLUDE_SKIP);
			}

			/*
			 * Do an apples to apples comparison, based upon the
			 * number of levels:
			 *
			 * Assume fname is /A/B/C/D/E and the pattern is D/E.
			 * In that case, 'ptr' will point to "D/E" and
			 * 'slashes_to_adv' will be '4'.
			 */
			(void) strlcpy(fname_cp, fname, sizeof (fname_cp));
			ptr = fname_cp;
			slashes_to_adv = num_fname_slash - num_pattern_slash;
			for (i = 0; i < slashes_to_adv; i++)  {
				ptr = strchr(ptr, '/');
				ptr++;
			}
			if ((pattern[0] == '.') && (pattern[1] == '.') &&
			    (pattern[2] == '/')) {
				pattern = strchr(pattern, '/');
				ptr = strchr(ptr, '/');
			}


			/* OK, now do the fnmatch() compare to the file */
			if (fnmatch(pattern, ptr, FNM_PATHNAME) == 0) {
				/* matches, is it an exclude? */
				if (mod_ptr->include == B_FALSE)
					return (EXCLUDE_SKIP);
			} else if (mod_ptr->include == B_TRUE) {
				/* failed a required filename match */
				return (EXCLUDE_SKIP);
			}
		} else {
			/*
			 * The rule requires directory matching.
			 *
			 * Unlike filename matching, directory matching can
			 * prune.
			 *
			 * First, make copies, since both the pattern and
			 * filename need to be modified.
			 *
			 * When copying 'fname', ignore the relocatable root
			 * since pattern matching is done for the string AFTER
			 * the relocatable root.  For example, if the
			 * relocatable root is "/dir1/dir2/dir3" and the
			 * pattern is "dir3/", we do NOT want to include every
			 * directory in the relocatable root.  Instead, we
			 * only want to include subtrees that look like:
			 * "/dir1/dir2/dir3/....dir3/....."
			 *
			 * NOTE: the 'fname_cp' does NOT have a trailing '/':
			 * necessary for fnmatch().
			 */
			(void) strlcpy(fname_cp,
			    (fname+strlen(rule_ptr->subtree)),
			    sizeof (fname_cp));
			(void) strlcpy(pattern_cp, pattern,
			    sizeof (pattern_cp));

			/*
			 * For non-directory files, remove the trailing
			 * name, e.g., for a file /A/B/C/D where 'D' is
			 * the actual filename, remove the 'D' since it
			 * should *not* be considered in the directory match.
			 */
			if (fname_type != 'D') {
				ptr = strrchr(fname_cp, '/');
				if (ptr != NULL)
					*ptr = '\0';

				/*
				 * Trivial case: a simple filename does
				 * not match a directory by definition,
				 * so skip if match is required,
				 * keep analyzing otherwise.
				 */

				if (strlen(fname_cp) == 0)
					if (mod_ptr->include == B_TRUE)
						return (EXCLUDE_SKIP);
			}

			/* Count the # of slashes in the pattern and fname */
			num_pattern_slash = count_slashes(pattern_cp);
			num_fname_slash = count_slashes(fname_cp);

			/*
			 * fname_cp is too short if this is not a dir
			 */
			if ((num_pattern_slash > num_fname_slash) &&
			    (fname_type != 'D')) {
				if (mod_ptr->include == B_TRUE)
					return (EXCLUDE_SKIP);
			}


			/*
			 * Take the leading '/' from fname_cp before
			 * decrementing the number of slashes.
			 */
			if (fname_cp[0] == '/') {
				(void) strlcpy(fname_cp,
				    strchr(fname_cp, '/') + 1,
				    sizeof (fname_cp));
				num_fname_slash--;
			}

			/*
			 * Begin the loop, walk through the file name until
			 * it can be determined that there is no match.
			 * For example: if pattern is C/D/, and fname_cp is
			 * A/B/C/D/E then compare A/B/ with C/D/, if it doesn't
			 * match, then walk further so that the next iteration
			 * checks B/C/ against C/D/, continue until we have
			 * exhausted options.
			 * In the above case, the 3rd iteration will match
			 * C/D/ with C/D/.
			 */
			while (num_pattern_slash <= num_fname_slash) {
				/* get a pointer to our filename */
				fname_ptr = fname_cp;

				/*
				 * Walk the filename through the slashes
				 * so that we have a component of the same
				 * number of slashes as the pattern.
				 */

				for (i = 0; i < num_pattern_slash; i++) {
					ptr = strchr(fname_ptr, '/');
					fname_ptr = ptr + 1;
				}

				/*
				 * Save the character after our target slash
				 * before breaking the string for use with
				 * fnmatch
				 */
				saved_char = *(++ptr);

				*ptr = '\0';

				/*
				 * Call compare function for the current
				 * component with the pattern we are looking
				 * for.
				 */
				if (fnmatch(pattern_cp, fname_cp,
				    FNM_PATHNAME) == 0) {
					if (mod_ptr->include == B_TRUE) {
						break;
					} else if (fname_type == 'D')
						return (EXCLUDE_PRUNE);
					else
						return (EXCLUDE_SKIP);
				} else if (mod_ptr->include == B_TRUE) {
					if (fname_type == 'D')
						return (EXCLUDE_PRUNE);
					else
						return (EXCLUDE_SKIP);
				}
				/*
				 * We didn't match, so restore the saved
				 * character to the original position.
				 */
				*ptr = saved_char;

				/*
				 * Break down fname_cp, if it was A/B/C
				 * then after this operation it will be B/C
				 * in preparation for the next iteration.
				 */
				(void) strlcpy(fname_cp,
				    strchr(fname_cp, '/') + 1,
				    sizeof (fname_cp));

				/*
				 * Decrement the number of slashes to
				 * compensate for the one removed above.
				 */
				num_fname_slash--;
			} /* end while loop looking down the path */

			/*
			 * If we didn't get a match above then we may be on the
			 * last component of our filename.
			 * This is to handle the following cases
			 *    - filename is A/B/C/D/E and pattern may be D/E/
			 *    - filename is D/E and pattern may be D/E/
			 */
			if (num_pattern_slash == (num_fname_slash + 1)) {

				/* strip the trailing slash from the pattern */
				ptr = strrchr(pattern_cp, '/');
				*ptr = '\0';

				/* fnmatch returns 0 for a match */
				if (fnmatch(pattern_cp, fname_cp,
				    FNM_PATHNAME) == 0) {
					if (mod_ptr->include == B_FALSE) {
						if (fname_type == 'D')
							return (EXCLUDE_PRUNE);
						else
							return (EXCLUDE_SKIP);
					}
				} else if (mod_ptr->include == B_TRUE)
					return (EXCLUDE_SKIP);

			}

		}
	}
	return (NO_EXCLUDE);
}

static int
count_slashes(const char *in_path)
{
	int num_fname_slash = 0;
	const char *p;
	for (p = in_path; *p != '\0'; p++)
		if (*p == '/')
			num_fname_slash++;
	return (num_fname_slash);
}

static struct rule *
gen_rulestruct(void)
{
	struct rule	*new_rule;

	new_rule = (struct rule *)safe_calloc(sizeof (struct rule));
	return (new_rule);
}

static struct tree_modifier *
gen_tree_modifier(void)
{
	struct tree_modifier	*new_modifier;

	new_modifier = (struct tree_modifier *)safe_calloc
	    (sizeof (struct tree_modifier));
	return (new_modifier);
}

static struct dir_component *
gen_dir_component(void)
{
	struct dir_component	*new_dir;

	new_dir = (struct dir_component *)safe_calloc
	    (sizeof (struct dir_component));
	return (new_dir);
}

/*
 * Set up a default rule when there is no rules file.
 */
static struct rule *
setup_default_rule(char *reloc_root, uint_t flags)
{
	struct	rule	*new_rule;

	new_rule = add_single_rule(reloc_root[0] == '\0' ? "/" : reloc_root);
	init_rule(flags, new_rule);
	add_modifier(new_rule, "*");

	return (new_rule);
}

/*
 * Utility function, used to initialize the flag in a new rule structure.
 */
static void
init_rule(uint_t flags, struct rule *new_rule)
{

	if (new_rule == NULL)
		return;
	new_rule->attr_list = flags;
}

/*
 * Function to read the rulesfile.  Used by both 'bart create' and
 * 'bart compare'.
 */
int
read_rules(FILE *file, char *reloc_root, uint_t in_flags, int create)
{
	char		*s;
	struct rule	*block_begin = NULL, *new_rule, *rp;
	struct attr_keyword *akp;
	int		check_flag, ignore_flag, syntax_err, ret_code;
	int		global_block;

	ret_code = EXIT;

	lex_linenum = 0;
	check_flag = 0;
	ignore_flag = 0;
	syntax_err = 0;
	global_block = 1;

	if (file == NULL) {
		(void) setup_default_rule(reloc_root, in_flags);
		return (ret_code);
	} else if (!create) {
		block_begin = setup_default_rule("/", in_flags);
	}

	while (!feof(file)) {
		/* Read a line from the file */
		s = lex(file);

		/* skip blank lines and comments */
		if (s == NULL || *s == 0 || *s == '#')
			continue;

		/*
		 * Beginning of a subtree and possibly a new block.
		 *
		 * If this is a new block, keep track of the beginning of
		 * the block. if there are directives later on, we need to
		 * apply that directive to all members of the block.
		 *
		 * If the first stmt in the file was an 'IGNORE all' or
		 * 'IGNORE contents', we need to keep track of it and
		 * automatically switch off contents checking for new
		 * subtrees.
		 */
		if (s[0] == '/') {
			/* subtree definition hence not a global block */
			global_block = 0;

			new_rule = add_subtree_rule(s, reloc_root, create,
			    &ret_code);

			s = lex(0);
			while ((s != NULL) && (*s != 0) && (*s != '#')) {
				add_modifier(new_rule, s);
				s = lex(0);
			}

			/* Found a new block, keep track of the beginning */
			if (block_begin == NULL ||
			    (ignore_flag != 0) || (check_flag != 0)) {
				block_begin = new_rule;
				check_flag = 0;
				ignore_flag = 0;
			}

			/* Apply global settings to this block, if any */
			init_rule(in_flags, new_rule);
		} else if (IGNORE_KEYWORD(s) || CHECK_KEYWORD(s)) {
			int check_kw;

			if (IGNORE_KEYWORD(s)) {
				ignore_flag++;
				check_kw = 0;
			} else {
				check_flag++;
				check_kw = 1;
			}

			/* Parse next token */
			s = lex(0);
			while ((s != NULL) && (*s != 0) && (*s != '#')) {
				akp = attr_keylookup(s);
				if (akp == NULL) {
					(void) fprintf(stderr, SYNTAX_ERR, s);
					syntax_err++;
					exit(2);
				}

				/*
				 * For all the flags, check if this is a global
				 * IGNORE/CHECK. If so, set the global flags.
				 *
				 * NOTE: The only time you can have a
				 * global ignore is when its the
				 * stmt before any blocks have been
				 * spec'd.
				 */
				if (global_block) {
					if (check_kw)
						in_flags |= akp->ak_flags;
					else
						in_flags &= ~(akp->ak_flags);
				} else {
					for (rp = block_begin; rp != NULL;
					    rp = rp->next) {
						if (check_kw)
							rp->attr_list |=
							    akp->ak_flags;
						else
							rp->attr_list &=
							    ~(akp->ak_flags);
					}
				}

				/* Parse next token */
				s = lex(0);
			}
		} else {
			(void) fprintf(stderr, SYNTAX_ERR, s);
			s = lex(0);
			while (s != NULL && *s != 0) {
				(void) fprintf(stderr, " %s", s);
				s = lex(0);
			}
			(void) fprintf(stderr, "\n");
			syntax_err++;
		}
	}

	(void) fclose(file);

	if (syntax_err) {
		(void) fprintf(stderr, SYNTAX_ABORT);
		exit(2);
	}

	return (ret_code);
}
/*
 * Add a modifier to the mod_ptr list in each rule, putting negative
 * directory entries
 * first to guarantee walks will be appropriately pruned.
 */
static void
add_modifier(struct rule *rule, char *modifier_str)
{
	int	include, is_dir;
	char	*pattern;
	struct tree_modifier	*new_mod_ptr, *curr_mod_ptr;
	struct rule		*this_rule;

	include = B_TRUE;
	pattern = modifier_str;

	/* see if the pattern is an include or an exclude */
	if (pattern[0] == '!') {
		include = B_FALSE;
		pattern++;
	}

	is_dir = (pattern[0] != '\0' && pattern[strlen(pattern) - 1] == '/');

	for (this_rule = rule; this_rule != NULL; this_rule = this_rule->next) {
		new_mod_ptr = gen_tree_modifier();
		new_mod_ptr->include = include;
		new_mod_ptr->is_dir = is_dir;
		new_mod_ptr->mod_str = safe_strdup(pattern);

		if (is_dir && !include) {
			new_mod_ptr->next = this_rule->modifiers;
			this_rule->modifiers = new_mod_ptr;
		} else if (this_rule->modifiers == NULL)
			this_rule->modifiers = new_mod_ptr;
		else {
			curr_mod_ptr = this_rule->modifiers;
			while (curr_mod_ptr->next != NULL)
				curr_mod_ptr = curr_mod_ptr->next;

			curr_mod_ptr->next = new_mod_ptr;
		}
	}
}

/*
 * This funtion is invoked when reading rulesfiles.  A subtree may have
 * wildcards in it, e.g., '/home/n*', which is expected to match all home
 * dirs which start with an 'n'.
 *
 * This function needs to break down the subtree into its components.  For
 * each component, see how many directories match.  Take the subtree list just
 * generated and run it through again, this time looking at the next component.
 * At each iteration, keep a linked list of subtrees that currently match.
 * Once the final list is created, invoke add_single_rule() to create the
 * rule struct with the correct information.
 *
 * This function returns a ptr to the first element in the block of subtrees
 * which matched the subtree def'n in the rulesfile.
 */
static struct rule *
add_subtree_rule(char *rule, char *reloc_root, int create, int *err_code)
{
	char			full_path[PATH_MAX], pattern[PATH_MAX];
	char			new_dirname[PATH_MAX];
	char			*beg_pattern, *end_pattern, *curr_dirname;
	struct	dir_component	*current_level = NULL, *next_level = NULL;
	struct	dir_component	*tmp_ptr;
	DIR			*dir_ptr;
	struct dirent		*dir_entry;
	struct rule		*begin_rule = NULL;
	int			ret;
	struct stat64		statb;

	(void) snprintf(full_path, sizeof (full_path),
	    (rule[0] == '/') ? "%s%s" : "%s/%s", reloc_root, rule);

	/*
	 * In the case of 'bart compare', don't validate
	 * the subtrees, since the machine running the
	 * comparison may not be the machine which generated
	 * the manifest.
	 */
	if (create == 0)
		return (add_single_rule(full_path));


	/* Insert 'current_level' into the linked list */
	add_dir(&current_level, NULL);

	/* Special case: occurs when -R is "/" and the subtree is "/" */
	if (strcmp(full_path, "/") == 0)
		(void) strcpy(current_level->dirname, "/");

	beg_pattern = full_path;

	while (beg_pattern != NULL) {
		/*
		 * Extract the pathname component starting at 'beg_pattern'.
		 * Take those chars and put them into 'pattern'.
		 */
		while (*beg_pattern == '/')
			beg_pattern++;
		if (*beg_pattern == '\0')	/* end of pathname */
			break;
		end_pattern = strchr(beg_pattern, '/');
		if (end_pattern != NULL)
			(void) strlcpy(pattern, beg_pattern,
			    end_pattern - beg_pattern + 1);
		else
			(void) strlcpy(pattern, beg_pattern, sizeof (pattern));
		beg_pattern = end_pattern;

		/*
		 * At this point, search for 'pattern' as a *subdirectory* of
		 * the dirs in the linked list.
		 */
		while (current_level != NULL) {
			/* curr_dirname used to make the code more readable */
			curr_dirname = current_level->dirname;

			/* Initialization case */
			if (strlen(curr_dirname) == 0)
				(void) strcpy(curr_dirname, "/");

			/* Open up the dir for this element in the list */
			dir_ptr = opendir(curr_dirname);
			dir_entry = NULL;

			if (dir_ptr == NULL) {
				perror(curr_dirname);
				*err_code = WARNING_EXIT;
			} else
				dir_entry = readdir(dir_ptr);

			/*
			 * Now iterate through the subdirs of 'curr_dirname'
			 * In the case of a match against 'pattern',
			 * add the path to the next linked list, which
			 * will be matched on the next iteration.
			 */
			while (dir_entry != NULL) {
				/* Skip the dirs "." and ".." */
				if ((strcmp(dir_entry->d_name, ".") == 0) ||
				    (strcmp(dir_entry->d_name, "..") == 0)) {
					dir_entry = readdir(dir_ptr);
					continue;
				}
				if (fnmatch(pattern, dir_entry->d_name,
				    FNM_PATHNAME) == 0) {
					/*
					 * Build 'new_dirname' which will be
					 * examined on the next iteration.
					 */
					if (curr_dirname[strlen(curr_dirname)-1]
					    != '/')
						(void) snprintf(new_dirname,
						    sizeof (new_dirname),
						    "%s/%s", curr_dirname,
						    dir_entry->d_name);
					else
						(void) snprintf(new_dirname,
						    sizeof (new_dirname),
						    "%s%s", curr_dirname,
						    dir_entry->d_name);

					/* Add to the next lined list */
					add_dir(&next_level, new_dirname);
				}
				dir_entry = readdir(dir_ptr);
			}

			/* Close directory */
			if (dir_ptr != NULL)
				(void) closedir(dir_ptr);

			/* Free this entry and move on.... */
			tmp_ptr = current_level;
			current_level = current_level->next;
			free(tmp_ptr);
		}

		/*
		 * OK, done with this level.  Move to the next level and
		 * advance the ptrs which indicate the component name.
		 */
		current_level = next_level;
		next_level = NULL;
	}

	tmp_ptr = current_level;

	/* Error case: the subtree doesn't exist! */
	if (current_level == NULL) {
		(void) fprintf(stderr, INVALID_SUBTREE, full_path);
		*err_code = WARNING_EXIT;
	}

	/*
	 * Iterate through all the dirnames which match the pattern and
	 * add them to to global list of subtrees which must be examined.
	 */
	while (current_level != NULL) {
		/*
		 * Sanity check for 'bart create', make sure the subtree
		 * points to a valid object.
		 */
		ret = lstat64(current_level->dirname, &statb);
		if (ret < 0) {
			(void) fprintf(stderr, INVALID_SUBTREE,
			    current_level->dirname);
			current_level = current_level->next;
			*err_code = WARNING_EXIT;
			continue;
		}

		if (begin_rule == NULL) {
			begin_rule =
			    add_single_rule(current_level->dirname);
		} else
			(void) add_single_rule(current_level->dirname);

		current_level = current_level->next;
	}

	/*
	 * Free up the memory and return a ptr to the first entry in the
	 * subtree block.  This is necessary for the parser, which may need
	 * to add modifier strings to all the elements in this block.
	 */
	dirs_cleanup(tmp_ptr);

	return (begin_rule);
}


/*
 * Add a single entry to the linked list of rules to be read.  Does not do
 * the wildcard expansion of 'add_subtree_rule', so is much simpler.
 */
static struct rule *
add_single_rule(char *path)
{

	/*
	 * If the rules list does NOT exist, then create it.
	 * If the rules list does exist, then traverse the next element.
	 */
	if (first_rule == NULL) {
		first_rule = gen_rulestruct();
		current_rule = first_rule;
	} else {
		current_rule->next = gen_rulestruct();
		current_rule->next->prev = current_rule;
		current_rule = current_rule->next;
	}

	/* Setup the rule struct, handle relocatable roots, i.e. '-R' option */
	(void) strlcpy(current_rule->subtree, path,
	    sizeof (current_rule->subtree));

	return (current_rule);
}

/*
 * Code stolen from filesync utility, used by read_rules() to read in the
 * rulesfile.
 */
static char *
lex(FILE *file)
{
	char c, delim;
	char *p;
	char *s;
	static char *savep;
	static char namebuf[ BUF_SIZE ];
	static char inbuf[ BUF_SIZE ];

	if (file) {			/* read a new line		*/
		p = inbuf + sizeof (inbuf);

		s = inbuf;
		/* read the next input line, with all continuations	*/
		while (savep = fgets(s, p - s, file)) {
			lex_linenum++;

			/* go find the last character of the input line	*/
			while (*s && s[1])
				s++;
			if (*s == '\n')
				s--;

			/* see whether or not we need a continuation	*/
			if (s < inbuf || *s != '\\')
				break;

			continue;
		}

		if (savep == NULL)
			return (0);

		s = inbuf;
	} else {			/* continue with old line	*/
		if (savep == NULL)
			return (0);
		s = savep;
	}
	savep = NULL;

	/* skip over leading white space	*/
	while (isspace(*s))
		s++;
	if (*s == 0)
		return (0);

	/* see if this is a quoted string	*/
	c = *s;
	if (c == '\'' || c == '"') {
		delim = c;
		s++;
	} else
		delim = 0;

	/* copy the token into the buffer	*/
	for (p = namebuf; (c = *s) != 0; s++) {
		/* literal escape		*/
		if (c == '\\') {
			s++;
			*p++ = *s;
			continue;
		}

		/* closing delimiter		*/
		if (c == delim) {
			s++;
			break;
		}

		/* delimiting white space	*/
		if (delim == 0 && isspace(c))
			break;

		/* ordinary characters		*/
		*p++ = *s;
	}


	/* remember where we left off		*/
	savep = *s ? s : 0;

	/* null terminate and return the buffer	*/
	*p = 0;
	return (namebuf);
}

/*
 * Iterate through the dir strcutures and free memory.
 */
static void
dirs_cleanup(struct dir_component *dir)
{
	struct	dir_component	*next;

	while (dir != NULL) {
		next = dir->next;
		free(dir);
		dir = next;
	}
}

/*
 * Create and initialize a new dir structure.  Used by add_subtree_rule() when
 * doing expansion of directory names caused by wildcards.
 */
static void
add_dir(struct dir_component **dir, char *dirname)
{
	struct	dir_component	*new, *next_dir;

	new = gen_dir_component();
	if (dirname != NULL)
		(void) strlcpy(new->dirname, dirname, sizeof (new->dirname));

	if (*dir == NULL)
		*dir = new;
	else {
		next_dir = *dir;
		while (next_dir->next != NULL)
			next_dir = next_dir->next;

		next_dir->next = new;
	}
}

/*
 * Traverse the linked list of rules in a REVERSE order.
 */
static struct rule *
get_last_entry(boolean_t reset)
{
	static struct rule	*curr_root = NULL;

	if (reset) {

		curr_root = first_rule;

		/* RESET: set cur_root to the end of the list */
		while (curr_root != NULL)
			if (curr_root->next == NULL)
				break;
			else
				curr_root = curr_root->next;
	} else
		curr_root = (curr_root->prev);

	return (curr_root);
}

/*
 * Traverse the first entry, used by 'bart create' to iterate through
 * subtrees or individual filenames.
 */
struct rule *
get_first_subtree()
{
	return (first_rule);
}

/*
 * Traverse the next entry, used by 'bart create' to iterate through
 * subtrees or individual filenames.
 */
struct rule *
get_next_subtree(struct rule *entry)
{
	return (entry->next);
}

char *
safe_strdup(char *s)
{
	char *ret;
	size_t len;

	len = strlen(s) + 1;
	ret = safe_calloc(len);
	(void) strlcpy(ret, s, len);
	return (ret);
}

/*
 * Function to match a filename against the subtrees in the link list
 * of 'rule' strcutures.  Upon finding a matching rule, see if it should
 * be excluded.  Keep going until a match is found OR all rules have been
 * exhausted.
 * NOTES: Rules are parsed in reverse;
 * satisfies the spec that "Last rule wins".  Also, the default rule should
 * always match, so this function should NEVER return NULL.
 */
struct rule *
check_rules(const char *fname, char type)
{
	struct rule		*root;

	root = get_last_entry(B_TRUE);
	while (root != NULL) {
		if (match_subtree(fname, root->subtree)) {
			if (exclude_fname(fname, type, root) == NO_EXCLUDE)
				break;
		}
		root = get_last_entry(B_FALSE);
	}

	return (root);
}

/*
 * Function to determine if an entry in a rules file (see bart_rules(5)) applies
 * to a filename. We truncate "fname" such that it has the same number of
 * components as "rule" and let fnmatch(3C) do the rest. A "component" is one
 * part of an fname as delimited by slashes ('/'). So "/A/B/C/D" has four
 * components: "A", "B", "C" and "D".
 *
 * For example:
 *
 * 1. the rule "/home/nickiso" applies to fname "/home/nickiso/src/foo.c" so
 * should match.
 *
 * 2. the rule "/home/nickiso/temp/src" does not apply to fname
 * "/home/nickiso/foo.c" so should not match.
 */
static int
match_subtree(const char *fname, char *rule)
{
	int	match, num_rule_slash;
	char	*ptr, fname_cp[PATH_MAX];

	/* If rule has more components than fname, it cannot match. */
	if ((num_rule_slash = count_slashes(rule)) > count_slashes(fname))
		return (0);

	/* Create a copy of fname that we can truncate. */
	(void) strlcpy(fname_cp, fname, sizeof (fname_cp));

	/*
	 * Truncate fname_cp such that it has the same number of components
	 * as rule. If rule ends with '/', so should fname_cp. ie:
	 *
	 * rule		fname			fname_cp	matches
	 * ----		-----			--------	-------
	 * /home/dir*	/home/dir0/dir1/fileA	/home/dir0	yes
	 * /home/dir/	/home/dir0/dir1/fileA	/home/dir0/	no
	 */
	for (ptr = fname_cp; num_rule_slash > 0; num_rule_slash--, ptr++)
		ptr = strchr(ptr, '/');
	if (*(rule + strlen(rule) - 1) != '/') {
		while (*ptr != '\0') {
			if (*ptr == '/')
				break;
			ptr++;
		}
	}
	*ptr = '\0';

	/* OK, now see if they match. */
	match = fnmatch(rule, fname_cp, FNM_PATHNAME);

	/* No match, return failure */
	if (match != 0)
		return (0);
	else
		return (1);
}

void
process_glob_ignores(char *ignore_list, uint_t *flags)
{
	char	*cp;
	struct attr_keyword *akp;

	if (ignore_list == NULL)
		usage();

	cp = strtok(ignore_list, ",");
	while (cp != NULL) {
		akp = attr_keylookup(cp);
		if (akp == NULL)
			(void) fprintf(stderr, "ERROR: Invalid keyword %s\n",
			    cp);
		else
			*flags &= ~akp->ak_flags;
		cp = strtok(NULL, ",");
	}
}
