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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	implicit.c
 *
 *	Handle suffix and percent rules
 */

/*
 * Included files
 */
#include <mk/defs.h>
#include <mksh/macro.h>		/* expand_value() */
#include <mksh/misc.h>		/* retmem() */
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
static	wchar_t		WIDE_NULL[1] = {(wchar_t) nul_char};

/*
 * File table of contents
 */
extern	Doname		find_suffix_rule(Name target, Name target_body, Name target_suffix, Property *command, Boolean rechecking);
extern	Doname		find_ar_suffix_rule(register Name target, Name true_target, Property *command, Boolean rechecking);
extern	Doname		find_double_suffix_rule(register Name target, Property *command, Boolean rechecking);
extern	void		build_suffix_list(register Name target_suffix);
extern	Doname		find_percent_rule(register Name target, Property *command, Boolean rechecking);
static	void 		create_target_group_and_dependencies_list(Name target, Percent pat_rule, String percent);
static	Boolean		match_found_with_pattern(Name target, Percent pat_rule, String percent, wchar_t *percent_buf);
static	void		construct_string_from_pattern(Percent pat_rule, String percent, String result);
static	Boolean		dependency_exists(Name target, Property line);
extern	Property	maybe_append_prop(Name, Property_id);
extern	void		add_target_to_chain(Name target, Chain * query);

/*
 *	find_suffix_rule(target, target_body, target_suffix, command, rechecking)
 * 
 *	Does the lookup for single and double suffix rules.
 *	It calls build_suffix_list() to build the list of possible suffixes
 *	for the given target.
 *	It then scans the list to find the first possible source file that
 *	exists. This is done by concatenating the body of the target name
 *	(target name less target suffix) and the source suffix and checking
 *	if the resulting file exists.
 *
 *	Return value:
 *				Indicates if search failed or not
 *
 *	Parameters:
 *		target		The target we need a rule for
 *		target_body	The target name without the suffix
 *		target_suffix	The suffix of the target
 *		command		Pointer to slot to deposit cmd in if found
 *		rechecking	true if we are rechecking target which depends
 *				on conditional macro and keep_state is set
 *
 *	Global variables used:
 *		debug_level	Indicates how much tracing to do
 *		recursion_level	Used for tracing
 */

static Boolean actual_doname = false;

/* /tolik/
 * fix bug 1247448: Suffix Rules failed when combine with Pattern Matching Rules.
 * When make attemps to apply % rule it didn't look for a single suffix rule because
 * if "doname" is called from "find_percent_rule" argument "implicit" is set to true
 * and find_suffix_rule was not called. I've commented the checking of "implicit"
 * in "doname" and make got infinite recursion for SVR4 tilde rules.
 * Usage of "we_are_in_tilde" is intended to avoid this recursion.
 */

static Boolean we_are_in_tilde = false; 

Doname
find_suffix_rule(Name target, Name target_body, Name target_suffix, Property *command, Boolean rechecking)
{
	static wchar_t		static_string_buf_3M [ 3 * MAXPATHLEN ];
	Name			true_target = target;
	wchar_t			*sourcename = (wchar_t*)static_string_buf_3M;
	register wchar_t	*put_suffix;
	register Property	source_suffix;
	register Name		source;
	Doname			result;
	register Property	line;
	extern Boolean 		tilde_rule;
	Boolean 		name_found = true;
	Boolean 		posix_tilde_attempt = true;
	int			src_len = MAXPATHLEN + strlen(target_body->string_mb);

	/*
	 * To avoid infinite recursion
	 */
	if(we_are_in_tilde) {
		we_are_in_tilde = false;
		return(build_dont_know);
	}

	/*
	 * If the target is a constructed one for a "::" target,
	 * we need to consider that.
	 */
	if (target->has_target_prop) {
		true_target = get_prop(target->prop,
				       target_prop)->body.target.target;
	}
	if (debug_level > 1) {
		(void) printf("%*sfind_suffix_rule(%s,%s,%s)\n",
			      recursion_level,
			      "",
			      true_target->string_mb,
			      target_body->string_mb,
			      target_suffix->string_mb);
	}
	if (command != NULL) {
		if ((true_target->suffix_scan_done == true) && (*command == NULL)) {
			return build_ok;
		}
	}
	true_target->suffix_scan_done = true;
	/*
	 * Enter all names from the directory where the target lives as
	 * files that makes sense.
	 * This will make finding the synthesized source possible.
	 */
	read_directory_of_file(target_body);
	/* Cache the suffixes for this target suffix if not done. */
	if (!target_suffix->has_read_suffixes) {
		build_suffix_list(target_suffix);
	}
	/* Preload the sourcename vector with the head of the target name. */
	if (src_len >= sizeof(static_string_buf_3M)) {
		sourcename = ALLOC_WC(src_len);
	}
	(void) mbstowcs(sourcename,
		      target_body->string_mb,
		      (int) target_body->hash.length);
	put_suffix = sourcename + target_body->hash.length;
	/* Scan the suffix list for the target if one exists. */
	if (target_suffix->has_suffixes) {
posix_attempts:
		for (source_suffix = get_prop(target_suffix->prop,
					      suffix_prop);
		     source_suffix != NULL;
		     source_suffix = get_prop(source_suffix->next,
					      suffix_prop)) {
			/* Build the synthesized source name. */
			(void) mbstowcs(put_suffix,
				      source_suffix->body.
				      suffix.suffix->string_mb,
				      (int) source_suffix->body.
				      suffix.suffix->hash.length);
			put_suffix[source_suffix->body.
				   suffix.suffix->hash.length] =
			  (int) nul_char;
			if (debug_level > 1) {
				WCSTOMBS(mbs_buffer, sourcename);
				(void) printf(gettext("%*sTrying %s\n"),
					      recursion_level,
					      "",
					      mbs_buffer);
			}
			source = getname_fn(sourcename, FIND_LENGTH, false, &name_found);
			/*
			 * If the source file is not registered as
			 * a file, this source suffix did not match.
			 */
			if(vpath_defined && !posix && !svr4) {
				(void) exists(source);	
			}
			if (!source->stat.is_file) {
			   if(!(posix|svr4))
			   {
				if(!name_found) {
					free_name(source);
				}
				continue;
			   }

			   /* following code will ensure that the corresponding
			   ** tilde rules are executed when corresponding s. file
			   ** exists in the current directory. Though the current
			   ** target ends with a ~ character, there wont be any
			   ** any file in the current directory with that suffix
			   ** as it's fictitious. Even if it exists, it'll
			   ** execute all the rules for the ~ target.
			   */

			   if(source->string_mb[source->hash.length - 1] == '~' &&
			      ( svr4 || posix_tilde_attempt ) )
			   {
				char *p, *np; 
				char *tmpbuf;

				tmpbuf = getmem(source->hash.length + 8); 
				/* + 8 to add "s." or "SCCS/s." */
			        memset(tmpbuf,0,source->hash.length + 8);
			        source->string_mb[source->hash.length - 1] = '\0';
			        if(p = (char *) memchr((char *)source->string_mb,'/',source->hash.length)) 
				{
			          while(1) {  	
				    if(np = (char *) memchr((char *)p+1,'/',source->hash.length - (p - source->string_mb))) {
			              p = np;
			            } else {break;}
			          }
				  /* copy everything including '/' */
				  strncpy(tmpbuf, source->string_mb, p - source->string_mb + 1);
				  strcat(tmpbuf, "s.");
				  strcat(tmpbuf, p+1);
				  retmem((wchar_t *) source->string_mb); 
				  source->string_mb = tmpbuf;
				
			        } else {
				  strcpy(tmpbuf, "s.");
				  strcat(tmpbuf, source->string_mb);
				  retmem((wchar_t *) source->string_mb); 
				  source->string_mb = tmpbuf;
				
			        }
				source->hash.length = strlen(source->string_mb);
				if(exists(source) == file_doesnt_exist)
				  continue;
				tilde_rule = true;
				we_are_in_tilde = true;
			   } else {
				if(!name_found) {
					free_name(source);
				}
				continue;
			   }
			} else {
			   if(posix && posix_tilde_attempt) {
				if(exists(source) == file_doesnt_exist) {
					if(!name_found) {
						free_name(source);
					}
					continue;
				}
			   } 
			}
			
			if (command != NULL) {
				if(!name_found) {
					store_name(source);
				}
				/*
				 * The source file is a file.
				 * Make sure it is up to date.
				 */
				if (dependency_exists(source,
						      get_prop(target->prop,
							       line_prop))) {
					result = (Doname) source->state;
				} else {
#if 0  /* with_squiggle sends false, which is buggy. : djay */
					result = doname(source,
							(Boolean) source_suffix->body.
							suffix.suffix->with_squiggle,
							true);
#else
					result = doname(source,
							true,
							true);
#endif
				}	
			} else {
				result = target_can_be_built(source);
				
				if (result == build_ok) {
					return result;
				} else {
					if(!name_found) {
						free_name(source);
					}
					continue;
				}
			}
			
			switch (result) {
			case build_dont_know:
				/*
				 * If we still can't build the source,
				 * this rule is not a match,
				 * try the next one.
				 */
				if (source->stat.time == file_doesnt_exist) {
					if(!name_found) {
						free_name(source);
					}
					continue;
				}
			case build_running:
				if(!name_found) {
					store_name(source);
				}
				true_target->suffix_scan_done = false;
				line = maybe_append_prop(target, line_prop);
				enter_dependency(line, source, false);
				line->body.line.target = true_target;
				return build_running;
			case build_ok:
				if(!name_found) {
					store_name(source);
				}
				break;
			case build_failed:
				if(!name_found) {
					store_name(source);
				}
				if (sourcename != static_string_buf_3M) {
					retmem(sourcename);
				}
				return build_failed;
			}
			
			if (debug_level > 1) {
				WCSTOMBS(mbs_buffer, sourcename);
				(void) printf(gettext("%*sFound %s\n"),
					      recursion_level,
					      "",
					      mbs_buffer);
			}
			
			if (source->depends_on_conditional) {
				target->depends_on_conditional = true;
			}
/*
 * Since it is possible that the same target is built several times during
 * the make run, we have to patch the target with all information we found
 * here. Thus, the target will have an explicit rule the next time around.
 */
			line = maybe_append_prop(target, line_prop);
			if (*command == NULL) {
				*command = line;
			}
			if ((source->stat.time > (*command)->body.line.dependency_time) &&
			    (debug_level > 1)) {
				(void) printf(gettext("%*sDate(%s)=%s Date-dependencies(%s)=%s\n"),
					      recursion_level,
					      "",
					      source->string_mb,
					      time_to_string(source->
							     stat.time),
					      true_target->string_mb,
					      time_to_string((*command)->
							     body.line.
							     dependency_time));
			}
			/*
			 * Determine if this new dependency made the
			 * target out of date.
			 */
			(*command)->body.line.dependency_time =
			  MAX((*command)->body.line.dependency_time,
			      source->stat.time);
			Boolean out_of_date;
			if (target->is_member) {
				out_of_date = (Boolean) OUT_OF_DATE_SEC(target->stat.time,
									(*command)->body.line.dependency_time);
			} else {
				out_of_date = (Boolean) OUT_OF_DATE(target->stat.time,
								    (*command)->body.line.dependency_time);
			}
			if (build_unconditional || out_of_date) {
				if(!rechecking) {
					line->body.line.is_out_of_date = true;
				}
				if (debug_level > 0) {
					(void) printf(gettext("%*sBuilding %s using suffix rule for %s%s because it is out of date relative to %s\n"),
						      recursion_level,
						      "",
						      true_target->string_mb,
						      source_suffix->body.suffix.suffix->string_mb,
						      target_suffix->string_mb,
						      source->string_mb);
				}
			}
			/*
			 * Add the implicit rule as the target's explicit
			 * rule if none actually given, and register
			 * dependency.
			 * The time checking above really should be
			 * conditional on actual use of implicit rule
			 * as well.
			 */
			line->body.line.sccs_command = false;
			if (line->body.line.command_template == NULL) {
				line->body.line.command_template =
				  source_suffix->body.suffix.command_template;
			}
			enter_dependency(line, source, false);
			line->body.line.target = true_target;
			/*
			 * Also make sure the rule is built with
			 * $* and $< bound properly.
			 */
			line->body.line.star = target_body;
			if(svr4|posix) {
			  char * p;
			  char tstr[256];
			  extern Boolean dollarless_flag;
			  extern Name dollarless_value;

			  if(tilde_rule) {
			      MBSTOWCS(wcs_buffer, source->string_mb);
			      dollarless_value = GETNAME(wcs_buffer,FIND_LENGTH);
			  }
			  else {
				   dollarless_flag = false;
			  }
			}
			line->body.line.less = source;
			line->body.line.percent = NULL;
			add_target_to_chain(source, &(line->body.line.query));
			if (sourcename != static_string_buf_3M) {
				retmem(sourcename);
			}
			return build_ok;
		}
		if(posix && posix_tilde_attempt) {
			posix_tilde_attempt = false;
			goto posix_attempts;
		}
		if ((command != NULL) &&
		    ((*command) != NULL) &&
		    ((*command)->body.line.star == NULL)) {
			(*command)->body.line.star = target_body;
		}
	}
	if (sourcename != static_string_buf_3M) {
		retmem(sourcename);
	}
	/* Return here in case no rule matched the target */
	return build_dont_know;
}

/*
 *	find_ar_suffix_rule(target, true_target, command, rechecking)
 *
 *	Scans the .SUFFIXES list and tries
 *	to find a suffix on it that matches the tail of the target member name.
 *	If it finds a matching suffix it calls find_suffix_rule() to find
 *	a rule for the target using the suffix ".a".
 *
 *	Return value:
 *				Indicates if search failed or not
 *
 *	Parameters:
 *		target		The target we need a rule for
 *		true_target	The proper name
 *		command		Pointer to slot where we stuff cmd, if found
 *		rechecking	true if we are rechecking target which depends
 *				on conditional macro and keep_state is set
 *
 *	Global variables used:
 *		debug_level	Indicates how much tracing to do
 *		dot_a		The Name ".a", compared against
 *		recursion_level	Used for tracing
 *		suffixes	List of suffixes used for scan (from .SUFFIXES)
 */
Doname
find_ar_suffix_rule(register Name target, Name true_target, Property *command, Boolean rechecking)
{
	wchar_t			*target_end;
	register Dependency	suffix;
	register int		suffix_length;
	Property		line;
	Name			body;
	static Name		dot_a;

	Wstring			targ_string(true_target);
	Wstring			suf_string;

	if (dot_a == NULL) {
		MBSTOWCS(wcs_buffer, ".a");
		dot_a = GETNAME(wcs_buffer, FIND_LENGTH);
	}
	target_end = targ_string.get_string() + true_target->hash.length;

	/*
	 * We compare the tail of the target name with the suffixes
	 * from .SUFFIXES.
	 */
	if (debug_level > 1) {
		(void) printf("%*sfind_ar_suffix_rule(%s)\n",
			      recursion_level,
			      "",
			      true_target->string_mb);
	}
	/*
	 * Scan the .SUFFIXES list to see if the target matches any of
	 * those suffixes.
	 */
	for (suffix = suffixes; suffix != NULL; suffix = suffix->next) {
		/* Compare one suffix. */
		suffix_length = suffix->name->hash.length;
		suf_string.init(suffix->name);
		if (!IS_WEQUALN(suf_string.get_string(),
			        target_end - suffix_length,
			        suffix_length)) {
			goto not_this_one;
		}
		/*
		 * The target tail matched a suffix from the .SUFFIXES list.
		 * Now check for a rule to match.
		 */
		target->suffix_scan_done = false;
		body = GETNAME(targ_string.get_string(),
  			       (int)(true_target->hash.length -
				     suffix_length));
		we_are_in_tilde = false;
		switch (find_suffix_rule(target,
					 body,
					 dot_a,
					 command,
					 rechecking)) {
		case build_ok:
			line = get_prop(target->prop, line_prop);
			line->body.line.star = body;
			return build_ok;
		case build_running:
			return build_running;
		}
		/*
		 * If no rule was found, we try the next suffix to see
		 * if it matches the target tail, and so on.
		 * Go here if the suffix did not match the target tail.
		 */
	not_this_one:;			 
	}
	return build_dont_know;
}

/*
 *	find_double_suffix_rule(target, command, rechecking)
 *
 *	Scans the .SUFFIXES list and tries
 *	to find a suffix on it that matches the tail of the target name.
 *	If it finds a matching suffix it calls find_suffix_rule() to find
 *	a rule for the target.
 *
 *	Return value:
 *				Indicates if scan failed or not
 *
 *	Parameters:
 *		target		Target we need a rule for
 *		command		Pointer to slot where we stuff cmd, if found
 *		rechecking	true if we are rechecking target which depends
 *				on conditional macro and keep_state is set
 *
 *	Global variables used:
 *		debug_level	Indicates how much tracing to do
 *		recursion_level	Used for tracing
 *		suffixes	List of suffixes used for scan (from .SUFFIXES)
 */
Doname
find_double_suffix_rule(register Name target, Property *command, Boolean rechecking)
{
	Name			true_target = target;
	Name			target_body;
	register wchar_t	*target_end;
	register Dependency	suffix;
	register int		suffix_length;
	Boolean			scanned_once = false;
	Boolean			name_found = true;

	Wstring			targ_string;
	Wstring			suf_string;

	/*
	 * If the target is a constructed one for a "::" target,
	 * we need to consider that.
	 */
	if (target->has_target_prop) {
		true_target = get_prop(target->prop,
				       target_prop)->body.target.target;
	}
	targ_string.init(true_target);

	/*
	 * We compare the tail of the target name with the
	 * suffixes from .SUFFIXES.
	 */
	target_end = targ_string.get_string() + true_target->hash.length;
	if (debug_level > 1) {
		(void) printf("%*sfind_double_suffix_rule(%s)\n",
			      recursion_level,
			      "",
			      true_target->string_mb);
	}
	/*
	 * Scan the .SUFFIXES list to see if the target matches
	 * any of those suffixes.
	 */
	for (suffix = suffixes; suffix != NULL; suffix = suffix->next) {
		target->suffix_scan_done = false;
		true_target->suffix_scan_done = false;
		/* Compare one suffix. */
		suffix_length = suffix->name->hash.length;
		suf_string.init(suffix->name);
		/* Check the lengths, or else RTC will report rua. */
		if (true_target->hash.length < suffix_length) {
			goto not_this_one;
		} else if (!IS_WEQUALN(suf_string.get_string(),
			        (target_end - suffix_length),
			        suffix_length)) {
			goto not_this_one;
		}
		/*
		 * The target tail matched a suffix from the .SUFFIXES list.
		 * Now check for a rule to match.
		 */
		we_are_in_tilde = false;
		target_body = GETNAME(
			targ_string.get_string(),
			(int)(true_target->hash.length - suffix_length)
		);
		switch (find_suffix_rule(target,
					 target_body,
					 suffix->name,
					 command,
					 rechecking)) {
		case build_ok:
			return build_ok;
		case build_running:
			return build_running;
		}
		if (true_target->suffix_scan_done == true) {
			scanned_once = true;
		}
		/*
		 * If no rule was found, we try the next suffix to see
		 * if it matches the target tail. And so on.
		 * Go here if the suffix did not match the target tail.
		 */
	not_this_one:;			 
	}
	if (scanned_once)
		true_target->suffix_scan_done = true;
	return build_dont_know;
}

/*
 *	build_suffix_list(target_suffix)
 *
 *	Scans the .SUFFIXES list and figures out
 *	which suffixes this target can be derived from.
 *	The target itself is not know here, we just know the suffix of the
 *	target. For each suffix on the list the target can be derived iff
 *	a rule exists for the name "<suffix-on-list><target-suffix>".
 *	A list of all possible building suffixes is built, with the rule for
 *	each, and tacked to the target suffix nameblock.
 *
 *	Parameters:
 *		target_suffix	The suffix we build a match list for
 *
 *	Global variables used:
 *		debug_level	Indicates how much tracing to do
 *		recursion_level	Used for tracing
 *		suffixes	List of suffixes used for scan (from .SUFFIXES)
 *		working_on_targets Indicates that this is a real target
 */
void
build_suffix_list(register Name target_suffix)
{
	register Dependency	source_suffix;
	wchar_t			rule_name[MAXPATHLEN];
	register Property	line;
	register Property	suffix;
	Name			rule;

	/* If this is before default.mk has been read we just return to try */
	/* again later */
	if ((suffixes == NULL) || !working_on_targets) {
		return;
	}
	if (debug_level > 1) {
		(void) printf("%*sbuild_suffix_list(%s) ",
			      recursion_level,
			      "",
			      target_suffix->string_mb);
	}
	/* Mark the target suffix saying we cashed its list */
	target_suffix->has_read_suffixes = true;
	/* Scan the .SUFFIXES list */
	for (source_suffix = suffixes;
	     source_suffix != NULL;
	     source_suffix = source_suffix->next) {
		/*
		 * Build the name "<suffix-on-list><target-suffix>".
		 * (a popular one would be ".c.o").
		 */
		(void) mbstowcs(rule_name,
			      source_suffix->name->string_mb,
			      (int) source_suffix->name->hash.length);
		(void) mbstowcs(rule_name + source_suffix->name->hash.length,
			      target_suffix->string_mb,
			      (int) target_suffix->hash.length);
		/*
		 * Check if that name has a rule. If not, it cannot match
		 * any implicit rule scan and is ignored.
		 * The GETNAME() call only checks for presence, it will not
		 * enter the name if it is not defined.
		 */
		if (((rule = getname_fn(rule_name,
					(int) (source_suffix->name->
					       hash.length +
					       target_suffix->hash.length),
					true)) != NULL) &&
		    ((line = get_prop(rule->prop, line_prop)) != NULL)) {
			if (debug_level > 1) {
				(void) printf("%s ", rule->string_mb);
			}
			/*
			 * This makes it possible to quickly determine if
			 * it will pay to look for a suffix property.
			 */
			target_suffix->has_suffixes = true;
			/*
			 * Add the suffix property to the target suffix
			 * and save the rule with it.
			 * All information the implicit rule scanner need
			 * is saved in the suffix property.
			 */
			suffix = append_prop(target_suffix, suffix_prop);
			suffix->body.suffix.suffix = source_suffix->name;
			suffix->body.suffix.command_template =
			  line->body.line.command_template;
		}
	}
	if (debug_level > 1) {
		(void) printf("\n");
	}
}

/*
 *	find_percent_rule(target, command, rechecking)
 *
 *	Tries to find a rule from the list of wildcard matched rules.
 *	It scans the list attempting to match the target.
 *	For each target match it checks if the corresponding source exists.
 *	If it does the match is returned.
 *	The percent_list is built at makefile read time.
 *	Each percent rule get one entry on the list.
 *
 *	Return value:
 *				Indicates if the scan failed or not
 *
 *	Parameters:
 *		target		The target we need a rule for
 *		command		Pointer to slot where we stuff cmd, if found
 *		rechecking	true if we are rechecking target which depends
 *				on conditional macro and keep_state is set
 *
 *	Global variables used:
 *		debug_level	Indicates how much tracing to do
 *		percent_list	List of all percent rules
 *		recursion_level	Used for tracing
 *		empty_name
 */
Doname
find_percent_rule(register Name target, Property *command, Boolean rechecking)
{
	register Percent	pat_rule, pat_depe;
	register Name		depe_to_check;
	register Dependency	depe;
	register Property	line;
	String_rec		string;
	wchar_t			string_buf[STRING_BUFFER_LENGTH];
	String_rec		percent;
	wchar_t			percent_buf[STRING_BUFFER_LENGTH];
	Name			true_target = target;
	Name			less;
	Boolean			nonpattern_less;
	Boolean			dep_name_found = false;
	Doname			result = build_dont_know;
	Percent			rule_candidate = NULL;
	Boolean			rule_maybe_ok;
	Boolean			is_pattern;

	/* If the target is constructed for a "::" target we consider that */
	if (target->has_target_prop) {
		true_target = get_prop(target->prop,
				       target_prop)->body.target.target;
	}
	if (target->has_long_member_name) {
		true_target = get_prop(target->prop,
				       long_member_name_prop)->body.long_member_name.member_name;
	}
	if (debug_level > 1) {
		(void) printf(gettext("%*sLooking for %% rule for %s\n"),
			      recursion_level,
			      "",
			      true_target->string_mb);
	}
	for (pat_rule = percent_list;
	     pat_rule != NULL;
	     pat_rule = pat_rule->next) {
		/* Avoid infinite recursion when expanding patterns */
		if (pat_rule->being_expanded == true) {
			continue;
		}

		/* Mark this pat_rule as "maybe ok". If no % rule is found
		   make will use this rule. The following algorithm is used:
		   1) make scans all pattern rules in order to find the rule
		      where ALL dependencies, including nonpattern ones, exist or
		      can be built (GNU behaviour). If such rule is found make
		      will apply it.
		   2) During this check make also remembers the first pattern rule
		      where all PATTERN dependencies can be build (no matter what
		      happens with nonpattern dependencies).
		   3) If no rule satisfying 1) is found, make will apply the rule
		      remembered in 2) if there is one.
		*/
		rule_maybe_ok = true;

		/* used to track first percent dependency */
		less = NULL;
		nonpattern_less = true;

		/* check whether pattern matches.
		   if it matches, percent string will contain matched percent part of pattern */
		if (!match_found_with_pattern(true_target, pat_rule, &percent, percent_buf)) {
			continue;
		}
		if (pat_rule->dependencies != NULL) {
			for (pat_depe = pat_rule->dependencies;
			     pat_depe != NULL;
			     pat_depe = pat_depe->next) {
				/* checking result for dependency */
				result = build_dont_know;

				dep_name_found = true;
				if (pat_depe->name->percent) {
					is_pattern = true;
					/* build dependency name */
					INIT_STRING_FROM_STACK(string, string_buf);
					construct_string_from_pattern(pat_depe, &percent, &string); 
					depe_to_check = getname_fn(string.buffer.start,
						FIND_LENGTH,
						false,
						&dep_name_found
					);

					if ((less == NULL) || nonpattern_less) {
						less = depe_to_check;
						nonpattern_less = false;
					}
				} else {
					/* nonpattern dependency */
					is_pattern = false;
					depe_to_check = pat_depe->name;
					if(depe_to_check->dollar) {
						INIT_STRING_FROM_STACK(string, string_buf);
						expand_value(depe_to_check, &string, false);
						depe_to_check = getname_fn(string.buffer.start,
							FIND_LENGTH,
							false,
							&dep_name_found
						);
					}
					if (less == NULL) {
						less = depe_to_check;
					}
				}

				if (depe_to_check == empty_name) {
						result = build_ok;
				} else {
					if (debug_level > 1) {
						(void) printf(gettext("%*sTrying %s\n"),
							      recursion_level,
							      "",
							      depe_to_check->string_mb);
					}

					pat_rule->being_expanded = true;

					/* suppress message output */
					int save_debug_level = debug_level;
					debug_level = 0;

					/* check whether dependency can be built */
					if (dependency_exists(depe_to_check,
					      get_prop(target->prop,
						       line_prop)))
					{
						result = (Doname) depe_to_check->state;
					} else {
						if(actual_doname) {
							result = doname(depe_to_check, true, true);
						} else {
							result = target_can_be_built(depe_to_check);
						}
						if(!dep_name_found) {
							if(result != build_ok && result != build_running) {
								free_name(depe_to_check);
							} else {
								store_name(depe_to_check);
							}
						}
					}
					if(result != build_ok && is_pattern) {
						rule_maybe_ok = false;
					}

					/* restore debug_level */
					debug_level = save_debug_level;
				}

				if (pat_depe->name->percent) {
					if (string.free_after_use) {
						retmem(string.buffer.start);
					}
				}
				/* make can't figure out how to make this dependency */
				if (result != build_ok && result != build_running) {
					pat_rule->being_expanded = false;
					break;
				}
			}
		} else {
			result = build_ok;
		}

		/* this pattern rule is the needed one since all dependencies could be built */
		if (result == build_ok || result == build_running) {
			break;
		}

		/* Make does not know how to build some of dependencies from this rule.
		   But if all "pattern" dependencies can be built, we remember this rule
		   as a candidate for the case if no other pattern rule found.
		*/
		if(rule_maybe_ok && rule_candidate == NULL) {
			rule_candidate = pat_rule;
		}
	}

	/* if no pattern matching rule was found, use the remembered candidate
	   or return build_dont_know if there is no candidate.
	*/
	if (result != build_ok && result != build_running) {
		if(rule_candidate) {
			pat_rule = rule_candidate;
		} else {
			return build_dont_know;
		}
	}

	/* if we are performing only check whether dependency could be built with existing rules,
	   return success */
	if (command == NULL) {
		if(pat_rule != NULL) {
			pat_rule->being_expanded = false;
		}
		return result;
	}

	if (debug_level > 1) {
		(void) printf(gettext("%*sMatched %s:"),
				      recursion_level,
				      "",
				      target->string_mb);

		for (pat_depe = pat_rule->dependencies;
		     pat_depe != NULL;
		     pat_depe = pat_depe->next) {
			if (pat_depe->name->percent) {
				INIT_STRING_FROM_STACK(string, string_buf);
				construct_string_from_pattern(pat_depe, &percent, &string);
				depe_to_check = GETNAME(string.buffer.start, FIND_LENGTH);
			} else {
				depe_to_check = pat_depe->name;
				if(depe_to_check->dollar) {
					INIT_STRING_FROM_STACK(string, string_buf);
					expand_value(depe_to_check, &string, false);
					depe_to_check = GETNAME(string.buffer.start, FIND_LENGTH);
				}
			}

			if (depe_to_check != empty_name) {
				(void) printf(" %s", depe_to_check->string_mb);
			}
		}

		(void) printf(gettext(" from: %s:"),
			      pat_rule->name->string_mb);

		for (pat_depe = pat_rule->dependencies;
		     pat_depe != NULL;
		     pat_depe = pat_depe->next) {
			(void) printf(" %s", pat_depe->name->string_mb);
		}

		(void) printf("\n");
	}

	if (true_target->colons == no_colon) {
		true_target->colons = one_colon;
	}

	/* create deppendency list and target group from matched pattern rule */
	create_target_group_and_dependencies_list(target, pat_rule, &percent);

	/* save command */
	line = get_prop(target->prop, line_prop);
	*command = line;

	/* free query chain if one exist */
	while(line->body.line.query != NULL) {
		Chain to_free = line->body.line.query;
		line->body.line.query = line->body.line.query->next;
		retmem_mb((char *) to_free);
	}

	if (line->body.line.dependencies != NULL) {
		/* build all collected dependencies */
		for (depe = line->body.line.dependencies;
		     depe != NULL; 
		     depe = depe->next) {
			actual_doname = true;
			result = doname_check(depe->name, true, true, depe->automatic);

			actual_doname = false;
			if (result == build_failed) {
				pat_rule->being_expanded = false;
				return build_failed;
			}
			if (result == build_running) {
				pat_rule->being_expanded = false;
				return build_running;
			}

			if ((depe->name->stat.time > line->body.line.dependency_time) &&
			    (debug_level > 1)) {
				(void) printf(gettext("%*sDate(%s)=%s Date-dependencies(%s)=%s\n"),
					      recursion_level,
					      "",
					      depe->name->string_mb,
					      time_to_string(depe->name->stat.time),
					      true_target->string_mb,
					      time_to_string(line->body.line.dependency_time));
			}

			line->body.line.dependency_time =
			  MAX(line->body.line.dependency_time, depe->name->stat.time);

			/* determine whether this dependency made target out of date */
			Boolean out_of_date;
			if (target->is_member || depe->name->is_member) {
				out_of_date = (Boolean) OUT_OF_DATE_SEC(target->stat.time, depe->name->stat.time);
			} else {
				out_of_date = (Boolean) OUT_OF_DATE(target->stat.time, depe->name->stat.time);
			}
			if (build_unconditional || out_of_date) {
				if(!rechecking) {
					line->body.line.is_out_of_date = true;
				}
				add_target_to_chain(depe->name, &(line->body.line.query));

				if (debug_level > 0) {
					(void) printf(gettext("%*sBuilding %s using pattern rule %s:"),
						      recursion_level,
						      "",
						      true_target->string_mb,
						      pat_rule->name->string_mb);

					for (pat_depe = pat_rule->dependencies;
					     pat_depe != NULL;
					     pat_depe = pat_depe->next) {
						(void) printf(" %s", pat_depe->name->string_mb);
					}

					(void) printf(gettext(" because it is out of date relative to %s\n"), 
						      depe->name->string_mb);
				}	
			}
		}
	} else {
		if ((true_target->stat.time <= file_doesnt_exist) ||
		    (true_target->stat.time < line->body.line.dependency_time)) {
			if(!rechecking) {
				line->body.line.is_out_of_date = true;
			}
			if (debug_level > 0) {
				(void) printf(gettext("%*sBuilding %s using pattern rule %s: "),
					      recursion_level,
					      "",
					      true_target->string_mb,
					      pat_rule->name->string_mb,
					      (target->stat.time > file_doesnt_exist) ?
					      gettext("because it is out of date") :
					      gettext("because it does not exist"));
			}
		}
	}

	/* enter explicit rule from percent rule */	
	Name lmn_target = true_target;
	if (true_target->has_long_member_name) {
		lmn_target = get_prop(true_target->prop, long_member_name_prop)->body.long_member_name.member_name;
	}
	line->body.line.sccs_command = false;
	line->body.line.target = true_target;
	line->body.line.command_template = pat_rule->command_template;
	line->body.line.star = GETNAME(percent.buffer.start, FIND_LENGTH);
	line->body.line.less = less;

	if (lmn_target->parenleft) {
		Wstring lmn_string(lmn_target);

		wchar_t *left = (wchar_t *) wcschr(lmn_string.get_string(), (int) parenleft_char);
		wchar_t *right = (wchar_t *) wcschr(lmn_string.get_string(), (int) parenright_char);

		if ((left == NULL) || (right == NULL)) {
			line->body.line.percent = NULL;
		} else {
			line->body.line.percent = GETNAME(left + 1, right - left - 1);
		}
	} else {
		line->body.line.percent = NULL;
	}
	pat_rule->being_expanded = false;

	return result;
}

/*
 *	match_found_with_pattern 
 *           ( target, pat_rule, percent, percent_buf)
 *	
 *	matches "target->string" with a % pattern.
 *	If pattern contains a MACRO definition, it's expanded first.
 *
 *	Return value:
 *				true if a match was found
 *
 *	Parameters:
 *		target		The target we're trying to match
 *     		pattern		
 *		percent		record that contains "percent_buf" below
 *		percent_buf	This is where the patched % part of pattern is stored 
 *
 */

static Boolean
match_found_with_pattern(Name target, Percent pat_rule, String percent, wchar_t *percent_buf) {
	String_rec		string;
	wchar_t			string_buf[STRING_BUFFER_LENGTH];

	/* construct prefix string and check whether prefix matches */
	Name prefix = pat_rule->patterns[0];
	int prefix_length;

	Wstring targ_string(target);
	Wstring pref_string(prefix);
	Wstring suf_string;

	if (prefix->dollar) {	
		INIT_STRING_FROM_STACK(string, string_buf);
		expand_value(prefix, &string, false);
		prefix_length = string.text.p - string.buffer.start;
		if ((string.buffer.start[0] == (int) period_char) &&
		    (string.buffer.start[1] == (int) slash_char)) {
			string.buffer.start += 2;
			prefix_length -= 2;
		}
		if (!targ_string.equaln(string.buffer.start, prefix_length)) {
			return false;
		}
	} else {
		prefix_length = prefix->hash.length;
		if (!targ_string.equaln(&pref_string, prefix_length)) {
			return false;
		}
	}

	/* do the same with pattern suffix */
	Name suffix = pat_rule->patterns[pat_rule->patterns_total - 1];
	suf_string.init(suffix);

	int suffix_length;
	if (suffix->dollar) {
		INIT_STRING_FROM_STACK(string, string_buf);
		expand_value(suffix, &string, false);
		suffix_length = string.text.p - string.buffer.start;
		if(suffix_length > target->hash.length) {
			return false;
		}
		if (!targ_string.equal(string.buffer.start, target->hash.length - suffix_length)) {
			return false;
		}
	} else {
		suffix_length = (int) suffix->hash.length;
		if(suffix_length > target->hash.length) {
			return false;
		}
		if (!targ_string.equal(&suf_string, target->hash.length - suffix_length)) {
			return false;
		}
	}

	Boolean match_found = false;
	int percent_length = target->hash.length - prefix_length - suffix_length;
	
	while (!match_found && (percent_length >= 0)) {
		/* init result string */
		INIT_STRING_FROM_STACK(string, string_buf);

		/* init percent string */
		percent->buffer.start = percent_buf;
		percent->text.p = percent_buf;
		percent->text.end = NULL;
		percent->free_after_use = false;
		percent->buffer.end = percent_buf + STRING_BUFFER_LENGTH;

		/* construct percent and result strings */
		targ_string.append_to_str(percent, prefix_length, percent_length);
		construct_string_from_pattern(pat_rule, percent, &string);

		/* check for match */
		if (targ_string.equal(string.buffer.start, 0)) {
			match_found = true;
		} else {
			percent_length--;
		}
	}
	
	/* result */
	return match_found;
}


/*
 *	create_target_group_and_dependencies_list
 *           (target, pat_rule, percent)
 *	
 *	constructs dependency list and a target group from pattern.
 *
 *	If we have the lines
 *		%/%.a + %/%.b + C%/CC%.c: yyy %.d bb%/BB%.e
 *			commands
 *
 * 	and we have matched the pattern xx/xx.a with %/%.a, then we
 *	construct a target group that looks like this:
 *		xx/xx.a + xx/xx.b + Cxx/CCxx.c: dependencies
 *
 *	and construct dependency list that looks like this:
 *	yyy xx.d bbxx/BBxx.e + already existed dependencies
 *	
 *	Return value:
 *				none
 *
 *	Parameters:
 *		target		The target we are building, in the previous
 *				example, this is xx/xx.a
 *     		pat_rule        the % pattern that matched "target", here %/%.a
 *		percent		string containing matched % part. In the example=xx.
 *
 *	Global variables used:
 *		empty_name
 */

static void
create_target_group_and_dependencies_list(Name target, Percent pat_rule, String percent) {
	String_rec	string;
	wchar_t		string_buf[STRING_BUFFER_LENGTH];
	Percent		pat_depe;
	Name		depe;
	Property	line = maybe_append_prop(target, line_prop);
	Chain		new_target_group = NULL;
	Chain		*new_target_group_tail = &new_target_group;
	Chain		group_member;
	
	/* create and append dependencies from rule */
	for (pat_depe = pat_rule->dependencies; pat_depe != NULL; pat_depe = pat_depe->next) {
		if (pat_depe->name->percent) {
			INIT_STRING_FROM_STACK(string, string_buf);
			construct_string_from_pattern(pat_depe, percent, &string);
			depe = GETNAME(string.buffer.start, FIND_LENGTH);
			if (depe != empty_name) {
				enter_dependency(line, depe, false);
			}
		} else {
			depe = pat_depe->name;
			if(depe->dollar) {
				INIT_STRING_FROM_STACK(string, string_buf);
				expand_value(depe, &string, false);
				depe = GETNAME(string.buffer.start, FIND_LENGTH);
			}
			enter_dependency(line, depe, false);
		}
	}
	
	/* if matched pattern is a group member, create new target group */
	for (group_member = pat_rule->target_group; group_member != NULL; group_member = group_member->next) {
		Name new_target = group_member->name;
		if (group_member->name->percent) {
			INIT_STRING_FROM_STACK(string, string_buf);
			construct_string_from_pattern(group_member->percent_member, percent, &string);
			new_target = GETNAME(string.buffer.start, FIND_LENGTH);
			if (new_target == empty_name) {
				continue;
			}
		}

		/* check for duplicates */
		Chain	tgm;
		for (tgm = new_target_group; tgm != NULL; tgm = tgm->next) {
			if (new_target == tgm->name) {
				break;
			}
		}
		if (tgm != NULL) {
			continue;
		}
		
		/* insert it into the targets list */
		(*new_target_group_tail) = ALLOC(Chain);
		(*new_target_group_tail)->name = new_target;
		(*new_target_group_tail)->next = NULL;
		new_target_group_tail = &(*new_target_group_tail)->next;
	}
	
	/* now we gathered all dependencies and created target group */
	line->body.line.target_group = new_target_group;

	/* update properties for group members */
	for (group_member = new_target_group; group_member != NULL; group_member = group_member->next) {
		if (group_member->name != target) {
			group_member->name->prop = target->prop;
			group_member->name->conditional_cnt = target->conditional_cnt;
		}
	}
}

/*
 *	construct_string_from_pattern
 *		(pat_rule, percent, result)
 *
 *	after pattern matched a target this routine is called to construct targets and dependencies
 *	strings from this matched pattern rule and a string (percent) with substitutes % sign in pattern.
 *
 *	Return value:
 *				none
 *
 *	Parameters:
 *     		pat_rule 	matched pattern rule
 *		percent		string containing matched % sign part.
 *		result		holds the result of string construction.
 *
 */
static void
construct_string_from_pattern(Percent pat_rule, String percent, String result) {
	for (int i = 0; i < pat_rule->patterns_total; i++) {
		if (pat_rule->patterns[i]->dollar) {
			expand_value(pat_rule->patterns[i],
				     result,
				     false);
			
		} else {
			append_string(pat_rule->patterns[i]->string_mb,
				      result,
				      pat_rule->patterns[i]->hash.length);
		}
		
		if (i < pat_rule->patterns_total - 1) {
			append_string(percent->buffer.start,
				      result,
				      percent->text.p - percent->buffer.start);
		}
	}
	
	if ((result->buffer.start[0] == (int) period_char) &&
	    (result->buffer.start[1] == (int) slash_char)) {
		result->buffer.start += 2;
	}
}

/*
 *	dependency_exists(target, line)
 *
 *	Returns true if the target exists in the
 *	dependency list of the line.
 *
 *	Return value:
 *				True if target is on dependency list
 *
 *	Parameters:
 *		target		Target we scan for
 *		line		We get the dependency list from here
 *
 *	Global variables used:
 */
static Boolean
dependency_exists(Name target, Property line)
{
	Dependency	dp;

	if (line == NULL) {
		return false;
	}
	for (dp = line->body.line.dependencies; dp != NULL; dp = dp->next) {
		if (dp->name == target) {
			return true;
		}
	}
	return false;
}

void
add_target_to_chain(Name target, Chain * query)
{
	if (target->is_member && (get_prop(target->prop, member_prop) != NULL)) {
		target = get_prop(target->prop, member_prop)->body.member.member;
	}
	Chain	*query_tail;
	for (query_tail = query; *query_tail != NULL; query_tail = &(*query_tail)->next) {
		if ((*query_tail)->name == target) {
			return;
		}
	}
	*query_tail = ALLOC(Chain);
	(*query_tail)->name = target;
	(*query_tail)->next = NULL;
}

