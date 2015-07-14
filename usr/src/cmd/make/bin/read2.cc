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
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	read.c
 *
 *	This file contains the makefile reader.
 */

/*
 * Included files
 */
#include <mk/defs.h>
#include <mksh/dosys.h>		/* sh_command2string() */
#include <mksh/macro.h>		/* expand_value() */
#include <mksh/misc.h>		/* retmem() */
#include <stdarg.h>		/* va_list, va_start(), va_end() */
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
static	Boolean		built_last_make_run_seen;

/*
 * File table of contents
 */
static	Name_vector	enter_member_name(register wchar_t *lib_start, register wchar_t *member_start, register wchar_t *string_end, Name_vector current_names, Name_vector *extra_names);
extern	Name		normalize_name(register wchar_t *name_string, register int length);
static	void		read_suffixes_list(register Name_vector depes);
static	void		make_relative(wchar_t *to, wchar_t *result);
static	void		print_rule(register Cmd_line command);
static	void		sh_transform(Name *name, Name *value);


/*
 *	enter_name(string, tail_present, string_start, string_end,
 *	      current_names, extra_names, target_group_seen)
 *
 *	Take one string and enter it as a name. The string is passed in
 *	two parts. A make string and possibly a C string to append to it.
 *	The result is stuffed in the vector current_names.
 *	extra_names points to a vector that is used if current_names overflows.
 *	This is allocad in the calling routine.
 *	Here we handle the "lib.a[members]" notation.
 *
 *	Return value:
 *				The name vector that was used
 *
 *	Parameters:
 *		tail_present	Indicates if both C and make string was passed
 *		string_start	C string
 *		string_end	Pointer to char after last in C string
 *		string		make style string with head of name
 *		current_names	Vector to deposit the name in
 *		extra_names	Where to get next name vector if we run out
 *		target_group_seen Pointer to boolean that is set if "+" is seen
 *
 *	Global variables used:
 *		makefile_type	When we read a report file we normalize paths
 *		plus		Points to the Name "+"
 */

Name_vector
enter_name(String string, Boolean tail_present, register wchar_t *string_start, register wchar_t *string_end, Name_vector current_names, Name_vector *extra_names, Boolean *target_group_seen)
{
	Name			name;
	register wchar_t	*cp;
	wchar_t			ch;

	/* If we were passed a separate tail of the name we append it to the */
	/* make string with the rest of it */
	if (tail_present) {
		append_string(string_start, string, string_end - string_start);
		string_start = string->buffer.start;
		string_end = string->text.p;
	}
	ch = *string_end;
	*string_end = (int) nul_char;
	/*
	 * Check if there are any ( or [ that are not prefixed with $.
	 * If there are, we have to deal with the lib.a(members) format.
	 */
	for (cp = (wchar_t *) wcschr(string_start, (int) parenleft_char);
	     cp != NULL;
	     cp = (wchar_t *) wcschr(cp + 1, (int) parenleft_char)) {
		if (*(cp - 1) != (int) dollar_char) {
			*string_end = ch;
			return enter_member_name(string_start,
						 cp,
						 string_end,
						 current_names,
						 extra_names);
		}
	}
	*string_end = ch;

	if (makefile_type == reading_cpp_file) {
		/* Remove extra ../ constructs if we are reading from a report file */
		name = normalize_name(string_start, string_end - string_start);
	} else {
		/*
		 * /tolik, fix bug 1197477/
		 * Normalize every target name before entering.
		 * ..//obj/a.o and ../obj//a.o are not two different targets.
		 * There is only one target ../obj/a.o
		 */
		/*name = GETNAME(string_start, string_end - string_start);*/
		name = normalize_name(string_start, string_end - string_start);
	}

	/* Internalize the name. Detect the name "+" (target group here) */
if(current_names->used != 0 && current_names->names[current_names->used-1] == plus) {
	if(name == plus) {
		return current_names;
	}
}
	/* If the current_names vector is full we patch in the one from */
	/* extra_names */
	if (current_names->used == VSIZEOF(current_names->names)) {
		if (current_names->next != NULL) {
			current_names = current_names->next;
		} else {
			current_names->next = *extra_names;
			*extra_names = NULL;
			current_names = current_names->next;
			current_names->used = 0;
			current_names->next = NULL;
		}
	}
	current_names->target_group[current_names->used] = NULL;
	current_names->names[current_names->used++] = name;
	if (name == plus) {
		*target_group_seen = true;
	}
	if (tail_present && string->free_after_use) {
		retmem(string->buffer.start);
	}
	return current_names;
}

/*
 *	enter_member_name(lib_start, member_start, string_end,
 *		  current_names, extra_names)
 *
 *	A string has been found to contain member names.
 *	(The "lib.a[members]" and "lib.a(members)" notation)
 *	Handle it pretty much as enter_name() does for simple names.
 *
 *	Return value:
 *				The name vector that was used
 *
 *	Parameters:
 *		lib_start	Points to the of start of "lib.a(member.o)"
 *		member_start	Points to "member.o" from above string.
 *		string_end	Points to char after last of above string.
 *		current_names	Vector to deposit the name in
 *		extra_names	Where to get next name vector if we run out
 *
 *	Global variables used:
 */
static Name_vector
enter_member_name(register wchar_t *lib_start, register wchar_t *member_start, register wchar_t *string_end, Name_vector current_names, Name_vector *extra_names)
{
	register Boolean	entry = false;
	wchar_t			buffer[STRING_BUFFER_LENGTH];
	Name			lib;
	Name			member;
	Name			name;
	Property		prop;
	wchar_t			*memberp;
	wchar_t			*q;
	register int		paren_count;
	register Boolean	has_dollar;
	register wchar_t	*cq;
	Name			long_member_name = NULL;

	/* Internalize the name of the library */
	lib = GETNAME(lib_start, member_start - lib_start);
	lib->is_member = true;
	member_start++;
	if (*member_start == (int) parenleft_char) {
		/* This is really the "lib.a((entries))" format */
		entry = true;
		member_start++;
	}
	/* Move the library name to the buffer where we intend to build the */
	/* "lib.a(member)" for each member */
	(void) wcsncpy(buffer, lib_start, member_start - lib_start);
	memberp = buffer + (member_start-lib_start);
	while (1) {
		long_member_name = NULL;
		/* Skip leading spaces */
		for (;
		     (member_start < string_end) && iswspace(*member_start);
		     member_start++);
		/* Find the end of the member name. Allow nested (). Detect $*/
		for (cq = memberp, has_dollar = false, paren_count = 0;
		     (member_start < string_end) &&
		     ((*member_start != (int) parenright_char) ||
		      (paren_count > 0)) &&
		     !iswspace(*member_start);
		     *cq++ = *member_start++) {
			switch (*member_start) {
			case parenleft_char:
				paren_count++;
				break;
			case parenright_char:
				paren_count--;
				break;
			case dollar_char:
				has_dollar = true;
			}
		}
		/* Internalize the member name */
		member = GETNAME(memberp, cq - memberp);
		*cq = 0;
		if ((q = (wchar_t *) wcsrchr(memberp, (int) slash_char)) == NULL) {
			q = memberp;
		}
		if ((cq - q > (int) ar_member_name_len) &&
		    !has_dollar) {
			*cq++ = (int) parenright_char;
			if (entry) {
				*cq++ = (int) parenright_char;
			}
			long_member_name = GETNAME(buffer, cq - buffer);
			cq = q + (int) ar_member_name_len;
		}
		*cq++ = (int) parenright_char;
		if (entry) {
			*cq++ = (int) parenright_char;
		}
		/* Internalize the "lib.a(member)" notation for this member */
		name = GETNAME(buffer, cq - buffer);
		name->is_member = lib->is_member;
		if (long_member_name != NULL) {
			prop = append_prop(name, long_member_name_prop);
			name->has_long_member_name = true;
			prop->body.long_member_name.member_name =
			  long_member_name;
		}
		/* And add the member prop */
		prop = append_prop(name, member_prop);
		prop->body.member.library = lib;
		if (entry) {
			/* "lib.a((entry))" notation */
			prop->body.member.entry = member;
			prop->body.member.member = NULL;
		} else {
			/* "lib.a(member)" Notation */
			prop->body.member.entry = NULL;
			prop->body.member.member = member;
		}
		/* Handle overflow of current_names */
		if (current_names->used == VSIZEOF(current_names->names)) {
			if (current_names->next != NULL) {
				current_names = current_names->next;
			} else {
				if (*extra_names == NULL) {
					current_names =
					  current_names->next =
					    ALLOC(Name_vector);
				} else {
					current_names =
					  current_names->next =
					    *extra_names;
					*extra_names = NULL;
				}
				current_names->used = 0;
				current_names->next = NULL;
			}
		}
		current_names->target_group[current_names->used] = NULL;
		current_names->names[current_names->used++] = name;
		while (iswspace(*member_start)) {
			member_start++;
		}
		/* Check if there are more members */
		if ((*member_start == (int) parenright_char) ||
		    (member_start >= string_end)) {
			return current_names;
		}
	}
	/* NOTREACHED */
}

/*
 *	normalize_name(name_string, length)
 *
 *	Take a namestring and remove redundant ../, // and ./ constructs
 *
 *	Return value:
 *				The normalized name
 *
 *	Parameters:
 *		name_string	Path string to normalize
 *		length		Length of that string
 *
 *	Global variables used:
 *		dot		The Name ".", compared against
 *		dotdot		The Name "..", compared against
 */
Name
normalize_name(register wchar_t *name_string, register int length)
{
	static Name		dotdot;
	register wchar_t	*string = ALLOC_WC(length + 1);
	register wchar_t	*string2;
	register wchar_t	*cdp;
	wchar_t			*current_component;
	Name			name;
	register int		count;

	if (dotdot == NULL) {
		MBSTOWCS(wcs_buffer, "..");
		dotdot = GETNAME(wcs_buffer, FIND_LENGTH);
	}

	/*
	 * Copy string removing ./ and //.
	 * First strip leading ./
	 */
	while ((length > 1) &&
	       (name_string[0] == (int) period_char) &&
	       (name_string[1] == (int) slash_char)) {
		name_string += 2;
		length -= 2;
		while ((length > 0) && (name_string[0] == (int) slash_char)) {
			name_string++;
			length--;
		}
	}
	/* Then copy the rest of the string removing /./ & // */
	cdp = string;
	while (length > 0) {
		if (((length > 2) &&
		     (name_string[0] == (int) slash_char) &&
		     (name_string[1] == (int) period_char) &&
		     (name_string[2] == (int) slash_char)) ||
		    ((length == 2) &&
		     (name_string[0] == (int) slash_char) &&
		     (name_string[1] == (int) period_char))) {
			name_string += 2;
			length -= 2;
			continue;
		}
		if ((length > 1) &&
		    (name_string[0] == (int) slash_char) &&
		    (name_string[1] == (int) slash_char)) {
			name_string++;
			length--;
			continue;
		}
		*cdp++ = *name_string++;
		length--;
	}
	*cdp = (int) nul_char;
	/*
	 * Now scan for <name>/../ and remove such combinations iff <name>
	 * is not another ..
	 * Each time something is removed, the whole process is restarted.
	 */
removed_one:
	name_string = string;
	string2 = name_string;		/*save for free*/
	current_component =
	  cdp =
	    string =
	      ALLOC_WC((length = wcslen(name_string)) + 1);
	while (length > 0) {
		if (((length > 3) &&
		     (name_string[0] == (int) slash_char) &&
		     (name_string[1] == (int) period_char) &&
		     (name_string[2] == (int) period_char) &&
		     (name_string[3] == (int) slash_char)) ||
		    ((length == 3) &&
		     (name_string[0] == (int) slash_char) &&
		     (name_string[1] == (int) period_char) &&
		     (name_string[2] == (int) period_char))) {
			/* Positioned on the / that starts a /.. sequence */
			if (((count = cdp - current_component) != 0) &&
			    (exists(name = GETNAME(string, cdp - string)) > file_doesnt_exist) &&
			    (!name->stat.is_sym_link)) {
				name = GETNAME(current_component, count);
				if(name != dotdot) {
					cdp = current_component;
					name_string += 3;
					length -= 3;
					if (length > 0) {
						name_string++;	/* skip slash */
						length--;
						while (length > 0) {
							*cdp++ = *name_string++;
							length--;
						}
					}
					*cdp = (int) nul_char;
					retmem(string2);
					goto removed_one;
				}
			}
		}
		if ((*cdp++ = *name_string++) == (int) slash_char) {
			current_component = cdp;
		}
		length--;
	}
	*cdp = (int) nul_char;
	if (string[0] == (int) nul_char) {
		name = dot;
	} else {
		name = GETNAME(string, FIND_LENGTH);
	}
	retmem(string);
	retmem(string2);
	return name;
}

/*
 *	find_target_groups(target_list)
 *
 *	If a "+" was seen when the target list was scanned we need to extract
 *	the groups. Each target in the name vector that is a member of a
 *	group gets a pointer to a chain of all the members stuffed in its
 *	target_group vector slot
 *
 *	Parameters:
 *		target_list	The list of targets that contains "+"
 *
 *	Global variables used:
 *		plus		The Name "+", compared against
 */
Chain
find_target_groups(register Name_vector target_list, register int i, Boolean reset)
{
	static Chain		target_group = NULL;
	static Chain		tail_target_group = NULL;
	static Name		*next;
	static Boolean	clear_target_group = false;

	if (reset) {
		target_group = NULL;
		tail_target_group = NULL;
		clear_target_group = false;
	}

	/* Scan the list of targets */
	/* If the previous target terminated a group */
	/* we flush the pointer to that member chain */
	if (clear_target_group) {
		clear_target_group = false;
		target_group = NULL;
	}
	/* Pick up a pointer to the cell with */
	/* the next target */
	if (i + 1 != target_list->used) {
		next = &target_list->names[i + 1];
	} else {
		next = (target_list->next != NULL) ?
		  &target_list->next->names[0] : NULL;
	}
	/* We have four states here :
	 *	0:	No target group started and next element is not "+" 
	 *		This is not interesting.
	 *	1:	A target group is being built and the next element 
	 *		is not "+". This terminates the group.
	 *	2:	No target group started and the next member is "+" 
	 *		This is the first target in a group.
	 *	3:	A target group started and the next member is a "+" 
	 *		The group continues.
	 */
	switch ((target_group ? 1 : 0) +
		(next && (*next == plus) ?
		 2 : 0)) {
	      case 0:	/* Not target_group */
		break;
	      case 1:	/* Last group member */
		/* We need to keep this pointer so */
		/* we can stuff it for last member */
		clear_target_group = true;
		/* fall into */
	      case 3:	/* Middle group member */
		/* Add this target to the */
		/* current chain */
		tail_target_group->next = ALLOC(Chain);
		tail_target_group = tail_target_group->next;
		tail_target_group->next = NULL;
		tail_target_group->name = target_list->names[i];
		break;
	      case 2:	/* First group member */
		/* Start a new chain */
		target_group = tail_target_group = ALLOC(Chain);
		target_group->next = NULL;
		target_group->name = target_list->names[i];
		break;
	}
	/* Stuff the current chain, if any, in the */
	/* targets group slot */
	target_list->target_group[i] = target_group;
	if ((next != NULL) &&
	    (*next == plus)) {
		*next = NULL;
	}
	return (tail_target_group);
}

/*
 *	enter_dependencies(target, target_group, depes, command, separator)
 *
 *	Take one target and a list of dependencies and process the whole thing.
 *	The target might be special in some sense in which case that is handled
 *
 *	Parameters:
 *		target		The target we want to enter
 *		target_group	Non-NULL if target is part of a group this time
 *		depes		A list of dependencies for the target
 *		command		The command the target should be entered with
 *		separator	Indicates if this is a ":" or a "::" rule
 *
 *	Static variables used:
 *		built_last_make_run_seen If the previous target was
 *					.BUILT_LAST_MAKE_RUN we say to rewrite
 *					the state file later on
 *
 *	Global variables used:
 *		command_changed	Set to indicate if .make.state needs rewriting
 *		default_target_to_build Set to the target if reading makefile
 *					and this is the first regular target
 *		force		The Name " FORCE", used with "::" targets
 *		makefile_type	We do different things for makefile vs. report
 *		not_auto	The Name ".NOT_AUTO", compared against
 *		recursive_name	The Name ".RECURSIVE", compared against
 *		temp_file_number Used to figure out when to clear stale
 *					automatic dependencies
 *		trace_reader	Indicates that we should echo stuff we read
 */
void
enter_dependencies(register Name target, Chain target_group, register Name_vector depes, register Cmd_line command, register Separator separator)
{
	register int		i;
	register Property	line;
	Name			name;
	Name			directory;
	wchar_t			*namep;
	char			*mb_namep;
	Dependency		dp;
	Dependency		*dpp;
	Property		line2;
	wchar_t			relative[MAXPATHLEN];
	register int		recursive_state;
	Boolean			register_as_auto;
	Boolean			not_auto_found;
	char			*slash;
	Wstring			depstr;

	/* Check if this is a .RECURSIVE line */
	if ((depes->used >= 3) &&
	    (depes->names[0] == recursive_name)) {
		target->has_recursive_dependency = true;
		depes->names[0] = NULL;
		recursive_state = 0;
		dp = NULL;
		dpp = &dp;
		/* Read the dependencies. They are "<directory> <target-made>*/
		/* <makefile>*" */
		for (; depes != NULL; depes = depes->next) {
			for (i = 0; i < depes->used; i++) {
				if (depes->names[i] != NULL) {
					switch (recursive_state++) {
					case 0:	/* Directory */
					{
						depstr.init(depes->names[i]);
						make_relative(depstr.get_string(),
							      relative);
						directory =
						  GETNAME(relative,
							  FIND_LENGTH);
					}
						break;
					case 1:	/* Target */
						name = depes->names[i];
						break;
					default:	/* Makefiles */
						*dpp = ALLOC(Dependency);
						(*dpp)->next = NULL;
						(*dpp)->name = depes->names[i];
						(*dpp)->automatic = false;
						(*dpp)->stale = false;
						(*dpp)->built = false;
						dpp = &((*dpp)->next);
						break;
					}
				}
			}
		}
		/* Check if this recursion already has been reported else */
		/* enter the recursive prop for the target */
		/* The has_built flag is used to tell if this .RECURSIVE */
		/* was discovered from this run (read from a tmp file) */
		/* or was from discovered from the original .make.state */
		/* file */
		for (line = get_prop(target->prop, recursive_prop);
		     line != NULL;
		     line = get_prop(line->next, recursive_prop)) {
			if ((line->body.recursive.directory == directory) &&
			    (line->body.recursive.target == name)) {
				line->body.recursive.makefiles = dp;
				line->body.recursive.has_built = 
				  (Boolean)
				    (makefile_type == reading_cpp_file);
				return;
			}
		}
		line2 = append_prop(target, recursive_prop);
		line2->body.recursive.directory = directory;
		line2->body.recursive.target = name;
		line2->body.recursive.makefiles = dp;
		line2->body.recursive.has_built = 
		    (Boolean) (makefile_type == reading_cpp_file);
		line2->body.recursive.in_depinfo = false;
		return;
	}
	/* If this is the first target that doesnt start with a "." in the */
	/* makefile we remember that */
	Wstring tstr(target);
	wchar_t * wcb = tstr.get_string();
	if ((makefile_type == reading_makefile) &&
	    (default_target_to_build == NULL) &&
	    ((wcb[0] != (int) period_char) ||
	     wcschr(wcb, (int) slash_char))) {

/* BID 1181577: $(EMPTY_MACRO) + $(EMPTY_MACRO):
** The target with empty name cannot be default_target_to_build
*/
		if (target->hash.length != 0)
			default_target_to_build = target;
	}
	/* Check if the line is ":" or "::" */
	if (makefile_type == reading_makefile) {
		if (target->colons == no_colon) {
			target->colons = separator;
		} else {
			if (target->colons != separator) {
				fatal_reader(gettext(":/:: conflict for target `%s'"),
					     target->string_mb);
			}
		}
		if (target->colons == two_colon) {
			if (depes->used == 0) {
				/* If this is a "::" type line with no */
				/* dependencies we add one "FRC" type */
				/* dependency for free */
				depes->used = 1; /* Force :: targets with no
						  * depes to always run */
				depes->names[0] = force;
			}
			/* Do not delete "::" type targets when interrupted */
			target->stat.is_precious = true;
			/*
			 * Build a synthetic target "<number>%target"
			 * for "target".
			 */
			mb_namep = getmem((int) (strlen(target->string_mb) + 10));
			namep = ALLOC_WC((int) (target->hash.length + 10));
			slash = strrchr(target->string_mb, (int) slash_char);
			if (slash == NULL) {
				(void) sprintf(mb_namep,
					        "%d@%s",
					        target->colon_splits++,
					        target->string_mb);
			} else {
				*slash = 0;
				(void) sprintf(mb_namep,
					        "%s/%d@%s",
					        target->string_mb,
					        target->colon_splits++,
					        slash + 1);
				*slash = (int) slash_char;
			}
			MBSTOWCS(namep, mb_namep);
			retmem_mb(mb_namep);
			name = GETNAME(namep, FIND_LENGTH);
			retmem(namep);
			if (trace_reader) {
				(void) printf("%s:\t", target->string_mb);
			}
			/* Make "target" depend on "<number>%target */
			line2 = maybe_append_prop(target, line_prop);
			enter_dependency(line2, name, true);
			line2->body.line.target = target;
			/* Put a prop on "<number>%target that makes */
			/* appear as "target" */
			/* when it is processed */
			maybe_append_prop(name, target_prop)->
			  body.target.target = target;
			target->is_double_colon_parent = true;
			name->is_double_colon = true;
			name->has_target_prop = true;
			if (trace_reader) {
				(void) printf("\n");
			}
			(target = name)->stat.is_file = true;
		}
	}
	/* This really is a regular dependency line. Just enter it */
	line = maybe_append_prop(target, line_prop);
	line->body.line.target = target;
	/* Depending on what kind of makefile we are reading we have to */
	/* treat things differently */
	switch (makefile_type) {
	case reading_makefile:
		/* Reading regular makefile. Just notice whether this */
		/* redefines the rule for the  target */
		if (command != NULL) {
			if (line->body.line.command_template != NULL) {
				line->body.line.command_template_redefined =
				  true;
				if ((wcb[0] == (int) period_char) &&
				    !wcschr(wcb, (int) slash_char)) {
					line->body.line.command_template =
					  command;
				}
			} else {
				line->body.line.command_template = command;
			}
		} else {
			if ((wcb[0] == (int) period_char) &&
			    !wcschr(wcb, (int) slash_char)) {
				line->body.line.command_template = command;
			}
		}
		break;
	case rereading_statefile:
		/* Rereading the statefile. We only enter thing that changed */
		/* since the previous time we read it */
		if (!built_last_make_run_seen) {
			for (Cmd_line next, cmd = command; cmd != NULL; cmd = next) {
				next = cmd->next;
				free(cmd);
			}
			return;
		}
		built_last_make_run_seen = false;
		command_changed = true;
		target->ran_command = true;
	case reading_statefile:
		/* Reading the statefile for the first time. Enter the rules */
		/* as "Commands used" not "templates to use" */
		if (command != NULL) {
			for (Cmd_line next, cmd = line->body.line.command_used;
			     cmd != NULL; cmd = next) {
				next = cmd->next;
				free(cmd);
			}
			line->body.line.command_used = command;
		}
	case reading_cpp_file:
		/* Reading report file from programs that reports */
		/* dependencies. If this is the first time the target is */
		/* read from this reportfile we clear all old */
		/* automatic depes */
		if (target->temp_file_number == temp_file_number) {
			break;
		}
		target->temp_file_number = temp_file_number;
		command_changed = true;
		if (line != NULL) {
			for (dp = line->body.line.dependencies;
			     dp != NULL;
			     dp = dp->next) {
				if (dp->automatic) {
					dp->stale = true;
				}
			}
		}
		break;
	default:
		fatal_reader(gettext("Internal error. Unknown makefile type %d"),
			     makefile_type);
	}
	/* A target may only be involved in one target group */
	if (line->body.line.target_group != NULL) {
		if (target_group != NULL) {
			fatal_reader(gettext("Too many target groups for target `%s'"),
				     target->string_mb);
		}
	} else {
		line->body.line.target_group = target_group;
	}

	if (trace_reader) {
		(void) printf("%s:\t", target->string_mb);
	}
	/* Enter the dependencies */
	register_as_auto = BOOLEAN(makefile_type != reading_makefile);
	not_auto_found = false;
	for (;
	     (depes != NULL) && !not_auto_found;
	     depes = depes->next) {
		for (i = 0; i < depes->used; i++) {
			/* the dependency .NOT_AUTO signals beginning of
			 * explicit dependancies which were put at end of
			 * list in .make.state file - we stop entering
			 * dependencies at this point
			 */
			if (depes->names[i] == not_auto) {
				not_auto_found = true;
				break;
			}
			enter_dependency(line,
					 depes->names[i],
					 register_as_auto);
		}
	}
	if (trace_reader) {
		(void) printf("\n");
		print_rule(command);
	}
}

/*
 *	enter_dependency(line, depe, automatic)
 *
 *	Enter one dependency. Do not enter duplicates.
 *
 *	Parameters:
 *		line		The line block that the dependeny is
 *				entered for
 *		depe		The dependency to enter
 *		automatic	Used to set the field "automatic"
 *
 *	Global variables used:
 *		makefile_type	We do different things for makefile vs. report
 *		trace_reader	Indicates that we should echo stuff we read
 *		wait_name	The Name ".WAIT", compared against
 */
void
enter_dependency(Property line, register Name depe, Boolean automatic)
{
	register Dependency	dp;
	register Dependency	*insert;

	if (trace_reader) {
		(void) printf("%s ", depe->string_mb);
	}
	/* Find the end of the list and check for duplicates */
	for (insert = &line->body.line.dependencies, dp = *insert;
	     dp != NULL;
	     insert = &dp->next, dp = *insert) {
		if ((dp->name == depe) && (depe != wait_name)) {
			if (dp->automatic) {
				dp->automatic = automatic;
				if (automatic) {
					dp->built = false;
					depe->stat.is_file = true;
				}
			}
			dp->stale = false;
			return;
		}
	}
	/* Insert the new dependency since we couldnt find it */
	dp = *insert = ALLOC(Dependency);
	dp->name = depe;
	dp->next = NULL;
	dp->automatic = automatic;
	dp->stale = false;
	dp->built = false;
	depe->stat.is_file = true;

	if ((makefile_type == reading_makefile) &&
	    (line != NULL) &&
	    (line->body.line.target != NULL)) {
		line->body.line.target->has_regular_dependency = true;
	}
}

/*
 *	enter_percent(target, depes, command)
 *
 *	Enter "x%y : a%b" type lines
 *	% patterns are stored in four parts head and tail for target and source
 *
 *	Parameters:
 *		target		Left hand side of pattern
 *		depes		The dependency list with the rh pattern
 *		command		The command for the pattern
 *
 *	Global variables used:
 *		empty_name	The Name "", compared against
 *		percent_list	The list of all percent rules, added to
 *		trace_reader	Indicates that we should echo stuff we read
 */
Percent
enter_percent(register Name target, Chain target_group, register Name_vector depes, Cmd_line command)
{
	register Percent	result = ALLOC(Percent);
	register Percent	depe;
	register Percent	*depe_tail = &result->dependencies;
	register Percent	*insert;
	register wchar_t	*cp, *cp1;
	Name_vector		nvp;
	int			i;
	int			pattern;

	result->next = NULL;
	result->patterns = NULL;
	result->patterns_total = 0;
	result->command_template = command;
	result->being_expanded = false;
	result->name = target;
	result->dependencies = NULL;
	result->target_group = target_group;

	/* get patterns count */
	Wstring wcb(target);
	cp = wcb.get_string();
	while (true) {
		cp = (wchar_t *) wcschr(cp, (int) percent_char);
		if (cp != NULL) {
			result->patterns_total++;
			cp++;
		} else {
			break;
		}
	}
	result->patterns_total++;

	/* allocate storage for patterns */
	result->patterns = (Name *) getmem(sizeof(Name) * result->patterns_total);

	/* then create patterns */
	cp = wcb.get_string();
	pattern = 0;
	while (true) {
		cp1 = (wchar_t *) wcschr(cp, (int) percent_char);
		if (cp1 != NULL) {
			result->patterns[pattern] = GETNAME(cp, cp1 - cp);
			cp = cp1 + 1;
			pattern++;
		} else {
			result->patterns[pattern] = GETNAME(cp, (int) target->hash.length - (cp - wcb.get_string()));
			break;
		}
	}

	Wstring wcb1;

	/* build dependencies list */
	for (nvp = depes; nvp != NULL; nvp = nvp->next) {
		for (i = 0; i < nvp->used; i++) {
			depe = ALLOC(Percent);
			depe->next = NULL;
			depe->patterns = NULL;
			depe->patterns_total = 0;
			depe->name = nvp->names[i];
			depe->dependencies = NULL;
			depe->command_template = NULL;
			depe->being_expanded = false;
			depe->target_group = NULL;

			*depe_tail = depe;
			depe_tail = &depe->next;

			if (depe->name->percent) {
				/* get patterns count */
				wcb1.init(depe->name);
				cp = wcb1.get_string();
				while (true) {
					cp = (wchar_t *) wcschr(cp, (int) percent_char);
					if (cp != NULL) {
						depe->patterns_total++;
						cp++;
					} else {
						break;
					}
				}
				depe->patterns_total++;

				/* allocate storage for patterns */
				depe->patterns = (Name *) getmem(sizeof(Name) * depe->patterns_total);

				/* then create patterns */
				cp = wcb1.get_string();
				pattern = 0;
				while (true) {
					cp1 = (wchar_t *) wcschr(cp, (int) percent_char);
					if (cp1 != NULL) {
						depe->patterns[pattern] = GETNAME(cp, cp1 - cp);
						cp = cp1 + 1;
						pattern++;
					} else {
						depe->patterns[pattern] = GETNAME(cp, (int) depe->name->hash.length - (cp - wcb1.get_string()));
						break;
					}
				}
			}
		}
	}

	/* Find the end of the percent list and append the new pattern */
	for (insert = &percent_list; (*insert) != NULL; insert = &(*insert)->next);
	*insert = result;

	if (trace_reader) {
		(void) printf("%s:", result->name->string_mb);

		for (depe = result->dependencies; depe != NULL; depe = depe->next) {
			(void) printf(" %s", depe->name->string_mb);
		}

		(void) printf("\n");

		print_rule(command);
	}

	return result;
}

/*
 *	enter_dyntarget(target)
 *
 *	Enter "$$(MACRO) : b" type lines
 *
 *	Parameters:
 *		target		Left hand side of pattern
 *
 *	Global variables used:
 *		dyntarget_list	The list of all percent rules, added to
 *		trace_reader	Indicates that we should echo stuff we read
 */
Dyntarget
enter_dyntarget(register Name target)
{
	register Dyntarget	result = ALLOC(Dyntarget);
	Dyntarget		p;
	Dyntarget		*insert;
	int				i;

	result->next = NULL;
	result->name = target;


	/* Find the end of the dyntarget list and append the new pattern */
	for (insert = &dyntarget_list, p = *insert;
	     p != NULL;
	     insert = &p->next, p = *insert);
	*insert = result;

	if (trace_reader) {
		(void) printf("Dynamic target %s:\n", result->name->string_mb);
	}
	return( result);
}


/*
 *	special_reader(target, depes, command)
 *
 *	Read the pseudo targets make knows about
 *	This handles the special targets that should not be entered as regular
 *	target/dependency sets.
 *
 *	Parameters:
 *		target		The special target
 *		depes		The list of dependencies it was entered with
 *		command		The command it was entered with
 *
 *	Static variables used:
 *		built_last_make_run_seen Set to indicate .BUILT_LAST... seen
 *
 *	Global variables used:
 *		all_parallel	Set to indicate that everything runs parallel
 *		svr4 		Set when ".SVR4" target is read
 *		svr4_name	The Name ".SVR4"
 *		posix 		Set when ".POSIX" target is read
 *		posix_name	The Name ".POSIX"
 *		current_make_version The Name "<current version number>"
 *		default_rule	Set when ".DEFAULT" target is read
 *		default_rule_name The Name ".DEFAULT", used for tracing
 *		dot_keep_state	The Name ".KEEP_STATE", used for tracing
 *		ignore_errors	Set if ".IGNORE" target is read
 *		ignore_name	The Name ".IGNORE", used for tracing
 *		keep_state	Set if ".KEEP_STATE" target is read
 *		no_parallel_name The Name ".NO_PARALLEL", used for tracing
 *		only_parallel	Set to indicate only some targets runs parallel
 *		parallel_name	The Name ".PARALLEL", used for tracing
 *		precious	The Name ".PRECIOUS", used for tracing
 *		sccs_get_name	The Name ".SCCS_GET", used for tracing
 *		sccs_get_posix_name The Name ".SCCS_GET_POSIX", used for tracing
 *		get_name	The Name ".GET", used for tracing
 *		sccs_get_rule	Set when ".SCCS_GET" target is read
 *		silent		Set when ".SILENT" target is read
 *		silent_name	The Name ".SILENT", used for tracing
 *		trace_reader	Indicates that we should echo stuff we read
 */
void
special_reader(Name target, register Name_vector depes, Cmd_line command)
{
	register int		n;

	switch (target->special_reader) {

	case svr4_special:
		if (depes->used != 0) {
			fatal_reader(gettext("Illegal dependencies for target `%s'"),
				     target->string_mb);
		}
		svr4  = true;
		posix  = false;
		keep_state = false;
		all_parallel = false;
		only_parallel = false;
		if (trace_reader) {
			(void) printf("%s:\n", svr4_name->string_mb);
		}
		break;

	case posix_special:
		if(svr4)
		  break;
		if (depes->used != 0) {
			fatal_reader(gettext("Illegal dependencies for target `%s'"),
				     target->string_mb);
		}
		posix  = true;
			/* with posix on, use the posix get rule */
		sccs_get_rule = sccs_get_posix_rule;
			/* turn keep state off being SunPro make specific */
		keep_state = false;
		/* Use /usr/xpg4/bin/sh on Solaris */
		MBSTOWCS(wcs_buffer, "/usr/xpg4/bin/sh");
		(void) SETVAR(shell_name, GETNAME(wcs_buffer, FIND_LENGTH), false);
		if (trace_reader) {
			(void) printf("%s:\n", posix_name->string_mb);
		}
		break;

	case built_last_make_run_special:
		built_last_make_run_seen = true;
		break;

	case default_special:
		if (depes->used != 0) {
			warning(gettext("Illegal dependency list for target `%s'"),
				target->string_mb);
		}
		default_rule = command;
		if (trace_reader) {
			(void) printf("%s:\n",
				      default_rule_name->string_mb);
			print_rule(command);
		}
		break;


	case ignore_special:
		if ((depes->used != 0) &&(!posix)){
			fatal_reader(gettext("Illegal dependencies for target `%s'"),
				     target->string_mb);
		}
		if (depes->used == 0)
		{
		   ignore_errors_all = true;
		}
		if(svr4) {
		  ignore_errors_all = true;
		  break;
		}
		for (; depes != NULL; depes = depes->next) {
			for (n = 0; n < depes->used; n++) {
				depes->names[n]->ignore_error_mode = true;
			}
		}
		if (trace_reader) {
			(void) printf("%s:\n", ignore_name->string_mb);
		}
		break;

	case keep_state_special:
		if(svr4)
		  break;
			/* ignore keep state, being SunPro make specific */
		if(posix)
		  break;
		if (depes->used != 0) {
			fatal_reader(gettext("Illegal dependencies for target `%s'"),
				     target->string_mb);
		}
		keep_state = true;
		if (trace_reader) {
			(void) printf("%s:\n",
				      dot_keep_state->string_mb);
		}
		break;

	case keep_state_file_special:
		if(svr4)
		  break;
		if(posix)
		  break;
			/* it's not necessary to specify KEEP_STATE, if this 
			** is given, so set the keep_state.
			*/
		keep_state = true;
		if (depes->used != 0) {
		   if((!make_state) ||(!strcmp(make_state->string_mb,".make.state"))) {
		     make_state = depes->names[0];
		   }
		}
		break;
	case make_version_special:
		if(svr4)
		  break;
		if (depes->used != 1) {
			fatal_reader(gettext("Illegal dependency list for target `%s'"),
				     target->string_mb);
		}
		if (depes->names[0] != current_make_version) {
			/*
			 * Special case the fact that version 1.0 and 1.1
			 * are identical.
			 */
			if (!IS_EQUAL(depes->names[0]->string_mb,
				      "VERSION-1.1") ||
			    !IS_EQUAL(current_make_version->string_mb,
				      "VERSION-1.0")) {
				/*
				 * Version mismatches should cause the
				 * .make.state file to be skipped.
				 * This is currently not true - it is read
				 * anyway.
				 */
				warning(gettext("Version mismatch between current version `%s' and `%s'"),
					current_make_version->string_mb,
					depes->names[0]->string_mb);
			}
		}
		break;

	case no_parallel_special:
		if(svr4)
		  break;
		/* Set the no_parallel bit for all the targets on */
		/* the dependency list */
		if (depes->used == 0) {
			/* only those explicitly made parallel */
			only_parallel = true;
			all_parallel = false;
		}
		for (; depes != NULL; depes = depes->next) {
			for (n = 0; n < depes->used; n++) {
				if (trace_reader) {
					(void) printf("%s:\t%s\n",
						      no_parallel_name->string_mb,
						      depes->names[n]->string_mb);
				}
				depes->names[n]->no_parallel = true;
				depes->names[n]->parallel = false;
			}
		}
		break;

	case parallel_special:
		if(svr4)
		  break;
		if (depes->used == 0) {
			/* everything runs in parallel */
			all_parallel = true;
			only_parallel = false;
		}
		/* Set the parallel bit for all the targets on */
		/* the dependency list */
		for (; depes != NULL; depes = depes->next) {
			for (n = 0; n < depes->used; n++) {
				if (trace_reader) {
					(void) printf("%s:\t%s\n",
						      parallel_name->string_mb,
						      depes->names[n]->string_mb);
				}
				depes->names[n]->parallel = true;
				depes->names[n]->no_parallel = false;
			}
		}
		break;

	case localhost_special:
		if(svr4)
		  break;
		/* Set the no_parallel bit for all the targets on */
		/* the dependency list */
		if (depes->used == 0) {
			/* only those explicitly made parallel */
			only_parallel = true;
			all_parallel = false;
		}
		for (; depes != NULL; depes = depes->next) {
			for (n = 0; n < depes->used; n++) {
				if (trace_reader) {
					(void) printf("%s:\t%s\n",
						      localhost_name->string_mb,
						      depes->names[n]->string_mb);
				}
				depes->names[n]->no_parallel = true;
				depes->names[n]->parallel = false;
				depes->names[n]->localhost = true;
			}
		}
		break;

	case precious_special:
		if (depes->used == 0) {
			/* everything is precious      */
			all_precious = true;
		} else {
			all_precious = false;
		}
		if(svr4) {
		  all_precious = true;
		  break;
		}
		/* Set the precious bit for all the targets on */
		/* the dependency list */
		for (; depes != NULL; depes = depes->next) {
			for (n = 0; n < depes->used; n++) {
				if (trace_reader) {
					(void) printf("%s:\t%s\n",
						      precious->string_mb,
						      depes->names[n]->string_mb);
				}
				depes->names[n]->stat.is_precious = true;
			}
		}
		break;

	case sccs_get_special:
		if (depes->used != 0) {
			fatal_reader(gettext("Illegal dependencies for target `%s'"),
				     target->string_mb);
		}
		sccs_get_rule = command;
		sccs_get_org_rule = command;
		if (trace_reader) {
			(void) printf("%s:\n", sccs_get_name->string_mb);
			print_rule(command);
		}
		break;

	case sccs_get_posix_special:
		if (depes->used != 0) {
			fatal_reader(gettext("Illegal dependencies for target `%s'"),
				     target->string_mb);
		}
		sccs_get_posix_rule = command;
		if (trace_reader) {
			(void) printf("%s:\n", sccs_get_posix_name->string_mb);
			print_rule(command);
		}
		break;

	case get_posix_special:
		if (depes->used != 0) {
			fatal_reader(gettext("Illegal dependencies for target `%s'"),
				     target->string_mb);
		}
		get_posix_rule = command;
		if (trace_reader) {
			(void) printf("%s:\n", get_posix_name->string_mb);
			print_rule(command);
		}
		break;

	case get_special:
		if(!svr4) {
		  break;
		}
		if (depes->used != 0) {
			fatal_reader(gettext("Illegal dependencies for target `%s'"),
				     target->string_mb);
		}
		get_rule = command;
		sccs_get_rule = command;
		if (trace_reader) {
			(void) printf("%s:\n", get_name->string_mb);
			print_rule(command);
		}
		break;

	case silent_special:
		if ((depes->used != 0) && (!posix)){
			fatal_reader(gettext("Illegal dependencies for target `%s'"),
				     target->string_mb);
		}
		if (depes->used == 0)
		{
		   silent_all = true;
		}
		if(svr4) {
		  silent_all = true;
		  break;
		}
		for (; depes != NULL; depes = depes->next) {
			for (n = 0; n < depes->used; n++) {
				depes->names[n]->silent_mode = true;
			}
		}
		if (trace_reader) {
			(void) printf("%s:\n", silent_name->string_mb);
		}
		break;

	case suffixes_special:
		read_suffixes_list(depes);
		break;

	default:

		fatal_reader(gettext("Internal error: Unknown special reader"));
	}
}

/*
 *	read_suffixes_list(depes)
 *
 *	Read the special list .SUFFIXES. If it is empty the old list is
 *	cleared. Else the new one is appended. Suffixes with ~ are extracted
 *	and marked.
 *
 *	Parameters:
 *		depes		The list of suffixes
 *
 *	Global variables used:
 *		hashtab		The central hashtable for Names.
 *		suffixes	The list of suffixes, set or appended to
 *		suffixes_name	The Name ".SUFFIXES", used for tracing
 *		trace_reader	Indicates that we should echo stuff we read
 */
static void
read_suffixes_list(register Name_vector depes)
{
	register int		n;
	register Dependency	dp;
	register Dependency	*insert_dep;
	register Name		np;
	Name			np2;
	register Boolean	first = true;

	if (depes->used == 0) {
		/* .SUFFIXES with no dependency list clears the */
		/* suffixes list */
		for (Name_set::iterator np = hashtab.begin(), e = hashtab.end(); np != e; np++) {
				np->with_squiggle =
				  np->without_squiggle =
				    false;
		}
		suffixes = NULL;
		if (trace_reader) {
			(void) printf("%s:\n", suffixes_name->string_mb);
		}
		return;
	}
	Wstring str;
	/* Otherwise we append to the list */
	for (; depes != NULL; depes = depes->next) {
		for (n = 0; n < depes->used; n++) {
			np = depes->names[n];
			/* Find the end of the list and check if the */
			/* suffix already has been entered */
			for (insert_dep = &suffixes, dp = *insert_dep;
			     dp != NULL;
			     insert_dep = &dp->next, dp = *insert_dep) {
				if (dp->name == np) {
					goto duplicate_suffix;
				}
			}
			if (trace_reader) {
				if (first) {
					(void) printf("%s:\t",
						      suffixes_name->string_mb);
					first = false;
				}
				(void) printf("%s ", depes->names[n]->string_mb);
			}
		if(!(posix|svr4)) {
			/* If the suffix is suffixed with "~" we */
			/* strip that and mark the suffix nameblock */
			str.init(np);
			wchar_t * wcb = str.get_string();
			if (wcb[np->hash.length - 1] ==
			    (int) tilde_char) {
				np2 = GETNAME(wcb,
					      (int)(np->hash.length - 1));
				np2->with_squiggle = true;
				if (np2->without_squiggle) {
					continue;
				}
				np = np2;
			}
		}
			np->without_squiggle = true;
			/* Add the suffix to the list */
			dp = *insert_dep = ALLOC(Dependency);
			insert_dep = &dp->next;
			dp->next = NULL;
			dp->name = np;
			dp->built = false;
		duplicate_suffix:;
		}
	}
	if (trace_reader) {
		(void) printf("\n");
	}
}

/*
 *	make_relative(to, result)
 *
 *	Given a file name compose a relative path name from it to the
 *	current directory.
 *
 *	Parameters:
 *		to		The path we want to make relative
 *		result		Where to put the resulting relative path
 *
 *	Global variables used:
 */
static void
make_relative(wchar_t *to, wchar_t *result)
{
	wchar_t			*from;
	wchar_t			*allocated;
	wchar_t			*cp;
	wchar_t			*tocomp;
	int			ncomps;
	int			i;
	int			len;

	/* Check if the path is already relative. */
	if (to[0] != (int) slash_char) {
		(void) wcscpy(result, to);
		return;
	}

	MBSTOWCS(wcs_buffer, get_current_path());
	from = allocated = (wchar_t *) wcsdup(wcs_buffer);

	/*
	 * Find the number of components in the from name.
	 * ncomp = number of slashes + 1.
	 */
	ncomps = 1;
	for (cp = from; *cp != (int) nul_char; cp++) {
		if (*cp == (int) slash_char) {
			ncomps++;
		}
	}

	/*
	 * See how many components match to determine how many "..",
	 * if any, will be needed.
	 */
	result[0] = (int) nul_char;
	tocomp = to;
	while ((*from != (int) nul_char) && (*from == *to)) {
		if (*from == (int) slash_char) {
			ncomps--;
			tocomp = &to[1];
		}
		from++;
		to++;
	}

	/*
	 * Now for some special cases. Check for exact matches and
	 * for either name terminating exactly.
	 */
	if (*from == (int) nul_char) {
		if (*to == (int) nul_char) {
			MBSTOWCS(wcs_buffer, ".");
			(void) wcscpy(result, wcs_buffer);
			retmem(allocated);
			return;
		}
		if (*to == (int) slash_char) {
			ncomps--;
			tocomp = &to[1];
		}
	} else if ((*from == (int) slash_char) && (*to == (int) nul_char)) {
		ncomps--;
		tocomp = to;
	}
	/* Add on the ".."s. */
	for (i = 0; i < ncomps; i++) {
		MBSTOWCS(wcs_buffer, "../");
		(void) wcscat(result, wcs_buffer);
	}

	/* Add on the remainder of the to name, if any. */
	if (*tocomp == (int) nul_char) {
		len = wcslen(result);
		result[len - 1] = (int) nul_char;
	} else {
		(void) wcscat(result, tocomp);
	}
	retmem(allocated);
	return;
}

/*
 *	print_rule(command)
 *
 *	Used when tracing the reading of rules
 *
 *	Parameters:
 *		command		Command to print
 *
 *	Global variables used:
 */
static void
print_rule(register Cmd_line command)
{
	for (; command != NULL; command = command->next) {
		(void) printf("\t%s\n", command->command_line->string_mb);
	}
}

/*
 *	enter_conditional(target, name, value, append)
 *
 *	Enter "target := MACRO= value" constructs
 *
 *	Parameters:
 *		target		The target the macro is for
 *		name		The name of the macro
 *		value		The value for the macro
 *		append		Indicates if the assignment is appending or not
 *
 *	Global variables used:
 *		conditionals	A special Name that stores all conditionals
 *				where the target is a % pattern
 *		trace_reader	Indicates that we should echo stuff we read
 */
void
enter_conditional(register Name target, Name name, Name value, register Boolean append)
{
	register Property	conditional;
	static int		sequence;
	Name			orig_target = target;

	if (name == target_arch) {
		enter_conditional(target, virtual_root, virtual_root, false);
	}

	if (target->percent) {
		target = conditionals;
	}
	
	if (name->colon) {
		sh_transform(&name, &value);
	}

	/* Count how many conditionals we must activate before building the */
	/* target */
	if (target->percent) {
		target = conditionals;
	}

	target->conditional_cnt++;
	maybe_append_prop(name, macro_prop)->body.macro.is_conditional = true;
	/* Add the property for the target */
	conditional = append_prop(target, conditional_prop);
	conditional->body.conditional.target = orig_target;
	conditional->body.conditional.name = name;
	conditional->body.conditional.value = value;
	conditional->body.conditional.sequence = sequence++;
	conditional->body.conditional.append = append;
	if (trace_reader) {
		if (value == NULL) {
			(void) printf("%s := %s %c=\n",
				      target->string_mb,
				      name->string_mb,
				      append ?
				      (int) plus_char : (int) space_char);
		} else {
			(void) printf("%s := %s %c= %s\n",
				      target->string_mb,
				      name->string_mb,
				      append ?
				      (int) plus_char : (int) space_char,
				      value->string_mb);
		}
	}
}

/*
 *	enter_equal(name, value, append)
 *
 *	Enter "MACRO= value" constructs
 *
 *	Parameters:
 *		name		The name of the macro
 *		value		The value for the macro
 *		append		Indicates if the assignment is appending or not
 *
 *	Global variables used:
 *		trace_reader	Indicates that we should echo stuff we read
 */
void
enter_equal(Name name, Name value, register Boolean append)
{
	wchar_t		*string;
	Name		temp;

	if (name->colon) {
		sh_transform(&name, &value);
	}
	(void) SETVAR(name, value, append);

	/* if we're setting FC, we want to set F77 to the same value. */
	Wstring nms(name);
	wchar_t * wcb = nms.get_string();
	string = wcb;
	if (string[0]=='F' &&
	    string[1]=='C' &&
	    string[2]=='\0') {
		MBSTOWCS(wcs_buffer, "F77");
		temp = GETNAME(wcs_buffer, FIND_LENGTH);
		(void) SETVAR(temp, value, append);
/*
		fprintf(stderr, gettext("warning: FC is obsolete, use F77 instead\n"));
 */
	}

	if (trace_reader) {
		if (value == NULL) {
			(void) printf("%s %c=\n",
				      name->string_mb,
				      append ?
				      (int) plus_char : (int) space_char);
		} else {
			(void) printf("%s %c= %s\n",
				      name->string_mb,
				      append ?
				      (int) plus_char : (int) space_char,
				      value->string_mb);
		}
	}
}

/*
 *	sh_transform(name, value)
 *
 *	Parameters:
 *		name	The name of the macro we might transform
 *		value	The value to transform
 *
 */
static void
sh_transform(Name *name, Name *value)
{
	/* Check if we need :sh transform */
	wchar_t		*colon;
	String_rec	command;
	String_rec	destination;
	wchar_t		buffer[1000];
	wchar_t		buffer1[1000];

	static wchar_t	colon_sh[4];
	static wchar_t	colon_shell[7];

	if (colon_sh[0] == (int) nul_char) {
		MBSTOWCS(colon_sh, ":sh");
		MBSTOWCS(colon_shell, ":shell");
	}
	Wstring nms((*name));
	wchar_t * wcb = nms.get_string();

	colon = (wchar_t *) wcsrchr(wcb, (int) colon_char);
	if ((colon != NULL) && (IS_WEQUAL(colon, colon_sh) || IS_WEQUAL(colon, colon_shell))) {
		INIT_STRING_FROM_STACK(destination, buffer);

		if(*value == NULL) {
			buffer[0] = 0;
		} else {
			Wstring wcb1((*value));
			if (IS_WEQUAL(colon, colon_shell)) {
				INIT_STRING_FROM_STACK(command, buffer1);
				expand_value(*value, &command, false);
			} else {
				command.text.p = wcb1.get_string() + (*value)->hash.length;
				command.text.end = command.text.p;
				command.buffer.start = wcb1.get_string();
				command.buffer.end = command.text.p;
			}
			sh_command2string(&command, &destination);
		}

		(*value) = GETNAME(destination.buffer.start, FIND_LENGTH);
		*colon = (int) nul_char;
		(*name) = GETNAME(wcb, FIND_LENGTH);
		*colon = (int) colon_char;
	}
}

/*
 *	fatal_reader(format, args...)
 *
 *	Parameters:
 *		format		printf style format string
 *		args		arguments to match the format
 *
 *	Global variables used:
 *		file_being_read	Name of the makefile being read
 *		line_number	Line that is being read
 *		report_pwd	Indicates whether current path should be shown
 *		temp_file_name	When reading tempfile we report that name
 */
/*VARARGS*/
void
fatal_reader(char * pattern, ...)
{
	va_list args;
	char	message[1000];

	va_start(args, pattern);
	if (file_being_read != NULL) {
		WCSTOMBS(mbs_buffer, file_being_read);
		if (line_number != 0) {
			(void) sprintf(message,
				       gettext("%s, line %d: %s"),
				       mbs_buffer,
				       line_number,
				       pattern);
		} else {
			(void) sprintf(message,
				       "%s: %s",
				       mbs_buffer,
				       pattern);
		}
		pattern = message;
	}

	(void) fflush(stdout);
	(void) fprintf(stderr, gettext("%s: Fatal error in reader: "),
	    getprogname());
	(void) vfprintf(stderr, pattern, args);
	(void) fprintf(stderr, "\n");
	va_end(args);

	if (temp_file_name != NULL) {
		(void) fprintf(stderr,
			       gettext("%s: Temp-file %s not removed\n"),
			       getprogname(),
			       temp_file_name->string_mb);
		temp_file_name = NULL;
	}

	if (report_pwd) {
		(void) fprintf(stderr,
			       gettext("Current working directory %s\n"),
			       get_current_path());
	}
	(void) fflush(stderr);
	exit_status = 1;
	exit(1);
}

