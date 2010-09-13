/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	ticparse.c		
 *
 *	Terminal Information Compiler
 *
 *	Copyright 1990, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 *	Portions of this code Copyright 1982 by Pavel Curtis.
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/tic/rcs/ticparse.c 1.22 1995/06/27 14:56:46 ant Exp $";
#endif
#endif

#include "tic.h"
#include <ctype.h>
#include <sys/stat.h>
#include <errno.h>

extern int get_token ANSI((void));	/* from ticscan.c */

char *string_table;
int next_free;		/* next free character in string_table */
int table_size = 0; 	/* current string_table size */
int term_names;		/* string table offset - current terminal */
int part2 = 0;		/* set to allow old compiled defns to be used */
int complete = 0;	/* 1 if entry done with no forward uses */

struct use_item {
	long	offset;
	struct use_item	*fptr, *bptr;
};

struct use_header {
	struct use_item	*head, *tail;
};

struct use_header	use_list = {NULL, NULL};
int			use_count = 0;

/*
 *  The use_list is a doubly-linked list with NULLs terminating the lists:
 *
 *	   use_item    use_item    use_item
 *	  ---------   ---------   ---------
 *	  |       |   |       |   |       |   offset
 *        |-------|   |-------|   |-------|
 *	  |   ----+-->|   ----+-->|  NULL |   fptr
 *	  |-------|   |-------|   |-------|
 *	  |  NULL |<--+----   |<--+----   |   bptr
 *	  ---------   ---------   ---------
 *	  ^                       ^
 *	  |  ------------------   |
 *	  |  |       |        |   |
 *	  +--+----   |    ----+---+
 *	     |       |        |
 *	     ------------------
 *	       head     tail
 *	          use_list
 *
 */

char bad_start[] = m_textstr(
	3107, "File does not start with terminal names in column one", "E"
);
char not_names[] = m_textstr(3108, "Token after a seek not NAMES", "E");
char use_links[] = m_textstr(3109, "\
\n\
Error in following up use-links.  Either there is\n\
a loop in the links or they reference non-existant\n\
terminals.  The following is a list of the entries\n\
involved:\n\n\
", "E");
char nomem_use_list[] = m_textstr(
	3110, "Not enough memory for use_list element", "E"
);
char long_path[] = m_textstr(3111, "Pathname \"%c/%s\" too long.", "W char term");
char more_than_one[] = m_textstr(
	3112, "More than one entry defined for \"%s\".\n","W term"
);
char fail_open[] = m_textstr(3113, "Failed to open \"%s\".\n", "E filename");
char write_err[] = m_textstr(3114, "Error in writing \"%s\".\n", "E filename");
char synonym[] = m_textstr(3115, "Terminal \"%s\" is a synonym for itself.\n", "W term");
char fail_link[] = m_textstr(3116, "Failed to link \"%s\" to \"%s\".\n", "E file1 file2");
char name_check[] = m_textstr(3117, "\
compile: Line %d: Illegal terminal name - '%s'\n\
Terminal names must start with lowercase or digit.\n\
", "E line_num term");
char nomem[] = m_textstr(3118, "Failed to allocated memory.\n", "E");
char unknown_term[] = m_textstr(202, "Unknown terminal \"%s\".\n", "E term"); 
char no_terminfo[] = m_textstr(203, "No terminfo database.\n", "E"); 
char unknown_cap[] = m_textstr(3119, "Unknown capability '%s'.", "E action");
char unknown_token[] = m_textstr(3120, "Unknown token type.", "W");
char wrong_type[] = m_textstr(3121, "Wrong type used for capability \"%s\".", "W type");


/*f
 * debugging routine to dump list
 */
STATIC int
dump_list(str)
char *str;
{
	struct use_item *ptr;
	char line[512];

	fprintf(stderr, "dump_list %s\n", str);
	for (ptr = use_list.head; ptr != NULL; ptr = ptr->fptr)
	{
		fseek(stdin, ptr->offset, 0);
		fgets(line, 1024, stdin);
		fprintf(stderr, "ptr %x off %d bptr %x fptr %x str %s",
		ptr, ptr->offset, ptr->bptr, ptr->fptr, line);
	}
	fprintf(stderr, "\n");
}


/*f
 *	Generate an error message if given name does not begin with a
 *	digit or lower-case letter.
 */
STATIC int
check_name(name)
char	*name;
{
	if (!isdigit(name[0]) && !isalpha(name[0])) {
		fprintf(stderr, m_strmsg(name_check), curr_line, name);
		exit(1);
	}
}

/*f
 *	Test whether this machine will need byte-swapping
 */
STATIC int
must_swap()
{
	union {
		short num;
		char byte[2];
	} test;
	test.num = 1;
	return (test.byte[1]);
}


/*f
 *      Put a record of the given offset onto the use-list.
 */
STATIC int
enqueue(offset)
long	offset;
{
	struct use_item	*item;

	item = (struct use_item *) malloc(sizeof(struct use_item));

	if (item == NULL)
	    syserr_abort(m_strmsg(nomem_use_list));

	item->offset = offset;

	if (use_list.head != NULL)
	{
	    item->bptr = use_list.tail;
	    use_list.tail->fptr = item;
	    item->fptr = NULL;
	    use_list.tail = item;
	}
	else
	{
	    use_list.tail = use_list.head = item;
	    item->fptr = item->bptr = NULL;
	}

	use_count ++;
}



/*f
 *	remove the pointed-to item from the use_list
 */
STATIC int
dequeue(ptr)
struct use_item	*ptr;
{
	if (ptr->fptr == NULL)
	    use_list.tail = ptr->bptr;
	else
	    (ptr->fptr)->bptr = ptr->bptr;

	if (ptr->bptr == NULL)
	    use_list.head = ptr->fptr;
	else
	    (ptr->bptr)->fptr = ptr->fptr;
	
	use_count --;
}



/*f
 *	Write out the compiled entry to the given file.
 *	Return 0 if OK or -1 if not.
 */
STATIC int
write_object(fp)
FILE *fp;
{
	int i, tlength;
    	__t_term_header header;
	char *tnames, zero = '\0';

	tnames = string_table + term_names;
	tlength = strlen(tnames) + 1;
	if (TERM_NAMES_LENGTH < tlength) 
		tlength = TERM_NAMES_LENGTH;
	if (must_swap()) {
		header.magic = swap(TERMINFO_MAGIC);
		header.name_size = swap(tlength);
		header.bool_count = swap(BOOLCOUNT);
		header.num_count = swap(NUMCOUNT);
		header.str_count = swap(STRCOUNT);
		header.str_size = swap(next_free);
	} else {
		header.magic = TERMINFO_MAGIC;
		header.name_size = tlength;
		header.bool_count = BOOLCOUNT;
		header.num_count = NUMCOUNT;
		header.str_count = STRCOUNT;
		header.str_size = next_free;
	}

	if (fwrite(&header, sizeof (header), 1, fp) != 1
	|| fwrite(tnames, sizeof (char), tlength, fp) != tlength 
	|| fwrite(boolean, sizeof (char), BOOLCOUNT, fp) != BOOLCOUNT)
		return (-1);
	
	if ((tlength+BOOLCOUNT) % 2 != 0 
	&& fwrite(&zero, sizeof (char), 1, fp) != 1)
		return (-1);

	if (must_swap()) {
		for (i = 0; i < NUMCOUNT; ++i)
			number[i] = swap(number[i]);
		for (i = 0; i < STRCOUNT; ++i)
			string[i] = swap(string[i]);
	}

	if (fwrite(number, sizeof (short), NUMCOUNT, fp) != NUMCOUNT
	|| fwrite(string, sizeof (short), STRCOUNT, fp) != STRCOUNT
	|| fwrite(string_table, sizeof (char), next_free, fp) != next_free)
		return (-1);
	return (0);
}



/*f
 *	Save the compiled version of a description in the filesystem.
 *
 *	make a copy of the name-list
 *	break it up into first-name and all-but-last-name
 *	creat(first-name)
 *	write object information to first-name
 *	close(first-name)
 *      for each name in all-but-last-name
 *	    link to first-name
 *
 */
STATIC void
dump_structure()
{
	FILE *fp;
	struct stat sb;
	char *p, *q, *first, *fn, *long_name, dir[2], tname[TERM_NAMES_LENGTH];

	/* Bag copy of terminal name list.  Parse off the last name,
	 * which should be the terminal's long name.  Parse off the 
	 * first name to be used for the terminal filename. 
	 */
	(void) strncpy(tname, string_table + term_names, TERM_NAMES_LENGTH);
	DEBUG(7, "Terminal names are \"%s\".\n", tname);
	for (p = tname + strlen(tname); tname < p; --p) {
		if (*p == '|') {
			long_name = ++p;
			break;
		}
	}
	if (tname == p)
		long_name = tname;
	for (p = tname; p < long_name; ++p) {
		if (*p == '|') {
			if (tname < p)
				*p++ = '\0';
			break;	
		}
	}
	if (check_only) {
		DEBUG(1, "Checked \"%s\".\n", tname);
		return;
	}
	DEBUG(7, "Terminfo file name is \"%s\".\n", tname);
	DEBUG(7, "Terminal's long name is \"%s\".\n", long_name);

	/* Create terminfo object file. */
	check_name(tname);
	*dir = tolower(*tname);
	dir[1] = '\0';
	first = m_pathcat(dir, tname);
	if (first == NULL)
		err_abort(m_strmsg(long_path), *tname, tname);
	if (0 <= stat(first, &sb) && start_time <= sb.st_mtime)
		warning(m_strmsg(more_than_one), tname);
	if (access(first, W_OK) == -1 && errno != ENOENT) {
		perror(first);
		err_abort(m_strmsg(write_err), first);
	}
	(void) unlink(first);
	if ((fp = fopen(first, "w")) == NULL)
		err_abort(m_strmsg(fail_open), first);
	DEBUG(1, "Created \"%s\".\n", first);
	if (write_object(fp) < 0)
		err_abort(m_strmsg(write_err), first);
	(void) fclose(fp);

	/* Create links for alternate names. */
	while (p < long_name) {
		for (q = p; p < long_name; ++p) {
			if (*p == '|') {
				*p++ = '\0';
				break;
			}
		}
		check_name(q);
		*dir = tolower(*q);
		dir[1] = '\0';
		fn = m_pathcat(dir, q);
		if (fn == NULL) {
			warning(m_strmsg(long_path), *q, q);
			continue;
		}
		if (strcmp(q, tname) == 0) {
			warning(m_strmsg(synonym), tname);
			continue;
		}
		if (0 <= stat(fn, &sb) && start_time <= sb.st_mtime) {
			warning(m_strmsg(more_than_one), q);
			continue;
		}
		if (access(fn, W_OK) == -1 && errno != ENOENT) {
			err_abort(m_strmsg(write_err), fn);
		}
		(void) unlink(fn);
		if (link(first, fn) < 0) {
			if ((fp = fopen(fn, "w")) == NULL)
				err_abort(m_strmsg(fail_open), fn);
			DEBUG(1, "Created \"%s\".\n", fn);
			if (write_object(fp) < 0)
				err_abort(m_strmsg(write_err), fn);
			(void) fclose(fp);
		} else {
			DEBUG(1, "Linked \"%s\".\n", fn);
		}
		free(fn);
	}
	free(first);
}


/*f
 *	copy string into next free part of string_table, doing a realloc()
 *	if necessary.  return offset of beginning of string from start of
 *	string_table.
 */
STATIC int
save_str(string)
char	*string;
{
	int	old_next_free = next_free;

	if (table_size == 0)
	{
	    if ((string_table = malloc(1024)) == NULL)
		syserr_abort(m_strmsg(nomem));
	    table_size = 1024;
	    DEBUG(5, "Made initial string table allocation.  Size is %d\n",
								    table_size);
	}

	while (table_size < next_free + strlen(string))
	{
	    if ((string_table = realloc(string_table, table_size + 1024))
									== NULL)
		syserr_abort(m_strmsg(nomem));
	    table_size += 1024;
	    DEBUG(5, "Extended string table.  Size now %d\n", table_size);
	}

	strcpy(&string_table[next_free], string);
	DEBUG(7, "Saved string '%s' ", string);
	DEBUG(7, "at location %d\n", next_free);
	next_free += strlen(string) + 1;

	return (old_next_free);
}

/*f
 *	Merge the compiled file whose name is in cur_token.valstring
 *	with the current entry.
 *
 *		if it's a forward use-link
 *	    	    if item_ptr == NULL
 *		        queue it up for later handling
 *	            else
 *		        ignore it (we're already going through the queue)
 *	        else it's a backward use-link
 *	            read in the object file for that terminal
 *	            merge contents with current structure
 *
 *	Returned value is 0 if it was a backward link and we
 *	successfully read it in, -1 if a forward link.
 */
STATIC int
handle_use(item_ptr, entry_offset)
struct use_item	*item_ptr;
long entry_offset;
{
        int i, err;
	struct stat sb;
	char *filename, dir[2];

	check_name(curr_token.tk_valstring);
	*dir = tolower(*curr_token.tk_valstring);
	dir[1] = '\0';
	filename = m_pathcat(dir, curr_token.tk_valstring);
	if (filename == NULL) {
		err_abort(
			m_strmsg(long_path), 
			*curr_token.tk_valstring, curr_token.tk_valstring
		);
	}
	if (stat(filename, &sb) < 0 
	|| (part2 == 0 && sb.st_mtime < start_time)) {
		DEBUG(2, "Forward USE to %s", curr_token.tk_valstring);
		if (item_ptr == NULL) {
			DEBUG(2, " (enqueued)\n", "");
			enqueue(entry_offset);
		} else {
			DEBUG(2, " (skipped)\n", "");
		}
		free(filename);
		return (-1);
	}
	DEBUG(2, "Backward USE to %s\n", curr_token.tk_valstring);
	(void) setupterm(curr_token.tk_valstring, STDOUT_FILENO, &err);
	switch (err) {
	case 1:
		for (i = 0; i < BOOLCOUNT; ++i) {
			if (boolean[i] == 0 && cur_term->Booleans[i])
				boolean[i] = 1;
		}
		for (i = 0; i < NUMCOUNT; ++i) {
			if (number[i] == -1 && cur_term->Numbers[i] != -1)
				number[i] = cur_term->Numbers[i];
		}
		for (i = 0; i < STRCOUNT; ++i) {
			if (string[i] == -1 && cur_term->Strings[i] != NULL)
				string[i] = save_str(cur_term->Strings[i]);
		}
		(void) del_curterm(cur_term);
		free(filename);
		break;
	case 0:
		err_abort(m_strmsg(unknown_term), filename); 
		exit(BAD_TERMINAL);
	case -1:
		err_abort(m_strmsg(no_terminfo)); 
		exit(BAD_TERMINAL);
	}
	return (0);
}



/*f
 *	Compile one entry.  During the first pass, item_ptr is NULL.  In pass
 *	two, item_ptr points to the current entry in the use_list.
 *
 *	found-forward-use = FALSE
 *	re-initialise internal arrays
 *	save names in string_table
 *	get_token()
 *	while (not EOF and not NAMES)
 *	    if found-forward-use
 *		do nothing
 *	    else if 'use'
 *		if handle_use() < 0
 *		    found-forward-use = TRUE
 *          else
 *	        check for existance and type-correctness
 *	        enter cap into structure
 *	        if STRING
 *	            save string in string_table
 *	    get_token()
 *      if ! found-forward-use
 *	    clear CANCELS out of the structure
 *	    dump compiled entry into filesystem
 */
STATIC int
do_entry(item_ptr)
struct use_item	*item_ptr;
{
	void *array;
	long entry_offset;
	int i, index;
	register int token_type;
	int found_forward_use = 0;

	reset();
	next_free = 0;

	complete = 0;
	term_names = save_str(curr_token.tk_name);
	DEBUG(2, "Starting '%s'\n", curr_token.tk_name);
	entry_offset = curr_file_pos;

	for (token_type = get_token(); 
	token_type != EOF && token_type != NAMES;
	token_type = get_token()) {
		if (found_forward_use) {
			;
		} else if (strcmp(curr_token.tk_name, "use") == 0) {
			if (handle_use(item_ptr, entry_offset) < 0)
				found_forward_use = 1;
		} else {
			if (find(curr_token.tk_name, &array, &index) < 0) {
				warning(
					m_strmsg(unknown_cap), 
					curr_token.tk_name
				);
				continue;
			}
			switch (token_type) {
			case CANCEL:
				if (array == boolean)
					boolean[index] = 2;
				else
					((short*) array)[index] = -2;
				continue;
			case BOOLEAN:
				if (array == boolean) {
					boolean[index] = 1;
					continue;
				}
				break;
			case NUMBER:
				if (array == number) {
					number[index] = curr_token.tk_valnumber;
					continue;
				}
				break;
			case STRING:
				if (array == string) {
					string[index] = save_str(
						curr_token.tk_valstring
					);
					continue;
				}
				break;
			default:
				warning(m_strmsg(unknown_token));
				panic_mode(',');
				continue;
			}
			warning(m_strmsg(wrong_type), curr_token.tk_name);
		} 
	} 
	if (found_forward_use)
		return (token_type);

	/* Changed canceled values into in-active values. */
	for (i = 0; i < BOOLCOUNT; ++i)
		if (boolean[i] == 2)
			boolean[i] = 0;
	for (i = 0; i < NUMCOUNT; ++i)
		if (number[i] == -2)
			number[i] = -1;
	for (i = 0; i < STRCOUNT; ++i)
		if (string[i] == -2)
			string[i] = -1;
	dump_structure();
	complete = 1;
	return (token_type);
}



/*f
 *	Main loop of the compiler.
 *
 *	get_token()
 *	if curr_token != NAMES
 *	    err_abort()
 *	while (not at end of file)
 *	    do an entry
 */
void
compile()
{
	char			line[1024];
	int			token_type;
	struct use_item	*ptr;
	int			old_use_count;

	token_type = get_token();

	if (token_type != NAMES)
		err_abort(m_strmsg(bad_start));
	
	while (token_type != EOF)
	    token_type = do_entry(NULL);

	DEBUG(2, "Starting handling of forward USE's\n", "");

	for (part2=0; part2<2; part2++) {
	    old_use_count = -1;

	    DEBUG(2, "\n\nPART %d\n\n", part2);

	    while (use_list.head != NULL && old_use_count != use_count)
	    {
		old_use_count = use_count;
		for (ptr = use_list.tail; ptr != NULL; ptr = ptr->bptr)
		{
		    fseek(stdin, ptr->offset, 0);
		    reset_input();
		    if ((token_type = get_token()) != NAMES)
			syserr_abort(m_strmsg(not_names));			
		    (void) do_entry(ptr);
		    if (complete)
			dequeue(ptr);
		}

		for (ptr = use_list.head; ptr != NULL; ptr = ptr->fptr)
		{
		    fseek(stdin, ptr->offset, 0);
		    reset_input();
		    if ((token_type = get_token()) != NAMES)
			syserr_abort(m_strmsg(not_names));			
		    (void) do_entry(ptr);
		    if (complete)
			dequeue(ptr);
		}
		
		DEBUG(2,"Finished a pass through enqueued forward USE's\n","");
	    }
	}

	if (use_list.head != NULL) {
		fprintf(stderr, use_links);
		for (ptr = use_list.head; ptr != NULL; ptr = ptr->fptr) {
			fseek(stdin, ptr->offset, 0);
			fgets(line, 1024, stdin);
			fprintf(stderr, "%s", line);
		}
		exit(1);
	}
}
