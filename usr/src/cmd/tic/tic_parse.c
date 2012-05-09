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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 */
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 *  *******************************************************************
 *                         COPYRIGHT NOTICE                           *
 * ********************************************************************
 *        This software is copyright (C) 1982 by Pavel Curtis         *
 *                                                                    *
 *        Permission is granted to reproduce and distribute           *
 *        this file by any means so long as no fee is charged         *
 *        above a nominal handling fee and so long as this            *
 *        notice is always included in the copies.                    *
 *                                                                    *
 *        Other rights are reserved except as explicitly granted      *
 *        by written permission of the author.                        *
 *                Pavel Curtis                                        *
 *                Computer Science Dept.                              *
 *                405 Upson Hall                                      *
 *                Cornell University                                  *
 *                Ithaca, NY 14853                                    *
 *                                                                    *
 *                Ph- (607) 256-4934                                  *
 *                                                                    *
 *                Pavel.Cornell@Udel-Relay   (ARPAnet)                *
 *                decvax!cornell!pavel       (UUCPnet)                *
 * ********************************************************************
 */

/*
 *	comp_parse.c -- The high-level (ha!) parts of the compiler,
 *			that is, the routines which drive the scanner,
 *			etc.
 *
 *   $Log:	RCS/comp_parse.v $
 * Revision 2.1  82/10/25  14:45:43  pavel
 * Added Copyright Notice
 *
 * Revision 2.0  82/10/24  15:16:39  pavel
 * Beta-one Test Release
 *
 * Revision 1.3  82/08/23  22:29:39  pavel
 * The REAL Alpha-one Release Version
 *
 * Revision 1.2  82/08/19  19:09:53  pavel
 * Alpha Test Release One
 *
 * Revision 1.1  82/08/12  18:37:12  pavel
 * Initial revision
 *
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include "curses_inc.h"
#include "compiler.h"
#include "object.h"

extern	char check_only;
extern	char *progname;

char	*string_table;
int	next_free;	/* next free character in string_table */
unsigned int	table_size = 0; /* current string_table size */
short	term_names;	/* string table offset - current terminal */
int	part2 = 0;	/* set to allow old compiled defns to be used */
int	complete = 0;	/* 1 if entry done with no forward uses */

struct use_item {
	long	offset;
	struct use_item	*fptr, *bptr;
};

struct use_header {
	struct use_item	*head, *tail;
};

struct use_header	use_list = {NULL, NULL};
int			use_count = 0;

void dequeue(struct use_item *);
void init_structure(short Booleans[], short Numbers[], short Strings[]);
void dump_structure(short Booleans[], short Numbers[], short Strings[]);

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


/*
 *	compile()
 *
 *	Main loop of the compiler.
 *
 *	get_token()
 *	if curr_token != NAMES
 *	    err_abort()
 *	while (not at end of file)
 *	    do an entry
 *
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
		err_abort(
"File does not start with terminal names in column one");

	while (token_type != EOF)
		token_type = do_entry((struct use_item *)NULL);

	DEBUG(2, "Starting handling of forward USE's\n", "");

	for (part2 = 0; part2 < 2; part2++) {
		old_use_count = -1;
		DEBUG(2, "\n\nPART %d\n\n", part2);
		while (use_list.head != NULL && old_use_count != use_count) {
			old_use_count = use_count;
			for (ptr = use_list.tail; ptr != NULL;
			    ptr = ptr->bptr) {
				fseek(stdin, ptr->offset, 0);
				reset_input();
				if ((token_type = get_token()) != NAMES)
					syserr_abort(
"Token after a seek not NAMES");
				(void) do_entry(ptr);
				if (complete)
					dequeue(ptr);
			}

			for (ptr = use_list.head; ptr != NULL;
			    ptr = ptr->fptr) {
				fseek(stdin, ptr->offset, 0);
				reset_input();
				if ((token_type = get_token()) != NAMES)
					syserr_abort(
"Token after a seek not NAMES");
				(void) do_entry(ptr);
				if (complete)
					dequeue(ptr);
			}

			DEBUG(2,
"Finished a pass through enqueued forward USE's\n", "");
		}
	}

	if (use_list.head != NULL && !check_only) {
		fprintf(stderr,
"\nError in following use-links. Either there is a loop in the links\n"
"or they reference non-existent terminals. The following is a list of\n"
"the entries involved:\n\n");

		for (ptr = use_list.head; ptr != NULL; ptr = ptr->fptr) {
			fseek(stdin, ptr->offset, 0);
			fgets(line, 1024, stdin);
			fprintf(stderr, "%s", line);
		}

		exit(1);
	}
}

void
dump_list(char *str)
{
	struct use_item *ptr;
	char line[1024];

	fprintf(stderr, "dump_list %s\n", str);
	for (ptr = use_list.head; ptr != NULL; ptr = ptr->fptr) {
		fseek(stdin, ptr->offset, 0);
		fgets(line, 1024, stdin);
		fprintf(stderr, "ptr %x off %d bptr %x fptr %x str %s",
		    ptr, ptr->offset, ptr->bptr, ptr->fptr, line);
	}
	fprintf(stderr, "\n");
}

/*
 *	int
 *	do_entry(item_ptr)
 *
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
 *	    dump compiled entry into filesystem
 *
 */

int
do_entry(item_ptr)
struct use_item	*item_ptr;
{
	long					entry_offset;
	int					token_type;
	struct name_table_entry			*entry_ptr;
	int					found_forward_use = FALSE;
	short					Booleans[MAXBOOLS],
						Numbers[MAXNUMS],
						Strings[MAXSTRINGS];

	init_structure(Booleans, Numbers, Strings);
	complete = 0;
	term_names = save_str(curr_token.tk_name);
	DEBUG(2, "Starting '%s'\n", curr_token.tk_name);
	entry_offset = curr_file_pos;

	for (token_type = get_token();
				token_type != EOF && token_type != NAMES;
				token_type = get_token()) {
		if (found_forward_use)
			/* do nothing */;
		else if (strcmp(curr_token.tk_name, "use") == 0) {
			if (handle_use(item_ptr, entry_offset,
					Booleans, Numbers, Strings) < 0)
				found_forward_use = TRUE;
		} else {
			entry_ptr = find_entry(curr_token.tk_name);

			if (entry_ptr == NOTFOUND) {
				warning("Unknown Capability - '%s'",
							curr_token.tk_name);
				continue;
			}


			if (token_type != CANCEL &&
					entry_ptr->nte_type != token_type)
				warning("Wrong type used for capability '%s'",
							curr_token.tk_name);
			switch (token_type) {
			case CANCEL:
				switch (entry_ptr->nte_type) {
				case BOOLEAN:
					Booleans[entry_ptr->nte_index] = -2;
					break;

				case NUMBER:
					Numbers[entry_ptr->nte_index] = -2;
					break;

				case STRING:
					Strings[entry_ptr->nte_index] = -2;
					break;
				}
				break;

			case BOOLEAN:
				if (Booleans[entry_ptr->nte_index] == 0)
					Booleans[entry_ptr->nte_index] = TRUE;
				break;

			case NUMBER:
				if (Numbers[entry_ptr->nte_index] == -1)
					Numbers[entry_ptr->nte_index] =
						curr_token.tk_valnumber;
				break;

			case STRING:
				if (Strings[entry_ptr->nte_index] == -1)
					Strings[entry_ptr->nte_index] =
					    save_str(curr_token.tk_valstring);
				break;

			default:
				warning("Unknown token type");
				panic_mode(',');
				continue;
			}
		} /* end else cur_token.name != "use" */

	} /* endwhile (not EOF and not NAMES) */

	if (found_forward_use)
		return (token_type);

	dump_structure(Booleans, Numbers, Strings);

	complete = 1;
	return (token_type);
}

/*
 * Change all cancellations to a non-entry.
 * For booleans, @ -> false
 * For nums, @ -> -1
 * For strings, @ -> -1
 *
 * This only has to be done for entries which
 * have to be compatible with the pre-Vr3 format.
 */
#ifndef NOCANCELCOMPAT
void
elim_cancellations(short Booleans[], short Numbers[], short Strings[])
{
	int i;
	for (i = 0; i < BoolCount; i++) {
		if (Booleans[i] == -2)
			Booleans[i] = FALSE;
	}

	for (i = 0; i < NumCount; i++) {
		if (Numbers[i] == -2)
			Numbers[i] = -1;
	}

	for (i = 0; i < StrCount; i++) {
		if (Strings[i] == -2)
			Strings[i] = -1;
	}
}
#endif /* NOCANCELCOMPAT */
/*
 * Change the cancellation signal from the -2 used internally to
 * the 2 used within the binary.
 */
void
change_cancellations(short Booleans[])
{
	int i;
	for (i = 0; i < BoolCount; i++) {
		if (Booleans[i] == -2)
			Booleans[i] = 2;
	}

}

/*
 *	enqueue(offset)
 *
 *      Put a record of the given offset onto the use-list.
 *
 */

void
enqueue(long offset)
{
	struct use_item	*item;

	item = (struct use_item *)malloc(sizeof (struct use_item));

	if (item == NULL)
		syserr_abort("Not enough memory for use_list element");

	item->offset = offset;

	if (use_list.head != NULL) {
		item->bptr = use_list.tail;
		use_list.tail->fptr = item;
		item->fptr = NULL;
		use_list.tail = item;
	} else {
		use_list.tail = use_list.head = item;
		item->fptr = item->bptr = NULL;
	}

	use_count ++;
}

/*
 *	dequeue(ptr)
 *
 *	remove the pointed-to item from the use_list
 *
 */

void
dequeue(struct use_item *ptr)
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

/*
 *	invalid_term_name(name)
 *
 *	Look for invalid characters in a term name. These include
 *	space, tab and '/'.
 *
 *	Generate an error message if given name does not begin with a
 *	digit or letter, then exit.
 *
 *	return TRUE if name is invalid.
 *
 */

static int
invalid_term_name(char *name)
{
	int error = 0;
	if (! isdigit(*name) && ! islower(*name) && ! isupper(*name))
		error++;

	for (; *name; name++)
		if (isalnum(*name))
			continue;
		else if (isspace(*name) || (*name == '/'))
			return (1);
	if (error) {
		fprintf(stderr, "%s: Line %d: Illegal terminal name - '%s'\n",
		    progname, curr_line, name);
		fprintf(stderr,
		    "Terminal names must start with a letter or digit\n");
		exit(1);
	}
	return (0);
}

/*
 *	dump_structure()
 *
 *	Save the compiled version of a description in the filesystem.
 *
 *	make a copy of the name-list
 *	break it up into first-name and all-but-last-name
 *	if necessary
 *	    clear CANCELS out of the structure
 *	creat(first-name)
 *	write object information to first-name
 *	close(first-name)
 *      for each valid name
 *	    link to first-name
 *
 */

void
dump_structure(short Booleans[], short Numbers[], short Strings[])
{
	struct stat64	statbuf;
	FILE		*fp;
	char		name_list[1024];
	char		*first_name, *other_names, *cur_name;
	char		filename[128 + 2 + 1];
	char		linkname[128 + 2 + 1];
	int		len;
	int		alphastart = 0;
	extern char	*strchr(), *strrchr();

	strcpy(name_list, term_names + string_table);
	DEBUG(7, "Name list = '%s'\n", name_list);

	first_name = name_list;
	/* Set othernames to 1 past first '|' in the list. */
	/* Null out that '|' in the process. */
	other_names = strchr(first_name, '|');
	if (other_names)
		*other_names++ = '\0';

	if (invalid_term_name(first_name))
		warning("'%s': bad first term name.", first_name);


	DEBUG(7, "First name = '%s'\n", first_name);
	DEBUG(7, "Other names = '%s'\n", other_names ? other_names : "NULL");

	if ((len = strlen(first_name)) > 128)
		warning("'%s': terminal name too long.", first_name);
	else if (len == 1)
		warning("'%s': terminal name too short.", first_name);

	check_dir(first_name[0]);

	sprintf(filename, "%c/%s", first_name[0], first_name);

	if (stat64(filename, &statbuf) >= 0 && statbuf.st_mtime >= start_time) {
		warning("'%s' defined in more than one entry.", first_name);
		fprintf(stderr, "Entry being used is '%s'.\n",
		    (unsigned)term_names + string_table);
	}

	if (!check_only) {
		unlink(filename);
		fp = fopen(filename, "w");
		if (fp == NULL) {
			perror(filename);
			syserr_abort("Can't open %s/%s\n", destination,
			    filename);
		}
		DEBUG(1, "Created %s\n", filename);
	} else DEBUG(1, "Would have created %s\n", filename);

#ifndef NOCANCELCOMPAT
	/* eliminate cancellation markings if there is no '+' in the name */
	if (strchr(first_name, '+') == 0)
		elim_cancellations(Booleans, Numbers, Strings);
	else
#endif /* NOCANCELCOMPAT */
		change_cancellations(Booleans);

	if (!check_only) {
		if (write_object(fp, Booleans, Numbers, Strings) < 0) {
			syserr_abort("Error writing %s/%s", destination,
			    filename);
		}
		fclose(fp);
	}

	alphastart = isalpha(first_name[0]);

	while (other_names) {
		cur_name = other_names;
		other_names = strchr(cur_name, '|');
		if (other_names)
			*other_names++ = '\0';
		if (*cur_name == '\0')
			continue;

		if ((len = strlen(cur_name)) > 128) {
			warning("'%s': terminal name too long.", cur_name);
			continue;
		} else if (len == 1) {
			warning("'%s': terminal name too short.", first_name);
			continue;
		}

		if (invalid_term_name(cur_name)) {
			if (other_names)
				warning("'%s': bad term name found in list.",
				    cur_name);
			continue;
		}

		check_dir(cur_name[0]);

		sprintf(linkname, "%c/%s", cur_name[0], cur_name);

		alphastart |= isalpha(cur_name[0]);

		if (strcmp(first_name, cur_name) == 0) {
			warning("Terminal name '%s' synonym for itself",
			    first_name);
		} else  {
			if (!check_only) {
				if (stat64(linkname, &statbuf) >= 0 &&
				    statbuf.st_mtime >= start_time) {
					warning(
"'%s' defined in more than one entry.", cur_name);
					fprintf(stderr,
					    "Entry being used is '%s'.\n",
					    (unsigned)term_names +
					    string_table);
				}
				unlink(linkname);
				if (link(filename, linkname) < 0)
					syserr_abort("Can't link %s to %s",
					    filename, linkname);
				DEBUG(1, "Linked %s\n", linkname);
			} else DEBUG(1, "Would have linked %s\n", linkname);
		}
	}

	if (!alphastart) {
		warning("At least one synonym should begin with a letter.");
	}
}

/*
 *	int
 *	write_object(fp, Booleans, Numbers, Strings)
 *
 *	Write out the compiled entry to the given file.
 *	Return 0 if OK or -1 if not.
 *
 */

#define	swap(x)		(((x >> 8) & 0377) + 256 * (x & 0377))

#define	might_swap(x)	(must_swap()  ?  swap(x)  :  (x))


int
write_object(fp, Booleans, Numbers, Strings)
FILE	*fp;
short	Booleans[];
short	Numbers[];
short	Strings[];
{
	struct header	header;
	char		*namelist;
	short		namelen;
	char		zero = '\0';
	int		i;
	char		cBooleans[MAXBOOLS];
	int		l_next_free;

	namelist = term_names + string_table;
	namelen = strlen(namelist) + 1;

	l_next_free = next_free;
	if (l_next_free % 256 == 255)
		l_next_free++;

	if (must_swap()) {
		header.magic = swap(MAGIC);
		header.name_size = swap(namelen);
		header.bool_count = swap(BoolCount);
		header.num_count = swap(NumCount);
		header.str_count = swap(StrCount);
		header.str_size = swap(l_next_free);
	} else {
		header.magic = MAGIC;
		header.name_size = namelen;
		header.bool_count = BoolCount;
		header.num_count = NumCount;
		header.str_count = StrCount;
		header.str_size = l_next_free;
	}

	for (i = 0; i < BoolCount; i++)
		cBooleans[i] = Booleans[i];

	if (fwrite(&header, sizeof (header), 1, fp) != 1 ||
		    fwrite(namelist, sizeof (char), namelen, fp) != namelen ||
		    fwrite(cBooleans, sizeof (char), BoolCount, fp) !=
								BoolCount)
		return (-1);

	if ((namelen+BoolCount) % 2 != 0 &&
				fwrite(&zero, sizeof (char), 1, fp) != 1)
		return (-1);

	if (must_swap()) {
		for (i = 0; i < NumCount; i++)
			Numbers[i] = swap(Numbers[i]);
		for (i = 0; i < StrCount; i++)
			Strings[i] = swap(Strings[i]);
	}

	if (fwrite((char *)Numbers, sizeof (short), NumCount, fp) != NumCount ||
		    fwrite((char *)Strings, sizeof (short), StrCount, fp)
							!= StrCount ||
		    fwrite(string_table, sizeof (char), l_next_free, fp)
							!= l_next_free)
		return (-1);

	return (0);
}

/*
 *	int
 *	save_str(string)
 *
 *	copy string into next free part of string_table, doing a realloc()
 *	if necessary.  return offset of beginning of string from start of
 *	string_table.
 *
 */

int
save_str(string)
char	*string;
{
	int	old_next_free;

	/* Do not let an offset be 255. It reads as -1 in Vr2 binaries. */
	if (next_free % 256 == 255)
		next_free++;

	old_next_free = next_free;

	if (table_size == 0) {
		if ((string_table = malloc(1024)) == NULL)
			syserr_abort("Out of memory");
		table_size = 1024;
		DEBUG(5, "Made initial string table allocation.  Size is %u\n",
							    table_size);
	}

	while (table_size <= next_free + strlen(string)) {
		if ((string_table = realloc(string_table, table_size + 1024))
								== NULL)
			syserr_abort("Out of memory");
		table_size += 1024;
		DEBUG(5, "Extended string table.  Size now %u\n", table_size);
	}

	strcpy(&string_table[next_free], string);
	DEBUG(7, "Saved string '%s' ", string);
	DEBUG(7, "at location %d\n", next_free);
	next_free += strlen(string) + 1;

	return (old_next_free);
}

/*
 *	init_structure(Booleans, Numbers, Strings)
 *
 *	Initialise the given arrays
 *	Reset the next_free counter to zero.
 *
 */

void
init_structure(short Booleans[], short Numbers[], short Strings[])
{
	int	i;

	for (i = 0; i < BoolCount; i++)
		Booleans[i] = FALSE;

	for (i = 0; i < NumCount; i++)
		Numbers[i] = -1;

	for (i = 0; i < StrCount; i++)
		Strings[i] = -1;

	next_free = 0;
}

/*
 *	int
 *	handle_use(item_ptr, entry_offset, Booleans, Numbers, Strings)
 *
 *	Merge the compiled file whose name is in cur_token.valstring
 *	with the current entry.
 *
 *		if it's a forward use-link
 *		    if item_ptr == NULL
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

int
handle_use(item_ptr, entry_offset, Booleans, Numbers, Strings)
long		entry_offset;
struct use_item	*item_ptr;
short		Booleans[];
short		Numbers[];
short		Strings[];
{
	struct _bool_struct	use_bools;
	struct _num_struct	use_nums;
	struct _str_struct	use_strs;
	struct stat64	statbuf;
	char		filename[50];
	int		i;
	char  *UB = &use_bools._auto_left_margin;	/* first bool */
	short *UN = &use_nums._columns;			/* first num */
	char **US = &use_strs.strs._back_tab;		/* first str */

	if (invalid_term_name(curr_token.tk_valstring))
		warning("%s: bad term name", curr_token.tk_valstring);

	sprintf(filename, "%c/%s", curr_token.tk_valstring[0],
						curr_token.tk_valstring);

	if (stat64(filename, &statbuf) < 0 ||
				part2 == 0 && statbuf.st_mtime < start_time) {
		DEBUG(2, "Forward USE to %s", curr_token.tk_valstring);

		if (item_ptr == NULL) {
			DEBUG(2, " (enqueued)\n", "");
			enqueue(entry_offset);
		} else DEBUG(2, " (skipped)\n", "");

		return (-1);
	} else {
		DEBUG(2, "Backward USE to %s\n", curr_token.tk_valstring);
		if (read_entry(filename, &use_bools, &use_nums, &use_strs) < 0)
			syserr_abort("Error in re-reading compiled file %s",
								filename);

		for (i = 0; i < BoolCount; i++) {
			if (Booleans[i] == FALSE)
				if (UB[i] == TRUE)		/* now true */
					Booleans[i] = TRUE;
				else if (UB[i] > TRUE)	/* cancelled */
					Booleans[i] = -2;
		}

		for (i = 0; i < NumCount; i++) {
			if (Numbers[i] == -1)
				Numbers[i] = UN[i];
		}

		for (i = 0; i < StrCount; i++) {
			if (Strings[i] == -1)
				if (US[i] == (char *)-1)
					Strings[i] = -2;
				else if (US[i] != (char *)0)
					Strings[i] = save_str(US[i]);
		}

	}
	return (0);
}
