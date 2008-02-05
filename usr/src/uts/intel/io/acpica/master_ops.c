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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

#define	masterfile "/boot/solaris/devicedb/master"

/* Maximum size of a master line */
#define	MASTER_LINE_MAX (1024*2)
static char *one_master_line;
static int one_master_line_cur_index = 0, one_master_line_max = 0;
struct master_line {
	char *column[10];
	char *text; /* to be kmem alloc'd */
	int line_size;
	struct master_line *next, *prev;
};
static struct master_line *incore_master_head = NULL,
	*incore_master_tail = NULL;
/* same order as columns in /boot/solaris/devicedb/master */
static int mf_column = 0;
static int incore_master_table_line_count = 0;

#define	MASTER_OPS_DEBUG_PRINT_INCORE	0x0001
#define	MASTER_OPS_DEBUG_PROCESS	0x0002
#define	MASTER_OPS_DEBUG_LOOKUP		0x0004
#define	MASTER_OPS_DEBUG_CID_FOUND	0x2000
static long master_ops_debug = 0x0;
#define	EOL 0xA
#define	FILE_T struct _buf

static void
print_incore_master_table() {
	struct master_line *ptr = incore_master_head;
	int i;

	if (master_ops_debug & MASTER_OPS_DEBUG_PRINT_INCORE) {
		for (i = 0; i < incore_master_table_line_count; i++) {
			printf("1)%s, 2)%s, 3)%s, 4)%s, 5)%s, 6)%s, ",
			    ptr->column[0],
			    ptr->column[1],
			    ptr->column[2],
			    ptr->column[3],
			    ptr->column[4],
			    ptr->column[5]);
			if (ptr->column[6] != NULL) {
			    printf("7)%s, ", ptr->column[6]);
			}
			if (ptr->column[7] != NULL) {
				printf("8)%s", ptr->column[7]);
			}
			printf("\n");
			ptr = ptr->next;
			if (ptr == NULL) {
				i++;
				break;
			}
		}
		printf("There are %d lines\n", i);
	}
}

/*
 * parses one_master_line[] from index pointed by one_master_line_cur_index
 * returns the following tokens
 * POUND -- if a comment line
 * NEWLINE -- if an empty line
 * NAME -- return a string from one_master_line separated by " or blank
 * EOL -- End of line
 */
static int
master_lex(char *val) {
	char *cp;
	int	ch;
	int token;

	cp = val;
	/* skip leading blanks */
	while (((ch = one_master_line[one_master_line_cur_index++]) == ' ' ||
	    (ch == '\t')) && (one_master_line_cur_index < one_master_line_max))
		;
	if ((ch == 0) || (one_master_line_cur_index >= one_master_line_max)) {
		val = 0;
		return (EOL);
	}
	*cp++ = (char)ch;
	switch (ch) {
	case '#':
		token = POUND;
		break;
	case '\n':
	case '\r':
		token = NEWLINE;
		break;
	case '"':
		cp--;
		while (((ch  = one_master_line[one_master_line_cur_index++])
		    != '"') && (one_master_line_cur_index <=
		    one_master_line_max)) {
			*cp++ = (char)ch;
		}
		token = NAME;
		break;
	default:
		ch = one_master_line[one_master_line_cur_index++];
		while ((ch != ' ') && (ch != '\t') && (ch != '\n') &&
		    (ch != '\r') && (one_master_line_cur_index <=
		    one_master_line_max)) {
			*cp++ = (char)ch;
			ch = one_master_line[one_master_line_cur_index++];
		}
		token = NAME;
		break;
	}
	*cp = '\0';
	return (token);
}

/*
 * read a line from devicedb/master file and put it to one_master_line[] buffer
 * one_master_line_max -- size of data in one_master_line[]
 * one_master_line_cur_index -- reset to zero
 */
static int
master_get_a_line(FILE_T *file) {
	int ch;
	one_master_line_max = 0;
	one_master_line_cur_index = 0; /* used by master_lex() */
	while (((ch = kobj_getc(file)) != '\n') && (ch != '\r')) {
		if (ch == -1) {
			if (one_master_line_max == 0) {
				one_master_line[0] = 0;
				return (EOF);
			} else {
				return (one_master_line_max);
			}
		}
		one_master_line[one_master_line_max++] = ch;
		if (one_master_line_max >= MASTER_LINE_MAX) {
			cmn_err(CE_WARN, "!master file line too long:");
			cmn_err(CE_CONT, "%s", one_master_line);
		}
	}
	one_master_line[one_master_line_max] = 0;
	return (one_master_line_max);
}

/*
 * skip a line
 */
static void
master_skip(FILE_T *file) {
	char ch;
	while (((ch = kobj_getc(file)) != '\n') && (ch != '\r'))
		;
}

/*
 * return NULL if no bar found
 * if bar found, return pointer after the bar
 * plus, change character '|' (bar) to null as a delimiter
 */
static char *
find_bar(char *target) {
	if (target == NULL) {
		return (NULL);
	}
	while ((*target != '|') && (*target != ' ') && (*target != 0)) {
		target++;
	}
	if (*target == '|') {
		*target = 0;
		return (++target);
	}
	return (NULL);
}

/*
 * If column 0 has | (bars) as device separators, we need make (dup)
 * more lines for each device.
 */
static void
dup_devices() {
	struct master_line *last, *ptr = incore_master_tail;
	char *token;
	int i;

	if (ptr == NULL || ptr->column == NULL || ptr->column[0] == NULL) {
		return;
	}
	token = incore_master_tail->column[0];
	while ((token = find_bar(token)) != NULL) {
		last = (struct master_line *)kmem_zalloc(
		    sizeof (struct master_line), KM_SLEEP);
		for (i = 0; i < 10; i++) {
		    last->column[i] = ptr->column[i];
		}
		last->text = ptr->text;
		last->line_size = 0; /* 'cause we re-use the same line */
		last->column[0] = token;
		ptr->next = last;
		last->prev = ptr;
		last->next = NULL;
		ptr = incore_master_tail = last;
		incore_master_table_line_count++;
	}
}

/*
 * sets master_ops_debug flag from propertyu passed by the boot
 */
static void
set_master_ops_debug_flags()
{
	char *prop;
	long flags;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "master_ops_debug", &prop) == DDI_PROP_SUCCESS) {
		long data;
		if (ddi_strtol(prop, NULL, 0, &data) == 0) {
			master_ops_debug = (unsigned long)data;
			e_ddi_prop_remove(DDI_DEV_T_NONE, ddi_root_node(),
			    "master_ops_debug");
			e_ddi_prop_update_int(DDI_DEV_T_NONE, ddi_root_node(),
			    "master_ops_debug", data);
		}
		ddi_prop_free(prop);
	}
}

/*
 * open / read / parse / close devicedb/master file
 */
void
process_master_file() {
	FILE_T *file;
	char tokbuf[MASTER_LINE_MAX];
	int token;
	int done = 0;
	int line_begin;
	int x = 0;
	int total_line_processed = 0;

	set_master_ops_debug_flags();

	incore_master_head = incore_master_tail = NULL;
	if ((file = kobj_open_file(masterfile)) == (struct _buf *)-1) {
		cmn_err(CE_WARN, "!cannot open master file: %s", masterfile);
		return;
	}
	one_master_line = (char *)kmem_zalloc(MASTER_LINE_MAX, KM_SLEEP);
	master_skip(file); /* skip the first line which is "version" */
	mf_column = 0;
	while (!done) {
		if (mf_column == 0) {
			x = master_get_a_line(file);
			total_line_processed++;
			if (x == EOF) { /* end of file */
				done = 1;
				continue;
			}
			if (x == 0) { /* blank line */
				continue;
			}
		}
		token = master_lex(tokbuf);
		switch (token) {
		case POUND: /* ignore comment line */
			if (master_ops_debug & MASTER_OPS_DEBUG_PROCESS) {
				printf("master_ops: # found skip this line\n");
			}
			mf_column = 0;
			break;
		case NAME: /* found actual string, parse and keep it */
			if (mf_column == 0) {
				if (incore_master_tail == NULL) {
					/* very 1st line */
					incore_master_head =
					incore_master_tail = (struct
					    master_line *) kmem_zalloc(
					    sizeof (struct master_line),
					    KM_SLEEP);
					incore_master_head->text = (char *)
					    kmem_zalloc(one_master_line_max,
					    KM_SLEEP);
					incore_master_head->line_size =
					    one_master_line_max;
				} else {
					incore_master_tail->next = (struct
					    master_line *)kmem_zalloc(
					    sizeof (struct master_line),
					    KM_SLEEP);
					incore_master_tail =
					    incore_master_tail->next;
					incore_master_tail->text = (char *)
					    kmem_zalloc(one_master_line_max,
					    KM_SLEEP);
					incore_master_tail->line_size =
					    one_master_line_max;
				}
				line_begin = 0;
				incore_master_table_line_count++;
			}
			if ((line_begin + strlen(tokbuf) + 1) >
			    MASTER_LINE_MAX) {
				mf_column = 0;
				cmn_err(CE_WARN, "!master file line too long");
				cmn_err(CE_CONT, "line data: \"%s\"",
				    one_master_line);
				master_skip(file); /* skip this line */
				break;
			}
			(void) strcpy(incore_master_tail->text + line_begin,
			    tokbuf);
			incore_master_tail->column[mf_column] = line_begin +
			    incore_master_tail->text;
			if (master_ops_debug & MASTER_OPS_DEBUG_PROCESS) {
				printf("master_ops: line=%d column[%x] found:"\
				    " \"%s\"\n",
				    incore_master_table_line_count, mf_column,
				    incore_master_tail->column[mf_column]);
			}
			line_begin += strlen(tokbuf) + 1;
			mf_column++;
			break;
		case EOF: /* end of file */
			if (master_ops_debug & MASTER_OPS_DEBUG_PROCESS) {
				printf("master_ops: EOF found. We're done.\n");
			}
			done = 1;
			break;
		case EOL: /* end of line */
			if (master_ops_debug & MASTER_OPS_DEBUG_PROCESS) {
				printf("master_ops: EOL found.\n");
			}
			mf_column = 0;
			one_master_line_max = 0;
			dup_devices();
			break;
		default: /* something went wrong */
			cmn_err(CE_WARN, "!master_ops: something went wrong "\
			    "parsing master file: %s", tokbuf);
		}
	}
	kobj_close_file(file);

	if (master_ops_debug & MASTER_OPS_DEBUG_PROCESS) {
		printf("master_ops: incore line count: %d\n",
		    incore_master_table_line_count);
		printf("master_ops: total line processed: %d\n",
		    total_line_processed);
	}
	print_incore_master_table();
}

/*
 * Loop and free all per line master data, including line text
 */
void
free_master_data() {
	int i;
	struct master_line *next, *cur = incore_master_head;
	for (i = 0; i < incore_master_table_line_count; i++) {
		next = cur->next;
		if ((cur->text != NULL) && (cur->line_size != 0)) {
			kmem_free(cur->text, cur->line_size);
		}
		kmem_free(cur, sizeof (struct master_line));
		if (next == NULL) {
			break; /* we're done */
		}
			cur = next;
	}
	incore_master_head = incore_master_tail = NULL;
	if (one_master_line) {
		kmem_free(one_master_line, MASTER_LINE_MAX);
	}
}

/*
 *  To match pnpid with master table entries
 *  returns 0 if no matching device found in master file
 *          1 if a matching device is in master file
 *            devname -- device node name
 *            description -- device description string
 *            properties -- device attributes (e.g. compatibility="kb8042")
 *                          (could be NULL)
 */
int
master_file_lookup(char *pnpid, char **devname, char **description,
    char **properties)
{
	struct master_line *cur = incore_master_head;

	ASSERT(pnpid != NULL);

	if (master_ops_debug & MASTER_OPS_DEBUG_LOOKUP)
		printf("master_ops: Looking for %s: ", pnpid);

	while (cur != NULL) {
		if (strcmp(pnpid, cur->column[0]) == 0) {

			*devname = kmem_zalloc(strlen(cur->column[1]) + 1,
			    KM_SLEEP);
			(void) strcpy(*devname, cur->column[1]);
			*description = kmem_zalloc(strlen(cur->column[5]) + 1,
			    KM_SLEEP);
			(void) strcpy(*description, cur->column[5]);
			if (cur->column[6] != NULL) {
				*properties = kmem_zalloc(
				    strlen(cur->column[6]) + 1, KM_SLEEP);
				(void) strcpy(*properties, cur->column[6]);
			} else
				*properties = NULL;

			if (master_ops_debug & MASTER_OPS_DEBUG_LOOKUP) {
				printf("FOUND. dev node name: \"%s\"\n",
				    *devname);
				printf("description: \"%s\"", *description);
				if (*properties != NULL) {
					printf(" properties: \"%s\"\n",
					    *properties);
				} else {
					printf("\n");
				}
			}
			return (1);
		}
		cur = cur->next;
	}
	/* XXX: for the devices not found, they should go to used resources?? */
	if (master_ops_debug & MASTER_OPS_DEBUG_LOOKUP) {
		printf("NOT FOUND!!!\n");
	}
	return (0);
}

/*
 * master_file_lookups() -- processes multiple pnp IDs (CIDs)
 * 	return 1 if a PNP id is matched
 * 	else return 0
 */
int
master_file_lookups(char *pnpid, char **devname, char **description,
    char **properties, int pnpid_size)
{
	char *tmp = pnpid;

	/*
	 * terminate the loop based on pnpid_size.  If pnpid_size
	 * is 0, the loop terminates without ever calling
	 * master_file_lookup(); this happens if there's no
	 * _CID object present
	 */
	while (tmp < pnpid + pnpid_size) {
		int ret = master_file_lookup(tmp, devname, description,
		    properties);
		if (ret == 1) {
			if (master_ops_debug & MASTER_OPS_DEBUG_CID_FOUND) {
				cmn_err(CE_NOTE, "CID found: %s", tmp);
			}
			return (ret); /* a CID is found */
		}
		tmp += strlen(tmp) + 1; /* move on to the next one */
	}
	return (0);
}
