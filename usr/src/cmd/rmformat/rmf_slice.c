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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * rmf_slice.c :
 *	This file contains the functions for parsing a slice file
 *	for rmformat.
 */

#include <sys/types.h>
#include <ctype.h>
#include <sys/vtoc.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <memory.h>
#include <dirent.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/dkio.h>
#include <priv_utils.h>
#include "rmformat.h"

extern void my_perror(char *err_string);

static int32_t	last_token_type = 0;
#define	spc()	  (last_token_type)


/*
 * This global is used to store the current line # in the
 * data file. It must be global because the I/O routines
 * are allowed to side effect it to keep track of backslashed
 * newlines.
 */

static int32_t	data_lineno;		/* current line # in data file */

#define	CHG_MODE_UNDEFINED  (-1)	/* undefined value */
#define	CHG_MODE_SET	0		/* set bits by or'ing */
#define	CHG_MODE_CLR	1		/* clr bits by and'ing */
#define	CHG_MODE_ABS	2		/* set absolute value */


#define	TOKEN_SIZE	36		/* max length of a token */
typedef char TOKEN[TOKEN_SIZE+1];	/* token type */
#define	DATA_INPUT	0		/* 2 modes of input */
#define	CMD_INPUT	1
#define	WILD_STRING	"$"		/* wildcard character */
#define	COMMENT_CHAR	'#'		/* comment character */

/*
 * List of strings with arbitrary matching values
 */
typedef struct slist {
	char	*str;
	char	*help;
	int32_t	value;
} slist_t;

static slist_t ptag_choices[] = {
	{ "unassigned", "",	V_UNASSIGNED	},
	{ "boot",	"",	V_BOOT		},
	{ "root",	"",	V_ROOT		},
	{ "swap",	"",	V_SWAP		},
	{ "usr",	"",	V_USR		},
	{ "backup",	"",	V_BACKUP	},
	{ "stand",	"",	V_STAND		},
	{ "var",	"",	V_VAR		},
	{ "home",	"",	V_HOME		},
	{ "alternates", "",	V_ALTSCTR	},
	{ NULL }
};


/*
 * Choices for the p_flag vtoc field
 */
static slist_t pflag_choices[] = {
	{ "wm", "read-write, mountable",	0	},
	{ "wu", "read-write, unmountable",	V_UNMNT	},
	{ "rm", "read-only, mountable",		V_RONLY	},
	{ "ru", "read-only, unmountable",	V_RONLY|V_UNMNT },
	{ NULL }
};

/*
 * The definitions are the token types that the data file parser recognizes.
 */
#define	SUP_EOF			-1		/* eof token */
#define	SUP_STRING		0		/* string token */
#define	SUP_EQL			1		/* equals token */
#define	SUP_COMMA		2		/* comma token */
#define	SUP_COLON		3		/* colon token */
#define	SUP_EOL			4		/* newline token */
#define	SUP_OR			5		/* vertical bar */
#define	SUP_AND			6		/* ampersand */
#define	SUP_TILDE		7		/* tilde */


/*
 *	Prototypes for ANSI C compilers
 */
static int32_t	sup_prxfile(char *file_name, struct extvtoc *vt);
static int32_t	sup_setpart(struct extvtoc *vt);
static void	sup_pushchar(int32_t c);
static void	clean_token(char *cleantoken, char *token);
static void clean_token(char *cleantoken, char *token);
static int32_t sup_inputchar();
static int32_t sup_gettoken(char *buf);
static int32_t sup_get_token(char *buf);
static int32_t find_value(slist_t *slist, char *str, int32_t *value);
static int32_t check_vtoc_sanity(smedia_handle_t, int32_t fd,
		struct extvtoc *vt);
static uint64_t str2sector(char *str);
static int32_t strcnt(char *s1, char *s2);
static int32_t get_fdisk(smedia_handle_t, int32_t fd, int32_t offset,
		struct fdisk_info *fdisk);
static void erase(smedia_handle_t handle, diskaddr_t offset, diskaddr_t size);

extern char *myname;
extern uint64_t my_atoll(char *ptr);
extern smmedium_prop_t med_info;

static FILE *data_file;

static int32_t
sup_prxfile(char *file_name, struct extvtoc *vt)
{
	int32_t	status, ret_val;
	TOKEN	token;
	TOKEN	cleaned;

	/*
	 * Open the data file.  Return 0 if unable to do so.
	 */
	data_file = fopen(file_name, "r");
	if (data_file == NULL) {
		PERROR("Open failed");
		return (-1);
	}
	/*
	 * Step through the data file a meta-line at a time.  There are
	 * typically several backslashed newlines in each meta-line,
	 * so data_lineno will be getting side effected along the way.
	 */
	data_lineno = 1;
	for (;;) {

		/*
		 * Get the keyword.
		 */
		status = sup_gettoken(token);
		/*
		 * If we hit the end of the data file, we're done.
		 */
		if (status == SUP_EOF)
			break;
		/*
		 * If the line starts with some key character, it's an error.
		 */
		if (status != SUP_STRING) {
			(void) fprintf(stderr,
			    gettext("Expecting keyword, found '%s'"),
			    token);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
			continue;
		}
		/*
		 * Clean up the token and see which keyword it is.  Call
		 * the appropriate routine to process the rest of the line.
		 */
		clean_token(cleaned, token);
		if (strcmp(cleaned, "slices") == 0) {
			ret_val = sup_setpart(vt);
			(void) fclose(data_file);
			return (ret_val);
		} else {
			(void) fprintf(stderr, gettext("Unknown keyword '%s'"),
			    cleaned);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
			(void) fclose(data_file);
			return (-1);
		}
	}
	/*
	 * Close the data file.
	 */
	(void) fclose(data_file);

	(void) fprintf(stderr,
	    gettext("Unexpected end of file (line no %d)\n"), data_lineno);
	return (-1);
}

static int32_t
sup_gettoken(char *buf)
{
	/*
	 * Skip end of lines and blank lines.
	 */
	while ((last_token_type = sup_get_token(buf)) == SUP_EOL)
			;
	return (last_token_type);
}

static int32_t
sup_get_token(char *buf)
{
	char	*ptr = buf;
	int32_t	c, quoted = 0;

	/*
	 * Was an end of file detected last try?
	 */

	if (feof(data_file)) {
		return (SUP_EOF);
	}

	/*
	 * Zero out the returned token buffer
	 */

	bzero(buf, TOKEN_SIZE + 1);

	/*
	 * Strip off leading white-space.
	 */
	while (isspace(c = sup_inputchar()))
		;

	/*
	 * Only white spaces and then end of file?
	 */

	if (feof(data_file)) {
		return (SUP_EOF);
	}

	/*
	 * Read in characters until we hit unquoted white-space.
	 */
	for (; !isspace(c) || quoted; c = sup_inputchar()) {

		/*
		 * If we hit eof, check if we have anything in buffer.
		 * if we have, return STRING, next time we will return EOF
		 * else, return EOF here...should not happen.
		 */
		if (feof(data_file)) {
			if (ptr - buf > 0) {
				return (SUP_STRING);
			} else {
				return (SUP_EOF);
			}
		}

		/*
		 * If we hit a double quote, change the state of quoting.
		 */
		if (c == '"') {
			quoted = !quoted;
			continue;
		}
		/*
		 * If we hit a newline, that delimits a token.
		 */
		if (c == '\n')
			break;
		/*
		 * If we hit any nonquoted special delimiters, that delimits
		 * a token.
		 */
		if (!quoted && (c == '=' || c == ',' || c == ':' ||
		    c == '#' || c == '|' || c == '&' || c == '~'))
				break;
		/*
		 * Store the character if there's room left.
		 */
		if (ptr - buf < TOKEN_SIZE)
			*ptr++ = (char)c;
	}
	/*
	 * If we stored characters in the buffer, then we inputted a string.
	 * Push the delimiter back into the pipe and return the string.
	 */
	if (ptr - buf > 0) {
		sup_pushchar(c);
		return (SUP_STRING);
	}
	/*
	 * We didn't input a string, so we must have inputted a known delimiter.
	 * store the delimiter in the buffer, so it will get returned.
	 */
	buf[0] = c;
	/*
	 * Switch on the delimiter.  Return the appropriate value for each one.
	 */
	switch (c) {
	case '=':
		return (SUP_EQL);
	case ':':
		return (SUP_COLON);
	case ',':
		return (SUP_COMMA);
	case '\n':
		return (SUP_EOL);
	case '|':
		return (SUP_OR);
	case '&':
		return (SUP_AND);
	case '~':
		return (SUP_TILDE);
	case '#':
		/*
		 * For comments, we flush out the rest of the line and return
		 * an eol.
		 */
		while ((c = sup_inputchar()) != '\n' && !feof(data_file))
			;
		if (feof(data_file))
			return (SUP_EOF);
		else
			return (SUP_EOL);
	/*
	 * Shouldn't ever get here.
	 */
	default:
		return (SUP_STRING);
	}
}
static int32_t
sup_inputchar()
{
	int32_t	c;

	/*
	 * Input the character.
	 */
	c = getc(data_file);
	/*
	 * If it's not a backslash, return it.
	 */

	/*
	 * It was a backslash.  Get the next character.
	 */

	if (c == '\\')
		c = getc(data_file);

	/*
	 * If it was a newline, update the line counter and get the next
	 * character.
	 */
	if (c == '\n') {
		data_lineno++;
	}
	/*
	 * Return the character.
	 */
	return (c);
}

static void
sup_pushchar(int32_t c)
{

	(void) ungetc(c, data_file);
	if (c == '\n')
		data_lineno--;
}

static void
clean_token(char *cleantoken, char *token)
{
	char	*ptr;

	/*
	 * Strip off leading white-space.
	 */
	for (ptr = token; isspace(*ptr) && (ptr <=
	    (token + strlen(token) - 1)); ptr++)
		;

	/*
	 * Copy it into the clean buffer.
	 */
	(void) strcpy(cleantoken, ptr);
	/*
	 * Strip off trailing white-space.
	 */
	for (ptr = cleantoken + strlen(cleantoken) - 1;
	    isspace(*ptr) && (ptr >= cleantoken); ptr--) {
		*ptr = '\0';
	}
}

static int32_t
sup_setpart(struct extvtoc *vt)
{
	TOKEN	token, cleaned, ident;
	int32_t	i, index, status;
	uint64_t	val1, val2;
	ushort_t	vtoc_tag = 0xFFFF;
	ushort_t	vtoc_flag = 0xFFFF;

	/*
	 * Pull in some grammar.
	 */

		status = sup_gettoken(token);

		if (status != SUP_COLON) {
			(void) fprintf(stderr,
			    gettext("Expecting ':', found '%s'"), token);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
			return (-1);
		}

	for (;;) {
		status = sup_gettoken(token);
		if (status != SUP_STRING) {
			(void) fprintf(stderr,
			    gettext("Expecting string, found '%s'"), token);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
			return (-1);
		}
		clean_token(ident, token);
		/*
		 * Here's the index of the partition we're dealing with
		 */
		index = (int32_t)my_atoll(ident);
		if ((index < 0) || (index >= NDKMAP)) {
			(void) fprintf(stderr,
			    gettext("Unknown partition %d"), index);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
			return (-1);
		}
		/*
		 * Check for floppy and PCMCIA_MEM cards.
		 * for floppy, the partition no. can be 0 1 2.
		 * for PCMCIA, the partition no. can be 2
		 */
		if (med_info.sm_media_type == SM_FLOPPY) {
			if ((index < 0) || (index > 2)) {
				(void) fprintf(stderr, gettext(
			"Floppy can have partitions 0 1 and 2\n"));
				return (-1);
			}
		}
		if (med_info.sm_media_type == SM_PCMCIA_MEM) {
			if (index != 2) {
				(void) fprintf(stderr, gettext(
			"PCMCIA Memory cards can have partition 2 only.\n"));
				return (-1);
			}
		}

		DPRINTF1("\n Partition %d: ", index);

		status = sup_gettoken(token);
		if (status != SUP_EQL) {
			(void) fprintf(stderr,
			    gettext("Expecting '=', found '%s'"), token);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
			return (-1);

		}


		status = sup_gettoken(token);
		/*
		 * If we hit a key character, it's an error.
		 */
		if (status != SUP_STRING) {
			(void) fprintf(stderr,
			    gettext("Expecting value, found '%s'"), token);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
			return (-1);
		}
		clean_token(cleaned, token);
		/*
		 * <tag> may be one of: boot, root, swap, etc.
		 * <flag> consists of two characters:
		 *	W (writable) or R (read-only)
		 *	M (mountable) or U (unmountable)
		 *
		 * Start with the defaults assigned above:
		 */

		/*
		 * All other attributes have a pair of numeric values.
		 * Convert the first value to a number.  This value
		 * is the starting cylinder number of the partition.
		 */

		/* Check for valid partition, e.g. > 8 or 16 */
		val1 = str2sector(cleaned);
		if (val1 == -1) {
			(void) fprintf(stderr,
			    gettext("Invalid partition beggining %s \n"),
			    cleaned);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
		}

		DPRINTF1(" begins %s", cleaned);
		/*
		 * Pull in some grammar.
		 */
		status = sup_gettoken(token);
		if (status != SUP_COMMA) {
			(void) fprintf(stderr,
			    gettext("Expecting ', ', found '%s'"), token);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
			return (-1);
		}
		/*
		 * Pull in the second value.
		 */
		status = sup_gettoken(token);
		if (status != SUP_STRING) {
			(void) fprintf(stderr,
			    gettext("Expecting value, found '%s'"), token);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
			return (-1);
		}
		clean_token(cleaned, token);

		val2 = str2sector(cleaned);
		if (val2 == -1) {
			(void) fprintf(stderr,
			    gettext("Invalid partition size %s \n"),
			    cleaned);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
		}
		DPRINTF1(" ends %s ", cleaned);

		/*
		 * Pull in some grammar.
		 */
		status = sup_gettoken(token);

		if (status == SUP_COMMA) {
			/* tags and flags  */
			status = sup_gettoken(token);
			if (status != SUP_STRING) {
				(void) fprintf(stderr,
				    gettext("Expecting value, found '%s'"),
				    token);
				(void) fprintf(stderr,
				    gettext("Line no %d\n"), data_lineno);
				return (-1);
			}
			clean_token(cleaned, token);
			if (find_value(pflag_choices, cleaned, &i) == 1) {
				/*
				 * Found valid tag. Use it and advance parser
				 */
				DPRINTF1(" flag = %s", cleaned);
				vtoc_flag = (ushort_t)i;
				status = sup_gettoken(token);
			} else if (find_value(ptag_choices, cleaned, &i) == 1) {
				DPRINTF1(" tag = %s", cleaned);
				vtoc_tag = (ushort_t)i;
				status = sup_gettoken(token);
				if (status == SUP_COMMA) {
					(void) fprintf(stderr,
					    gettext("Expecting : got %s\n"),
					    token);
					(void) fprintf(stderr,
					    gettext("Line no %d\n"),
					    data_lineno);
					return (-1);
				}
			} else {
				(void) fprintf(stderr,
				    gettext("Invalid flag or tag\n"));
				(void) fprintf(stderr,
				    gettext("Line no %d\n"), data_lineno);
				return (-1);
			}


			if (status == SUP_COMMA) {
					/* Can be tag only */

					status = sup_gettoken(token);
					if (status != SUP_STRING) {
						(void) fprintf(stderr,
						    gettext("Expecting value"
						    ", found '%s'"),
						    token);
						(void) fprintf(stderr,
						    gettext("Line no %d\n"),
						    data_lineno);
						return (-1);
					}

					clean_token(cleaned, token);
					if (find_value(ptag_choices,
					    cleaned, &i) == 1) {
						DPRINTF1(" tag = %s", cleaned);
						vtoc_tag = (ushort_t)i;
					}
			status = sup_gettoken(token);
			}
		}

		/*
		 * Fill in the appropriate map entry with the values.
		 */
		vt->v_part[index].p_start = val1;
		vt->v_part[index].p_size = val2;
		if (vtoc_tag != 0xFFFF) {
			vt->v_part[index].p_tag = vtoc_tag;
			vtoc_tag = 0xFFFF;
		}
		if (vtoc_flag != 0xFFFF) {
			vt->v_part[index].p_flag = vtoc_flag;
			vtoc_flag = 0xFFFF;
		}
		if (status == SUP_EOF) {
			DPRINTF("\nEnd of file\n");
			break;
		}
		if (status != SUP_COLON) {
			(void) fprintf(stderr,
			    gettext("Expecting ':', found '%s'"), token);
			(void) fprintf(stderr,
			    gettext("Line no %d\n"), data_lineno);
			return (-1);
		}

	}
	return (0);
}

static int32_t
find_value(slist_t *slist, char *match_str, int32_t *match_value)
{
	int32_t	i;
	int32_t	nmatches;
	int32_t	length;
	int32_t	match_length;

	nmatches = 0;
	length = 0;

	match_length = strlen(match_str);

	for (; slist->str != NULL; slist++) {
		/*
		 * See how many characters of the token match
		 */
		i = strcnt(match_str, slist->str);
		/*
		 * If it's not the whole token, then it's not a match.
		 */
		if (i  < match_length) {
			continue;
		}
		/*
		 * If it ties with another input, remember that.
		 */
		if (i == length)
			nmatches++;
		/*
		 * If it matches the most so far, record that.
		 */
		if (i > length) {
			*match_value = slist->value;
			nmatches = 1;
			length = i;
		}
	}

	return (nmatches);
}

static int32_t
strcnt(char	*s1, char *s2)
{
	int32_t	i = 0;

	while ((*s1 != '\0') && (*s1++ == *s2++))
		i++;
	return (i);
}

static uint64_t
str2sector(char *str)
{
	int32_t mul_factor = 1;
	char *s1, *s2, *base;
	uint64_t num_sectors;
	uint64_t size;

	base = s2 = (char *)malloc(strlen(str) + 1);
	if (s2 == NULL) {
		PERROR("Malloc failed");
		return (-1);
	}
	*s2 = '\0';



	s1 = str;
	while (*s1) {
		if ((*s1 != 'x') && ((*s1 < 'A') || (*s1 > 'F')) &&
		    ((*s1 < 'a') || (*s1 > 'f')) && ((*s1 < '0') ||
		    (*s1 > '9'))) {
			if (*s1 == 'G') {
					mul_factor = 1024*1024*1024;
					s1++;
			} else if (*s1 == 'M') {
					mul_factor = 1024*1024;
					s1++;
			} else if (*s1 == 'K') {
					mul_factor = 1024;
					s1++;
			}
			if ((*s1 != 'B') || (*(++s1) != NULL)) {
				(void) fprintf(stderr,
				    gettext("Extra chars at the end\n"));
				free(base);
				return (-1);
			}
			break;
		} else {
			*s2++ = *s1++;
			*s2 = '\0';
		}
	}
	*s2 = NULL;

	size = my_atoll(base);
	if ((!mul_factor) || (size == -1)) {
		free(base);
		return (-1);
	}
	num_sectors = size * (uint64_t)mul_factor /512;

	free(base);
	return (num_sectors);
}


int32_t
valid_slice_file(smedia_handle_t handle, int32_t fd, char *file_name,
    struct extvtoc *vt)
{
	struct stat status;
	int32_t ret_val;
	if (stat(file_name, &status)) {
		PERROR(file_name);
		return (-1);
	}
	(void) memset(vt, 0, sizeof (*vt));
	/* Set default tag and flag */
#ifdef sparc
	vt->v_part[0].p_tag = V_ROOT;
	vt->v_part[1].p_tag = V_SWAP;
	vt->v_part[2].p_tag = V_BACKUP;
	vt->v_part[6].p_tag = V_USR;

	vt->v_part[1].p_flag = V_UNMNT; /* Unmountable */
	vt->v_part[2].p_flag = V_UNMNT; /* Unmountable */
#endif

	ret_val = sup_prxfile(file_name, vt);
	if (ret_val < 0)
		return (-1);

#ifdef DEBUG
{
	int32_t i;
	for (i = 0; i < 8; i++) {
		DPRINTF1("\npart %d\n", i);
		DPRINTF1("\t start %llu",  vt->v_part[i].p_start);
		DPRINTF1("\t size %llu ", vt->v_part[i].p_size);
		DPRINTF1("\t tag %d", vt->v_part[i].p_tag);
		DPRINTF1("\t flag %d", vt->v_part[i].p_flag);
	}
}
#endif /* DEBUG */
	if (check_vtoc_sanity(handle, fd, vt) < 0) {
		return (-1);
	}
#ifdef DEBUG
{
	int32_t i;
	for (i = 0; i < 8; i++) {
		DPRINTF1("\npart %d\n", i);
		DPRINTF1("\t start %llu",  vt->v_part[i].p_start);
		DPRINTF1("\t size %llu ", vt->v_part[i].p_size);
		DPRINTF1("\t tag %d", vt->v_part[i].p_tag);
		DPRINTF1("\t flag %d", vt->v_part[i].p_flag);
	}
}
#endif /* DEBUG */
	return (0);
}

#define	SWAP(a, b)	{diskaddr_t tmp; tmp = (a); (a) = (b); (b) = tmp; }

/*
 * On x86 Solaris, the partitioning is done in two levels, fdisk and Solaris
 * VTOC. Where as, on sparc solaris, it is only VTOC. On floppy and PCMCIA
 * also it is assumed to be only VTOC, no fdisk.
 *
 * On sparc, the back up slice can cover the whole medium. But on x86
 * (SCSI/ATAPI disks), the backup slice can cover the solaris partition
 * in fdisk table.
 *	Following table describes how is it handled
 * SPARC:
 *	SCSI/ATAPI, floppy, pcmcia : don't check for fdisk.
 *				DKIOCGGEOM is sufficient.
 * x86 : floppy, pcmcia : Don't check for fdisk. DKIOCGGEOM is sufficient.
 *	SCSI/ATAPI : Check for fdisk.
 *			if not present, assume that the solaris
 *				partition covers 100% of the medium
 *				(minus one cylinder).
 *
 *		if present :
 *				check for active solaris partition.
 *				if not found, take the first solaris
 *					partition.
 *			If there are no solaris partitions, its an error, stop.
 */

static int32_t
check_vtoc_sanity(smedia_handle_t handle, int32_t fd, struct extvtoc *vt)
{

	int32_t i, j;
	struct dk_geom dkg;
	int32_t num_backup = 0;
	diskaddr_t backup_size = 0;
	struct part_struct {
		diskaddr_t start;
		diskaddr_t end;
		int32_t num;
	} part[NDKMAP];
	diskaddr_t min_val;
	int32_t min_slice, num_slices;
	diskaddr_t media_size;
	uint32_t cyl_size;
	int sparc_style = 0;	/* sparc_style handling ? */
	struct fdisk_info fdisk;
	int sol_part;
	int total_parts = 0;

#ifdef sparc
	sparc_style = 1;
#endif /* sparc */

	if ((med_info.sm_media_type == SM_FLOPPY) ||
	    (med_info.sm_media_type == SM_PCMCIA_MEM) ||
	    (med_info.sm_media_type == SM_PCMCIA_ATA) ||
	    (med_info.sm_media_type == SM_SCSI_FLOPPY)) {
		sparc_style = 1;
	}

	if (sparc_style) {
		DPRINTF("sparc style true\n");
		if (ioctl(fd, DKIOCGGEOM, &dkg) < 0) {
			PERROR("DKIOCGGEOM Failed");
			return (-1);
		}
		media_size = (diskaddr_t)dkg.dkg_ncyl * dkg.dkg_nhead *
		    dkg.dkg_nsect;
		cyl_size = dkg.dkg_nhead * dkg.dkg_nsect;
	}

	if (!sparc_style) {
	/*
	 * Try to get the fdisk information if available.
	 */
		if (get_fdisk(handle, fd, 0, &fdisk) >= 0) {
			/* fdisk table on disk */
			sol_part = 0xFF;
			for (i = 0; i < FD_NUMPART; i++) {
				if (fdisk.part[i].systid == SUNIXOS ||
				    fdisk.part[i].systid == SUNIXOS2) {
					if (sol_part == 0xFF)
						sol_part = i;
					total_parts++;
					if (fdisk.part[i].bootid == ACTIVE)
						sol_part = i;
				}
			}
			if (sol_part == 0xFF) {
				/* No Solaris partition */

				(void) fprintf(stderr, gettext("No FDISK \
Solaris partition found!\n"));
				return (-1);
			}
			if (total_parts > 1)
				(void) fprintf(stderr, gettext("Multiple FDISK \
Solaris partitions found.\n"));
			media_size = (diskaddr_t)fdisk.part[sol_part].numsect;

			DPRINTF1("sol_part %d\n", sol_part);
			DPRINTF1("media_size %llu\n", media_size);
		} else {
			DPRINTF("Didn't get fdisk\n");
			/*
			 * No fdisk partition available. Assume a 100% Solaris.
			 * partition.
			 * Try getting disk geometry.
			 */
			if (ioctl(fd, DKIOCGGEOM, &dkg) < 0)
				if (ioctl(fd, DKIOCG_PHYGEOM, &dkg) < 0) {
					DPRINTF("DKIOCG_PHYGEOM ioctl failed");
					return (-1);
			}
			/* On x86 platform 1 cylinder is used for fdisk table */
			dkg.dkg_ncyl = dkg.dkg_ncyl - 1;
			media_size = (diskaddr_t)dkg.dkg_ncyl * dkg.dkg_nhead *
			    dkg.dkg_nsect;
		}
	}

#ifdef DEBUG
	DPRINTF1("Ncyl %d\n", dkg.dkg_ncyl);
	DPRINTF1("nhead %d\n", dkg.dkg_nhead);
	DPRINTF1("nsect %d\n", dkg.dkg_nsect);
#endif /* DEBUG */

	if (media_size == 0) {
		media_size = (uint32_t)med_info.sm_capacity;
	}

	(void) memset(&part, 0, sizeof (part));
	for (i = 0, j = 0; i < NDKMAP; i++) {
		if (vt->v_part[i].p_tag == V_BACKUP) {
			if (vt->v_part[i].p_start != 0) {
				(void) fprintf(stderr,
				    gettext(
			"Backup slice should start at sector 0\n"));
			return (-1);
			}
			backup_size = vt->v_part[i].p_size;
			num_backup++;
			continue;
		}
		if (vt->v_part[i].p_size) {

			if (sparc_style) {
				if (vt->v_part[i].p_start % cyl_size) {
					(void) fprintf(stderr,
					    gettext(
			"Slice %d does not start on cylinder boundary\n"), i);
					(void) fprintf(stderr,
					    gettext(
			"Cylinder size %d 512 byte sectors\n"), cyl_size);
					return (-1);
				}
			}
			part[j].start = vt->v_part[i].p_start;
			part[j].end = vt->v_part[i].p_start +
			    vt->v_part[i].p_size -1;
			part[j].num = i;
			j++;
		}
	}
	if (num_backup > 1) {
		(void) fprintf(stderr,
		    gettext("Maximum one backup slice is allowed\n"));
		(void) smedia_release_handle(handle);
		(void) close(fd);
		exit(1);
	}
	num_slices = j;

	for (i = 0; i < num_slices; i++) {
		min_val = part[i].start;
		min_slice = i;
		for (j = i+1; j < num_slices; j++) {
			if (part[j].start < min_val) {
				min_val = part[j].start;
				min_slice = j;
			}
		}
		if (min_slice != i) {
			SWAP(part[i].start, part[min_slice].start)
			SWAP(part[i].end, part[min_slice].end)
			SWAP(part[i].num, part[min_slice].num)
		}
	}

#ifdef DEBUG
	for (i = 0; i < num_slices; i++) {
		DPRINTF4("\n %d (%d) : %llu, %llu", i, part[i].num,
		    part[i].start, part[i].end);
	}
#endif /* DEBUG */

	if (backup_size > media_size) {
		if (sparc_style) {
			(void) fprintf(stderr,
			    gettext(
			"Backup slice extends beyond size of media\n"));
			(void) fprintf(stderr,
			    gettext("media size : %llu sectors \n"),
			    media_size);
		} else {

			(void) fprintf(stderr,
			    gettext("Backup slice extends beyond size of FDISK \
Solaris partition\n"));
			(void) fprintf(stderr,
			    gettext(
			"FDISK Solaris partition size : %llu sectors \n"),
			    media_size);
		}
		return (-1);
	}

	/*
	 * If we have only backup slice return success here.
	 */
	if (num_slices == 0)
		return (0);

	if (backup_size) {
		if (part[num_slices - 1].end > backup_size) {
			(void) fprintf(stderr,
			    gettext("Slice %d extends beyond backup slice.\n"),
			    part[num_slices -1].num);
			return (-1);
		}
	} else {
		if (part[num_slices - 1].end > media_size) {
			if (sparc_style) {
				(void) fprintf(stderr,
				    gettext(
				"Slice %d extends beyond media size\n"),
				    part[num_slices -1].num);
				(void) fprintf(stderr,
				    gettext("media size : %llu sectors \n"),
				    media_size);
			} else {
				(void) fprintf(stderr,
				    gettext("Slice %d extends beyond FDISK"
				    " Solaris partition size\n"),
				    part[num_slices -1].num);
				(void) fprintf(stderr, gettext(
				    "FDISK Solaris partition size : %llu "
				    "sectors \n"), media_size);
			}
			return (-1);
		}
	}



	for (i = 0; i < num_slices; i++) {
		if (i == 0)
			continue;
		if (part[i].start <= part[i-1].end) {
			(void) fprintf(stderr,
			    gettext("Overlap between slices %d and %d\n"),
			    part[i-1].num, part[i].num);
			(void) smedia_release_handle(handle);
			(void) close(fd);
			exit(1);
		}
	}

	return (0);
}


static int32_t
get_fdisk(smedia_handle_t handle, int32_t fd, int32_t offset,
    struct fdisk_info *fdisk)
{
	struct mboot *boot_sec;
	struct ipart *part;
	char *buf;
	int32_t i, ret;
	int	save_errno;

	/* Read the master boot program */

	buf = (char *)malloc(med_info.sm_blocksize);
	if (buf == NULL) {
		PERROR("malloc failed");
		exit(1);
	}
	errno = 0;
	ret = ioctl(fd, DKIOCGMBOOT, buf);
	if (ret < 0) {
		if (errno != ENOTTY) {
			PERROR("DKIOCGMBOOT ioctl failed");
			return (-1);
		}

		/* Turn on privileges. */
		(void) __priv_bracket(PRIV_ON);

		ret = smedia_raw_read(handle,
		    (diskaddr_t)offset/med_info.sm_blocksize,
		    buf, med_info.sm_blocksize);

		/* Turn off privileges. */
		(void) __priv_bracket(PRIV_OFF);

		save_errno = errno;
		errno = save_errno;
		if (ret != med_info.sm_blocksize) {
			if (errno == ENOTSUP) {
				errno = 0;
				if (lseek(fd, offset, SEEK_SET)) {
					PERROR("Seek failed:");
					free(buf);
					return (-1);
				}

				/* Turn on privileges. */
				(void) __priv_bracket(PRIV_ON);

				ret = read(fd, buf, sizeof (struct mboot));

				/* Turn off privileges. */
				(void) __priv_bracket(PRIV_OFF);

				if (ret != sizeof (struct mboot)) {
					PERROR("Could not read "
					    "master boot record");
					free(buf);
					return (-1);
				}
			} else {
				PERROR("Could not read master boot record");
				free(buf);
				return (-1);
			}
		}
	}
	/* LINTED pointer cast may result in improper alignment */
	boot_sec = (struct mboot *)buf;

	/* Is this really a master boot record? */
	if (les(boot_sec->signature) != MBB_MAGIC) {
		DPRINTF("fdisk: Invalid master boot file \n");
		DPRINTF2("Bad magic number: is %x, should be %x.\n",
		    les(boot_sec->signature), MBB_MAGIC);
		free(buf);
		return (-1);
	}

	for (i = 0; i < FD_NUMPART; i++) {
		DPRINTF1("part %d\n", i);
		/* LINTED pointer cast may result in improper alignment */
		part = (struct ipart *)&boot_sec->parts[i *
		    sizeof (struct ipart)];
		fdisk->part[i].bootid = part->bootid;
		if (part->bootid && (part->bootid != ACTIVE)) {
			/* Hmmm...not a valid fdisk! */
			return (-1);
		}
		fdisk->part[i].systid = part->systid;

		/* To avoid the misalign access in sparc */

		fdisk->part[i].relsect = lel(GET_32(&(part->relsect)));
		fdisk->part[i].numsect = lel(GET_32(&(part->numsect)));

		DPRINTF1("\tboot id 0x%x\n", part->bootid);
		DPRINTF1("\tsystem id 0x%x\n", part->systid);
		DPRINTF1("\trel sector 0x%x\n", fdisk->part[i].relsect);
		DPRINTF1("\tnum sector 0x%x\n", fdisk->part[i].numsect);
	}
	free(buf);
	return (0);
}


/*
 * wrrite_defualt_label(int32_t fd)
 *	fd = file descriptor for the device.
 *
 * For sparc solaris
 *	Create a vtoc partition with
 *		slice 0 = slice 2 = medium capacity.
 *	The cyl, head, sect (CHS) values are computed as done in sd
 *	capacity <= 1GB,
 *		nhead = 64, nsect = 32
 *	capacity > 1gb,
 *		nhead = 255, nsect = 63
 *
 * For x86 solaris
 *	Create a fdisk partition,
 *		partition 0 covers the full medium, the partition
 *		type is set to Solaris.
 *	Then create solaris vtoc. The algorithm is same as sparc solaris.
 *	But the capacity is reduced by 1 cyl, to leave space for fdisk table.
 */

#ifdef sparc
/*ARGSUSED*/
void
write_default_label(smedia_handle_t handle, int32_t fd)
{

	struct extvtoc v_toc;
	uint32_t nhead, numcyl, nsect;
	diskaddr_t capacity;
	int32_t ret;
	char asciilabel[LEN_DKL_ASCII];
	char asciilabel2[LEN_DKL_ASCII] = "DEFAULT\0";
	uint32_t acyl = 2;


	DPRINTF("Writing default vtoc\n");
	(void) memset(&v_toc, 0, sizeof (v_toc));


	v_toc.v_nparts = V_NUMPAR;
	v_toc.v_sanity = VTOC_SANE;
	v_toc.v_version = V_VERSION;
	v_toc.v_sectorsz = DEV_BSIZE;

	/*
	 * For the head, cyl and number of sector per track,
	 * if the capacity <= 1GB, head = 64, sect = 32.
	 * else head = 255, sect 63
	 * NOTE: the capacity should be equal to C*H*S values.
	 * This will cause some truncation of size due to
	 * round off errors.
	 */
	if ((uint32_t)med_info.sm_capacity <= 0x200000) {
		nhead = 64;
		nsect = 32;
	} else {
		nhead = 255;
		nsect = 63;
	}

	numcyl = (uint32_t)med_info.sm_capacity / (nhead * nsect);
	capacity = (diskaddr_t)nhead * nsect * numcyl;

	v_toc.v_part[0].p_start = 0;
	v_toc.v_part[0].p_size = capacity;
	v_toc.v_part[0].p_tag  = V_ROOT;
	v_toc.v_part[0].p_flag = 0;	/* Mountable */

	v_toc.v_part[2].p_start = 0;
	v_toc.v_part[2].p_size = capacity;
	v_toc.v_part[2].p_tag  = V_BACKUP;
	v_toc.v_part[2].p_flag = V_UNMNT;

	/* Create asciilabel for compatibility with format utility */
	(void) snprintf(asciilabel, sizeof (asciilabel),
	    "%s cyl %d alt %d hd %d sec %d",
	    asciilabel2, numcyl, acyl, nhead, nsect);
	(void) memcpy(v_toc.v_asciilabel, asciilabel,
	    LEN_DKL_ASCII);

	errno = 0;

	/* Turn on privileges. */
	(void) __priv_bracket(PRIV_ON);

	ret = write_extvtoc(fd, &v_toc);

	/* Turn off privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (ret < 0) {
		PERROR("write VTOC failed");
		DPRINTF1("Errno = %d\n", errno);
	}
}

#else /* !sparc */
#ifdef i386

void
write_default_label(smedia_handle_t handle, int32_t fd)
{

	int32_t i, ret;
	struct dk_geom  dkg;
	struct extvtoc v_toc;
	int tmp_fd;
	char *fdisk_buf;
	struct mboot boot_code;		/* Buffer for master boot record */
	struct ipart parts[FD_NUMPART];
	uint32_t numcyl, nhead, nsect;
	uint32_t unixend;
	uint32_t blocksize;
	diskaddr_t capacity;
	int	save_errno;
	size_t	bytes_written;
	char asciilabel[LEN_DKL_ASCII];
	char asciilabel2[LEN_DKL_ASCII] = "DEFAULT\0";
	uint32_t acyl = 2;

	DPRINTF("Writing default fdisk table and vtoc\n");
	(void) memset(&v_toc, 0, sizeof (v_toc));
	/*
	 * Try getting disk geometry.
	 */
	if (ioctl(fd, DKIOCGGEOM, &dkg) < 0)
		if (ioctl(fd, DKIOCG_PHYGEOM, &dkg) < 0) {

			DPRINTF("DKIOCG_PHYGEOM ioctl failed");
			return;
	}

	tmp_fd = open("/boot/pmbr", O_RDONLY);
	if (tmp_fd <= 0) {
		return;
	}

	if (read(tmp_fd, &boot_code, sizeof (struct mboot))
			!= sizeof (struct mboot)) {
		(void) close(tmp_fd);
		return;
	}

	blocksize = med_info.sm_blocksize;
	fdisk_buf = (char *)malloc(blocksize);
	if (fdisk_buf == NULL) {
		DPRINTF("malloc for fdisk_buf failed\n");
		return;
	}

	(void) memset(&parts, 0, sizeof (parts));

	for (i = 0; i < FD_NUMPART; i++) {
		parts[i].systid = UNUSED;
		parts[i].numsect = lel(UNUSED);
		parts[i].relsect = lel(UNUSED);
		parts[i].bootid = 0;
	}

	numcyl = dkg.dkg_ncyl;
	nhead = dkg.dkg_nhead;
	nsect = dkg.dkg_nsect;

	parts[0].bootid = ACTIVE;
	parts[0].begsect = 1;

	unixend = numcyl;

	parts[0].relsect = lel(nhead * nsect);
	parts[0].numsect = lel(((diskaddr_t)numcyl * nhead * nsect));
	parts[0].systid = SUNIXOS2;   /* Solaris */
	parts[0].beghead = 0;
	parts[0].begcyl = 1;
	parts[0].endhead = nhead - 1;
	parts[0].endsect = (nsect & 0x3f) |
	    (char)((unixend >> 2) & 0x00c0);
	parts[0].endcyl = (char)(unixend & 0x00ff);

	(void) memcpy(&(boot_code.parts), parts, sizeof (parts));
	(void) memcpy(fdisk_buf, &boot_code, sizeof (boot_code));

	/* Turn on privileges. */
	(void) __priv_bracket(PRIV_ON);

	ret = ioctl(fd, DKIOCSMBOOT, fdisk_buf);

	/* Turn off privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (ret == -1) {
		if (errno != ENOTTY) {
			PERROR("DKIOCSMBOOT ioctl Failed");
			return;
		}

		/* Turn on privileges. */
		(void) __priv_bracket(PRIV_ON);

		bytes_written = smedia_raw_write(handle, (diskaddr_t)0,
		    fdisk_buf, blocksize);

		/* Turn off privileges. */
		(void) __priv_bracket(PRIV_OFF);

		save_errno = errno;
		errno = save_errno;
		if (bytes_written != blocksize) {
			if (errno == ENOTSUP) {

			    /* Turn on privileges. */
				(void) __priv_bracket(PRIV_ON);

				ret = write(fd, fdisk_buf, blocksize);

			    /* Turn off privileges. */
				(void) __priv_bracket(PRIV_OFF);

				if (ret != blocksize) {
					return;
				}
			} else {
				return;
			}
		}
	}
	capacity = (diskaddr_t)(numcyl - 1) * nhead * nsect;

	v_toc.v_nparts = V_NUMPAR;
	v_toc.v_sanity = VTOC_SANE;
	v_toc.v_version = V_VERSION;
	v_toc.v_sectorsz = DEV_BSIZE;

	v_toc.v_part[0].p_start = 0;
	v_toc.v_part[0].p_size = capacity;
	v_toc.v_part[0].p_tag  = V_ROOT;
	v_toc.v_part[0].p_flag = 0;	/* Mountable */

	v_toc.v_part[2].p_start = 0;
	v_toc.v_part[2].p_size = capacity;
	v_toc.v_part[2].p_tag  = V_BACKUP;
	v_toc.v_part[2].p_flag = V_UNMNT;

	/* Create asciilabel for compatibility with format utility */
	(void) snprintf(asciilabel, sizeof (asciilabel),
	    "%s cyl %d alt %d hd %d sec %d",
	    asciilabel2, numcyl, acyl, nhead, nsect);
	(void) memcpy(v_toc.v_asciilabel, asciilabel,
	    LEN_DKL_ASCII);

	errno = 0;


	/* Turn on privileges. */
	(void) __priv_bracket(PRIV_ON);

	ret = write_extvtoc(fd, &v_toc);

	/* Turn off privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (ret < 0) {
		PERROR("write VTOC failed");
		DPRINTF1("Errno = %d\n", errno);
	}
}

#else	/* !i386 */

#error One of sparc or i386 must be defined!

#endif /* i386 */
#endif /* sparc */

/*
 * void overwrite_metadata(int32_t fd, smedia_handle_t handle)
 *
 * purpose : quick format does not erase the data on Iomega
 * zip/jaz media. So, the meta data on the disk should be erased.
 *
 * If there is a valid fdisk table,
 *	erase first 64K of each partition.
 * If there is a valid vtoc,
 *	erase first 64k of each slice.
 * Then erase the 0th sector (the home for vtoc and fdisk) of the disk.
 * Note that teh vtoc on x86 resides in one of the fdisk partition.
 * So delay the erasing of the solaris partition until the vtoc is read.
 */

void
overwrite_metadata(int32_t fd, smedia_handle_t handle)
{

	struct fdisk_info fdisk;
	diskaddr_t sol_offset = 0;
	int i, ret;
	struct extvtoc t_vtoc;
#ifdef i386
	diskaddr_t sol_size = 0;
	int32_t active = 0;
#endif /* i386 */

	/* Get fdisk info. */
	if (get_fdisk(handle, fd, 0, &fdisk) >= 0) {
		/* Got a valid fdisk */
		for (i = 0; i < FD_NUMPART; i++) {

			if (fdisk.part[i].numsect == 0)
				continue;
			if ((fdisk.part[i].systid == UNUSED) ||
			    (fdisk.part[i].systid == 0))
				continue;
#ifdef i386
			if (fdisk.part[i].systid == SUNIXOS ||
			    fdisk.part[i].systid == SUNIXOS2) {
				if (!sol_offset) {
					sol_offset = fdisk.part[i].relsect;
					sol_size = fdisk.part[i].numsect;
					if (fdisk.part[i].bootid == ACTIVE)
						active = 1;
					continue;
				} else if ((fdisk.part[i].bootid == ACTIVE) &&
				    (!active)) {
					erase(handle, sol_offset, sol_size);
					sol_offset = fdisk.part[i].relsect;
					sol_size = fdisk.part[i].numsect;
					active = 1;
					continue;
				}
			}
#endif /* i386 */
			erase(handle, (diskaddr_t)fdisk.part[i].relsect,
			    (diskaddr_t)fdisk.part[i].numsect);
		}
	}

	(void) memset(&t_vtoc, 0, sizeof (t_vtoc));

	if (sol_offset) {
		/* fdisk x86 Solaris partition */
		/* VTOC location in solaris partition is DK_LABEL_LOC */

		/* Turn on privileges. */
		(void) __priv_bracket(PRIV_ON);

		ret = read_extvtoc(fd, &t_vtoc);

		/* Turn off privileges. */
		(void) __priv_bracket(PRIV_OFF);

		if (ret < 0) {
			/* No valid vtoc, erase fdisk table. */
			erase(handle, (diskaddr_t)0, (diskaddr_t)1);
			return;
		}
	} else {
		/* Sparc Solaris or x86 solaris with faked fdisk */

		/* Turn on privileges */
		(void) __priv_bracket(PRIV_ON);

		ret = read_extvtoc(fd, &t_vtoc);

		/* Turn off privileges. */
		(void) __priv_bracket(PRIV_OFF);

		if (ret < 0) {
			/* No valid vtoc, erase from 0th sector */
			erase(handle, (diskaddr_t)0,
			    (uint32_t)med_info.sm_capacity);
			return;
		}
	}

	for (i = 0; i < V_NUMPAR; i++) {
		if (t_vtoc.v_part[i].p_size != 0) {
			erase(handle, sol_offset + t_vtoc.v_part[i].p_start,
			    t_vtoc.v_part[i].p_size);
			/*
			 * To make the udfs not recognise the partition we will
			 * erase sectors 256, (p_size-256) and psize.
			 */
			erase(handle,
			    sol_offset + t_vtoc.v_part[i].p_start + 256,
			    (diskaddr_t)1);
			erase(handle,
			    (sol_offset + t_vtoc.v_part[i].p_start +
			    t_vtoc.v_part[i].p_size - 256),
			    (diskaddr_t)1);
			erase(handle,
			    (sol_offset + t_vtoc.v_part[i].p_start +
			    t_vtoc.v_part[i].p_size - 1),
			    (diskaddr_t)1);
		}
	}

	/*
	 * If x86 fdisk solaris partition, erase the vtoc also.
	 * for sparc, the erasing 0the sector erases vtoc.
	 */
	if (sol_offset) {
		erase(handle, sol_offset, (diskaddr_t)DK_LABEL_LOC + 2);
	}

	/*
	 * erase the 0th sector, it is not guaranteed to be
	 * erased in the above sequence.
	 */

	erase(handle, (diskaddr_t)0, (diskaddr_t)1);
}

/*
 * void erase(smedia_handle_t handle, uint32_t offset, uint32_t size)
 *
 * Initialize the media with '0' from offset 'offset' upto 'size'
 * or 128 blocks(64k), whichever is smaller.
 */

static void
erase(smedia_handle_t handle, diskaddr_t offset, diskaddr_t size)
{
	char *buf;
	diskaddr_t nblocks = size;
	int32_t ret;


	nblocks = (nblocks < 128) ? nblocks : 128;
	buf = (char *)malloc(nblocks * med_info.sm_blocksize);
	if (buf == NULL) {
		PERROR("malloc failed");
		return;
	}
	(void) memset(buf, 0, (size_t)nblocks * med_info.sm_blocksize);

	/* Turn on privileges. */
	(void) __priv_bracket(PRIV_ON);

	ret = smedia_raw_write(handle, offset, buf,
	    (size_t)nblocks * med_info.sm_blocksize);

	/* Turn off privileges. */
	(void) __priv_bracket(PRIV_OFF);

	if (ret != (nblocks * med_info.sm_blocksize))
		PERROR("error in writing\n");

	free(buf);

}
