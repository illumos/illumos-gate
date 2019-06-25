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
 *	Copyright(c) 1988 AT&T
 *	  All Rights Reserved
 *
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "mcs.h"
#include "extern.h"
#include "gelf.h"

/*
 * Function prototypes.
 */
static void docompress(section_info_table *);
static char *compress(char *, size_t *);
static void doappend(char *, section_info_table *);
static void doprint(char *, section_info_table *);
static void dozap(section_info_table *);
static int dohash(char *);



/*
 * Apply the actions specified by the user.
 */
int
apply_action(section_info_table *info, char *cur_file, Cmd_Info *cmd_info)
{
	int act_index;
	int ret = 0;
	GElf_Shdr shdr;

	(void) gelf_getshdr(info->scn, &shdr);
	for (act_index = 0; act_index < actmax; act_index++) {
		Action[act_index].a_cnt++;
		switch (Action[act_index].a_action) {
		case ACT_ZAP:
			if (GET_ACTION(info->flags) == ACT_DELETE)
				break;
			dozap(info);
			SET_ACTION(info->flags, ACT_ZAP);
			SET_MODIFIED(info->flags);
			break;
		case ACT_PRINT:
			if (GET_ACTION(info->flags) == ACT_DELETE)
				break;
			if (shdr.sh_type == SHT_NOBITS) {
				error_message(ACT_PRINT_ERROR, PLAIN_ERROR,
				    NULL, prog, cur_file, SECT_NAME);
				break;
			}
			doprint(cur_file, info);
			break;
		case ACT_DELETE:
			/*
			 * If I am strip command, this is the
			 * only action I can take.
			 */
			if (GET_ACTION(info->flags) == ACT_DELETE)
				break;
			if (GET_LOC(info->flags) == IN) {
				/*
				 * If I am 'strip', I have to
				 * unset the candidate flag and
				 * unset the error return code.
				 */
				if (CHK_OPT(info, I_AM_STRIP)) {
					ret = 0;
					UNSET_CANDIDATE(info->flags);
				} else {
					char *name = info->name;

					ret++;
					if (name == NULL)
						name = gettext("<unknown>");
					error_message(ACT_DELETE1_ERROR,
					    PLAIN_ERROR, NULL,
					    prog, cur_file, name);
				}
				break;
			} else if (info->rel_loc == IN) {
				/*
				 * If I am 'strip', I have to
				 * unset the candidate flag and
				 * unset the error return code.
				 */
				if (CHK_OPT(info, I_AM_STRIP)) {
					ret = 0;
					UNSET_CANDIDATE(info->flags);
				} else {
					ret++;
					error_message(ACT_DELETE2_ERROR,
					    PLAIN_ERROR, NULL,
					    prog, cur_file, SECT_NAME,
					    info->rel_name);
				}
				break;
			} else if (GET_LOC(info->flags) == PRIOR) {
				/*
				 * I can not delete this
				 * section. I can only NULL
				 * this out.
				 */
				info->secno = (GElf_Word)NULLED;
				(cmd_info->no_of_nulled)++;
			} else {
				info->secno = (GElf_Word)DELETED;
				(cmd_info->no_of_delete)++;
			}
			SET_ACTION(info->flags, ACT_DELETE);
			SET_MODIFIED(info->flags);
			break;
		case ACT_APPEND:
			if (shdr.sh_type == SHT_NOBITS) {
				ret++;
				error_message(ACT_APPEND1_ERROR, PLAIN_ERROR,
				    NULL, prog, cur_file, SECT_NAME);
				break;
			} else if (GET_LOC(info->flags) == IN) {
				ret++;
				error_message(ACT_APPEND2_ERROR, PLAIN_ERROR,
				    NULL, prog, cur_file, SECT_NAME);
				break;
			}
			doappend(Action[act_index].a_string, info);
			(cmd_info->no_of_append)++;
			info->secno = info->osecno;
			SET_ACTION(info->flags, ACT_APPEND);
			SET_MODIFIED(info->flags);
			if (GET_LOC(info->flags) == PRIOR)
				info->secno = (GElf_Word)EXPANDED;
			break;
		case ACT_COMPRESS:
			/*
			 * If this section is already deleted,
			 * don't do anything.
			 */
			if (GET_ACTION(info->flags) == ACT_DELETE)
				break;
			if (shdr.sh_type == SHT_NOBITS) {
				ret++;
				error_message(ACT_COMPRESS1_ERROR, PLAIN_ERROR,
				    NULL, prog, cur_file, SECT_NAME);
				break;
			} else if (GET_LOC(info->flags) == IN) {
				ret++;
				error_message(ACT_COMPRESS2_ERROR, PLAIN_ERROR,
				    NULL, prog, cur_file, SECT_NAME);
				break;
			}

			docompress(info);
			(cmd_info->no_of_compressed)++;
			SET_ACTION(info->flags, ACT_COMPRESS);
			SET_MODIFIED(info->flags);
			if (GET_LOC(info->flags) == PRIOR)
				info->secno = (GElf_Word)SHRUNK;
			break;
		}
	}
	return (ret);
}

/*
 * ACT_ZAP
 */
static void
dozap(section_info_table *info)
{
	Elf_Data *data;

	info->mdata = data = malloc(sizeof (Elf_Data));
	if (data == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, NULL, prog);
		mcs_exit(FAILURE);
	}
	*data = *info->data;
	data->d_buf = calloc(1, data->d_size);
	if (data->d_buf == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, NULL, prog);
		mcs_exit(FAILURE);
	}
}

/*
 * ACT_PRINT
 */
static void
doprint(char *cur_file, section_info_table *info)
{
	Elf_Data *data;
	size_t	temp_size;
	char	*temp_string;

	if (GET_MODIFIED(info->flags) == 0)
		data = info->data;
	else
		data = info->mdata;
	if (data == 0)
		return;

	temp_size = data->d_size;
	temp_string = data->d_buf;

	if (temp_size == 0)
		return;
	(void) fprintf(stdout, "%s:\n", cur_file);

	while (temp_size--) {
		char c = *temp_string++;
		switch (c) {
		case '\0':
			(void) putchar('\n');
			break;
		default:
			(void) putchar(c);
			break;
		}
	}
	(void) putchar('\n');
}

/*
 * ACT_APPEND
 */
static void
doappend(char *a_string, section_info_table *info)
{
	Elf_Data *data;
	char *p;
	size_t len;
	char *tp;

	/*
	 * Get the length of the string to be added. We accept any
	 * string (even null), as this is arbitrary user defined text.
	 *
	 * The caller expects this routine to replace a NULL info->mdata
	 * field with a pointer to a freshly allocated copy. Any attempt
	 * to optimize away a null string append would have to deal with
	 * that, as failing to do so will cause a segfault when the NULL
	 * mdata field is dereferenced. Accepting null strings in
	 * this very unimportant case eliminates the need for that.
	 */
	len = strlen(a_string);

	/*
	 * Every modification operation will be done
	 * to a new Elf_Data descriptor.
	 */
	if (info->mdata == 0) {
		/*
		 * mdata is not allocated yet.
		 * Allocate the data and set it.
		 */
		info->mdata = data = calloc(1, sizeof (Elf_Data));
		if (data == NULL) {
			error_message(MALLOC_ERROR, PLAIN_ERROR, NULL, prog);
			mcs_exit(FAILURE);
		}
		*data = *info->data;

		/*
		 * Check if the section is deleted or not.
		 * Or if the size is 0 or not.
		 */
		if ((GET_ACTION(info->flags) == ACT_DELETE) ||
		    data->d_size == 0) {
			/*
			 * The section was deleated.
			 * But now, the user wants to add data to this
			 * section.
			 */
			data->d_buf = calloc(1, len + 2);
			if (data->d_buf == NULL) {
				error_message(MALLOC_ERROR, PLAIN_ERROR, NULL,
				    prog);
				mcs_exit(FAILURE);
			}
			tp = (char *)data->d_buf;
			(void) memcpy(& tp[1], a_string, len + 1);
			data->d_size = len + 2;
		} else {
			/*
			 * The user wants to add data to the section.
			 * I am not going to change the original data.
			 * Do the modification on the new one.
			 */
			p = malloc(len + 1 + data->d_size);
			if (p == NULL) {
				error_message(MALLOC_ERROR, PLAIN_ERROR, NULL,
				    prog);
				mcs_exit(FAILURE);
			}
			(void) memcpy(p, data->d_buf, data->d_size);
			(void) memcpy(&p[data->d_size], a_string, len + 1);
			data->d_buf = p;
			data->d_size = data->d_size + len + 1;
		}
	} else {
		/*
		 * mdata is already allocated.
		 * Modify it.
		 */
		data = info->mdata;
		if ((GET_ACTION(info->flags) == ACT_DELETE) ||
		    data->d_size == 0) {
			/*
			 * The section was deleated.
			 * But now, the user wants to add data to this
			 * section.
			 */
			if (data->d_buf)
				free(data->d_buf);
			data->d_buf = calloc(1, len + 2);
			if (data->d_buf == NULL) {
				error_message(MALLOC_ERROR, PLAIN_ERROR, NULL,
				    prog);
				mcs_exit(FAILURE);
			}
			tp = (char *)data->d_buf;
			(void) memcpy(&tp[1], a_string, len + 1);
			data->d_size = len + 2;
		} else {
			/*
			 * The user wants to add data to the section.
			 * I am not going to change the original data.
			 * Do the modification on the new one.
			 */
			p = malloc(len + 1 + data->d_size);
			if (p == NULL) {
				error_message(MALLOC_ERROR, PLAIN_ERROR, NULL,
				    prog);
				mcs_exit(FAILURE);
			}
			(void) memcpy(p, data->d_buf, data->d_size);
			(void) memcpy(&p[data->d_size], a_string, len + 1);
			free(data->d_buf);
			data->d_buf = p;
			data->d_size = data->d_size + len + 1;
		}
	}
}

/*
 * ACT_COMPRESS
 */
#define	HALFLONG 16
#define	low(x)  (x&((1L<<HALFLONG)-1))
#define	high(x) (x>>HALFLONG)

static void
docompress(section_info_table *info)
{
	Elf_Data *data;
	size_t size;
	char *buf;

	if (info->mdata == 0) {
		/*
		 * mdata is not allocated yet.
		 * Allocate the data and set it.
		 */
		char *p;
		info->mdata = data = calloc(1, sizeof (Elf_Data));
		if (data == NULL) {
			error_message(MALLOC_ERROR, PLAIN_ERROR, NULL, prog);
			mcs_exit(FAILURE);
		}
		*data = *info->data;
		p = malloc(data->d_size);
		(void) memcpy(p, (char *)data->d_buf, data->d_size);
		data->d_buf = p;
	}
	size = info->mdata->d_size;
	buf = (char *)info->mdata->d_buf;
	buf = compress(buf, &size);
	info->mdata->d_buf = buf;
	info->mdata->d_size = size;
}

static char *
compress(char *str, size_t *size)
{
	int hash;
	int i;
	size_t temp_string_size = 0;
	size_t o_size = *size;
	char *temp_string = str;

	int *hash_key;
	size_t hash_num;
	size_t hash_end;
	size_t *hash_str;
	char *strings;
	size_t next_str;
	size_t str_size;

	hash_key = malloc(sizeof (int) * 200);
	hash_end = 200;
	hash_str = malloc(sizeof (size_t) * 200);
	str_size = o_size+1;
	strings = malloc(str_size);

	if (hash_key == NULL || hash_str == NULL || strings == NULL) {
		error_message(MALLOC_ERROR, PLAIN_ERROR, NULL, prog);
		mcs_exit(FAILURE);
	}

	hash_num = 0;
	next_str = 0;

	while (temp_string_size < o_size)  {
		size_t pos;
		char c;
		/*
		 * Get a string
		 */
		pos = next_str;

		while ((c = *(temp_string++)) != '\0' &&
		    (temp_string_size + (next_str - pos)) <= o_size) {
			if (next_str >= str_size) {
				str_size *= 2;
				if ((strings = (char *)
				    realloc(strings, str_size)) == NULL) {
					error_message(MALLOC_ERROR, PLAIN_ERROR,
					    NULL, prog);
					mcs_exit(FAILURE);
				}
			}
			strings[next_str++] = c;
		}

		if (next_str >= str_size) {
			str_size *= 2;
			if ((strings = (char *)
			    realloc(strings, str_size)) == NULL) {
				error_message(MALLOC_ERROR, PLAIN_ERROR, NULL,
				    prog);
				mcs_exit(FAILURE);
			}
		}
		strings[next_str++] = '\0';
		/*
		 * End get string
		 */

		temp_string_size += (next_str - pos);
		hash = dohash(pos + strings);
		for (i = 0; i < hash_num; i++) {
			if (hash != hash_key[i])
				continue;
			if (strcmp(pos + strings, hash_str[i] + strings) == 0)
				break;
		}
		if (i != hash_num) {
			next_str = pos;
			continue;
		}
		if (hash_num == hash_end) {
			hash_end *= 2;
			hash_key = realloc((char *)hash_key,
			    hash_end * sizeof (int));
			hash_str = realloc((char *)hash_str,
			    hash_end * sizeof (size_t));
			if (hash_key == NULL || hash_str == NULL) {
				error_message(MALLOC_ERROR, PLAIN_ERROR, NULL,
				    prog);
				mcs_exit(FAILURE);
			}
		}
		hash_key[hash_num] = hash;
		hash_str[hash_num++] = pos;
	}

	/*
	 * Clean up
	 */
	free(hash_key);
	free(hash_str);

	/*
	 * Return
	 */
	if (next_str != o_size) {
		/*
		 * string compressed.
		 */
		*size = next_str;
		free(str);
		str = malloc(next_str);
		(void) memcpy(str, strings, next_str);
	}
	free(strings);
	return (str);
}

static int
dohash(char *str)
{
	long sum;
	unsigned shift;
	int t;
	sum = 1;
	for (shift = 0; (t = *str++) != 0; shift += 7) {
		sum += (long)t << (shift %= HALFLONG);
	}
	sum = low(sum) + high(sum);
	/* LINTED */
	return ((short)low(sum) + (short)high(sum));
}
