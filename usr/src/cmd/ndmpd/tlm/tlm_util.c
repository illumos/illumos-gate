/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <cstack.h>
#include <ctype.h>
#include <tlm.h>
#include "tlm_proto.h"

/*
 * Implementation of a list based stack class. The stack only holds
 * pointers/references to application objects. The objects are not
 * copied and the stack never attempts to dereference or access the
 * data objects. Applications should treat cstack_t references as
 * opaque handles.
 */

/*
 * cstack_new
 *
 * Allocate and initialize a new stack, which is just an empty cstack_t.
 * A pointer to the new stack is returned. This should be treated as an
 * opaque handle by the caller.
 */
cstack_t *
cstack_new(void)
{
	cstack_t *stk;

	if ((stk = ndmp_malloc(sizeof (cstack_t))) == NULL)
		return (NULL);

	return (stk);
}


/*
 * cstack_delete
 *
 * Deallocate the stack. This goes through the list freeing all of the
 * cstack nodes but not the data because we don't know how the data was
 * allocated. A stack really should be empty before it is deleted.
 */
void
cstack_delete(cstack_t *stk)
{
	cstack_t *tmp;

	if (stk == NULL) {
		NDMP_LOG(LOG_DEBUG, "cstack_delete: invalid stack");
		return;
	}

	while ((tmp = stk->next) != NULL) {
		stk->next = tmp->next;
		NDMP_LOG(LOG_DEBUG, "cstack_delete(element): 0x%p", tmp);
		free(tmp);
	}

	NDMP_LOG(LOG_DEBUG, "cstack_delete: 0x%p", stk);
	free(stk);
}


/*
 * cstack_push
 *
 * Push an element onto the stack. Allocate a new node and assign the
 * data and len values. We don't care what about the real values of
 * data or len and we never try to access them. The stack head will
 * point to the new node.
 *
 * Returns 0 on success. Otherwise returns -1 to indicate overflow.
 */
int
cstack_push(cstack_t *stk, void *data, int len)
{
	cstack_t *stk_node;

	if (stk == NULL) {
		NDMP_LOG(LOG_DEBUG, "cstack_push: invalid stack");
		return (-1);
	}

	if ((stk_node = ndmp_malloc(sizeof (cstack_t))) == NULL)
		return (-1);

	stk_node->data = data;
	stk_node->len = len;
	stk_node->next = stk->next;
	stk->next = stk_node;

	NDMP_LOG(LOG_DEBUG, "cstack_push(0x%p): 0x%p", stk, stk_node);
	return (0);
}


/*
 * cstack_pop
 *
 * Pop an element off the stack. Set up the data and len references for
 * the caller, advance the stack head and free the popped stack node.
 *
 * Returns 0 on success. Otherwise returns -1 to indicate underflow.
 */
int
cstack_pop(cstack_t *stk, void **data, int *len)
{
	cstack_t *stk_node;

	if (stk == NULL) {
		NDMP_LOG(LOG_DEBUG, "cstack_pop: invalid stack");
		return (-1);
	}

	if ((stk_node = stk->next) == NULL) {
		NDMP_LOG(LOG_DEBUG, "cstack_pop: underflow");
		return (-1);
	}

	if (data)
		*data = stk_node->data;

	if (len)
		*len = stk_node->len;

	stk->next = stk_node->next;
	NDMP_LOG(LOG_DEBUG, "cstack_pop(0x%p): 0x%p", stk, stk_node);

	free(stk_node);
	return (0);
}

/*
 * cstack_top
 *
 * Returns the top data element on the stack without removing it.
 *
 * Returns 0 on success. Otherwise returns -1 to indicate underflow.
 */
int
cstack_top(cstack_t *stk, void **data, int *len)
{
	if (stk == NULL) {
		NDMP_LOG(LOG_DEBUG, "cstack_pop: invalid stack");
		return (-1);
	}

	if (stk->next == NULL) {
		NDMP_LOG(LOG_DEBUG, "cstack_pop: underflow");
		return (-1);
	}

	if (data)
		*data = stk->next->data;

	if (len)
		*len = stk->next->len;

	return (0);
}

/*
 * match
 *
 * Matching rules:
 *	c	Any non-special character matches itslef
 *	?	Match any character
 *	ab	character 'a' followed by character 'b'
 *	S	Any string of non-special characters
 *	AB	String 'A' followed by string 'B'
 *	*	Any String, including the empty string
 */
boolean_t
match(char *patn, char *str)
{
	for (; ; ) {
		switch (*patn) {
		case 0:
			return (*str == 0);

		case '?':
			if (*str != 0) {
				str++;
				patn++;
				continue;
			}
			return (FALSE);

		case '*':
			patn++;
			if (*patn == 0)
				return (TRUE);

			while (*str) {
				if (match(patn, str))
					return (TRUE);
				str++;
			}
			return (FALSE);

		default:
			if (*str != *patn)
				return (FALSE);
			str++;
			patn++;
			continue;
		}
	}
}

/*
 * Match recursive call
 */
int
match_ci(char *patn, char *str)
{
	/*
	 * "<" is a special pattern that matches only those names
	 * that do NOT have an extension. "." and ".." are ok.
	 */
	if (strcmp(patn, "<") == 0) {
		if ((strcmp(str, ".") == 0) || (strcmp(str, "..") == 0))
			return (TRUE);
		if (strchr(str, '.') == 0)
			return (TRUE);
		return (FALSE);
	}
	for (; ; ) {
		switch (*patn) {
		case 0:
			return (*str == 0);

		case '?':
			if (*str != 0) {
				str++;
				patn++;
				continue;
			}
			return (FALSE);

		case '*':
			patn++;
			if (*patn == 0)
				return (TRUE);

			while (*str) {
				if (match_ci(patn, str))
					return (TRUE);
				str++;
			}
			return (FALSE);

		default:
			if (*str != *patn) {
				int	c1 = *str;
				int	c2 = *patn;

				c1 = tolower(c1);
				c2 = tolower(c2);
				if (c1 != c2)
					return (FALSE);
			}
			str++;
			patn++;
			continue;
		}
	}
	/* NOT REACHED */
}

/*
 * Linear matching against a list utility function
 */
static boolean_t
parse_match(char line, char *seps)
{
	char *sep = seps;

	while (*sep != 0) {
		/* compare this char with the seperator list */
		if (*sep == line)
			return (TRUE);
		sep++;
	}
	return (FALSE);
}

/*
 * Returns the next entry of the list after
 * each separator
 */
char *
parse(char **line, char *seps)
{
	char *start = *line;

	while (**line != 0) {
		*line = *line + 1;
		if (parse_match(**line, seps)) {
			/* hit a terminator, skip trailing terminators */
			while (parse_match(**line, seps)) {
				**line = 0;
				*line = *line + 1;
			}
			break;
		}
	}
	return (start);
}

/*
 * oct_atoi
 *
 * Convert an octal string to integer
 */
int
oct_atoi(char *p)
{
	int v = 0;
	int c;

	while (*p == ' ')
		p++;

	while ('0' <= (c = *p++) && c <= '7') {
		v <<= 3;
		v += c - '0';
	}

	return (v);
}

/*
 * strupr
 *
 * Convert a string to uppercase using the appropriate codepage. The
 * string is converted in place. A pointer to the string is returned.
 * There is an assumption here that uppercase and lowercase values
 * always result encode to the same length.
 */
char *
strupr(char *s)
{
	char c;
	unsigned char *p = (unsigned char *)s;

	while (*p) {
		c = toupper(*p);
		*p++ = c;
	}
	return (s);
}

/*
 * trim_whitespace
 *
 * Trim leading and trailing whitespace chars(as defined by isspace)
 * from a buffer. Example; if the input buffer contained "  text  ",
 * it will contain "text", when we return. We assume that the buffer
 * contains a null terminated string. A pointer to the buffer is
 * returned.
 */
char *
trim_whitespace(char *buf)
{
	char *p = buf;
	char *q = buf;

	if (buf == 0)
		return (0);

	while (*p && isspace(*p))
		++p;

	while ((*q = *p++) != 0)
		++q;

	if (q != buf) {
		while ((--q, isspace(*q)) != 0)
			*q = '\0';
	}

	return (buf);
}

/*
 * trim_name
 *
 * Trims the slash and dot slash from the beginning of the
 * path name.
 */
char *
trim_name(char *nm)
{
	while (*nm) {
		if (*nm == '/') {
			nm++;
			continue;
		}
		if (*nm == '.' && nm[1] == '/' && nm[2]) {
			nm += 2;
			continue;
		}
		break;
	}
	return (nm);
}

/*
 * get_volname
 *
 * Extract the volume name from the path
 */
char *
get_volname(char *path)
{
	char *cp, *save;
	int sp;

	if (!path)
		return (NULL);

	if (!(save = strdup(path)))
		return (NULL);

	sp = strspn(path, "/");
	if (*(path + sp) == '\0') {
		free(save);
		return (NULL);
	}

	if ((cp = strchr(save + sp, '/')))
		*cp = '\0';

	return (save);
}

/*
 * fs_volexist
 *
 * Check if the volume exists
 */
boolean_t
fs_volexist(char *path)
{
	struct stat64 st;
	char *p;

	if ((p = get_volname(path)) == NULL)
		return (FALSE);

	if (stat64(p, &st) != 0) {
		free(p);
		return (FALSE);
	}

	free(p);
	return (TRUE);
}

/*
 * tlm_tarhdr_size
 *
 * Returns the size of the TLM_TAR_HDR structure.
 */
int
tlm_tarhdr_size(void)
{
	return (sizeof (tlm_tar_hdr_t));
}

/*
 * dup_dir_info
 *
 * Make and return a copy of the directory info.
 */
struct full_dir_info *
dup_dir_info(struct full_dir_info *old_dir_info)
{
	struct	full_dir_info *new_dir_info;
	new_dir_info = ndmp_malloc(sizeof (struct full_dir_info));

	if (new_dir_info) {
		bcopy(old_dir_info, new_dir_info,
		    sizeof (struct full_dir_info));
	}
	return (new_dir_info);
}

/*
 * tlm_new_dir_info
 *
 * Create a new structure, set fh field to what is specified and the path
 * to the concatenation of directory and the component
 */
struct full_dir_info *
tlm_new_dir_info(struct  fs_fhandle *fhp, char *dir, char *nm)
{
	struct full_dir_info *fdip;

	if (!(fdip = ndmp_malloc(sizeof (struct full_dir_info))))
		return (NULL);

	(void) memcpy(&fdip->fd_dir_fh, fhp, sizeof (fs_fhandle_t));
	if (!tlm_cat_path(fdip->fd_dir_name, dir, nm)) {
		free(fdip);
		NDMP_LOG(LOG_DEBUG, "TAPE BACKUP Find> path too long [%s][%s]",
		    dir, nm);
		return (NULL);
	}
	return (fdip);
}

/*
 * sysattr_rdonly
 *
 * Check if the attribute file is one of the readonly system
 * attributes.
 */
int
sysattr_rdonly(char *name)
{
	return (name && strcmp(name, SYSATTR_RDONLY) == 0);
}

/*
 * sysattr_rw
 *
 * Check if the attribute file is one of the read/write system
 * attributes.
 */
int
sysattr_rw(char *name)
{
	return (name && strcmp(name, SYSATTR_RW) == 0);
}
