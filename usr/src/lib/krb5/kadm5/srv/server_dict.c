
/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    <sys/types.h>
#include    <sys/file.h>
#include    <fcntl.h>
#include    <sys/stat.h>
#include    <unistd.h>
#include <errno.h>
#include    "server_internal.h"
#include    <kadm5/admin.h>
#include    <stdlib.h>
#include    <stdio.h>
#include    <string.h>
#ifdef HAVE_MEMORY_H
#include    <memory.h>
#endif
#include    "adm_proto.h"
#include    <syslog.h>
#include    <libintl.h>

static char	    **word_list = NULL;	    /* list of word pointers */
static char	    *word_block = NULL;	    /* actual word data */
static unsigned int word_count = 0;	    /* number of words */


/*
 * Function: word_compare
 *
 * Purpose: compare two words in the dictionary.
 *
 * Arguments:
 *	w1		(input)	pointer to first word
 *	w2		(input) pointer to second word
 *	<return value>	result of strcmp
 *
 * Requires:
 *	w1 and w2 to point to valid memory
 *
 */

static int
word_compare(const void *s1, const void *s2)
{
    return (strcasecmp(*(const char **)s1, *(const char **)s2));
}

/*
 * Function: init-dict
 *
 * Purpose: Initialize in memory word dictionary
 *
 * Arguments:
 *	    none
 *	    <return value> KADM5_OK on success errno on failure;
 * 			   (but success on ENOENT)
 *
 * Requires:
 *	If WORDFILE exists, it must contain a list of words,
 *	one word per-line.
 *
 * Effects:
 *	If WORDFILE exists, it is read into memory sorted for future
 * use.  If it does not exist, it syslogs an error message and returns
 * success.
 *
 * Modifies:
 *	word_list to point to a chunck of allocated memory containing
 *	pointers to words
 *	word_block to contain the dictionary.
 *
 */

int init_dict(kadm5_config_params *params)
{
    int		    fd,
		    len,
		    i;
    char	    *p,
		    *t;
    struct  stat    sb;

    if(word_list != NULL && word_block != NULL)
	return KADM5_OK;
    if (! (params->mask & KADM5_CONFIG_DICT_FILE)) {
	/* Solaris Kerberos */
	 krb5_klog_syslog(LOG_INFO,
		dgettext(TEXT_DOMAIN,
			"No dictionary file specified, continuing "
			"without one."));
	 return KADM5_OK;
    }
    if ((fd = open(params->dict_file, O_RDONLY)) == -1) {
	 if (errno == ENOENT) {
	/* Solaris Kerberos */
	      krb5_klog_syslog(LOG_ERR,
		     dgettext(TEXT_DOMAIN,
			"WARNING!  Cannot find dictionary file %s, "
			     "continuing without one."), params->dict_file);
	      return KADM5_OK;
	 } else
	      return errno;
    }
    if (fstat(fd, &sb) == -1)
	return errno;
    if ((word_block = (char *) malloc(sb.st_size + 1)) == NULL)
	return errno;
    if (read(fd, word_block, sb.st_size) != sb.st_size)
	return errno;
    (void) close(fd);
    word_block[sb.st_size] = '\0';

    p = word_block;
    len = sb.st_size;
    while(len > 0 && (t = memchr(p, '\n', len)) != NULL) {
	*t = '\0';
	len -= t - p + 1;
	p = t + 1;
	word_count++;
    }
    if ((word_list = (char **) malloc(word_count * sizeof(char *))) == NULL)
	return errno;
    p = word_block;
    for (i = 0; i < word_count; i++) {
	word_list[i] = p;
	p += strlen(p) + 1;
    }
    qsort(word_list, word_count, sizeof(char *), word_compare);
    return KADM5_OK;
}

/*
 * Function: find_word
 *
 * Purpose: See if the specified word exists in the in-core dictionary
 *
 * Arguments:
 *	word		(input) word to search for.
 * 	<return value>	WORD_NOT_FOUND if not in dictionary,
 *			KADM5_OK if if found word
 *			errno if init needs to be called and returns an
 *			error
 *
 * Requires:
 *	word to be a null terminated string.
 *	That word_list and word_block besetup
 *
 * Effects:
 *	finds word in dictionary.
 * Modifies:
 *	nothing.
 *
 */

int
find_word(const char *word)
{
    char    **value;

    if(word_list == NULL || word_block == NULL)
	    return WORD_NOT_FOUND;
    if ((value = (char **) bsearch(&word, word_list, word_count, sizeof(char *),
				   word_compare)) == NULL)
	return WORD_NOT_FOUND;
    else
	return KADM5_OK;
}

/*
 * Function: destroy_dict
 *
 * Purpose: destroy in-core copy of dictionary.
 *
 * Arguments:
 *	    none
 *	    <return value>  none
 * Requires:
 *	    nothing
 * Effects:
 *	frees up memory occupied by word_list and word_block
 *	sets count back to 0, and resets the pointers to NULL
 *
 * Modifies:
 *	word_list, word_block, and word_count.
 *
 */

void
destroy_dict(void)
{
    if(word_list) {
	free(word_list);
	word_list = NULL;
    }
    if(word_block) {
	free(word_block);
	word_block = NULL;
    }
    if(word_count)
	word_count = 0;
    return;
}
