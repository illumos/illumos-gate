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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Module:	sml.c
 * Synopsis:	simplified markup language (SML) support
 * Taxonomy:	project private
 * Debug flag:	sml
 * Description:
 *
 *   This module implements methods that support the processing of a
 *   simplified markup language (SML). Objects that contain SML data
 *   can be created and manipulated, and SML can be imported into
 *   internal SML objects or exported from internal SML objects.
 *
 * Public Methods:
 *
 *   smlAddTag - Add new tag object into existing tag object
 *   smlConvertStringToTag - Convert string into tag object
 *   smlConvertTagToString - Convert a tag object into a string
 *		representation of the XML
 *   smlDbgPrintTag - Print a representation of an XML tag if debugging
 *   smlDelParam - Delete a parameter from a tag object
 *   smlDelTag - Delete element from tag object
 *   smlDup - Duplicate a tag object
 *   smlFindAndDelTag - Delete a tag if found in tag object
 *   smlFreeTag - Free a tag object and all its contents when no
 *		longer needed
 *   smlFstatCompareEq - Compare file status information
 *   smlGetElementName - Return a tag's element name
 *   smlGetNumParams - Get number of parameters set in tag
 *   smlGetParam - Get a parameter from a tag
 *   smlGetParamF - Get a formatted parameter from a tag
 *   smlGetParamByTag - Get a parameter by tag and index
 *   smlGetParamByTagParam Get parameter given tag name, index,
 *		parameter name, and value
 *   smlGetParamName - Get the name of a tag parameter given its index
 *   smlGetParam_r - Get a parameter from a tag into fixed buffer
 *   smlGetTag - Get an element from a tag
 *   smlGetTagByName - Get an element given a name and an index
 *   smlGetTagByTagParam - Get element given tag name, index, parameter name,
 *		and value
 *   smlGetVerbose - get current verbose mode setting
 *   smlLoadTagFromFile - Load a file into a tag object
 *   smlNewTag - Create a new (empty) tag object
 *   smlParamEq - Determine if parameter is equal to a specified value
 *   smlParamEqF - Determine if parameter is equal to a specified value
 *   smlPrintTag - Print a simple XML representation of a tag to stderr
 *   smlReadOneTag - read one complete tag from a datastream
 *   smlReadTagFromDs - read tag object from datastream
 *   smlSetFileStatInfo - encode file status information into tag
 *   smlSetVerbose - set/clear verbose mode for debugging output
 *   smlSetParam - Set parameter value in tag object
 *   smlSetParamF - Set parameter value in tag object
 *   smlWriteTagToDs - Write an XML representation of a tag to a datastream
 *   smlWriteTagToFd - Write an XML representation of a tag to an open file
 *		descriptor
 *   smlWriteTagToFile - Write an XML representation of a tag to a file
 */

/*
 * Unix includes
 */

#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <strings.h>

/*
 * liblu Includes
 */

#include "libinst.h"
#include "messages.h"

/* Should be defined by cc -D */
#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * Private Method Forward Declarations
 */

/*PRINTFLIKE2*/
static void	_smlLogMsg(LogMsgType a_type, const char *a_format, ...);

static int	_smlReadTag(SML_TAG **r_tag, char **a_str, char *parent);

static int	_smlWriteSimpleTag(char **a_str,
				SML_TAG *tag);

static int	_smlWriteParamValue(char **a_str, char *value);

static void		_smlFreeTag(SML_TAG *tag);

static char		*_sml_fileStatInfoTag = "File-Stat-Info";

static boolean_t	verbose = B_FALSE;

/*
 *
 * This definition controls the maximum size of any individual sml
 * component, such as a tag name, tag *value*, etc. The code should
 * someday be revised to dynamically allocate whatever memory is needed
 * to hold such components while parsing, but that exercise is left for
 * another day. Any component that exceeds this length is silently
 * truncated...
 */

#define	MAX_SML_COMPONENT_LENGTH	16384

/*
 * Public Methods
 */

/*
 * Name:	smlAddTag
 * Description:	Add new tag object into existing tag object
 * Arguments:	r_tag - [RO, *RW] - (SML_TAG **)
 *			Pointer to handle to the tag object to update
 *			The handle may be updated if the tag object is
 *			moved in memory
 *		a_index - [RO] - (int)
 *			Add the tag after the "n"th tag in the tag object
 *			-1 == add the tag to the end of the tag object
 *			0 == add the tag to the beginning of the tag object
 *		a_subTag - [RO, *RW] - (SML_TAG *)
 *			The tag to add to 'tag'
 * Returns:	SML_TAG *
 *			The location within "r_tag" where "a_subTag"
 *			has been added - this is the handle into the r_tag
 *			object to the tag that was just added
 * Errors:	If the tag object cannot be updated, the process exits
 */

SML_TAG *
smlAddTag(SML_TAG **r_tag, int a_index, SML_TAG *a_subTag)
{
	SML_TAG	*tag;

	/* entry assertions */

	assert(SML_TAG__ISVALID(a_subTag));
	assert(SML_TAG__R_ISVALID(r_tag));

	/* if no tag to update specified, ignore request */

	tag = *r_tag;
	if (tag == SML_TAG__NULL) {
		return (tag);
	}

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_ADD_TAG,
		a_subTag->name, tag->name);

	/* if index is out of range or -1, append to tag object */

	if ((a_index > tag->tags_num) || (a_index == -1)) {
		a_index = tag->tags_num;
	}

	/* bump number of tags in tag object */

	tag->tags_num++;

	/* expand tag object to hold new subtag */

	tag->tags = (SML_TAG *)realloc(tag->tags,
		sizeof (SML_TAG) * tag->tags_num);

	/* if not appending, adjust tag object to hold new subtag */

	if (a_index < (tag->tags_num - 1)) {
		(void) memmove(&(tag->tags[a_index + 1]), &(tag->tags[a_index]),
			sizeof (SML_TAG) * (tag->tags_num - a_index - 1));
	}

	/* copy new subtag into correct location in tag object */

	(void) memcpy(&(tag->tags[a_index]), a_subTag,
		sizeof (SML_TAG));

	return (&(tag->tags[a_index]));
}

/*
 * Name:	smlDelTag
 * Description:	Delete element from tag object
 * Arguments:	tag - [RO, *RW] - (SML_TAG *)
 *			The tag object to update
 *		sub_tag - [RO, *RW] - (SML_TAG *)
 *			Element to be removed from the tag object
 * Returns:	void
 *			The sub_tag is removed from the tag object
 * NOTE:	The sub-tag and all elements contained within it are deallocated
 *		the sub-tag is no longer valid when this method returns
 */

void
smlDelTag(SML_TAG *tag, SML_TAG *sub_tag)
{
	int	index;

	/* entry assertions */

	assert(SML_TAG__ISVALID(sub_tag));

	/* if no tag to update specified, ignore request */

	if (tag == SML_TAG__NULL) {
		return;
	}

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_DEL_TAG,
		sub_tag->name, tag->name);

	/* if tag object is empty, ignore request */

	if (tag->tags_num == 0) {
		return;
	}

	/* determine index into tag object of element to remove */
	for (index = 0; index < tag->tags_num; index++) {
		if (sub_tag == &tag->tags[index]) {
			break;
		}
	}

	/* if element not found in tag, ignore request */

	if (index >= tag->tags_num) {
		return;
	}

	/* free up the subtag to be deleted */

	_smlFreeTag(sub_tag);

	/*
	 * if not removing last element, collapse tag object removing
	 * target element
	 */

	if (index < (tag->tags_num - 1)) {
		(void) memmove(&(tag->tags[index]), &(tag->tags[index + 1]),
			sizeof (SML_TAG) *(tag->tags_num - index - 1));
	}

	/* one less tag object in tag */

	tag->tags_num --;

	/*
	 * If only one tag left, then delete entire tag structure
	 * otherwise reallocate removing unneeded entry
	 */

	if (tag->tags_num > 0) {
		/* realloc removing last element in tag object */

		tag->tags = (SML_TAG *)realloc(tag->tags,
			sizeof (SML_TAG) *tag->tags_num);
	} else {
		tag->tags = SML_TAG__NULL;
	}
}

/*
 * Name:	smlFreeTag
 * Description:	Free a tag object and all its contents when no longer needed
 * Arguments:	tag - [RO, *RW] - (SML_TAG *)
 *			The tag object to be deleted
 * Returns:	void
 *			The tag object and all its contents are deallocated
 */

void
smlFreeTag(SML_TAG *tag)
{
	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));

	/* entry debugging info */

	if (tag->name != (char *)NULL) {
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_FREE_TAG,
			(unsigned long)tag, tag->name);
	}

	/* free the tag object contents */

	_smlFreeTag(tag);

	/* free the tag object handle */

	bzero(tag, sizeof (SML_TAG));
	free(tag);
}

/*
 * Name:	smlGetNumParams
 * Synopsis:	Get number of parameters set in tag
 * Description:	Return the number of parameters set in a tag
 * Arguments:	a_tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the # params from
 * Returns:	int
 *			Number of parameters set in tag
 *			0 = no parameters are set
 */

int
smlGetNumParams(SML_TAG *a_tag)
{
	return (a_tag ? a_tag->params_num : 0);
}


/*
 * Name:	smlGetParam_r
 * Description:	Get a parameter from a tag into a buffer of fixed size
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the parameter from
 *		name - [RO, *RO] - (char *)
 *			Name of the parameter to retrieve
 *		buf - [RO, *RW] - (char *)
 *			Location of buffer to contain results
 *		bufLen - [RO, *RO] - (int)
 *			Maximum bytes available in buffer to contain results
 * Returns:	void
 */

void
smlGetParam_r(SML_TAG *tag, char *name, char *buf, int bufLen)
{
	int	k;

	/* entry assertions */

	assert(name != (char *)NULL);
	assert(*name != '\0');
	assert(buf != (char *)NULL);
	assert(bufLen > 0);

	/* terminate the buffer */

	buf[0] = '\0';
	buf[bufLen-1] = '\0';

	bzero(buf, bufLen);

	/* if no tag specified, return NULL */

	if (tag == SML_TAG__NULL) {
		return;
	}

	/* if no parameters in tag, return NULL */

	if (tag->params == NULL) {
		return;
	}

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_GET_PARAM,
		name, tag->name);

	/* scan tag object looking for specified parameter */

	for (k = 0; k < tag->params_num; k++) {
		assert(tag->params[k].name != (char *)NULL);
		assert(tag->params[k].value != (char *)NULL);
		if (streq(tag->params[k].name, name)) {
			_smlLogMsg(LOG_MSG_DEBUG,
				DBG_SML_GOT_PARAM,
				tag->name, name, tag->params[k].value);
			(void) strncpy(buf, tag->params[k].value, bufLen-1);
			return;
		}
	}

	/* parameter not found - return */
}

/*
 * Name:	smlGetParam
 * Description:	Get a parameter from a tag
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the parameter from
 *		name - [RO, *RO] - (char *)
 *			Name of the parameter to retrieve
 * Returns:	char *
 *			Value of the specified parameter
 *			== (char *)NULL if the parameter does not exist
 * NOTE:    	Any parameter returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the parameter is no longer needed.
 */

char *
smlGetParam(SML_TAG *tag, char *name)
{
	int	k;

	/* entry assertions */

	assert(name != (char *)NULL);
	assert(*name != '\0');

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, "get param param <%s>", name);

	/* if no tag specified, return NULL */

	if (tag == SML_TAG__NULL) {
		return ((char *)NULL);
	}

	/* if no parameters in tag, return NULL */

	if (tag->params == NULL) {
		return ((char *)NULL);
	}

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_GET_PARAM,
		name, tag->name);

	/* scan tag object looking for specified parameter */

	for (k = 0; k < tag->params_num; k++) {
		assert(tag->params[k].name != (char *)NULL);
		assert(tag->params[k].value != (char *)NULL);
		if (streq(tag->params[k].name, name)) {
			_smlLogMsg(LOG_MSG_DEBUG,
				DBG_SML_GOT_PARAM,
				tag->name, name, tag->params[k].value);
			return (strdup(tag->params[k].value));
		}
	}

	/* parameter not found - return NULL */

	return ((char *)NULL);
}

/*
 * Name:	smlGetParamName
 * Description:	Get the name of a tag parameter given its index
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the parameter name from
 *		index - [RO] - (int)
 *			Index of parameter name to return
 * Returns:	char *
 *			Name of 'index'th parameter
 *			== (char *)NULL if no such parameter exists in tag
 * NOTE:    	Any parameter name returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the parameter name is no longer needed.
 */

char *
smlGetParamName(SML_TAG *tag, int index)
{
	/* if no tag specified, return NULL */

	if (tag == NULL) {
		return ((char *)NULL);
	}

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_GET_PARAM_NAME,
		tag->name, index);

	/* if no parameters in tag, return NULL */

	if (tag->params == NULL) {
		return ((char *)NULL);
	}

	/* if index not within range, return NULL */

	if (index >= tag->params_num) {
		return ((char *)NULL);
	}

	/* index within range - return parameter name */

	assert(tag->params[index].name != (char *)NULL);
	assert(tag->params[index].value != (char *)NULL);

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_GOT_PARAM_NAME,
		tag->name, index, tag->params[index].name);

	return (strdup(tag->params[index].name));
}

/*
 * Name:	smlGetParamByTag
 * Synopsis:	Get a parameter value from a tag by name and index
 * Description:	Call to look for a parameter value from a tag with
 *		a given name with a parameter of a given name
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the parameter
 *		index - [RO] - (int)
 *			Index of nth tag by name to look for
 *		tagName - [RO, *RO] - (char *)
 *			Name of tag to look for
 *		paramName - [RO, *RO] - (char *)
 *			Name of parameter to return value of
 * Returns:	char *
 *			== (char *)NULL - no parameter value set
 *			!= (char *)NULL - value of parameter set
 */

char *
smlGetParamByTag(SML_TAG *tag, int index,
	char *tagName, char *paramName)
{
	SML_TAG	*rtag;

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));
	assert(tagName != (char *)NULL);
	assert(*tagName != '\0');
	assert(paramName != (char *)NULL);
	assert(*paramName != '\0');

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_GET_PARAM_BY_TAG,
		tagName, index, paramName);

	/* find the requested tag by name  and index */

	rtag = smlGetTagByName(tag, index, tagName);
	if (rtag == SML_TAG__NULL) {
		return ((char *)NULL);
	}

	return (smlGetParam(rtag, paramName));
}

/*
 * Name:	smlGetTagByTagParam
 * Synopsis:	Get element given tag name, index, parameter name, and value
 * Description:	Call to look for a tag with a given nae, that has a parameter
 *		of a given name with a specified value
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the element from
 *		index - [RO] - (int)
 *			Index of nth name to return
 *		tagName - [RO, *RO] - (char *)
 *			Tag name to look up
 *		paramName - [RO, *RO] - (char *)
 *			Parameter name to look up
 *		paramValue - [RO, *RO] - (char *)
 *			Parameter value to match
 * Returns:	SML_TAG *
 *			The 'index'th occurance of element 'name' with
 *			a parameter 'name' with value specified
 *			== SML_TAG__NULL if no such element exists
 */

SML_TAG *
smlGetTagByTagParam(SML_TAG *tag, int index,
	char *tagName, char *paramName, char *paramValue)
{
	int		ti;		/* tag structure index */

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));
	assert(tagName != (char *)NULL);
	assert(*tagName != '\0');
	assert(paramName != (char *)NULL);
	assert(*paramName != '\0');
	assert(paramValue != (char *)NULL);
	assert(*paramValue != '\0');

	/* if tag has no elements, return NULL */

	if (tag->tags == NULL) {
		return (SML_TAG__NULL);
	}

	/*
	 * Search algorithm:
	 *  -> search tag structure; for each tag with element == "tagName":
	 *  -> search tag parameters; if parameter name == "paramName"
	 *  -> if parameter value != "paramValue"; to next tag
	 *  -> if parameter value == "paramValue":
	 *  -> if not the "index"th paramValue found; to next tag
	 *  -> return tag found
	 */

	for (ti = 0; ti < tag->tags_num; ti++) {
		int	pi;	/* parameter structure index */

		/* if tag element does not match, go on to next tag */

		if (strcmp(tag->tags[ti].name, tagName)) {
			continue;
		}

		/* element matches: search for specified parameter name/value */

		for (pi = 0; pi < tag->tags[ti].params_num; pi++) {
			assert(tag->tags[ti].params[pi].name != (char *)NULL);
			assert(tag->tags[ti].params[pi].value != (char *)NULL);

			/* if parameter name doesnt match to next parameter */

			if (strcmp(tag->tags[ti].params[pi].name, paramName)) {
				continue;
			}

			/* if parameter value doesnt match to next tag */

			if (strcmp(tag->tags[ti].params[pi].value,
				paramValue)) {
				break;
			}

			/*
			 * found element/paramname/paramvalue:
			 * -> if this is not the 'index'th one, go to next tag
			 */

			if (index-- != 0) {
				break;
			}

			/*
			 * found specified element/paramname/paramvalue:
			 * -> return the tag found
			 */

			return (&tag->tags[ti]);
		}

	}

	/* no such element found - return NULL */

	return (SML_TAG__NULL);
}

/*
 * Name:	smlGetParamByTagParam
 * Synopsis:	Get parameter given tag name, index, parameter name, and value
 * Description:	Call to return the value of a parameter from a tag of a
 *		given name, with a parameter of a given name with a
 *		specified value
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the element from
 *		index - [RO] - (int)
 *			Index of nth name to return
 *		tagName - [RO, *RO] - (char *)
 *			Tag name to look up
 *		paramName - [RO, *RO] - (char *)
 *			Parameter name to look up
 *		paramValue - [RO, *RO] - (char *)
 *			Parameter value to match
 *		paramReturn - [RO, *RO] - (char *)
 *			Parameter name to return the value of
 * Returns:	char *
 *			The value of parameter 'paramReturn' from the
 *			The 'index'th occurance of element 'name' with
 *			a parameter 'name' with value specified
 *			== (char *)NULL if no such parameter exists
 */

char *
smlGetParamByTagParam(SML_TAG *tag, int index,
	char *tagName, char *paramName, char *paramValue, char *paramReturn)
{
	int		ti;		/* tag structure index */

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));
	assert(tagName != (char *)NULL);
	assert(*tagName != '\0');
	assert(paramName != (char *)NULL);
	assert(*paramName != '\0');
	assert(paramValue != (char *)NULL);
	assert(*paramValue != '\0');
	assert(paramReturn != (char *)NULL);
	assert(*paramReturn != '\0');

	/* if tag has no elements, return NULL */

	if (tag->tags == NULL) {
		return ((char *)NULL);
	}

	/*
	 * Search algorithm:
	 *  -> search tag structure; for each tag with element == "tagName":
	 *  -> search tag parameters; if parameter name == "paramName"
	 *  -> if parameter value != "paramValue"; to next tag
	 *  -> if parameter value == "paramValue":
	 *  -> if not the "index"th paramValue found; to next tag
	 *  -> return value of "paramReturn"
	 */

	for (ti = 0; ti < tag->tags_num; ti++) {
		int	pi;	/* parameter structure index */

		/* if tag element does not match, go on to next tag */

		if (strcmp(tag->tags[ti].name, tagName)) {
			continue;
		}

		/* element matches: search for specified parameter name/value */

		for (pi = 0; pi < tag->tags[ti].params_num; pi++) {
			assert(tag->tags[ti].params[pi].name != (char *)NULL);
			assert(tag->tags[ti].params[pi].value != (char *)NULL);

			/* if parameter name doesnt match to next parameter */

			if (strcmp(tag->tags[ti].params[pi].name, paramName)) {
				continue;
			}

			/* if parameter value doesnt match to next tag */

			if (strcmp(tag->tags[ti].params[pi].value,
				paramValue)) {
				break;
			}

			/*
			 * found element/paramname/paramvalue:
			 * -> if this is not the 'index'th one, go to next tag
			 */

			if (index-- != 0) {
				break;
			}

			/*
			 * found specified element/paramname/paramvalue:
			 * -> return parameter requested
			 */

			return (smlGetParam(&tag->tags[ti], paramReturn));
		}

	}

	/* no such element found - return NULL */

	return ((char *)NULL);
}

/*
 * Name:	smlGetElementName
 * Description:	Return the name of a given tag
 * Arguments:	a_tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the element name from
 * Returns:	char *
 *			Value of name of specified tag
 * NOTE:    	Any name string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the name string is no longer needed.
 */

char *
smlGetElementName(SML_TAG *a_tag)
{
	/* entry assertions */

	assert(SML_TAG__ISVALID(a_tag));
	assert(a_tag->name != (char *)NULL);
	assert(*a_tag->name != '\0');

	/* return the tag name */

	return (strdup(a_tag->name));
}

/*
 * Name:	smlGetTag
 * Description:	Get an element from a tag
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the element from
 *		index - [RO] - (int)
 *			Index of element to return
 * Returns:	SML_TAG *
 *			The 'index'th element from the specified tag
 *			== SML_TAG__NULL if no such tag or element
 */

SML_TAG *
smlGetTag(SML_TAG *tag, int index)
{
	/* if no tag specified, return NULL */

	if (tag == NULL) {
		return (SML_TAG__NULL);
	}

	/* if tag has no elements, return NULL */

	if (tag->tags == NULL) {
		return (SML_TAG__NULL);
	}

	/* if index not within range, return NULL */

	if (tag->tags_num <= index) {
		return (SML_TAG__NULL);
	}

	/* index within range, return element specified */

	assert(SML_TAG__ISVALID(&tag->tags[index]));

	return (&tag->tags[index]);
}

/*
 * Name:	smlGetTagByName
 * Description:	Get an element given a name and an index
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the element from
 *		index - [RO] - (int)
 *			Index of nth name to return
 *		name - [RO, *RO] - (char *)
 *			Tag name to look up
 * Returns:	SML_TAG *
 *			The 'index'th occurance of element 'name'
 *			== SML_TAG__NULL if no such element exists
 */

SML_TAG *
smlGetTagByName(SML_TAG *tag, int index, char *name)
{
	int k;

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_GET_TAG_BY_NAME, name, index);

	/* if no tag specified, return NULL */

	if (tag == NULL) {
		return (SML_TAG__NULL);
	}

	/* if this tag is the one mentioned, return it */

	if (streq(tag->name, name) && (index == 0)) {
		return (tag);
	}

	/* if tag has no elements, return NULL */

	if (tag->tags == NULL) {
		return (SML_TAG__NULL);
	}

	/* if index out of range, return NULL */

	if (tag->tags_num <= index) {
		return (SML_TAG__NULL);
	}

	/* index within range - search for specified element */

	for (k = 0; k < tag->tags_num; k++) {
		if (streq(tag->tags[k].name, name)) {
			if (index == 0) {
				assert(SML_TAG__ISVALID(&tag->tags[k]));
				return (&tag->tags[k]);
			} else {
				index--;
			}
		}
	}

	/* no such element found - return NULL */

	return (SML_TAG__NULL);
}

/*
 * Name:	smlConvertStringToTag
 * Description:	Convert string into tag object
 * Arguments:	err - [RO, *RW] (LU_ERR)
 *			Error object - used to contain any errors encountered
 *			and return those errors to this methods caller
 *		r_tag - [RW, *RW] - (SML_TAG **)
 *			Pointer to handle to place new tag object
 *		str - [RO, *RO] - (char *)
 *			String object to convert to tag object
 * Returns:	int
 *			RESULT_OK - string converted to tag object
 *			RESULT_ERR - problem converting string to tag object
 * NOTE:    	Any tag object returned is placed in new storage for the
 *		calling method. The caller must use 'smlFreeTag' to dispose
 *		of the storage once the tag object name is no longer needed.
 */

int
smlConvertStringToTag(SML_TAG **r_tag, char *str)
{
	int	r;
	SML_TAG	*tag = SML_TAG__NULL;
	SML_TAG	*tmp_tag;

	/* entry assertions */

	assert(SML_TAG__R_ISVALID(r_tag));
	assert(str != (char *)NULL);
	assert(*str != '\0');

	tag = smlNewTag("tagfile");

	for (;;) {
		r = _smlReadTag(&tmp_tag, &str, NULL);
		if (r != RESULT_OK) {
			smlFreeTag(tag);
			return (r);
		}
		if (tmp_tag == SML_TAG__NULL) {
			if (*str != '\0') {
				continue;
			}
			_smlLogMsg(LOG_MSG_DEBUG,
				DBG_SML_LOADED_TAGS_FROM_STR,
				(unsigned long)tag, tag->name);
			*r_tag = tag;
			return (RESULT_OK);
		}
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_READ_IN_TOP_TAG,
			tmp_tag->name);
		tag->tags_num++;
		tag->tags = (SML_TAG *)realloc(tag->tags,
			sizeof (SML_TAG) *tag->tags_num);
		(void) memcpy(&(tag->tags[tag->tags_num - 1]), tmp_tag,
			sizeof (SML_TAG));
	}
}

/*
 * Name:	smlReadOneTag
 * Description:	read one complete tag from a datastream
 * Arguments:	err - [RO, *RW] (LU_ERR)
 *			Error object - used to contain any errors encountered
 *			and return those errors to this methods caller
 *		r_tag - [RW, *RW] - (SML_TAG **)
 *			Pointer to handle to place new tag object
 *			== SML_TAG__NULL if empty tag found (not an error)
 *		ds - [RO, *RO] - (LU_DS)
 *			Handle to datastream to read tag from
 * Returns:	int
 *			RESULT_OK - tag successfully read
 *			RESULT_ERR - problem reading tag
 * NOTE:    	Any tag object returned is placed in new storage for the
 *		calling method. The caller must use 'smlFreeTag' to dispose
 *		of the storage once the tag object name is no longer needed.
 */

int
smlReadOneTag(SML_TAG **r_tag, char *a_str)
{
	int	r;

	/* entry assertions */

	assert(SML_TAG__R_ISVALID(r_tag));
	assert(a_str != (char *)NULL);

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_READ_ONE_TAG, a_str);

	/* reset return tag */

	*r_tag = SML_TAG__NULL;

	/* read tag from datastream, no parent tag to attach it to */

	r = _smlReadTag(r_tag, &a_str, NULL);
	if (r != RESULT_OK) {
		_smlLogMsg(LOG_MSG_ERR, ERR_SML_CANNOT_READ_TAG);
		return (r);
	}

	if (*r_tag != SML_TAG__NULL) {
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_ONE_TAG_READ,
			(unsigned long)*r_tag,
			(*r_tag)->name ? (*r_tag)->name : "<no name>");
	} else {
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_READ_ONE_TAG_NOTAG);
	}

	/* exit debugging info */

	return (RESULT_OK);
}

/*
 * Name:	smlNewTag
 * Description:	Create a new (empty) tag object
 * Arguments:	name - [RO, *RO] - (char *)
 *			Name of tag; NULL to give the tag no name
 * Returns:	SML_TAG *
 *			Tag object created
 * NOTE:    	Any tag object returned is placed in new storage for the
 *		calling method. The caller must use 'smlFreeTag' to dispose
 *		of the storage once the tag object name is no longer needed.
 * Errors:	If the tag object cannot be created, the process exits
 */

SML_TAG *
smlNewTag(char *name)
{
	SML_TAG	*tag;

	/* entry assertions */

	assert((name == (char *)NULL) || (*name != '\0'));

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_CREATE_NEW_TAG_OBJECT,
		name ? name : "<no name>");

	/* allocate zeroed storage for the tag object */

	tag = (SML_TAG *)calloc(1, sizeof (SML_TAG));
	assert(tag != SML_TAG__NULL);

	/* if name is provided, duplicate and assign it */

	if (name != (char *)NULL) {
		tag->name = strdup(name);
	}

	/* exit assertions */

	assert(SML_TAG__ISVALID(tag));

	/* exit debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_CREATED_NEW_TAG_OBJECT,
		(unsigned long)tag, name ? name : "<no name>");

	return (tag);
}

/*
 * Name:	smlConvertTagToString
 * Description:	Convert a tag object into a string representation of the XML
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to convert to a string
 * Returns:	char *
 *			String representation (in XML) of tag object
 *			== (char *)NULL if conversion is not possible
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 */

char *
smlConvertTagToString(SML_TAG *tag)
{
	char		*str = (char *)NULL;

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));

	/* convert the tag object into the datastream */

	(void) _smlWriteSimpleTag(&str, tag);

	assert(str != (char *)NULL);
	assert(*str != '\0');

	/* return the results */

	return (str);
}

/*
 * Name:	smlDbgPrintTag
 * Synopsis:	Print a representation of an XML tag if debugging
 * Arguments:	a_tag - [RO, *RO] - (SML_TAG *)
 *			Pointer to tag structure to dump
 *		a_format - [RO, RO*] (char *)
 *			printf-style format for debugging message to be output
 *		VARG_LIST - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	void
 *			If one of the debugging flags is set, the hexdump
 *			is output.
 */

/*PRINTFLIKE2*/
void
smlDbgPrintTag(SML_TAG *a_tag, char *a_format, ...)
{
	va_list	ap;
	size_t		vres = 0;
	char		bfr[1];
	char		*rstr = (char *)NULL;

	/* entry assertions */

	assert(a_format != (char *)NULL);
	assert(*a_format != '\0');
	assert(SML_TAG__ISVALID(a_tag));

	/*
	 * output the message header
	 */

	/* determine size of the message in bytes */

	va_start(ap, a_format);
	vres = vsnprintf(bfr, 1, a_format, ap);
	va_end(ap);

	assert(vres > 0);

	/* allocate storage to hold the message */

	rstr = (char *)calloc(1, vres+2);
	assert(rstr != (char *)NULL);

	/* generate the results of the printf conversion */

	va_start(ap, a_format);
	vres = vsnprintf(rstr, vres+1, a_format, ap);
	va_end(ap);

	assert(vres > 0);
	assert(*rstr != '\0');

	_smlLogMsg(LOG_MSG_DEBUG, "%s", rstr);
	free(rstr);

	/* convert the tag into a string to be printed */

	rstr = smlConvertTagToString(a_tag);
	if (rstr != (char *)NULL) {
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_PRINTTAG, a_tag->name,
			strlen(rstr), rstr);
	}
	free(rstr);
}

/*
 * Name:	smlDelParam
 * Description:	Delete a parameter from a tag object
 * Arguments:	tag - [RO, *RW] - (SML_TAG *)
 *			The tag object to delete the parameter from
 *		name - [RO, *RO] - (char *)
 *			The parameter to delete from the tag object
 * Returns:	void
 *			If the parameter exists, it is deleted from the tag
 */

void
smlDelParam(SML_TAG *tag, char *name)
{
	int k;

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));
	assert(tag->name != (char *)NULL);
	assert(name != NULL);
	assert(*name != '\0');

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_DELETE_PARAM,
		tag->name, name);

	/* if tag has no parameters, nothing to delete */

	if (tag->params == NULL) {
		_smlLogMsg(LOG_MSG_DEBUG,
			DBG_SML_DELETE_PARAM_NO_PARAMS);
		return;
	}

	assert(tag->params_num > 0);

	/* search the tag for the parameter */

	for (k = 0; k < tag->params_num; k++) {
		if (streq(tag->params[k].name, name)) {
			break;
		}
	}

	/* if the parameter was not found, nothing to delete */

	if (k >= tag->params_num) {
		_smlLogMsg(LOG_MSG_DEBUG,
			DBG_SML_DELETE_PARAM_NOT_FOUND,
			name);
		return;
	}

	/* parameter found - indicate deleted */

	assert(tag->params[k].name != (char *)NULL);
	assert(tag->params[k].value != (char *)NULL);

	_smlLogMsg(LOG_MSG_DEBUG,
		DBG_SML_DELETE_PARAM_FOUND,
		name, tag->params[k].value);

	/* free up storage fro parameter */

	free(tag->params[k].name);
	free(tag->params[k].value);

	/* if not at end, compact parameter storage */

	if (k < (tag->params_num -1)) {
		(void) memmove(&(tag->params[k]), &(tag->params[k + 1]),
			sizeof (SML_PARAM) *(tag->params_num - k - 1));
	}

	/* one less parameter object in tag */

	tag->params_num --;

	/*
	 * If only one parameter left, then delete entire parameter storage,
	 * otherwise reallocate removing unneeded entry
	 */

	if (tag->params_num > 0) {
		/* realloc removing last element in tag object */

		tag->params = (SML_PARAM *)
			realloc(tag->params,
			sizeof (SML_PARAM) *tag->params_num);
	} else {
		tag->params = (SML_PARAM *)NULL;
	}
}

/*
 * Name:	smlSetParamF
 * Description:	Set formatted parameter value in tag object
 * Arguments:	tag - [RO, *RW] - (SML_TAG *)
 *			The tag object to set the parameter in
 *		name - [RO, *RO] - (char *)
 *			The parameter to add to the tag object
 *		format - [RO, RO*] (char *)
 *			printf-style format to create parameter value from
 *		... - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	void
 *			The parameter value is set in the tag object
 *			according to the results of the format string
 *			and arguments
 */

/*PRINTFLIKE3*/
void
smlSetParamF(SML_TAG *tag, char *name, char *format, ...)
{
	va_list	ap;
	size_t		vres = 0;
	char		*bfr = NULL;
	char		fbfr[1];

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));
	assert(name != (char *)NULL);
	assert(*name != '\0');
	assert(format != NULL);
	assert(*format != '\0');

	/* determine size of the parameter name in bytes */

	va_start(ap, format);
	vres = vsnprintf(fbfr, 1, format, ap);
	va_end(ap);

	assert(vres > 0);

	/* allocate storage to hold the message */

	bfr = (char *)calloc(1, vres+2);
	assert(bfr != (char *)NULL);

	/* generate the parameter name and store it in the allocated storage */

	va_start(ap, format);
	vres = vsnprintf(bfr, vres+1, format, ap);
	va_end(ap);

	assert(vres > 0);
	assert(*bfr != '\0');

	/* add the parameter to the tag */

	smlSetParam(tag, name, bfr);

	/* free up temporary storage and return */

	free(bfr);
}

/*
 * Name:	smlGetParam
 * Description:	Get a format-generated parameter from a tag
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to obtain the parameter from
 *		format - [RO, RO*] (char *)
 *			printf-style format for parameter name to be
 *			looked up to be formatted
 *		... - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	char *
 *			Value of the specified parameter
 *			== (char *)NULL if the parameter does not exist
 * NOTE:    	Any parameter returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the parameter is no longer needed.
 */

/*PRINTFLIKE2*/
char *
smlGetParamF(SML_TAG *tag, char *format, ...)
{
	va_list	ap;
	size_t		vres = 0;
	char		*bfr = NULL;
	char		fbfr[1];
	char		*p;

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));
	assert(format != NULL);
	assert(*format != '\0');

	/* determine size of the parameter name in bytes */

	va_start(ap, format);
	vres = vsnprintf(fbfr, 1, format, ap);
	va_end(ap);

	assert(vres > 0);

	/* allocate storage to hold the message */

	bfr = (char *)calloc(1, vres+2);
	assert(bfr != (char *)NULL);

	/* generate the parameter name and store it in the allocated storage */

	va_start(ap, format);
	vres = vsnprintf(bfr, vres+1, format, ap);
	va_end(ap);

	assert(vres > 0);
	assert(*bfr != '\0');

	/* add the parameter to the tag */

	p = smlGetParam(tag, bfr);

	/* free up temporary storage and return */

	free(bfr);

	return (p);
}

/*
 * Name:	smlSetParam
 * Description:	Set parameter value in tag object
 * Arguments:	tag - [RO, *RW] - (SML_TAG *)
 *			The tag object to set the parameter in
 *		name - [RO, *RO] - (char *)
 *			The parameter to add to the tag object
 *		value - [RO, *RO] - (char *)
 *			The value of the parameter to set in the tag object
 * Returns:	void
 *			The parameter value is set in the tag object
 */

void
smlSetParam(SML_TAG *tag, char *name, char *value)
{
	SML_PARAM *parameter;

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));
	assert(name != (char *)NULL);
	assert(*name != '\0');
	assert(value != (char *)NULL);

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_SET_PARAM,
		tag->name, name, value);

	/* if parameters exist, see if modifying existing parameter */

	if (tag->params != NULL) {
		int k;
		for (k = 0; k < tag->params_num; k++) {
			assert(tag->params[k].name != (char *)NULL);
			assert(tag->params[k].value != (char *)NULL);

			/* if name does not match, skip */

			if (!streq(tag->params[k].name, name)) {
				continue;
			}

			/* found parameter - if value is same, leave alone */

			if (streq(tag->params[k].value, value)) {
				_smlLogMsg(LOG_MSG_DEBUG,
					DBG_SML_SET_PARAM_LEAVE_ALONE,
					tag->params[k].value);
				return;
			}

			/* exists and has different value - change */

			_smlLogMsg(LOG_MSG_DEBUG,
				DBG_SML_SET_PARAM_MODIFY,
				tag->params[k].value);
				free(tag->params[k].value);
				tag->params[k].value = strdup(value);
				return;
		}
	}

	/* not modifying existing - add new parameter */

	_smlLogMsg(LOG_MSG_DEBUG,
		DBG_SML_SET_PARAM_CREATE_NEW);

	parameter = (SML_PARAM *)calloc(1, sizeof (SML_PARAM));
	bzero(parameter, sizeof (SML_PARAM));
	parameter->name = strdup(name);
	parameter->value = strdup(value);

	tag->params_num++;
	tag->params = (SML_PARAM *)realloc(tag->params,
			sizeof (SML_PARAM) *tag->params_num);
	(void) memcpy(&(tag->params[tag->params_num - 1]), parameter,
			sizeof (SML_PARAM));
	free(parameter);
}

/*
 * Name:	smlParamEqF
 * Description:	Determine if parameter is equal to a specified formatted value
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to look for the parameter to compare
 *		findTag - [RO, *RO] - (char *)
 *			Tag within tag object to look for the parameter in
 *		findParam - [RO, *RO] - (char *)
 *			Parameter within tag to look for
 *		format - [RO, RO*] (char *)
 *			printf-style format for value to be compared against
 *			parameter value
 *		... - [RO] (?)
 *			arguments as appropriate to 'format' specified to
 *			generate the value to compare parameter with
 * Returns:	boolean_t
 *			B_TRUE - the parameter exists and matches given value
 *			B_FALSE - parameter does not exist or does not match
 */

/*PRINTFLIKE4*/
boolean_t
smlParamEqF(SML_TAG *tag, char *findTag, char *findParam, char *format, ...)
{
	va_list	ap;
	size_t		vres = 0;
	char		*bfr = NULL;
	char		fbfr[1];
	boolean_t	b;

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));
	assert(format != NULL);
	assert(*format != '\0');

	/* determine size of the parameter value in bytes */

	va_start(ap, format);
	vres = vsnprintf(fbfr, 1, format, ap);
	va_end(ap);

	assert(vres > 0);

	/* allocate storage to hold the message */

	bfr = (char *)calloc(1, vres+2);
	assert(bfr != (char *)NULL);

	/* generate the parameter value and store it in the allocated storage */

	va_start(ap, format);
	vres = vsnprintf(bfr, vres+1, format, ap);
	va_end(ap);

	assert(vres > 0);
	assert(*bfr != '\0');

	/* add the parameter to the tag */

	b = smlParamEq(tag, findTag, findParam, bfr);

	/* free up temporary storage and return */

	free(bfr);

	return (b);
}

/*
 * Name:	smlParamEq
 * Description:	Determine if parameter is equal to a specified value
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to look for the parameter to compare
 *		findTag - [RO, *RO] - (char *)
 *			Tag within tag object to look for the parameter in
 *		findParam - [RO, *RO] - (char *)
 *			Parameter within tag to look for
 *		str - [RO, *RO] - (char *)
 *			Value to compare parameter with
 * Returns:	boolean_t
 *			B_TRUE - the parameter exists and matches given value
 *			B_FALSE - parameter does not exist or does not match
 */

boolean_t
smlParamEq(SML_TAG *tag, char *findTag, char *findParam, char *str)
{
	SML_TAG	*rtag;
	char		*rparm;
	boolean_t	answer;

	/* entry assertions */

	assert(str != (char *)NULL);
	assert(findParam != (char *)NULL);
	assert(findTag != (char *)NULL);
	assert(SML_TAG__ISVALID(tag));

	/* look for the specified tag - if not found, return false */

	rtag = smlGetTagByName(tag, 0, findTag);
	if (rtag == SML_TAG__NULL) {
		return (B_FALSE);
	}

	/* look for the specified parameter - if not found, return false */

	rparm = smlGetParam(rtag, findParam);
	if (rparm == (char *)NULL) {
		return (B_FALSE);
	}

	/* parameter found - compare against given value */

	answer = strcasecmp(str, rparm);

	/* free up parameter storage */

	free(rparm);

	/* return results of comparison */

	return (answer == 0 ? B_TRUE : B_FALSE);
}

/*
 * Name:	smlFindAndDelTag
 * Description:	Delete a tag if found in tag object
 * Arguments:	tag - [RO, *RW] - (SML_TAG *)
 *			The tag object to delete the tag from
 *		findTag - [RO, *RO] - (char *)
 *			Tag within tag object to delete
 * Returns:	boolean_t
 *			B_TRUE - tag found and deleted
 *			B_FALSE - tag not found
 */

boolean_t
smlFindAndDelTag(SML_TAG *tag, char *findTag)
{
	SML_TAG	*rtag = SML_TAG__NULL;

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));
	assert(findTag != (char *)NULL);
	assert(*findTag != '\0');

	/* find the specified tag - if not found, return false */

	rtag = smlGetTagByName(tag, 0, findTag);
	if (rtag == SML_TAG__NULL) {
		return (B_FALSE);
	}

	/* tag found - delete it and return true */

	smlDelTag(tag, rtag);

	return (B_TRUE);
}

/*
 * Name:	smlDup
 * Description:	Duplicate a tag object
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to duplicate
 * Returns:	SML_TAG *
 *			A handle to a complete duplicate of the tag provided
 * NOTE:    	Any tag object returned is placed in new storage for the
 *		calling method. The caller must use 'smlFreeTag' to dispose
 *		of the storage once the tag object name is no longer needed.
 * Errors:	If the tag object cannot be duplicated, the process exits
 */

SML_TAG *
smlDup(SML_TAG *tag)
{
	SML_TAG	*rtag = SML_TAG__NULL;
	int		i;

	/* entry assertions */

	assert(SML_TAG__ISVALID(tag));

	/* allocate zeroed storage for the tag object */

	rtag = (SML_TAG *)calloc(1, sizeof (SML_TAG));
	assert(rtag != SML_TAG__NULL);

	/* duplicate all parameters of the tag */

	rtag->name = (tag->name ? strdup(tag->name) : (char *)NULL);
	rtag->params_num = tag->params_num;
	if (tag->params != (SML_PARAM *)NULL) {
		rtag->params = (SML_PARAM *)
			calloc(1, sizeof (SML_PARAM)*rtag->params_num);
		bzero(rtag->params, sizeof (SML_PARAM)*rtag->params_num);
		for (i = 0; i < rtag->params_num; i++) {
			rtag->params[i].name = tag->params[i].name ?
				strdup(tag->params[i].name) :
					(char *)NULL;
			rtag->params[i].value = tag->params[i].value ?
				strdup(tag->params[i].value) :
					(char *)NULL;
		}
	}

	/* duplicate all elements of the tag */

	rtag->tags_num = tag->tags_num;

	if (tag->tags != SML_TAG__NULL) {
		rtag->tags = (SML_TAG *)
			calloc(1, sizeof (SML_TAG)*rtag->tags_num);
		bzero(rtag->tags, sizeof (SML_TAG)*rtag->tags_num);
		for (i = 0; i < rtag->tags_num; i++) {
			SML_TAG *stag;
			stag = smlDup(&tag->tags[i]);
			(void) memcpy(&rtag->tags[i], stag,
				sizeof (SML_TAG));
			free(stag);
		}
	}

	/* exit assertions */

	assert(SML_TAG__ISVALID(rtag));

	/* return */

	return (rtag);
}

/*
 * Name:	smlSetFileStatInfo
 * Description;	Given a file status structure and path name, encode the
 *		structure and place it and the name into the specified tag
 *		in a "_sml_fileStatInfoTag" (private) element
 * Arguments:	tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to deposit the information into
 *		statbuf - [RO, *RO] - (struct stat *)
 *			Pointer to file status structure to encode
 *		path - [RO, *RO] - (char *)
 *			Pointer to path name of file to encode
 * Returns:	void
 *			The information is placed into the specified tag object
 */

void
smlSetFileStatInfo(SML_TAG **tag, struct stat *statbuf, char *path)
{
	SML_TAG	*rtag;

	/* entry assertions */

	assert(SML_TAG__R_ISVALID(tag));
	assert(SML_TAG__ISVALID(*tag));
	assert(statbuf != (struct stat *)NULL);

	/* if stat info exists, delete it */

	(void) smlFindAndDelTag(*tag, _sml_fileStatInfoTag);

	/* create the file stat info inside of the top level tag */

	assert(smlGetTagByName(*tag, 0, _sml_fileStatInfoTag)
							== SML_TAG__NULL);
	rtag = smlNewTag(_sml_fileStatInfoTag);
	assert(SML_TAG__ISVALID(rtag));
	(void) smlAddTag(tag, 0, rtag);
	free(rtag);

	/* obtain handle on newly created file stat info tag */

	rtag = smlGetTagByName(*tag, 0, _sml_fileStatInfoTag);
	assert(SML_TAG__ISVALID(rtag));

	/* add file info as parameters to the tag */

	if (path != (char *)NULL) {
		smlSetParam(rtag, "st_path", path);
	}

	smlSetParamF(rtag, "st_ino", "0x%llx",
		(unsigned long long)statbuf->st_ino);
	smlSetParamF(rtag, "st_mode", "0x%llx",
		(unsigned long long)statbuf->st_mode);
	smlSetParamF(rtag, "st_mtime", "0x%llx",
		(unsigned long long)statbuf->st_mtime);
	smlSetParamF(rtag, "st_ctime", "0x%llx",
		(unsigned long long)statbuf->st_ctime);
	smlSetParamF(rtag, "st_size", "0x%llx",
		(unsigned long long)statbuf->st_size);
}

/*
 * Name:	smlFstatCompareEQ
 * Description:	Given a file status structure and path name, look for the
 *		information placed into a tag object via smlSetFileStatInfo
 *		and if present compare the encoded information with the
 *		arguments provided
 * Arguments:	statbuf - [RO, *RO] - (struct stat *)
 *			Pointer to file status structure to compare
 *		tag - [RO, *RO] - (SML_TAG *)
 *			The tag object to compare against
 *		path - [RO, *RO] - (char *)
 *			Pointer to path name of file to compare
 * Returns:	boolean_t
 *			B_TRUE - both status structures are identical
 *			B_FALSE - the status structures are not equal
 */

boolean_t
smlFstatCompareEq(struct stat *statbuf, SML_TAG *tag, char *path)
{
	if (tag == SML_TAG__NULL) {
		return (B_FALSE);
	}

	assert(SML_TAG__ISVALID(tag));

	if (statbuf == (struct stat *)NULL) {
		return (B_FALSE);
	}

	if (path != (char *)NULL) {
		if (smlParamEq(tag,
			_sml_fileStatInfoTag, "st_path", path) != B_TRUE) {
			return (B_FALSE);
		}
	}

	if (smlParamEqF(tag, _sml_fileStatInfoTag, "st_ino",
		"0x%llx", (unsigned long long)statbuf->st_ino) != B_TRUE) {
		return (B_FALSE);
	}

	if (smlParamEqF(tag, _sml_fileStatInfoTag, "st_mode",
		"0x%llx", (unsigned long long)statbuf->st_mode) != B_TRUE) {
		return (B_FALSE);
	}

	if (smlParamEqF(tag, _sml_fileStatInfoTag, "st_mtime",
		"0x%llx", (unsigned long long)statbuf->st_mtime) != B_TRUE) {
		return (B_FALSE);
	}

	if (smlParamEqF(tag, _sml_fileStatInfoTag, "st_ctime",
		"0x%llx", (unsigned long long)statbuf->st_ctime) != B_TRUE) {
		return (B_FALSE);
	}

	if (smlParamEqF(tag, _sml_fileStatInfoTag, "st_size",
		"0x%llx", (unsigned long long)statbuf->st_size) != B_TRUE) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Name:	set_verbose
 * Description:	Turns on verbose output
 * Scope:	public
 * Arguments:	verbose = B_TRUE indicates verbose mode
 * Returns:	none
 */
void
smlSetVerbose(boolean_t setting)
{
	verbose = setting;
}

/*
 * Name:	get_verbose
 * Description:	Returns whether or not to output verbose messages
 * Scope:	public
 * Arguments:	none
 * Returns:	B_TRUE - verbose messages should be output
 */
boolean_t
smlGetVerbose()
{
	return (verbose);
}

/*
 * Name:	sml_strPrintf
 * Synopsis:	Create string from printf style format and arguments
 * Description:	Call to convert a printf style format and arguments into a
 *		string of characters placed in allocated storage
 * Arguments:	format - [RO, RO*] (char *)
 *			printf-style format for string to be formatted
 *		... - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	char *
 *			A string representing the printf conversion results
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'free' to dispose
 *		of the storage once the string is no longer needed.
 * Errors:	If the string cannot be created, the process exits
 */

/*PRINTFLIKE1*/
char *
sml_strPrintf(char *a_format, ...)
{
	va_list	ap;
	size_t		vres = 0;
	char		bfr[1];
	char		*rstr = (char *)NULL;

	/* entry assertions */

	assert(a_format != (char *)NULL);
	assert(*a_format != '\0');

	/* determine size of the message in bytes */

	va_start(ap, a_format);
	vres = vsnprintf(bfr, 1, a_format, ap);
	va_end(ap);

	assert(vres > 0);

	/* allocate storage to hold the message */

	rstr = (char *)calloc(1, vres+2);
	assert(rstr != (char *)NULL);

	/* generate the results of the printf conversion */

	va_start(ap, a_format);
	vres = vsnprintf(rstr, vres+1, a_format, ap);
	va_end(ap);

	assert(vres > 0);
	assert(*rstr != '\0');

	/* return the results */

	return (rstr);
}

/*
 * Name:	sml_strPrintf_r
 * Synopsis:	Create string from printf style format and arguments
 * Description:	Call to convert a printf style format and arguments into a
 *		string of characters placed in allocated storage
 * Arguments:	a_buf - [RO, *RW] - (char *)
 *			- Pointer to buffer used as storage space for the
 *			  returned string created
 *		a_bufLen - [RO, *RO] - (int)
 *			- Size of 'a_buf' in bytes - a maximum of 'a_bufLen-1'
 *			  bytes will be placed in 'a_buf' - the returned
 *			  string is always null terminated
 *		a_format - [RO, RO*] (char *)
 *			printf-style format for string to be formatted
 *		VARG_LIST - [RO] (?)
 *			arguments as appropriate to 'format' specified
 * Returns:	void
 */

/*PRINTFLIKE3*/
void
sml_strPrintf_r(char *a_buf, int a_bufLen, char *a_format, ...)
{
	va_list	ap;
	size_t		vres = 0;

	/* entry assertions */

	assert(a_format != (char *)NULL);
	assert(*a_format != '\0');
	assert(a_buf != (char *)NULL);
	assert(a_bufLen > 1);

	/* generate the results of the printf conversion */

	va_start(ap, a_format);
	vres = vsnprintf(a_buf, a_bufLen-1, a_format, ap);
	va_end(ap);

	assert(vres > 0);
	assert(vres < a_bufLen);

	a_buf[a_bufLen-1] = '\0';
}

/*
 * Name:	sml_XmlEncodeString
 * Description:	Given a plain text string, convert that string into one that
 *		encoded using the XML character reference encoding format.
 * Arguments:	a_plain_text_string	- [RO, *RO] (char *)
 *			The plain text string to convert (encode)
 * Returns:	char *
 *			The encoded form of the plain text string provided
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'lu_memFree' to dispose
 *		of the storage once the string is no longer needed.
 */

char *
sml_XmlEncodeString(char *a_plainTextString)
{
	char *stringHead;	/* -> start of string containing encoded data */
	long stringTail;	/* byte pos of first free byte in stringHead */
	long stringLength;	/* total bytes allocd starting at stringHead */
	char *p;		/* temp -> to retrieve bytes from src string */
	long textLength = 0;	/* length of the string to convert */

	/* entry assertions */

	assert(a_plainTextString != (char *)NULL);

	textLength = strlen(a_plainTextString);

	/* Allocate initial string buffer to hold results */

	stringLength = textLength*2;
	stringTail = 0;
	stringHead = (char *)calloc(1, (size_t)stringLength+2);
	assert(stringHead != (char *)NULL);

	/* Add in the encoded message text */

	for (p = a_plainTextString; textLength > 0; p++, textLength--) {
		/*
		 * Must have at least 12 bytes: this must be at least the
		 * maximum number of bytes that can be added for a single
		 * byte as the last byte of the stream. Assuming the byte
		 * needs to be encoded, it could be:
		 * &#xxxxxxxx;\0
		 * If not that many bytes left, grow the buffer.
		 */

		if ((stringLength-stringTail) < 12) {
			stringLength += (textLength*2)+12;
			stringHead =
				realloc(stringHead,
					(size_t)stringLength+2);
			assert(stringHead != (char *)NULL);
		}

		/*
		 * See if this byte is a 'printable 7-bit ascii value'.
		 * If so just add it to the new string; otherwise, must
		 * output an XML character value encoding for the byte.
		 */

		switch (*p) {
		case '!':
		case '#':
		case '%':
		case '\'':
		case '(':
		case ')':
		case '*':
		case '+':
		case ',':
		case '-':
		case '.':
		case '/':
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case ':':
		case ';':
		case '<':
		case '=':
		case '>':
		case '?':
		case '@':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case '[':
		case ']':
		case '^':
		case '_':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':
		case '{':
		case '|':
		case '}':
		case '~':
		case ' ':
			/*
			 * It is a printable 7-bit ascii character:
			 * just add it to the end of the new string.
			 */

			stringHead[stringTail++] = *p;
			break;
		default:
			/*
			 * It is not a printable 7-bit ascii character:
			 * add it as an xml character value encoding.
			 */

			stringTail += sprintf(&stringHead[stringTail], "&#%x;",
					(*p)&0xFF);
			break;
		}
	}

	/* Terminate the new string */

	stringHead[stringTail] = '\0';

	/* realloc the string so it is only as big as it needs to be */

	stringHead = realloc(stringHead, stringTail+1);
	assert(stringHead != (char *)NULL);

	return (stringHead);
}

/*
 * Name:	sml_XmlDecodeString
 * Description:	Given a string encoded using the XML character reference format,
 *		convert that string into a plain text (unencoded) string.
 * Arguments:	a_xml_encoded_string	- [RO, *RO] (char *)
 *			The XML encoded string to convert to plain text
 * Returns:	char *
 *			The unencoded (plain text) form of the encoded string
 * NOTE:    	Any string returned is placed in new storage for the
 *		calling method. The caller must use 'lu_memFree' to dispose
 *		of the storage once the string is no longer needed.
 */

char *
sml_XmlDecodeString(char *a_xmlEncodedString)
{
	char *s = NULL;		/* -> index into encoded bytes string */
	char *d = NULL;		/* -> index into decoded bytes string */
	char *rs = NULL;	/* -> string holding ref bytes allocated */
	char *ri = NULL;	/* -> index into string holding reference */
	long textLength = 0;	/* length of encoded string to decode */
	unsigned long rv = 0;	/* temp to hold scanf results of byte conv */
	char *i = NULL;		/* temp to hold strchr results */
	char *stringHead = NULL;	/* -> plain test buffer */
	ptrdiff_t tmpdiff;

	/*
	 * A finite state machine is used to convert the xml encoded string
	 * into plain text. The states of the machine are defined below.
	 */

	int fsmsState = -1;	/* Finite state machine state */
#define	fsms_text	0	/* Decoding plain text */
#define	fsms_seenAmp	1	/* Found & */
#define	fsms_seenPound	2	/* Found # following & */
#define	fsms_collect	3	/* Collecting character reference bytes */

	/* entry assertions */

	assert(a_xmlEncodedString != (char *)NULL);

	textLength = strlen(a_xmlEncodedString);

	/*
	 * Allocate string that can contain the decoded string.
	 * Since decoding always results in a shorter string (bytes encoded
	 * using the XML character reference are larger in the encoded form)
	 * we can allocate a string the same size as the encoded string.
	 */

	stringHead = (char *)calloc(1, textLength+1);
	assert(stringHead != (char *)NULL);

	/*
	 * Convert all bytes.
	 */

	/* Decoding plain text */
	fsmsState = fsms_text;

	for (s = a_xmlEncodedString, d = stringHead; textLength > 0;
		s++, textLength--) {
		switch (fsmsState) {
		case fsms_text:	/* Decoding plain text */
			if (rs != NULL) {
				free(rs);
				rs = NULL;
				ri = NULL;
			}
			if (*s == '&') {
				/* Found & */
				fsmsState = fsms_seenAmp;
				continue;
			}
			*d++ = *s;
			continue;

		case fsms_seenAmp:	/* Found & */
			if (*s == '#') {
				/* Found # following & */
				fsmsState = fsms_seenPound;
				continue;
			}
			fsmsState = fsms_text;	/* Decoding plain text */
			*d++ = '&';
			*d++ = *s;
			continue;

		case fsms_seenPound:		/* Found # following & */
			i = strchr(s, ';');
			if (i == NULL) {
				/* Decoding plain text */
				fsmsState = fsms_text;
				*d++ = '&';
				*d++ = '#';
				*d++ = *s;
				continue;
			}
			tmpdiff = (ptrdiff_t)i - (ptrdiff_t)s;
			rs = (char *)calloc(1, tmpdiff + 1);
			assert(rs != (char *)NULL);
			ri = rs;
			/* Collecting character reference bytes */
			fsmsState = fsms_collect;

			/*FALLTHRU*/

		/* Collecting character reference bytes */
		case fsms_collect:
			if (*s != ';') {
				switch (*s) {
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
				case 'a':
				case 'b':
				case 'c':
				case 'd':
				case 'e':
				case 'f':
				case 'A':
				case 'B':
				case 'C':
				case 'D':
				case 'E':
				case 'F':
					*ri++ = *s;
					break;
				default:
					*ri = '\0';
					*d++ = '&';
					*d++ = '#';
					tmpdiff = (ptrdiff_t)ri - (ptrdiff_t)rs;
					(void) strncpy(d, rs, tmpdiff-1);
					*d++ = *s;
					/* Decoding plain text */
					fsmsState = fsms_text;
					break;
				}
				continue;
			}
			*ri = '\0';
			if (sscanf(rs, "%lx", &rv) != 1) {
				*d++ = '?';
			} else {
				*d++ = (rv & 0xFF);
			}
			/* Decoding plain text */
			fsmsState = fsms_text;
		}
	}

	/* Done converting bytes - deallocate reference byte storage */

	free(rs);

	/* terminate the converted (plain text) string */

	*d = '\0';

	/* exit assertions */

	assert(stringHead != (char *)NULL);

	return (stringHead);
}

/*
 * Private Methods
 */

/*
 * Name:	_smlReadTag
 * Description:	read complete tag from a datastream
 * Arguments:	err - [RO, *RW] (LU_ERR)
 *			Error object - used to contain any errors encountered
 *			and return those errors to this methods caller
 *		r_tag - [RW, *RW] - (SML_TAG **)
 *			Pointer to handle to place new tag object
 *			== SML_TAG__NULL if empty tag found (not an error)
 *		ds - [RO, *RO] - (LU_DS)
 *			Handle to datastream to read tag from
 *		parent - [RO, *RO] - (char *)
 *			Name for parent of tag (NONE if top of tag)
 * Returns:	int
 *			RESULT_OK - tag successfully read
 *			RESULT_ERR - problem reading tag
 * NOTE:    	Any tag object returned is placed in new storage for the
 *		calling method. The caller must use 'smlFreeTag' to dispose
 *		of the storage once the tag object name is no longer needed.
 * Errors:	If the tag object cannot be duplicated, the process exits
 */

static int
_smlReadTag(SML_TAG **r_tag, char **a_str, char *parent)
{
	int	r;
	SML_TAG	*tag;
	SML_TAG	*tmp_tag;
	char	name[MAX_SML_COMPONENT_LENGTH];
	int	pos = 0;
	int	c;
	char	*p = *a_str;

	/* entry assertions */

	assert(SML_TAG__R_ISVALID(r_tag));
	assert(a_str != (char **)NULL);

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_READ_TAG,
		parent ? parent : "<<TOP TAG>>");

	/* reset return tag */

	*r_tag = SML_TAG__NULL;

	/* allocate zeroed storage for the tag object */

	tag = (SML_TAG *)calloc(1, sizeof (SML_TAG));
	assert(tag != SML_TAG__NULL);

	/* reset name accumulator storage */

	bzero(name, sizeof (name));

	/* ignore delimters before tag */

	for (;;) {
		/* read tag character - handle failure/EOF */

		if ((*p == '\0') || ((c = (*p++)) == '\0')) {
			if (parent == NULL) {
				_smlLogMsg(LOG_MSG_DEBUG,
					DBG_SML_READTAG_EXPECTED_EOF,
					p ? p : "?");
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_OK);
			}

			/* EOF in middle of processing tag */

			_smlLogMsg(LOG_MSG_ERR,
				DBG_SML_READTAG_UNEXPECTED_EOF,
				p ? p : "?");
			smlFreeTag(tag);
			*a_str = p;
			return (RESULT_ERR);
		}

		/* if beginning of tag, break out */

		if (c == '<') {
			break;
		}

		/* not tag beginning: ignore delimiters if not inside tag yet */

		if (parent == (char *)NULL) {
			/* ignore delimters */

			if (strchr(" \t", c) != (char *)NULL) {
				continue;
			}

			/* on blank lines, return no tag object */

			if (c == '\n') {
				_smlLogMsg(LOG_MSG_DEBUG,
					DBG_SML_READTAG_BLANKLINE,
					p ? p : "?");
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_OK);
			}

			/* invalid character before tag start */

			_smlLogMsg(LOG_MSG_ERR, ERR_SML_READTAG_BAD_START_CHAR,
				c, (unsigned int)c);
			*a_str = p;
			return (RESULT_ERR);
		}
	}

	/*
	 * all delimiters have been ignored and opening tag character seen;
	 * process tag
	 */

	assert(c == '<');

	c = *p;
	if (*p != '\0') {
		p++;
	}

	/* handle EOF after tag opening character found */

	if (c == '\0') {
		_smlLogMsg(LOG_MSG_ERR,
			ERR_SML_EOF_BEFORE_TAG_NAME,
			parent ? parent : "<<NONE>>");
		smlFreeTag(tag);
		*a_str = p;
		return (RESULT_ERR);
	}

	/* is this a tag closure? */

	if (c == '/') {
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_START_CLOSE_TAG,
			parent ? parent : "<<NONE>>");

		for (;;) {
			/* get next character of tag name */

			c = *p;
			if (*p != '\0') {
				p++;
			}

			/* EOF inside tag name? */

			if (c == '\0') {
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_CLOSE_TAG_EOF,
					parent ? parent : "<<NONE>>");
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_ERR);
			}

			/* tag close: break out of collection loop */

			if (c == '>') {
				break;
			}

			/* see if illegal character in tag name */

			/* CSTYLED */
			if (strchr("/ \t\n\":<?$'\\`!@#%^&*()+=|[]{};,", c)
				!= NULL) {
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_CLOSE_TAG_ILLCHAR,
					c, (unsigned int)c, name);
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_ERR);
			}

			/* valid character - add to name if room left */

			if (pos < sizeof (name)-1) {
				name[pos] = (c&0xFF);
				pos++;
			}

			assert(pos < sizeof (name));
		}

		/* close of tag found */

		assert(c == '>');

		/* is the tag empty? If so that's an error */

		if (*name == '\0') {
			_smlLogMsg(LOG_MSG_ERR,
				ERR_SML_READTAG_CLOSE_EMPTY_TAG);
			smlFreeTag(tag);
			*a_str = p;
			return (RESULT_ERR);
		}

		/* if no parent, a close tag outside of any open tag */

		if (parent == (char *)NULL) {
			_smlLogMsg(LOG_MSG_ERR,
				ERR_SML_READTAG_CLOSE_NO_PARENT,
				name);
			smlFreeTag(tag);
			*a_str = p;
			return (RESULT_ERR);
		}

		/* if not close to current parent, error */

		if (!streq(parent, name)) {
			_smlLogMsg(LOG_MSG_ERR,
				ERR_SML_READTAG_CLOSE_WRONG_TAG,
				name, parent);
			smlFreeTag(tag);
			*a_str = p;
			return (RESULT_ERR);
		}

		/* close of current tag found - success */

		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_READTAG_CLOSE_TAG,
			name);
		smlFreeTag(tag);
		*a_str = p;
		return (RESULT_OK);
	}

	/* not starting a close tag */

	assert(c != '/');
	assert(c != '<');

	/* at start of tag - input tag name */

	bzero(name, sizeof (name));
	pos = 0;

	for (;;) {

		/* EOF inside of tag name? */

		if (c == '\0') {
			_smlLogMsg(LOG_MSG_ERR,
				ERR_SML_READTAG_TAG_EOF,
				name, parent ? parent : "<<NONE>>");
			smlFreeTag(tag);
			*a_str = p;
			return (RESULT_ERR);
		}

		/* if separator or end of line then tag name collected */

		if (strchr(" >\t\n", c) != NULL) {
			break;
		}

		/* see if illegal character in tag name */

		/*CSTYLED*/
		if (strchr("\":<>?$'\\`!@#%^&*()+=|[]{};,", c) != NULL) {
			_smlLogMsg(LOG_MSG_ERR,
				ERR_SML_READTAG_TAG_ILLCHAR,
				c, (unsigned int)c, name);
			smlFreeTag(tag);
			*a_str = p;
			return (RESULT_ERR);
		}

		/* close current tag? */

		if (c == '/') {
			/* get next character of tag name */

			c = *p;
			if (*p != '\0') {
				p++;
			}

			/* tag close not found? */

			if (c != '>') {
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_BADTAG_CLOSE,
					name, parent ? parent : "<<NONE>>");
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_ERR);
			}

			/* is the tag empty? If so that's an error */

			if (*name == '\0') {
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_EMPTY_TAG,
					parent ? parent : "<<NONE>>");
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_ERR);
			}

			/* tag closed */

			_smlLogMsg(LOG_MSG_DEBUG,
				DBG_SML_READTAG_CLOSED_TAG,
				name, parent ? parent : "<<NONE>>");

			tag->name = strdup(name);
			*r_tag = tag;
			*a_str = p;
			return (RESULT_OK);
		}

		/* valid character - add to name if room left */

		if (pos < sizeof (name)-1) {
			name[pos] = (c&0xFF);
			pos++;
		}

		assert(pos < sizeof (name));

		/* get next character to parse */

		c = *p;
		if (*p != '\0') {
			p++;
		}
	}

	/* have a valid tag name: <tagname */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_HAVE_TAG_NAME,
		name, parent ? parent : "<<NONE>>");

	assert(*name != '\0');

	/* place tag name inside of tag object */

	tag->name = strdup(name);

	/* clear out name accumulator to get parameters */

	bzero(name, sizeof (name));
	pos = 0;

	/* input parameters */

	if (c != '>')
		for (;;) {

		char *pname;
		char *pvalue;
		SML_PARAM *parameter;

		/* pass spaces before parameter name */

		for (;;) {

			/* get next character of parameter name */

			c = *p;
			if (*p != '\0') {
				p++;
			}

			/* EOF inside parameter name? */

			if (c == '\0') {
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_PARM_EOF,
					tag->name,
					parent ? parent : "<<NONE>>");
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_ERR);
			}

			/* if separator/end of line tag parameter collected */

			if (strchr(" \t\n", c) != NULL) {
				continue;
			}

			/* see if illegal character in parameter name */

			/*CSTYLED*/
			if (strchr("\":<?$'\\`!@#%^&*()+=|[]{};,.", c) !=
				(char *)NULL) {
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_PARMNAME_ILLCHAR,
					c, (unsigned int)c, name, tag->name,
					parent ? parent : "<<NONE>>");
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_ERR);
			}

			/* tag close found? */

			if (c == '>') {
				break;
			}

			/* close tag found ? */

			if (c == '/') {
				c = *p;
				if (*p != '\0') {
					p++;
				}
				if (c == '>') {
					_smlLogMsg(LOG_MSG_DEBUG,
						DBG_SML_TAG_ONLY,
						tag->name);
					*r_tag = tag;
					*a_str = p;
					return (RESULT_OK);
				}

				/* / not followed by > */
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_BADPARMNAME_CLOSE,
					name, tag->name,
					parent ? parent : "<<NONE>>");
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_ERR);
			}

			/* valid character - add to name if room left */

			if (pos < sizeof (name)-1) {
				name[pos] = (c&0xFF);
				pos++;
			}

			assert(pos < sizeof (name));
			break;
		}

		if (c == '>') {
			break;
		}

		/* input parameter name */

		for (;;) {
			c = *p;
			if (*p != '\0') {
				p++;
			}

			/* EOF inside of parameter name? */

			if (c == '\0') {
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_PARM_EOF,
					tag->name,
					parent ? parent : "<<NONE>>");
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_ERR);
			}

			/*CSTYLED*/
			if (strchr("\t \n\":<>?$'\\`!@%^*()+|[]{},./", c) != NULL) {
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_PARMNAME_ILLCHAR,
					c, (unsigned int)c, name, tag->name,
					parent ? parent : "<<NONE>>");
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_ERR);
			}

			/* name - value separator found ? */

			if (c == '=') {
				break;
			}

			/* valid character - add to name if room left */

			if (pos < sizeof (name)-1) {
				name[pos] = (c&0xFF);
				pos++;
			}

			assert(pos < sizeof (name));
		}

		/* is the parameter name empty? If so that's an error */

		if (*name == '\0') {
			_smlLogMsg(LOG_MSG_ERR,
				ERR_SML_READTAG_EMPTY_PARMNAME,
				tag->name, parent ? parent : "<<NONE>>");
			smlFreeTag(tag);
			*a_str = p;
			return (RESULT_ERR);
		}

		/* have a parameter name */

		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_HAVE_PARM_NAME,
			name, tag->name);

		/* duplicate (save) parameter name */

		pname = strdup(name);

		/* clear out name accumulator to get parameters */

		bzero(name, sizeof (name));
		pos = 0;

		c = *p;
		if (*p != '\0') {
			p++;
		}

		if (c != '"') {
			_smlLogMsg(LOG_MSG_ERR,
				ERR_SML_PARM_SEP_BAD,
				c, (unsigned int)c);
			free(pname);
			smlFreeTag(tag);
			*a_str = p;
			return (RESULT_ERR);
		}

		/* input parameter value */

		for (;;) {
			c = *p;
			if (*p != '\0') {
				p++;
			}

			/* EOF inside of parameter value? */

			if (c == '\0') {
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_PARMVAL_EOF,
					pname, tag->name,
					parent ? parent : "<<NONE>>");
				smlFreeTag(tag);
				free(pname);
				*a_str = p;
				return (RESULT_ERR);
			}

			/* close of parameter value? */

			if (c == '"') {
				break;
			}

			if (strchr("\n", c) != NULL) {
				_smlLogMsg(LOG_MSG_ERR,
					ERR_SML_READTAG_PARMVAL_NL,
					pname, tag->name,
					parent ? parent : "<<NONE>>");
				free(pname);
				smlFreeTag(tag);
				*a_str = p;
				return (RESULT_ERR);
			}

			/* valid character - add to value if room left */

			if (pos < sizeof (name)-1) {
				name[pos] = (c&0xFF);
				pos++;
			}

			assert(pos < sizeof (name));
		}

		/* got the value */

		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_HAVE_PARM_VALUE,
			pname, name, tag->name);

		pvalue = sml_XmlDecodeString(name);
		bzero(name, sizeof (name));
		pos = 0;

		parameter = (SML_PARAM *)calloc(1, sizeof (SML_PARAM));
		bzero(parameter, sizeof (SML_PARAM));
		parameter->name = pname;
		parameter->value = pvalue;
		tag->params_num++;
		tag->params = (SML_PARAM *)
			realloc(tag->params,
				sizeof (SML_PARAM) *tag->params_num);
		(void) memcpy(&(tag->params[tag->params_num - 1]), parameter,
			sizeof (SML_PARAM));

		free(parameter);
		if (c == '>') {
			break;
		}
	}

	/* finished processing this tag element entry */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_TAG_HEAD_DONE,
		tag->name, parent ? parent : "<<NULL>>");

	tag->tags = NULL;

	while (((r = _smlReadTag(&tmp_tag, &p, tag->name))
		== RESULT_OK) && (tmp_tag != NULL)) {
		tag->tags_num++;
		tag->tags = (SML_TAG *)realloc(tag->tags,
			sizeof (SML_TAG) *tag->tags_num);
		(void) memcpy(&(tag->tags[tag->tags_num - 1]), tmp_tag,
			sizeof (SML_TAG));
		free(tmp_tag);
	}

	c = *p;
	if (*p != '\0') {
		p++;
	}

	*r_tag = tag;
	*a_str = p;
	return (r);
}

/*
 * Name:	_smlWriteParamValue
 * Description:	XML Encode a plain text parameter value and write to datastream
 * Arguments:	ds - [RO, *RO] - (LU_DS)
 *			Handle to datastream to write parameter value to
 *		value - [RO, *RO] - (char *)
 *			Parameter value to be encoded and written
 * Returns:	int
 *			RESULT_OK - tag successfully read
 *			RESULT_ERR - problem reading tag
 */

static int
_smlWriteParamValue(char **a_str, char *value)
{
	char		*ns;
	char		*p;

	/* entry assertions */

	assert(a_str != (char **)NULL);
	assert(value != (char *)NULL);

	/* xml encode the plain text string */

	p = sml_XmlEncodeString(value);
	assert(p != (char *)NULL);

	/* write the xml encoded parameter value to the datastream */

	ns = sml_strPrintf("%s\"%s\"", *a_str ? *a_str : "", p);

	/* free up xml encoded value storage */

	free(p);

	if (ns == NULL) {
		return (RESULT_ERR);
	}

	if (*a_str != NULL) {
		free(*a_str);
	}
	*a_str = ns;

	/* return results */

	return (RESULT_OK);
}

static int
_smlWriteSimpleTag(char **a_str, SML_TAG *tag)
{
	int	r;
	int 	k;
	char	*ns;
	char	*np0;
	char	*np1;

	if (tag == NULL) {
		return (RESULT_OK);
	}

	if (*a_str == NULL) {
		*a_str = strdup("");
	}

	if (tag->params_num == 0) {
		if (tag->tags_num == 0) {
			ns = sml_strPrintf("%s<%s/>\n", *a_str, tag->name);
			free(*a_str);
			*a_str = ns;
			return (RESULT_OK);
		} else {
			ns = sml_strPrintf("%s<%s>\n", *a_str, tag->name);
			if (ns == NULL) {
				return (RESULT_ERR);
			}
			free(*a_str);
			*a_str = ns;
		}
	} else {
		ns = sml_strPrintf("%s<%s %s=", *a_str ? *a_str : "", tag->name,
				tag->params[0].name);
		if (ns == NULL) {
			return (RESULT_ERR);
		}
		free(*a_str);
		*a_str = ns;

		np0 = NULL;
		r = _smlWriteParamValue(&np0, tag->params[0].value);
		if ((np0 == NULL) || (r != RESULT_OK)) {
			return (RESULT_ERR);
		}

		ns = sml_strPrintf("%s%s", *a_str, np0);
		if (ns == NULL) {
			return (RESULT_ERR);
		}

		free(np0);
		free(*a_str);
		*a_str = ns;

		for (k = 1; k < tag->params_num; k++) {
			np0 = sml_strPrintf(" %s=", tag->params[k].name);
			if (np0 == NULL) {
				return (RESULT_ERR);
			}
			np1 = NULL;
			r = _smlWriteParamValue(&np1, tag->params[k].value);
			if ((np1 == NULL) || (r != RESULT_OK)) {
				return (RESULT_ERR);
			}

			ns = sml_strPrintf("%s%s%s", *a_str, np0, np1);
			if (ns == NULL) {
				return (RESULT_ERR);
			}

			free(np0);
			free(np1);
			free(*a_str);
			*a_str = ns;
		}

		if (tag->tags_num == 0) {
			np0 = sml_strPrintf("/>\n");
			if (np0 == NULL) {
				return (RESULT_ERR);
			}
			ns = sml_strPrintf("%s%s", *a_str, np0);
			if (ns == NULL) {
				return (RESULT_ERR);
			}
			free(np0);
			free(*a_str);
			*a_str = ns;
		} else {
			np0 = sml_strPrintf(">\n");
			if (np0 == NULL) {
				return (RESULT_ERR);
			}
			ns = sml_strPrintf("%s%s", *a_str, np0);
			if (ns == NULL) {
				return (RESULT_ERR);
			}
			free(np0);
			free(*a_str);
			*a_str = ns;
		}
	}

	for (k = 0; k < tag->tags_num; k++) {
		r = _smlWriteSimpleTag(a_str, &(tag->tags[k]));
		if (r != RESULT_OK) {
			return (r);
		}
	}

	if (tag->tags_num > 0) {
		np0 = sml_strPrintf("</%s>\n", tag->name);
		if (np0 == NULL) {
			return (RESULT_ERR);
		}
		ns = sml_strPrintf("%s%s", *a_str ? *a_str : "", np0);
		if (ns == NULL) {
			return (RESULT_ERR);
		}
		free(np0);
		free(*a_str);
		*a_str = ns;
	}

	return (RESULT_OK);
}

static void
_smlFreeTag(SML_TAG *tag)
{
	int k;

	/* entry assertions */

	assert(tag != SML_TAG__NULL);

	/* entry debugging info */

	_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_INT_FREE_TAG,
		(unsigned long)tag,
		tag->name ? tag->name : "<<NONE>>",
		tag->params_num, tag->tags_num);

	for (k = 0; k < tag->params_num; k++) {
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_INT_FREE_PARAM_NAME,
			(unsigned long)(&tag->params[k]),
			(unsigned long)(tag->params[k].name),
			tag->params[k].name);
		free(tag->params[k].name);
		tag->params[k].name = (char *)NULL;
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_INT_FREE_PARAM_VALUE,
			(unsigned long)(&tag->params[k]),
			(unsigned long)(tag->params[k].value),
			tag->params[k].value);
		free(tag->params[k].value);
		tag->params[k].value = (char *)NULL;
	}

	for (k = 0; k < tag->tags_num; k++) {
		_smlFreeTag(&tag->tags[k]);
	}

	if (tag->name != NULL) {
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_INT_FREE_TAG_NAME,
			(unsigned long)tag->name, tag->name);
		free(tag->name);
		tag->name = NULL;
	}


	if (tag->params != NULL) {
		assert(tag->params_num > 0);
		bzero(tag->params, sizeof (SML_PARAM)*tag->params_num);
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_INT_FREE_PARAMS,
					(unsigned long)tag->params);
		free(tag->params);
		tag->params = NULL;
		tag->params_num = 0;
	}

	if (tag->tags != NULL) {
		assert(tag->tags_num > 0);
		bzero(tag->tags, sizeof (SML_TAG)*tag->tags_num);
		_smlLogMsg(LOG_MSG_DEBUG, DBG_SML_INT_FREE_TAGS,
			(unsigned long)tag->tags);
		free(tag->tags);
		tag->tags = NULL;
		tag->tags_num = 0;
	}
}

/*
 * Name:	log_msg
 * Description:	Outputs messages to logging facility.
 * Scope:	public
 * Arguments:	type - the severity of the message
 *		out - where to output the message.
 *		fmt - the printf format, plus its arguments
 * Returns:	none
 */

/*PRINTFLIKE2*/
static void
_smlLogMsg(LogMsgType a_type, const char *a_format, ...)
{
	va_list	ap;
	size_t		vres = 0;
	char		bfr[1];
	char		*rstr = (char *)NULL;
	FILE	*out;
	char	*prefix;

	switch (a_type) {
	case LOG_MSG_ERR:
	default:
		out = stderr;
		prefix = MSG_LOG_ERROR;
		break;
	case LOG_MSG_WRN:
		out = stderr;
		prefix = MSG_LOG_WARNING;
		break;
	case LOG_MSG_INFO:
		out = stdout;
		prefix = NULL;
		break;
	case LOG_MSG_DEBUG:
		if (!smlGetVerbose()) {
			/* no debug messages if not verbose mode */
			return;
		}
		out = stderr;
		prefix = MSG_LOG_DEBUG;
		break;
	}

	if (prefix != NULL) {
		(void) fprintf(out, "%s: ", prefix);
	}

	/* determine size of the message in bytes */

	va_start(ap, a_format);
	vres = vsnprintf(bfr, 1, a_format, ap);
	va_end(ap);

	/* allocate storage to hold the message */

	rstr = (char *)malloc(vres+2);

	/* generate the results of the printf conversion */

	va_start(ap, a_format);
	vres = vsnprintf(rstr, vres+1, a_format, ap);
	va_end(ap);

	if (fprintf(out, "%s\n", rstr) < 0) {
		/*
		 * nothing output, try stderr as a
		 * last resort
		 */
		(void) fprintf(stderr, ERR_LOG_FAIL, a_format);
	}

	free(rstr);
}
