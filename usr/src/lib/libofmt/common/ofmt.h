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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _OFMT_H
#define	_OFMT_H

/*
 * Data structures and routines for printing output.
 *
 * All output is assumed to be in a columnar format, where each column
 * represents a field to be printed out. Multiple fields in parsable output
 * are separated by ':', with the ':' character itself escaped by a \
 * (e.g., IPv6 addresses  may be printed as "fe80\:\:1"); single field output
 * is printed as-is.
 * In multiline mode, every [field,value] pair is printed in a line of
 * its own, thus: "field: value".
 *
 * The caller must open a handle for each set of fields to be printed by
 * invoking ofmt_open(). The invocation to ofmt_open must provide the list of
 * supported fields, along with formatting information (e.g., field width), and
 * a pointer to a callback function that can provide a string representation of
 * the value to be printed out. The set of supported fields must be a NULL
 * terminated array of type ofmt_field_t *ofields[]. The contents of the
 * ofmt_field_t structure are used to construct the string that is emitted by
 * ofmt_print(), and the interpretation of these contents is described with the
 * semantics of ofmt_print() below.
 *
 * In addition, the call to ofmt_open() should provide a comma-separated
 * list of the fields, char *fields_str, that have been selected for output
 * (typically the string passed to -o in the command-line). The caller may
 * also specify machine-parsable mode by specifying OFMT_PARSABLE in the oflags
 * argument. Specifying a null or empty fields_str in the machine-parsable mode
 * will result in a returned error value of OFMT_EPARSENONE. An attempt to
 * create a handle in machine-parsable mode with the fields_str set to "all"
 * will result in a returned error value of OFMT_EPARSEALL. In human-friendly
 * (non machine-parsable) mode, a NULL fields_str, or a value of "all" for
 * fields_str, is treated as a request to print all allowable fields that fit
 * other applicable constraints.
 * To achieve multiline mode, OFMT_MULTILINE needs to be specified in oflags.
 * Specifying both OFMT_MULTILINE and OFMT_PARSABLE will result in
 * OFMT_EPARSEMULTI.
 *
 * Thus a typical invocation to open the ofmt_handle would be:
 *
 *	ofmt_handle_t ofmt;
 *	ofmt_status_t ofmt_err;
 *
 *	ofmt_err = ofmt_open(fields_str, ofields, oflags, maxcols, &ofmt);
 *
 * where ofields is an array of the form:
 *
 * static ofmt_field_t ofields[] = {
 *	{<name>, <field width>,  <id>, <callback> },
 *	:
 *	{<name>, <field width>,  <id>, <callback> },
 *	{NULL, 0, 0, NULL}}
 *
 * <callback> is the application-specified function that provides a string
 * representation of the value to be printed for the field. The calling
 * application may provide unique values of <id> that will be passed back to
 * <callback>, allowing a single <callback> to be shared between multiple
 * fields in ofields[] with the value of <id> identifying the field that
 * triggers the callback.
 *
 * If successful, ofmt_open() will return OFMT_SUCCESS, with a non-null
 * ofmt_handle. The function returns a failure code otherwise, and more
 * information about the type of failure can be obtained by calling
 * ofmt_strerror()
 *
 * In order to print a row of output, the calling application should invoke
 *
 *     ofmt_print(ofmt_handle, cbarg);
 *
 * where  'cbarg' points at the arguments to be  passed to the <callback>
 * function  for each column in the row. The call to ofmt_print() will then
 * result in the <callback> function of each selected field from ofields[]
 * invoked with cbarg embedded in the ofmt_arg as
 *
 *     (*callback)(ofmt_arg_t *ofmt_arg, char *buf, uint_t bufsize)
 *
 * Columns selected for output are identified by a match between the of_name
 * value in the ofmt_field_t and the fields_str requested. For each selected
 * column, the callback function (*of_cb)() is invoked, and is passed the of_id
 * value from the ofmt_field_t structure for the field.
 *
 * The interpretation of the of_id field is completely private to the caller,
 * and can be optionally used by the callback function as a cookie
 * to identify the field being printed when a single callback function is
 * shared between multiple ofmt_field_t entries.
 *
 * The callback function should fill `buf' with the string to be printed for
 * the field using the data in cbarg.
 *
 * The calling application should invoke ofmt_close(ofmt_handle) to free up any
 * resources allocated for the handle after all printing is completed.
 *
 * The printing library computes the current size of the output window when the
 * handle is first created. If the caller wishes to adjust the window size
 * after the handle has been created (e.g., on the reception of SIGWINCH by the
 * caller), the function ofmt_update_winsize(handle) may be called.
 */

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Recommended buffer size for buffers passed, for example, to ofmt_strerror().
 */
#define	OFMT_BUFSIZE		256

typedef enum {
	OFMT_SUCCESS = 0,
	OFMT_ENOMEM,		/* out of memory */
	OFMT_EBADFIELDS,	/* one or more bad fields with good fields */
	OFMT_ENOFIELDS,		/* no valid output fields */
	OFMT_EPARSEALL,		/* 'all' invalid in parsable mode */
	OFMT_EPARSENONE,	/* output fields missing in parsable mode */
	OFMT_EPARSEWRAP,	/* parsable mode incompatible with wrap mode */
	OFMT_ENOTEMPLATE,	/* no template provided for fields */
	OFMT_EPARSEMULTI	/* parsable and multiline don't mix */
} ofmt_status_t;

/*
 * The callback function for each field is invoked with a pointer to the
 * ofmt_arg_t structure that contains the <id> registered by the application
 * for that field, and the cbarg used by the application when invoking
 * ofmt_output().
 */
typedef struct ofmt_arg_s {
	uint_t	ofmt_id;
	uint_t	ofmt_width;
	uint_t	ofmt_index;
	void	*ofmt_cbarg;
} ofmt_arg_t;

/*
 * ofmt callback function that provides a string representation of the value to
 * be printed for the field.
 */
typedef boolean_t ofmt_cb_t(ofmt_arg_t *, char *, uint_t);
typedef struct ofmt_field_s {
	char	*of_name;	/* column name */
	uint_t	of_width;	/* output column width */
	uint_t	of_id;		/* implementation specific cookie */
	ofmt_cb_t *of_cb;	/* callback function defined by caller */
} ofmt_field_t;

/*
 * ofmt_open() must be called to create the ofmt_handle_t; Resources allocated
 * for the handle are freed by ofmt_close();
 */
typedef struct ofmt_state_s *ofmt_handle_t;
extern ofmt_status_t ofmt_open(const char *, const ofmt_field_t *, uint_t,
    uint_t, ofmt_handle_t *);

#define	OFMT_PARSABLE	0x00000001 /* machine parsable mode */
#define	OFMT_WRAP	0x00000002 /* wrap output if field width is exceeded */
#define	OFMT_MULTILINE	0x00000004 /* "long" output: "name: value" lines */
#define	OFMT_RIGHTJUST	0x00000008 /* right justified output */

/*
 * ofmt_close() must be called to free resources associated
 * with the ofmt_handle_t
 */
extern void ofmt_close(ofmt_handle_t);

/*
 * ofmt_print() emits one row of output
 */
extern void ofmt_print(ofmt_handle_t, void *);

/*
 * ofmt_update_winsize() updates the window size information for ofmt_handle_t
 */
extern void ofmt_update_winsize(ofmt_handle_t);

/*
 * ofmt_strerror() provides error diagnostics in the buffer that it is passed.
 */
extern char *ofmt_strerror(ofmt_handle_t, ofmt_status_t, char *, uint_t);

#ifdef __cplusplus
}
#endif

#endif /* _OFMT_H */
