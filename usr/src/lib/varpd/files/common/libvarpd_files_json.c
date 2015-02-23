/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>
#include <errno.h>
#include <libnvpair.h>
#include <sys/ccompile.h>

#include "libvarpd_files_json.h"

typedef enum json_type {
	JSON_TYPE_NOTHING = 0,
	JSON_TYPE_STRING = 1,
	JSON_TYPE_INTEGER,
	JSON_TYPE_DOUBLE,
	JSON_TYPE_BOOLEAN,
	JSON_TYPE_NULL,
	JSON_TYPE_OBJECT,
	JSON_TYPE_ARRAY
} json_type_t;

typedef enum parse_state {
	PARSE_ERROR = -1,
	PARSE_DONE = 0,
	PARSE_REST,
	PARSE_OBJECT,
	PARSE_KEY_STRING,
	PARSE_COLON,
	PARSE_STRING,
	PARSE_OBJECT_COMMA,
	PARSE_ARRAY,
	PARSE_BAREWORD,
	PARSE_NUMBER,
	PARSE_ARRAY_VALUE,
	PARSE_ARRAY_COMMA
} parse_state_t;

#define	JSON_MARKER		".__json_"
#define	JSON_MARKER_ARRAY	JSON_MARKER "array"

typedef struct parse_frame {
	parse_state_t pf_ps;
	nvlist_t *pf_nvl;

	char *pf_key;
	void *pf_value;
	json_type_t pf_value_type;
	int pf_array_index;

	struct parse_frame *pf_next;
} parse_frame_t;

typedef struct state {
	const char *s_in;
	unsigned long s_pos;
	unsigned long s_len;

	parse_frame_t *s_top;

	nvlist_parse_json_flags_t s_flags;

	/*
	 * This string buffer is used for temporary storage by the
	 * "collect_*()" family of functions.
	 */
	custr_t *s_collect;

	int s_errno;
	custr_t *s_errstr;
} state_t;

typedef void (*parse_handler_t)(state_t *);

static void
movestate(state_t *s, parse_state_t ps)
{
	if (s->s_flags & NVJSON_DEBUG) {
		(void) fprintf(stderr, "nvjson: move state %d -> %d\n",
		    s->s_top->pf_ps, ps);
	}
	s->s_top->pf_ps = ps;
}

static void
posterror(state_t *s, int erno, const char *error)
{
	/*
	 * If the caller wants error messages printed to stderr, do that
	 * first.
	 */
	if (s->s_flags & NVJSON_ERRORS_TO_STDERR) {
		(void) fprintf(stderr, "nvjson error (pos %ld, errno %d): %s\n",
		    s->s_pos, erno, error);
	}

	/*
	 * Try and store the error message for the caller.  This may fail if
	 * the error was related to memory pressure, and that condition still
	 * exists.
	 */
	s->s_errno = erno;
	if (s->s_errstr != NULL) {
		(void) custr_append(s->s_errstr, error);
	}

	movestate(s, PARSE_ERROR);
}

static int
pushstate(state_t *s, parse_state_t ps, parse_state_t retps)
{
	parse_frame_t *n;

	if (s->s_flags & NVJSON_DEBUG) {
		(void) fprintf(stderr, "nvjson: push state %d -> %d (ret %d)\n",
		    s->s_top->pf_ps, ps, retps);
	}

	if ((n = calloc(1, sizeof (*n))) == NULL) {
		posterror(s, errno, "pushstate calloc failure");
		return (-1);
	}

	/*
	 * Store the state we'll return to when popping this
	 * frame:
	 */
	s->s_top->pf_ps = retps;

	/*
	 * Store the initial state for the new frame, and
	 * put it on top of the stack:
	 */
	n->pf_ps = ps;
	n->pf_value_type = JSON_TYPE_NOTHING;

	n->pf_next = s->s_top;
	s->s_top = n;

	return (0);
}

static char
popchar(state_t *s)
{
	if (s->s_pos > s->s_len) {
		return (0);
	}
	return (s->s_in[s->s_pos++]);
}

static char
peekchar(state_t *s)
{
	if (s->s_pos > s->s_len) {
		return (0);
	}
	return (s->s_in[s->s_pos]);
}

static void
discard_whitespace(state_t *s)
{
	while (isspace(peekchar(s))) {
		(void) popchar(s);
	}
}

static char *escape_pairs[] = {
	"\"\"", "\\\\", "//", "b\b", "f\f", "n\n", "r\r", "t\t", NULL
};

static char
collect_string_escape(state_t *s)
{
	int i;
	char c = popchar(s);

	if (c == '\0') {
		posterror(s, EPROTO, "EOF mid-escape sequence");
		return (-1);
	}

	/*
	 * Handle four-digit Unicode escapes up to and including \u007f.
	 * Strings that cannot be represented as 7-bit clean ASCII are not
	 * currently supported.
	 */
	if (c == 'u') {
		int res;
		int ndigs = 0;
		char digs[5];

		/*
		 * Deal with 4-digit unicode escape.
		 */
		while (ndigs < 4) {
			if ((digs[ndigs++] = popchar(s)) == '\0') {
				posterror(s, EPROTO, "EOF mid-escape "
				    "sequence");
				return (-1);
			}
		}
		digs[4] = '\0';
		if ((res = atoi(digs)) > 127) {
			posterror(s, EPROTO, "unicode escape above 0x7f");
			return (-1);
		}

		if (custr_appendc(s->s_collect, res) != 0) {
			posterror(s, errno, "custr_appendc failure");
			return (-1);
		}
		return (0);
	}

	/*
	 * See if this is a C-style escape character we recognise.
	 */
	for (i = 0; escape_pairs[i] != NULL; i++) {
		char *ep = escape_pairs[i];
		if (ep[0] == c) {
			if (custr_appendc(s->s_collect, ep[1]) != 0) {
				posterror(s, errno, "custr_appendc failure");
				return (-1);
			}
			return (0);
		}
	}

	posterror(s, EPROTO, "unrecognised escape sequence");
	return (-1);
}

static int
collect_string(state_t *s)
{
	custr_reset(s->s_collect);

	for (;;) {
		char c;

		switch (c = popchar(s)) {
		case '"':
			/*
			 * Legal End of String.
			 */
			return (0);

		case '\0':
			posterror(s, EPROTO, "EOF mid-string");
			return (-1);

		case '\\':
			/*
			 * Escape Characters and Sequences.
			 */
			if (collect_string_escape(s) != 0) {
				return (-1);
			}
			break;

		default:
			if (custr_appendc(s->s_collect, c) != 0) {
				posterror(s, errno, "custr_appendc failure");
				return (-1);
			}
			break;
		}
	}
}

static int
collect_bareword(state_t *s)
{
	custr_reset(s->s_collect);

	for (;;) {
		if (!islower(peekchar(s))) {
			return (0);
		}

		if (custr_appendc(s->s_collect, popchar(s)) != 0) {
			posterror(s, errno, "custr_appendc failure");
			return (-1);
		}
	}
}

static void
hdlr_bareword(state_t *s)
{
	const char *str;

	if (collect_bareword(s) != 0) {
		return;
	}

	str = custr_cstr(s->s_collect);
	if (strcmp(str, "true") == 0) {
		s->s_top->pf_value_type = JSON_TYPE_BOOLEAN;
		s->s_top->pf_value = (void *)B_TRUE;
	} else if (strcmp(str, "false") == 0) {
		s->s_top->pf_value_type = JSON_TYPE_BOOLEAN;
		s->s_top->pf_value = (void *)B_FALSE;
	} else if (strcmp(str, "null") == 0) {
		s->s_top->pf_value_type = JSON_TYPE_NULL;
	} else {
		posterror(s, EPROTO, "expected 'true', 'false' or 'null'");
		return;
	}

	movestate(s, PARSE_DONE);
}

/* ARGSUSED */
static int
collect_number(state_t *s, boolean_t *isint, int32_t *result,
    double *fresult __unused)
{
	boolean_t neg = B_FALSE;
	int t;

	custr_reset(s->s_collect);

	if (peekchar(s) == '-') {
		neg = B_TRUE;
		(void) popchar(s);
	}
	/*
	 * Read the 'int' portion:
	 */
	if (!isdigit(peekchar(s))) {
		posterror(s, EPROTO, "malformed number: expected digit (0-9)");
		return (-1);
	}
	for (;;) {
		if (!isdigit(peekchar(s))) {
			break;
		}
		if (custr_appendc(s->s_collect, popchar(s)) != 0) {
			posterror(s, errno, "custr_append failure");
			return (-1);
		}
	}
	if (peekchar(s) == '.' || peekchar(s) == 'e' || peekchar(s) == 'E') {
		posterror(s, ENOTSUP, "do not yet support FRACs or EXPs");
		return (-1);
	}

	t = atoi(custr_cstr(s->s_collect));

	*isint = B_TRUE;
	*result = (neg == B_TRUE) ? (-t) : t;
	return (0);
}

static void
hdlr_number(state_t *s)
{
	boolean_t isint;
	int32_t result;
	double fresult;

	if (collect_number(s, &isint, &result, &fresult) != 0) {
		return;
	}

	if (isint == B_TRUE) {
		s->s_top->pf_value = (void *)(uintptr_t)result;
		s->s_top->pf_value_type = JSON_TYPE_INTEGER;
	} else {
		s->s_top->pf_value = malloc(sizeof (fresult));
		bcopy(&fresult, s->s_top->pf_value, sizeof (fresult));
		s->s_top->pf_value_type = JSON_TYPE_DOUBLE;
	}

	movestate(s, PARSE_DONE);
}

static void
hdlr_rest(state_t *s)
{
	char c;
	discard_whitespace(s);
	c = popchar(s);
	switch (c) {
	case '{':
		movestate(s, PARSE_OBJECT);
		return;

	case '[':
		movestate(s, PARSE_ARRAY);
		return;

	default:
		posterror(s, EPROTO, "EOF before object or array");
		return;
	}
}

static int
add_empty_child(state_t *s)
{
	/*
	 * Here, we create an empty nvlist to represent this object
	 * or array:
	 */
	nvlist_t *empty;
	if (nvlist_alloc(&empty, NV_UNIQUE_NAME, 0) != 0) {
		posterror(s, errno, "nvlist_alloc failure");
		return (-1);
	}
	if (s->s_top->pf_next != NULL) {
		/*
		 * If we're a child of the frame above, we store ourselves in
		 * that frame's nvlist:
		 */
		nvlist_t *nvl = s->s_top->pf_next->pf_nvl;
		char *key = s->s_top->pf_next->pf_key;

		if (nvlist_add_nvlist(nvl, key, empty) != 0) {
			posterror(s, errno, "nvlist_add_nvlist failure");
			nvlist_free(empty);
			return (-1);
		}
		nvlist_free(empty);
		if (nvlist_lookup_nvlist(nvl, key, &empty) != 0) {
			posterror(s, errno, "nvlist_lookup_nvlist failure");
			return (-1);
		}
	}
	s->s_top->pf_nvl = empty;
	return (0);
}

static int
decorate_array(state_t *s)
{
	int idx = s->s_top->pf_array_index;
	/*
	 * When we are done creating an array, we store a 'length'
	 * property on it, as well as an internal-use marker value.
	 */
	if (nvlist_add_boolean(s->s_top->pf_nvl, JSON_MARKER_ARRAY) != 0 ||
	    nvlist_add_uint32(s->s_top->pf_nvl, "length", idx) != 0) {
		posterror(s, errno, "nvlist_add failure");
		return (-1);
	}

	return (0);
}

static void
hdlr_array(state_t *s)
{
	s->s_top->pf_value_type = JSON_TYPE_ARRAY;

	if (add_empty_child(s) != 0) {
		return;
	}

	discard_whitespace(s);

	switch (peekchar(s)) {
	case ']':
		(void) popchar(s);

		if (decorate_array(s) != 0) {
			return;
		}

		movestate(s, PARSE_DONE);
		return;

	default:
		movestate(s, PARSE_ARRAY_VALUE);
		return;
	}
}

static void
hdlr_array_comma(state_t *s)
{
	discard_whitespace(s);

	switch (popchar(s)) {
	case ']':
		if (decorate_array(s) != 0) {
			return;
		}

		movestate(s, PARSE_DONE);
		return;
	case ',':
		movestate(s, PARSE_ARRAY_VALUE);
		return;
	default:
		posterror(s, EPROTO, "expected ',' or ']'");
		return;
	}
}

static void
hdlr_array_value(state_t *s)
{
	char c;

	/*
	 * Generate keyname from the next array index:
	 */
	if (s->s_top->pf_key != NULL) {
		(void) fprintf(stderr, "pf_key not null! was %s\n",
		    s->s_top->pf_key);
		abort();
	}

	if (asprintf(&s->s_top->pf_key, "%d", s->s_top->pf_array_index++) < 0) {
		posterror(s, errno, "asprintf failure");
		return;
	}

	discard_whitespace(s);

	/*
	 * Select which type handler we need for the next value:
	 */
	switch (c = peekchar(s)) {
	case '"':
		(void) popchar(s);
		(void) pushstate(s, PARSE_STRING, PARSE_ARRAY_COMMA);
		return;

	case '{':
		(void) popchar(s);
		(void) pushstate(s, PARSE_OBJECT, PARSE_ARRAY_COMMA);
		return;

	case '[':
		(void) popchar(s);
		(void) pushstate(s, PARSE_ARRAY, PARSE_ARRAY_COMMA);
		return;

	default:
		if (islower(c)) {
			(void) pushstate(s, PARSE_BAREWORD,
			    PARSE_ARRAY_COMMA);
			return;
		} else if (c == '-' || isdigit(c)) {
			(void) pushstate(s, PARSE_NUMBER, PARSE_ARRAY_COMMA);
			return;
		} else {
			posterror(s, EPROTO, "unexpected character at start "
			    "of value");
			return;
		}
	}
}

static void
hdlr_object(state_t *s)
{
	s->s_top->pf_value_type = JSON_TYPE_OBJECT;

	if (add_empty_child(s) != 0) {
		return;
	}

	discard_whitespace(s);

	switch (popchar(s)) {
	case '}':
		movestate(s, PARSE_DONE);
		return;

	case '"':
		movestate(s, PARSE_KEY_STRING);
		return;

	default:
		posterror(s, EPROTO, "expected key or '}'");
		return;
	}
}

static void
hdlr_key_string(state_t *s)
{
	if (collect_string(s) != 0) {
		return;
	}

	/*
	 * Record the key name of the next value.
	 */
	if ((s->s_top->pf_key = strdup(custr_cstr(s->s_collect))) == NULL) {
		posterror(s, errno, "strdup failure");
		return;
	}

	movestate(s, PARSE_COLON);
}

static void
hdlr_colon(state_t *s)
{
	char c;
	discard_whitespace(s);

	if ((c = popchar(s)) != ':') {
		posterror(s, EPROTO, "expected ':'");
		return;
	}

	discard_whitespace(s);

	/*
	 * Select which type handler we need for the value after the colon:
	 */
	switch (c = peekchar(s)) {
	case '"':
		(void) popchar(s);
		(void) pushstate(s, PARSE_STRING, PARSE_OBJECT_COMMA);
		return;

	case '{':
		(void) popchar(s);
		(void) pushstate(s, PARSE_OBJECT, PARSE_OBJECT_COMMA);
		return;

	case '[':
		(void) popchar(s);
		(void) pushstate(s, PARSE_ARRAY, PARSE_OBJECT_COMMA);
		return;

	default:
		if (islower(c)) {
			(void) pushstate(s, PARSE_BAREWORD, PARSE_OBJECT_COMMA);
			return;
		} else if (c == '-' || isdigit(c)) {
			(void) pushstate(s, PARSE_NUMBER, PARSE_OBJECT_COMMA);
			return;
		} else {
			(void) posterror(s, EPROTO, "unexpected character at "
			    "start of value");
			return;
		}
	}
}

static void
hdlr_object_comma(state_t *s)
{
	discard_whitespace(s);

	switch (popchar(s)) {
	case '}':
		movestate(s, PARSE_DONE);
		return;

	case ',':
		discard_whitespace(s);
		if (popchar(s) != '"') {
			posterror(s, EPROTO, "expected '\"'");
			return;
		}
		movestate(s, PARSE_KEY_STRING);
		return;

	default:
		posterror(s, EPROTO, "expected ',' or '}'");
		return;
	}
}

static void
hdlr_string(state_t *s)
{
	if (collect_string(s) != 0) {
		return;
	}

	s->s_top->pf_value_type = JSON_TYPE_STRING;
	if ((s->s_top->pf_value = strdup(custr_cstr(s->s_collect))) == NULL) {
		posterror(s, errno, "strdup failure");
		return;
	}

	movestate(s, PARSE_DONE);
}

static int
store_value(state_t *s)
{
	nvlist_t *targ = s->s_top->pf_next->pf_nvl;
	char *key = s->s_top->pf_next->pf_key;
	json_type_t type = s->s_top->pf_value_type;
	int ret = 0;

	switch (type) {
	case JSON_TYPE_STRING:
		if (nvlist_add_string(targ, key, s->s_top->pf_value) != 0) {
			posterror(s, errno, "nvlist_add_string failure");
			ret = -1;
		}
		free(s->s_top->pf_value);
		break;

	case JSON_TYPE_BOOLEAN:
		if (nvlist_add_boolean_value(targ, key,
		    (boolean_t)s->s_top->pf_value) != 0) {
			posterror(s, errno, "nvlist_add_boolean_value "
			    "failure");
			ret = -1;
		}
		break;

	case JSON_TYPE_NULL:
		if (nvlist_add_boolean(targ, key) != 0) {
			posterror(s, errno, "nvlist_add_boolean failure");
			ret = -1;
		}
		break;

	case JSON_TYPE_INTEGER:
		if (nvlist_add_int32(targ, key,
		    (int32_t)(uintptr_t)s->s_top->pf_value) != 0) {
			posterror(s, errno, "nvlist_add_int32 failure");
			ret = -1;
		}
		break;

	case JSON_TYPE_ARRAY:
	case JSON_TYPE_OBJECT:
		/*
		 * Objects and arrays are already 'stored' in their target
		 * nvlist on creation. See: hdlr_object, hdlr_array.
		 */
		break;

	default:
		(void) fprintf(stderr, "ERROR: could not store unknown "
		    "type %d\n", type);
		abort();
	}

	s->s_top->pf_value = NULL;
	free(s->s_top->pf_next->pf_key);
	s->s_top->pf_next->pf_key = NULL;
	return (ret);
}

static parse_frame_t *
parse_frame_free(parse_frame_t *pf, boolean_t free_nvl)
{
	parse_frame_t *next = pf->pf_next;
	if (pf->pf_key != NULL) {
		free(pf->pf_key);
	}
	if (pf->pf_value != NULL) {
		abort();
	}
	if (free_nvl && pf->pf_nvl != NULL) {
		nvlist_free(pf->pf_nvl);
	}
	free(pf);
	return (next);
}

static parse_handler_t hdlrs[] = {
	NULL,				/* PARSE_DONE */
	hdlr_rest,			/* PARSE_REST */
	hdlr_object,			/* PARSE_OBJECT */
	hdlr_key_string,		/* PARSE_KEY_STRING */
	hdlr_colon,			/* PARSE_COLON */
	hdlr_string,			/* PARSE_STRING */
	hdlr_object_comma,		/* PARSE_OBJECT_COMMA */
	hdlr_array,			/* PARSE_ARRAY */
	hdlr_bareword,			/* PARSE_BAREWORD */
	hdlr_number,			/* PARSE_NUMBER */
	hdlr_array_value,		/* PARSE_ARRAY_VALUE */
	hdlr_array_comma		/* PARSE_ARRAY_COMMA */
};
#define	NUM_PARSE_HANDLERS	(int)(sizeof (hdlrs) / sizeof (hdlrs[0]))

int
nvlist_parse_json(const char *buf, size_t buflen, nvlist_t **nvlp,
    nvlist_parse_json_flags_t flag, nvlist_parse_json_error_t *errout)
{
	state_t s;

	/*
	 * Check for valid flags:
	 */
	if ((flag & NVJSON_FORCE_INTEGER) && (flag & NVJSON_FORCE_DOUBLE)) {
		errno = EINVAL;
		return (-1);
	}
	if ((flag & ~NVJSON_ALL) != 0) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Initialise parsing state structure:
	 */
	bzero(&s, sizeof (s));
	s.s_in = buf;
	s.s_pos = 0;
	s.s_len = buflen;
	s.s_flags = flag;

	/*
	 * Allocate the collect buffer string.
	 */
	if (custr_alloc(&s.s_collect) != 0) {
		s.s_errno = errno;
		if (errout != NULL) {
			(void) snprintf(errout->nje_message,
			    sizeof (errout->nje_message),
			    "custr alloc failure: %s",
			    strerror(errno));
		}
		goto out;
	}

	/*
	 * If the caller has requested error information, allocate the error
	 * string now.
	 */
	if (errout != NULL) {
		if (custr_alloc_buf(&s.s_errstr, errout->nje_message,
		    sizeof (errout->nje_message)) != 0) {
			s.s_errno = errno;
			(void) snprintf(errout->nje_message,
			    sizeof (errout->nje_message),
			    "custr alloc failure: %s",
			    strerror(errno));
			goto out;
		}
		custr_reset(s.s_errstr);
	}

	/*
	 * Allocate top-most stack frame:
	 */
	if ((s.s_top = calloc(1, sizeof (*s.s_top))) == NULL) {
		s.s_errno = errno;
		goto out;
	}

	s.s_top->pf_ps = PARSE_REST;
	for (;;) {
		if (s.s_top->pf_ps < 0) {
			/*
			 * The parser reported an error.
			 */
			goto out;
		}

		if (s.s_top->pf_ps == PARSE_DONE) {
			if (s.s_top->pf_next == NULL) {
				/*
				 * Last frame, so we're really
				 * done.
				 */
				*nvlp = s.s_top->pf_nvl;
				goto out;
			} else {
				/*
				 * Otherwise, pop a frame and continue in
				 * previous state.  Copy out the value we
				 * created in the old frame:
				 */
				if (store_value(&s) != 0) {
					goto out;
				}

				/*
				 * Free old frame:
				 */
				s.s_top = parse_frame_free(s.s_top, B_FALSE);
			}
		}

		/*
		 * Dispatch to parser handler routine for this state:
		 */
		if (s.s_top->pf_ps >= NUM_PARSE_HANDLERS ||
		    hdlrs[s.s_top->pf_ps] == NULL) {
			(void) fprintf(stderr, "no handler for state %d\n",
			    s.s_top->pf_ps);
			abort();
		}
		hdlrs[s.s_top->pf_ps](&s);
	}

out:
	if (errout != NULL) {
		/*
		 * Copy out error number and parse position.  The custr_t for
		 * the error message was backed by the buffer in the error
		 * object, so no copying is required.
		 */
		errout->nje_errno = s.s_errno;
		errout->nje_pos = s.s_pos;
	}

	/*
	 * Free resources:
	 */
	while (s.s_top != NULL) {
		s.s_top = parse_frame_free(s.s_top, s.s_errno == 0 ? B_FALSE :
		    B_TRUE);
	}
	custr_free(s.s_collect);
	custr_free(s.s_errstr);

	errno = s.s_errno;
	return (s.s_errno == 0 ? 0 : -1);
}
