#include <string.h>
#include "target.h"
#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "expression.h"
#include "char.h"

static const char *parse_escape(const char *p, unsigned *val, const char *end, int bits, struct position pos)
{
	unsigned c = *p++;
	unsigned d;
	if (c != '\\') {
		*val = c;
		return p;
	}

	c = *p++;
	switch (c) {
	case 'a': c = '\a'; break;
	case 'b': c = '\b'; break;
	case 't': c = '\t'; break;
	case 'n': c = '\n'; break;
	case 'v': c = '\v'; break;
	case 'f': c = '\f'; break;
	case 'r': c = '\r'; break;
	case 'e': c = '\e'; break;
	case 'x': {
		unsigned mask = -(1U << (bits - 4));
		for (c = 0; p < end; c = (c << 4) + d) {
			d = hexval(*p);
			if (d > 16)
				break;
			p++;
			if (c & mask) {
				warning(pos,
					"hex escape sequence out of range");
				mask = 0;
			}
		}
		break;
	}
	case '0'...'7': {
		if (p + 2 < end)
			end = p + 2;
		c -= '0';
		while (p < end && (d = *p - '0') < 8) {
			c = (c << 3) + d;
			p++;
		}
		if ((c & 0400) && bits < 9)
			warning(pos,
				"octal escape sequence out of range");
		break;
	}
	default:	/* everything else is left as is */
		warning(pos, "unknown escape sequence: '\\%c'", c);
		break;
	case '\\':
	case '\'':
	case '"':
	case '?':
		break;	/* those are legal, so no warnings */
	}
	*val = c & ~((~0U << (bits - 1)) << 1);
	return p;
}

void get_char_constant(struct token *token, unsigned long long *val)
{
	const char *p = token->embedded, *end;
	unsigned v;
	int type = token_type(token);
	switch (type) {
	case TOKEN_CHAR:
	case TOKEN_WIDE_CHAR:
		p = token->string->data;
		end = p + token->string->length - 1;
		break;
	case TOKEN_CHAR_EMBEDDED_0 ... TOKEN_CHAR_EMBEDDED_3:
		end = p + type - TOKEN_CHAR;
		break;
	default:
		end = p + type - TOKEN_WIDE_CHAR;
	}
	p = parse_escape(p, &v, end,
			type < TOKEN_WIDE_CHAR ? bits_in_char : wchar_ctype->bit_size, token->pos);
	if (p != end)
		warning(token->pos,
			"multi-character character constant");
	*val = v;
}

struct token *get_string_constant(struct token *token, struct expression *expr)
{
	struct string *string = token->string;
	struct token *next = token->next, *done = NULL;
	int stringtype = token_type(token);
	int is_wide = stringtype == TOKEN_WIDE_STRING;
	static char buffer[MAX_STRING];
	int len = 0;
	int bits;
	int esc_count = 0;

	while (!done) {
		switch (token_type(next)) {
		case TOKEN_WIDE_STRING:
			is_wide = 1;
		case TOKEN_STRING:
			next = next->next;
			break;
		default:
			done = next;
		}
	}
	bits = is_wide ? wchar_ctype->bit_size: bits_in_char;
	while (token != done) {
		unsigned v;
		const char *p = token->string->data;
		const char *end = p + token->string->length - 1;
		while (p < end) {
			if (*p == '\\')
				esc_count++;
			p = parse_escape(p, &v, end, bits, token->pos);
			if (len < MAX_STRING)
				buffer[len] = v;
			len++;
		}
		token = token->next;
	}
	if (len > MAX_STRING) {
		warning(token->pos, "trying to concatenate %d-character string (%d bytes max)", len, MAX_STRING);
		len = MAX_STRING;
	}

	if (esc_count || len >= string->length) {
		if (string->immutable || len >= string->length)	/* can't cannibalize */
			string = __alloc_string(len+1);
		string->length = len+1;
		memcpy(string->data, buffer, len);
		string->data[len] = '\0';
	}
	expr->string = string;
	expr->wide = is_wide;
	return token;
}
