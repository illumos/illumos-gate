static int e[] = { '\'', '\"', '\?', '\\',
                   '\a', '\b', '\f', '\n', '\r', '\t', '\v',
		   '\0', '\012', '\x7890', '\xabcd' };
static char *s = "\'\"\?\\ \a\b\f\n\r\t\v \377\xcafe";

static int bad_e[] = { '\c', '\0123', '\789', '\xdefg' };

static char a_hex[3] = "\x61\x62\x63";
static char b_hex[3] = "\x61\x62\x63\x64";
static char c_hex[3] = "\x61\x62";
static char d_hex[3] = "\x61";

static char a_oct[3] = "\141\142\143";
static char b_oct[3] = "\141\142\143\144";
static char c_oct[3] = "\141\142";
static char d_oct[3] = "\141";
/*
 * check-name: Character escape sequences
 *
 * check-error-start
escapes.c:3:34: warning: hex escape sequence out of range
escapes.c:3:44: warning: hex escape sequence out of range
escapes.c:4:18: warning: hex escape sequence out of range
escapes.c:6:24: warning: unknown escape sequence: '\c'
escapes.c:6:30: warning: multi-character character constant
escapes.c:6:39: warning: multi-character character constant
escapes.c:6:47: warning: hex escape sequence out of range
escapes.c:6:47: warning: multi-character character constant
escapes.c:9:24: warning: too long initializer-string for array of char
escapes.c:14:24: warning: too long initializer-string for array of char
 * check-error-end
 */
