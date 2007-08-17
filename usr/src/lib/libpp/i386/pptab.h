/*
 * 
 * Glenn Fowler
 * AT&T Research
 * 
 * @(#)pp.tab (AT&T Labs Research) 2006-05-09
 * 
 * C preprocessor tables and states
 * 
 * + marks extensions to the standard
 * 
 */

static struct ppkeyword directives[] =
{
	"define",	DEFINE,
	"elif",	ELIF,
	"else",	ELSE,
	"endif",	ENDIF,
	"+endmac",	ENDMAC,
	"error",	ERROR,
	"if",	IF,
	"ifdef",	IFDEF,
	"ifndef",	IFNDEF,
	"include",	INCLUDE,
	"+let",	LET,
	"line",	LINE,
	"+macdef",	MACDEF,
	"pragma",	PRAGMA,
	"+rename",	RENAME,
	"undef",	UNDEF,
	"+warning",	WARNING,
	0,	0
};

static struct ppkeyword options[] =
{
	"allmultiple",	X_ALLMULTIPLE,
	"allpossible",	X_ALLPOSSIBLE,
	"builtin",	X_BUILTIN,
	"catliteral",	X_CATLITERAL,
	"cdir",	X_CDIR,
	"checkpoint",	X_CHECKPOINT,
	"chop",	X_CHOP,
	"compatibility",	X_COMPATIBILITY,
	"debug",	X_DEBUG,
	"elseif",	X_ELSEIF,
	"externalize",	X_EXTERNALIZE,
	"final",	X_FINAL,
	"hide",	X_HIDE,
	"headerexpand",	X_HEADEREXPAND,
	"headerexpandall",	X_HEADEREXPANDALL,
	"hosted",	X_HOSTED,
	"hostedtransition",	X_HOSTEDTRANSITION,
	"hostdir",	X_HOSTDIR,
	"id",	X_ID,
	"ignore",	X_IGNORE,
	"include",	X_INCLUDE,
	"initial",	X_INITIAL,
	"keyargs",	X_KEYARGS,
	"line",	X_LINE,
	"linebase",	X_LINEBASE,
	"linefile",	X_LINEFILE,
	"lineid",	X_LINEID,
	"linetype",	X_LINETYPE,
	"macref",	X_MACREF,
	"map",	X_MAP,
	"mapinclude",	X_MAPINCLUDE,
	"modern",	X_MODERN,
	"multiple",	X_MULTIPLE,
	"native",	X_NATIVE,
	"note",	X_NOTE,
	"opspace",	X_OPSPACE,
	"passthrough",	X_PASSTHROUGH,
	"pedantic",	X_PEDANTIC,
	"pluscomment",	X_PLUSCOMMENT,
	"plusplus",	X_PLUSPLUS,
	"plussplice",	X_PLUSSPLICE,
	"pragmaflags",	X_PRAGMAFLAGS,
	"pragmaexpand",	X_PRAGMAEXPAND,
	"predefined",	X_PREDEFINED,
	"prefix",	X_PREFIX,
	"preserve",	X_PRESERVE,
	"proto",	X_PROTO,
	"prototyped",	X_PROTOTYPED,
	"quote",	X_QUOTE,
	"readonly",	X_READONLY,
	"reguard",	X_REGUARD,
	"reserved",	X_RESERVED,
	"spaceout",	X_SPACEOUT,
	"splicecat",	X_SPLICECAT,
	"splicespace",	X_SPLICESPACE,
	"standard",	X_STANDARD,
	"statement",	X_STATEMENT,
	"strict",	X_STRICT,
	"stringspan",	X_STRINGSPAN,
	"stringsplit",	X_STRINGSPLIT,
	"system_header",	X_SYSTEM_HEADER,
	"test",	X_TEST,
	"text",	X_TEXT,
	"transition",	X_TRANSITION,
	"truncate",	X_TRUNCATE,
	"vendor",	X_VENDOR,
	"version",	X_VERSION,
	"warn",	X_WARN,
	"zeof",	X_ZEOF,
	0,	0
};

static struct ppkeyword predicates[] =
{
	"defined",	X_DEFINED,
	"+exists",	X_EXISTS,
	"+included",	X_INCLUDED,
	"+match",	X_MATCH,
	"+noticed",	X_NOTICED,
	"+option",	X_OPTION,
	"sizeof",	X_SIZEOF,
	"+strcmp",	X_STRCMP,
	0,	0
};

static struct ppkeyword readonlys[] =
{
	"defined",	R_DEFINED,
	0,	0
};

static struct ppkeyword variables[] =
{
	"_Pragma",	V__PRAGMA,
	"+ARGC",	V_ARGC,
	"+BASE",	V_BASE,
	"DATE",	V_DATE,
	"FILE",	V_FILE,
	"+FUNCTION",	V_FUNCTION,
	"LINE",	V_LINE,
	"+PATH",	V_PATH,
	"+SOURCE",	V_SOURCE,
	"-STDC",	V_STDC,
	"TIME",	V_TIME,
	"+VERSION",	V_VERSION,
	"-default",	V_DEFAULT,
	"-directive",	V_DIRECTIVE,
	"-empty",	V_EMPTY,
	"-getenv",	V_GETENV,
	"-getmac",	V_GETMAC,
	"-getopt",	V_GETOPT,
	"-getprd",	V_GETPRD,
	"-iterate",	V_ITERATE,
	0,	0
};
