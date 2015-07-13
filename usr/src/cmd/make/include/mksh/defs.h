#ifndef _MKSH_DEFS_H
#define _MKSH_DEFS_H
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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#include <limits.h>		/* MB_LEN_MAX */
#include <stdio.h>
#include <stdlib.h>		/* wchar_t */
#include <string.h>		/* strcmp() */
#include <sys/param.h>		/* MAXPATHLEN */
#include <sys/types.h>		/* time_t, caddr_t */
#include <vroot/vroot.h>	/* pathpt */
#include <sys/time.h>		/* timestruc_t */
#include <errno.h>		/* errno */

#include <wctype.h>

/*
 * A type and some utilities for boolean values
 */

#define	false	BOOLEAN_false
#define	true	BOOLEAN_true

typedef enum {
	false =		0,
	true =		1,
	failed =	0,
	succeeded =	1
} Boolean;
#define BOOLEAN(expr)		((expr) ? true : false)

/*
 * Some random constants (in an enum so dbx knows their values)
 */
enum {
	update_delay = 30,		/* time between rstat checks */
	ar_member_name_len = 1024,
	hashsize = 2048			/* size of hash table */
};


/*
 * Symbols that defines all the different char constants make uses
 */
enum {
	ampersand_char =	'&',
	asterisk_char =		'*',
	at_char =		'@',
	backquote_char =	'`',
	backslash_char =	'\\',
	bar_char =		'|',
	braceleft_char =	'{',
	braceright_char =	'}',
	bracketleft_char =	'[',
	bracketright_char =	']',
	colon_char =		':',
	comma_char =		',',
	dollar_char =		'$',
	doublequote_char =	'"',
	equal_char =		'=',
	exclam_char =		'!',
	greater_char =		'>',
	hat_char =		'^',
	hyphen_char =		'-',
	less_char =		'<',
	newline_char =		'\n',
	nul_char =		'\0',
	numbersign_char =	'#',
	parenleft_char =	'(',
	parenright_char =	')',
	percent_char =		'%',
	period_char =		'.',
	plus_char =		'+',
	question_char =		'?',
	quote_char =		'\'',
	semicolon_char =	';',
	slash_char =		'/',
	space_char =		' ',
	tab_char =		'\t',
	tilde_char =		'~'
};

/*
 * For make i18n. Codeset independent.
 * Setup character semantics by identifying all the special characters
 * of make, and assigning each an entry in the char_semantics[] vector.
 */
enum {
	ampersand_char_entry = 0,	/*  0 */
	asterisk_char_entry,		/*  1 */
	at_char_entry,			/*  2 */
	backquote_char_entry,		/*  3 */
	backslash_char_entry,		/*  4 */
	bar_char_entry,			/*  5 */
	bracketleft_char_entry,		/*  6 */
	bracketright_char_entry,	/*  7 */
	colon_char_entry,		/*  8 */
	dollar_char_entry,		/*  9 */
	doublequote_char_entry,		/* 10 */
	equal_char_entry,		/* 11 */
	exclam_char_entry,		/* 12 */
	greater_char_entry,		/* 13 */
	hat_char_entry,			/* 14 */
	hyphen_char_entry,		/* 15 */
	less_char_entry,		/* 16 */
	newline_char_entry,		/* 17 */
	numbersign_char_entry,		/* 18 */
	parenleft_char_entry,		/* 19 */
	parenright_char_entry,		/* 20 */
	percent_char_entry,		/* 21 */
	plus_char_entry,		/* 22 */
	question_char_entry,		/* 23 */
	quote_char_entry,		/* 24 */
	semicolon_char_entry,		/* 25 */
	no_semantics_entry		/* 26 */
};

/*
 * CHAR_SEMANTICS_ENTRIES should be the number of entries above.
 * The last entry in char_semantics[] should be blank.
 */
#define CHAR_SEMANTICS_ENTRIES	27
/*
#define CHAR_SEMANTICS_STRING	"&*@`\\|[]:$=!>-\n#()%+?;^<'\""
 */

/*
 * Some utility macros
 */
#define ALLOC(x)		((struct _##x *)getmem(sizeof (struct _##x)))
#define ALLOC_WC(x)		((wchar_t *)getmem((x) * SIZEOFWCHAR_T))
#define FIND_LENGTH		-1
#define GETNAME(a,b)		getname_fn((a), (b), false)
#define IS_EQUAL(a,b)		(!strcmp((a), (b)))
#define IS_EQUALN(a,b,n)	(!strncmp((a), (b), (n)))
#define IS_WEQUAL(a,b)		(!wcscmp((a), (b)))
#define IS_WEQUALN(a,b,n)	(!wcsncmp((a), (b), (n)))
#define MBLEN(a)		mblen((a), MB_LEN_MAX)
#define MBSTOWCS(a,b)		(void) mbstowcs_with_check((a), (b), MAXPATHLEN)
#define	MBTOWC(a,b)		mbtowc((a), (b), MB_LEN_MAX)
#define	SIZEOFWCHAR_T		(sizeof (wchar_t))
#define VSIZEOF(v)		(sizeof (v) / sizeof ((v)[0]))
#define WCSTOMBS(a,b)		(void) wcstombs((a), (b), (MAXPATHLEN * MB_LEN_MAX))
#define WCTOMB(a,b)		(void) wctomb((a), (b))
#define	HASH(v, c)		(v = (v)*31 + (unsigned int)(c))

extern void mbstowcs_with_check(wchar_t *pwcs, const char *s, size_t n);

/*
 * Bits stored in funny vector to classify chars
 */
enum {
	dollar_sem =		0001,
	meta_sem =		0002,
	percent_sem =		0004,
	wildcard_sem =		0010,
	command_prefix_sem =	0020,
	special_macro_sem =	0040,
	colon_sem =		0100,
	parenleft_sem =		0200
};

/*
 * Type returned from doname class functions
 */
typedef enum {
	build_dont_know = 0,
	build_failed,
	build_ok,
	build_in_progress,
	build_running,		/* PARALLEL & DISTRIBUTED */
	build_pending,		/* PARALLEL & DISTRIBUTED */
	build_serial,		/* PARALLEL & DISTRIBUTED */
	build_subtree		/* PARALLEL & DISTRIBUTED */
} Doname;

/*
 * The String struct defines a string with the following layout
 *	"xxxxxxxxxxxxxxxCxxxxxxxxxxxxxxx________"
 *	^		^		^		^
 *	|		|		|		|
 *	buffer.start	text.p		text.end	buffer.end
 *	text.p points to the next char to read/write.
 */
struct _String {
	struct Text {
		wchar_t		*p;	/* Read/Write pointer */
		wchar_t		*end;	/* Read limit pointer */
	}		text;
	struct Physical_buffer {
		wchar_t		*start;	/* Points to start of buffer */
		wchar_t		*end;	/* End of physical buffer */
	}		buffer;
	Boolean		free_after_use:1;
};

#define STRING_BUFFER_LENGTH	1024
#define INIT_STRING_FROM_STACK(str, buf) { \
			str.buffer.start = (buf); \
			str.text.p = (buf); \
			str.text.end = NULL; \
			str.buffer.end = (buf) \
                          + (sizeof (buf)/SIZEOFWCHAR_T); \
			str.free_after_use = false; \
		  }

#define APPEND_NAME(np, dest, len)	append_string((np)->string_mb, (dest), (len));

class Wstring {
	public:
		struct _String	string;
		wchar_t		string_buf[STRING_BUFFER_LENGTH];

	public:
		Wstring();
		Wstring(struct _Name * name);
		~Wstring();

		void init(struct _Name * name);
		void init(wchar_t * name, unsigned length);
		unsigned length() {
			return wcslen(string.buffer.start);
		};
		void append_to_str(struct _String * str, unsigned off, unsigned length);

		wchar_t * get_string() {
			return string.buffer.start;
		};

		wchar_t * get_string(unsigned off) {
			return string.buffer.start + off;
		};

		Boolean equaln(wchar_t * str, unsigned length);
		Boolean equal(wchar_t * str);
		Boolean equal(wchar_t * str, unsigned off);
		Boolean equal(wchar_t * str, unsigned off, unsigned length);

		Boolean equaln(Wstring * str, unsigned length);
		Boolean equal(Wstring * str);
		Boolean equal(Wstring * str, unsigned off);
		Boolean equal(Wstring * str, unsigned off, unsigned length);
};


/*
 * Used for storing the $? list and also for the "target + target:"
 * construct.
 */
struct _Chain {
	struct _Chain		*next;
	struct _Name		*name;
	struct _Percent	*percent_member;
};

/*
 * Stores one command line for a rule
 */
struct _Cmd_line {
	struct _Cmd_line	*next;
	struct _Name		*command_line;
	Boolean			make_refd:1;	/* $(MAKE) referenced? */
	/*
	 * Remember any command line prefixes given
	 */
	Boolean			ignore_command_dependency:1;	/* `?' */
	Boolean			assign:1;			/* `=' */
	Boolean			ignore_error:1;			/* `-' */
	Boolean			silent:1;			/* `@' */
	Boolean			always_exec:1;			/* `+' */
};

/*
 * Linked list of targets/files
 */
struct _Dependency {
	struct _Dependency	*next;
	struct _Name		*name;
	Boolean			automatic:1;
	Boolean			stale:1;
	Boolean			built:1;
};

/*
 * The specials are markers for targets that the reader should special case
 */
typedef enum {
	no_special,
	built_last_make_run_special,
	default_special,
	get_posix_special,
	get_special,
	ignore_special,
	keep_state_file_special,
	keep_state_special,
	make_version_special,
	no_parallel_special,
	parallel_special,
	posix_special,
	precious_special,
	sccs_get_posix_special,
	sccs_get_special,
	silent_special,
	suffixes_special,
	svr4_special,
	localhost_special
} Special;

typedef enum {
	no_colon,
	one_colon,
	two_colon,
	equal_seen,
	conditional_seen,
	none_seen
} Separator;

/*
 * Magic values for the timestamp stored with each name object
 */


extern const timestruc_t file_no_time;
extern const timestruc_t file_doesnt_exist;
extern const timestruc_t file_is_dir;
extern const timestruc_t file_min_time;
extern const timestruc_t file_max_time;

/*
 * Each Name has a list of properties
 * The properties are used to store information that only
 * a subset of the Names need
 */
typedef enum {
	no_prop,
	conditional_prop,
	line_prop,
	macro_prop,
	makefile_prop,
	member_prop,
	recursive_prop,
	sccs_prop,
	suffix_prop,
	target_prop,
	time_prop,
	vpath_alias_prop,
	long_member_name_prop,
	macro_append_prop,
	env_mem_prop
} Property_id;

typedef enum {
	no_daemon = 0,
	chain_daemon
} Daemon;

struct _Env_mem {
	char		*value;
};

struct _Macro_appendix {
	struct _Name		*value;
	struct _Name		*value_to_append;
};

struct _Macro {
	/*
	* For "ABC = xyz" constructs
	* Name "ABC" get one macro prop
	*/
	struct _Name		*value;
	Boolean			exported:1;
	Boolean			read_only:1;
	/*
	* This macro is defined conditionally
	*/
	Boolean			is_conditional:1;
	/*
	* The list for $? is stored as a structured list that
	* is translated into a string iff it is referenced.
	* This is why  some macro values need a daemon.
	*/
	Daemon			daemon:2;
};

struct _Macro_list {
	struct _Macro_list	*next;
	char			*macro_name;
	char			*value;
};

enum sccs_stat {
	DONT_KNOW_SCCS = 0,
	NO_SCCS,
	HAS_SCCS
};

struct _Name {
	struct _Property	*prop;		/* List of properties */
	char			*string_mb;     /* Multi-byte name string */
	struct {
		unsigned int		length;
	}                       hash;
	struct {
		timestruc_t		time;		/* Modification */
		int			stat_errno;	/* error from "stat" */
		off_t			size;		/* Of file */
		mode_t			mode;		/* Of file */
		Boolean			is_file:1;
		Boolean			is_dir:1;
		Boolean			is_sym_link:1;
		Boolean			is_precious:1;
		enum sccs_stat		has_sccs:2;
	}                       stat;
	/*
	 * Count instances of :: definitions for this target
	 */
	short			colon_splits;
	/*
	 * We only clear the automatic depes once per target per report
	 */
	short			temp_file_number;
	/*
	 * Count how many conditional macros this target has defined
	 */
	short			conditional_cnt;
	/*
	 * A conditional macro was used when building this target
	 */
	Boolean			depends_on_conditional:1;
	/*
	 * Pointer to list of conditional macros which were used to build
	 * this target
	 */
	struct _Macro_list	*conditional_macro_list;
	Boolean			has_member_depe:1;
	Boolean			is_member:1;
	/*
	 * This target is a directory that has been read
	 */
	Boolean			has_read_dir:1;
	/*
	 * This name is a macro that is now being expanded
	 */
	Boolean			being_expanded:1;
	/*
	 * This name is a magic name that the reader must know about
	 */
	Special			special_reader:5;
	Doname			state:3;
	Separator		colons:3;
	Boolean			has_depe_list_expanded:1;
	Boolean			suffix_scan_done:1;
	Boolean			has_complained:1;	/* For sccs */
	/*
	 * This target has been built during this make run
	 */
	Boolean			ran_command:1;
	Boolean			with_squiggle:1;	/* for .SUFFIXES */
	Boolean			without_squiggle:1;	/* for .SUFFIXES */
	Boolean			has_read_suffixes:1;	/* Suffix list cached*/
	Boolean			has_suffixes:1;
	Boolean			has_target_prop:1;
	Boolean			has_vpath_alias_prop:1;
	Boolean			dependency_printed:1;	/* For dump_make_state() */
	Boolean			dollar:1;		/* In namestring */
	Boolean			meta:1;			/* In namestring */
	Boolean			percent:1;		/* In namestring */
	Boolean			wildcard:1;		/* In namestring */
        Boolean                 has_parent:1;
        Boolean                 is_target:1;
	Boolean			has_built:1;
	Boolean			colon:1;		/* In namestring */
	Boolean			parenleft:1;		/* In namestring */
	Boolean			has_recursive_dependency:1;
	Boolean			has_regular_dependency:1;
	Boolean			is_double_colon:1;
	Boolean			is_double_colon_parent:1;
	Boolean			has_long_member_name:1;
	/*
	 * allowed to run in parallel
	 */
	Boolean			parallel:1;
	/*
	 * not allowed to run in parallel
	 */
	Boolean			no_parallel:1;
	/*
	 * used in dependency_conflict
	 */
	Boolean			checking_subtree:1;
	Boolean			added_pattern_conditionals:1;
	/*
	 * rechecking target for possible rebuild
	 */
	Boolean			rechecking_target:1;
	/*
	 * build this target in silent mode
	 */
	Boolean			silent_mode:1;
	/*
	 * build this target in ignore error mode
	 */
	Boolean			ignore_error_mode:1;
	Boolean			dont_activate_cond_values:1;
	/*
	 * allowed to run serially on local host
	 */
	Boolean			localhost:1;
};

/*
 * Stores the % matched default rules
 */
struct _Percent {
	struct _Percent	*next;
	struct _Name		**patterns;
	struct _Name		*name;
	struct _Percent		*dependencies;
	struct _Cmd_line	*command_template;
	struct _Chain		*target_group;
	int			patterns_total;
	Boolean			being_expanded;
};

struct Conditional {
	/*
	 * For "foo := ABC [+]= xyz" constructs
	 * Name "foo" gets one conditional prop
	 */
	struct _Name		*target;
	struct _Name		*name;
	struct _Name		*value;
	int			sequence;
	Boolean			append:1;
};

struct Line {
	/*
	 * For "target : dependencies" constructs
	 * Name "target" gets one line prop
	 */
	struct _Cmd_line	*command_template;
	struct _Cmd_line	*command_used;
	struct _Dependency	*dependencies;
	timestruc_t		dependency_time;
	struct _Chain		*target_group;
	Boolean			is_out_of_date:1;
	Boolean			sccs_command:1;
	Boolean			command_template_redefined:1;
	Boolean			dont_rebuild_command_used:1;
	/*
	 * Values for the dynamic macros
	 */
	struct _Name		*target;
	struct _Name		*star;
	struct _Name		*less;
	struct _Name		*percent;
	struct _Chain		*query;
};

struct Makefile {
	/*
	 * Names that reference makefiles gets one prop
	 */
	wchar_t			*contents;
	off_t			size;
};

struct Member {
	/*
	 * For "lib(member)" and "lib((entry))" constructs
	 * Name "lib(member)" gets one member prop
	 * Name "lib((entry))" gets one member prop
	 * The member field is filled in when the prop is refd
	 */
	struct _Name		*library;
	struct _Name		*entry;
	struct _Name		*member;
};

struct Recursive {
	/*
	 * For "target: .RECURSIVE dir makefiles" constructs
	 * Used to keep track of recursive calls to make
	 * Name "target" gets one recursive prop
	 */
	struct _Name		*directory;
	struct _Name		*target;
	struct _Dependency	*makefiles;
	Boolean			has_built;
	Boolean			in_depinfo;
};

struct Sccs {
	/*
	 * Each file that has a SCCS s. file gets one prop
	 */
	struct _Name		*file;
};

struct Suffix {
	/*
	 * Cached list of suffixes that can build this target
	 * suffix is built from .SUFFIXES
	 */
	struct _Name		*suffix;
	struct _Cmd_line	*command_template;
};

struct Target {
	/*
	 * For "target:: dependencies" constructs
	 * The "::" construct is handled by converting it to
	 * "foo: 1@foo" + "1@foo: dependecies"
	 * "1@foo" gets one target prop
	 * This target prop cause $@ to be bound to "foo"
	 * not "1@foo" when the rule is evaluated
	 */
	struct _Name		*target;
};

struct STime {
	/*
	 * Save the original time for :: targets
	 */
	timestruc_t			time;
};

struct Vpath_alias {
	/*
	 * If a file was found using the VPATH it gets
	 * a vpath_alias prop
	 */
	struct _Name		*alias;
};

struct Long_member_name {
	/*
	 * Targets with a truncated member name carries
	 * the full lib(member) name for the state file
	 */
	struct _Name		*member_name;
};

union Body {
	struct _Macro		macro;
	struct Conditional	conditional;
	struct Line		line;
	struct Makefile		makefile;
	struct Member		member;
	struct Recursive	recursive;
	struct Sccs		sccs;
	struct Suffix		suffix;
	struct Target		target;
	struct STime		time;
	struct Vpath_alias	vpath_alias;
	struct Long_member_name	long_member_name;
	struct _Macro_appendix	macro_appendix;
	struct _Env_mem		env_mem;
};

#define PROPERTY_HEAD_SIZE (sizeof (struct _Property)-sizeof (union Body))
struct _Property {
	struct _Property	*next;
	Property_id		type:4;
	union Body		body;
};

/* Structure for dynamic "ascii" arrays */
struct ASCII_Dyn_Array {
	char			*start;
	size_t			size;
};

struct _Envvar {
	struct _Name		*name;
	struct _Name		*value;
	struct _Envvar		*next;
	char			*env_string;
	Boolean			already_put:1;
};

/*
 * Macros for the reader
 */
#define GOTO_STATE(new_state) { \
				  SET_STATE(new_state); \
				    goto enter_state; \
			      }
#define SET_STATE(new_state) state = (new_state)

#define UNCACHE_SOURCE()	if (source != NULL) { \
					source->string.text.p = source_p; \
				  }
#define CACHE_SOURCE(comp)	if (source != NULL) { \
					source_p = source->string.text.p - \
					  (comp); \
					source_end = source->string.text.end; \
				  }
#define GET_NEXT_BLOCK_NOCHK(source)	{ UNCACHE_SOURCE(); \
				 source = get_next_block_fn(source); \
				 CACHE_SOURCE(0) \
			   }
#define GET_NEXT_BLOCK(source)	{ GET_NEXT_BLOCK_NOCHK(source); \
				 if (source != NULL && source->error_converting) { \
				 	GOTO_STATE(illegal_bytes_state); \
				 } \
			   }
#define GET_CHAR()		((source == NULL) || \
				(source_p >= source_end) ? 0 : *source_p)

struct _Source {
	struct _String		string;
	struct _Source		*previous;
	off_t			bytes_left_in_file;
	short			fd;
	Boolean			already_expanded:1;
	Boolean			error_converting:1;
	char			*inp_buf;
	char			*inp_buf_end;
	char			*inp_buf_ptr;
};

typedef enum {
	reading_nothing,
	reading_makefile,
	reading_statefile,
	rereading_statefile,
	reading_cpp_file
} Makefile_type;

/*
 * Typedefs for all structs
 */
typedef struct _Chain		*Chain, Chain_rec;
typedef struct _Envvar		*Envvar, Envvar_rec;
typedef struct _Macro_list	*Macro_list, Macro_list_rec;
typedef struct _Name		*Name, Name_rec;
typedef struct _Property	*Property, Property_rec;
typedef struct _Source		*Source, Source_rec;
typedef struct _String		*String, String_rec;

/*
 * name records hash table.
 */
struct Name_set {
private:
	// single node in a tree
	struct entry {
		entry(Name name_, entry *parent_) :
			name(name_),
			parent(parent_),
			left(0),
			right(0),
			depth(1)
		{}

		Name		name;

		entry		*parent;
		entry		*left;
		entry		*right;
		unsigned	depth;

		void setup_depth() {
			unsigned rdepth = (right != 0) ? right->depth : 0;
			unsigned ldepth = (left != 0) ? left->depth : 0;
			depth = 1 + ((ldepth > rdepth) ? ldepth : rdepth);
		}
	};

public:
	// make iterator a friend of Name_set to have access to struct entry
	struct iterator;
	friend struct Name_set::iterator;

	// iterator over tree nodes
	struct iterator {
	public:
		// constructors
		iterator() : node(0) {}
		iterator(entry *node_) : node(node_) {}

		// dereference operator
		Name operator->() const { return node->name; }

		// conversion operator
		operator Name() { return node->name; }

		// assignment operator
		iterator& operator=(const iterator &o) { node = o.node; return *this; }

		// equality/inequality operators
		int operator==(const iterator &o) const { return (node == o.node); }
		int operator!=(const iterator &o) const { return (node != o.node); }

		// pre/post increment operators
		iterator& operator++();
		iterator  operator++(int) { iterator it = *this; ++*this; return it; }

	private:
		// the node iterator points to
		entry *node;
	};

public:
	// constructor
	Name_set() : root(0) {}

	// lookup, insert and remove operations
	Name lookup(const char *key);
	Name insert(const char *key, Boolean &found);
	void insert(Name name);

	// begin/end iterators
	iterator begin() const;
	iterator end() const { return iterator(); }

private:
	// rebalance given node
	void	rebalance(entry *node);

private:
	// tree root
	entry	*root;
};

/*
 *	extern declarations for all global variables.
 *	The actual declarations are in globals.cc
 */
extern char		char_semantics[];
extern wchar_t		char_semantics_char[];
extern Macro_list	cond_macro_list;
extern Boolean		conditional_macro_used;
extern Boolean		do_not_exec_rule;		/* `-n' */
extern Boolean		dollarget_seen;
extern Boolean		dollarless_flag;
extern Name		dollarless_value;
extern char		**environ;
extern Envvar		envvar;
extern int		exit_status;
extern wchar_t		*file_being_read;
/* Variable gnu_style=true if env. var. SUN_MAKE_COMPAT_MODE=GNU (RFE 4866328) */
extern Boolean		gnu_style;
extern Name_set		hashtab;
extern Name		host_arch;
extern Name		host_mach;
extern int		line_number;
extern char		*make_state_lockfile;
extern Boolean		make_word_mentioned;
extern Makefile_type	makefile_type;
extern char		mbs_buffer[];
extern Name		path_name;
extern Boolean		posix;
extern Name		query;
extern Boolean		query_mentioned;
extern Name		hat;
extern Boolean		reading_environment;
extern Name		shell_name;
extern Boolean		svr4;
extern Name		target_arch;
extern Name		target_mach;
extern Boolean		tilde_rule;
extern wchar_t		wcs_buffer[];
extern Boolean		working_on_targets;
extern Name		virtual_root;
extern Boolean		vpath_defined;
extern Name		vpath_name;
extern Boolean		make_state_locked;
extern Boolean		out_err_same;
extern pid_t		childPid;

/*
 * RFE 1257407: make does not use fine granularity time info available from stat.
 * High resolution time comparison.
 */

inline int
operator==(const timestruc_t &t1, const timestruc_t &t2) {
	return ((t1.tv_sec == t2.tv_sec) && (t1.tv_nsec == t2.tv_nsec));
}

inline int
operator!=(const timestruc_t &t1, const timestruc_t &t2) {
	return ((t1.tv_sec != t2.tv_sec) || (t1.tv_nsec != t2.tv_nsec));
}

inline int
operator>(const timestruc_t &t1, const timestruc_t &t2) {
	if (t1.tv_sec == t2.tv_sec) {
		return (t1.tv_nsec > t2.tv_nsec);
	}
	return (t1.tv_sec > t2.tv_sec);
}

inline int
operator>=(const timestruc_t &t1, const timestruc_t &t2) {
	if (t1.tv_sec == t2.tv_sec) {
		return (t1.tv_nsec >= t2.tv_nsec);
	}
	return (t1.tv_sec > t2.tv_sec);
}

inline int
operator<(const timestruc_t &t1, const timestruc_t &t2) {
	if (t1.tv_sec == t2.tv_sec) {
		return (t1.tv_nsec < t2.tv_nsec);
	}
	return (t1.tv_sec < t2.tv_sec);
}

inline int
operator<=(const timestruc_t &t1, const timestruc_t &t2) {
	if (t1.tv_sec == t2.tv_sec) {
		return (t1.tv_nsec <= t2.tv_nsec);
	}
	return (t1.tv_sec < t2.tv_sec);
}

#endif
