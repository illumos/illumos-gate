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

#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/wait.h>
#include	<stdarg.h>
#include	<fcntl.h>
#include	<stdlib.h>
#include	<stdio.h>
#include	<signal.h>
#include	<dirent.h>
#include	<libelf.h>
#include	<gelf.h>
#include	<conv.h>
#include	<dlfcn.h>
#include	<link.h>
#include	<stdarg.h>
#include	<libgen.h>
#include	<libintl.h>
#include	<locale.h>
#include	<unistd.h>
#include	<errno.h>
#include	<ctype.h>
#include	<limits.h>
#include	<strings.h>
#include	<sgs.h>
#include	"msg.h"
#include	"_elfedit.h"
#include	<debug.h>	/* liblddb */



/*
 * Column at which elfedit_format_command_usage() will wrap the
 * generated usage string if the wrap argument is True (1).
 */
#define	USAGE_WRAP_COL 55




/*
 * Type used to represent a string buffer that can grow as needed
 * to hold strings of arbitrary length. The user should declare
 * variables of this type sa static. The strbuf_ensure_size() function
 * is used to ensure that it has a minimum desired size.
 */
typedef struct {
	char *buf;		/* String buffer */
	size_t n;		/* Size of buffer */
} STRBUF;




/*
 * Types used by tokenize_user_cmd() to represent the result of
 * spliting a user command into individual tokens.
 */
typedef struct {
	char	*tok_str;	/* Token string */
	size_t	tok_len;	/* strlen(str) */
	size_t	tok_line_off;	/* Token offset in original string */
} TOK_ELT;
typedef struct {
	size_t	tokst_cmd_len;	/* Length of original user command, without */
				/*	newline or NULL termination chars */
	size_t	tokst_str_size;	/* Space needed to hold all the resulting */
				/*	tokens, including terminating NULL */
	TOK_ELT	*tokst_buf;	/* The array of tokens */
	size_t	tokst_cnt;	/* # of tokens in array */
	size_t	tokst_bufsize;	/* capacity of array */
} TOK_STATE;




/* State block used by gettok_init() and gettok() */
typedef struct {
	const char	*gtok_buf;	/* Addr of buffer containing string */
	char		*gtok_cur_buf;	/* Addr withing buffer for next token */
	int		gtok_inc_null_final; /* True if final NULL token used */
	int		gtok_null_seen;	/* True when NULL byte seen */
	TOK_ELT		gtok_last_token; /* Last token parsed */

} GETTOK_STATE;




/*
 * The elfedit_cpl_*() functions are used for command line completion.
 * Currently this uses the tecla library, but to allow for changing the
 * library used, we hide all tecla interfaces from our modules. Instead,
 * cmd_match_fcn() builds an ELFEDIT_CPL_STATE struct, and we pass the
 * address of that struct as an opaque handle to the modules. Since the
 * pointer is opaque, the contents of ELFEDIT_CPL_STATE are free to change
 * as necessary.
 */
typedef struct {
	WordCompletion	*ecpl_cpl;		/* tecla handle */
	const char	*ecpl_line;		/* raw input line */
	int		ecpl_word_start;	/* start offset within line */
	int		ecpl_word_end;		/* offset just past token */
	/*
	 * ecpl_add_mod_colon is a secret handshake between
	 * elfedit_cpl_command() and  elfedit_cpl_add_match(). It adds
	 * ':' to end of matched modules.
	 */
	int		ecpl_add_mod_colon;
	const char	*ecpl_token_str;	/* token being completed */
	size_t		ecpl_token_len;		/* strlen(ecpl_token_str) */
} ELFEDIT_CPL_STATE;




/* This structure maintains elfedit global state */
STATE_T state;



/*
 * Define a pair of static global variables that contain the
 * ISA strings that correspond to %i and %I tokens in module search
 * paths.
 *
 *	isa_i_str - The ISA string for the currently running program
 *	isa_I_str - For 64-bit programs, the same as isa_i_str. For
 *		32-bit programs, an empty string.
 */
#ifdef __sparc
#ifdef __sparcv9
static const char *isa_i_str = MSG_ORIG(MSG_ISA_SPARC_64);
static const char *isa_I_str = MSG_ORIG(MSG_ISA_SPARC_64);
#else
static const char *isa_i_str = MSG_ORIG(MSG_ISA_SPARC_32);
static const char *isa_I_str = MSG_ORIG(MSG_STR_EMPTY);
#endif
#endif

#ifdef __i386
static const char *isa_i_str = MSG_ORIG(MSG_ISA_X86_32);
static const char *isa_I_str = MSG_ORIG(MSG_STR_EMPTY);
#endif
#ifdef __amd64
static const char *isa_i_str = MSG_ORIG(MSG_ISA_X86_64);
static const char *isa_I_str = MSG_ORIG(MSG_ISA_X86_64);
#endif



/* Forward declarations */
static void free_user_cmds(void);
static void elfedit_pager_cleanup(void);



/*
 * We supply this function for the msg module
 */
const char *
_elfedit_msg(Msg mid)
{
	return (gettext(MSG_ORIG(mid)));
}


/*
 * Copy at most min(cpsize, dstsize-1) bytes from src into dst,
 * truncating src if necessary.  The  result is always null-terminated.
 *
 * entry:
 *	dst - Destination buffer
 *	src - Source string
 *	dstsize - sizeof(dst)
 *
 * note:
 *	This is similar to strncpy(), but with two modifications:
 *	1) You specify the number of characters to copy, not just
 *		the size of the destination. Hence, you can copy non-NULL
 *		terminated strings.
 *	2) The destination is guaranteed to be NULL terminated. strncpy()
 *		does not terminate a completely full buffer.
 */
static void
elfedit_strnbcpy(char *dst, const char *src, size_t cpsize, size_t dstsize)
{
	if (cpsize >= dstsize)
		cpsize = dstsize - 1;
	if (cpsize > 0)
		(void) strncpy(dst, src, cpsize + 1);
	dst[cpsize] = '\0';
}


/*
 * Calls exit() on behalf of elfedit.
 */
void
elfedit_exit(int status)
{
	if (state.file.present) {
		/* Exiting with unflushed changes pending? Issue debug notice */
		if (state.file.dirty)
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_DIRTYEXIT));

		/*
		 * If the edit file is marked for unlink on exit, then
		 * take care of it here.
		 */
		if (state.file.unlink_on_exit) {
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_UNLINKFILE),
			    state.file.outfile);
			(void) unlink(state.file.outfile);
		}
	}

	exit(status);
}


/*
 * Standard message function for elfedit. All user visible
 * output, for error or informational reasons, should go through
 * this function.
 *
 * entry:
 *	type - Type of message. One of the ELFEDIT_MSG_* values.
 *	format, ... - As per the printf() family
 *
 * exit:
 *	The desired message has been output. For informational
 *	messages, control returns to the caller. For errors,
 *	this routine will terminate execution or strip the execution
 *	stack and return control directly to the outer control loop.
 *	In either case, the caller will not receive control.
 */
/*PRINTFLIKE2*/
void
elfedit_msg(elfedit_msg_t type, const char *format, ...)
{
	typedef enum {			/* What to do after finished */
		DISP_RET = 0,		/* Return to caller */
		DISP_JMP = 1,		/* if (interactive) longjmp else exit */
		DISP_EXIT = 2		/* exit under all circumstances */
	} DISP;

	va_list args;
	FILE *stream = stderr;
	DISP disp = DISP_RET;
	int do_output = 1;
	int need_prefix = 1;

	va_start(args, format);

	switch (type) {
	case ELFEDIT_MSG_ERR:
	case ELFEDIT_MSG_CMDUSAGE:
		disp = DISP_JMP;
		break;
	case ELFEDIT_MSG_FATAL:
		disp = DISP_EXIT;
		break;
	case ELFEDIT_MSG_USAGE:
		need_prefix = 0;
		break;
	case ELFEDIT_MSG_DEBUG:
		if (!(state.flags & ELFEDIT_F_DEBUG))
			return;
		stream = stdout;
		break;
	case ELFEDIT_MSG_QUIET:
		do_output = 0;
		disp = DISP_JMP;
		break;
	}


	/*
	 * If there is a pager process running, we are returning to the
	 * caller, and the output is going to stdout, then let the
	 * pager handle it instead of writing it directly from this process.
	 * That way, the output gets paged along with everything else.
	 *
	 * If there is a pager process running, and we are not returning
	 * to the caller, then end the pager process now, before we generate
	 * any new output. This allows for any text buffered in the pager
	 * pipe to be output before the new stuff.
	 */
	if (state.pager.fptr != NULL) {
		if (disp == DISP_RET) {
			if (stream == stdout)
				stream = state.pager.fptr;
		} else {
			elfedit_pager_cleanup();
		}
	}

	/*
	 * If this message is coming from within the libtecla command
	 * completion code, call gl_normal_io() to give the library notice.
	 * That function sets the tty back to cooked mode and advances
	 * the cursor to the beginning of the next line so that our output
	 * will appear properly. When we return to the command completion code,
	 * tecla will re-enter raw mode and redraw the current command line.
	 */
	if (state.input.in_tecla)
		(void) gl_normal_io(state.input.gl);

	if (do_output) {
		if (need_prefix)
			(void) fprintf(stream, MSG_ORIG(MSG_STR_ELFEDIT));
		(void) vfprintf(stream, format, args);
		(void) fflush(stream);
	}
	va_end(args);

	/*
	 * If this is an error, then we do not return to the caller.
	 * The action taken depends on whether the outer loop has registered
	 * a jump buffer for us or not.
	 */
	if (disp != DISP_RET) {
		if (state.msg_jbuf.active && (disp == DISP_JMP)) {
			/* Free the user command list */
			free_user_cmds();

			/* Clean up to reflect effect of non-local goto */
			state.input.in_tecla = FALSE;

			/* Jump to the outer loop to resume */
			siglongjmp(state.msg_jbuf.env, 1);
		} else {
			elfedit_exit(1);
		}
	}
}


/*
 * Wrapper on elfedit_msg() that issues an error that results from
 * a call to libelf.
 *
 * entry:
 *	file - Name of ELF object
 *	libelf_rtn_name - Name of routine that was called
 *
 * exit:
 *	An error has been issued that shows the routine called
 *	and the libelf error string for it from elf_errmsg().
 *	This routine does not return to the caller.
 */
void
elfedit_elferr(const char *file, const char *libelf_rtn_name)
{
	const char *errstr = elf_errmsg(elf_errno());

	elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_LIBELF), file,
	    libelf_rtn_name, errstr ? errstr : MSG_INTL(MSG_FMT_UNKNOWN));
}


/*
 * Start an output pager process for elfedit_printf()/elfedit_write() to use.
 *
 * note:
 *	If this elfedit session is not interactive, then no pager is
 *	started. Paging is only intended for interactive use. The caller
 *	is not supposed to worry about this point, but simply to use
 *	this function to flag situations in which paging might be needed.
 */
void
elfedit_pager_init(void)
{
	const char	*errstr;
	const char	*cmd;
	int		err;

	/*
	 * If there is no pager process running, start one.
	 * Only do this for interactive sessions --- elfedit_pager()
	 * won't use a pager in batch mode.
	 */
	if (state.msg_jbuf.active && state.input.full_tty &&
	    (state.pager.fptr == NULL)) {
		/*
		 * If the user has the PAGER environment variable set,
		 * then we will use that program. Otherwise we default
		 * to /bin/more.
		 */
		cmd = getenv(MSG_ORIG(MSG_STR_PAGER));
		if ((cmd == NULL) || (*cmd == '\0'))
			cmd = MSG_ORIG(MSG_STR_BINMORE);

		/*
		 * The popen() manpage says that on failure, it "may set errno",
		 * which is somewhat ambiguous. We explicitly zero it here, and
		 * assume that any change is due to popen() failing.
		 */
		errno = 0;
		state.pager.fptr = popen(cmd, MSG_ORIG(MSG_STR_W));
		if (state.pager.fptr == NULL) {
			err = errno;
			errstr = (err == 0) ? MSG_INTL(MSG_ERR_UNKNOWNSYSERR) :
			    strerror(err);
			elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTEXEC),
			    MSG_ORIG(MSG_STR_ELFEDIT), cmd, errstr);
		}
	}
}


/*
 * If there is a pager process present, close it out.
 *
 * note:
 *	This function is called from within elfedit_msg(), and as
 *	such, must not use elfedit_msg() to report errors. Furthermore,
 *	any such errors are not a sufficient reason to terminate the process
 *	or to longjmp(). This is a rare case where errors are written
 *	directly to stderr.
 */
static void
elfedit_pager_cleanup(void)
{
	if (state.pager.fptr != NULL) {
		if (pclose(state.pager.fptr) == -1)
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_PAGERFINI));

		state.pager.fptr = NULL;
	}
}


/*
 * Print general formtted text for the user, using printf()-style
 * formatting. Uses the pager process if one has been started, or
 * stdout otherwise.
 */
void
elfedit_printf(const char *format, ...)
{
	va_list	args;
	int	err;
	FILE	*fptr;
	int	pager;
	int	broken_pipe = 0;

	/*
	 * If there is a pager process, then use it. Otherwise write
	 * directly to stdout.
	 */
	pager = (state.pager.fptr != NULL);
	fptr = pager ? state.pager.fptr : stdout;

	va_start(args, format);
	errno = 0;
	err = vfprintf(fptr, format, args);

	/* Did we fail because a child pager process has exited? */
	broken_pipe = pager && (err < 0) && (errno == EPIPE);

	va_end(args);

	/*
	 * On error, we simply issue the error without cleaning up
	 * the pager process. The message code handles that as a standard
	 * part of error processing.
	 *
	 * We handle failure due to an exited pager process differently
	 * than a normal error, because it is usually due to the user
	 * intentionally telling it to.
	 */
	if (err < 0) {
		if (broken_pipe)
			elfedit_msg(ELFEDIT_MSG_QUIET, MSG_ORIG(MSG_STR_NULL));
		else
			elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_PRINTF));
	}
}


/*
 * Some our modules use liblddb routines to format ELF output.
 * In order to ensure that such output is sent to the pager pipe
 * when there is one, and stdout otherwise, we redefine the dbg_print()
 * function here.
 *
 * This item should be defined NODIRECT.
 */
/* PRINTFLIKE2 */
void
dbg_print(Lm_list *lml, const char *format, ...)
{
	va_list	ap;
	int	err;
	FILE	*fptr;
	int	pager;
	int	broken_pipe = 0;

#if	defined(lint)
	/*
	 * The lml argument is only meaningful for diagnostics sent to ld.so.1.
	 * Supress the lint error by making a dummy assignment.
	 */
	lml = 0;
#endif

	/*
	 * If there is a pager process, then use it. Otherwise write
	 * directly to stdout.
	 */
	pager = (state.pager.fptr != NULL);
	fptr = pager ? state.pager.fptr : stdout;

	va_start(ap, format);
	errno = 0;
	err = vfprintf(fptr, format, ap);
	if (err >= 0)
		err = fprintf(fptr, MSG_ORIG(MSG_STR_NL));

	/* Did we fail because a child pager process has exited? */
	broken_pipe = (err < 0) && pager && (errno == EPIPE);

	va_end(ap);

	/*
	 * On error, we simply issue the error without cleaning up
	 * the pager process. The message code handles that as a standard
	 * part of error processing.
	 *
	 * We handle failure due to an exited pager process differently
	 * than a normal error, because it is usually due to the user
	 * intentionally telling it to.
	 */
	if (err < 0) {
		if (broken_pipe)
			elfedit_msg(ELFEDIT_MSG_QUIET, MSG_ORIG(MSG_STR_NULL));
		else
			elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_PRINTF));
	}
}


/*
 * Write raw bytes of text in a manner similar to fwrite().
 * Uses the pager process if one has been started, or
 * stdout otherwise.
 */
void
elfedit_write(const void *ptr, size_t size)
{
	FILE	*fptr;
	int	err;

	/*
	 * If there is a pager process, then use it. Otherwise write
	 * directly to stdout.
	 */
	fptr = (state.pager.fptr == NULL) ? stdout : state.pager.fptr;

	if (fwrite(ptr, 1, size, fptr) != size) {
		err = errno;
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_FWRITE),
		    strerror(err));
	}
}


/*
 * Convert the NULL terminated string to the form used by the C
 * language to represent literal strings. See conv_str_to_c_literal()
 * for details.
 *
 * This routine differs from conv_str_to_c_literal() in two ways:
 *	1) String is NULL terminated instead of counted
 *	2) Signature of outfunc
 *
 * entry:
 *	str - String to be processed
 *	outfunc - Function to be called to move output characters. Note
 *		that this function has the same signature as elfedit_write(),
 *		and that function can be used to write the characters to
 *		the output.
 *
 * exit:
 *	The string has been processed, with the resulting data passed
 *	to outfunc for processing.
 */
static void
elfedit_str_to_c_literal_cb(const void *ptr, size_t size, void *uvalue)
{
	elfedit_write_func_t *outfunc = (elfedit_write_func_t *)uvalue;

	(* outfunc)(ptr, size);

}
void
elfedit_str_to_c_literal(const char *str, elfedit_write_func_t *outfunc)
{
	conv_str_to_c_literal(str, strlen(str),
	    elfedit_str_to_c_literal_cb, (void *) outfunc);
}


/*
 * Wrappers on malloc() and realloc() that check the result for success
 * and issue an error if not. The caller can use the result of these
 * functions without checking for a NULL pointer, as we do not return to
 * the caller in the failure case.
 */
void *
elfedit_malloc(const char *item_name, size_t size)
{
	void *m;

	m = malloc(size);
	if (m == NULL) {
		int err = errno;
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_MALLOC),
		    item_name, strerror(err));
	}

	return (m);
}

void *
elfedit_realloc(const char *item_name, void *ptr, size_t size)
{
	void *m;

	m = realloc(ptr, size);
	if (m == NULL) {
		int err = errno;
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_MALLOC),
		    item_name, strerror(err));
	}

	return (m);
}


/*
 * Ensure that the given buffer has room for n bytes of data.
 */
static void
strbuf_ensure_size(STRBUF *str, size_t size)
{
#define	INITIAL_STR_ALLOC 128

	size_t n;

	n = (str->n == 0) ? INITIAL_STR_ALLOC : str->n;
	while (size > n)	/* Double buffer until string fits */
		n *= 2;
	if (n != str->n) {		/* Alloc new string buffer if needed */
		str->buf = elfedit_realloc(MSG_INTL(MSG_ALLOC_UCMDSTR),
		    str->buf, n);
		str->n = n;
	}

#undef	INITIAL_STR_ALLOC
}


/*
 * Extract the argument/option information for the next item referenced
 * by optarg, and advance the pointer to the next item.
 *
 * entry:
 *	optarg - Address of pointer to argument or option array
 *	item - Struct to be filled in.
 *
 * exit:
 *	The item block has been filled in with the information for
 *	the next item in the optarg array. *optarg has been advanced
 *	to the next item.
 */
void
elfedit_next_optarg(elfedit_cmd_optarg_t **optarg, elfedit_optarg_item_t *item)
{
	/*
	 * Array of inheritable options/arguments. Indexed by one less
	 * than the corresponding ELFEDIT_STDOA_ value.
	 */
	static const elfedit_optarg_item_t stdoa[] = {
		/* ELFEDIT_STDOA_O */
		{ MSG_ORIG(MSG_STR_MINUS_O), MSG_ORIG(MSG_STR_OUTSTYLE),
		    /* MSG_INTL(MSG_STDOA_OPTDESC_O) */
		    (elfedit_i18nhdl_t)MSG_STDOA_OPTDESC_O,
		    ELFEDIT_CMDOA_F_VALUE },

		/* ELFEDIT_STDOA_AND */
		{ MSG_ORIG(MSG_STR_MINUS_AND), NULL,
		    /* MSG_INTL(MSG_STDOA_OPTDESC_AND) */
		    (elfedit_i18nhdl_t)MSG_STDOA_OPTDESC_AND, 0 },

		/* ELFEDIT_STDOA_CMP */
		{ MSG_ORIG(MSG_STR_MINUS_CMP), NULL,
		    /* MSG_INTL(MSG_STDOA_OPTDESC_CMP) */
		    (elfedit_i18nhdl_t)MSG_STDOA_OPTDESC_CMP, 0 },

		/* ELFEDIT_STDOA_OR */
		{ MSG_ORIG(MSG_STR_MINUS_OR), NULL,
		    /* MSG_INTL(MSG_STDOA_OPTDESC_OR) */
		    (elfedit_i18nhdl_t)MSG_STDOA_OPTDESC_OR, 0 },
	};

	elfedit_cmd_optarg_t *oa;


	/* Grab first item, advance the callers pointer over it */
	oa = (*optarg)++;

	if (oa->oa_flags & ELFEDIT_CMDOA_F_INHERIT) {
		/* Values are pre-chewed in the stdoa array above */
		*item = stdoa[((uintptr_t)oa->oa_name) - 1];

		/*
		 * Set the inherited flag so that elfedit_optarg_helpstr()
		 * can tell who is responsible for translating the help string.
		 */
		item->oai_flags |= ELFEDIT_CMDOA_F_INHERIT;
	} else {	/* Non-inherited item */
		item->oai_name = oa->oa_name;
		if ((oa->oa_flags & ELFEDIT_CMDOA_F_VALUE) != 0) {
			item->oai_vname = oa[1].oa_name;

			/* Advance users pointer past value element */
			(*optarg)++;
		} else {
			item->oai_vname = NULL;
		}
		item->oai_help = oa->oa_help;
		item->oai_flags = oa->oa_flags;
	}

	/*
	 * The module determines the idmask and excmask fields whether
	 * or not inheritance is in play.
	 */
	item->oai_idmask = oa->oa_idmask;
	item->oai_excmask = oa->oa_excmask;
}



/*
 * Return the help string for an option/argument item, as returned
 * by elfedit_next_optarg(). This routine handles the details of
 * knowing whether the string is provided by elfedit itself (inherited),
 * or needs to be translated by the module.
 */
const char *
elfedit_optarg_helpstr(elfeditGC_module_t *mod, elfedit_optarg_item_t *item)
{
	/*
	 * The help string from an inherited item comes right out
	 * of the main elfedit string table.
	 */
	if (item->oai_flags & ELFEDIT_CMDOA_F_INHERIT)
		return (MSG_INTL((Msg) item->oai_help));

	/*
	 * If the string is defined by the module, then we need to
	 * have the module translate it for us.
	 */
	return ((* mod->mod_i18nhdl_to_str)(item->oai_help));
}



/*
 * Used by usage_optarg() to insert a character into the output buffer,
 * advancing the buffer pointer and current column, and reducing the
 * amount of remaining space.
 */
static void
usage_optarg_insert_ch(int ch, char **cur, size_t *n, size_t *cur_col)
{

	*(*cur)++ = ch;
	**cur = '\0';
	(*n)--;
	(*cur_col)++;
}

/*
 * Used by usage_optarg() to insert a string into the output
 * buffer, advancing the buffer pointer and current column, and reducing
 * the amount of remaining space.
 */
static void
usage_optarg_insert_str(char **cur, size_t *n, size_t *cur_col,
    const char *format, ...)
{
	size_t len;
	va_list args;

	va_start(args, format);
	len = vsnprintf(*cur, *n, format, args);
	va_end(args);

	*cur += len;
	*n -= len;
	*cur_col += len;
}
/*
 * Used by usage_optarg() to insert an optarg item string into the output
 * buffer, advancing the buffer pointer and current column, and reducing
 * the amount of remaining space.
 */
static void
usage_optarg_insert_item(elfedit_optarg_item_t *item, char **cur,
    size_t *n, size_t *cur_col)
{
	size_t len;

	if (item->oai_flags & ELFEDIT_CMDOA_F_VALUE) {
		len = snprintf(*cur, *n, MSG_ORIG(MSG_STR_HLPOPTARG2),
		    item->oai_name, item->oai_vname);
	} else {
		len = snprintf(*cur, *n, MSG_ORIG(MSG_STR_HLPOPTARG),
		    item->oai_name);
	}
	*cur += len;
	*n -= len;
	*cur_col += len;
}



/*
 * Write the options/arguments to the usage string.
 *
 * entry:
 *	main_buf_n - Size of main buffer from which buf and buf_n are
 *		allocated.
 *	buf - Address of pointer to where next item is to be placed.
 *	buf_n - Address of count of remaining bytes in buffer
 *	buf_cur_col - Address of current output column for current line
 *		of generated string.
 *	optarg - Options list
 *	isopt - True if these are options, false for arguments.
 *	wrap_str - String to indent wrapped lines. If NULL, lines
 *		are not wrapped
 */
static void
usage_optarg(size_t main_buf_n, char **buf, size_t *buf_n, size_t *buf_cur_col,
    elfedit_cmd_optarg_t *optarg, int isopt, const char *wrap_str)
{
	/*
	 * An option can be combined into a simple format if it lacks
	 * these flags and is only one character in length.
	 */
	static const elfedit_cmd_oa_flag_t exflags =
	    (ELFEDIT_CMDOA_F_VALUE | ELFEDIT_CMDOA_F_MULT);

	/*
	 * A static buffer, which is grown as needed to accomodate
	 * the maximum usage string seen.
	 */
	static STRBUF simple_str;

	char			*cur = *buf;
	size_t			n = *buf_n;
	size_t			cur_col = *buf_cur_col;
	int			len;
	int			use_simple = 0;
	elfedit_optarg_item_t	item;
	elfedit_cmd_oa_mask_t	optmask = 0;
	int			use_bkt;

	/*
	 * If processing options, pull the 1-character ones that don't have
	 * an associated value and don't have any mutual exclusion issues into
	 * a single combination string to go at the beginning of the usage.
	 */
	if (isopt) {
		elfedit_cmd_optarg_t *tmp_optarg = optarg;
		char *s;

		/*
		 * The simple string is guaranteed to fit in the same
		 * amount of space reserved for the main buffer.
		 */
		strbuf_ensure_size(&simple_str, main_buf_n);
		s = simple_str.buf;
		*s++ = ' ';
		*s++ = '[';
		*s++ = '-';
		while (tmp_optarg->oa_name != NULL) {
			elfedit_next_optarg(&tmp_optarg, &item);
			if (((item.oai_flags & exflags) == 0) &&
			    (item.oai_name[2] == '\0') &&
			    (item.oai_excmask == 0)) {
				optmask |= item.oai_idmask;
				*s++ = item.oai_name[1];
			}
		}

		/*
		 * If we found more than one, then finish the string and
		 * add it. Don't do this for a single option, because
		 * it looks better in that case if the option shows up
		 * in alphabetical order rather than being hoisted.
		 */
		use_simple = (s > (simple_str.buf + 4));
		if (use_simple) {
			*s++ = ']';
			*s++ = '\0';
			usage_optarg_insert_str(&cur, &n, &cur_col,
			    MSG_ORIG(MSG_STR_HLPOPTARG), simple_str.buf);
		} else {
			/* Not using it, so reset the cumulative options mask */
			optmask = 0;
		}
	}

	while (optarg->oa_name != NULL) {
		elfedit_next_optarg(&optarg, &item);

		if (isopt) {
			/*
			 * If this is an option that was pulled into the
			 * combination string above, then skip over it.
			 */
			if (use_simple && ((item.oai_flags & exflags) == 0) &&
			    (item.oai_name[2] == '\0') &&
			    (item.oai_excmask == 0))
				continue;

			/*
			 * If this is a mutual exclusion option that was
			 * picked up out of order by a previous iteration
			 * of this loop, then skip over it.
			 */
			if ((optmask & item.oai_idmask) != 0)
				continue;

			/* Add this item to the accumulating options mask */
			optmask |= item.oai_idmask;
		}

		/* Wrap line, or insert blank separator */
		if ((wrap_str != NULL) && (cur_col > USAGE_WRAP_COL)) {
			len = snprintf(cur, n, MSG_ORIG(MSG_FMT_WRAPUSAGE),
			    wrap_str);
			cur += len;
			n -= len;
			cur_col = len - 1;   /* Don't count the newline */
		} else {
			usage_optarg_insert_ch(' ', &cur, &n, &cur_col);
		}

		use_bkt = (item.oai_flags & ELFEDIT_CMDOA_F_OPT) || isopt;
		if (use_bkt)
			usage_optarg_insert_ch('[', &cur, &n, &cur_col);

		/* Add the item to the buffer */
		usage_optarg_insert_item(&item, &cur, &n, &cur_col);

		/*
		 * If this item has a non-zero mutual exclusion mask,
		 * then look for the other items and display them all
		 * together with alternation (|). Note that plain arguments
		 * cannot have a non-0 exclusion mask, so this is
		 * effectively options-only (isopt != 0).
		 */
		if (item.oai_excmask != 0) {
			elfedit_cmd_optarg_t *tmp_optarg = optarg;
			elfedit_optarg_item_t tmp_item;

			/*
			 * When showing alternation, elipses for multiple
			 * copies need to appear inside the [] brackets.
			 */
			if (item.oai_flags & ELFEDIT_CMDOA_F_MULT)
				usage_optarg_insert_str(&cur, &n, &cur_col,
				    MSG_ORIG(MSG_STR_ELIPSES));


			while (tmp_optarg->oa_name != NULL) {
				elfedit_next_optarg(&tmp_optarg, &tmp_item);
				if ((item.oai_excmask & tmp_item.oai_idmask) ==
				    0)
					continue;
				usage_optarg_insert_str(&cur, &n, &cur_col,
				    MSG_ORIG(MSG_STR_SP_BAR_SP));
				usage_optarg_insert_item(&tmp_item,
				    &cur, &n, &cur_col);

				/*
				 * Add it to the mask of seen options.
				 * This will keep us from showing it twice.
				 */
				optmask |= tmp_item.oai_idmask;
			}
		}
		if (use_bkt)
			usage_optarg_insert_ch(']', &cur, &n, &cur_col);

		/*
		 * If alternation was not shown above (non-zero exclusion mask)
		 * then the elipses for multiple copies are shown outside
		 * any [] brackets.
		 */
		if ((item.oai_excmask == 0) &&
		    (item.oai_flags & ELFEDIT_CMDOA_F_MULT))
			usage_optarg_insert_str(&cur, &n, &cur_col,
			    MSG_ORIG(MSG_STR_ELIPSES));

	}

	*buf = cur;
	*buf_n = n;
	*buf_cur_col = cur_col;
}



/*
 * Format the usage string for a command into a static buffer and
 * return the pointer to the user. The resultant string is valid
 * until the next call to this routine, and which point it
 * will be overwritten or the memory is freed.
 *
 * entry:
 *	mod, cmd - Module and command definitions for command to be described
 *	wrap_str - NULL, or string to be used to indent when
 *		lines are wrapped. If NULL, no wrapping is done, and
 *		all output is on a single line.
 *	cur_col - Starting column at which the string will be displayed.
 *		Ignored if wrap_str is NULL.
 */
const char *
elfedit_format_command_usage(elfeditGC_module_t *mod, elfeditGC_cmd_t *cmd,
    const char *wrap_str, size_t cur_col)
{

	/*
	 * A static buffer, which is grown as needed to accomodate
	 * the maximum usage string seen.
	 */
	static STRBUF str;

	elfedit_cmd_optarg_t	*optarg;
	size_t			len, n, elipses_len;
	char			*cur;
	elfedit_optarg_item_t	item;

	/*
	 * Estimate a worst case size for the usage string:
	 *	- module name
	 *	- lengths of the strings
	 *	- every option or argument is enclosed in brackets
	 *	- space in between each item, with an alternation (" | ")
	 *	- elipses will be displayed with each option and argument
	 */
	n = strlen(mod->mod_name) + strlen(cmd->cmd_name[0]) + 6;
	elipses_len = strlen(MSG_ORIG(MSG_STR_ELIPSES));
	if ((optarg = cmd->cmd_opt) != NULL)
		while (optarg->oa_name != NULL) {
			elfedit_next_optarg(&optarg, &item);
			n += strlen(item.oai_name) + 5 + elipses_len;
		}
	if ((optarg = cmd->cmd_args) != NULL)
		while (optarg->oa_name != NULL) {
			elfedit_next_optarg(&optarg, &item);
			n += strlen(item.oai_name) + 5 + elipses_len;
		}
	n++;			/* Null termination */

	/*
	 * If wrapping lines, we insert a newline and then wrap_str
	 * every USAGE_WRAP_COL characters.
	 */
	if (wrap_str != NULL)
		n += ((n + USAGE_WRAP_COL) / USAGE_WRAP_COL) *
		    (strlen(wrap_str) + 1);

	strbuf_ensure_size(&str, n);

	/* Command name */
	cur = str.buf;
	n = str.n;
	if (strcmp(mod->mod_name, MSG_ORIG(MSG_MOD_SYS)) == 0)
		len = snprintf(cur, n, MSG_ORIG(MSG_FMT_SYSCMD),
		    cmd->cmd_name[0]);
	else
		len = snprintf(cur, n, MSG_ORIG(MSG_FMT_MODCMD),
		    mod->mod_name, cmd->cmd_name[0]);
	cur += len;
	n -= len;
	cur_col += len;

	if (cmd->cmd_opt != NULL)
		usage_optarg(str.n, &cur, &n, &cur_col, cmd->cmd_opt,
		    1, wrap_str);
	if (cmd->cmd_args != NULL)
		usage_optarg(str.n, &cur, &n, &cur_col, cmd->cmd_args,
		    0, wrap_str);

	return (str.buf);
}

/*
 * Wrapper on elfedit_msg() that issues an ELFEDIT_MSG_USAGE
 * error giving usage information for the command currently
 * referenced by state.cur_cmd.
 */
void
elfedit_command_usage(void)
{
	elfedit_msg(ELFEDIT_MSG_CMDUSAGE, MSG_INTL(MSG_USAGE_CMD),
	    elfedit_format_command_usage(state.cur_cmd->ucmd_mod,
	    state.cur_cmd->ucmd_cmd, NULL, 0));
}


/*
 * This function allows the loadable modules to get the command line
 * flags.
 */
elfedit_flag_t
elfedit_flags(void)
{
	return (state.flags);
}

/*
 * This function is used to register a per-command invocation output style
 * that will momentarily override the global output style for the duration
 * of the current command. This function must only be called by an
 * active command.
 *
 * entry:
 *	str - One of the valid strings for the output style
 */
void
elfedit_set_cmd_outstyle(const char *str)
{
	if ((state.cur_cmd != NULL) && (str != NULL)) {
		if (elfedit_atooutstyle(str, &state.cur_cmd->ucmd_ostyle) == 0)
			elfedit_msg(ELFEDIT_MSG_ERR,
			    MSG_INTL(MSG_ERR_BADOSTYLE), str);
		state.cur_cmd->ucmd_ostyle_set = 1;
	}
}

/*
 * This function allows the loadable modules to get the output style.
 */
elfedit_outstyle_t
elfedit_outstyle(void)
{
	/*
	 * If there is an active  per-command output style,
	 * return it.
	 */
	if ((state.cur_cmd != NULL) && (state.cur_cmd->ucmd_ostyle_set))
		return (state.cur_cmd->ucmd_ostyle);


	return (state.outstyle);
}

/*
 * Return the command descriptor of the currently executing command.
 * For use only by the modules or code called by the modules.
 */
elfeditGC_cmd_t *
elfedit_curcmd(void)
{
	return (state.cur_cmd->ucmd_cmd);
}

/*
 * Build a dynamically allocated elfedit_obj_state_t struct that
 * contains a cache of the ELF file contents. This pre-chewed form
 * is fed to each command, reducing the amount of ELF boilerplate
 * code each command needs to contain.
 *
 * entry:
 *	file - Name of file to process
 *
 * exit:
 *	Fills state.elf with the necessary information for the open file.
 *
 * note: The resulting elfedit_obj_state_t is allocated from a single
 *	piece of memory, such that a single call to free() suffices
 *	to release it as well as any memory it references.
 */
static void
init_obj_state(const char *file)
{
	int	fd;
	Elf	*elf;
	int	open_flag;

	/*
	 * In readonly mode, we open the file readonly so that it is
	 * impossible to modify the file by accident. This also allows
	 * us to access readonly files, perhaps in a case where we don't
	 * intend to change it.
	 *
	 * We always use ELF_C_RDWR with elf_begin(), even in a readonly
	 * session. This allows us to modify the in-memory image, which
	 * can be useful when examining a file, even though we don't intend
	 * to modify the on-disk data. The file is not writable in
	 * this case, and we don't call elf_update(), so it is safe to do so.
	 */
	open_flag = ((state.flags & ELFEDIT_F_READONLY) ? O_RDONLY : O_RDWR);
	if ((fd = open(file, open_flag)) == -1) {
		int err = errno;
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTOPNFILE),
		    file, strerror(err));
	}
	(void) elf_version(EV_CURRENT);
	elf = elf_begin(fd, ELF_C_RDWR, NULL);
	if (elf == NULL) {
		(void) close(fd);
		elfedit_elferr(file, MSG_ORIG(MSG_ELF_BEGIN));
		/*NOTREACHED*/
	}

	/* We only handle standalone ELF files */
	switch (elf_kind(elf)) {
	case ELF_K_AR:
		(void) close(fd);
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOAR), file);
		break;
	case ELF_K_ELF:
		break;
	default:
		(void) close(fd);
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_UNRECELFFILE),
		    file);
		break;
	}

	/*
	 * Tell libelf that we take responsibility for object layout.
	 * Otherwise, it will compute "proper" values for layout and
	 * alignment fields, and these values can overwrite the values
	 * set in the elfedit session. We are modifying existing
	 * objects --- the layout concerns have already been dealt
	 * with when the object was built.
	 */
	(void) elf_flagelf(elf, ELF_C_SET, ELF_F_LAYOUT);

	/* Fill in state.elf.obj_state */
	state.elf.elfclass = gelf_getclass(elf);
	switch (state.elf.elfclass) {
	case ELFCLASS32:
		elfedit32_init_obj_state(file, fd, elf);
		break;
	case ELFCLASS64:
		elfedit64_init_obj_state(file, fd, elf);
		break;
	default:
		(void) close(fd);
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_BADELFCLASS),
		    file);
		break;
	}
}


#ifdef DEBUG_MODULE_LIST
/*
 * Debug routine. Dump the module list to stdout.
 */
static void
dbg_module_list(char *title)
{
	MODLIST_T *m;

	printf("<MODULE LIST: %s>\n", title);
	for (m = state.modlist; m != NULL; m = m->next) {
		printf("Module: >%s<\n", m->mod->mod_name);
		printf("    hdl:  %llx\n", m->dl_hdl);
		printf("    path: >%s<\n", m->path ? m->path : "<builtin>");
	}
	printf("<END OF MODULE LIST>\n");
}
#endif


/*
 * Search the module list for the named module.
 *
 * entry:
 *	name - Name of module to find
 *	insdef - Address of variable to receive address of predecessor
 *		node to the desired one.
 *
 * exit:
 *	If the module is it is found, this routine returns the pointer to
 *	its MODLIST_T structure. *insdef references the predecessor node, or
 *	is NULL if the found item is at the head of the list.
 *
 *	If the module is not found, NULL is returned. *insdef references
 *	the predecessor node of the position where an entry for this module
 *	would be placed, or NULL if it would go at the beginning.
 */
static MODLIST_T *
module_loaded(const char *name, MODLIST_T **insdef)
{
	MODLIST_T	*moddef;
	int		cmp;

	*insdef = NULL;
	moddef = state.modlist;
	if (moddef != NULL) {
		cmp = strcasecmp(name, moddef->ml_mod->mod_name);
		if (cmp == 0) {		/* Desired module is first in list */
			return (moddef);
		} else if (cmp > 0) {	/* cmp > 0: Insert in middle/end */
			*insdef = moddef;
			moddef = moddef->ml_next;
			cmp = -1;
			while (moddef && (cmp < 0)) {
				cmp = strcasecmp(moddef->ml_mod->mod_name,
				    name);
				if (cmp == 0)
					return (moddef);
				if (cmp < 0) {
					*insdef = moddef;
					moddef = (*insdef)->ml_next;
				}
			}
		}
	}

	return (NULL);
}


/*
 * Determine if a file is a sharable object based on its file path.
 * If path ends in a .so, followed optionally by a period and 1 or more
 * digits, we say that it is and return a pointer to the first character
 * of the suffix. Otherwise NULL is returned.
 */
static const char *
path_is_so(const char *path)
{
	int		dotso_len;
	const char	*tail;
	size_t		len;

	len = strlen(path);
	if (len == 0)
		return (NULL);
	tail = path + len;
	if (isdigit(*(tail - 1))) {
		while ((tail > path) && isdigit(*(tail - 1)))
			tail--;
		if ((tail <= path) || (*tail != '.'))
			return (NULL);
	}
	dotso_len = strlen(MSG_ORIG(MSG_STR_DOTSO));
	if ((tail - path) < dotso_len)
		return (NULL);
	tail -= dotso_len;
	if (strncmp(tail, MSG_ORIG(MSG_STR_DOTSO), dotso_len) == 0)
		return (tail);

	return (NULL);
}


/*
 * Locate the start of the unsuffixed file name within path. Returns pointer
 * to first character of that name in path.
 *
 * entry:
 *	path - Path to be examined.
 *	tail - NULL, or pointer to position at tail of path from which
 *		the search for '/' characters should start. If NULL,
 *		strlen() is used to locate the end of the string.
 *	buf - NULL, or buffer to receive a copy of the characters that
 *		lie between the start of the filename and tail.
 *	bufsize - sizeof(buf)
 *
 * exit:
 *	The pointer to the first character of the unsuffixed file name
 *	within path is returned. If buf is non-NULL, the characters
 *	lying between that point and tail (or the end of path if tail
 *	is NULL) are copied into buf.
 */
static const char *
elfedit_basename(const char *path, const char *tail, char *buf, size_t bufsiz)
{
	const char	*s;

	if (tail == NULL)
		tail = path + strlen(path);
	s = tail;
	while ((s > path) && (*(s - 1) != '/'))
		s--;
	if (buf != NULL)
		elfedit_strnbcpy(buf, s, tail - s, bufsiz);
	return (s);
}


/*
 * Issue an error on behalf of load_module(), taking care to release
 * resources that routine may have aquired:
 *
 * entry:
 *	moddef - NULL, or a module definition to be released via free()
 *	dl_hdl - NULL, or a handle to a sharable object to release via
 *		dlclose().
 *	dl_path - If dl_hdl is non-NULL, the path to the sharable object
 *		file that was loaded.
 *	format - A format string to pass to elfedit_msg(), containing
 *		no more than (3) %s format codes, and no other format codes.
 *	[s1-s4] - Strings to pass to elfedit_msg() to satisfy the four
 *		allowed %s codes in format. Should be set to NULL if the
 *		format string does not need them.
 *
 * note:
 *	This routine makes a copy of the s1-s4 strings before freeing any
 *	memory or unmapping the sharable library. It is therefore safe to
 *	use strings from moddef, or from the sharable library (which will
 *	be unmapped) to satisfy the other arguments s1-s4.
 */
static void
load_module_err(MODLIST_T *moddef, void *dl_hdl, const char *dl_path,
    const char *format, const char *s1, const char *s2, const char *s3,
    const char *s4)
{
#define	SCRBUFSIZE (PATH_MAX + 256)   /* A path, plus some extra */

	char s1_buf[SCRBUFSIZE];
	char s2_buf[SCRBUFSIZE];
	char s3_buf[SCRBUFSIZE];
	char s4_buf[SCRBUFSIZE];

	/*
	 * The caller may provide strings for s1-s3 that are from
	 * moddef. If we free moddef, the printf() will die on access
	 * to free memory. We could push back on the user and force
	 * each call to carefully make copies of such data. However, this
	 * is an easy case to miss. Furthermore, this is an error case,
	 * and machine efficiency is not the main issue. We therefore make
	 * copies of the s1-s3 strings here into auto variables, and then
	 * use those copies. The user is freed from worrying about it.
	 *
	 * We use oversized stack based buffers instead of malloc() to
	 * reduce the number of ways that things can go wrong while
	 * reporting the error.
	 */
	if (s1 != NULL)
		(void) strlcpy(s1_buf, s1, sizeof (s1_buf));
	if (s2 != NULL)
		(void) strlcpy(s2_buf, s2, sizeof (s2_buf));
	if (s3 != NULL)
		(void) strlcpy(s3_buf, s3, sizeof (s3_buf));
	if (s4 != NULL)
		(void) strlcpy(s4_buf, s4, sizeof (s4_buf));


	if (moddef != NULL)
		free(moddef);

	if ((dl_hdl != NULL) && (dlclose(dl_hdl) != 0))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTDLCLOSE),
		    dl_path, dlerror());

	elfedit_msg(ELFEDIT_MSG_ERR, format, s1_buf, s2_buf, s3_buf, s4_buf);
#undef	SCRBUFSIZE
}


/*
 * Load a module sharable object for load_module().
 *
 * entry:
 *	path - Path of file to open
 *	moddef - If this function issues a non-returning error, it will
 *		first return the memory referenced by moddef. This argument
 *		is not used otherwise.
 *	must_exist - If True, we consider it to be an error if the file given
 *		by path does not exist. If False, no error is issued
 *		and a NULL value is quietly returned.
 *
 * exit:
 *	Returns a handle to the loaded object on success, or NULL if no
 *	file was loaded.
 */
static void *
load_module_dlopen(const char *path, MODLIST_T *moddef, int must_exist)
{
	int	fd;
	void	*hdl;

	/*
	 * If the file is not required to exist, and it doesn't, then
	 * we want to quietly return without an error.
	 */
	if (!must_exist) {
		fd = open(path, O_RDONLY);
		if (fd >= 0) {
			(void) close(fd);
		} else if (errno == ENOENT) {
			return (NULL);
		}
	}

	if ((hdl = dlopen(path, RTLD_LAZY|RTLD_FIRST)) == NULL)
		load_module_err(moddef, NULL, NULL,
		    MSG_INTL(MSG_ERR_CNTDLOPEN), path, dlerror(), NULL, NULL);

	return (hdl);
}


/*
 * Sanity check option arguments to prevent common errors. The rest of
 * elfedit assumes these tests have been done, and does not check
 * again.
 */
static void
validate_optarg(elfedit_cmd_optarg_t *optarg, int isopt, MODLIST_T *moddef,
    const char *mod_name, const char *cmd_name,
    void *dl_hdl, const char *dl_path)
{
#define	FAIL(_msg) errmsg = _msg; goto fail

	Msg errmsg;
	elfedit_cmd_oa_mask_t	optmask = 0;

	for (; optarg->oa_name != NULL; optarg++) {
		/*
		 * If ELFEDIT_CMDOA_F_INHERIT is set:
		 *	- oa_name must be a value in the range of
		 *		known ELFEDIT_STDOA_ values.
		 *	- oa_help must be NULL
		 *	- ELFEDIT_CMDOA_F_INHERIT must be the only flag set
		 */
		if (optarg->oa_flags & ELFEDIT_CMDOA_F_INHERIT) {
			if ((((uintptr_t)optarg->oa_name) >
			    ELFEDIT_NUM_STDOA) ||
			    (optarg->oa_help != 0) ||
			    (optarg->oa_flags != ELFEDIT_CMDOA_F_INHERIT))
				/*
				 * Can't use FAIL --- oa_name is not a valid
				 * string, and load_module_err() looks at args.
				 */
				load_module_err(moddef, dl_hdl, dl_path,
				    MSG_INTL(MSG_ERR_BADSTDOA), dl_path,
				    mod_name, cmd_name, NULL);
			continue;
		}

		if (isopt) {
			/*
			 * Option name must start with a '-', and must
			 * have at one following character.
			 */
			if (optarg->oa_name[0] != '-') {
				/* MSG_INTL(MSG_ERR_OPT_MODPRE) */
				FAIL(MSG_ERR_OPT_MODPRE);
			}
			if (optarg->oa_name[1] == '\0') {
				/* MSG_INTL(MSG_ERR_OPT_MODLEN) */
				FAIL(MSG_ERR_OPT_MODLEN);
			}

			/*
			 * oa_idmask must be 0, or it must have a single
			 * bit set (a power of 2).oa_excmask must be 0
			 * if oa_idmask is 0
			 */
			if (optarg->oa_idmask == 0) {
				if (optarg->oa_excmask != 0) {
					/* MSG_INTL(MSG_ERR_OPT_EXCMASKN0) */
					FAIL(MSG_ERR_OPT_EXCMASKN0);
				}
			} else {
				if (elfedit_bits_set(optarg->oa_idmask,
				    sizeof (optarg->oa_idmask)) != 1) {
					/* MSG_INTL(MSG_ERR_OPT_IDMASKPOW2) */
					FAIL(MSG_ERR_OPT_IDMASKPOW2);
				}

				/* Non-zero idmask must be unique */
				if ((optarg->oa_idmask & optmask) != 0) {
					/* MSG_INTL(MSG_ERR_OPT_IDMASKUNIQ) */
					FAIL(MSG_ERR_OPT_IDMASKUNIQ);
				}

				/* Add this one to the overall mask */
				optmask |= optarg->oa_idmask;
			}
		} else {
			/*
			 * Argument name cannot start with a'-', and must
			 * not be a null string.
			 */
			if (optarg->oa_name[0] == '-') {
				/* MSG_INTL(MSG_ERR_ARG_MODPRE) */
				FAIL(MSG_ERR_ARG_MODPRE);
			}
			if (optarg->oa_name[1] == '\0') {
				/* MSG_INTL(MSG_ERR_ARG_MODLEN) */
				FAIL(MSG_ERR_ARG_MODLEN);
			}


			/* oa_idmask and oa_excmask must both be 0 */
			if ((optarg->oa_idmask != 0) ||
			    (optarg->oa_excmask != 0)) {
				/* MSG_INTL(MSG_ERR_ARG_MASKNOT0) */
				FAIL(MSG_ERR_ARG_MASKNOT0);
			}

		}

		/*
		 * If it takes a value, make sure that we are
		 * processing options, because CMDOA_F_VALUE is not
		 * allowed for plain arguments. Then check the following
		 * item in the list:
		 *	- There must be a following item.
		 *	- oa_name must be non-NULL. This is the only field
		 *		that is used by elfedit.
		 *	- oa_help, oa_flags, oa_idmask, and oa_excmask
		 *		must be 0.
		 */
		if (optarg->oa_flags & ELFEDIT_CMDOA_F_VALUE) {
			elfedit_cmd_optarg_t *oa1 = optarg + 1;

			if (!isopt) {
				/* MSG_INTL(MSG_ERR_ARG_CMDOA_VAL) */
				FAIL(MSG_ERR_ARG_CMDOA_VAL);
			}

			if ((optarg + 1)->oa_name == NULL) {
				/* MSG_INTL(MSG_ERR_BADMODOPTVAL) */
				FAIL(MSG_ERR_BADMODOPTVAL);
			}

			if (oa1->oa_name == NULL) {
				/* MSG_INTL(MSG_ERR_CMDOA_VALNAM) */
				FAIL(MSG_ERR_CMDOA_VALNAM);
			}
			if ((oa1->oa_help != 0) || (oa1->oa_flags != 0) ||
			    (oa1->oa_idmask != 0) || (oa1->oa_excmask != 0)) {
				/* MSG_INTL(MSG_ERR_CMDOA_VALNOT0) */
				FAIL(MSG_ERR_CMDOA_VALNOT0);
			}
			optarg++;
		}
	}


	return;

fail:
	load_module_err(moddef, dl_hdl, dl_path, MSG_INTL(errmsg),
	    dl_path, mod_name, cmd_name, optarg->oa_name);
}

/*
 * Look up the specified module, loading the module if necessary,
 * and return its definition, or NULL on failure.
 *
 * entry:
 *	name - Name of module to load. If name contains a '/' character or has
 *		a ".so" suffix, then it is taken to be an absolute file path,
 *		and is used directly as is. If name does not contain a '/'
 *		character, then we look for it against the locations in
 *		the module path, addint the '.so' suffix, and taking the first
 *		one we find.
 *	must_exist - If True, we consider it to be an error if we are unable
 *		to locate a file to load and the module does not already exist.
 *		If False, NULL is returned quietly in this case.
 *	allow_abs - True if absolute paths are allowed. False to disallow
 *		them.
 *
 * note:
 *	If the path is absolute, then we load the file and take the module
 *	name from the data returned by its elfedit_init() function. If a
 *	module of that name is already loaded, it is unloaded and replaced
 *	with the new one.
 *
 *	If the path is non absolute, then we check to see if the module has
 *	already been loaded, and if so, we return that module definition.
 *	In this case, nothing new is loaded. If the module has not been loaded,
 *	we search the path for it and load it. If the module name provided
 *	by the elfedit_init() function does not match the name of the file,
 *	an error results.
 */
elfeditGC_module_t *
elfedit_load_module(const char *name, int must_exist, int allow_abs)
{
	elfedit_init_func_t	*init_func;
	elfeditGC_module_t	*mod;
	MODLIST_T		*moddef, *insdef;
	const char		*path;
	char			path_buf[PATH_MAX + 1];
	void			*hdl;
	size_t			i;
	int			is_abs_path;
	elfeditGC_cmd_t		*cmd;

	/*
	 * If the name includes a .so suffix, or has any '/' characters,
	 * then it is an absolute path that we use as is to load the named
	 * file. Otherwise, we iterate over the path, adding the .so suffix
	 * and load the first file that matches.
	 */
	is_abs_path = (path_is_so(name) != NULL) ||
	    (name != elfedit_basename(name, NULL, NULL, 0));

	if (is_abs_path && !allow_abs)
		load_module_err(NULL, NULL, NULL,
		    MSG_INTL(MSG_ERR_UNRECMOD), name, NULL, NULL, NULL);

	/*
	 * If this is a non-absolute path, search for the module already
	 * having been loaded, and return it if so.
	 */
	if (!is_abs_path) {
		moddef = module_loaded(name, &insdef);
		if (moddef != NULL)
			return (moddef->ml_mod);
		/*
		 * As a result of module_loaded(), insdef now contains the
		 * immediate predecessor node for the new one, or NULL if
		 * it goes at the front. In the absolute-path case, we take
		 * care of this below, after the sharable object is loaded.
		 */
	}

	/*
	 * malloc() a module definition block before trying to dlopen().
	 * Doing things in the other order can cause the dlopen()'d object
	 * to leak: If elfedit_malloc() fails, it can cause a jump to the
	 * outer command loop without returning to the caller. Hence,
	 * there will be no opportunity to clean up. Allocaing the module
	 * first allows us to free it if necessary.
	 */
	moddef = elfedit_malloc(MSG_INTL(MSG_ALLOC_MODDEF),
	    sizeof (*moddef) + PATH_MAX + 1);
	moddef->ml_path = ((char *)moddef) + sizeof (*moddef);

	if (is_abs_path) {
		path = name;
		hdl = load_module_dlopen(name, moddef, must_exist);
	} else {
		hdl = NULL;
		path = path_buf;
		for (i = 0; i < state.modpath.n; i++) {
			if (snprintf(path_buf, sizeof (path_buf),
			    MSG_ORIG(MSG_FMT_BLDSOPATH), state.modpath.seg[i],
			    name) > sizeof (path_buf))
				load_module_err(moddef, NULL, NULL,
				    MSG_INTL(MSG_ERR_PATHTOOLONG),
				    state.modpath.seg[i], name, NULL, NULL);
			hdl = load_module_dlopen(path, moddef, 0);
		}
		if (must_exist && (hdl == NULL))
			load_module_err(moddef, NULL, NULL,
			    MSG_INTL(MSG_ERR_UNRECMOD), name, NULL, NULL, NULL);
	}

	if (hdl == NULL) {
		free(moddef);
		return (NULL);
	}

	if (state.elf.elfclass == ELFCLASS32) {
		init_func = (elfedit_init_func_t *)
		    dlsym(hdl, MSG_ORIG(MSG_STR_ELFEDITINIT32));
	} else {
		init_func = (elfedit_init_func_t *)
		    dlsym(hdl, MSG_ORIG(MSG_STR_ELFEDITINIT64));
	}
	if (init_func == NULL)
		load_module_err(moddef, hdl, path,
		    MSG_INTL(MSG_ERR_SONOTMOD), path, NULL, NULL, NULL);

	/*
	 * Note that the init function will be passing us an
	 * elfedit[32|64]_module_t pointer, which we cast to the
	 * generic module pointer type in order to be able to manage
	 * either type with one set of code.
	 */
	if (!(mod = (elfeditGC_module_t *)(* init_func)(ELFEDIT_VER_CURRENT)))
		load_module_err(moddef, hdl, path,
		    MSG_INTL(MSG_ERR_BADMODLOAD), path, NULL, NULL, NULL);

	/*
	 * Enforce some rules, to help module developers:
	 *	- The primary name of a command must not be
	 *		the empty string ("").
	 *	- Options must start with a '-' followed by at least
	 *		one character.
	 *	- Arguments and options must be well formed.
	 */
	for (cmd = mod->mod_cmds; cmd->cmd_func != NULL; cmd++) {
		if (**cmd->cmd_name == '\0')
			load_module_err(moddef, hdl, path,
			    MSG_INTL(MSG_ERR_NULLPRICMDNAM), mod->mod_name,
			    NULL, NULL, NULL);

		if (cmd->cmd_args != NULL)
			validate_optarg(cmd->cmd_args, 0, moddef, mod->mod_name,
			    cmd->cmd_name[0], hdl, path);
		if (cmd->cmd_opt != NULL)
			validate_optarg(cmd->cmd_opt, 1, moddef, mod->mod_name,
			    cmd->cmd_name[0], hdl, path);
	}

	/*
	 * Check the name the module provides. How we handle this depends
	 * on whether the path is absolute or the result of a path search.
	 */
	if (is_abs_path) {
		MODLIST_T *old_moddef = module_loaded(mod->mod_name, &insdef);

		if (old_moddef != NULL) {	/* Replace existing */
			free(moddef);		/* Rare case: Don't need it */
			/*
			 * Be sure we don't unload builtin modules!
			 * These have a NULL dl_hdl field.
			 */
			if (old_moddef->ml_dl_hdl == NULL)
				load_module_err(NULL, hdl, path,
				    MSG_INTL(MSG_ERR_CNTULSMOD),
				    old_moddef->ml_mod->mod_name, NULL,
				    NULL, NULL);

			/* Unload existing */
			if (dlclose(old_moddef->ml_dl_hdl) != 0)
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_CNTDLCLOSE),
				    old_moddef->ml_path, dlerror());
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_MODUNLOAD),
			    old_moddef->ml_mod->mod_name, old_moddef->ml_path);
			old_moddef->ml_mod = mod;
			old_moddef->ml_dl_hdl = hdl;
			(void) strlcpy((char *)old_moddef->ml_path, path,
			    PATH_MAX + 1);
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_MODLOAD),
			    old_moddef->ml_mod->mod_name, path);
			return (old_moddef->ml_mod);
		}
		/*
		 * insdef now contains the insertion point for the absolute
		 * path case.
		 */
	} else {
		/* If the names don't match, then error */
		if (strcasecmp(name, mod->mod_name) != 0)
			load_module_err(moddef, hdl, path,
			    MSG_INTL(MSG_ERR_BADMODNAME),
			    mod->mod_name, name, path, NULL);
	}

	/*
	 * Link module into the module list. If insdef is NULL,
	 * it goes at the head. If insdef is non-NULL, it goes immediately
	 * after
	 */
	if (insdef == NULL) {
		moddef->ml_next = state.modlist;
		state.modlist = moddef;
	} else {
		moddef->ml_next = insdef->ml_next;
		insdef->ml_next = moddef;
	}
	moddef->ml_mod = mod;
	moddef->ml_dl_hdl = hdl;
	(void) strlcpy((char *)moddef->ml_path, path, PATH_MAX + 1);

	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_MODLOAD),
	    moddef->ml_mod->mod_name, path);

	return (moddef->ml_mod);
}


/*
 * Unload the specified module
 */
void
elfedit_unload_module(const char *name)
{
	MODLIST_T	*moddef, *insdef;

	moddef = module_loaded(name, &insdef);
	if (moddef == NULL)
		return;

	/* Built in modules cannot be unloaded. They have a NULL dl_hdl field */
	if (moddef->ml_dl_hdl == NULL)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTULSMOD),
		    moddef->ml_mod->mod_name);

	/*
	 * When we unload it, the name string goes with it. So
	 * announce it while we still can without having to make a copy.
	 */
	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_MODUNLOAD),
	    moddef->ml_mod->mod_name, moddef->ml_path);

	/*
	 * Close it before going further. On failure, we'll jump, and the
	 * record will remain in the module list. On success,
	 * we'll retain control, and can safely remove it.
	 */
	if (dlclose(moddef->ml_dl_hdl) != 0)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTDLCLOSE),
		    moddef->ml_path, dlerror());

	/* Unlink the record from the module list */
	if (insdef == NULL)
		state.modlist = moddef->ml_next;
	else
		insdef->ml_next = moddef->ml_next;

	/* Release the memory */
	free(moddef);
}


/*
 * Load all sharable objects found in the specified directory.
 *
 * entry:
 *	dirpath - Path of directory to process.
 *	must_exist - If True, it is an error if diropen() fails to open
 *		the given directory. Of False, we quietly ignore it and return.
 *	abs_path - If True, files are loaded using their literal paths.
 *		If False, their module name is extracted from the dirpath
 *		and a path based search is used to locate it.
 */
void
elfedit_load_moddir(const char *dirpath, int must_exist, int abs_path)
{
	char		path[PATH_MAX + 1];
	DIR		*dir;
	struct dirent	*dp;
	const char	*tail;

	dir = opendir(dirpath);
	if (dir == NULL) {
		int err = errno;

		if (!must_exist && (err == ENOENT))
			return;
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTOPNDIR),
		    dirpath, strerror(err));
		/*NOTREACHED*/
	}

	while ((dp = readdir(dir)) != NULL) {
		if ((tail = path_is_so(dp->d_name)) != NULL) {
			if (abs_path) {
				(void) snprintf(path, sizeof (path),
				    MSG_ORIG(MSG_FMT_BLDPATH), dirpath,
				    dp->d_name);
			} else {
				(void) elfedit_basename(dp->d_name, tail,
				    path, sizeof (path));
			}
			(void) elfedit_load_module(path, must_exist, 1);
		}
	}
	(void) closedir(dir);
}


/*
 * Follow the module load path, and load the first module found for each
 * given name.
 */
void
elfedit_load_modpath(void)
{
	size_t		i;

	for (i = 0; i < state.modpath.n; i++)
		elfedit_load_moddir(state.modpath.seg[i], 0, 0);
}

/*
 * Given a module definition, look for the specified command.
 * Returns the command if found, and NULL otherwise.
 */
static elfeditGC_cmd_t *
find_cmd(elfeditGC_module_t *mod, const char *name)
{
	elfeditGC_cmd_t *cmd;
	const char **cmd_name;

	for (cmd = mod->mod_cmds; cmd->cmd_func != NULL; cmd++)
		for (cmd_name = cmd->cmd_name; *cmd_name; cmd_name++)
			if (strcasecmp(name, *cmd_name) == 0) {
				if (cmd_name != cmd->cmd_name)
					elfedit_msg(ELFEDIT_MSG_DEBUG,
					    MSG_INTL(MSG_DEBUG_CMDALIAS),
					    mod->mod_name, *cmd_name,
					    mod->mod_name, *cmd->cmd_name);
				return (cmd);
			}

	return (NULL);
}


/*
 * Given a command name, return its command definition.
 *
 * entry:
 *	name - Command to be looked up
 *	must_exist - If True, we consider it to be an error if the command
 *		does not exist. If False, NULL is returned quietly in
 *		this case.
 *	mod_ret - NULL, or address of a variable to receive the
 *		module definition block of the module containing
 *		the command.
 *
 * exit:
 *	On success, returns a pointer to the command definition, and
 *	if mod_ret is non-NULL, *mod_ret receives a pointer to the
 *	module definition. On failure, must_exist determines the
 *	action taken: If must_exist is True, an error is issued and
 *	control does not return to the caller. If must_exist is False,
 *	NULL is quietly returned.
 *
 * note:
 *	A ':' in name is used to delimit the module and command names.
 *	If it is omitted, or if it is the first non-whitespace character
 *	in the name, then the built in sys: module is implied.
 */
elfeditGC_cmd_t *
elfedit_find_command(const char *name, int must_exist,
    elfeditGC_module_t **mod_ret)
{
	elfeditGC_module_t	*mod;
	const char		*mod_str;
	const char		*cmd_str;
	char			mod_buf[ELFEDIT_MAXMODNAM + 1];
	size_t			n;
	elfeditGC_cmd_t		*cmd;


	cmd_str = strstr(name, MSG_ORIG(MSG_STR_COLON));
	if (cmd_str == NULL) {		/* No module name -> sys: */
		mod_str = MSG_ORIG(MSG_MOD_SYS);
		cmd_str = name;
	} else if (cmd_str == name) {	/* Empty module name -> sys: */
		mod_str = MSG_ORIG(MSG_MOD_SYS);
		cmd_str++;		/* Skip the colon */
	} else {			/* Have both module and command */
		n = cmd_str - name;
		if (n >= sizeof (mod_buf)) {
			if (must_exist)
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_MODNAMTOOLONG), name);
			return (NULL);
		}
		(void) strlcpy(mod_buf, name, n + 1);
		mod_str = mod_buf;
		cmd_str++;
	}

	/* Lookup/load module. Won't return on error */
	mod = elfedit_load_module(mod_str, must_exist, 0);
	if (mod == NULL)
		return (NULL);

	/* Locate the command */
	cmd = find_cmd(mod, cmd_str);
	if (cmd == NULL) {
		if (must_exist) {
			/*
			 * Catch empty command in order to provide
			 * a better error message.
			 */
			if (*cmd_str == '\0') {
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_MODNOCMD), mod_str);
			} else {
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_UNRECCMD),
				    mod_str, cmd_str);
			}
		}
	} else {
		if (mod_ret != NULL)
			*mod_ret = mod;
	}
	return (cmd);
}


/*
 * Release all user command blocks found on state.ucmd
 */
static void
free_user_cmds(void)
{
	USER_CMD_T *next;

	while (state.ucmd.list) {
		next = state.ucmd.list->ucmd_next;
		free(state.ucmd.list);
		state.ucmd.list = next;
	}
	state.ucmd.tail = NULL;
	state.ucmd.n = 0;
	state.cur_cmd = NULL;
}


/*
 * Process all user command blocks found on state.ucmd, and then
 * remove them from the list.
 */
static void
dispatch_user_cmds()
{
	USER_CMD_T		*ucmd;
	elfedit_cmdret_t	cmd_ret;

	ucmd = state.ucmd.list;
	if (ucmd) {
		/* Do them, in order */
		for (; ucmd; ucmd = ucmd->ucmd_next) {
			state.cur_cmd = ucmd;
			if (!state.msg_jbuf.active)
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_EXECCMD),
				    ucmd->ucmd_orig_str);
			/*
			 * The cmd_func field is the generic definition.
			 * We need to cast it to the type that matches
			 * the proper ELFCLASS before calling it.
			 */
			if (state.elf.elfclass == ELFCLASS32) {
				elfedit32_cmd_func_t *cmd_func =
				    (elfedit32_cmd_func_t *)
				    ucmd->ucmd_cmd->cmd_func;

				cmd_ret = (* cmd_func)(state.elf.obj_state.s32,
				    ucmd->ucmd_argc, ucmd->ucmd_argv);
			} else {
				elfedit64_cmd_func_t *cmd_func =
				    (elfedit64_cmd_func_t *)
				    ucmd->ucmd_cmd->cmd_func;

				cmd_ret = (* cmd_func)(state.elf.obj_state.s64,
				    ucmd->ucmd_argc, ucmd->ucmd_argv);
			}
			state.cur_cmd = NULL;
			/* If a pager was started, wrap it up */
			elfedit_pager_cleanup();

			switch (cmd_ret) {
			case ELFEDIT_CMDRET_MOD_OS_MACH:
				/*
				 * Inform the elfconst module that the machine
				 * or osabi has has changed. It may be necessary
				 * to fetch new strings from libconv.
				 */
				state.elf.elfconst_ehdr_change = 1;
				/*FALLTHROUGH*/
			case ELFEDIT_CMDRET_MOD:
				/*
				 * Command modified the output ELF image,
				 * mark the file as needing a flush to disk.
				 */
				state.file.dirty = 1;
				break;
			case ELFEDIT_CMDRET_FLUSH:
				/*
				 * Command flushed the output file,
				 * clear the dirty bit.
				 */
				state.file.dirty = 0;
				break;
			case ELFEDIT_CMDRET_NONE:
				break;
			}
		}
		free_user_cmds();
	}
}


/*
 * Prepare a GETTOK_STATE struct for gettok().
 *
 * entry:
 *	gettok_state - gettok state block to use
 *	str - Writable buffer to tokenize. Note that gettok()
 *		is allowed to change the contents of this buffer.
 *	inc_null_final - If the line ends in whitespace instead of
 *		immediately hitting a NULL, and inc_null_final is TRUE,
 *		then a null final token is generated. Otherwise trailing
 *		whitespace is ignored.
 */
static void
gettok_init(GETTOK_STATE *gettok_state, char *buf, int inc_null_final)
{
	gettok_state->gtok_buf = gettok_state->gtok_cur_buf = buf;
	gettok_state->gtok_inc_null_final = inc_null_final;
	gettok_state->gtok_null_seen = 0;
}


/*
 * Locate the next token from the buffer.
 *
 * entry:
 *	gettok_state - State of gettok() operation. Initialized
 *		by gettok_init(), and passed to gettok().
 *
 * exit:
 *	If a token is found, gettok_state->gtok_last_token is filled in
 *	with the details and True (1) is returned. If no token is found,
 *	False (1) is returned, and the contents of
 *	gettok_state->gtok_last_token are undefined.
 *
 * note:
 *	- The token returned references the memory in gettok_state->gtok_buf.
 *		The caller should not modify the buffer until all such
 *		pointers have been discarded.
 *	- This routine will modify the contents of gettok_state->gtok_buf
 *		as necessary to remove quotes and eliminate escape
 *		(\)characters.
 */
static int
gettok(GETTOK_STATE *gettok_state)
{
	char	*str = gettok_state->gtok_cur_buf;
	char	*look;
	int	quote_ch = '\0';

	/* Skip leading whitespace */
	while (isspace(*str))
		str++;

	if (*str == '\0') {
		/*
		 * If user requested it, and there was whitespace at the
		 * end, then generate one last null token.
		 */
		if (gettok_state->gtok_inc_null_final &&
		    !gettok_state->gtok_null_seen) {
			gettok_state->gtok_inc_null_final = 0;
			gettok_state->gtok_null_seen = 1;
			gettok_state->gtok_last_token.tok_str = str;
			gettok_state->gtok_last_token.tok_len = 0;
			gettok_state->gtok_last_token.tok_line_off =
			    str - gettok_state->gtok_buf;
			return (1);
		}
		gettok_state->gtok_null_seen = 1;
		return (0);
	}

	/*
	 * Read token: The standard delimiter is whitespace, but
	 * we honor either single or double quotes. Also, we honor
	 * backslash escapes.
	 */
	gettok_state->gtok_last_token.tok_str = look = str;
	gettok_state->gtok_last_token.tok_line_off =
	    look - gettok_state->gtok_buf;
	for (; *look; look++) {
		if (*look == quote_ch) {	/* Terminates active quote */
			quote_ch = '\0';
			continue;
		}

		if (quote_ch == '\0') {		/* No quote currently active */
			if ((*look == '\'') || (*look == '"')) {
				quote_ch = *look;	/* New active quote */
				continue;
			}
			if (isspace(*look))
				break;
		}

		/*
		 * The semantics of the backslash character depends on
		 * the quote style in use:
		 *	- Within single quotes, backslash is not
		 *		an escape character, and is taken literally.
		 *	- If outside of quotes, the backslash is an escape
		 *		character. The backslash is ignored and the
		 *		following character is taken literally, losing
		 *		any special properties it normally has.
		 *	- Within double quotes, backslash works like a
		 *		backslash escape within a C literal. Certain
		 *		escapes are recognized and replaced with their
		 *		special character. Any others are an error.
		 */
		if (*look == '\\') {
			if (quote_ch == '\'') {
				*str++ = *look;
				continue;
			}

			look++;
			if (*look == '\0') {	/* Esc applied to NULL term? */
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_ESCEOL));
				/*NOTREACHED*/
			}

			if (quote_ch == '"') {
				int ch = conv_translate_c_esc(&look);

				if (ch == -1)
					elfedit_msg(ELFEDIT_MSG_ERR,
					    MSG_INTL(MSG_ERR_BADCESC), *look);
				*str++ = ch;
				look--;		/* for() will advance by 1 */
				continue;
			}
		}

		if (look != str)
			*str = *look;
		str++;
	}

	/* Don't allow unterminated quoted tokens */
	if (quote_ch != '\0')
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_UNTERMQUOTE),
		    quote_ch);

	gettok_state->gtok_last_token.tok_len = str -
	    gettok_state->gtok_last_token.tok_str;
	gettok_state->gtok_null_seen = *look == '\0';
	if (!gettok_state->gtok_null_seen)
		look++;
	*str = '\0';
	gettok_state->gtok_cur_buf = look;

#ifdef DEBUG_GETTOK
	printf("GETTOK >");
	elfedit_str_to_c_literal(gettok_state->gtok_last_token.tok_str,
	    elfedit_write);
	printf("< \tlen(%d) offset(%d)\n",
	    gettok_state->gtok_last_token.tok_len,
	    gettok_state->gtok_last_token.tok_line_off);
#endif

	return (1);
}


/*
 * Tokenize the user command string, and return a pointer to the
 * TOK_STATE buffer maintained by this function. That buffer contains
 * the tokenized strings.
 *
 * entry:
 *	user_cmd_str - String to tokenize
 *	len - # of characters in user_cmd_str to examine. If
 *		(len < 0), then the complete string is processed
 *		stopping with the NULL termination. Otherwise,
 *		processing stops after len characters, and any
 *		remaining characters are ignored.
 *	inc_null_final - If True, and if user_cmd_str has whitespace
 *		at the end following the last non-null token, then
 *		a final null token will be included. If False, null
 *		tokens are ignored.
 *
 * note:
 *	This routine returns pointers to internally allocated memory.
 *	The caller must not alter anything contained in the TOK_STATE
 *	buffer returned. Furthermore, the the contents of TOK_STATE
 *	are only valid until the next call to tokenize_user_cmd().
 */
static TOK_STATE *
tokenize_user_cmd(const char *user_cmd_str, size_t len, int inc_null_final)
{
#define	INITIAL_TOK_ALLOC 5

	/*
	 * As we parse the user command, we need temporary space to
	 * hold the tokens. We do this by dynamically allocating a string
	 * buffer and a token array, and doubling them as necessary. This
	 * is a single threaded application, so static variables suffice.
	 */
	static STRBUF str;
	static TOK_STATE tokst;

	GETTOK_STATE	gettok_state;
	size_t		n;

	/*
	 * Make a copy we can modify. If (len == 0), take the entire
	 * string. Otherwise limit it to the specified length.
	 */
	tokst.tokst_cmd_len = strlen(user_cmd_str);
	if ((len > 0) && (len < tokst.tokst_cmd_len))
		tokst.tokst_cmd_len = len;
	tokst.tokst_cmd_len++;	/* Room for NULL termination */
	strbuf_ensure_size(&str, tokst.tokst_cmd_len);
	(void) strlcpy(str.buf, user_cmd_str, tokst.tokst_cmd_len);

	/* Trim off any newline character that might be present */
	if ((tokst.tokst_cmd_len > 1) &&
	    (str.buf[tokst.tokst_cmd_len - 2] == '\n')) {
		tokst.tokst_cmd_len--;
		str.buf[tokst.tokst_cmd_len - 1] = '\0';
	}

	/* Tokenize the user command string into tok struct */
	gettok_init(&gettok_state, str.buf, inc_null_final);
	tokst.tokst_str_size = 0;	/* Space needed for token strings */
	for (tokst.tokst_cnt = 0; gettok(&gettok_state) != 0;
	    tokst.tokst_cnt++) {
		/* If we need more room, expand the token buffer */
		if (tokst.tokst_cnt >= tokst.tokst_bufsize) {
			n = (tokst.tokst_bufsize == 0) ?
			    INITIAL_TOK_ALLOC : (tokst.tokst_bufsize * 2);
			tokst.tokst_buf = elfedit_realloc(
			    MSG_INTL(MSG_ALLOC_TOKBUF), tokst.tokst_buf,
			    n * sizeof (*tokst.tokst_buf));
			tokst.tokst_bufsize = n;
		}
		tokst.tokst_str_size +=
		    gettok_state.gtok_last_token.tok_len + 1;
		tokst.tokst_buf[tokst.tokst_cnt] = gettok_state.gtok_last_token;
	}
	/* fold the command token to lowercase */
	if (tokst.tokst_cnt > 0) {
		char *s;

		for (s = tokst.tokst_buf[0].tok_str; *s; s++)
			if (isupper(*s))
				*s = tolower(*s);
	}

	return (&tokst);

#undef	INITIAL_TOK_ALLOC
}


/*
 * Parse the user command string, and put an entry for it at the end
 * of state.ucmd.
 */
static void
parse_user_cmd(const char *user_cmd_str)
{
	TOK_STATE	*tokst;
	char		*s;
	size_t		n;
	size_t		len;
	USER_CMD_T	*ucmd;
	elfeditGC_module_t *mod;
	elfeditGC_cmd_t	*cmd;

	/*
	 * Break it into tokens. If there are none, then it is
	 * an empty command and is ignored.
	 */
	tokst = tokenize_user_cmd(user_cmd_str, -1, 0);
	if (tokst->tokst_cnt == 0)
		return;

	/* Find the command. Won't return on error */
	cmd = elfedit_find_command(tokst->tokst_buf[0].tok_str, 1, &mod);

	/*
	 * If there is no ELF file being edited, then only commands
	 * from the sys: module are allowed.
	 */
	if ((state.file.present == 0) &&
	    (strcmp(mod->mod_name, MSG_ORIG(MSG_MOD_SYS)) != 0))
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_NOFILSYSONLY),
		    mod->mod_name, cmd->cmd_name[0]);


	/* Allocate, fill in, and insert a USER_CMD_T block */
	n = S_DROUND(sizeof (USER_CMD_T));
	ucmd = elfedit_malloc(MSG_INTL(MSG_ALLOC_UCMD),
	    n + (sizeof (char *) * (tokst->tokst_cnt - 1)) +
	    tokst->tokst_cmd_len + tokst->tokst_str_size);
	ucmd->ucmd_next = NULL;
	ucmd->ucmd_argc = tokst->tokst_cnt - 1;
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	ucmd->ucmd_argv = (const char **)(n + (char *)ucmd);
	ucmd->ucmd_orig_str = (char *)(ucmd->ucmd_argv + ucmd->ucmd_argc);
	(void) strncpy(ucmd->ucmd_orig_str, user_cmd_str, tokst->tokst_cmd_len);
	ucmd->ucmd_mod = mod;
	ucmd->ucmd_cmd = cmd;
	ucmd->ucmd_ostyle_set = 0;
	s = ucmd->ucmd_orig_str + tokst->tokst_cmd_len;
	for (n = 1; n < tokst->tokst_cnt; n++) {
		len = tokst->tokst_buf[n].tok_len + 1;
		ucmd->ucmd_argv[n - 1] = s;
		(void) strncpy(s, tokst->tokst_buf[n].tok_str, len);
		s += len;
	}
	if (state.ucmd.list == NULL) {
		state.ucmd.list = state.ucmd.tail = ucmd;
	} else {
		state.ucmd.tail->ucmd_next = ucmd;
		state.ucmd.tail = ucmd;
	}
	state.ucmd.n++;
}


/*
 * Copy infile to a new file with the name given by outfile.
 */
static void
create_outfile(const char *infile, const char *outfile)
{
	pid_t pid;
	int statloc;
	struct stat statbuf;


	pid = fork();
	switch (pid) {
	case -1:			/* Unable to create process */
		{
			int err = errno;
			elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTFORK),
			    strerror(err));
		}
		/*NOTREACHED*/
		return;

	case 0:
		(void) execl(MSG_ORIG(MSG_STR_BINCP),
		    MSG_ORIG(MSG_STR_BINCP), infile, outfile, NULL);
		/*
		 * exec() only returns on error. This is the child process,
		 * so we want to stay away from the usual error mechanism
		 * and handle things directly.
		 */
		{
			int err = errno;
			(void) fprintf(stderr, MSG_INTL(MSG_ERR_CNTEXEC),
			    MSG_ORIG(MSG_STR_ELFEDIT),
			    MSG_ORIG(MSG_STR_BINCP), strerror(err));
		}
		exit(1);
		/*NOTREACHED*/
	}

	/* This is the parent: Wait for the child to terminate */
	if (waitpid(pid, &statloc,  0) != pid) {
		int err = errno;
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTWAIT),
		    strerror(err));
	}
	/*
	 * If the child failed, then terminate the process. There is no
	 * need for an error message, because the child will have taken
	 * care of that.
	 */
	if (!WIFEXITED(statloc) || (WEXITSTATUS(statloc) != 0))
		exit(1);

	/* Make sure the copy allows user write access */
	if (stat(outfile, &statbuf) == -1) {
		int err = errno;
		(void) unlink(outfile);
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTSTAT),
		    outfile, strerror(err));
	}
	if ((statbuf.st_mode & S_IWUSR) == 0) {
		/* Only keep permission bits, and add user write */
		statbuf.st_mode |= S_IWUSR;
		statbuf.st_mode &= 07777;   /* Only keep the permission bits */
		if (chmod(outfile, statbuf.st_mode) == -1) {
			int err = errno;
			(void) unlink(outfile);
			elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTCHMOD),
			    outfile, strerror(err));
		}
	}
}

/*
 * Given a module path string, determine how long the resulting path will
 * be when all % tokens have been expanded.
 *
 * entry:
 *	path - Path for which expanded length is desired
 *	origin_root - Root of $ORIGIN  tree containing running elfedit program
 *
 * exit:
 *	Returns the value strlen() will give for the expanded path.
 */
static size_t
modpath_strlen(const char *path, const char *origin_root)
{
	size_t len = 0;
	const char *s;

	s = path;
	len = 0;
	for (s = path; *s != '\0'; s++) {
		if (*s == '%') {
			s++;
			switch (*s) {
			case 'i':	/* ISA of running elfedit */
				len += strlen(isa_i_str);
				break;
			case 'I':	/* "" for 32-bit, same as %i for 64 */
				len += strlen(isa_I_str);
				break;
			case 'o':	/* Insert default path */
				len +=
				    modpath_strlen(MSG_ORIG(MSG_STR_MODPATH),
				    origin_root);
				break;
			case 'r':	/* root of tree with running elfedit */
				len += strlen(origin_root);
				break;

			case '%':	/* %% is reduced to just '%' */
				len++;
				break;
			default:	/* All other % codes are reserved */
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_BADPATHCODE), *s);
				/*NOTREACHED*/
				break;
			}
		} else {	/* Non-% character passes straight through */
			len++;
		}
	}

	return (len);
}


/*
 * Given a module path string, and a buffer large enough to hold the results,
 * fill the buffer with the expanded path.
 *
 * entry:
 *	path - Path for which expanded length is desired
 *	origin_root - Root of tree containing running elfedit program
 *	buf - Buffer to receive the result. buf must as large or larger
 *		than the value given by modpath_strlen().
 *
 * exit:
 *	Returns pointer to location following the last character
 *	written to buf. A NULL byte is written to that address.
 */
static char *
modpath_expand(const char *path, const char *origin_root, char *buf)
{
	size_t len;
	const char *cp_str;

	for (; *path != '\0'; path++) {
		if (*path == '%') {
			path++;
			cp_str = NULL;
			switch (*path) {
			case 'i':	/* ISA of running elfedit */
				cp_str = isa_i_str;
				break;
			case 'I':	/* "" for 32-bit, same as %i for 64 */
				cp_str = isa_I_str;
				break;
			case 'o':	/* Insert default path */
				buf = modpath_expand(MSG_ORIG(MSG_STR_MODPATH),
				    origin_root, buf);
				break;
			case 'r':
				cp_str = origin_root;
				break;
			case '%':	/* %% is reduced to just '%' */
				*buf++ = *path;
				break;
			default:	/* All other % codes are reserved */
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_BADPATHCODE), *path);
				/*NOTREACHED*/
				break;
			}
			if ((cp_str != NULL) && ((len = strlen(cp_str)) > 0)) {
				bcopy(cp_str, buf, len);
				buf += len;
			}
		} else {	/* Non-% character passes straight through */
			*buf++ = *path;
		}
	}

	*buf = '\0';
	return (buf);
}


/*
 * Establish the module search path: state.modpath
 *
 * The path used comes from the following sources, taking the first
 * one that has a value, and ignoring any others:
 *
 *	- ELFEDIT_PATH environment variable
 *	- -L command line argument
 *	- Default value
 *
 * entry:
 *	path - NULL, or the value of the -L command line argument
 *
 * exit:
 *	state.modpath has been filled in
 */
static void
establish_modpath(const char *cmdline_path)
{
	char origin_root[PATH_MAX + 1];	/* Where elfedit binary is */
	const char	*path;		/* Initial path */
	char		*expath;	/* Expanded path */
	size_t		len;
	char		*src, *dst;

	path = getenv(MSG_ORIG(MSG_STR_ENVVAR));
	if (path == NULL)
		path = cmdline_path;
	if (path == NULL)
		path = MSG_ORIG(MSG_STR_MODPATH);


	/*
	 * Root of tree containing running for running program. 32-bit elfedit
	 * is installed in /usr/bin, and 64-bit elfedit is one level lower
	 * in an ISA-specific subdirectory. So, we find the root by
	 * getting the $ORGIN of the current running program, and trimming
	 * off the last 2 (32-bit) or 3 (64-bit) directories.
	 *
	 * On a standard system, this will simply yield '/'. However,
	 * doing it this way allows us to run elfedit from a proto area,
	 * and pick up modules from the same proto area instead of those
	 * installed on the system.
	 */
	if (dlinfo(RTLD_SELF, RTLD_DI_ORIGIN, &origin_root) == -1)
		elfedit_msg(ELFEDIT_MSG_ERR, MSG_INTL(MSG_ERR_CNTGETORIGIN));
	len = (sizeof (char *) == 8) ? 3 : 2;
	src = origin_root + strlen(origin_root);
	while ((src > origin_root) && (len > 0)) {
		if (*(src - 1) == '/')
			len--;
		src--;
	}
	*src = '\0';


	/*
	 * Calculate space needed to hold expanded path. Note that
	 * this assumes that MSG_STR_MODPATH will never contain a '%o'
	 * code, and so, the expansion is not recursive. The codes allowed
	 * are:
	 *	%i - ISA of running elfedit (sparc, sparcv9, etc)
	 *	%I - 64-bit ISA: Same as %i for 64-bit versions of elfedit,
	 *		but yields empty string for 32-bit ISAs.
	 *	%o - The original (default) path.
	 *	%r - Root of tree holding elfedit program.
	 *	%% - A single %
	 *
	 * A % followed by anything else is an error. This allows us to
	 * add new codes in the future without backward compatability issues.
	 */
	len = modpath_strlen(path, origin_root);

	expath = elfedit_malloc(MSG_INTL(MSG_ALLOC_EXPATH), len + 1);
	(void) modpath_expand(path, origin_root, expath);

	/*
	 * Count path segments, eliminate extra '/', and replace ':'
	 * with NULL.
	 */
	state.modpath.n = 1;
	for (src = dst = expath; *src; src++) {
		if (*src == '/') {
			switch (*(src + 1)) {
			case '/':
			case ':':
			case '\0':
				continue;
			}
		}
		if (*src == ':') {
			state.modpath.n++;
			*dst = '\0';
		} else if (src != dst) {
			*dst = *src;
		}
		dst++;
	}
	if (src != dst)
		*dst = '\0';

	state.modpath.seg = elfedit_malloc(MSG_INTL(MSG_ALLOC_PATHARR),
	    sizeof (state.modpath.seg[0]) * state.modpath.n);

	src = expath;
	for (len = 0; len < state.modpath.n; len++) {
		if (*src == '\0') {
			state.modpath.seg[len] = MSG_ORIG(MSG_STR_DOT);
			src++;
		} else {
			state.modpath.seg[len] = src;
			src += strlen(src) + 1;
		}
	}
}

/*
 * When interactive (reading commands from a tty), we catch
 * SIGINT in order to restart the outer command loop.
 */
/*ARGSUSED*/
static void
sigint_handler(int sig, siginfo_t *sip, void *ucp)
{
	/* Jump to the outer loop to resume */
	if (state.msg_jbuf.active) {
		state.msg_jbuf.active = 0;
		siglongjmp(state.msg_jbuf.env, 1);
	}
}


static void
usage(int full)
{
	elfedit_msg(ELFEDIT_MSG_USAGE, MSG_INTL(MSG_USAGE_BRIEF));
	if (full) {
		elfedit_msg(ELFEDIT_MSG_USAGE, MSG_INTL(MSG_USAGE_DETAIL1));
		elfedit_msg(ELFEDIT_MSG_USAGE, MSG_INTL(MSG_USAGE_DETAIL2));
		elfedit_msg(ELFEDIT_MSG_USAGE, MSG_INTL(MSG_USAGE_DETAIL3));
		elfedit_msg(ELFEDIT_MSG_USAGE, MSG_INTL(MSG_USAGE_DETAIL4));
		elfedit_msg(ELFEDIT_MSG_USAGE, MSG_INTL(MSG_USAGE_DETAIL5));
		elfedit_msg(ELFEDIT_MSG_USAGE, MSG_INTL(MSG_USAGE_DETAIL6));
		elfedit_msg(ELFEDIT_MSG_USAGE, MSG_INTL(MSG_USAGE_DETAIL_LAST));
	}
	elfedit_exit(2);
}


/*
 * In order to complete commands, we need to know about them,
 * which means that we need to force all the modules to be
 * loaded. This is a relatively expensive operation, so we use
 * this function, which avoids doing it more than once in a session.
 */
static void
elfedit_cpl_load_modules(void)
{
	static int loaded;

	if (!loaded) {
		elfedit_load_modpath();
		loaded = 1;	/* Don't do it again */
	}
}

/*
 * Compare the token to the given string, and if they share a common
 * initial sequence, add the tail of string to the tecla command completion
 * buffer:
 *
 * entry:
 *	cpldata - Current completion state
 *	str - String to match against token
 *	casefold - True to allow case insensitive completion, False
 *		if case must match exactly.
 */
void
elfedit_cpl_match(void *cpldata, const char *str, int casefold)
{
	ELFEDIT_CPL_STATE *cstate = (ELFEDIT_CPL_STATE *) cpldata;
	const char	*cont_suffix;
	const char	*type_suffix;

	/*
	 * Reasons to return immediately:
	 *	- NULL strings have no completion value
	 *	- The string is shorter than the existing item being completed
	 */
	if ((str == NULL) || (*str == '\0') ||
	    ((cstate->ecpl_token_len != 0) &&
	    ((strlen(str) < cstate->ecpl_token_len))))
		return;

	/* If the string does not share the existing prefix, don't use it */
	if (casefold) {
		if (strncasecmp(cstate->ecpl_token_str, str,
		    cstate->ecpl_token_len) != 0)
			return;
	} else {
		if (strncmp(cstate->ecpl_token_str, str,
		    cstate->ecpl_token_len) != 0)
			return;
	}

	if (cstate->ecpl_add_mod_colon) {
		cont_suffix = type_suffix = MSG_ORIG(MSG_STR_COLON);
	} else {
		cont_suffix = MSG_ORIG(MSG_STR_SPACE);
		type_suffix = NULL;
	}
	(void) cpl_add_completion(cstate->ecpl_cpl, cstate->ecpl_line,
	    cstate->ecpl_word_start, cstate->ecpl_word_end,
	    str + cstate->ecpl_token_len, type_suffix, cont_suffix);

}


/*
 * Convenience wrapper on elfedit_cpl_match(): Format an unsigned
 * 32-bit integer as a string and enter the result for command completion.
 */
void
elfedit_cpl_ndx(void *cpldata, uint_t ndx)
{
	Conv_inv_buf_t	buf;

	(void) snprintf(buf.buf, sizeof (buf.buf),
	    MSG_ORIG(MSG_FMT_WORDVAL), ndx);
	elfedit_cpl_match(cpldata, buf.buf, 0);
}


/*
 * Compare the token to the names of the commands from the given module,
 * and if they share a common initial sequence, add the tail of string
 * to the tecla command completion buffer:
 *
 * entry:
 *	tok_buf - Token user has entered
 *	tok_len - strlen(tok_buf)
 *	mod - Module definition from which commands should be matched
 *	cpl, line, word_start, word_end, cont_suffix - As documented
 *		for gl_get_line() and cpl_add_completion.
 */
static void
match_module_cmds(ELFEDIT_CPL_STATE *cstate, elfeditGC_module_t *mod)
{
	elfeditGC_cmd_t *cmd;
	const char **cmd_name;

	for (cmd = mod->mod_cmds; cmd->cmd_func != NULL; cmd++)
		for (cmd_name = cmd->cmd_name; *cmd_name; cmd_name++)
			elfedit_cpl_match(cstate, *cmd_name, 1);
}


/*
 * Compare the token to the known module names, and add those that
 * match to the list of alternatives via elfedit_cpl_match().
 *
 * entry:
 *	load_all_modules - If True, causes all modules to be loaded
 *		before processing is done. If False, only the modules
 *		currently seen will be used.
 */
void
elfedit_cpl_module(void *cpldata, int load_all_modules)
{
	ELFEDIT_CPL_STATE	*cstate = (ELFEDIT_CPL_STATE *) cpldata;
	MODLIST_T		*modlist;

	if (load_all_modules)
		elfedit_cpl_load_modules();

	for (modlist = state.modlist; modlist != NULL;
	    modlist = modlist->ml_next) {
		elfedit_cpl_match(cstate, modlist->ml_mod->mod_name, 1);
	}
}


/*
 * Compare the token to all the known commands, and add those that
 * match to the list of alternatives.
 *
 * note:
 *	This routine will force modules to be loaded as necessary to
 *	obtain the names it needs to match.
 */
void
elfedit_cpl_command(void *cpldata)
{
	ELFEDIT_CPL_STATE	*cstate = (ELFEDIT_CPL_STATE *) cpldata;
	ELFEDIT_CPL_STATE	colon_state;
	const char		*colon_pos;
	MODLIST_T		*modlist;
	MODLIST_T		*insdef;
	char			buf[128];

	/*
	 * Is there a colon in the command? If so, locate its offset within
	 * the raw input line.
	 */
	for (colon_pos = cstate->ecpl_token_str;
	    *colon_pos && (*colon_pos != ':'); colon_pos++)
		;

	/*
	 * If no colon was seen, then we are completing a module name,
	 * or one of the commands from 'sys:'
	 */
	if (*colon_pos == '\0') {
		/*
		 * Setting cstate->add_mod_colon tells elfedit_cpl_match()
		 * to add an implicit ':' to the names it matches. We use it
		 * here so the user doesn't have to enter the ':' manually.
		 * Hiding this in the opaque state instead of making it
		 * an argument to that function gives us the ability to
		 * change it later without breaking the published interface.
		 */
		cstate->ecpl_add_mod_colon = 1;
		elfedit_cpl_module(cpldata, 1);
		cstate->ecpl_add_mod_colon = 0;

		/* Add bare (no sys: prefix) commands from the sys: module */
		match_module_cmds(cstate,
		    elfedit_load_module(MSG_ORIG(MSG_MOD_SYS), 1, 0));

		return;
	}

	/*
	 * A colon was seen, so we have a module name. Extract the name,
	 * substituting 'sys' for the case where the given name is empty.
	 */
	if (colon_pos == 0)
		(void) strlcpy(buf, MSG_ORIG(MSG_MOD_SYS), sizeof (buf));
	else
		elfedit_strnbcpy(buf, cstate->ecpl_token_str,
		    colon_pos - cstate->ecpl_token_str, sizeof (buf));

	/*
	 * Locate the module. If it isn't already loaded, make an explicit
	 * attempt to load it and try again. If a module definition is
	 * obtained, process the commands it supplies.
	 */
	modlist = module_loaded(buf, &insdef);
	if (modlist == NULL) {
		(void) elfedit_load_module(buf, 0, 0);
		modlist = module_loaded(buf, &insdef);
	}
	if (modlist != NULL) {
		/*
		 * Make a copy of the cstate, and adjust the line and
		 * token so that the new one starts just past the colon
		 * character. We know that the colon exists because
		 * of the preceeding test that found it. Therefore, we do
		 * not need to test against running off the end of the
		 * string here.
		 */
		colon_state = *cstate;
		while (colon_state.ecpl_line[colon_state.ecpl_word_start] !=
		    ':')
			colon_state.ecpl_word_start++;
		while (*colon_state.ecpl_token_str != ':') {
			colon_state.ecpl_token_str++;
			colon_state.ecpl_token_len--;
		}
		/* Skip past the ':' character */
		colon_state.ecpl_word_start++;
		colon_state.ecpl_token_str++;
		colon_state.ecpl_token_len--;

		match_module_cmds(&colon_state, modlist->ml_mod);
	}
}


/*
 * Command completion function for use with libtacla.
 */
/*ARGSUSED1*/
static int
cmd_match_fcn(WordCompletion *cpl, void *data, const char *line, int word_end)
{
	const char		*argv[ELFEDIT_MAXCPLARGS];
	ELFEDIT_CPL_STATE	cstate;
	TOK_STATE		*tokst;
	int			ndx;
	int			i;
	elfeditGC_module_t	*mod;
	elfeditGC_cmd_t		*cmd;
	int			num_opt;
	int			opt_term_seen;
	int			skip_one;
	elfedit_cmd_optarg_t	*optarg;
	elfedit_optarg_item_t	item;
	int			ostyle_ndx = -1;

	/*
	 * For debugging, enable the following block. It tells the tecla
	 * library that the program using is going to write to stdout.
	 * It will put the tty back into normal mode, and it will cause
	 * tecla to redraw the current input line when it gets control back.
	 */
#ifdef DEBUG_CMD_MATCH
	gl_normal_io(state.input.gl);
#endif

	/*
	 * Tokenize the line up through word_end. The last token in
	 * the list is the one requiring completion.
	 */
	tokst = tokenize_user_cmd(line, word_end, 1);
	if (tokst->tokst_cnt == 0)
		return (0);

	/* Set up the cstate block, containing the completion state */
	ndx = tokst->tokst_cnt - 1;	/* Index of token to complete */
	cstate.ecpl_cpl = cpl;
	cstate.ecpl_line = line;
	cstate.ecpl_word_start = tokst->tokst_buf[ndx].tok_line_off;
	cstate.ecpl_word_end = word_end;
	cstate.ecpl_add_mod_colon = 0;
	cstate.ecpl_token_str = tokst->tokst_buf[ndx].tok_str;
	cstate.ecpl_token_len = tokst->tokst_buf[ndx].tok_len;

	/*
	 * If there is only one token, then we are completing the
	 * command itself.
	 */
	if (ndx == 0) {
		elfedit_cpl_command(&cstate);
		return (0);
	}

	/*
	 * There is more than one token. Use the first one to
	 * locate the definition for the command. If we don't have
	 * a definition for the command, then there's nothing more
	 * we can do.
	 */
	cmd = elfedit_find_command(tokst->tokst_buf[0].tok_str, 0, &mod);
	if (cmd == NULL)
		return (0);

	/*
	 * Since we know the command, give them a quick usage message.
	 * It may be that they just need a quick reminder about the form
	 * of the command and the options.
	 */
	(void) gl_normal_io(state.input.gl);
	elfedit_printf(MSG_INTL(MSG_USAGE_CMD),
	    elfedit_format_command_usage(mod, cmd, NULL, 0));


	/*
	 * We have a generous setting for ELFEDIT_MAXCPLARGS, so there
	 * should always be plenty of room. If there's not room, we
	 * can't proceed.
	 */
	if (ndx >= ELFEDIT_MAXCPLARGS)
		return (0);

	/*
	 * Put pointers to the tokens into argv, and determine how
	 * many of the tokens are optional arguments.
	 *
	 * We consider the final optional argument to be the rightmost
	 * argument that starts with a '-'. If a '--' is seen, then
	 * we stop there, and any argument that follows is a plain argument
	 * (even if it starts with '-').
	 *
	 * We look for an inherited '-o' option, because we are willing
	 * to supply command completion for these values.
	 */
	num_opt = 0;
	opt_term_seen = 0;
	skip_one = 0;
	for (i = 0; i < ndx; i++) {
		argv[i] = tokst->tokst_buf[i + 1].tok_str;
		if (opt_term_seen || skip_one) {
			skip_one = 0;
			continue;
		}
		skip_one = 0;
		ostyle_ndx = -1;
		if ((strcmp(argv[i], MSG_ORIG(MSG_STR_MINUS_MINUS)) == 0) ||
		    (*argv[i] != '-')) {
			opt_term_seen = 1;
			continue;
		}
		num_opt = i + 1;
		/*
		 * If it is a recognised ELFEDIT_CMDOA_F_VALUE option,
		 * then the item following it is the associated value.
		 * Check for this and skip the value.
		 *
		 * At the same time, look for STDOA_OPT_O inherited
		 * options. We want to identify the index of any such
		 * item. Although the option is simply "-o", we are willing
		 * to treat any option that starts with "-o" as a potential
		 * STDOA_OPT_O. This lets us to command completion for things
		 * like "-onum", and is otherwise harmless, the only cost
		 * being a few additional strcmps by the cpl code.
		 */
		if ((optarg = cmd->cmd_opt) == NULL)
			continue;
		while (optarg->oa_name != NULL) {
			int is_ostyle_optarg =
			    (optarg->oa_flags & ELFEDIT_CMDOA_F_INHERIT) &&
			    (optarg->oa_name == ELFEDIT_STDOA_OPT_O);

			elfedit_next_optarg(&optarg, &item);
			if (item.oai_flags & ELFEDIT_CMDOA_F_VALUE) {
				if (is_ostyle_optarg && (strncmp(argv[i],
				    MSG_ORIG(MSG_STR_MINUS_O), 2) == 0))
					ostyle_ndx = i + 1;

				if (strcmp(item.oai_name, argv[i]) == 0) {
					num_opt = i + 2;
					skip_one = 1;
					break;
				}
				/*
				 * If it didn't match "-o" exactly, but it is
				 * ostyle_ndx, then it is a potential combined
				 * STDOA_OPT_O, as discussed above. It counts
				 * as a single argument.
				 */
				if (ostyle_ndx == ndx)
					break;
			}
		}
	}

#ifdef DEBUG_CMD_MATCH
	(void) printf("NDX(%d) NUM_OPT(%d) ostyle_ndx(%d)\n", ndx, num_opt,
	    ostyle_ndx);
#endif

	if (ostyle_ndx != -1) {
		/*
		 * If ostyle_ndx is one less than ndx, and ndx is
		 * the same as num_opt, then we have a definitive
		 * STDOA_OPT_O inherited outstyle option. We supply
		 * the value strings, and are done.
		 */
		if ((ostyle_ndx == (ndx - 1)) && (ndx == num_opt)) {
			elfedit_cpl_atoconst(&cstate, ELFEDIT_CONST_OUTSTYLE);
			return (0);
		}

		/*
		 * If ostyle is the same as ndx, then we have an option
		 * staring with "-o" that may end up being a STDOA_OPT_O,
		 * and we are still inside that token. In this case, we
		 * supply completion strings that include the leading
		 * "-o" followed by the values, without a space
		 * (i.e. "-onum"). We then fall through, allowing any
		 * other options starting with "-o" to be added
		 * below. elfedit_cpl_match() will throw out the incorrect
		 * options, so it is harmless to add these extra items in
		 * the worst case, and useful otherwise.
		 */
		if (ostyle_ndx == ndx)
			elfedit_cpl_atoconst(&cstate,
			    ELFEDIT_CONST_OUTSTYLE_MO);
	}

	/*
	 * If (ndx <= num_opt), then the token needing completion
	 * is an option. If the leading '-' is there, then we should fill
	 * in all of the option alternatives. If anything follows the '-'
	 * though, we assume that the user has already figured out what
	 * option to use, and we leave well enough alone.
	 *
	 * Note that we are intentionally ignoring a related case
	 * where supplying option strings would be legal: In the case
	 * where we are one past the last option (ndx == (num_opt + 1)),
	 * and the current option is an empty string, the argument can
	 * be either a plain argument or an option --- the user needs to
	 * enter the next character before we can tell. It would be
	 * OK to enter the option strings in this case. However, consider
	 * what happens when the first plain argument to the command does
	 * not provide any command completion (e.g. it is a plain integer).
	 * In this case, tecla will see that all the alternatives start
	 * with '-', and will insert a '-' into the input. If the user
	 * intends the next argument to be plain, they will have to delete
	 * this '-', which is annoying. Worse than that, they may be confused
	 * by it, and think that the plain argument is not allowed there.
	 * The best solution is to not supply option strings unless the
	 * user first enters the '-'.
	 */
	if ((ndx <= num_opt) && (argv[ndx - 1][0] == '-')) {
		if ((optarg = cmd->cmd_opt) != NULL) {
			while (optarg->oa_name != NULL) {
				elfedit_next_optarg(&optarg, &item);
				elfedit_cpl_match(&cstate, item.oai_name, 1);
			}
		}
		return (0);
	}

	/*
	 * At this point we know that ndx and num_opt are not equal.
	 * If num_opt is larger than ndx, then we have an ELFEDIT_CMDOA_F_VALUE
	 * argument at the end, and the following value has not been entered.
	 *
	 * If ndx is greater than num_opt, it means that we are looking
	 * at a plain argument (or in the case where (ndx == (num_opt + 1)),
	 * a *potential* plain argument.
	 *
	 * If the command has a completion function registered, then we
	 * hand off the remaining work to it. The cmd_cplfunc field is
	 * the generic definition. We need to cast it to the type that matches
	 * the proper ELFCLASS before calling it.
	 */
	if (state.elf.elfclass == ELFCLASS32) {
		elfedit32_cmdcpl_func_t *cmdcpl_func =
		    (elfedit32_cmdcpl_func_t *)cmd->cmd_cplfunc;

		if (cmdcpl_func != NULL)
			(* cmdcpl_func)(state.elf.obj_state.s32,
			    &cstate, ndx, argv, num_opt);
	} else {
		elfedit64_cmdcpl_func_t *cmdcpl_func =
		    (elfedit64_cmdcpl_func_t *)cmd->cmd_cplfunc;

		if (cmdcpl_func != NULL)
			(* cmdcpl_func)(state.elf.obj_state.s64,
			    &cstate, ndx, argv, num_opt);
	}

	return (0);
}


/*
 * Read a line of input from stdin, and return pointer to it.
 *
 * This routine uses a private buffer, so the contents of the returned
 * string are only good until the next call.
 */
static const char *
read_cmd(void)
{
	char *s;

	if (state.input.full_tty) {
		state.input.in_tecla = TRUE;
		s = gl_get_line(state.input.gl,
		    MSG_ORIG(MSG_STR_PROMPT), NULL, -1);
		state.input.in_tecla = FALSE;
		/*
		 * gl_get_line() returns NULL for EOF or for error. EOF is fine,
		 * but we need to catch and report anything else. Since
		 * reading from stdin is critical to our operation, an
		 * error implies that we cannot recover and must exit.
		 */
		if ((s == NULL) &&
		    (gl_return_status(state.input.gl) == GLR_ERROR)) {
			elfedit_msg(ELFEDIT_MSG_FATAL, MSG_INTL(MSG_ERR_GLREAD),
			    gl_error_message(state.input.gl, NULL, 0));
		}
	} else {
		/*
		 * This should be a dynamically sized buffer, but for now,
		 * I'm going to take a simpler path.
		 */
		static char cmd_buf[ELFEDIT_MAXCMD + 1];

		s = fgets(cmd_buf, sizeof (cmd_buf), stdin);
	}

	/* Return user string, or 'quit' on EOF */
	return (s ? s : MSG_ORIG(MSG_SYS_CMD_QUIT));
}

int
main(int argc, char **argv, char **envp)
{
	/*
	 * Note: This function can use setjmp()/longjmp() which does
	 * not preserve the values of auto/register variables. Hence,
	 * variables that need their values preserved across a jump must
	 * be marked volatile, or must not be auto/register.
	 *
	 * Volatile can be messy, because it requires explictly casting
	 * away the attribute when passing it to functions, or declaring
	 * those functions with the attribute as well. In a single threaded
	 * program like this one, an easier approach is to make things
	 * static. That can be done here, or by putting things in the
	 * 'state' structure.
	 */

	int		c, i;
	int		num_batch = 0;
	char		**batch_list = NULL;
	const char	*modpath = NULL;

	/*
	 * Always have liblddb display unclipped section names.
	 * This global is exported by liblddb, and declared in debug.h.
	 */
	dbg_desc->d_extra |= DBG_E_LONG;

	opterr = 0;
	while ((c = getopt(argc, argv, MSG_ORIG(MSG_STR_OPTIONS))) != EOF) {
		switch (c) {
		case 'a':
			state.flags |= ELFEDIT_F_AUTOPRINT;
			break;

		case 'd':
			state.flags |= ELFEDIT_F_DEBUG;
			break;

		case 'e':
			/*
			 * Delay parsing the -e options until after the call to
			 * conv_check_native() so that we won't bother loading
			 * modules of the wrong class.
			 */
			if (batch_list == NULL)
				batch_list = elfedit_malloc(
				    MSG_INTL(MSG_ALLOC_BATCHLST),
				    sizeof (*batch_list) * (argc - 1));
			batch_list[num_batch++] = optarg;
			break;

		case 'L':
			modpath = optarg;
			break;

		case 'o':
			if (elfedit_atooutstyle(optarg, &state.outstyle) == 0)
				usage(1);
			break;

		case 'r':
			state.flags |= ELFEDIT_F_READONLY;
			break;

		case '?':
			usage(1);
		}
	}

	/*
	 * We allow 0, 1, or 2 files:
	 *
	 * The no-file case is an extremely limited mode, in which the
	 * only commands allowed to execute come from the sys: module.
	 * This mode exists primarily to allow easy access to the help
	 * facility.
	 *
	 * To get full access to elfedit's capablities, there must
	 * be an input file. If this is not a readonly
	 * session, then an optional second output file is allowed.
	 *
	 * In the case where two files are given and the session is
	 * readonly, use a full usage message, because the simple
	 * one isn't enough for the user to understand their error.
	 * Otherwise, the simple usage message suffices.
	 */
	argc = argc - optind;
	if ((argc == 2) && (state.flags & ELFEDIT_F_READONLY))
		usage(1);
	if (argc > 2)
		usage(0);

	state.file.present = (argc != 0);

	/*
	 * If we have a file to edit, and unless told otherwise by the
	 * caller, we try to run the 64-bit version of this program
	 * when the system is capable of it. If that fails, then we
	 * continue on with the currently running version.
	 *
	 * To force 32-bit execution on a 64-bit host, set the
	 * LD_NOEXEC_64 environment variable to a non-empty value.
	 *
	 * There is no reason to bother with this if in "no file" mode.
	 */
	if (state.file.present != 0)
		(void) conv_check_native(argv, envp);

	elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_VERSION),
	    (sizeof (char *) == 8) ? 64 : 32);

	/*
	 * Put a module definition for the builtin system module on the
	 * module list. We know it starts out empty, so we do not have
	 * to go through a more general insertion process than this.
	 */
	state.modlist = elfedit_sys_init(ELFEDIT_VER_CURRENT);

	/* Establish the search path for loadable modules */
	establish_modpath(modpath);

	/*
	 * Now that we are running the final version of this program,
	 * deal with the input/output file(s).
	 */
	if (state.file.present == 0) {
		/*
		 * This is arbitrary --- we simply need to be able to
		 * load modules so that we can access their help strings
		 * and command completion functions. Without a file, we
		 * will refuse to call commands from any module other
		 * than sys. Those commands have been written to be aware
		 * of the case where there is no input file, and are
		 * therefore safe to run.
		 */
		state.elf.elfclass = ELFCLASS32;
		elfedit_msg(ELFEDIT_MSG_DEBUG, MSG_INTL(MSG_DEBUG_NOFILE));

	} else {
		state.file.infile = argv[optind];
		if (argc == 1) {
			state.file.outfile = state.file.infile;
			if (state.flags & ELFEDIT_F_READONLY)
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_READONLY));
			else
				elfedit_msg(ELFEDIT_MSG_DEBUG,
				    MSG_INTL(MSG_DEBUG_INPLACEWARN),
				    state.file.infile);
		} else {
			state.file.outfile = argv[optind + 1];
			create_outfile(state.file.infile, state.file.outfile);
			elfedit_msg(ELFEDIT_MSG_DEBUG,
			    MSG_INTL(MSG_DEBUG_CPFILE),
			    state.file.infile, state.file.outfile);
			/*
			 * We are editing a copy of the original file that we
			 * just created. If we should exit before the edits are
			 * updated, then we want to unlink this copy so that we
			 * don't leave junk lying around. Once an update
			 * succeeds however, we'll leave it in place even
			 * if an error occurs afterwards.
			 */
			state.file.unlink_on_exit = 1;
			optind++;	/* Edit copy instead of the original */
		}

		init_obj_state(state.file.outfile);
	}


	/*
	 * Process commands.
	 *
	 * If any -e options were used, then do them and
	 * immediately exit. On error, exit immediately without
	 * updating the target ELF file. On success, the 'write'
	 * and 'quit' commands are implicit in this mode.
	 *
	 * If no -e options are used, read commands from stdin.
	 * quit must be explicitly used. Exit is implicit on EOF.
	 * If stdin is a tty, then errors do not cause the editor
	 * to terminate. Rather, the error message is printed, and the
	 * user prompted to continue.
	 */
	if (batch_list != NULL) {	/* -e was used */
		/* Compile the commands */
		for (i = 0; i < num_batch; i++)
			parse_user_cmd(batch_list[i]);
		free(batch_list);

		/*
		 * 'write' and 'quit' are implicit in this mode.
		 * Add them as well.
		 */
		if ((state.flags & ELFEDIT_F_READONLY) == 0)
			parse_user_cmd(MSG_ORIG(MSG_SYS_CMD_WRITE));
		parse_user_cmd(MSG_ORIG(MSG_SYS_CMD_QUIT));

		/* And run them. This won't return, thanks to the 'quit' */
		dispatch_user_cmds();
	} else {
		state.input.is_tty = isatty(fileno(stdin));
		state.input.full_tty = state.input.is_tty &&
		    isatty(fileno(stdout));

		if (state.input.full_tty) {
			struct sigaction act;

			act.sa_sigaction = sigint_handler;
			(void) sigemptyset(&act.sa_mask);
			act.sa_flags = 0;
			if (sigaction(SIGINT, &act, NULL) == -1) {
				int err = errno;
				elfedit_msg(ELFEDIT_MSG_ERR,
				    MSG_INTL(MSG_ERR_SIGACTION), strerror(err));
			}
			/*
			 * If pager process exits before we are done
			 * writing, we can see SIGPIPE. Prevent it
			 * from killing the process.
			 */
			(void) sigignore(SIGPIPE);

			/* Open tecla handle for command line editing */
			state.input.gl = new_GetLine(ELFEDIT_MAXCMD,
			    ELFEDIT_MAXHIST);
			/* Register our command completion function */
			(void) gl_customize_completion(state.input.gl,
			    NULL, cmd_match_fcn);

			/*
			 * Make autoprint the default for interactive
			 * sessions.
			 */
			state.flags |= ELFEDIT_F_AUTOPRINT;
		}
		for (;;) {
			/*
			 * If this is an interactive session, then use
			 * sigsetjmp()/siglongjmp() to recover from bad
			 * commands and keep going. A non-0 return from
			 * sigsetjmp() means that an error just occurred.
			 * In that case, we simply restart this loop.
			 */
			if (state.input.is_tty) {
				if (sigsetjmp(state.msg_jbuf.env, 1) != 0) {
					if (state.input.full_tty)
						gl_abandon_line(state.input.gl);
					continue;
				}
				state.msg_jbuf.active = TRUE;
			}

			/*
			 * Force all output out before each command.
			 * This is a no-OP when a tty is in use, but
			 * in a pipeline, it ensures that the block
			 * mode buffering doesn't delay output past
			 * the completion of each command.
			 *
			 * If we didn't do this, the output would eventually
			 * arrive at its destination, but the lag can be
			 * annoying when you pipe the output into a tool
			 * that displays the results in real time.
			 */
			(void) fflush(stdout);
			(void) fflush(stderr);

			parse_user_cmd(read_cmd());
			dispatch_user_cmds();
			state.msg_jbuf.active = FALSE;
		}
	}


	/*NOTREACHED*/
	return (0);
}
