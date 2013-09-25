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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/disp.h>
#include <sys/conf.h>
#include <sys/bootconf.h>
#include <sys/sysconf.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/hwconf.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/autoconf.h>
#include <sys/callb.h>
#include <sys/sysmacros.h>
#include <sys/dacf.h>
#include <vm/seg_kmem.h>

struct hwc_class *hcl_head;	/* head of list of classes */
static kmutex_t hcl_lock;	/* for accessing list of classes */

#define	DAFILE		"/etc/driver_aliases"
#define	CLASSFILE	"/etc/driver_classes"
#define	DACFFILE	"/etc/dacf.conf"

static char class_file[] = CLASSFILE;
static char dafile[] = DAFILE;
static char dacffile[] = DACFFILE;

char *systemfile = "/etc/system";	/* name of ascii system file */

static struct sysparam *sysparam_hd;	/* head of parameters list */
static struct sysparam *sysparam_tl;	/* tail of parameters list */
static vmem_t *mod_sysfile_arena;	/* parser memory */

char obp_bootpath[BO_MAXOBJNAME];	/* bootpath from obp */
char svm_bootpath[BO_MAXOBJNAME];	/* bootpath redirected via rootdev */

#if defined(_PSM_MODULES)

struct psm_mach {
	struct psm_mach *m_next;
	char		*m_machname;
};

static struct psm_mach *pmach_head;	/* head of list of classes */

#define	MACHFILE	"/etc/mach"
static char mach_file[] = MACHFILE;

#endif	/* _PSM_MODULES */

#if defined(_RTC_CONFIG)
static char rtc_config_file[] = "/etc/rtc_config";
#endif

static void sys_set_var(int, struct sysparam *, void *);

static void setparams(void);

/*
 * driver.conf parse thread control structure
 */
struct hwc_parse_mt {
	ksema_t		sema;
	char		*name;		/* name of .conf files */
	struct par_list	**pl;		/* parsed parent list */
	ddi_prop_t	**props;	/* parsed properties */
	int		rv;		/* return value */
};

static int hwc_parse_now(char *, struct par_list **, ddi_prop_t **);
static void hwc_parse_thread(struct hwc_parse_mt *);
static struct hwc_parse_mt *hwc_parse_mtalloc(char *, struct par_list **,
	ddi_prop_t **);
static void hwc_parse_mtfree(struct hwc_parse_mt *);
static void add_spec(struct hwc_spec *, struct par_list **);
static void add_props(struct hwc_spec *, ddi_prop_t **);

static void check_system_file(void);
static int sysparam_compare_entry(struct sysparam *, struct sysparam *);
static char *sysparam_type_to_str(int);
static void sysparam_count_entry(struct sysparam *, int *, u_longlong_t *);
static void sysparam_print_warning(struct sysparam *, u_longlong_t);

#ifdef DEBUG
static int parse_debug_on = 0;

/*VARARGS1*/
static void
parse_debug(struct _buf *file, char *fmt, ...)
{
	va_list adx;

	if (parse_debug_on) {
		va_start(adx, fmt);
		vprintf(fmt, adx);
		if (file)
			printf(" on line %d of %s\n", kobj_linenum(file),
			    kobj_filename(file));
		va_end(adx);
	}
}
#endif /* DEBUG */

#define	FE_BUFLEN 256

/*PRINTFLIKE3*/
void
kobj_file_err(int type,  struct _buf *file, char *fmt, ...)
{
	va_list ap;
	/*
	 * If we're in trouble, we might be short on stack... be paranoid
	 */
	char *buf = kmem_alloc(FE_BUFLEN, KM_SLEEP);
	char *trailer = kmem_alloc(FE_BUFLEN, KM_SLEEP);
	char *fmt_str = kmem_alloc(FE_BUFLEN, KM_SLEEP);
	char prefix = '\0';

	va_start(ap, fmt);
	if (strchr("^!?", fmt[0]) != NULL) {
		prefix = fmt[0];
		fmt++;
	}
	(void) vsnprintf(buf, FE_BUFLEN, fmt, ap);
	va_end(ap);
	(void) snprintf(trailer, FE_BUFLEN, " on line %d of %s",
	    kobj_linenum(file), kobj_filename(file));

	/*
	 * If prefixed with !^?, prepend that character
	 */
	if (prefix != '\0') {
		(void) snprintf(fmt_str, FE_BUFLEN, "%c%%s%%s", prefix);
	} else {
		(void) strncpy(fmt_str, "%s%s", FE_BUFLEN);
	}

	cmn_err(type, fmt_str, buf, trailer);
	kmem_free(buf, FE_BUFLEN);
	kmem_free(trailer, FE_BUFLEN);
	kmem_free(fmt_str, FE_BUFLEN);
}

#ifdef DEBUG
char *tokennames[] = {
	"UNEXPECTED",
	"EQUALS",
	"AMPERSAND",
	"BIT_OR",
	"STAR",
	"POUND",
	"COLON",
	"SEMICOLON",
	"COMMA",
	"SLASH",
	"WHITE_SPACE",
	"NEWLINE",
	"EOF",
	"STRING",
	"HEXVAL",
	"DECVAL",
	"NAME"
};
#endif /* DEBUG */

token_t
kobj_lex(struct _buf *file, char *val, size_t size)
{
	char	*cp;
	int	ch, oval, badquote;
	size_t	remain;
	token_t token = UNEXPECTED;

	if (size < 2)
		return (token);	/* this token is UNEXPECTED */

	cp = val;
	while ((ch = kobj_getc(file)) == ' ' || ch == '\t')
		;

	remain = size - 1;
	*cp++ = (char)ch;
	switch (ch) {
	case '=':
		token = EQUALS;
		break;
	case '&':
		token = AMPERSAND;
		break;
	case '|':
		token = BIT_OR;
		break;
	case '*':
		token = STAR;
		break;
	case '#':
		token = POUND;
		break;
	case ':':
		token = COLON;
		break;
	case ';':
		token = SEMICOLON;
		break;
	case ',':
		token = COMMA;
		break;
	case '/':
		token = SLASH;
		break;
	case ' ':
	case '\t':
	case '\f':
		while ((ch = kobj_getc(file)) == ' ' ||
		    ch == '\t' || ch == '\f') {
			if (--remain == 0) {
				token = UNEXPECTED;
				goto out;
			}
			*cp++ = (char)ch;
		}
		(void) kobj_ungetc(file);
		token = WHITE_SPACE;
		break;
	case '\n':
	case '\r':
		token = NEWLINE;
		break;
	case '"':
		remain++;
		cp--;
		badquote = 0;
		while (!badquote && (ch  = kobj_getc(file)) != '"') {
			switch (ch) {
			case '\n':
			case -1:
				kobj_file_err(CE_WARN, file, "Missing \"");
				remain = size - 1;
				cp = val;
				*cp++ = '\n';
				badquote = 1;
				/* since we consumed the newline/EOF */
				(void) kobj_ungetc(file);
				break;

			case '\\':
				if (--remain == 0) {
					token = UNEXPECTED;
					goto out;
				}
				ch = (char)kobj_getc(file);
				if (!isdigit(ch)) {
					/* escape the character */
					*cp++ = (char)ch;
					break;
				}
				oval = 0;
				while (ch >= '0' && ch <= '7') {
					ch -= '0';
					oval = (oval << 3) + ch;
					ch = (char)kobj_getc(file);
				}
				(void) kobj_ungetc(file);
				/* check for character overflow? */
				if (oval > 127) {
					cmn_err(CE_WARN,
					    "Character "
					    "overflow detected.");
				}
				*cp++ = (char)oval;
				break;
			default:
				if (--remain == 0) {
					token = UNEXPECTED;
					goto out;
				}
				*cp++ = (char)ch;
				break;
			}
		}
		token = STRING;
		break;

	case -1:
		token = EOF;
		break;

	default:
		/*
		 * detect a lone '-' (including at the end of a line), and
		 * identify it as a 'name'
		 */
		if (ch == '-') {
			if (--remain == 0) {
				token = UNEXPECTED;
				goto out;
			}
			*cp++ = (char)(ch = kobj_getc(file));
			if (iswhite(ch) || (ch == '\n')) {
				(void) kobj_ungetc(file);
				remain++;
				cp--;
				token = NAME;
				break;
			}
		} else if (isunary(ch)) {
			if (--remain == 0) {
				token = UNEXPECTED;
				goto out;
			}
			*cp++ = (char)(ch = kobj_getc(file));
		}


		if (isdigit(ch)) {
			if (ch == '0') {
				if ((ch = kobj_getc(file)) == 'x') {
					if (--remain == 0) {
						token = UNEXPECTED;
						goto out;
					}
					*cp++ = (char)ch;
					ch = kobj_getc(file);
					while (isxdigit(ch)) {
						if (--remain == 0) {
							token = UNEXPECTED;
							goto out;
						}
						*cp++ = (char)ch;
						ch = kobj_getc(file);
					}
					(void) kobj_ungetc(file);
					token = HEXVAL;
				} else {
					goto digit;
				}
			} else {
				ch = kobj_getc(file);
digit:
				while (isdigit(ch)) {
					if (--remain == 0) {
						token = UNEXPECTED;
						goto out;
					}
					*cp++ = (char)ch;
					ch = kobj_getc(file);
				}
				(void) kobj_ungetc(file);
				token = DECVAL;
			}
		} else if (isalpha(ch) || ch == '\\' || ch == '_') {
			if (ch != '\\') {
				ch = kobj_getc(file);
			} else {
				/*
				 * if the character was a backslash,
				 * back up so we can overwrite it with
				 * the next (i.e. escaped) character.
				 */
				remain++;
				cp--;
			}
			while (isnamechar(ch) || ch == '\\') {
				if (ch == '\\')
					ch = kobj_getc(file);
				if (--remain == 0) {
					token = UNEXPECTED;
					goto out;
				}
				*cp++ = (char)ch;
				ch = kobj_getc(file);
			}
			(void) kobj_ungetc(file);
			token = NAME;
		} else {
			token = UNEXPECTED;
		}
		break;
	}
out:
	*cp = '\0';

#ifdef DEBUG
	/*
	 * The UNEXPECTED token is the first element of the tokennames array,
	 * but its token value is -1.  Adjust the value by adding one to it
	 * to change it to an index of the array.
	 */
	parse_debug(NULL, "kobj_lex: token %s value '%s'\n",
	    tokennames[token+1], val);
#endif
	return (token);
}

/*
 * Leave NEWLINE as the next character.
 */

void
kobj_find_eol(struct _buf *file)
{
	int ch;

	while ((ch = kobj_getc(file)) != -1) {
		if (isnewline(ch)) {
			(void) kobj_ungetc(file);
			break;
		}
	}
}

/*
 * The ascii system file is read and processed.
 *
 * The syntax of commands is as follows:
 *
 * '*' in column 1 is a comment line.
 * <command> : <value>
 *
 * command is EXCLUDE, INCLUDE, FORCELOAD, ROOTDEV, ROOTFS,
 *	SWAPDEV, SWAPFS, MODDIR, SET
 *
 * value is an ascii string meaningful for the command.
 */

/*
 * Table of commands
 */
static struct modcmd modcmd[] = {
	{ "EXCLUDE",	MOD_EXCLUDE	},
	{ "exclude",	MOD_EXCLUDE	},
	{ "INCLUDE",	MOD_INCLUDE	},
	{ "include",	MOD_INCLUDE	},
	{ "FORCELOAD",	MOD_FORCELOAD	},
	{ "forceload",	MOD_FORCELOAD	},
	{ "ROOTDEV",	MOD_ROOTDEV	},
	{ "rootdev",	MOD_ROOTDEV	},
	{ "ROOTFS",	MOD_ROOTFS	},
	{ "rootfs",	MOD_ROOTFS	},
	{ "SWAPDEV",	MOD_SWAPDEV	},
	{ "swapdev",	MOD_SWAPDEV	},
	{ "SWAPFS",	MOD_SWAPFS	},
	{ "swapfs",	MOD_SWAPFS	},
	{ "MODDIR",	MOD_MODDIR	},
	{ "moddir",	MOD_MODDIR	},
	{ "SET",	MOD_SET		},
	{ "set",	MOD_SET		},
	{ "SET32",	MOD_SET32	},
	{ "set32",	MOD_SET32	},
	{ "SET64",	MOD_SET64	},
	{ "set64",	MOD_SET64	},
	{ NULL,		MOD_UNKNOWN	}
};


static char bad_op[] = "illegal operator '%s' used on a string";
static char colon_err[] = "A colon (:) must follow the '%s' command";
static char tok_err[] = "Unexpected token '%s'";
static char extra_err[] = "extraneous input ignored starting at '%s'";
static char oversize_err[] = "value too long";

static struct sysparam *
do_sysfile_cmd(struct _buf *file, const char *cmd)
{
	struct sysparam *sysp;
	struct modcmd *mcp;
	token_t token, op;
	char *cp;
	int ch;
	char tok1[MOD_MAXPATH + 1]; /* used to read the path set by 'moddir' */
	char tok2[64];

	for (mcp = modcmd; mcp->mc_cmdname != NULL; mcp++) {
		if (strcmp(mcp->mc_cmdname, cmd) == 0)
			break;
	}
	sysp = vmem_alloc(mod_sysfile_arena, sizeof (struct sysparam),
	    VM_SLEEP);
	bzero(sysp, sizeof (struct sysparam));
	sysp->sys_op = SETOP_NONE; /* set op to noop initially */

	switch (sysp->sys_type = mcp->mc_type) {
	case MOD_INCLUDE:
	case MOD_EXCLUDE:
	case MOD_FORCELOAD:
		/*
		 * Are followed by colon.
		 */
	case MOD_ROOTFS:
	case MOD_SWAPFS:
		if ((token = kobj_lex(file, tok1, sizeof (tok1))) == COLON) {
			token = kobj_lex(file, tok1, sizeof (tok1));
		} else {
			kobj_file_err(CE_WARN, file, colon_err, cmd);
		}
		if (token != NAME) {
			kobj_file_err(CE_WARN, file, "value expected");
			goto bad;
		}

		cp = tok1 + strlen(tok1);
		while ((ch = kobj_getc(file)) != -1 && !iswhite(ch) &&
		    !isnewline(ch)) {
			if (cp - tok1 >= sizeof (tok1) - 1) {
				kobj_file_err(CE_WARN, file, oversize_err);
				goto bad;
			}
			*cp++ = (char)ch;
		}
		*cp = '\0';

		if (ch != -1)
			(void) kobj_ungetc(file);
		if (sysp->sys_type == MOD_INCLUDE)
			return (NULL);
		sysp->sys_ptr = vmem_alloc(mod_sysfile_arena, strlen(tok1) + 1,
		    VM_SLEEP);
		(void) strcpy(sysp->sys_ptr, tok1);
		break;
	case MOD_SET:
	case MOD_SET64:
	case MOD_SET32:
	{
		char *var;
		token_t tok3;

		if (kobj_lex(file, tok1, sizeof (tok1)) != NAME) {
			kobj_file_err(CE_WARN, file, "value expected");
			goto bad;
		}

		/*
		 * If the next token is a colon (:),
		 * we have the <modname>:<variable> construct.
		 */
		if ((token = kobj_lex(file, tok2, sizeof (tok2))) == COLON) {
			if ((token = kobj_lex(file, tok2,
			    sizeof (tok2))) == NAME) {
				var = tok2;
				/*
				 * Save the module name.
				 */
				sysp->sys_modnam = vmem_alloc(mod_sysfile_arena,
				    strlen(tok1) + 1, VM_SLEEP);
				(void) strcpy(sysp->sys_modnam, tok1);
				op = kobj_lex(file, tok1, sizeof (tok1));
			} else {
				kobj_file_err(CE_WARN, file, "value expected");
				goto bad;
			}
		} else {
			/* otherwise, it was the op */
			var = tok1;
			op = token;
		}
		/*
		 * kernel param - place variable name in sys_ptr.
		 */
		sysp->sys_ptr = vmem_alloc(mod_sysfile_arena, strlen(var) + 1,
		    VM_SLEEP);
		(void) strcpy(sysp->sys_ptr, var);
		/* set operation */
		switch (op) {
		case EQUALS:
			/* simple assignment */
			sysp->sys_op = SETOP_ASSIGN;
			break;
		case AMPERSAND:
			/* bitwise AND */
			sysp->sys_op = SETOP_AND;
			break;
		case BIT_OR:
			/* bitwise OR */
			sysp->sys_op = SETOP_OR;
			break;
		default:
			/* unsupported operation */
			kobj_file_err(CE_WARN, file,
			    "unsupported operator %s", tok2);
			goto bad;
		}

		switch ((tok3 = kobj_lex(file, tok1, sizeof (tok1)))) {
		case STRING:
			/* string variable */
			if (sysp->sys_op != SETOP_ASSIGN) {
				kobj_file_err(CE_WARN, file, bad_op, tok1);
				goto bad;
			}
			if (kobj_get_string(&sysp->sys_info, tok1) == 0) {
				kobj_file_err(CE_WARN, file, "string garbled");
				goto bad;
			}
			/*
			 * Set SYSPARAM_STR_TOKEN in sys_flags to notify
			 * sysparam_print_warning() that this is a string
			 * token.
			 */
			sysp->sys_flags |= SYSPARAM_STR_TOKEN;
			break;
		case HEXVAL:
		case DECVAL:
			if (kobj_getvalue(tok1, &sysp->sys_info) == -1) {
				kobj_file_err(CE_WARN, file,
				    "invalid number '%s'", tok1);
				goto bad;
			}

			/*
			 * Set the appropriate flag (hexadecimal or decimal)
			 * in sys_flags for sysparam_print_warning() to be
			 * able to print the number with the correct format.
			 */
			if (tok3 == HEXVAL) {
				sysp->sys_flags |= SYSPARAM_HEX_TOKEN;
			} else {
				sysp->sys_flags |= SYSPARAM_DEC_TOKEN;
			}
			break;
		default:
			kobj_file_err(CE_WARN, file, "bad rvalue '%s'", tok1);
			goto bad;
		} /* end switch */

		/*
		 * Now that we've parsed it to check the syntax, consider
		 * discarding it (because it -doesn't- apply to this flavor
		 * of the kernel)
		 */
#ifdef _LP64
		if (sysp->sys_type == MOD_SET32)
			return (NULL);
#else
		if (sysp->sys_type == MOD_SET64)
			return (NULL);
#endif
		sysp->sys_type = MOD_SET;
		break;
	}
	case MOD_MODDIR:
		if ((token = kobj_lex(file, tok1, sizeof (tok1))) != COLON) {
			kobj_file_err(CE_WARN, file, colon_err, cmd);
			goto bad;
		}

		cp = tok1;
		while ((token = kobj_lex(file, cp,
		    sizeof (tok1) - (cp - tok1))) != NEWLINE && token != EOF) {
			if (token == -1) {
				kobj_file_err(CE_WARN, file, oversize_err);
				goto bad;
			}
			cp += strlen(cp);
			while ((ch = kobj_getc(file)) != -1 && !iswhite(ch) &&
			    !isnewline(ch) && ch != ':') {
				if (cp - tok1 >= sizeof (tok1) - 1) {
					kobj_file_err(CE_WARN, file,
					    oversize_err);
					goto bad;
				}
				*cp++ = (char)ch;
			}
			*cp++ = ' ';
			if (isnewline(ch)) {
				cp--;
				(void) kobj_ungetc(file);
			}
		}
		(void) kobj_ungetc(file);
		*cp  = '\0';
		sysp->sys_ptr = vmem_alloc(mod_sysfile_arena, strlen(tok1) + 1,
		    VM_SLEEP);
		(void) strcpy(sysp->sys_ptr, tok1);
		break;

	case MOD_SWAPDEV:
	case MOD_ROOTDEV:
		if ((token = kobj_lex(file, tok1, sizeof (tok1))) != COLON) {
			kobj_file_err(CE_WARN, file, colon_err, cmd);
			goto bad;
		}
		while ((ch = kobj_getc(file)) == ' ' || ch == '\t')
			;
		cp = tok1;
		while (!iswhite(ch) && !isnewline(ch) && ch != -1) {
			if (cp - tok1 >= sizeof (tok1) - 1) {
				kobj_file_err(CE_WARN, file, oversize_err);
				goto bad;
			}

			*cp++ = (char)ch;
			ch = kobj_getc(file);
		}
		if (ch != -1)
			(void) kobj_ungetc(file);
		*cp = '\0';

		sysp->sys_ptr = vmem_alloc(mod_sysfile_arena, strlen(tok1) + 1,
		    VM_SLEEP);
		(void) strcpy(sysp->sys_ptr, tok1);
		break;

	case MOD_UNKNOWN:
	default:
		kobj_file_err(CE_WARN, file, "unknown command '%s'", cmd);
		goto bad;
	}

	return (sysp);

bad:
	kobj_find_eol(file);
	return (NULL);
}

void
mod_read_system_file(int ask)
{
	register struct sysparam *sp;
	register struct _buf *file;
	register token_t token, last_tok;
	char tokval[MAXLINESIZE];

	mod_sysfile_arena = vmem_create("mod_sysfile", NULL, 0, 8,
	    segkmem_alloc, segkmem_free, heap_arena, 0, VM_SLEEP);

	if (ask)
		mod_askparams();

	if (systemfile != NULL) {

		if ((file = kobj_open_file(systemfile)) ==
		    (struct _buf *)-1) {
			cmn_err(CE_WARN, "cannot open system file: %s",
			    systemfile);
		} else {
			sysparam_tl = (struct sysparam *)&sysparam_hd;

			last_tok = NEWLINE;
			while ((token = kobj_lex(file, tokval,
			    sizeof (tokval))) != EOF) {
				switch (token) {
				case STAR:
				case POUND:
					/*
					 * Skip comments.
					 */
					kobj_find_eol(file);
					break;
				case NEWLINE:
					kobj_newline(file);
					last_tok = NEWLINE;
					break;
				case NAME:
					if (last_tok != NEWLINE) {
						kobj_file_err(CE_WARN, file,
						    extra_err, tokval);
						kobj_find_eol(file);
					} else if ((sp = do_sysfile_cmd(file,
					    tokval)) != NULL) {
						sp->sys_next = NULL;
						sysparam_tl->sys_next = sp;
						sysparam_tl = sp;
					}
					last_tok = NAME;
					break;
				default:
					kobj_file_err(CE_WARN,
					    file, tok_err, tokval);
					kobj_find_eol(file);
					break;
				}
			}
			kobj_close_file(file);
		}
	}

	/*
	 * Sanity check of /etc/system.
	 */
	check_system_file();

	param_preset();
	(void) mod_sysctl(SYS_SET_KVAR, NULL);
	param_check();

	if (ask == 0)
		setparams();
}

/*
 * Search for a specific module variable assignment in /etc/system.  If
 * successful, 1 is returned and the value is stored in '*value'.
 * Otherwise 0 is returned and '*value' isn't modified.  If 'module' is
 * NULL we look for global definitions.
 *
 * This is useful if the value of an assignment is needed before a
 * module is loaded (e.g. to obtain a default privileged rctl limit).
 */
int
mod_sysvar(const char *module, const char *name, u_longlong_t *value)
{
	struct sysparam	*sysp;
	int cnt = 0; /* dummy */

	ASSERT(name != NULL);
	ASSERT(value != NULL);
	for (sysp = sysparam_hd; sysp != NULL; sysp = sysp->sys_next) {

		if ((sysp->sys_type == MOD_SET) &&
		    (((module == NULL) && (sysp->sys_modnam == NULL)) ||
		    ((module != NULL) && (sysp->sys_modnam != NULL) &&
		    (strcmp(module, sysp->sys_modnam) == 0)))) {

			ASSERT(sysp->sys_ptr != NULL);

			if (strcmp(name, sysp->sys_ptr) == 0) {
				sysparam_count_entry(sysp, &cnt, value);
				if ((sysp->sys_flags & SYSPARAM_TERM) != 0)
					return (1);
				continue;
			}
		}
	}
	ASSERT(cnt == 0);
	return (0);
}

/*
 * This function scans sysparam records, which are created from the
 * contents of /etc/system, for entries which are logical duplicates,
 * and prints warning messages as appropriate.  When multiple "set"
 * commands are encountered, the pileup of values with "&", "|"
 * and "=" operators results in the final value.
 */
static void
check_system_file(void)
{
	struct sysparam	*sysp;

	for (sysp = sysparam_hd; sysp != NULL; sysp = sysp->sys_next) {
		struct sysparam *entry, *final;
		u_longlong_t value = 0;
		int cnt = 1;
		/*
		 * If the entry is already checked, skip it.
		 */
		if ((sysp->sys_flags & SYSPARAM_DUP) != 0)
			continue;
		/*
		 * Check if there is a duplicate entry by doing a linear
		 * search.
		 */
		final = sysp;
		for (entry = sysp->sys_next; entry != NULL;
		    entry = entry->sys_next) {
			/*
			 * Check the entry. if it's different, skip this.
			 */
			if (sysparam_compare_entry(sysp, entry) != 0)
				continue;
			/*
			 * Count the entry and put the mark.
			 */
			sysparam_count_entry(entry, &cnt, &value);
			entry->sys_flags |= SYSPARAM_DUP;
			final = entry;
		}
		final->sys_flags |= SYSPARAM_TERM;
		/*
		 * Print the warning if it's duplicated.
		 */
		if (cnt >= 2)
			sysparam_print_warning(final, value);
	}
}

/*
 * Compare the sysparam records.
 * Return 0 if they are the same, return 1 if not.
 */
static int
sysparam_compare_entry(struct sysparam *sysp, struct sysparam *entry)
{
	ASSERT(sysp->sys_ptr != NULL && entry->sys_ptr != NULL);

	/*
	 * If the command is rootdev, rootfs, swapdev, swapfs or moddir,
	 * the record with the same type is treated as a duplicate record.
	 * In other cases, the record is treated as a duplicate record when
	 * its type, its module name (if it exists), and its variable name
	 * are the same.
	 */
	switch (sysp->sys_type) {
	case MOD_ROOTDEV:
	case MOD_ROOTFS:
	case MOD_SWAPDEV:
	case MOD_SWAPFS:
	case MOD_MODDIR:
		return (sysp->sys_type == entry->sys_type ? 0 : 1);
	default: /* In other cases, just go through it. */
		break;
	}

	if (sysp->sys_type != entry->sys_type)
		return (1);

	if (sysp->sys_modnam != NULL && entry->sys_modnam == NULL)
		return (1);

	if (sysp->sys_modnam == NULL && entry->sys_modnam != NULL)
		return (1);

	if (sysp->sys_modnam != NULL && entry->sys_modnam != NULL &&
	    strcmp(sysp->sys_modnam, entry->sys_modnam) != 0)
		return (1);

	return (strcmp(sysp->sys_ptr, entry->sys_ptr));
}

/*
 * Translate a sysparam type value to a string.
 */
static char *
sysparam_type_to_str(int type)
{
	struct modcmd *mcp;

	for (mcp = modcmd; mcp->mc_cmdname != NULL; mcp++) {
		if (mcp->mc_type == type)
			break;
	}
	ASSERT(mcp->mc_type == type);

	if (type != MOD_UNKNOWN)
		return ((++mcp)->mc_cmdname); /* lower case */
	else
		return ("");	/* MOD_UNKNOWN */
}

/*
 * Check the entry and accumulate the number of entries.
 */
static void
sysparam_count_entry(struct sysparam *sysp, int *cnt, u_longlong_t *value)
{
	u_longlong_t ul = sysp->sys_info;

	switch (sysp->sys_op) {
	case SETOP_ASSIGN:
		*value = ul;
		(*cnt)++;
		return;
	case SETOP_AND:
		*value &= ul;
		return;
	case SETOP_OR:
		*value |= ul;
		return;
	default: /* Not MOD_SET */
		(*cnt)++;
		return;
	}
}

/*
 * Print out the warning if multiple entries are found in the system file.
 */
static void
sysparam_print_warning(struct sysparam *sysp, u_longlong_t value)
{
	char *modnam = sysp->sys_modnam;
	char *varnam = sysp->sys_ptr;
	int type = sysp->sys_type;
	char *typenam = sysparam_type_to_str(type);
	boolean_t str_token = ((sysp->sys_flags & SYSPARAM_STR_TOKEN) != 0);
	boolean_t hex_number = ((sysp->sys_flags & SYSPARAM_HEX_TOKEN) != 0);
#define	warn_format1 " is set more than once in /%s. "
#define	warn_format2 " applied as the current setting.\n"

	ASSERT(varnam != NULL);

	if (type == MOD_SET) {
		/*
		 * If a string token is set, print out the string
		 * instead of its pointer value. In other cases,
		 * print out the value with the appropriate format
		 * for a hexadecimal number or a decimal number.
		 */
		if (modnam == NULL) {
			if (str_token == B_TRUE) {
				cmn_err(CE_WARN, "%s" warn_format1
				    "\"%s %s = %s\"" warn_format2,
				    varnam, systemfile, typenam,
				    varnam, (char *)(uintptr_t)value);
			} else if (hex_number == B_TRUE) {
				cmn_err(CE_WARN, "%s" warn_format1
				    "\"%s %s = 0x%llx\"" warn_format2,
				    varnam, systemfile, typenam,
				    varnam, value);
			} else {
				cmn_err(CE_WARN, "%s" warn_format1
				    "\"%s %s = %lld\"" warn_format2,
				    varnam, systemfile, typenam,
				    varnam, value);
			}
		} else {
			if (str_token == B_TRUE) {
				cmn_err(CE_WARN, "%s:%s" warn_format1
				    "\"%s %s:%s = %s\"" warn_format2,
				    modnam, varnam, systemfile,
				    typenam, modnam, varnam,
				    (char *)(uintptr_t)value);
			} else if (hex_number == B_TRUE) {
				cmn_err(CE_WARN, "%s:%s" warn_format1
				    "\"%s %s:%s = 0x%llx\"" warn_format2,
				    modnam, varnam, systemfile,
				    typenam, modnam, varnam, value);
			} else {
				cmn_err(CE_WARN, "%s:%s" warn_format1
				    "\"%s %s:%s = %lld\"" warn_format2,
				    modnam, varnam, systemfile,
				    typenam, modnam, varnam, value);
			}
		}
	} else {
		/*
		 * If the type is MOD_ROOTDEV, MOD_ROOTFS, MOD_SWAPDEV,
		 * MOD_SWAPFS or MOD_MODDIR, the entry is treated as
		 * a duplicate one if it has the same type regardless
		 * of its variable name.
		 */
		switch (type) {
		case MOD_ROOTDEV:
		case MOD_ROOTFS:
		case MOD_SWAPDEV:
		case MOD_SWAPFS:
		case MOD_MODDIR:
			cmn_err(CE_WARN, "\"%s\" appears more than once "
			    "in /%s.", typenam, systemfile);
			break;
		default:
			cmn_err(CE_NOTE, "\"%s: %s\" appears more than once "
			    "in /%s.", typenam, varnam, systemfile);
			break;
		}
	}
}

/*
 * Process the system file commands.
 */
int
mod_sysctl(int fcn, void *p)
{
	static char wmesg[] = "forceload of %s failed";
	struct sysparam *sysp;
	char *name;
	struct modctl *modp;

	if (sysparam_hd == NULL)
		return (0);

	for (sysp = sysparam_hd; sysp != NULL; sysp = sysp->sys_next) {

		switch (fcn) {

		case SYS_FORCELOAD:
		if (sysp->sys_type == MOD_FORCELOAD) {
			name = sysp->sys_ptr;
			if (modload(NULL, name) == -1)
				cmn_err(CE_WARN, wmesg, name);
			/*
			 * The following works because it
			 * runs before autounloading is started!!
			 */
			modp = mod_find_by_filename(NULL, name);
			if (modp != NULL)
				modp->mod_loadflags |= MOD_NOAUTOUNLOAD;
			/*
			 * For drivers, attempt to install it.
			 */
			if (strncmp(sysp->sys_ptr, "drv", 3) == 0) {
				(void) ddi_install_driver(name + 4);
			}
		}
		break;

		case SYS_SET_KVAR:
		case SYS_SET_MVAR:
			if (sysp->sys_type == MOD_SET)
				sys_set_var(fcn, sysp, p);
			break;

		case SYS_CHECK_EXCLUDE:
			if (sysp->sys_type == MOD_EXCLUDE) {
				if (p == NULL || sysp->sys_ptr == NULL)
					return (0);
				if (strcmp((char *)p, sysp->sys_ptr) == 0)
					return (1);
			}
		}
	}

	return (0);
}

/*
 * Process the system file commands, by type.
 */
int
mod_sysctl_type(int type, int (*func)(struct sysparam *, void *), void *p)
{
	struct sysparam *sysp;
	int	err;

	for (sysp = sysparam_hd; sysp != NULL; sysp = sysp->sys_next)
		if (sysp->sys_type == type)
			if (err = (*(func))(sysp, p))
				return (err);
	return (0);
}


static char seterr[] = "Symbol %s has size of 0 in symbol table. %s";
static char assumption[] = "Assuming it is an 'int'";
static char defmsg[] = "Trying to set a variable that is of size %d";

static void set_int8_var(uintptr_t, struct sysparam *);
static void set_int16_var(uintptr_t, struct sysparam *);
static void set_int32_var(uintptr_t, struct sysparam *);
static void set_int64_var(uintptr_t, struct sysparam *);

static void
sys_set_var(int fcn, struct sysparam *sysp, void *p)
{
	uintptr_t symaddr;
	int size;

	if (fcn == SYS_SET_KVAR && sysp->sys_modnam == NULL) {
		symaddr = kobj_getelfsym(sysp->sys_ptr, NULL, &size);
	} else if (fcn == SYS_SET_MVAR) {
		if (sysp->sys_modnam == (char *)NULL ||
		    strcmp(((struct modctl *)p)->mod_modname,
		    sysp->sys_modnam) != 0)
			return;
		symaddr = kobj_getelfsym(sysp->sys_ptr,
		    ((struct modctl *)p)->mod_mp, &size);
	} else
		return;

	if (symaddr != NULL) {
		switch (size) {
		case 1:
			set_int8_var(symaddr, sysp);
			break;
		case 2:
			set_int16_var(symaddr, sysp);
			break;
		case 0:
			cmn_err(CE_WARN, seterr, sysp->sys_ptr, assumption);
			/*FALLTHROUGH*/
		case 4:
			set_int32_var(symaddr, sysp);
			break;
		case 8:
			set_int64_var(symaddr, sysp);
			break;
		default:
			cmn_err(CE_WARN, defmsg, size);
			break;
		}
	} else {
		printf("sorry, variable '%s' is not defined in the '%s' ",
		    sysp->sys_ptr,
		    sysp->sys_modnam ? sysp->sys_modnam : "kernel");
		if (sysp->sys_modnam)
			printf("module");
		printf("\n");
	}
}

static void
set_int8_var(uintptr_t symaddr, struct sysparam *sysp)
{
	uint8_t uc = (uint8_t)sysp->sys_info;

	if (moddebug & MODDEBUG_LOADMSG)
		printf("OP: %x: param '%s' was '0x%" PRIx8
		    "' in module: '%s'.\n", sysp->sys_op, sysp->sys_ptr,
		    *(uint8_t *)symaddr, sysp->sys_modnam);

	switch (sysp->sys_op) {
	case SETOP_ASSIGN:
		*(uint8_t *)symaddr = uc;
		break;
	case SETOP_AND:
		*(uint8_t *)symaddr &= uc;
		break;
	case SETOP_OR:
		*(uint8_t *)symaddr |= uc;
		break;
	}

	if (moddebug & MODDEBUG_LOADMSG)
		printf("now it is set to '0x%" PRIx8 "'.\n",
		    *(uint8_t *)symaddr);
}

static void
set_int16_var(uintptr_t symaddr, struct sysparam *sysp)
{
	uint16_t us = (uint16_t)sysp->sys_info;

	if (moddebug & MODDEBUG_LOADMSG)
		printf("OP: %x: param '%s' was '0x%" PRIx16
		    "' in module: '%s'.\n", sysp->sys_op, sysp->sys_ptr,
		    *(uint16_t *)symaddr, sysp->sys_modnam);

	switch (sysp->sys_op) {
	case SETOP_ASSIGN:
		*(uint16_t *)symaddr = us;
		break;
	case SETOP_AND:
		*(uint16_t *)symaddr &= us;
		break;
	case SETOP_OR:
		*(uint16_t *)symaddr |= us;
		break;
	}

	if (moddebug & MODDEBUG_LOADMSG)
		printf("now it is set to '0x%" PRIx16 "'.\n",
		    *(uint16_t *)symaddr);
}

static void
set_int32_var(uintptr_t symaddr, struct sysparam *sysp)
{
	uint32_t ui = (uint32_t)sysp->sys_info;

	if (moddebug & MODDEBUG_LOADMSG)
		printf("OP: %x: param '%s' was '0x%" PRIx32
		    "' in module: '%s'.\n", sysp->sys_op, sysp->sys_ptr,
		    *(uint32_t *)symaddr, sysp->sys_modnam);

	switch (sysp->sys_op) {
	case SETOP_ASSIGN:
		*(uint32_t *)symaddr = ui;
		break;
	case SETOP_AND:
		*(uint32_t *)symaddr &= ui;
		break;
	case SETOP_OR:
		*(uint32_t *)symaddr |= ui;
		break;
	}

	if (moddebug & MODDEBUG_LOADMSG)
		printf("now it is set to '0x%" PRIx32 "'.\n",
		    *(uint32_t *)symaddr);
}

static void
set_int64_var(uintptr_t symaddr, struct sysparam *sysp)
{
	uint64_t ul = sysp->sys_info;

	if (moddebug & MODDEBUG_LOADMSG)
		printf("OP: %x: param '%s' was '0x%" PRIx64
		    "' in module: '%s'.\n", sysp->sys_op, sysp->sys_ptr,
		    *(uint64_t *)symaddr, sysp->sys_modnam);

	switch (sysp->sys_op) {
	case SETOP_ASSIGN:
		*(uint64_t *)symaddr = ul;
		break;
	case SETOP_AND:
		*(uint64_t *)symaddr &= ul;
		break;
	case SETOP_OR:
		*(uint64_t *)symaddr |= ul;
		break;
	}

	if (moddebug & MODDEBUG_LOADMSG)
		printf("now it is set to '0x%" PRIx64 "'.\n",
		    *(uint64_t *)symaddr);
}

/*
 * The next item on the line is a string value. Allocate memory for
 * it and copy the string. Return 1, and set arg ptr to newly allocated
 * and initialized buffer, or NULL if an error occurs.
 */
int
kobj_get_string(u_longlong_t *llptr, char *tchar)
{
	char *cp;
	char *start = (char *)0;
	int len = 0;

	len = strlen(tchar);
	start = tchar;
	/* copy string */
	cp = vmem_alloc(mod_sysfile_arena, len + 1, VM_SLEEP);
	bzero(cp, len + 1);
	*llptr = (u_longlong_t)(uintptr_t)cp;
	for (; len > 0; len--) {
		/* convert some common escape sequences */
		if (*start == '\\') {
			switch (*(start + 1)) {
			case 't':
				/* tab */
				*cp++ = '\t';
				len--;
				start += 2;
				break;
			case 'n':
				/* new line */
				*cp++ = '\n';
				len--;
				start += 2;
				break;
			case 'b':
				/* back space */
				*cp++ = '\b';
				len--;
				start += 2;
				break;
			default:
				/* simply copy it */
				*cp++ = *start++;
				break;
			}
		} else
			*cp++ = *start++;
	}
	*cp = '\0';
	return (1);
}


/*
 * this function frees the memory allocated by kobj_get_string
 */
void
kobj_free_string(void *ptr, int len)
{
	vmem_free(mod_sysfile_arena, ptr, len);
}


/*
 * get a decimal octal or hex number. Handle '~' for one's complement.
 */
int
kobj_getvalue(const char *token, u_longlong_t *valuep)
{
	int radix;
	u_longlong_t retval = 0;
	int onescompl = 0;
	int negate = 0;
	char c;

	if (*token == '~') {
		onescompl++; /* perform one's complement on result */
		token++;
	} else if (*token == '-') {
		negate++;
		token++;
	}
	if (*token == '0') {
		token++;
		c = *token;

		if (c == '\0') {
			*valuep = 0;	/* value is 0 */
			return (0);
		}

		if (c == 'x' || c == 'X') {
			radix = 16;
			token++;
		} else
			radix = 8;
	} else
		radix = 10;

	while ((c = *token++)) {
		switch (radix) {
		case 8:
			if (c >= '0' && c <= '7')
				c -= '0';
			else
				return (-1);	/* invalid number */
			retval = (retval << 3) + c;
			break;
		case 10:
			if (c >= '0' && c <= '9')
				c -= '0';
			else
				return (-1);	/* invalid number */
			retval = (retval * 10) + c;
			break;
		case 16:
			if (c >= 'a' && c <= 'f')
				c = c - 'a' + 10;
			else if (c >= 'A' && c <= 'F')
				c = c - 'A' + 10;
			else if (c >= '0' && c <= '9')
				c -= '0';
			else
				return (-1);	/* invalid number */
			retval = (retval << 4) + c;
			break;
		}
	}
	if (onescompl)
		retval = ~retval;
	if (negate)
		retval = -retval;
	*valuep = retval;
	return (0);
}

/*
 * Path to the root device and root filesystem type from
 * property information derived from the boot subsystem
 */
void
setbootpath(char *path)
{
	rootfs.bo_flags |= BO_VALID;
	(void) copystr(path, rootfs.bo_name, BO_MAXOBJNAME, NULL);
	BMDPRINTF(("rootfs bootpath: %s\n", rootfs.bo_name));
}

void
setbootfstype(char *fstype)
{
	(void) copystr(fstype, rootfs.bo_fstype, BO_MAXFSNAME, NULL);
	BMDPRINTF(("rootfs fstype: %s\n", rootfs.bo_fstype));
}

/*
 * set parameters that can be set early during initialization.
 */
static void
setparams()
{
	struct sysparam *sysp;
	struct bootobj *bootobjp;

	for (sysp = sysparam_hd; sysp != NULL; sysp = sysp->sys_next) {

		if (sysp->sys_type == MOD_MODDIR) {
			default_path = sysp->sys_ptr;
			continue;
		}

		if (sysp->sys_type == MOD_SWAPDEV ||
		    sysp->sys_type == MOD_SWAPFS)
			bootobjp = &swapfile;
		else if (sysp->sys_type == MOD_ROOTFS)
			bootobjp = &rootfs;

		switch (sysp->sys_type) {
		case MOD_ROOTDEV:
			root_is_svm = 1;
			(void) copystr(sysp->sys_ptr, svm_bootpath,
			    BO_MAXOBJNAME, NULL);
			break;
		case MOD_SWAPDEV:
			bootobjp->bo_flags |= BO_VALID;
			(void) copystr(sysp->sys_ptr, bootobjp->bo_name,
			    BO_MAXOBJNAME, NULL);
			break;
		case MOD_ROOTFS:
		case MOD_SWAPFS:
			bootobjp->bo_flags |= BO_VALID;
			(void) copystr(sysp->sys_ptr, bootobjp->bo_fstype,
			    BO_MAXOBJNAME, NULL);
			break;
		default:
			break;
		}
	}
}

/*
 * clean up after an error.
 */
static void
hwc_free(struct hwc_spec *hwcp)
{
	char *name;

	if ((name = hwcp->hwc_parent_name) != NULL)
		kmem_free(name, strlen(name) + 1);
	if ((name = hwcp->hwc_class_name) != NULL)
		kmem_free(name, strlen(name) + 1);
	if ((name = hwcp->hwc_devi_name) != NULL)
		kmem_free(name, strlen(name) + 1);
	i_ddi_prop_list_delete(hwcp->hwc_devi_sys_prop_ptr);
	kmem_free(hwcp, sizeof (struct hwc_spec));
}

/*
 * Free a list of specs
 */
void
hwc_free_spec_list(struct hwc_spec *list)
{
	while (list) {
		struct hwc_spec *tmp = list;
		list = tmp->hwc_next;
		hwc_free(tmp);
	}
}

struct val_list {
	struct val_list *val_next;
	enum {
		VAL_STRING,
		VAL_INTEGER
	} val_type;
	int		val_size;
	union {
		char *string;
		int integer;
	} val;
};

static struct val_list *
add_val(struct val_list **val_listp, struct val_list *tail,
    int val_type, caddr_t val)
{
	struct val_list *new_val;
#ifdef DEBUG
	struct val_list *listp = *val_listp;
#endif

	new_val = kmem_alloc(sizeof (struct val_list), KM_SLEEP);
	new_val->val_next = NULL;
	if ((new_val->val_type = val_type) == VAL_STRING) {
		new_val->val_size = strlen((char *)val) + 1;
		new_val->val.string = kmem_alloc(new_val->val_size, KM_SLEEP);
		(void) strcpy(new_val->val.string, (char *)val);
	} else {
		new_val->val_size = sizeof (int);
		new_val->val.integer = (int)(uintptr_t)val;
	}

	ASSERT((listp == NULL && tail == NULL) ||
	    (listp != NULL && tail != NULL));

	if (tail != NULL) {
		ASSERT(tail->val_next == NULL);
		tail->val_next = new_val;
	} else {
		*val_listp = new_val;
	}

	return (new_val);
}

static void
free_val_list(struct val_list *head)
{
	struct val_list *tval_list;

	for (/* CSTYLED */; head != NULL; /* CSTYLED */) {
		tval_list = head;
		head = head->val_next;
		if (tval_list->val_type == VAL_STRING)
			kmem_free(tval_list->val.string, tval_list->val_size);
		kmem_free(tval_list, sizeof (struct val_list));
	}
}

/*
 * make sure there are no reserved IEEE 1275 characters (except
 * for uppercase characters).
 */
static int
valid_prop_name(char *name)
{
	int i;
	int len = strlen(name);

	for (i = 0; i < len; i++) {
		if (name[i] < 0x21 ||
		    name[i] == '/' ||
		    name[i] == '\\' ||
		    name[i] == ':' ||
		    name[i] == '[' ||
		    name[i] == ']' ||
		    name[i] == '@')
			return (0);
	}
	return (1);
}

static void
make_prop(struct _buf *file, dev_info_t *devi, char *name, struct val_list *val)
{
	int propcnt = 0, val_type;
	struct val_list *vl, *tvl;
	caddr_t valbuf = NULL;
	char **valsp;
	int *valip;

	if (name == NULL)
		return;

#ifdef DEBUG
	parse_debug(NULL, "%s", name);
#endif
	if (!valid_prop_name(name)) {
		cmn_err(CE_WARN, "invalid property name '%s'", name);
		return;
	}
	if (val) {
		for (vl = val, val_type = vl->val_type; vl; vl = vl->val_next) {
			if (val_type != vl->val_type) {
				cmn_err(CE_WARN, "Mixed types in value list");
				return;
			}
			propcnt++;
		}

		vl = val;

		if (val_type == VAL_INTEGER) {
			valip = (int *)kmem_alloc(
			    (propcnt * sizeof (int)), KM_SLEEP);
			valbuf = (caddr_t)valip;
			while (vl) {
				tvl = vl;
				vl = vl->val_next;
#ifdef DEBUG
				parse_debug(NULL, " %x",  tvl->val.integer);
#endif
				*valip = tvl->val.integer;
				valip++;
			}
			/* restore valip */
			valip = (int *)valbuf;

			/* create the property */
			if (e_ddi_prop_update_int_array(DDI_DEV_T_NONE, devi,
			    name, valip, propcnt) != DDI_PROP_SUCCESS) {
				kobj_file_err(CE_WARN, file,
				    "cannot create property %s", name);
			}
			/* cleanup */
			kmem_free(valip, (propcnt * sizeof (int)));
		} else if (val_type == VAL_STRING) {
			valsp = (char **)kmem_alloc(
			    ((propcnt + 1) * sizeof (char *)), KM_SLEEP);
			valbuf = (caddr_t)valsp;
			while (vl) {
				tvl = vl;
				vl = vl->val_next;
#ifdef DEBUG
				parse_debug(NULL, " %s", tvl->val.string);
#endif
				*valsp = tvl->val.string;
				valsp++;
			}
			/* terminate array with NULL */
			*valsp = NULL;

			/* restore valsp */
			valsp = (char **)valbuf;

			/* create the property */
			if (e_ddi_prop_update_string_array(DDI_DEV_T_NONE,
			    devi, name, valsp, propcnt)
			    != DDI_PROP_SUCCESS) {
				kobj_file_err(CE_WARN, file,
				    "cannot create property %s", name);
			}
			/* Clean up */
			kmem_free(valsp, ((propcnt + 1) * sizeof (char *)));
		} else {
			cmn_err(CE_WARN, "Invalid property type");
			return;
		}
	} else {
		/*
		 * No value was passed in with property so we will assume
		 * it is a "boolean" property and create an integer
		 * property with 0 value.
		 */
#ifdef DEBUG
		parse_debug(NULL, "\n");
#endif
		if (e_ddi_prop_update_int(DDI_DEV_T_NONE, devi, name, 0)
		    != DDI_PROP_SUCCESS) {
			kobj_file_err(CE_WARN, file,
			    "cannot create property %s", name);
		}
	}
}

static char omit_err[] = "(the ';' may have been omitted on previous spec!)";
static char prnt_err[] = "'parent' property already specified";
static char nm_err[] = "'name' property already specified";
static char class_err[] = "'class' property already specified";

typedef enum {
	hwc_begin, parent, drvname, drvclass, prop,
	parent_equals, name_equals, drvclass_equals,
	parent_equals_string, name_equals_string,
	drvclass_equals_string,
	prop_equals, prop_equals_string, prop_equals_integer,
	prop_equals_string_comma, prop_equals_integer_comma
} hwc_state_t;

static struct hwc_spec *
get_hwc_spec(struct _buf *file, char *tokbuf, size_t linesize)
{
	char *prop_name;
	token_t token;
	struct hwc_spec *hwcp;
	struct dev_info *devi;
	struct val_list *val_list, *tail;
	hwc_state_t state;
	u_longlong_t ival;

	hwcp = kmem_zalloc(sizeof (*hwcp), KM_SLEEP);
	devi = kmem_zalloc(sizeof (*devi), KM_SLEEP);

	state = hwc_begin;
	token = NAME;
	prop_name = NULL;
	val_list = NULL;
	tail = NULL;
	do {
#ifdef DEBUG
		parse_debug(NULL, "state 0x%x\n", state);
#endif
		switch (token) {
		case NAME:
			switch (state) {
			case prop:
			case prop_equals_string:
			case prop_equals_integer:
				make_prop(file, (dev_info_t *)devi,
				    prop_name, val_list);
				if (prop_name) {
					kmem_free(prop_name,
					    strlen(prop_name) + 1);
					prop_name = NULL;
				}
				if (val_list) {
					free_val_list(val_list);
					val_list = NULL;
				}
				tail = NULL;
				/*FALLTHROUGH*/
			case hwc_begin:
				if (strcmp(tokbuf, "PARENT") == 0 ||
				    strcmp(tokbuf, "parent") == 0) {
					state = parent;
				} else if (strcmp(tokbuf, "NAME") == 0 ||
				    strcmp(tokbuf, "name") == 0) {
					state = drvname;
				} else if (strcmp(tokbuf, "CLASS") == 0 ||
				    strcmp(tokbuf, "class") == 0) {
					state = drvclass;
					prop_name = kmem_alloc(strlen(tokbuf) +
					    1, KM_SLEEP);
					(void) strcpy(prop_name, tokbuf);
				} else {
					state = prop;
					prop_name = kmem_alloc(strlen(tokbuf) +
					    1, KM_SLEEP);
					(void) strcpy(prop_name, tokbuf);
				}
				break;
			default:
				kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			}
			break;
		case EQUALS:
			switch (state) {
			case drvname:
				state = name_equals;
				break;
			case parent:
				state = parent_equals;
				break;
			case drvclass:
				state = drvclass_equals;
				break;
			case prop:
				state = prop_equals;
				break;
			default:
				kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			}
			break;
		case STRING:
			switch (state) {
			case name_equals:
				if (ddi_get_name((dev_info_t *)devi)) {
					kobj_file_err(CE_WARN, file, "%s %s",
					    nm_err, omit_err);
					goto bad;
				}
				devi->devi_name = kmem_alloc(strlen(tokbuf) + 1,
				    KM_SLEEP);
				(void) strcpy(devi->devi_name, tokbuf);
				state = hwc_begin;
				break;
			case parent_equals:
				if (hwcp->hwc_parent_name) {
					kobj_file_err(CE_WARN, file, "%s %s",
					    prnt_err, omit_err);
					goto bad;
				}
				hwcp->hwc_parent_name = kmem_alloc(strlen
				    (tokbuf) + 1, KM_SLEEP);
				(void) strcpy(hwcp->hwc_parent_name, tokbuf);
				state = hwc_begin;
				break;
			case drvclass_equals:
				if (hwcp->hwc_class_name) {
					kobj_file_err(CE_WARN, file, class_err);
					goto bad;
				}
				hwcp->hwc_class_name = kmem_alloc(
				    strlen(tokbuf) + 1, KM_SLEEP);
				(void) strcpy(hwcp->hwc_class_name, tokbuf);
				/*FALLTHROUGH*/
			case prop_equals:
			case prop_equals_string_comma:
				tail = add_val(&val_list, tail, VAL_STRING,
				    tokbuf);
				state = prop_equals_string;
				break;
			default:
				kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			}
			break;
		case HEXVAL:
		case DECVAL:
			switch (state) {
			case prop_equals:
			case prop_equals_integer_comma:
				(void) kobj_getvalue(tokbuf, &ival);
				tail = add_val(&val_list, tail,
				    VAL_INTEGER, (caddr_t)(uintptr_t)ival);
				state = prop_equals_integer;
				break;
			default:
				kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			}
			break;
		case COMMA:
			switch (state) {
			case prop_equals_string:
				state = prop_equals_string_comma;
				break;
			case prop_equals_integer:
				state = prop_equals_integer_comma;
				break;
			default:
				kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			}
			break;
		case NEWLINE:
			kobj_newline(file);
			break;
		case POUND:
			/*
			 * Skip comments.
			 */
			kobj_find_eol(file);
			break;
		case EOF:
			kobj_file_err(CE_WARN, file, "Unexpected EOF");
			goto bad;
		default:
			kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			goto bad;
		}
	} while ((token = kobj_lex(file, tokbuf, linesize)) != SEMICOLON);

	switch (state) {
	case prop:
	case prop_equals_string:
	case prop_equals_integer:
		make_prop(file, (dev_info_t *)devi,
		    prop_name, val_list);
		break;

	case hwc_begin:
		break;
	default:
		kobj_file_err(CE_WARN, file, "Unexpected end of line");
		break;
	}

	/* copy 2 relevant members of devi to hwcp */
	hwcp->hwc_devi_sys_prop_ptr = devi->devi_sys_prop_ptr;
	hwcp->hwc_devi_name = devi->devi_name;

	if (prop_name)
		kmem_free(prop_name, strlen(prop_name) + 1);
	if (val_list)
		free_val_list(val_list);

	kmem_free(devi, sizeof (struct dev_info));

	return (hwcp);

bad:
	if (prop_name)
		kmem_free(prop_name, strlen(prop_name) + 1);
	if (val_list)
		free_val_list(val_list);

	hwc_free(hwcp);

	if (devi->devi_name)
		kmem_free(devi->devi_name, strlen(devi->devi_name) + 1);

	kmem_free(devi, sizeof (struct dev_info));

	return (NULL);
}

/*
 * This is the primary kernel interface to parse driver.conf files.
 *
 * Yet another bigstk thread handoff due to deep kernel stacks when booting
 * cache-only-clients.
 */
int
hwc_parse(char *fname, struct par_list **pl, ddi_prop_t **props)
{
	int ret;
	struct hwc_parse_mt *pltp = hwc_parse_mtalloc(fname, pl, props);

	if (curthread != &t0) {
		(void) thread_create(NULL, DEFAULTSTKSZ * 2,
		    hwc_parse_thread, pltp, 0, &p0, TS_RUN, maxclsyspri);
		sema_p(&pltp->sema);
	} else {
		pltp->rv = hwc_parse_now(fname, pl, props);
	}
	ret = pltp->rv;
	hwc_parse_mtfree(pltp);
	return (ret);
}

/*
 * Calls to hwc_parse() are handled off to this routine in a separate
 * thread.
 */
static void
hwc_parse_thread(struct hwc_parse_mt *pltp)
{
	kmutex_t	cpr_lk;
	callb_cpr_t	cpr_i;

	mutex_init(&cpr_lk, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cpr_i, &cpr_lk, callb_generic_cpr, "hwc_parse");

	/*
	 * load and parse the .conf file
	 * return the hwc_spec list (if any) to the creator of this thread
	 */
	pltp->rv = hwc_parse_now(pltp->name, pltp->pl, pltp->props);
	sema_v(&pltp->sema);
	mutex_enter(&cpr_lk);
	CALLB_CPR_EXIT(&cpr_i);
	mutex_destroy(&cpr_lk);
	thread_exit();
}

/*
 * allocate and initialize a hwc_parse thread control structure
 */
static struct hwc_parse_mt *
hwc_parse_mtalloc(char *name, struct par_list **pl, ddi_prop_t **props)
{
	struct hwc_parse_mt *pltp = kmem_zalloc(sizeof (*pltp), KM_SLEEP);

	ASSERT(name != NULL);

	pltp->name = kmem_alloc(strlen(name) + 1, KM_SLEEP);
	bcopy(name, pltp->name, strlen(name) + 1);
	pltp->pl = pl;
	pltp->props = props;

	sema_init(&pltp->sema, 0, NULL, SEMA_DEFAULT, NULL);
	return (pltp);
}

/*
 * free a hwc_parse thread control structure
 */
static void
hwc_parse_mtfree(struct hwc_parse_mt *pltp)
{
	sema_destroy(&pltp->sema);

	kmem_free(pltp->name, strlen(pltp->name) + 1);
	kmem_free(pltp, sizeof (*pltp));
}

/*
 * hwc_parse -- parse an hwconf file.  Ignore error lines and parse
 * as much as possible.
 */
static int
hwc_parse_now(char *fname, struct par_list **pl, ddi_prop_t **props)
{
	struct _buf *file;
	struct hwc_spec *hwcp;
	char *tokval;
	token_t token;

	/*
	 * Don't use kobj_open_path's use_moddir_suffix option, we only
	 * expect to find conf files in the base module directory, not
	 * an ISA-specific subdirectory.
	 */
	if ((file = kobj_open_path(fname, 1, 0)) == (struct _buf *)-1) {
		if (moddebug & MODDEBUG_ERRMSG)
			cmn_err(CE_WARN, "Cannot open %s", fname);
		return (-1);
	}

	/*
	 * Initialize variables
	 */
	tokval = kmem_alloc(MAX_HWC_LINESIZE, KM_SLEEP);

	while ((token = kobj_lex(file, tokval, MAX_HWC_LINESIZE)) != EOF) {
		switch (token) {
		case POUND:
			/*
			 * Skip comments.
			 */
			kobj_find_eol(file);
			break;
		case NAME:
			hwcp = get_hwc_spec(file, tokval, MAX_HWC_LINESIZE);
			if (hwcp == NULL)
				break;
			/*
			 * No devi_name indicates global property.
			 * Make sure parent and class not NULL.
			 */
			if (hwcp->hwc_devi_name == NULL) {
				if (hwcp->hwc_parent_name ||
				    hwcp->hwc_class_name) {
					kobj_file_err(CE_WARN, file,
					    "missing name attribute");
					hwc_free(hwcp);
					continue;
				}
				/* Add to global property list */
				add_props(hwcp, props);
				break;
			}

			/*
			 * This is a node spec, either parent or class
			 * must be specified.
			 */
			if ((hwcp->hwc_parent_name == NULL) &&
			    (hwcp->hwc_class_name == NULL)) {
				kobj_file_err(CE_WARN, file,
				    "missing parent or class attribute");
				hwc_free(hwcp);
				continue;
			}

			/* add to node spec list */
			add_spec(hwcp, pl);
			break;
		case NEWLINE:
			kobj_newline(file);
			break;
		default:
			kobj_file_err(CE_WARN, file, tok_err, tokval);
			break;
		}
	}
	/*
	 * XXX - Check for clean termination.
	 */
	kmem_free(tokval, MAX_HWC_LINESIZE);
	kobj_close_file(file);
	return (0);	/* always return success */
}

void
make_aliases(struct bind **bhash)
{
	enum {
		AL_NEW, AL_DRVNAME, AL_DRVNAME_COMMA, AL_ALIAS, AL_ALIAS_COMMA
	} state;

	struct _buf *file;
	char tokbuf[MAXPATHLEN];
	char drvbuf[MAXPATHLEN];
	token_t token;
	major_t major;
	int done = 0;
	static char dupwarn[] = "!Driver alias \"%s\" conflicts with "
	    "an existing driver name or alias.";

	if ((file = kobj_open_file(dafile)) == (struct _buf *)-1)
		return;

	state = AL_NEW;
	major = DDI_MAJOR_T_NONE;
	while (!done) {
		token = kobj_lex(file, tokbuf, sizeof (tokbuf));
		switch (token) {
		case POUND:
			/*
			 * Skip comments.
			 */
			kobj_find_eol(file);
			break;
		case NAME:
		case STRING:
			switch (state) {
			case AL_NEW:
				(void) strcpy(drvbuf, tokbuf);
				state = AL_DRVNAME;
				break;
			case AL_DRVNAME_COMMA:
				(void) strcat(drvbuf, tokbuf);
				state = AL_DRVNAME;
				break;
			case AL_ALIAS_COMMA:
				(void) strcat(drvbuf, tokbuf);
				state = AL_ALIAS;
				break;
			case AL_DRVNAME:
				major = mod_name_to_major(drvbuf);
				if (major == DDI_MAJOR_T_NONE) {
					kobj_find_eol(file);
					state = AL_NEW;
				} else {
					(void) strcpy(drvbuf, tokbuf);
					state = AL_ALIAS;
				}
				break;
			case AL_ALIAS:
				if (make_mbind(drvbuf, major, NULL, bhash)
				    != 0) {
					cmn_err(CE_WARN, dupwarn, drvbuf);
				}
				/*
				 * copy this token just in case that there
				 * are multiple names on the same line.
				 */
				(void) strcpy(drvbuf, tokbuf);
				break;
			}
			break;
		case COMMA:
			(void) strcat(drvbuf, tokbuf);
			switch (state) {
			case AL_DRVNAME:
				state = AL_DRVNAME_COMMA;
				break;
			case AL_ALIAS:
				state = AL_ALIAS_COMMA;
				break;
			default:
				kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			}
			break;
		case EOF:
			done = 1;
			/*FALLTHROUGH*/
		case NEWLINE:
			if (state == AL_ALIAS) {
				if (make_mbind(drvbuf, major, NULL, bhash)
				    != 0) {
					cmn_err(CE_WARN, dupwarn, drvbuf);
				}
			} else if (state != AL_NEW) {
				kobj_file_err(CE_WARN, file,
				    "Missing alias for %s", drvbuf);
			}

			kobj_newline(file);
			state = AL_NEW;
			major = DDI_MAJOR_T_NONE;
			break;
		default:
			kobj_file_err(CE_WARN, file, tok_err, tokbuf);
		}
	}

	kobj_close_file(file);
}


/*
 * It is called for parsing these files:
 * - /etc/path_to_inst
 * - /etc/name_to_major
 * - /etc/name_to_sysnum
 * A callback "int (*line_parser)(char *, int, char *, struct bind **)"
 * is invoked for each line of the file.
 * The callback can inhash the entry into a hashtable by supplying
 * a pre-allocated hashtable in "struct bind **hashtab".
 */
int
read_binding_file(char *bindfile, struct bind **hashtab,
    int (*line_parser)(char *, int, char *, struct bind **))
{
	enum {
		B_NEW, B_NAME, B_VAL, B_BIND_NAME
	} state;
	struct _buf *file;
	char tokbuf[MAXNAMELEN];
	token_t token;
	int maxnum = 0;
	char *bind_name = NULL, *name = NULL, *bn = NULL;
	u_longlong_t val;
	int done = 0;

	static char num_err[] = "Missing number on preceding line?";
	static char dupwarn[] = "!The binding file entry \"%s %u\" conflicts "
	    "with a previous entry";

	if (hashtab != NULL) {
		clear_binding_hash(hashtab);
	}

	if ((file = kobj_open_file(bindfile)) == (struct _buf *)-1)
		panic("read_binding_file: %s file not found", bindfile);

	state = B_NEW;

	while (!done) {
		token = kobj_lex(file, tokbuf, sizeof (tokbuf));

		switch (token) {
		case POUND:
			/*
			 * Skip comments.
			 */
			kobj_find_eol(file);
			break;
		case NAME:
		case STRING:
			switch (state) {
			case B_NEW:
				/*
				 * This case is for the first name and
				 * possibly only name in an entry.
				 */
				ASSERT(name == NULL);
				name = kmem_alloc(strlen(tokbuf) + 1, KM_SLEEP);
				(void) strcpy(name, tokbuf);
				state = B_NAME;
				break;
			case B_VAL:
				/*
				 * This case is for a second name, which
				 * would be the binding name if the first
				 * name was actually a generic name.
				 */
				ASSERT(bind_name == NULL);
				bind_name = kmem_alloc(strlen(tokbuf) + 1,
				    KM_SLEEP);
				(void) strcpy(bind_name, tokbuf);
				state = B_BIND_NAME;
				break;
			default:
				kobj_file_err(CE_WARN, file, num_err);
			}
			break;
		case HEXVAL:
		case DECVAL:
			if (state != B_NAME) {
				kobj_file_err(CE_WARN, file, "Missing name?");
				state = B_NEW;
				continue;
			}
			(void) kobj_getvalue(tokbuf, &val);
			if (val > (u_longlong_t)INT_MAX) {
				kobj_file_err(CE_WARN, file,
				    "value %llu too large", val);
				state = B_NEW;
				continue;
			}
			state = B_VAL;
			break;
		case EOF:
			done = 1;
			/*FALLTHROUGH*/
		case NEWLINE:
			if ((state == B_BIND_NAME) || (state == B_VAL)) {
				if (state == B_BIND_NAME)
					bn = bind_name;
				else
					bn = NULL;

				if (line_parser != NULL) {
					if ((*line_parser)(name, (int)val, bn,
					    hashtab) == 0)
						maxnum = MAX((int)val, maxnum);
					else
						kobj_file_err(CE_WARN, file,
						    dupwarn, name, (uint_t)val);
				}
			} else if (state != B_NEW)
				kobj_file_err(CE_WARN, file, "Syntax error?");

			if (name) {
				kmem_free(name, strlen(name) + 1);
				name = NULL;
			}
			if (bind_name) {
				kmem_free(bind_name, strlen(bind_name) + 1);
				bind_name = NULL;
			}
			state = B_NEW;
			kobj_newline(file);
			break;
		default:
			kobj_file_err(CE_WARN, file, "Missing name/number?");
			break;
		}
	}

	ASSERT(name == NULL);		/* any leaks? */
	ASSERT(bind_name == NULL);

	kobj_close_file(file);
	return (maxnum);
}

/*
 * read_dacf_binding_file()
 * 	Read the /etc/dacf.conf file and build the dacf_rule_t database from it.
 *
 * The syntax of a line in the dacf.conf file is:
 *   dev-spec 	[module:]op-set	operation options 	[config-args];
 *
 * Where:
 *   	1. dev-spec is of the format: name="data"
 *   	2. operation is the operation that this rule matches. (i.e. pre-detach)
 *   	3. options is a comma delimited list of options (i.e. debug,foobar)
 *   	4. config-data is a whitespace delimited list of the format: name="data"
 */
int
read_dacf_binding_file(char *filename)
{
	enum {
		DACF_BEGIN,
		/* minor_nodetype="ddi_mouse:serial" */
		DACF_NT_SPEC, DACF_NT_EQUALS, DACF_NT_DATA,
		/* consconfig:mouseconfig */
		DACF_MN_MODNAME, DACF_MN_COLON, DACF_MN_OPSET,
		/* op */
		DACF_OP_NAME,
		/* [ option1, option2, option3... | - ] */
		DACF_OPT_OPTION, DACF_OPT_COMMA, DACF_OPT_END,
		/* argname1="argval1" argname2="argval2" ... */
		DACF_OPARG_SPEC, DACF_OPARG_EQUALS, DACF_OPARG_DATA,
		DACF_ERR, DACF_ERR_NEWLINE, DACF_COMMENT
	} state = DACF_BEGIN;

	struct _buf *file;
	char *fname;
	token_t token;

	char tokbuf[MAXNAMELEN];
	char mn_modname_buf[MAXNAMELEN], *mn_modnamep = NULL;
	char mn_opset_buf[MAXNAMELEN], *mn_opsetp = NULL;
	char nt_data_buf[MAXNAMELEN], *nt_datap = NULL;
	char arg_spec_buf[MAXNAMELEN];

	uint_t opts = 0;
	dacf_devspec_t nt_spec_type = DACF_DS_ERROR;

	dacf_arg_t *arg_list = NULL;
	dacf_opid_t opid = DACF_OPID_ERROR;
	int done = 0;

	static char w_syntax[] = "'%s' unexpected";
	static char w_equals[] = "'=' is illegal in the current context";
	static char w_baddevspec[] = "device specification '%s' unrecognized";
	static char w_badop[] = "operation '%s' unrecognized";
	static char w_badopt[] = "option '%s' unrecognized, ignoring";
	static char w_newline[] = "rule is incomplete";
	static char w_insert[] = "failed to register rule";
	static char w_comment[] = "'#' not allowed except at start of line";
	static char w_dupargs[] =
	    "argument '%s' duplicates a previous argument, skipping";
	static char w_nt_empty[] = "empty device specification not allowed";

	if (filename == NULL) {
		fname = dacffile;	/* default binding file */
	} else {
		fname = filename;	/* user specified */
	}

	if ((file = kobj_open_file(fname)) == (struct _buf *)-1) {
		return (ENOENT);
	}

	if (dacfdebug & DACF_DBG_MSGS) {
		printf("dacf debug: clearing rules database\n");
	}

	mutex_enter(&dacf_lock);
	dacf_clear_rules();

	if (dacfdebug & DACF_DBG_MSGS) {
		printf("dacf debug: parsing %s\n", fname);
	}

	while (!done) {
		token = kobj_lex(file, tokbuf, sizeof (tokbuf));

		switch (token) {
		case POUND:	/* comment line */
			if (state != DACF_BEGIN) {
				kobj_file_err(CE_WARN, file, w_comment);
				state = DACF_ERR;
				break;
			}
			state = DACF_COMMENT;
			kobj_find_eol(file);
			break;

		case EQUALS:
			switch (state) {
			case DACF_NT_SPEC:
				state = DACF_NT_EQUALS;
				break;
			case DACF_OPARG_SPEC:
				state = DACF_OPARG_EQUALS;
				break;
			default:
				kobj_file_err(CE_WARN, file, w_equals);
				state = DACF_ERR;
			}
			break;

		case NAME:
			switch (state) {
			case DACF_BEGIN:
				nt_spec_type = dacf_get_devspec(tokbuf);
				if (nt_spec_type == DACF_DS_ERROR) {
					kobj_file_err(CE_WARN, file,
					    w_baddevspec, tokbuf);
					state = DACF_ERR;
					break;
				}
				state = DACF_NT_SPEC;
				break;
			case DACF_NT_DATA:
				(void) strncpy(mn_modname_buf, tokbuf,
				    sizeof (mn_modname_buf));
				mn_modnamep = mn_modname_buf;
				state = DACF_MN_MODNAME;
				break;
			case DACF_MN_MODNAME:
				/*
				 * This handles the 'optional' modname.
				 * What we thought was the modname is really
				 * the op-set.  So it is copied over.
				 */
				ASSERT(mn_modnamep);
				(void) strncpy(mn_opset_buf, mn_modnamep,
				    sizeof (mn_opset_buf));
				mn_opsetp = mn_opset_buf;
				mn_modnamep = NULL;
				/*
				 * Now, the token we just read is the opset,
				 * so look that up and fill in opid
				 */
				if ((opid = dacf_get_op(tokbuf)) ==
				    DACF_OPID_ERROR) {
					kobj_file_err(CE_WARN, file, w_badop,
					    tokbuf);
					state = DACF_ERR;
					break;
				}
				state = DACF_OP_NAME;
				break;
			case DACF_MN_COLON:
				(void) strncpy(mn_opset_buf, tokbuf,
				    sizeof (mn_opset_buf));
				mn_opsetp = mn_opset_buf;
				state = DACF_MN_OPSET;
				break;
			case DACF_MN_OPSET:
				if ((opid = dacf_get_op(tokbuf)) ==
				    DACF_OPID_ERROR) {
					kobj_file_err(CE_WARN, file, w_badop,
					    tokbuf);
					state = DACF_ERR;
					break;
				}
				state = DACF_OP_NAME;
				break;
			case DACF_OP_NAME:
				/*
				 * This case is just like DACF_OPT_COMMA below,
				 * but we check for the sole '-' argument
				 */
				if (strcmp(tokbuf, "-") == 0) {
					state = DACF_OPT_END;
					break;
				}
				/*FALLTHROUGH*/
			case DACF_OPT_COMMA:
				/*
				 * figure out what option was given, but don't
				 * make a federal case if invalid, just skip it
				 */
				if (dacf_getopt(tokbuf, &opts) != 0) {
					kobj_file_err(CE_WARN, file, w_badopt,
					    tokbuf);
				}
				state = DACF_OPT_OPTION;
				break;
			case DACF_OPT_END:
			case DACF_OPT_OPTION:
			case DACF_OPARG_DATA:
				(void) strncpy(arg_spec_buf, tokbuf,
				    sizeof (arg_spec_buf));
				state = DACF_OPARG_SPEC;
				break;
			case DACF_OPARG_EQUALS:
				/*
				 * Add the arg.  Warn if it's a duplicate
				 */
				if (dacf_arg_insert(&arg_list, arg_spec_buf,
				    tokbuf) != 0) {
					kobj_file_err(CE_WARN, file, w_dupargs,
					    arg_spec_buf);
				}
				state = DACF_OPARG_DATA;
				break;
			default:
				kobj_file_err(CE_WARN, file, w_syntax, tokbuf);
				state = DACF_ERR;
				break;
			}
			break;

		case STRING:
			/*
			 * We need to check to see if the string has a \n in it.
			 * If so, we had an unmatched " mark error, and lex has
			 * already emitted an error for us, so we need to enter
			 * the error state.  Stupid lex.
			 */
			if (strchr(tokbuf, '\n')) {
				state = DACF_ERR;
				break;
			}
			switch (state) {
			case DACF_NT_EQUALS:
				if (strlen(tokbuf) == 0) {
					kobj_file_err(CE_WARN, file,
					    w_nt_empty);
					state = DACF_ERR;
					break;
				}
				state = DACF_NT_DATA;
				nt_datap = nt_data_buf;
				(void) strncpy(nt_datap, tokbuf,
				    sizeof (nt_data_buf));
				break;
			case DACF_OPARG_EQUALS:
				/*
				 * Add the arg.  Warn if it's a duplicate
				 */
				if (dacf_arg_insert(&arg_list, arg_spec_buf,
				    tokbuf) != 0) {
					kobj_file_err(CE_WARN, file, w_dupargs,
					    arg_spec_buf);
				}
				state = DACF_OPARG_DATA;
				break;
			default:
				kobj_file_err(CE_WARN, file, w_syntax, tokbuf);
				state = DACF_ERR;
				break;
			}
			break;

		case COMMA:
			switch (state) {
			case DACF_OPT_OPTION:
				state = DACF_OPT_COMMA;
				break;
			default:
				kobj_file_err(CE_WARN, file, w_syntax, ",");
				state = DACF_ERR;
				break;
			}
			break;

		case COLON:
			if (state == DACF_MN_MODNAME)
				state = DACF_MN_COLON;
			else {
				kobj_file_err(CE_WARN, file, w_syntax, ":");
				state = DACF_ERR;
			}
			break;

		case EOF:
			done = 1;
			/*FALLTHROUGH*/
		case NEWLINE:
			if (state == DACF_COMMENT || state == DACF_BEGIN) {
				state = DACF_BEGIN;
				kobj_newline(file);
				break;
			}
			if ((state != DACF_OPT_OPTION) &&
			    (state != DACF_OPARG_DATA) &&
			    (state != DACF_OPT_END)) {
				kobj_file_err(CE_WARN, file, w_newline);
				/*
				 * We can't just do DACF_ERR here, since we'll
				 * wind up eating the _next_ newline if so.
				 */
				state = DACF_ERR_NEWLINE;
				kobj_newline(file);
				break;
			}

			/*
			 * insert the rule.
			 */
			if (dacf_rule_insert(nt_spec_type, nt_datap,
			    mn_modnamep, mn_opsetp, opid, opts, arg_list) < 0) {
				/*
				 * We can't just do DACF_ERR here, since we'll
				 * wind up eating the _next_ newline if so.
				 */
				kobj_file_err(CE_WARN, file, w_insert);
				state = DACF_ERR_NEWLINE;
				kobj_newline(file);
				break;
			}

			state = DACF_BEGIN;
			kobj_newline(file);
			break;

		default:
			kobj_file_err(CE_WARN, file, w_syntax, tokbuf);
			break;
		} /* switch */

		/*
		 * Clean up after ourselves, either after a line has terminated
		 * successfully or because of a syntax error; or when we reach
		 * EOF (remember, we may reach EOF without being 'done' with
		 * handling a particular line).
		 */
		if (state == DACF_ERR) {
			kobj_find_eol(file);
		}
		if ((state == DACF_BEGIN) || (state == DACF_ERR) ||
		    (state == DACF_ERR_NEWLINE) || done) {
			nt_datap = NULL;
			mn_modnamep = mn_opsetp = NULL;
			opts = 0;
			opid = DACF_OPID_ERROR;
			nt_spec_type = DACF_DS_ERROR;
			dacf_arglist_delete(&arg_list);
			state = DACF_BEGIN;
		}
	} /* while */

	if (dacfdebug & DACF_DBG_MSGS) {
		printf("\ndacf debug: done!\n");
	}

	mutex_exit(&dacf_lock);

	kobj_close_file(file);
	return (0);
}

void
lock_hw_class_list()
{
	mutex_enter(&hcl_lock);
}

void
unlock_hw_class_list()
{
	mutex_exit(&hcl_lock);
}

void
add_class(char *exporter, char *class)
{
	struct hwc_class *hcl;

	/*
	 * If exporter's major is not registered in /etc/name_to_major,
	 * don't update hwc_class, but just return here.
	 */
	if (ddi_name_to_major(exporter) >= devcnt) {
		cmn_err(CE_WARN, "No major number for driver %s"
		    " in class %s", exporter, class);
		return;
	}
	hcl = kmem_zalloc(sizeof (struct hwc_class), KM_SLEEP);
	hcl->class_exporter = kmem_alloc(strlen(exporter) + 1, KM_SLEEP);
	hcl->class_name = kmem_alloc(strlen(class) + 1, KM_SLEEP);
	(void) strcpy(hcl->class_exporter, exporter);
	(void) strcpy(hcl->class_name, class);
	lock_hw_class_list();
	hcl->class_next = hcl_head;
	hcl_head = hcl;
	unlock_hw_class_list();
}

/*
 * Return the number of classes exported. If buf is not NULL, fill in
 * the array of the class names as well.
 *
 * Caller must hold hcl_lock to ensure the class list unmodified while
 * it is accessed. A typical caller will get a count first and then
 * allocate buf. The lock should be held by the caller.
 */
int
get_class(const char *exporter, char **buf)
{
	int n = 0;
	struct hwc_class *hcl;

	ASSERT(mutex_owned(&hcl_lock));
	for (hcl = hcl_head; hcl != NULL; hcl = hcl->class_next) {
		if (strcmp(exporter, hcl->class_exporter) == 0) {
			if (buf)
				buf[n] = hcl->class_name;
			++n;
		}
	}

	return (n);
}

void
read_class_file(void)
{
	struct _buf *file;
	struct hwc_class *hcl, *hcl1;
	char tokbuf[MAXNAMELEN];
	enum {
		C_BEGIN, C_EXPORTER, C_END
	} state;
	token_t token;
	int done = 0;
	char *exporter = NULL, *class = NULL, *name = NULL;

	if (hcl_head != NULL) {
		hcl = hcl_head;
		while (hcl != NULL) {
			kmem_free(hcl->class_exporter,
			    strlen(hcl->class_exporter) + 1);
			hcl1 = hcl;
			hcl = hcl->class_next;
			kmem_free(hcl1, sizeof (struct hwc_class));
		}
		hcl_head = NULL;
	}

	if ((file = kobj_open_file(class_file)) == (struct _buf *)-1)
		return;

	state = C_BEGIN;
	while (!done) {
		token = kobj_lex(file, tokbuf, sizeof (tokbuf));

		switch (token) {
		case POUND:
			/*
			 * Skip comments.
			 */
			kobj_find_eol(file);
			break;
		case NAME:
		case STRING:
			name = kmem_alloc(strlen(tokbuf) + 1, KM_SLEEP);
			(void) strcpy(name, tokbuf);
			switch (state) {
			case C_BEGIN:
				exporter = name;
				state = C_EXPORTER;
				break;
			case C_EXPORTER:
				class = name;
				add_class(exporter, class);
				state = C_END;
				break;
			case C_END:
				kobj_file_err(CE_WARN, file,
				    "Extra noise after entry");
				kmem_free(name, strlen(name) + 1);
				kobj_find_eol(file);
				break;
			} /* End Switch */
			break;
		case EOF:
			done = 1;
			/*FALLTHROUGH*/
		case NEWLINE:
			kobj_newline(file);
			if (state == C_EXPORTER)
				kobj_file_err(CE_WARN, file,
				    "Partial entry ignored");
			state = C_BEGIN;
			if (exporter)
				kmem_free(exporter, strlen(exporter) + 1);
			if (class)
				kmem_free(class, strlen(class) + 1);
			exporter = NULL;
			class = NULL;
			break;
		default:
			kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			break;
		}
	}
	kobj_close_file(file);
}

/*
 * Given par_list, get a list of parent major number
 */
int
impl_parlist_to_major(struct par_list *pl, char parents[])
{
	struct hwc_spec *hwcp;
	struct hwc_class *hcl;
	major_t major;
	int nmajor = 0;
	extern int devcnt;

	for (; pl != NULL; pl = pl->par_next) {
		if ((pl->par_major < devcnt) && (parents[pl->par_major] == 0)) {
			parents[pl->par_major] = 1;
			nmajor++;
			continue;
		}

		/* parent specs cannot be mapped to a driver */
		if (pl->par_major != DDI_MAJOR_T_NONE)
			continue;

		/* class spec */
		hwcp = pl->par_specs;
		ASSERT(hwcp->hwc_class_name);
		ASSERT(hwcp->hwc_parent_name == NULL);

		for (hcl = hcl_head; hcl != NULL; hcl = hcl->class_next) {
			if (strcmp(hwcp->hwc_class_name, hcl->class_name) != 0)
				continue;
			major = ddi_name_to_major(hcl->class_exporter);
			ASSERT(major != DDI_MAJOR_T_NONE);
			if (parents[major] == 0) {
				parents[major] = 1;
				nmajor++;
			}
		}
	}
	return (nmajor);
}

/*
 * delete a parent list and all its hwc specs
 */
void
impl_delete_par_list(struct par_list *pl)
{
	struct par_list *saved_pl;
	struct hwc_spec *hp, *hp1;

	while (pl) {
		hp = pl->par_specs;
		while (hp) {
			hp1 = hp;
			hp = hp->hwc_next;
			hwc_free(hp1);
		}
		saved_pl = pl;
		pl = pl->par_next;
		kmem_free(saved_pl, sizeof (*saved_pl));
	}
}

#if defined(_PSM_MODULES)
void
open_mach_list(void)
{
	struct _buf *file;
	char tokbuf[MAXNAMELEN];
	token_t token;
	struct psm_mach *machp;

	if ((file = kobj_open_file(mach_file)) == (struct _buf *)-1)
		return;

	while ((token = kobj_lex(file, tokbuf, sizeof (tokbuf))) != EOF) {
		switch (token) {
		case POUND:
			/*
			 * Skip comments.
			 */
			kobj_find_eol(file);
			break;
		case NAME:
		case STRING:
			machp = kmem_alloc((sizeof (struct psm_mach) +
			    strlen(tokbuf) + 1), KM_SLEEP);
			machp->m_next = pmach_head;
			machp->m_machname = (char *)(machp + 1);
			(void) strcpy(machp->m_machname, tokbuf);
			pmach_head = machp;
			break;
		case NEWLINE:
			kobj_newline(file);
			break;
		default:
			kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			break;
		}
	}
	kobj_close_file(file);
}

void *
get_next_mach(void *handle, char *buf)
{
	struct psm_mach *machp;

	machp = (struct psm_mach *)handle;
	if (machp)
		machp = machp->m_next;
	else
		machp = pmach_head;
	if (machp)
		(void) strcpy(buf, machp->m_machname);
	return (machp);
}

void
close_mach_list(void)
{
	struct psm_mach *machp;

	while (pmach_head) {
		machp = pmach_head;
		pmach_head = machp->m_next;
		kmem_free(machp, sizeof (struct psm_mach) +
		    strlen(machp->m_machname) + 1);
	}
}
#endif	/* _PSM_MODULES */

#if defined(_RTC_CONFIG)
/*
 * Read in the 'zone_lag' value from the rtc configuration file,
 * and return the value to the caller.  Note that there is other information
 * in this file (zone_info), so we ignore unknown values.  We do spit out
 * warnings if the line doesn't begin with an identifier, or if we don't find
 * exactly "zone_lag=value".  No one should be editing this file by hand
 * (use the rtc command instead), but it's better to be careful.
 */
long
process_rtc_config_file(void)
{
	enum {
		R_NEW, R_NAME, R_EQUALS, R_VALUE
	} state;
	struct _buf *file;
	char tokbuf[MAXNAMELEN];
	token_t token;
	long zone_lag = 0;
	u_longlong_t tmp;
	int done = 0;

	if ((file = kobj_open_file(rtc_config_file)) == (struct _buf *)-1)
		return (0);

	state = R_NEW;

	while (!done) {
		token = kobj_lex(file, tokbuf, sizeof (tokbuf));

		switch (token) {
		case POUND:
			/*
			 * Skip comments.
			 */
			kobj_find_eol(file);
			break;
		case NAME:
		case STRING:
			if (state == R_NEW) {
				if (strcmp(tokbuf, "zone_lag") == 0)
					state = R_NAME;
				else
					kobj_find_eol(file);   /* Ignore */
			} else
				kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			break;
		case EQUALS:
			if (state == R_NAME)
				state = R_EQUALS;
			else
				kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			break;
		case DECVAL:
			if (state == R_EQUALS) {
				if (kobj_getvalue(tokbuf, &tmp) != 0)
					kobj_file_err(CE_WARN, file,
					    "Bad value %s for zone_lag",
					    tokbuf);
				else
					zone_lag = (long)tmp;
				state = R_VALUE;
			} else
				kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			break;
		case EOF:
			done = 1;
			/*FALLTHROUGH*/
		case NEWLINE:
			if (state != R_NEW && state != R_VALUE)
				kobj_file_err(CE_WARN, file,
				    "Partial zone_lag entry ignored");
			kobj_newline(file);
			state = R_NEW;
			break;
		default:
			kobj_file_err(CE_WARN, file, tok_err, tokbuf);
			break;
		}
	}
	kobj_close_file(file);
	return (zone_lag);
}
#endif /* _RTC_CONFIG */


/*
 * Append node spec to the end of par_list
 */
static void
append(struct hwc_spec *spec, struct par_list *par)
{
	struct hwc_spec *hwc, *last;

	ASSERT(par->par_specs);
	for (hwc = par->par_specs; hwc; hwc = hwc->hwc_next)
		last = hwc;
	last->hwc_next = spec;
}

/*
 * Given a parent=/full-pathname, see if the platform
 * can resolve the pathname to driver, otherwise, try
 * the leaf node name.
 */
static major_t
get_major(char *parent)
{
	major_t major = DDI_MAJOR_T_NONE;
	char *tmp, *driver = NULL;

	if (*parent == '/')
		major = path_to_major(parent);

	if (major != DDI_MAJOR_T_NONE)
		return (major);

	/* extract the name between '/' and '@' */
	if (*parent == '/')
		driver = strrchr(parent, '/') + 1;
	else
		driver = parent;
	if ((tmp = strchr(driver, '@')) != NULL)
		*tmp = '\0';
	major = ddi_name_to_major(driver);
	if (tmp)
		*tmp = '@';
	return (major);
}

/*
 * Chain together specs whose parent's module name is the same.
 */
static void
add_spec(struct hwc_spec *spec, struct par_list **par)
{
	major_t maj;
	struct par_list *pl, *par_last = NULL;
	char *parent = spec->hwc_parent_name;
	char *class = spec->hwc_class_name;

	ASSERT(parent || class);

	/*
	 * If given a parent=/full-pathname, see if the platform
	 * can resolve the pathname to driver, otherwise, try
	 * the leaf node name.
	 *
	 * If parent=/full-pathname doesn't resolve to a driver,
	 * this could be cause by DR removal of the device.
	 * We put it on the major=-2 list in case the device
	 * is brought back into the system by DR.
	 */
	if (parent) {
		maj = get_major(parent);
		if (maj == DDI_MAJOR_T_NONE) {
			if ((*parent == '/') &&
			    (strncmp(parent, "/pseudo", 7) != 0)) {
				maj = (major_t)-2;
			} else {
				cmn_err(CE_WARN,
				    "add_spec: No major number for %s",
				    parent);
				hwc_free(spec);
				return;
			}
		}
	} else
		maj = DDI_MAJOR_T_NONE;

	/*
	 * Scan the list looking for a matching parent. When parent is
	 * not NULL, we match the parent by major. If parent is NULL but
	 * class is not NULL, we mache the pl by class name.
	 */
	for (pl = *par; pl; pl = pl->par_next) {
		if ((parent && (maj == pl->par_major)) || ((parent == NULL) &&
		    class && pl->par_specs->hwc_class_name && (strncmp(class,
		    pl->par_specs->hwc_class_name, strlen(class)) == 0))) {
			append(spec, pl);
			return;
		}
		par_last = pl;
	}

	/*
	 * Didn't find a match on the list.  Make a new parent list.
	 */
	pl = kmem_zalloc(sizeof (*pl), KM_SLEEP);
	pl->par_major = maj;
	pl->par_specs = spec;
	if (*par == NULL) {	/* null par list */
		*par = pl;
		return;
	}
	/* put "class=" entries last (lower pri if dups) */
	if (maj == DDI_MAJOR_T_NONE) {
		par_last->par_next = pl;
		return;
	}

	/* ensure unresolved "parent=/full-path" goes first */
	if ((maj != (major_t)-2) && ((*par)->par_major == (major_t)-2))
		par = &(*par)->par_next;
	pl->par_next = *par;
	*par = pl;
}

/*
 * Add property spec to property list in original order
 */
static void
add_props(struct hwc_spec *spec, ddi_prop_t **props)
{
	ASSERT(spec->hwc_devi_name == NULL);

	if (spec->hwc_devi_sys_prop_ptr) {
		while (*props)
			props = &(*props)->prop_next;
		*props = spec->hwc_devi_sys_prop_ptr;

		/* remove these properties from the spec */
		spec->hwc_devi_sys_prop_ptr = NULL;
	}
	hwc_free(spec);
}
