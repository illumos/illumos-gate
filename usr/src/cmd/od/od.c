/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * od - octal dump.  Not really just octal anymore; read the POSIX
 * specification for it -- its more complex than you think!
 *
 * NB: We followed the POSIX semantics fairly strictly, where the
 * legacy code's behavior was in conflict.  In many cases the legacy
 * Solaris code was so completely broken as to be completely unusable.
 * (For example, the long double support was broken beyond
 * imagination!)  Note that GNU coreutils violates POSIX in a few
 * interesting ways, such as changing the numbering of the addresses
 * when skipping.  (Address starts should always be at 0, according to
 * the sample output in the Open Group man page.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <err.h>
#include <wchar.h>
#include <locale.h>
#include <unistd.h>
#include <sys/stat.h>

#define	_(x)	gettext(x)


#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

/* address format */
static char *afmt  =	"%07llo";
static char *cfmt  =    "       ";

static FILE *input = NULL;
static size_t lcm = 1;
static size_t blocksize = 16;
static int numfiles = 0;
static int curfile = 0;
static char **files = NULL;
static off_t limit = -1;

/*
 * This structure describes our ring buffer.  Its always a power of 2
 * in size to make wrap around calculations fast using a mask instead
 * of doing modulo.
 *
 * The size is calculated thusly: We need three "blocks" of data, as
 * we process a block at a time (one block == one line of od output.)
 *
 * We need lookahead of an extra block to support multibyte chars.  We
 * also have a look behind so that we can avoid printing lines that
 * are identical to what we've already printed.  Finally, we need the
 * current block.
 *
 * The block size is determined by the least common multiple of the
 * data items being displayed.  Usually it will be 16, but sometimes
 * it is 24 (when 12-byte long doubles are presented.)
 *
 * The data buffer is allocaed via memalign to make sure it is
 * properly aligned.
 */
typedef struct buffer {
	char	*data;		/* data buffer */
	int	prod;		/* producer index */
	int	cons;		/* consumer index */
	int	mask;		/* buffer size - 1, wraparound index */
	int	navail;		/* total bytes avail */
} buffer_t;

/*
 * This structure is used to provide information on a specific output
 * format.  We link them together in a list representing the output
 * formats that the user has selected.
 */
typedef struct output {
	int	width;				/* bytes consumed per call */
	void	(*func)(buffer_t *, int);	/* output function */
	struct output	*next;			/* link node */
} output_t;

/*
 * Specifiers
 */

typedef unsigned char		u8;
typedef unsigned short		u16;
typedef unsigned int		u32;
typedef unsigned long long	u64;
typedef char			s8;
typedef short			s16;
typedef int			s32;
typedef long long		s64;
typedef float			fF;
typedef	double			fD;
typedef long double		fL;

static void
usage(void)
{
	(void) fprintf(stderr, _("usage: od [-bcCdDfFoOsSvxX] "
	    "[-t types ]... [-A base] [-j skip] [-N count] [file]...\n"));
	exit(1);
}

#define	DECL_GET(typ)							\
static typ								\
get_ ## typ(buffer_t *b, int index)					\
{									\
	typ val = *(typ *)(void *)(b->data + index);			\
	return (val);							\
}
DECL_GET(u8)
DECL_GET(u16)
DECL_GET(u32)
DECL_GET(u64)
DECL_GET(s8)
DECL_GET(s16)
DECL_GET(s32)
DECL_GET(s64)
DECL_GET(fF)
DECL_GET(fD)
DECL_GET(fL)

#define	DECL_OUT(nm, typ, fmt)					\
static void							\
do_ ## nm(buffer_t *buf, int index)				\
{								\
	typ v = get_ ## typ(buf, index);			\
	(void) printf(fmt, v);					\
}								\
								\
static output_t output_ ## nm =  {				\
	sizeof (typ), do_ ## nm					\
};

DECL_OUT(oct_b, u8, " %03o")
DECL_OUT(oct_w, u16, " %06ho")
DECL_OUT(oct_d, u32, " %011o")
DECL_OUT(oct_q, u64, " %022llo")
DECL_OUT(dec_b, u8, " %03u")
DECL_OUT(dec_w, u16, " %05hu")
DECL_OUT(dec_d, u32, " %010u")
DECL_OUT(dec_q, u64, " %020llu")
DECL_OUT(sig_b, s8, " %03d")
DECL_OUT(sig_w, s16, " %6.05hd")
DECL_OUT(sig_d, s32, " %11.010d")
DECL_OUT(sig_q, s64, " %20.019lld")
DECL_OUT(hex_b, u8, " %02x")
DECL_OUT(hex_w, u16, " %04hx")
DECL_OUT(hex_d, s32, " %08x")
DECL_OUT(hex_q, s64, " %016llx")
DECL_OUT(float, fF, " %14.7e")
DECL_OUT(double, fD, " %21.14e")
DECL_OUT(ldouble, fL, " %24.14Le")

static char *ascii[] = {
	"nul", "soh", "stx", "etx", "eot", "enq", "ack", " be",
	" bs", " ht", " lf", " vt", " ff", " cr", " so", " si",
	"dle", "dc1", "dc2", "dc3", "dc4", "nak", "syn", "etb",
	"can", " em", "sub", "esc", " fs", " gs", " rs", " us",
	" sp", "  !", "  \"", "  #", "  $", "  %", "  &", "  '",
	"  (", "  )", "  *", "  +", "  ,", "  -", "  .", "  /",
	"  0", "  1", "  2", "  3", "  4", "  5", "  6", "  7",
	"  8", "  9", "  :", "  ;", "  <", "  =", "  >", "  ?",
	"  @", "  A", "  B", "  C", "  D", "  E", "  F", "  G",
	"  H", "  I", "  J", "  K", "  L", "  M", "  N", "  O",
	"  P", "  Q", "  R", "  S", "  T", "  U", "  V", "  W",
	"  X", "  Y", "  Z", "  [", "  \\", "  ]", "  ^", "  _",
	"  `", "  a", "  b", "  c", "  d", "  e", "  f", "  g",
	"  h", "  i", "  j", "  k", "  l", "  m", "  n", "  o",
	"  p", "  q", "  r", "  s", "  t", "  u", "  v", "  w",
	"  x", "  y", "  z", "  {", "  |", "  }", "  ~", "del"
};

static void
do_ascii(buffer_t *buf, int index)
{
	uint8_t v = get_u8(buf, index);

	(void) fputc(' ', stdout);
	(void) fputs(ascii[v & 0x7f], stdout);
}

static output_t output_ascii = {
	1, do_ascii,
};

static void
do_char(buffer_t *buf, int index)
{
	static int	nresid = 0;
	static int	printable = 0;
	int		cnt;
	int		avail;
	int		nb;
	char		scratch[10];
	wchar_t		wc;
	int		which;

	uint8_t v = get_u8(buf, index);

	/*
	 * If there were residual bytes from an earlier
	 * character, then just display the ** continuation
	 * indication.
	 */
	if (nresid) {
		if (printable) {
			(void) fputs("  **", stdout);
		} else {
			(void) printf(" %03o", v);
		}
		nresid--;
		return;
	}

	/*
	 * Peek ahead up to MB_CUR_MAX characters.  This has to be
	 * done carefully because we might need to look into the next
	 * block to really know for sure.
	 */
	scratch[0] = v;
	avail = buf->navail;
	if (avail > MB_CUR_MAX)
		avail = MB_CUR_MAX;
	for (cnt = 1, which = index + 1; cnt < avail; cnt++, which++) {
		scratch[cnt] = buf->data[which & buf->mask];
	}

	/* now see if the value is a real character */
	nresid = 0;
	wc = 0;
	nb = mbtowc(&wc, scratch, avail);
	if (nb < 0) {
		(void) printf(" %03o", v);
		return;
	}
	if (nb == 0) {
		(void) fputs("  \\0", stdout);
		return;
	}
	nresid = nb - 1;
	if (nb && iswprint(wc)) {
		scratch[nb] = 0;
		(void) fputs("   ", stdout);
		(void) fputs(scratch, stdout);
		printable = 1;
		return;
	}
	printable = 0;
	if (wc == 0) {
		(void) fputs("  \\0", stdout);
	} else if (wc == '\b') {
		(void) fputs("  \\b", stdout);
	} else if (wc == '\f') {
		(void) fputs("  \\f", stdout);
	} else if (wc == '\n') {
		(void) fputs("  \\n", stdout);
	} else if (wc == '\r') {
		(void) fputs("  \\r", stdout);
	} else if (wc == '\t') {
		(void) fputs("  \\t", stdout);
	} else {
		(void) printf(" %03o", v);
	}
}

static output_t output_char = {
	1, do_char,
};

/*
 * List of output formatting structures.
 */
static output_t *head = NULL;
static output_t **tailp = &head;

static void
add_out(output_t *src)
{
	output_t	*out;
	int		m;

	if ((out = calloc(1, sizeof (*src))) == NULL) {
		err(1, "malloc");
	}

	m = lcm;
	while ((m % src->width) != 0) {
		m += lcm;
	}
	lcm = m;
	blocksize = lcm;
	while (blocksize < 16)
		blocksize *= 2;

	(void) memcpy(out, src, sizeof (*src));
	*tailp = out;
	tailp = &out->next;
}

static FILE *
next_input(void)
{
	for (;;) {
		if (curfile >= numfiles)
			return (NULL);

		if (input != NULL) {
			if ((input = freopen(files[curfile], "r", input)) !=
			    NULL) {
				curfile++;
				return (input);
			}
		} else {
			if ((input = fopen(files[curfile], "r")) != NULL) {
				curfile++;
				return (input);
			}
		}
		warn("open: %s", files[curfile]);
		curfile++;
	}
}

static void
refill(buffer_t *b)
{
	int	n;
	int	want;
	int	zero;

	/*
	 * If we have 2 blocks of bytes available, we're done.  Note
	 * that each iteration usually loads up 16 bytes, unless we
	 * run out of data.
	 */
	while ((input != NULL) && (b->navail < (2 * blocksize))) {

		/* we preload the next one in advance */

		if (limit == 0) {
			(void) fclose(input);
			input = NULL;
			continue;
		}

		/* we want to read a whole block if possible */
		want = blocksize;
		if ((limit >= 0) && (want > limit)) {
			want = limit;
		}
		zero = blocksize;

		while (want && input) {
			int	c;
			b->prod &= b->mask;
			c = (b->prod + want > (b->mask + 1)) ?
			    b->mask - b->prod :
			    want;

			n = fread(b->data + b->prod, 1, c, input);
			if (n < 0) {
				warn("read: %s",
				    files ? files[curfile-1] : "stdin");
				input = next_input();
				continue;
			}
			if (n == 0) {
				input = next_input();
				continue;
			}
			if (limit >= 0)
				limit -= n;
			b->navail += n;
			b->prod += n;
			want -= n;
			zero -= n;
		}

		while (zero) {
			b->data[b->prod & b->mask] = 0;
			b->prod++;
			b->prod &= b->mask;
			zero--;
		}
	}
}

#define	STR1	"C1"
#define	STR2	"S2"
#ifdef	_LP64
#define	STR8	"L8"
#define	STR4	"I4"
#else
#define	STR8	"8"
#define	STR4	"IL4"
#endif

static void
do_type_string(char *typestr)
{
	if (*typestr == 0) {
		errx(1, _("missing type string"));
	}
	while (*typestr) {
		switch (*typestr) {
		case 'a':
			typestr++;
			add_out(&output_ascii);
			break;
		case 'c':
			add_out(&output_char);
			typestr++;
			break;
		case 'f':
			typestr++;
			switch (*typestr) {
			case 'F':
			case '4':
				add_out(&output_float);
				typestr++;
				break;
			case '8':
			case 'D':
				add_out(&output_double);
				typestr++;
				break;
			case 'L':
				add_out(&output_ldouble);
				typestr++;
				break;
			default:
				add_out(&output_float);
				break;
			}
			break;


		case 'd':
			typestr++;
			if (strchr(STR1, *typestr)) {
				typestr++;
				add_out(&output_sig_b);
			} else if (strchr(STR2, *typestr)) {
				typestr++;
				add_out(&output_sig_w);
			} else if (strchr(STR4, *typestr)) {
				typestr++;
				add_out(&output_sig_d);
			} else if (strchr(STR8, *typestr)) {
				typestr++;
				add_out(&output_sig_q);
			} else {
				add_out(&output_sig_d);
			}
			break;

		case 'u':
			typestr++;
			if (strchr(STR1, *typestr)) {
				typestr++;
				add_out(&output_dec_b);
			} else if (strchr(STR2, *typestr)) {
				typestr++;
				add_out(&output_dec_w);
			} else if (strchr(STR4, *typestr)) {
				typestr++;
				add_out(&output_dec_d);
			} else if (strchr(STR8, *typestr)) {
				typestr++;
				add_out(&output_dec_q);
			} else {
				add_out(&output_dec_d);
			}
			break;

		case 'o':
			typestr++;
			if (strchr(STR1, *typestr)) {
				typestr++;
				add_out(&output_oct_b);
			} else if (strchr(STR2, *typestr)) {
				typestr++;
				add_out(&output_oct_w);
			} else if (strchr(STR4, *typestr)) {
				typestr++;
				add_out(&output_oct_d);
			} else if (strchr(STR8, *typestr)) {
				typestr++;
				add_out(&output_oct_q);
			} else {
				add_out(&output_oct_d);
			}
			break;

		case 'x':
			typestr++;
			if (strchr(STR1, *typestr)) {
				typestr++;
				add_out(&output_hex_b);
			} else if (strchr(STR2, *typestr)) {
				typestr++;
				add_out(&output_hex_w);
			} else if (strchr(STR4, *typestr)) {
				typestr++;
				add_out(&output_hex_d);
			} else if (strchr(STR8, *typestr)) {
				typestr++;
				add_out(&output_hex_q);
			} else {
				add_out(&output_hex_d);
			}
			break;

		default:
			errx(1, _("unrecognized type string character: %c"),
			    *typestr);
		}
	}
}

int
main(int argc, char **argv)
{
	int		c;
	int		i;
	buffer_t	buffer;
	boolean_t	first = B_TRUE;
	boolean_t	doall = B_FALSE;
	boolean_t	same = B_FALSE;
	boolean_t	newarg = B_FALSE;
	off_t		offset = 0;
	off_t		skip = 0;
	char		*eptr;
	char		*offstr = 0;

	input = stdin;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "A:bCcdDfFj:N:oOsSxXvt:")) != EOF) {
		switch (c) {
		case 'A':
			newarg = B_TRUE;
			if (strlen(optarg) > 1) {
				afmt = NULL;
			}
			switch (*optarg) {
			case 'o':
				afmt = "%07llo";
				cfmt = "       ";
				break;
			case 'd':
				afmt = "%07lld";
				cfmt = "       ";
				break;
			case 'x':
				afmt = "%07llx";
				cfmt = "       ";
				break;
			case 'n':
				/*
				 * You could argue that the code should
				 * use the same 7 spaces.  Legacy uses 8
				 * though.  Oh well.  Better to avoid
				 * gratuitous change.
				 */
				afmt = "        ";
				cfmt = "        ";
				break;
			default:
				afmt = NULL;
				break;
			}
			if (strlen(optarg) != 1) {
				afmt = NULL;
			}
			if (afmt == NULL)
				warnx(_("invalid address base, "
				    "must be o, d, x, or n"));
			break;

		case 'b':
			add_out(&output_oct_b);
			break;

		case 'c':
		case 'C':
			add_out(&output_char);
			break;

		case 'f':
			add_out(&output_float);
			break;

		case 'F':
			add_out(&output_double);
			break;

		case 'd':
			add_out(&output_dec_w);
			break;

		case 'D':
			add_out(&output_dec_d);
			break;

		case 't':
			newarg = B_TRUE;
			do_type_string(optarg);
			break;

		case 'o':
			add_out(&output_oct_w);
			break;

		case 'O':
			add_out(&output_oct_d);
			break;

		case 's':
			add_out(&output_sig_w);
			break;

		case 'S':
			add_out(&output_sig_d);
			break;

		case 'x':
			add_out(&output_hex_w);
			break;

		case 'X':
			add_out(&output_hex_d);
			break;

		case 'v':
			doall = B_TRUE;
			break;

		case 'j':
			newarg = B_TRUE;
			skip = strtoll(optarg, &eptr, 0);
			if (*eptr == 'b') {
				skip <<= 9;	/* 512 bytes */
				eptr++;
			} else if (*eptr == 'k') {
				skip <<= 10;	/* 1k */
				eptr++;
			} else if (*eptr == 'm') {
				skip <<= 20;	/* 1m */
				eptr++;
			} else if (*eptr == 'g') {
				skip <<= 30;	/* 1g */
				eptr++;
			}
			if ((skip < 0) || (eptr[0] != 0)) {
				warnx(_("invalid skip count '%s' specified"),
				    optarg);
				exit(1);
			}
			break;

		case 'N':
			newarg = B_TRUE;
			limit = strtoll(optarg, &eptr, 0);
			/*
			 * POSIX doesn't specify this, but I think these
			 * may be helpful.
			 */
			if (*eptr == 'b') {
				limit <<= 9;
				eptr++;
			} else if (*eptr == 'k') {
				limit <<= 10;
				eptr++;
			} else if (*eptr == 'm') {
				limit <<= 20;
				eptr++;
			} else if (*eptr == 'g') {
				limit <<= 30;
				eptr++;
			}
			if ((limit < 0) || (eptr[0] != 0)) {
				warnx(_("invalid byte count '%s' specified"),
				    optarg);
				exit(1);
			}
			break;

		default:
			usage();
			break;
		}
	}

	/* this finds the smallest power of two size we can use */
	buffer.mask = (1 << (ffs(blocksize * 3) + 1)) - 1;
	buffer.data = memalign(16, buffer.mask + 1);
	if (buffer.data == NULL) {
		err(1, "memalign");
	}


	/*
	 * Wow.  This option parsing is hideous.
	 *
	 * If the we've not seen a new option, and there is just one
	 * operand, if it starts with a "+", then treat it as an
	 * offset.  Otherwise if two operands, and the second operand
	 * starts with + or a digit, then it is an offset.
	 */
	if (!newarg) {
		if (((argc - optind) == 1) && (argv[optind][0] == '+')) {
			offstr = argv[optind];
			argc--;
		} else if (((argc - optind) == 2) &&
		    (strchr("+0123456789", (argv[optind + 1][0])) != NULL)) {
			offstr = argv[optind + 1];
			argc--;
		}
	}
	if (offstr) {
		int base = 0;
		int mult = 1;
		int l;
		if (*offstr == '+') {
			offstr++;
		}
		l = strlen(offstr);
		if ((strncmp(offstr, "0x", 2) == 0)) {
			afmt = "%07llx";
			base = 16;
			offstr += 2;
			if (offstr[l - 1] == 'B') {
				offstr[l - 1] = 0;
				l--;
				mult = 512;
			}
		} else {
			base = 8;
			afmt = "%07llo";
			if ((offstr[l - 1] == 'B') || (offstr[l - 1] == 'b')) {
				offstr[l - 1] = 0;
				l--;
				mult = 512;
			}
			if (offstr[l - 1] == '.') {
				offstr[l - 1] = 0;
				base = 10;
				afmt = "%07lld";
			}
		}
		skip = strtoll(offstr, &eptr, base);
		if (*eptr != '\0') {
			errx(1, _("invalid offset string specified"));
		}
		skip *= mult;
		offset += skip;
	}

	/*
	 * Allocate an array for all the input files.
	 */
	if (argc > optind) {
		files = calloc(sizeof (char *), argc - optind);
		for (i = 0; i < argc - optind; i++) {
			files[i] = argv[optind + i];
			numfiles++;
		}
		input = next_input();
	} else {
		input = stdin;
	}

	/*
	 * We need to seek ahead.  fseek would be faster.
	 */
	while (skip && (input != NULL)) {
		struct stat sbuf;

		/*
		 * Only fseek() on regular files.  (Others
		 * we have to read().
		 */
		if (fstat(fileno(input), &sbuf) < 0) {
			warn("fstat: %s", files[curfile-1]);
			input = next_input();
			continue;
		}
		if (S_ISREG(sbuf.st_mode)) {
			/*
			 * No point in seeking a file that is too
			 * short to begin with.
			 */
			if (sbuf.st_size < skip) {
				skip -= sbuf.st_size;
				input = next_input();
				continue;
			}
			if (fseeko(input, skip, SEEK_SET) < 0) {
				err(1, "fseek:%s", files[curfile-1]);
			}
			/* Done seeking. */
			skip = 0;
			break;
		}

		/*
		 * fgetc seems like it would be slow, but it uses
		 * buffered I/O, so it should be fast enough.
		 */
		flockfile(input);
		while (skip) {
			if (getc_unlocked(input) == EOF) {
				funlockfile(input);
				if (ferror(input)) {
					warn("read: %s", files[curfile-1]);
				}
				input = next_input();
				if (input != NULL) {
					flockfile(input);
				}
				break;
			}
			skip--;
		}
		if (input != NULL)
			funlockfile(input);
	}

	if (head == NULL) {
		add_out(&output_oct_w);
	}

	buffer.navail = 0;
	buffer.prod = 0;
	buffer.cons = 0;

	for (refill(&buffer); buffer.navail > 0; refill(&buffer)) {
		output_t *out;
		int	mx;
		int	j, k;

		/*
		 * If this buffer was the same as last, then just
		 * dump an asterisk.
		 */
		if ((!first) && (buffer.navail >= blocksize) && (!doall)) {
			j = buffer.cons;
			k = j - blocksize;
			for (i = 0; i < blocksize; i++) {
				if (buffer.data[j & buffer.mask] !=
				    buffer.data[k & buffer.mask]) {
					break;
				}
				j++;
				k++;
			}
			if (i == blocksize) {
				if (!same) {
					(void) fputs("*\n", stdout);
					same = B_TRUE;
				}
				buffer.navail -= blocksize;
				offset += blocksize;
				buffer.cons += blocksize;
				buffer.cons &= buffer.mask;
				continue;
			}
		}

		first = B_FALSE;
		same = B_FALSE;
		mx = (buffer.navail > blocksize) ? blocksize : buffer.navail;

		for (out = head; out != NULL; out = out->next) {

			if (out == head) {
				/*LINTED E_SEC_PRINTF_VAR_FMT*/
				(void) printf(afmt, offset);
			} else {
				(void) fputs(cfmt, stdout);
			}
			for (i = 0, j = buffer.cons; i < mx; i += out->width) {
				out->func(&buffer, j);
				j += out->width;
				j &= buffer.mask;
			}
			(void) fputs("\n", stdout);
		}
		buffer.cons += mx;
		buffer.cons &= buffer.mask;
		offset += mx;
		buffer.navail -= mx;
	}
	/*LINTED E_SEC_PRINTF_VAR_FMT*/
	(void) printf(afmt, offset);
	(void) fputs("\n", stdout);
	return (0);
}
