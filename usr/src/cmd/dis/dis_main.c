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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2011 Jason King.  All rights reserved.
 * Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
 * Copyright 2015 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 */

#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <sys/elf_SPARC.h>

#include <libdisasm.h>

#include "dis_target.h"
#include "dis_util.h"
#include "dis_list.h"

int g_demangle;		/* Demangle C++ names */
int g_quiet;		/* Quiet mode */
int g_numeric;		/* Numeric mode */
int g_flags;		/* libdisasm language flags */
int g_doall;		/* true if no functions or sections were given */

dis_namelist_t *g_funclist;	/* list of functions to disassemble, if any */
dis_namelist_t *g_seclist;	/* list of sections to disassemble, if any */

/*
 * Section options for -d, -D, and -s
 */
#define	DIS_DATA_RELATIVE	1
#define	DIS_DATA_ABSOLUTE	2
#define	DIS_TEXT		3

/*
 * libdisasm callback data.  Keeps track of current data (function or section)
 * and offset within that data.
 */
typedef struct dis_buffer {
	dis_tgt_t	*db_tgt;	/* current dis target */
	void		*db_data;	/* function or section data */
	uint64_t	db_addr;	/* address of function start */
	size_t		db_size;	/* size of data */
	uint64_t	db_nextaddr;	/* next address to be read */
} dis_buffer_t;

#define	MINSYMWIDTH	22	/* Minimum width of symbol portion of line */

/*
 * Given a symbol+offset as returned by dis_tgt_lookup(), print an appropriately
 * formatted symbol, based on the offset and current setttings.
 */
void
getsymname(uint64_t addr, const char *symbol, off_t offset, char *buf,
    size_t buflen)
{
	if (symbol == NULL || g_numeric) {
		if (g_flags & DIS_OCTAL)
			(void) snprintf(buf, buflen, "0%llo", addr);
		else
			(void) snprintf(buf, buflen, "0x%llx", addr);
	} else {
		if (g_demangle)
			symbol = dis_demangle(symbol);

		if (offset == 0)
			(void) snprintf(buf, buflen, "%s", symbol);
		else if (g_flags & DIS_OCTAL)
			(void) snprintf(buf, buflen, "%s+0%o", symbol, offset);
		else
			(void) snprintf(buf, buflen, "%s+0x%x", symbol, offset);
	}
}

/*
 * Determine if we are on an architecture with fixed-size instructions,
 * and if so, what size they are.
 */
static int
insn_size(dis_handle_t *dhp)
{
	int min = dis_min_instrlen(dhp);
	int max = dis_max_instrlen(dhp);

	if (min == max)
		return (min);

	return (0);
}

/*
 * The main disassembly routine.  Given a fixed-sized buffer and starting
 * address, disassemble the data using the supplied target and libdisasm handle.
 */
void
dis_data(dis_tgt_t *tgt, dis_handle_t *dhp, uint64_t addr, void *data,
    size_t datalen)
{
	dis_buffer_t db = { 0 };
	char buf[BUFSIZE];
	char symbuf[BUFSIZE];
	const char *symbol;
	const char *last_symbol;
	off_t symoffset;
	int i;
	int bytesperline;
	size_t symsize;
	int isfunc;
	size_t symwidth = 0;
	int ret;
	int insz = insn_size(dhp);

	db.db_tgt = tgt;
	db.db_data = data;
	db.db_addr = addr;
	db.db_size = datalen;

	dis_set_data(dhp, &db);

	if ((bytesperline = dis_max_instrlen(dhp)) > 6)
		bytesperline = 6;

	symbol = NULL;

	while (addr < db.db_addr + db.db_size) {

		ret = dis_disassemble(dhp, addr, buf, BUFSIZE);
		if (ret != 0 && insz > 0) {
			/*
			 * Since we know instructions are fixed size, we
			 * always know the address of the next instruction
			 */
			(void) snprintf(buf, sizeof (buf),
			    "*** invalid opcode ***");
			db.db_nextaddr = addr + insz;

		} else if (ret != 0) {
			off_t next;

			(void) snprintf(buf, sizeof (buf),
			    "*** invalid opcode ***");

			/*
			 * On architectures with variable sized instructions
			 * we have no way to figure out where the next
			 * instruction starts if we encounter an invalid
			 * instruction.  Instead we print the rest of the
			 * instruction stream as hex until we reach the
			 * next valid symbol in the section.
			 */
			if ((next = dis_tgt_next_symbol(tgt, addr)) == 0) {
				db.db_nextaddr = db.db_addr + db.db_size;
			} else {
				if (next > db.db_size)
					db.db_nextaddr = db.db_addr +
					    db.db_size;
				else
					db.db_nextaddr = addr + next;
			}
		}

		/*
		 * Print out the line as:
		 *
		 * 	address:	bytes	text
		 *
		 * If there are more than 6 bytes in any given instruction,
		 * spread the bytes across two lines.  We try to get symbolic
		 * information for the address, but if that fails we print out
		 * the numeric address instead.
		 *
		 * We try to keep the address portion of the text aligned at
		 * MINSYMWIDTH characters.  If we are disassembling a function
		 * with a long name, this can be annoying.  So we pick a width
		 * based on the maximum width that the current symbol can be.
		 * This at least produces text aligned within each function.
		 */
		last_symbol = symbol;
		symbol = dis_tgt_lookup(tgt, addr, &symoffset, 1, &symsize,
		    &isfunc);
		if (symbol == NULL) {
			symbol = dis_find_section(tgt, addr, &symoffset);
			symsize = symoffset;
		}

		if (symbol != last_symbol)
			getsymname(addr, symbol, symsize, symbuf,
			    sizeof (symbuf));

		symwidth = MAX(symwidth, strlen(symbuf));
		getsymname(addr, symbol, symoffset, symbuf, sizeof (symbuf));

		/*
		 * If we've crossed a new function boundary, print out the
		 * function name on a blank line.
		 */
		if (!g_quiet && symoffset == 0 && symbol != NULL && isfunc)
			(void) printf("%s()\n", symbol);

		(void) printf("    %s:%*s ", symbuf,
		    symwidth - strlen(symbuf), "");

		/* print bytes */
		for (i = 0; i < MIN(bytesperline, (db.db_nextaddr - addr));
		    i++) {
			int byte = *((uchar_t *)data + (addr - db.db_addr) + i);
			if (g_flags & DIS_OCTAL)
				(void) printf("%03o ", byte);
			else
				(void) printf("%02x ", byte);
		}

		/* trailing spaces for missing bytes */
		for (; i < bytesperline; i++) {
			if (g_flags & DIS_OCTAL)
				(void) printf("    ");
			else
				(void) printf("   ");
		}

		/* contents of disassembly */
		(void) printf(" %s", buf);

		/* excess bytes that spill over onto subsequent lines */
		for (; i < db.db_nextaddr - addr; i++) {
			int byte = *((uchar_t *)data + (addr - db.db_addr) + i);
			if (i % bytesperline == 0)
				(void) printf("\n    %*s  ", symwidth, "");
			if (g_flags & DIS_OCTAL)
				(void) printf("%03o ", byte);
			else
				(void) printf("%02x ", byte);
		}

		(void) printf("\n");

		addr = db.db_nextaddr;
	}
}

/*
 * libdisasm wrapper around symbol lookup.  Invoke the target-specific lookup
 * function, and convert the result using getsymname().
 */
int
do_lookup(void *data, uint64_t addr, char *buf, size_t buflen, uint64_t *start,
    size_t *symlen)
{
	dis_buffer_t *db = data;
	const char *symbol;
	off_t offset;
	size_t size;

	/*
	 * If NULL symbol is returned, getsymname takes care of
	 * printing appropriate address in buf instead of symbol.
	 */
	symbol = dis_tgt_lookup(db->db_tgt, addr, &offset, 0, &size, NULL);

	if (buf != NULL)
		getsymname(addr, symbol, offset, buf, buflen);

	if (start != NULL)
		*start = addr - offset;
	if (symlen != NULL)
		*symlen = size;

	if (symbol == NULL)
		return (-1);

	return (0);
}

/*
 * libdisasm wrapper around target reading.  libdisasm will always read data
 * in order, so update our current offset within the buffer appropriately.
 * We only support reading from within the current object; libdisasm should
 * never ask us to do otherwise.
 */
int
do_read(void *data, uint64_t addr, void *buf, size_t len)
{
	dis_buffer_t *db = data;
	size_t offset;

	if (addr < db->db_addr || addr >= db->db_addr + db->db_size)
		return (-1);

	offset = addr - db->db_addr;
	len = MIN(len, db->db_size - offset);

	(void) memcpy(buf, (char *)db->db_data + offset, len);

	db->db_nextaddr = addr + len;

	return (len);
}

/*
 * Routine to dump raw data in a human-readable format.  Used by the -d and -D
 * options.  We model our output after the xxd(1) program, which gives nicely
 * formatted output, along with an ASCII translation of the result.
 */
void
dump_data(uint64_t addr, void *data, size_t datalen)
{
	uintptr_t curaddr = addr & (~0xf);
	uint8_t *bytes = data;
	int i;
	int width;

	/*
	 * Determine if the address given to us fits in 32-bit range, in which
	 * case use a 4-byte width.
	 */
	if (((addr + datalen) & 0xffffffff00000000ULL) == 0ULL)
		width = 8;
	else
		width = 16;

	while (curaddr < addr + datalen) {
		/*
		 * Display leading address
		 */
		(void) printf("%0*x: ", width, curaddr);

		/*
		 * Print out data in two-byte chunks.  If the current address
		 * is before the starting address or after the end of the
		 * section, print spaces.
		 */
		for (i = 0; i < 16; i++) {
			if (curaddr + i < addr ||curaddr + i >= addr + datalen)
				(void) printf("  ");
			else
				(void) printf("%02x",
				    bytes[curaddr + i - addr]);

			if (i & 1)
				(void) printf(" ");
		}

		(void) printf(" ");

		/*
		 * Print out the ASCII representation
		 */
		for (i = 0; i < 16; i++) {
			if (curaddr + i < addr ||
			    curaddr + i >= addr + datalen) {
				(void) printf(" ");
			} else {
				uint8_t byte = bytes[curaddr + i - addr];
				if (isprint(byte))
					(void) printf("%c", byte);
				else
					(void) printf(".");
			}
		}

		(void) printf("\n");

		curaddr += 16;
	}
}

/*
 * Disassemble a section implicitly specified as part of a file.  This function
 * is called for all sections when no other flags are specified.  We ignore any
 * data sections, and print out only those sections containing text.
 */
void
dis_text_section(dis_tgt_t *tgt, dis_scn_t *scn, void *data)
{
	dis_handle_t *dhp = data;

	/* ignore data sections */
	if (!dis_section_istext(scn))
		return;

	if (!g_quiet)
		(void) printf("\nsection %s\n", dis_section_name(scn));

	dis_data(tgt, dhp, dis_section_addr(scn), dis_section_data(scn),
	    dis_section_size(scn));
}

/*
 * Structure passed to dis_named_{section,function} which keeps track of both
 * the target and the libdisasm handle.
 */
typedef struct callback_arg {
	dis_tgt_t	*ca_tgt;
	dis_handle_t	*ca_handle;
} callback_arg_t;

/*
 * Disassemble a section explicitly named with -s, -d, or -D.  The 'type'
 * argument contains the type of argument given.  Pass the data onto the
 * appropriate helper routine.
 */
void
dis_named_section(dis_scn_t *scn, int type, void *data)
{
	callback_arg_t *ca = data;

	if (!g_quiet)
		(void) printf("\nsection %s\n", dis_section_name(scn));

	switch (type) {
	case DIS_DATA_RELATIVE:
		dump_data(0, dis_section_data(scn), dis_section_size(scn));
		break;
	case DIS_DATA_ABSOLUTE:
		dump_data(dis_section_addr(scn), dis_section_data(scn),
		    dis_section_size(scn));
		break;
	case DIS_TEXT:
		dis_data(ca->ca_tgt, ca->ca_handle, dis_section_addr(scn),
		    dis_section_data(scn), dis_section_size(scn));
		break;
	}
}

/*
 * Disassemble a function explicitly specified with '-F'.  The 'type' argument
 * is unused.
 */
/* ARGSUSED */
void
dis_named_function(dis_func_t *func, int type, void *data)
{
	callback_arg_t *ca = data;

	dis_data(ca->ca_tgt, ca->ca_handle, dis_function_addr(func),
	    dis_function_data(func), dis_function_size(func));
}

/*
 * Disassemble a complete file.  First, we determine the type of the file based
 * on the ELF machine type, and instantiate a version of the disassembler
 * appropriate for the file.  We then resolve any named sections or functions
 * against the file, and iterate over the results (or all sections if no flags
 * were specified).
 */
void
dis_file(const char *filename)
{
	dis_tgt_t *tgt, *current;
	dis_scnlist_t *sections;
	dis_funclist_t *functions;
	dis_handle_t *dhp;
	GElf_Ehdr ehdr;

	/*
	 * First, initialize the target
	 */
	if ((tgt = dis_tgt_create(filename)) == NULL)
		return;

	if (!g_quiet)
		(void) printf("disassembly for %s\n\n",  filename);

	/*
	 * A given file may contain multiple targets (if it is an archive, for
	 * example).  We iterate over all possible targets if this is the case.
	 */
	for (current = tgt; current != NULL; current = dis_tgt_next(current)) {
		dis_tgt_ehdr(current, &ehdr);

		/*
		 * Eventually, this should probably live within libdisasm, and
		 * we should be able to disassemble targets from different
		 * architectures.  For now, we only support objects as the
		 * native machine type.
		 */
		switch (ehdr.e_machine) {
		case EM_SPARC:
			if (ehdr.e_ident[EI_CLASS] != ELFCLASS32 ||
			    ehdr.e_ident[EI_DATA] != ELFDATA2MSB) {
				warn("invalid E_IDENT field for SPARC object");
				return;
			}
			g_flags |= DIS_SPARC_V8;
			break;

		case EM_SPARC32PLUS:
		{
			uint64_t flags = ehdr.e_flags & EF_SPARC_32PLUS_MASK;

			if (ehdr.e_ident[EI_CLASS] != ELFCLASS32 ||
			    ehdr.e_ident[EI_DATA] != ELFDATA2MSB) {
				warn("invalid E_IDENT field for SPARC object");
				return;
			}

			if (flags != 0 &&
			    (flags & (EF_SPARC_32PLUS | EF_SPARC_SUN_US1 |
			    EF_SPARC_SUN_US3)) != EF_SPARC_32PLUS)
				g_flags |= DIS_SPARC_V9 | DIS_SPARC_V9_SGI;
			else
				g_flags |= DIS_SPARC_V9;
			break;
		}

		case EM_SPARCV9:
			if (ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
			    ehdr.e_ident[EI_DATA] != ELFDATA2MSB) {
				warn("invalid E_IDENT field for SPARC object");
				return;
			}

			g_flags |= DIS_SPARC_V9 | DIS_SPARC_V9_SGI;
			break;

		case EM_386:
			g_flags |= DIS_X86_SIZE32;
			break;

		case EM_AMD64:
			g_flags |= DIS_X86_SIZE64;
			break;

		case EM_S370:
			g_flags |= DIS_S370;

			if (ehdr.e_ident[EI_CLASS] != ELFCLASS32 ||
			    ehdr.e_ident[EI_DATA] != ELFDATA2MSB) {
				warn("invalid E_IDENT field for S370 object");
				return;
			}
			break;

		case EM_S390:
			/*
			 * Both 390 and z/Architecture use EM_S390, the only
			 * differences is the class: ELFCLASS32 for plain
			 * old s390 and ELFCLASS64 for z/Architecture (aka.
			 * s390x).
			 */
			if (ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
				g_flags |= DIS_S390_31;
			} else if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
				g_flags |= DIS_S390_64;
			} else {
				warn("invalid E_IDENT field for S390 object");
				return;
			}

			if (ehdr.e_ident[EI_DATA] != ELFDATA2MSB) {
				warn("invalid E_IDENT field for S390 object");
				return;
			}
			break;

		default:
			die("%s: unsupported ELF machine 0x%x", filename,
			    ehdr.e_machine);
		}

		/*
		 * If ET_REL (.o), printing immediate symbols is likely to
		 * result in garbage, as symbol lookups on unrelocated
		 * immediates find false and useless matches.
		 */

		if (ehdr.e_type == ET_REL)
			g_flags |= DIS_NOIMMSYM;

		if (!g_quiet && dis_tgt_member(current) != NULL)
			(void) printf("\narchive member %s\n",
			    dis_tgt_member(current));

		/*
		 * Instantiate a libdisasm handle based on the file type.
		 */
		if ((dhp = dis_handle_create(g_flags, current, do_lookup,
		    do_read)) == NULL)
			die("%s: failed to initialize disassembler: %s",
			    filename, dis_strerror(dis_errno()));

		if (g_doall) {
			/*
			 * With no arguments, iterate over all sections and
			 * disassemble only those that contain text.
			 */
			dis_tgt_section_iter(current, dis_text_section, dhp);
		} else {
			callback_arg_t ca;

			ca.ca_tgt = current;
			ca.ca_handle = dhp;

			/*
			 * If sections or functions were explicitly specified,
			 * resolve those names against the object, and iterate
			 * over just the resulting data.
			 */
			sections = dis_namelist_resolve_sections(g_seclist,
			    current);
			functions = dis_namelist_resolve_functions(g_funclist,
			    current);

			dis_scnlist_iter(sections, dis_named_section, &ca);
			dis_funclist_iter(functions, dis_named_function, &ca);

			dis_scnlist_destroy(sections);
			dis_funclist_destroy(functions);
		}

		dis_handle_destroy(dhp);
	}

	dis_tgt_destroy(tgt);
}

void
usage(void)
{
	(void) fprintf(stderr, "usage: dis [-CVoqn] [-d sec] \n");
	(void) fprintf(stderr, "\t[-D sec] [-F function] [-t sec] file ..\n");
	exit(2);
}

typedef struct lib_node {
	char *path;
	struct lib_node *next;
} lib_node_t;

int
main(int argc, char **argv)
{
	int optchar;
	int i;
	lib_node_t *libs = NULL;

	g_funclist = dis_namelist_create();
	g_seclist = dis_namelist_create();

	while ((optchar = getopt(argc, argv, "Cd:D:F:l:Lot:Vqn")) != -1) {
		switch (optchar) {
		case 'C':
			g_demangle = 1;
			break;
		case 'd':
			dis_namelist_add(g_seclist, optarg, DIS_DATA_RELATIVE);
			break;
		case 'D':
			dis_namelist_add(g_seclist, optarg, DIS_DATA_ABSOLUTE);
			break;
		case 'F':
			dis_namelist_add(g_funclist, optarg, 0);
			break;
		case 'l': {
			/*
			 * The '-l foo' option historically would attempt to
			 * disassemble '$LIBDIR/libfoo.a'.  The $LIBDIR
			 * environment variable has never been supported or
			 * documented for our linker.  However, until this
			 * option is formally EOLed, we have to support it.
			 */
			char *dir;
			lib_node_t *node;
			size_t len;

			if ((dir = getenv("LIBDIR")) == NULL ||
			    dir[0] == '\0')
				dir = "/usr/lib";
			node = safe_malloc(sizeof (lib_node_t));
			len = strlen(optarg) + strlen(dir) + sizeof ("/lib.a");
			node->path = safe_malloc(len);

			(void) snprintf(node->path, len, "%s/lib%s.a", dir,
			    optarg);
			node->next = libs;
			libs = node;
			break;
		}
		case 'L':
			/*
			 * The '-L' option historically would attempt to read
			 * the .debug section of the target to determine source
			 * line information in order to annotate the output.
			 * No compiler has emitted these sections in many years,
			 * and the option has never done what it purported to
			 * do.  We silently consume the option for
			 * compatibility.
			 */
			break;
		case 'n':
			g_numeric = 1;
			break;
		case 'o':
			g_flags |= DIS_OCTAL;
			break;
		case 'q':
			g_quiet = 1;
			break;
		case 't':
			dis_namelist_add(g_seclist, optarg, DIS_TEXT);
			break;
		case 'V':
			(void) printf("Solaris disassembler version 1.0\n");
			return (0);
		default:
			usage();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0 && libs == NULL) {
		warn("no objects specified");
		usage();
	}

	if (dis_namelist_empty(g_funclist) && dis_namelist_empty(g_seclist))
		g_doall = 1;

	/*
	 * See comment for 'l' option, above.
	 */
	while (libs != NULL) {
		lib_node_t *node = libs->next;

		dis_file(libs->path);
		free(libs->path);
		free(libs);
		libs = node;
	}

	for (i = 0; i < argc; i++)
		dis_file(argv[i]);

	dis_namelist_destroy(g_funclist);
	dis_namelist_destroy(g_seclist);

	return (g_error);
}
