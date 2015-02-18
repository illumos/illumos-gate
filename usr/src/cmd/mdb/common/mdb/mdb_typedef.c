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
 * Copyright (c) 2015 Joyent, Inc. All rights reserved.
 */

/*
 * ::typedef exists to allow a user to create and import auxiliary CTF
 * information for the currently running target. ::typedef is similar to the C
 * typedef keyword. However, ::typedef has no illusions of grandeur. It is not a
 * standards complaint version of C's typedef. For specifics on what it does and
 * does not support, please see the help message for ::typedef later on in this
 * file.
 *
 * In addition to allowing the user to create types, it has a notion of a
 * built-in set of types that a compiler might provide. Currently ::typedef
 * supports both the standard illumos 32-bit and 64-bit environments, mainly
 * LP32 and LP64. These are not present by default; it is up to the user to
 * request that they be inserted.
 *
 * To facilitate this, ::typedef adds all of its type information to an
 * auxiliary CTF container that is a part of the global mdb state. This is
 * abstracted away from ::typedef by the mdb_ctf_* apis. This container is
 * referred to as the synthetic container, as it holds these synthetic types.
 * The synthetic container does not have a parent CTF container. This is rather
 * important to its operation, as a user can end up referencing types that come
 * from many different such containers (eg. different kernel modules). As such,
 * whenever a type is referenced that we do not know about, we search all of the
 * CTF containers that mdb knows about it. If we find it, then that type is
 * imported (along with all of its dependent types) into the synthetic
 * container.
 *
 * Finally, ::typedef can source CTF information from external files with the -r
 * option. This will copy in every type from their container into the synthetic
 * container, because of this the parent and child relationship between
 * containers with parents cannot be maintained.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_list.h>
#include <mdb/mdb_nv.h>

struct parse_node;

#define	PN_F_POINTER	0x01
#define	PN_F_ARRAY	0x02

typedef struct parse_node {
	mdb_list_t		pn_list;	/* list entry, must be first */
	char			*pn_type;	/* name of base type */
	char			*pn_name;	/* name of the member */
	int			pn_flags;	/* flags */
	int			pn_nptrs;	/* number of pointers */
	int			pn_asub;	/* value of array subscript */
} parse_node_t;

typedef struct parse_root {
	mdb_list_t	pr_nodes;	/* list of members */
	int		pr_kind;	/* CTF_K_* */
	const char	*pr_name;	/* entity name */
	const char	*pr_tname;	/* entity typedef */
} parse_root_t;

static int
typedef_valid_identifier(const char *str)
{
	/*
	 * We can't use the standard ctype.h functions because those aren't
	 * necessairly available in kmdb. On the flip side, we only care about
	 * ascii characters here so that isn't too bad.
	 *
	 * C Identifiers have to start with a letter or a _. Afterwards they can
	 * be alphanumeric or an _.
	 */

	if (*str == '\0')
		return (1);

	if (*str != '_' &&
	    (*str < 'A' || *str > 'Z') &&
	    (*str < 'a' || *str > 'z'))
		return (1);
	str++;

	while (*str != '\0') {
		if (*str != '_' &&
		    (*str < '0' || *str > '9') &&
		    (*str < 'A' || *str > 'Z') &&
		    (*str < 'a' || *str > 'z'))
			return (1);
		str++;
	}

	return (0);
}

/*ARGSUSED*/
static int
typedef_list_cb(mdb_ctf_id_t id, void *arg)
{
	char buf[MDB_SYM_NAMLEN];

	/*
	 * The user may have created an anonymous structure or union as part of
	 * running ::typedef. If this is the case, we passed a NULL pointer for
	 * the name into the ctf routines. When we go back and ask for the name
	 * of that, ctf goes through and loops through all the declarations.
	 * This, however correctly, gives us back something undesirable to the
	 * user, eg. the name is simply 'struct' and 'union'. Because a typedef
	 * will always have a non-anonymous name for that, we instead opt to
	 * not include these anonymous names. ctf usefully includes a space as
	 * part of that name.
	 */
	(void) mdb_ctf_type_name(id, buf, sizeof (buf));
	if (strcmp("struct ", buf) != 0 && strcmp("union ", buf) != 0)
		mdb_printf("%s\n", buf);
	return (0);
}

static char *
typedef_join_strings(int nstr, const mdb_arg_t *args, int flags)
{
	int i, size = 0;
	char *ret, *sptr;

	for (i = 0; i <= nstr; i++) {
		/* Always account for the space or the null terminator */
		size += strlen(args[i].a_un.a_str) + 1;
	}
	ret = mdb_alloc(sizeof (char) * size, flags);
	if (ret == NULL)
		return (NULL);
	sptr = ret;
	for (i = 0; i <= nstr; i++) {
		(void) strcpy(sptr, args[i].a_un.a_str);
		sptr += strlen(args[i].a_un.a_str);
		*sptr = ' ';
		sptr++;
	}
	*sptr = '\0';

	return (ret);
}

static int
typedef_list(void)
{
	(void) mdb_ctf_type_iter(MDB_CTF_SYNTHETIC_ITER, typedef_list_cb,
	    NULL);
	return (DCMD_OK);
}

static int
typedef_destroy(void)
{
	if (mdb_ctf_synthetics_reset() != 0) {
		mdb_warn("failed to reset synthetic types");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

/*
 * We've been asked to create the basic types that exist. We accept the
 * following strings to indicate what we should create.
 * - LP32, ILP32 (case insensitive)
 * - LP64
 */
static int
typedef_create(const char *arg)
{
	int kind;

	if (strcasecmp(arg, "LP32") == 0 || strcasecmp(arg, "ILP32") == 0) {
		kind = SYNTHETIC_ILP32;
	} else if (strcasecmp(arg, "LP64") == 0) {
		kind = SYNTHETIC_LP64;
	} else {
		mdb_printf("invalid data model: %s\n", arg);
		return (DCMD_USAGE);
	}

	if (mdb_ctf_synthetics_create_base(kind) != 0) {
		mdb_printf("failed to create intrinsic types, maybe "
		    "they already exist\n");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * Search the current arguments for a complete member declaration. This function
 * modifies the value of defn based on what's necessary for parsing. It returns
 * the appropriate parse node in pnp.
 */
static int
typedef_parse_member(char *defn, char **next, parse_node_t **pnp)
{
	char *c, *name, *array;
	int nptrs = 0;
	parse_node_t *pn;

	c = strchr(defn, ';');
	if (c == NULL) {
		mdb_printf("Cannot find semi-colon to delineate the end "
		    "of a member.\n");
		return (DCMD_ERR);
	}
	*c = '\0';
	*next = c + 1;

	c = strrchr(defn, ' ');
	if (c == NULL) {
		mdb_printf("Missing both a name and a type declaration for "
		    "a member. Instead, found '%s'\n", defn);
		return (DCMD_ERR);
	}
	*c = '\0';
	name = c + 1;
	c--;
	while (*c == '*' || *c == ' ') {
		if (*c == '*')
			nptrs++;
		c--;
	}
	*(c + 1) = '\0';

	pn = mdb_zalloc(sizeof (parse_node_t), UM_SLEEP | UM_GC);
	pn->pn_type = defn;

	/*
	 * Go through and prepare the name field. Note that we still have to
	 * check if this is a pointer or an array. We also need to strip the
	 * ending semi-colon.
	 */
	while (*name == '*') {
		name++;
		nptrs++;
	}

	if ((c = strchr(name, '[')) != NULL) {
		array = c;
		if ((c = strchr(array, ']')) == NULL) {
			mdb_printf("Found the beginning of an array size "
			    "but no closing ']' in %s\n", array);
			return (DCMD_ERR);
		}
		*array = '\0';
		array++;
		*c = '\0';
		pn->pn_flags |= PN_F_ARRAY;
		pn->pn_asub = mdb_strtoull(array);
		if (pn->pn_asub < 0) {
			mdb_printf("Array lengths cannot be negative\n");
			return (DCMD_ERR);
		}
	}

	if (typedef_valid_identifier(name) != 0) {
		mdb_printf("The name %s is not a valid C identifier.\n",
		    name);
		return (DCMD_ERR);
	}

	if (nptrs) {
		pn->pn_flags |= PN_F_POINTER;
		pn->pn_nptrs = nptrs;
	}
	pn->pn_name = name;

	*pnp = pn;
	return (DCMD_OK);
}

/*
 * We're going to parse out our types here. Note that we are not strictly
 * speaking a truely ANSI C compliant parser. Currently we support normal
 * declarations except for the following:
 *   o function pointers
 *   o bit-fields
 */
static int
typedef_parse(char *defn, const char *name, parse_root_t **prp)
{
	int len, ret;
	const char *kind, *basename;
	char *c, *brace;
	parse_root_t *pr;
	parse_node_t *pn;
	mdb_ctf_id_t id;

	pr = mdb_zalloc(sizeof (parse_root_t), UM_SLEEP | UM_GC);
	basename = defn;

	c = strchr(defn, ' ');
	if (c == NULL) {
		mdb_printf("Invalid structure definition. Structure "
		    "must start with either 'struct {' or 'union {'\n");
		return (DCMD_ERR);
	}
	*c = '\0';

	if (strcmp(defn, "struct") == 0)
		pr->pr_kind = CTF_K_STRUCT;
	else if (strcmp(defn, "union") == 0)
		pr->pr_kind = CTF_K_UNION;
	else {
		mdb_printf("Invalid start of definition. "
		    "Expected 'struct' or 'union'. "
		    "Found: '%s'\n", defn);
		return (DCMD_ERR);
	}

	/*
	 * We transform this back to a space so we can validate that a
	 * non-anonymous struct or union name is valid.
	 */
	*c = ' ';

	kind = defn;
	defn = c + 1;
	while (*defn == ' ')
		defn++;

	/* Check whether this is anonymous or not */
	if (*defn != '{') {
		brace = strchr(defn, '{');
		c = brace;
		if (c == NULL) {
			mdb_printf("Missing opening brace for %s definition. "
			    "Expected '{'. "
			    "Found: '%c'\n", kind, *defn);
			return (DCMD_ERR);
		}
		*c = '\0';
		c--;
		while (*c == ' ')
			c--;
		*(c+1) = '\0';
		if (typedef_valid_identifier(defn) != 0) {
			mdb_printf("The name %s is not a valid C identifier.\n",
			    defn);
			return (DCMD_ERR);
		}

		if (mdb_ctf_lookup_by_name(basename, &id) != CTF_ERR) {
			mdb_printf("type name %s already in use\n", basename);
			return (DCMD_ERR);
		}

		pr->pr_name = defn;
		defn = brace;
	} else {
		pr->pr_name = NULL;
	}

	defn++;
	while (*defn == ' ')
		defn++;

	len = strlen(defn);
	if (defn[len-1] != '}') {
		mdb_printf("Missing closing brace for %s declaration. "
		    "Expected '}'.\n");
		return (DCMD_ERR);
	}
	defn[len-1] = '\0';

	/*
	 * Start walking all the arguments, looking for a terminating semicolon
	 * for type definitions.
	 */
	for (;;) {
		ret = typedef_parse_member(defn, &c, &pn);
		if (ret == DCMD_ERR)
			return (DCMD_ERR);

		mdb_list_append(&pr->pr_nodes, pn);

		while (*c == ' ')
			c++;

		if (*c == '\0')
			break;

		defn = c;
	}

	pr->pr_tname = name;
	*prp = pr;

	return (DCMD_OK);
}

/*
 * Make sure that none of the member names overlap and that the type names don't
 * already exist. If we have an array entry that is a VLA, make sure it is the
 * last member and not the only member.
 */
static int
typedef_validate(parse_root_t *pr)
{
	mdb_nv_t nv;
	parse_node_t *pn;
	mdb_ctf_id_t id;
	int count = 0;

	(void) mdb_nv_create(&nv, UM_SLEEP | UM_GC);
	for (pn = mdb_list_next(&pr->pr_nodes); pn != NULL;
	    pn = mdb_list_next(pn)) {
		count++;
		if (mdb_nv_lookup(&nv, pn->pn_name) != NULL) {
			mdb_printf("duplicate name detected: %s\n",
			    pn->pn_name);
			return (DCMD_ERR);
		}

		/*
		 * Our parse tree won't go away before the nv, so it's simpler
		 * to just mark everything external.
		 */
		(void) mdb_nv_insert(&nv, pn->pn_name, NULL, 0, MDB_NV_EXTNAME);

		if (pn->pn_flags & PN_F_ARRAY && pn->pn_asub == 0) {
			if (pr->pr_kind != CTF_K_STRUCT) {
				mdb_printf("Flexible array members are only "
				    "valid in structs.\n");
				return (DCMD_ERR);
			}

			if (&pn->pn_list != pr->pr_nodes.ml_prev) {
				mdb_printf("Flexible array entries are only "
				    "allowed to be the last entry in a "
				    "struct\n");
				return (DCMD_ERR);
			}

			if (count == 1) {
				mdb_printf("Structs must have members aside "
				    "from a flexible member\n");
				return (DCMD_ERR);
			}
		}
	}

	if (mdb_ctf_lookup_by_name(pr->pr_tname, &id) != CTF_ERR) {
		mdb_printf("typedef name %s already exists\n", pr->pr_tname);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
typedef_add(parse_root_t *pr)
{
	parse_node_t *pn;
	mdb_ctf_id_t id, aid, tid, pid;
	mdb_ctf_arinfo_t ar;
	int ii;

	/* Pre-flight checks */
	if (typedef_validate(pr) == DCMD_ERR)
		return (DCMD_ERR);

	if (pr->pr_kind == CTF_K_STRUCT) {
		if (mdb_ctf_add_struct(pr->pr_name, &id) != 0) {
			mdb_printf("failed to create struct for %s\n",
			    pr->pr_tname);
			return (DCMD_ERR);
		}
	} else {
		if (mdb_ctf_add_union(pr->pr_name, &id) != 0) {
			mdb_printf("failed to create union for %s\n",
			    pr->pr_tname);
			return (DCMD_ERR);
		}
	}

	for (pn = mdb_list_next(&pr->pr_nodes); pn != NULL;
	    pn = mdb_list_next(pn)) {

		if (mdb_ctf_lookup_by_name(pn->pn_type, &tid) == CTF_ERR) {
			mdb_printf("failed to add member %s: type %s does "
			    "not exist\n", pn->pn_name, pn->pn_type);
			goto destroy;
		}

		if (pn->pn_flags & PN_F_POINTER) {
			for (ii = 0; ii < pn->pn_nptrs; ii++) {
				if (mdb_ctf_add_pointer(&tid,
				    &pid) != 0) {
					mdb_printf("failed to add a pointer "
					    "type as part of member: %s\n",
					    pn->pn_name);
					goto destroy;
				}
				tid = pid;
			}
		}

		if (pn->pn_flags & PN_F_ARRAY) {
			if (mdb_ctf_lookup_by_name("long", &aid) != 0) {
				mdb_printf("failed to lookup the type 'long' "
				    "for array indexes, are you running mdb "
				    "without a target or using ::typedef -c?");
				goto destroy;
			}

			ar.mta_contents = tid;
			ar.mta_index = aid;
			ar.mta_nelems = pn->pn_asub;

			if (mdb_ctf_add_array(&ar, &tid) != 0) {
				mdb_printf("failed to create array type for "
				    "memeber%s\n", pn->pn_name);
				goto destroy;
			}
		}

		if (mdb_ctf_add_member(&id, pn->pn_name, &tid, NULL) ==
		    CTF_ERR) {
			mdb_printf("failed to create member %s\n",
			    pn->pn_name);
			goto destroy;
		}
	}

	if (mdb_ctf_add_typedef(pr->pr_tname, &id, NULL) != 0) {
		mdb_printf("failed to add typedef for %s\n",
		    pr->pr_tname);
		goto destroy;
	}

	return (DCMD_OK);

destroy:
	return (mdb_ctf_type_delete(&id));
}

static int
typedef_readfile(const char *file)
{
	int ret;

	ret = mdb_ctf_synthetics_from_file(file);
	if (ret != DCMD_OK)
		mdb_warn("failed to create synthetics from file %s\n", file);
	return (ret);
}

static int
typedef_writefile(const char *file)
{
	int ret;

	ret = mdb_ctf_synthetics_to_file(file);
	if (ret != DCMD_OK)
		mdb_warn("failed to write synthetics to file %s", file);
	return (ret);
}

/* ARGSUSED */
int
cmd_typedef(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_ctf_id_t id;
	int i;
	int destroy = 0, list = 0;
	const char *cmode = NULL, *rfile = NULL, *wfile = NULL;
	const char *dst, *src;
	char *dup;
	parse_root_t *pr;

	if (flags & DCMD_ADDRSPEC)
		return (DCMD_USAGE);

	i = mdb_getopts(argc, argv,
	    'd', MDB_OPT_SETBITS, TRUE, &destroy,
	    'l', MDB_OPT_SETBITS, TRUE, &list,
	    'c', MDB_OPT_STR, &cmode,
	    'r', MDB_OPT_STR, &rfile,
	    'w', MDB_OPT_STR, &wfile, NULL);

	argc -= i;
	argv += i;

	/*
	 * All our options are mutually exclusive currently.
	 */
	i = 0;
	if (destroy)
		i++;
	if (cmode != NULL)
		i++;
	if (list)
		i++;
	if (rfile != NULL)
		i++;
	if (wfile != NULL)
		i++;
	if (i > 1)
		return (DCMD_USAGE);

	if ((destroy || cmode != NULL || list || rfile != NULL ||
	    wfile != NULL) && argc != 0)
		return (DCMD_USAGE);

	if (destroy)
		return (typedef_destroy());

	if (cmode)
		return (typedef_create(cmode));

	if (list)
		return (typedef_list());

	if (rfile)
		return (typedef_readfile(rfile));

	if (wfile)
		return (typedef_writefile(wfile));

	if (argc < 2)
		return (DCMD_USAGE);

	/*
	 * Check to see if we are defining a struct or union. Note that we have
	 * to distinguish between struct foo and struct {. All typedef structs
	 * are annonymous structs that are only known by their typedef name. The
	 * same is true with unions. The problem that we have to deal with is
	 * that the ';' character in mdb causes mdb to begin another command. To
	 * work around that fact we require users to put the whole struct
	 * definition in a pair of "" or ''.
	 */
	if (argc == 2 && strchr(argv[0].a_un.a_str, '{') != NULL) {
		dup = mdb_alloc(strlen(argv[0].a_un.a_str) + 1,
		    UM_GC | UM_SLEEP);
		(void) strcpy(dup, argv[0].a_un.a_str);
		if (typedef_parse(dup, argv[1].a_un.a_str, &pr) == DCMD_ERR)
			return (DCMD_ERR);
		if (typedef_add(pr) == DCMD_ERR)
			return (DCMD_ERR);

		return (DCMD_OK);
	}

	/*
	 * Someone could give us something like struct foobar or unsigned int or
	 * even long double imaginary. In this case we end up conjoining all
	 * arguments except the last one into one large string that we look up.
	 */
	if (argc - 1 == 1) {
		src = argv[0].a_un.a_str;
	} else {
		src = typedef_join_strings(argc - 2, argv, UM_GC | UM_SLEEP);
	}

	dst = argv[argc-1].a_un.a_str;

	if (mdb_ctf_lookup_by_name(dst, &id) != -1) {
		mdb_printf("%s already exists\n", dst);
		return (DCMD_ERR);
	}

	if (mdb_ctf_lookup_by_name(src, &id) != 0)  {
		mdb_printf("%s does not exist\n", src);
		return (DCMD_ERR);
	}

	if (mdb_ctf_add_typedef(dst, &id, NULL) != 0) {
		mdb_printf("failed to create typedef\n");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static char typedef_desc[] =
"::typedef operates like the C typedef keyword and creates a synthetic type\n"
"that is usable across mdb just like a type that is embedded in CTF data.\n"
"This includes familiar dcmds like ::print as well as mdb's tab completion\n"
"engine. The \"type\" argument can either be a named structure or union\n"
"declaration, like \"struct proc { int p_id; }\" declartion, an anonymous\n"
"structure or union declaration, like \"struct { int count; }\", or simply\n"
"the name of an existing type, like \"uint64_t\". Either form may refer to\n"
"other types already defined in CTF or a previous ::typedef invocation. When\n"
"debugging binaries without CTF, definitions for intrinsic types may be\n"
"created using the -c option. See the OPTIONS section for more information.\n"
"If a named struct or union is used, then a type will be created for it just\n"
"like in C. This may be used to mimic a forward declaration and an example of\n"
"this is in the EXAMPLES section. Regardless of whether a struct or union is\n"
"anonymous or named, the \"name\" argument is always required.\n"
"\n"
"When declaring anonymous structures and unions, the entire definition must\n"
"be enclosed within \"\" or ''. The ';' is used by mdb to separate commands\n"
"in a similar fashion to the shell. The ';' cannot be escaped, therefore\n"
"quoting your argument is necessary. See the EXAMPLES sections for examples\n"
"of what this looks like.\n"
"\n"
"All member and type names must be valid C identifiers. They must start with\n"
"an underscore or a letter. Subsequent characters are allowed to be letters,\n"
"numbers, or an underscore.\n"
"\n"
"Declaring arrays and any number of pointers in anonymous structures is \n"
"supported. However the following C features are not supported: \n"
"  o function pointers (use a void * instead)\n"
"  o bitfields (use an integer of the appropriate size instead)\n"
"  o packed structures (all structures currently use their natural alignment)\n"
"\n"
"::typedef also allows you to read type definitions from a file. Definitions\n"
"can be read from any ELF file that has a CTF section that libctf can parse\n"
"or any raw CTF data files, such as those that can be created with ::typedef.\n"
"You can check if a file has such a section with elfdump(1). If a binary or\n"
"core dump does not have any type information, but you do have it elsewhere,\n"
"then you can use ::typedef -r to read in that type information.\n"
"\n"
"All built up definitions may be exported as a valid CTF container that can\n"
"be used again with ::typedef -r or anything that uses libctf. To write them\n"
"out, use ::typedef -w and specify the name of a file. For more information\n"
"on the CTF file format, see ctf(4).\n"
"\n";

static char typedef_opts[] =
"  -c model   create intrinsic types based on the specified data model.\n"
"             The INTRINSICS section lists the built-in types and typedefs.\n"
"             The following data models are supported:\n"
"                 o LP64  - Traditional illumos 64-bit program.\n"
"                 o LP32  - Traditional illumos 32-bit program.\n"
"                 o ILP32 - An alternate name for LP32.\n"
"  -d         delete all synthetic types\n"
"  -l         list all synthetic types\n"
"  -r file    import type definitions (CTF) from another ELF file\n"
"  -w file    write all synthetic type definitions out to file\n"
"\n";

static char typedef_examps[] =
"  ::typedef -c LP64\n"
"  ::typedef uint64_t bender_t\n"
"  ::typedef struct proc new_proc_t\n"
"  ::typedef \"union { int frodo; char sam; long gandalf; }\" ringbearer_t;\n"
"  ::typedef \"struct { uintptr_t stone[7]; void **white; }\" gift_t\n"
"  ::typedef \"struct list { struct list *l_next; struct list *l_prev; }\" "
"list_t\n"
"  ::typedef -r /var/tmp/qemu-system-x86_64\n"
"  ::typedef -w defs.ctf"
"\n";

static char typedef_intrins[] =
"The following C types and <stdint.h> typedefs are provided when \n"
"::typedef -c is used\n"
"\n"
"       signed              unsigned              void\n"
"       char                short                 int\n"
"       long                long long             signed char\n"
"       signed short        signed int            signed long\n"
"       singed long long    unsigned char         unsigned short\n"
"       unsigned int        unsigned long         unsigned long long\n"
"       _Bool               float                 double\n"
"       long double         float imaginary       double imaginary\n"
"       long double imaginary                     float complex\n"
"       double complex                            long double complex\n"
"\n"
"       int8_t              int16_t               int32_t\n"
"       int64_t             intptr_t              uint8_t\n"
"       uint16_t            uint32_t              uint64_t\n"
"       uchar_t             ushort_t              uint_t\n"
"       ulong_t             u_longlong_t          ptrdiff_t\n"
"       uintptr_t\n"
"\n";

void
cmd_typedef_help(void)
{
	mdb_printf("%s", typedef_desc);
	(void) mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	(void) mdb_inc_indent(2);
	mdb_printf("%s", typedef_opts);
	(void) mdb_dec_indent(2);
	mdb_printf("%<b>EXAMPLES%</b>\n");
	(void) mdb_inc_indent(2);
	mdb_printf("%s", typedef_examps);
	(void) mdb_dec_indent(2);
	mdb_printf("%<b>INTRINSICS%</b>\n");
	(void) mdb_inc_indent(2);
	mdb_printf("%s", typedef_intrins);
}
