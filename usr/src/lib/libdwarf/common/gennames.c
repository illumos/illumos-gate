/*
    Copyright 2009-2010 SN Systems Ltd. All rights reserved.
    Portions Copyright 2009-2018 David Anderson. All rights reserved.

    This program is free software; you can redistribute it and/or modify it
    under the terms of version 2.1 of the GNU Lesser General Public License
    as published by the Free Software Foundation.

    This program is distributed in the hope that it would be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    Further, this software is distributed without any warranty that it is
    free of the rightful claim of any third person regarding infringement
    or the like.  Any license provided herein, whether implied or
    otherwise, applies only to this software file.  Patent licenses, if
    any, provided herein do not apply to combinations of this program with
    other software, or any other product whatsoever.

    You should have received a copy of the GNU Lesser General Public
    License along with this program; if not, write the Free Software
    Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston MA 02110-1301,
    USA.

*/

#include "config.h"
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif /* _WIN32 */

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include <errno.h>   /* For errno declaration. */
#include <ctype.h>
#include <string.h>
#include "dwgetopt.h"
#include "libdwarf_version.h" /* for DW_VERSION_DATE_STR */

/*  gennames.c
    Prints routines to return constant name for the associated value
    (such as the TAG name string for a particular tag).

    The input is dwarf.h
    For each set of names with a common prefix, we create a routine
    to return the name given the value.
    Also print header file that gives prototypes of routines.
    To handle cases where there are multiple names for a single
    value (DW_AT_* has some due to ambiguities in the DWARF2 spec)
    we take the first of a given value as the definitive name.
    TAGs, Attributes, etc are given distinct checks.

    There are multiple output files as some people find one
    form more pleasant than the other.

    The doprinting argument is so that when used by tag_tree.c,
    and tag_attr.c that we don't get irritating messages on stderr
    when those dwarfdump built-time applications are run.

    Some compilers generate better code for switch statements than
    others, so the -s and -t options let the user decide which
    is better for their compiler (when building dwarfdump):
    a simple switch or code doing binary search.
    This choice affects the runtime speed of dwarfdump.  */

typedef int boolean;
#define TRUE 1
#define FALSE 0
#define FAILED 1

static void OpenAllFiles(void);
static void WriteFileTrailers(void);
static void CloseAllFiles(void);
static void GenerateInitialFileLines(void);
static void GenerateOneSet(void);
#ifdef TRACE_ARRAY
static void PrintArray(void);
#endif /* TRACE_ARRAY */
static boolean is_skippable_line(char *pLine);
static void ParseDefinitionsAndWriteOutput(void);

/* We don't need really long lines: the input file is simple. */
#define MAX_LINE_SIZE 1000
/* We don't need a variable array size, it just has to be big enough. */
#define ARRAY_SIZE 300

#define MAX_NAME_LEN 64

/* To store entries from dwarf.h */
typedef struct {
    char     name[MAX_NAME_LEN];  /* short name */
    unsigned value; /* value */
    /* Original spot in array.   Lets us guarantee a stable sort. */
    unsigned original_position;
} array_data;

/*  A group_array is a grouping from dwarf.h.
    All the TAGs are one group, all the
    FORMs are another group, and so on. */
static array_data group_array[ARRAY_SIZE];
static unsigned array_count = 0;

typedef int (*compfn)(const void *,const void *);
static int Compare(array_data *,array_data *);

static const char *prefix_root = "DW_";
static const unsigned prefix_root_len = 3;

/* f_dwarf_in is the input dwarf.h. The others are output files. */
static FILE *f_dwarf_in;
static FILE *f_names_h;
static FILE *f_names_c;
static FILE *f_names_enum_h;
static FILE *f_names_new_h;

/* Size unchecked, but large enough. */
static char prefix[200] = "";

static const char *usage[] = {
    "Usage: gennames <options>",
    "    -i input-table-path",
    "    -o output-table-path",
    "    -s use 'switch' in generation",
    "    -t use 'tables' in generation",
    "",
};

static void
print_args(int argc, char *argv[])
{
    int index;
    printf("Arguments: ");
    for (index = 1; index < argc; ++index) {
        printf("%s ",argv[index]);
    }
    printf("\n");
}


char *program_name = 0;
static char *input_name = 0;
static char *output_name = 0;
static boolean use_switch = TRUE;
static boolean use_tables = FALSE;

static void
print_version(const char * name)
{
#ifdef _DEBUG
    const char *acType = "Debug";
#else
    const char *acType = "Release";
#endif /* _DEBUG */

    printf("%s [%s %s]\n",name,DW_VERSION_DATE_STR,acType);
}


static void
print_usage_message(const char *options[])
{
    int index;
    for (index = 0; *options[index]; ++index) {
        printf("%s\n",options[index]);
    }
}


/* process arguments */
static void
process_args(int argc, char *argv[])
{
    int c = 0;
    boolean usage_error = FALSE;

    program_name = argv[0];

    while ((c = dwgetopt(argc, argv, "i:o:st")) != EOF) {
        switch (c) {
        case 'i':
            input_name = dwoptarg;
            break;
        case 'o':
            output_name = dwoptarg;
            break;
        case 's':
            use_switch = TRUE;
            use_tables = FALSE;
            break;
        case 't':
            use_switch = FALSE;
            use_tables = TRUE;
            break;
        default:
            usage_error = TRUE;
            break;
        }
    }

    if (usage_error || 1 == dwoptind || dwoptind != argc) {
        print_usage_message(usage);
        exit(FAILED);
    }
}

int
main(int argc,char **argv)
{
    print_version(argv[0]);
    print_args(argc,argv);
    process_args(argc,argv);
    OpenAllFiles();
    GenerateInitialFileLines();
    ParseDefinitionsAndWriteOutput();
    WriteFileTrailers();
    CloseAllFiles();
    return 0;
}

/* Print the array used to hold the tags, attributes values */
#ifdef TRACE_ARRAY
static void
PrintArray(void)
{
    int i;
    for (i = 0; i < array_count; ++i) {
        printf("%d: Name %s_%s, Value 0x%04x\n",
            i,prefix,
            array[i].name,
            array[i].value);
    }
}
#endif /* TRACE_ARRAY */

/* By including original position we force a stable sort */
static int
Compare(array_data *elem1,array_data *elem2)
{
    if (elem1->value < elem2->value) {
        return -1;
    }
    if (elem1->value > elem2->value) {
        return 1;
    }
    if (elem1->original_position < elem2->original_position) {
        return -1;
    }
    if (elem1->original_position > elem2->original_position) {
        return 1;
    }
    return 0;
}

static FILE *
open_path(const char *base, const char *file, const char *direction)
{
    FILE *f = 0;
    /*  POSIX PATH_MAX  would suffice, normally stdio BUFSIZ is larger
        than PATH_MAX */
    static char path_name[BUFSIZ];

    /* 2 == space for / and NUL */
    size_t netlen = strlen(file) +strlen(base) + 2;

    if (netlen >= BUFSIZ) {
        printf("Error opening '%s/%s', name too long\n",base,file);
        exit(1);
    }

    strcpy(path_name,base);
    strcat(path_name,"/");
    strcat(path_name,file);

    f = fopen(path_name,direction);
    if (!f) {
        printf("Error opening '%s'\n",path_name);
        exit(1);
    }
    return f;
}

/* Open files and write the basic headers */
static void
OpenAllFiles(void)
{
    const char *dwarf_h      = "dwarf.h";
    const char *names_h      = "dwarf_names.h";
    const char *names_c      = "dwarf_names.c";
    const char *names_enum_h = "dwarf_names_enum.h";
    const char *names_new_h  = "dwarf_names_new.h";

    f_dwarf_in = open_path(input_name,dwarf_h,"r");
    f_names_enum_h = open_path(output_name,names_enum_h,"w");
    f_names_new_h = open_path(output_name,names_new_h,"w");
    f_names_h = open_path(output_name,names_h,"w");
    f_names_c = open_path(output_name,names_c,"w");
}

static void
GenerateInitialFileLines(void)
{
    /* Generate entries for 'dwarf_names_enum.h' */
    fprintf(f_names_enum_h,"/* Automatically generated, do not edit. */\n");
    fprintf(f_names_enum_h,"/* Generated sourcedate %s */\n",
        DW_VERSION_DATE_STR);
    fprintf(f_names_enum_h,"\n/* BEGIN FILE */\n\n");
    fprintf(f_names_enum_h,"#ifndef __DWARF_NAMES_ENUM_H__\n");
    fprintf(f_names_enum_h,"#define __DWARF_NAMES_ENUM_H__\n");

    /* Generate entries for 'dwarf_names_new.h' */
    fprintf(f_names_new_h,"/* Automatically generated, do not edit. */\n");
    fprintf(f_names_new_h,"/* Generated sourcedate %s */\n",
        DW_VERSION_DATE_STR);
    fprintf(f_names_new_h,"\n/* BEGIN FILE */\n\n");
    fprintf(f_names_new_h,"/* define DWARF_PRINT_PREFIX before this\n");
    fprintf(f_names_new_h,"   point if you wish to.  */\n");
    fprintf(f_names_new_h,"#ifndef DWARF_PRINT_PREFIX\n");
    fprintf(f_names_new_h,"#define DWARF_PRINT_PREFIX dwarf_\n");
    fprintf(f_names_new_h,"#endif\n");
    fprintf(f_names_new_h,"#define dw_glue(x,y) x##y\n");
    fprintf(f_names_new_h,"#define dw_glue2(x,y) dw_glue(x,y)\n");
    fprintf(f_names_new_h,"#define DWPREFIX(x) dw_glue2(DWARF_PRINT_PREFIX,x)\n");

    /* Generate entries for 'dwarf_names.h' */
    fprintf(f_names_h,"/* Generated routines, do not edit. */\n");
    fprintf(f_names_h,"/* Generated sourcedate %s */\n",
        DW_VERSION_DATE_STR);
    fprintf(f_names_h,"\n/* BEGIN FILE */\n\n");

    fprintf(f_names_h,"#ifndef DWARF_NAMES_H\n");
    fprintf(f_names_h,"#define DWARF_NAMES_H\n\n");
    fprintf(f_names_h,"#ifdef __cplusplus\n");
    fprintf(f_names_h,"extern \"C\" {\n");
    fprintf(f_names_h,"#endif /* __cplusplus */\n\n");

    /* Generate entries for 'dwarf_names.c' */
    fprintf(f_names_c,"/* Generated routines, do not edit. */\n");
    fprintf(f_names_c,"/* Generated sourcedate %s */\n",
        DW_VERSION_DATE_STR);
    fprintf(f_names_c,"\n/* BEGIN FILE */\n\n");
    fprintf(f_names_c,"#include \"dwarf.h\"\n\n");
    fprintf(f_names_c,"#include \"libdwarf.h\"\n\n");

    if (use_tables) {
        fprintf(f_names_c,"typedef struct Names_Data {\n");
        fprintf(f_names_c,"    const char *l_name; \n");
        fprintf(f_names_c,"    unsigned    value;  \n");
        fprintf(f_names_c,"} Names_Data;\n\n");

        /* Generate code to find an entry */
        fprintf(f_names_c,"/* Use standard binary search to get entry */\n");
        fprintf(f_names_c,"static int\nfind_entry(Names_Data *table,"
            "const int last,unsigned value, const char **s_out)\n");
        fprintf(f_names_c,"{\n");
        fprintf(f_names_c,"    int low = 0;\n");
        fprintf(f_names_c,"    int high = last;\n");
        fprintf(f_names_c,"    int mid;\n");
        fprintf(f_names_c,"    unsigned maxval = table[last-1].value;\n");
        fprintf(f_names_c,"\n");
        fprintf(f_names_c,"    if (value > maxval) {\n");
        fprintf(f_names_c,"        return DW_DLV_NO_ENTRY;\n");
        fprintf(f_names_c,"    }\n");
        fprintf(f_names_c,"    while (low < high) {\n");
        fprintf(f_names_c,"        mid = low + ((high - low) / 2);\n");
        fprintf(f_names_c,"        if(mid == last) {\n");
        fprintf(f_names_c,"            break;\n");
        fprintf(f_names_c,"        }\n");
        fprintf(f_names_c,"        if (table[mid].value < value) {\n");
        fprintf(f_names_c,"            low = mid + 1;\n");
        fprintf(f_names_c,"        }\n");
        fprintf(f_names_c,"        else {\n");
        fprintf(f_names_c,"              high = mid;\n");
        fprintf(f_names_c,"        }\n");
        fprintf(f_names_c,"    }\n");
        fprintf(f_names_c,"\n");
        fprintf(f_names_c,"    if (low < last && table[low].value == value) {\n");
        fprintf(f_names_c,"        /* Found: low is the entry */\n");
        fprintf(f_names_c,"      *s_out = table[low].l_name;\n");
        fprintf(f_names_c,"      return DW_DLV_OK;\n");
        fprintf(f_names_c,"    }\n");
        fprintf(f_names_c,"    return DW_DLV_NO_ENTRY;\n");
        fprintf(f_names_c,"}\n");
        fprintf(f_names_c,"\n");
    }
}

/* Close files and write basic trailers */
static void
WriteFileTrailers(void)
{
    /* Generate entries for 'dwarf_names_enum.h' */
    fprintf(f_names_enum_h,"#endif /* __DWARF_NAMES_ENUM_H__ */\n");
    fprintf(f_names_enum_h,"\n/* END FILE */\n");

    /* Generate entries for 'dwarf_names_new.h' */
    fprintf(f_names_new_h,"\n/* END FILE */\n");

    /* Generate entries for 'dwarf_names.h' */

    fprintf(f_names_h,"\n#ifdef __cplusplus\n");
    fprintf(f_names_h,"}\n");
    fprintf(f_names_h,"#endif /* __cplusplus */\n\n");
    fprintf(f_names_h,"#endif /* DWARF_NAMES_H */\n");
    fprintf(f_names_h,"\n/* END FILE */\n");

    /* Generate entries for 'dwarf_names.c' */
    fprintf(f_names_c,"\n/* END FILE */\n");
}

static void
CloseAllFiles(void)
{
    fclose(f_dwarf_in);
    fclose(f_names_enum_h);
    fclose(f_names_new_h);
    fclose(f_names_h);
    fclose(f_names_c);
}

/* Write the table and code for a common set of names */
static void
GenerateOneSet(void)
{
    unsigned u;
    unsigned prev_value = 0;
    size_t len;
    char *prefix_id = prefix + prefix_root_len;
    unsigned actual_array_count = 0;

#ifdef TRACE_ARRAY
    printf("List before sorting:\n");
    PrintArray();
#endif /* TRACE_ARRAY */

    /*  Sort the array, because the values in 'libdwarf.h' are not in
        ascending order; if we use '-t' we must be sure the values are
        sorted, for the binary search to work properly.
        We want a stable sort, hence mergesort.  */
    qsort((void *)&group_array,array_count,sizeof(array_data),(compfn)Compare);

#ifdef TRACE_ARRAY
    printf("\nList after sorting:\n");
    PrintArray();
#endif /* TRACE_ARRAY */

    /* Generate entries for 'dwarf_names_enum.h' */
    fprintf(f_names_enum_h,"\nenum Dwarf_%s_e {\n",prefix_id);

    /* Generate entries for 'dwarf_names_new.h' */
    fprintf(f_names_new_h,"int DWPREFIX(get_%s_name) (unsigned int, const char **);\n",prefix_id);

    /* Generate entries for 'dwarf_names.h' and libdwarf.h */
    fprintf(f_names_h,"extern int dwarf_get_%s_name(unsigned int /*val_in*/, const char ** /*s_out */);\n",prefix_id);

    /* Generate code for 'dwarf_names.c' */
    fprintf(f_names_c,"/* ARGSUSED */\n");
    fprintf(f_names_c,"int\n");
    fprintf(f_names_c,"dwarf_get_%s_name (unsigned int val,const char ** s_out)\n",prefix_id);
    fprintf(f_names_c,"{\n");
    if (use_tables) {
        fprintf(f_names_c,"    static Names_Data Dwarf_%s_n[] = {\n",prefix_id);
    } else {
        fprintf(f_names_c,"    switch (val) {\n");
    }

    for (u = 0; u < array_count; ++u) {
        /* Check if value already dumped */
        if (u > 0 && group_array[u].value == prev_value) {
            fprintf(f_names_c,
                "    /* Skipping alternate spelling of value 0x%x. %s_%s */\n",
                (unsigned)prev_value,
                prefix,
                group_array[u].name);
            continue;
        }
        prev_value = group_array[u].value;

        /*  Generate entries for 'dwarf_names_enum.h'.
            The 39 just makes nice formatting in the output. */
        len = 39 - strlen(prefix);
        fprintf(f_names_enum_h,"    %s_%-*s = 0x%04x",
            prefix,(int)len,group_array[u].name,group_array[u].value);
        fprintf(f_names_enum_h,(u + 1 < array_count) ? ",\n" : "\n");

        /* Generate entries for 'dwarf_names.c' */
        if (use_tables) {
            fprintf(f_names_c,"    {/* %3u */ \"%s_%s\", ",
                actual_array_count,prefix,group_array[u].name);
            fprintf(f_names_c," %s_%s}", prefix,group_array[u].name);
            fprintf(f_names_c,(u + 1 < array_count) ? ",\n" : "\n");
        } else {
            fprintf(f_names_c,"    case %s_%s:\n",
                prefix,group_array[u].name);
            fprintf(f_names_c,"        *s_out = \"%s_%s\";\n",
                prefix,group_array[u].name);
            fprintf(f_names_c,"        return DW_DLV_OK;\n");
        }
        ++actual_array_count;
    }

    /* Closing entries for 'dwarf_names_enum.h' */
    fprintf(f_names_enum_h,"};\n");

    if (use_tables) {
        /* Closing entries for 'dwarf_names.c' */
        fprintf(f_names_c,"    };\n\n");

        /* Closing code for 'dwarf_names.c' */
        fprintf(f_names_c,"    const int last_entry = %d;\n",actual_array_count);
        fprintf(f_names_c,"    /* find the entry */\n");
        fprintf(f_names_c,"    int r = find_entry(Dwarf_%s_n,last_entry,val,s_out);\n",prefix_id);
        fprintf(f_names_c,"    return r;\n");
        fprintf(f_names_c,"}\n");
    } else {
        fprintf(f_names_c,"    }\n");
        fprintf(f_names_c,"    return DW_DLV_NO_ENTRY;\n");
        fprintf(f_names_c,"}\n");
    }

    /* Mark the group_array as empty */
    array_count = 0;
}

/*  Detect empty lines (and other lines we do not want to read) */
static boolean
is_skippable_line(char *pLine)
{
    boolean empty = TRUE;

    for (; *pLine && empty; ++pLine) {
        empty = isspace(*pLine);
    }
    return empty;
}

static void
safe_strncpy(char *out, unsigned out_len,
    char *in,unsigned in_len)
{
    if(in_len >= out_len) {
        fprintf(stderr,"Impossible input line from dwarf.h. Giving up. \n");
        fprintf(stderr,"Length %u is too large, limited to %u.\n",
            in_len,out_len);
        exit(1);
    }
    strncpy(out,in,in_len);
}


/* Parse the 'dwarf.h' file and generate the tables */
static void
ParseDefinitionsAndWriteOutput(void)
{
    char new_prefix[64];
    char *second_underscore = NULL;
    char type[1000];
    char name[1000];
    char value[1000];
    char extra[1000];
    char line_in[MAX_LINE_SIZE];
    int pending = FALSE;
    int prefix_len = 0;

    /* Process each line from 'dwarf.h' */
    while (!feof(f_dwarf_in)) {
        /*  errno is cleared here so printing errno after
            the fgets is showing errno as set by fgets. */
        char *fgbad = 0;
        errno = 0;
        fgbad = fgets(line_in,sizeof(line_in),f_dwarf_in);
        if(!fgbad) {
            if(feof(f_dwarf_in)) {
                break;
            }
            /*  Is error. errno must be set. */
            fprintf(stderr,"Error reading dwarf.h!. Errno %d\n",errno);
            exit(1);
        }
        if (is_skippable_line(line_in)) {
            continue;
        }
        sscanf(line_in,"%s %s %s %s",type,name,value,extra);
        if (strcmp(type,"#define") ||
            strncmp(name,prefix_root,prefix_root_len)) {
            continue;
        }

        second_underscore = strchr(name + prefix_root_len,'_');
        prefix_len = (int)(second_underscore - name);
        safe_strncpy(new_prefix,sizeof(new_prefix),name,prefix_len);
        new_prefix[prefix_len] = 0;

        /* Check for new prefix set */
        if (strcmp(prefix,new_prefix)) {
            if (pending) {
                /* Generate current prefix set */
                GenerateOneSet();
            }
            pending = TRUE;
            strcpy(prefix,new_prefix);
        }

        /* Be sure we have a valid entry */
        if (array_count >= ARRAY_SIZE) {
            printf("Too many entries for current group_array size of %d",ARRAY_SIZE);
            exit(1);
        }

        /* Move past the second underscore */
        ++second_underscore;

        {
            unsigned long v = strtoul(value,NULL,16);
            /*  Some values are duplicated, that is ok.
                After the sort we will weed out the duplicate values,
                see GenerateOneSet(). */
            /*  Record current entry */
            if (strlen(second_underscore) >= MAX_NAME_LEN) {
                printf("Too long a name %s for max len %d\n",
                    second_underscore,MAX_NAME_LEN);
                exit(1);
            }
            strcpy(group_array[array_count].name,second_underscore);
            group_array[array_count].value = v;
            group_array[array_count].original_position = array_count;
            ++array_count;
        }
    }
    if (pending) {
        /* Generate final prefix set */
        GenerateOneSet();
    }
}
