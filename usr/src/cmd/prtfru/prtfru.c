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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "fru_tag.h"
#include "libfrup.h"
#include "libfrureg.h"


#define	NUM_ITER_BYTES 4

#define	HEAD_ITER 0
#define	TAIL_ITER 1	/*  not used  */
#define	NUM_ITER  2
#define	MAX_ITER  3

#define	INDENT 3
#define	TIMESTRINGLEN 128
#define	TEMPERATURE_OFFSET 73

static void	(*print_node)(fru_node_t fru_type, const char *path,
				const char *name, end_node_fp_t *end_node,
				void **end_args);

static void	print_element(const uint8_t *data, const fru_regdef_t *def,
const char *parent_path, int indent);

static char	tagname[sizeof ("?_0123456789_0123456789_0123456789")];

static int	containers_only = 0, list_only = 0, saved_status = 0, xml = 0;

static FILE	*errlog;

int iterglobal = 0;
int FMAmessageR = -1;
int Fault_Install_DataR_flag = 0;
int Power_On_DataR_flag = 0;
/*
 * Definition for data elements found in devices but not found in
 * the system's version of libfrureg
 */
static fru_regdef_t  unknown = {
	REGDEF_VERSION,
	tagname,
	-1,
	-1,
	-1,
	-1,
	FDTYPE_ByteArray,
	FDISP_Hex,
	FRU_WHICH_UNDEFINED,
	FRU_WHICH_UNDEFINED,
	0,
	NULL,
	0,
	FRU_NOT_ITERATED,
	NULL
};


/*
 * Write message to standard error and possibly the error log buffer
 */
static void
error(const char *format, ...)
{
	va_list	args;


	/* make relevant output appear before error message */
	if (fflush(stdout) == EOF) {
		(void) fprintf(stderr, "Error flushing output:  %s\n",
		    strerror(errno));
		exit(1);
	}

	va_start(args, format);
	if (vfprintf(stderr, format, args) < 0) exit(1);
	if (errlog && (vfprintf(errlog, format, args) < 0)) exit(1);
}

/*
 * Write message to standard output
 */
static void
output(const char *format, ...)
{
	va_list   args;


	va_start(args, format);
	if (vfprintf(stdout, format, args) < 0) {
		error(gettext("Error writing output:  %s\n"),
		    strerror(errno));
		exit(1);
	}
}

/*
 * Safe wrapper for putchar()
 */
static void
voidputchar(int c)
{
	if (putchar(c) == EOF) {
		error(gettext("Error writing output:  %s\n"),
		    strerror(errno));
		exit(1);
	}
}

static void  (*safeputchar)(int c) = voidputchar;

/*
 * Safe wrapper for puts()
 */
static void
voidputs(const char *s)
{
	if (fputs(s, stdout) == EOF) {
		error(gettext("Error writing output:  %s\n"),
		    strerror(errno));
		exit(1);
	}
}

static void  (*safeputs)(const char *s) = voidputs;

/*
 * XML-safe wrapper for putchar():  quotes XML-special characters
 */
static void
xputchar(int c)
{
	switch (c) {
	case '<':
		c = fputs("&lt;", stdout);
		break;
	case '>':
		c = fputs("&gt;", stdout);
		break;
	case '&':
		c = fputs("&amp;", stdout);
		break;
	case '"':
		c = fputs("&quot;", stdout);
		break;
	default:
		c = putchar(c);
		break;
	}

	if (c == EOF) {
		error(gettext("Error writing output:  %s\n"),
		    strerror(errno));
		exit(1);
	}
}

/*
 * XML-safe analog of puts():  quotes XML-special characters
 */
static void
xputs(const char *s)
{
	char c;

	for (/* */; ((c = *s) != 0); s++)
		xputchar(c);
}

/*
 * Output the XML DTD derived from the registry provided by libfrureg
 */
int
output_dtd(void)
{
	char			**element;

	unsigned int		i, j, num_elements = 0;

	uint8_t			*tagged;

	const fru_regdef_t	*def;


	if (((element = fru_reg_list_entries(&num_elements)) == NULL) ||
	    (num_elements == 0)) {
		error(gettext("No FRU ID Registry elements"));
		return (1);
	}

	if ((tagged = calloc(num_elements, sizeof (*tagged))) == NULL) {
		error(gettext("Unable to get memory for tagged element list"),
		    strerror(errno));
		return (1);
	}

	/*
	 * Output the DTD preamble
	 */
	output("<!ELEMENT FRUID_XML_Tree (Parameter*, "
	    "(Fru | Location | Container)*,\n"
	    "                          Parameter*, ErrorLog?, Parameter*)>\n"
	    "<!ATTLIST FRUID_XML_Tree>\n"
	    "\n"
	    "<!ELEMENT Parameter EMPTY>\n"
	    "<!ATTLIST Parameter type CDATA #REQUIRED>\n"
	    "<!ATTLIST Parameter name CDATA #REQUIRED>\n"
	    "<!ATTLIST Parameter value CDATA #REQUIRED>\n"
	    "\n"
	    "<!ELEMENT Fru (Fru | Location | Container)*>\n"
	    "<!ATTLIST Fru name CDATA #REQUIRED>\n"
	    "\n"
	    "<!ELEMENT Location (Fru | Location | Container)*>\n"
	    "<!ATTLIST Location\n"
	    "	name CDATA #IMPLIED\n"
	    "	value CDATA #IMPLIED\n"
	    ">\n"
	    "\n"
	    "<!ELEMENT Container (ContainerData?, "
	    "(Fru | Location | Container)*)>\n"
	    "<!ATTLIST Container name CDATA #REQUIRED>\n"
	    "<!ATTLIST Container imagefile CDATA #IMPLIED>\n"
	    "\n"
	    "<!ELEMENT ContainerData (Segment*)>\n"
	    "<!ATTLIST ContainerData>\n"
	    "\n"
	    "<!ATTLIST Segment name CDATA #REQUIRED>\n"
	    "\n"
	    "<!ELEMENT Index EMPTY>\n"
	    "<!ATTLIST Index value CDATA #REQUIRED>\n"
	    "\n"
	    "<!ELEMENT ErrorLog (#PCDATA)>\n"
	    "<!ATTLIST ErrorLog>\n"
	    "\n");

	/*
	 * Output the definition for each element
	 */
	for (i = 0; i < num_elements; i++) {
		assert(element[i] != NULL);
		/* Prevent incompatible duplicate defn. from FRUID Registry. */
		if ((strcmp("Location", element[i])) == 0) continue;
		if ((def = fru_reg_lookup_def_by_name(element[i])) == NULL) {
			error(gettext("Error looking up registry "
			    "definition for \"%s\"\n"),
			    element[i]);
			return (1);
		}

		if (def->tagType != FRU_X) tagged[i] = 1;

		if (def->dataType == FDTYPE_Record) {
			if (def->iterationType == FRU_NOT_ITERATED)
				output("<!ELEMENT %s (%s", element[i],
				    def->enumTable[0].text);
			else
				output("<!ELEMENT %s (Index_%s*)>\n"
				    "<!ATTLIST Index_%s>\n"
				    "<!ELEMENT Index_%s (%s",
				    element[i], element[i], element[i],
				    element[i], def->enumTable[0].text);

			for (j = 1; j < def->enumCount; j++)
				output(",\n\t%s", def->enumTable[j].text);

			output(")>\n");
		} else if (def->iterationType == FRU_NOT_ITERATED) {
			output("<!ELEMENT %s EMPTY>\n"
			    "<!ATTLIST %s value CDATA #REQUIRED>\n",
			    element[i], element[i]);

			if (def->dataType == FDTYPE_Enumeration) {
				output("<!-- %s valid enumeration values\n");
				for (j = 0; j < def->enumCount; j++) {
					output("\t\"");
					xputs(def->enumTable[j].text);
					output("\"\n");
				}
				output("-->\n");
			}
		}
		else
			output("<!ELEMENT %s (Index*)>\n", element[i]);

		output("\n");
	}

	/* Provide for returning the tag for an "unknown" element */
	output("<!ATTLIST UNKNOWN tag CDATA \"UNKNOWN\">\n\n");


	/*
	 * List all data elements as possible members of "Segment"
	 */
	output("<!ELEMENT Segment ((UNKNOWN");
	for (i = 0; i < num_elements; i++) {
		if (tagged[i]) output("\n\t| %s", element[i]);
		free(element[i]);
	}
	output(")*)>\n");
	free(element);
	free(tagged);

	return (0);
}
/*
 * Function to convert bcd to binary to correct the SPD_Manufacturer_Week
 *
 */
static void convertbcdtobinary(int *val)
{
	int newval, tmpval, rem, origval, poweroften;
	int i;
	tmpval = 0;
	newval = 0;
	i = 0;
	rem = 0;
	poweroften = 1;
	origval = (int)(*val);
	tmpval = (int)(*val);
	while (tmpval != 0) {
		if (i >= 1)
			poweroften = poweroften * 10;
		origval = tmpval;
		tmpval = (int)(tmpval/16);
		rem = origval - (tmpval * 16);
		newval = newval +(int)(poweroften * rem);
		i ++;
	}
	*val = newval;
}


/*
 * Safely pretty-print the value of a field
 */
static void
print_field(const uint8_t *field, const fru_regdef_t *def)
{
	char		*errmsg = NULL, timestring[TIMESTRINGLEN], path[16384];

	int		i, valueint;

	uint64_t	value;

	time_t		timefield;

	struct tm	*tm;

	uchar_t		first_byte, data[128];

	const fru_regdef_t	*new_def;

	const char 	*elem_name = NULL;
	const char	*parent_path;
	switch (def->dataType) {
	case FDTYPE_Binary:
		assert(def->payloadLen <= sizeof (value));
		switch (def->dispType) {
		case FDISP_Binary:
			for (i = 0; i < def->payloadLen; i++)
				output("%c%c%c%c%c%c%c%c",
				    ((field[i] & 0x80) ? '1' : '0'),
				    ((field[i] & 0x40) ? '1' : '0'),
				    ((field[i] & 0x20) ? '1' : '0'),
				    ((field[i] & 0x10) ? '1' : '0'),
				    ((field[i] & 0x08) ? '1' : '0'),
				    ((field[i] & 0x04) ? '1' : '0'),
				    ((field[i] & 0x02) ? '1' : '0'),
				    ((field[i] & 0x01) ? '1' : '0'));
			return;
		case FDISP_Octal:
		case FDISP_Decimal:
			value = 0;
			valueint = 0;
			(void) memcpy((((uint8_t *)&value) +
			    sizeof (value) - def->payloadLen),
			    field, def->payloadLen);
			if ((value != 0) &&
			    (strcmp(def->name, "SPD_Manufacture_Week") == 0)) {
				valueint = (int)value;
				convertbcdtobinary(&valueint);
				output("%d", valueint);
				return;
			}
			if ((value != 0) &&
			    ((strcmp(def->name, "Lowest") == 0) ||
			    (strcmp(def->name, "Highest") == 0) ||
			    (strcmp(def->name, "Latest") == 0)))
				output((def->dispType == FDISP_Octal) ?
				"%llo" : "%lld (%lld degrees C)",
				    value, (value - TEMPERATURE_OFFSET));
			else
				output((def->dispType == FDISP_Octal) ?
				"%llo" : "%lld", value);
			return;
		case FDISP_Time:
			if (def->payloadLen > sizeof (timefield)) {
				errmsg = "time value too large for formatting";
				break;
			}
			timefield = 0;
			(void) memcpy((((uint8_t *)&timefield) +
			    sizeof (timefield) - def->payloadLen),
			    field, def->payloadLen);
			if (timefield == 0) {
				errmsg = "No Value Recorded";
				break;
			}
			if ((tm = localtime(&timefield)) == NULL) {
				errmsg = "cannot convert time value";
				break;
			}
			if (strftime(timestring, sizeof (timestring), "%C", tm)
			    == 0) {
				errmsg = "formatted time would overflow buffer";
				break;
			}
			safeputs(timestring);
			return;
		}
		break;
	case FDTYPE_ASCII:
		if (!xml) {
			if (strcmp(def->name, "Message") == 0) {
				if (FMAmessageR == 0)
					elem_name = "FMA_Event_DataR";
				else if (FMAmessageR == 1)
					elem_name = "FMA_MessageR";
				if (elem_name != NULL) {
					(void) memcpy(data, field,
					    def->payloadLen);
					new_def =
					    fru_reg_lookup_def_by_name
					    (elem_name);
					(void) snprintf(path, sizeof (path),
					"/Status_EventsR[%d]/Message(FMA)",
					    iterglobal);
					parent_path = path;
					output("\n");
					print_element(data, new_def,
					    parent_path, 2*INDENT);
					return;
				}
			}
		}
		for (i = 0; i < def->payloadLen && field[i]; i++)
			safeputchar(field[i]);
		return;
	case FDTYPE_Enumeration:
		value = 0;
		(void) memcpy((((uint8_t *)&value) + sizeof (value)
		    - def->payloadLen),
		    field, def->payloadLen);
		for (i = 0; i < def->enumCount; i++)
			if (def->enumTable[i].value == value) {
				if (strcmp(def->name, "Event_Code") == 0) {
					if (strcmp(def->enumTable[i].text,
"FMA Message R") == 0)
						FMAmessageR = 1;
				else
					if (strcmp(def->enumTable[i].text,
"FMA Event Data R") == 0)
						FMAmessageR = 0;
				}
				safeputs(def->enumTable[i].text);
				return;
			}

		errmsg = "unrecognized value";
		break;
	}

	/* If nothing matched above, print the field in hex */
	switch (def->dispType) {
		case FDISP_MSGID:
			(void) memcpy((uchar_t *)&first_byte, field, 1);
			if (isprint(first_byte)) {
				for (i = 0; i < def->payloadLen && field[i];
				    i++)
					safeputchar(field[i]);
			}
			break;
		case FDISP_UUID:
			for (i = 0; i < def->payloadLen; i++) {
				if ((i == 4) || (i == 6) ||
				    (i == 8) || (i == 10))
				output("-");
				output("%2.2x", field[i]);
			}
			break;
		default:
			for (i = 0; i < def->payloadLen; i++)
				output("%2.2X", field[i]);
			break;
	}

	/* Safely print any error message associated with the field */
	if (errmsg) {
		if (strcmp(def->name, "Fault_Diag_Secs") != 0) {
			output(" (");
			safeputs(errmsg);
			output(")");
		}
	}
}

/*
 * Recursively print the contents of a data element
 */
static void
print_element(const uint8_t *data, const fru_regdef_t *def,
    const char *parent_path, int indent)
{
	char	*path;
	size_t	len;

	int	bytes = 0, i;


	indent = (xml) ? (indent + INDENT) : (2*INDENT);
	if (strcmp(def->name, "Sun_SPD_DataR") == 0) {
		Fault_Install_DataR_flag = indent;
		Power_On_DataR_flag = indent;
	}
	/*
	 * Construct the path, or, for XML, the name, for the current
	 * data element
	 */
	if ((def->iterationCount == 0) &&
	    (def->iterationType != FRU_NOT_ITERATED)) {
		if (xml) {
			if (def->dataType == FDTYPE_Record) {
				len = strlen("Index_") + strlen(def->name) + 1;
				path = alloca(len);
				(void) snprintf(path, len,
				    "Index_%s", def->name);
			}
			else
				path = "Index";
		}
		else
			path = (char *)parent_path;
	} else {
		if (xml)
			path = (char *)def->name;
		else {
			len = strlen(parent_path) + sizeof ("/") +
			    strlen(def->name) +
			    (def->iterationCount ? sizeof ("[255]") : 0);
			path = alloca(len);
			bytes = snprintf(path, len,
			    "%s/%s", parent_path, def->name);
		}
	}

	if ((Fault_Install_DataR_flag) &&
	    (strcmp(path, "E_1_46") == 0) || (strcmp(path, "/E_1_46") == 0)) {
		int cnt;
		char timestring[128];
		time_t timefield = 0;
		struct tm *tm;
		indent = Fault_Install_DataR_flag;
		(void) memcpy((uint8_t *)&timefield, data, 4);
		if (timefield == 0) {
			(void) sprintf(timestring,
			    "00000000 (No Value Recorded)\"");
		} else {
			if ((tm = localtime(&timefield)) == NULL)
				(void) sprintf(timestring,
				    "cannot convert time value");
			if (strftime(timestring,
			    sizeof (timestring), "%C", tm) == 0)
				(void) sprintf(timestring,
				    "formatted time would overflow buffer");
		}
		if (xml) {
			(void) sprintf(path, "Fault_Install_DataR");
			output("%*s<%s>\n", indent, "", path);
			indent = Fault_Install_DataR_flag + INDENT;
			(void) sprintf(path, "UNIX_Timestamp32");
			output("%*s<%s value=\"", indent, "", path);
			/*CSTYLED*/
			output("%s\"/>\n", timestring);
			(void) sprintf(path, "MACADDR");
			output("%*s<%s value=\"", indent, "", path);
			for (cnt = 4; cnt < 4 + 6; cnt++) {
				output("%2.2x", data[cnt]);
				if (cnt < 4 + 6 - 1)
					output(":");
			}
			/*CSTYLED*/
			output("\"/>\n");
			(void) sprintf(path, "Status");
			output("%*s<%s value=\"", indent, "", path);
			/*CSTYLED*/
			output("%2.2x\"/>\n", data[10]);
			(void) sprintf(path, "Initiator");
			output("%*s<%s value=\"", indent, "", path);
			/*CSTYLED*/
			output("%2.2x\"/>\n", data[11]);
			(void) sprintf(path, "Message_Type");
			output("%*s<%s value=\"", indent, "", path);
			/*CSTYLED*/
			output("%2.2x\"/>\n", data[12]);
			(void) sprintf(path, "Message_32");
			output("%*s<%s value=\"", indent, "", path);
			for (cnt = 13; cnt < 13 + 32; cnt++)
				output("%2.2x", data[cnt]);
			/*CSTYLED*/
			output("\"/>\n");
			indent = Fault_Install_DataR_flag;
			(void) sprintf(path, "Fault_Install_DataR");
			output("%*s</%s>\n", indent, "", path);
		} else {
			(void) sprintf(path, "/Fault_Install_DataR");
			output("%*s%s\n", indent, "", path);
			(void) sprintf(path,
			    "/Fault_Install_DataR/UNIX_Timestamp32");
			output("%*s%s: ", indent, "", path);
			output("%s\n", timestring);
			(void) sprintf(path, "/Fault_Install_DataR/MACADDR");
			output("%*s%s: ", indent, "", path);
			for (cnt = 4; cnt < 4 + 6; cnt++) {
				output("%2.2x", data[cnt]);
				if (cnt < 4 + 6 - 1)
					output(":");
			}
			output("\n");
			(void) sprintf(path, "/Fault_Install_DataR/Status");
			output("%*s%s: ", indent, "", path);
			output("%2.2x\n", data[10]);
			(void) sprintf(path, "/Fault_Install_DataR/Initiator");
			output("%*s%s: ", indent, "", path);
			output("%2.2x\n", data[11]);
			(void) sprintf(path,
			    "/Fault_Install_DataR/Message_Type");
			output("%*s%s: ", indent, "", path);
			output("%2.2x\n", data[12]);
			(void) sprintf(path, "/Fault_Install_DataR/Message_32");
			output("%*s%s: ", indent, "", path);
			for (cnt = 13; cnt < 13 + 32; cnt++)
				output("%2.2x", data[cnt]);
			output("\n");
		}
		Fault_Install_DataR_flag = 0;
		return;
	} else if ((Power_On_DataR_flag) && (
	    strcmp(path, "C_10_8") == 0 ||
	    (strcmp(path, "/C_10_8") == 0))) {
		int cnt;
		char timestring[128];
		time_t timefield = 0;
		struct tm *tm;
		indent = Power_On_DataR_flag;
		(void) memcpy((uint8_t *)&timefield, data, 4);
		if (timefield == 0) {
			(void) sprintf(timestring,
			    "00000000 (No Value Recorded)");
		} else {
			if ((tm = localtime(&timefield)) == NULL)
				(void) sprintf(timestring,
				    "cannot convert time value");
			if (strftime(timestring,
			    sizeof (timestring), "%C", tm) == 0)
				(void) sprintf(timestring,
				    "formatted time would overflow buffer");
		}
		if (xml) {
			(void) sprintf(path, "Power_On_DataR");
			output("%*s<%s>\n", indent, "", path);
			indent = Power_On_DataR_flag + INDENT;
			(void) sprintf(path, "UNIX_Timestamp32");
			output("%*s<%s value=\"", indent, "", path);
			/*CSTYLED*/
			output("%s\"/>\n", timestring);
			(void) sprintf(path, "Power_On_Minutes");
			output("%*s<%s value=\"", indent, "", path);
			for (cnt = 4; cnt < 4 + 4; cnt++)
				output("%2.2x", data[cnt]);
			/*CSTYLED*/
			output("\"/>\n");
			indent = Power_On_DataR_flag;
			(void) sprintf(path, "Power_On_DataR");
			output("%*s</%s>\n", indent, "", path);
		} else {
			(void) sprintf(path, "/Power_On_DataR");
			output("%*s%s\n", indent, "", path);
			(void) sprintf(path,
			    "/Power_On_DataR/UNIX_Timestamp32");
			output("%*s%s: ", indent, "", path);
			output("%s\n", timestring);
			(void) sprintf(path,
			    "/Power_On_DataR/Power_On_Minutes");
			output("%*s%s: ", indent, "", path);
			for (cnt = 4; cnt < 4 + 4; cnt++)
				output("%2.2x", data[cnt]);
			output("\n");
		}
		Power_On_DataR_flag = 0;
		return;
	}
	/*
	 * Handle the various categories of data elements:  iteration,
	 * record, and field
	 */
	if (def->iterationCount) {
		int		iterlen = (def->payloadLen - NUM_ITER_BYTES)/
		    def->iterationCount,
		    n, valid = 1;

		uint8_t		head, num;

		fru_regdef_t	newdef;


		/*
		 * Make a new element definition to describe the components
		 * of the iteration
		 */
		(void) memcpy(&newdef, def, sizeof (newdef));
		newdef.iterationCount = 0;
		newdef.payloadLen = iterlen;

		/*
		 * Validate the contents of the iteration control bytes
		 */
		if (data[HEAD_ITER] >= def->iterationCount) {
			valid = 0;
			error(gettext("%s:  Invalid iteration head:  %d "
			    "(should be less than %d)\n"),
			    path, data[HEAD_ITER], def->iterationCount);
		}

		if (data[NUM_ITER] > def->iterationCount) {
			valid = 0;
			error(gettext("%s:  Invalid iteration count:  %d "
			    "(should not be greater than %d)\n"),
			    path, data[NUM_ITER], def->iterationCount);
		}

		if (data[MAX_ITER] != def->iterationCount) {
			valid = 0;
			error(gettext("%s:  Invalid iteration maximum:  %d "
			    "(should equal %d)\n"),
			    path, data[MAX_ITER], def->iterationCount);
		}

		if (valid) {
			head = data[HEAD_ITER];
			num  = data[NUM_ITER];
		} else {
			head = 0;
			num  = def->iterationCount;
			error(gettext("%s:  Showing all iterations\n"), path);
		}

		if (xml)
			output("%*s<%s>\n", indent, "", path);
		else
			output("%*s%s (%d iterations)\n", indent, "", path,
			    num);

		/*
		 * Print each component of the iteration
		 */
		for (i = head, n = 0, data += 4;
		    n < num;
		    i = ((i + 1) % def->iterationCount), n++) {
			if (!xml) (void) sprintf((path + bytes), "[%d]", n);
			iterglobal = n;
			print_element((data + i*iterlen), &newdef, path,
			    indent);
		}

		if (xml) output("%*s</%s>\n", indent, "", path);

	} else if (def->dataType == FDTYPE_Record) {
		const fru_regdef_t  *component;

		if (xml)
			output("%*s<%s>\n", indent, "", path);
		else
			output("%*s%s\n", indent, "", path);

		/*
		 * Print each component of the record
		 */
		for (i = 0; i < def->enumCount;
		    i++, data += component->payloadLen) {
			component = fru_reg_lookup_def_by_name(
			    def->enumTable[i].text);
			assert(component != NULL);
			print_element(data, component, path, indent);
		}

		if (xml) output("%*s</%s>\n", indent, "", path);
	} else if (xml) {
		/*
		 * Base case:  print the field formatted for XML
		 */
		char  *format = ((def == &unknown)
		    ? "%*s<UNKNOWN tag=\"%s\" value=\""
		    : "%*s<%s value=\"");

		output(format, indent, "", path);
		print_field(data, def);
		/*CSTYLED*/
		output("\"/>\n");	/* \" confuses cstyle */

		if ((strcmp(def->name, "Message") == 0) &&
		    ((FMAmessageR == 0) || (FMAmessageR == 1))) {
			const char	*elem_name = NULL;
			const char	*parent_path;
			uchar_t		tmpdata[128];
			char		path[16384];
			const fru_regdef_t	*new_def;

			if (FMAmessageR == 0)
				elem_name = "FMA_Event_DataR";
			else if (FMAmessageR == 1)
				elem_name = "FMA_MessageR";
			if (elem_name != NULL) {
				(void) memcpy(tmpdata, data, def->payloadLen);
				new_def = fru_reg_lookup_def_by_name(elem_name);
				(void) snprintf(path, sizeof (path),
				"/Status_EventsR[%d]/Message(FMA)", iterglobal);
				parent_path = path;
				print_element(tmpdata, new_def,
				    parent_path, 2*INDENT);
				FMAmessageR = -1;
			}
		}

	} else {
		/*
		 * Base case:  print the field
		 */
		output("%*s%s: ", indent, "", path);
		print_field(data, def);
		output("\n");
	}
}

/*
 * Print the contents of a packet (i.e., a tagged data element)
 */
/* ARGSUSED */
static int
print_packet(fru_tag_t *tag, uint8_t *payload, size_t length, void *args)
{
	int			tag_type = get_tag_type(tag);

	size_t			payload_length = 0;

	const fru_regdef_t	*def;

	/*
	 * Build a definition for unrecognized tags (e.g., not in libfrureg)
	 */
	if ((tag_type == -1) ||
	    ((payload_length = get_payload_length(tag)) != length)) {
		def = &unknown;

		unknown.tagType    = -1;
		unknown.tagDense   = -1;
		unknown.payloadLen = length;
		unknown.dataLength = unknown.payloadLen;

		if (tag_type == -1)
			(void) snprintf(tagname, sizeof (tagname), "INVALID");
		else
			(void) snprintf(tagname, sizeof (tagname),
			    "%s_%u_%u_%u", get_tagtype_str(tag_type),
			    get_tag_dense(tag), payload_length, length);
	} else if ((def = fru_reg_lookup_def_by_tag(*tag)) == NULL) {
		def = &unknown;

		unknown.tagType    = tag_type;
		unknown.tagDense   = get_tag_dense(tag);
		unknown.payloadLen = payload_length;
		unknown.dataLength = unknown.payloadLen;

		(void) snprintf(tagname, sizeof (tagname), "%s_%u_%u",
		    get_tagtype_str(unknown.tagType),
		    unknown.tagDense, payload_length);
	}


	/*
	 * Print the defined element
	 */
	print_element(payload, def, "", INDENT);

	return (FRU_SUCCESS);
}

/*
 * Print a segment's name and the contents of each data element in the segment
 */
static int
print_packets_in_segment(fru_seghdl_t segment, void *args)
{
	char	*name;

	int	status;


	if ((status = fru_get_segment_name(segment, &name)) != FRU_SUCCESS) {
		saved_status = status;
		name = "";
		error(gettext("Error getting segment name:  %s\n"),
		    fru_strerror(status));
	}


	if (xml)
		output("%*s<Segment name=\"%s\">\n", INDENT, "", name);
	else
		output("%*sSEGMENT: %s\n", INDENT, "", name);

	/* Iterate over the packets in the segment, printing the contents */
	if ((status = fru_for_each_packet(segment, print_packet, args))
	    != FRU_SUCCESS) {
		saved_status = status;
		error(gettext("Error processing data in segment \"%s\":  %s\n"),
		    name, fru_strerror(status));
	}

	if (xml) output("%*s</Segment>\n", INDENT, "");

	free(name);

	return (FRU_SUCCESS);
}

/* ARGSUSED */
static void
print_node_path(fru_node_t fru_type, const char *path, const char *name,
    end_node_fp_t *end_node, void **end_args)
{
	output("%s%s\n", path,
	    ((fru_type == FRU_NODE_CONTAINER) ? " (container)"
	    : ((fru_type == FRU_NODE_FRU) ? " (fru)" : "")));
}

/*
 * Close the XML element for a "location" node
 */
/* ARGSUSED */
static void
end_location_xml(fru_nodehdl_t node, const char *path, const char *name,
    void *args)
{
	assert(args != NULL);
	output("</Location> <!-- %s -->\n", args);
}

/*
 * Close the XML element for a "fru" node
 */
/* ARGSUSED */
static void
end_fru_xml(fru_nodehdl_t node, const char *path, const char *name, void *args)
{
	assert(args != NULL);
	output("</Fru> <!-- %s -->\n", args);
}

/*
 * Close the XML element for a "container" node
 */
/* ARGSUSED */
static void
end_container_xml(fru_nodehdl_t node, const char *path, const char *name,
    void *args)
{
	assert(args != NULL);
	output("</Container> <!-- %s -->\n", args);
}

/*
 * Introduce a node in XML and set the appropriate node-closing function
 */
/* ARGSUSED */
static void
print_node_xml(fru_node_t fru_type, const char *path, const char *name,
    end_node_fp_t *end_node, void **end_args)
{
	switch (fru_type) {
	case FRU_NODE_FRU:
		output("<Fru name=\"%s\">\n", name);
		*end_node = end_fru_xml;
		break;
	case FRU_NODE_CONTAINER:
		output("<Container name=\"%s\">\n", name);
		*end_node = end_container_xml;
		break;
	default:
		output("<Location name=\"%s\">\n", name);
		*end_node = end_location_xml;
		break;
	}

	*end_args = (void *) name;
}

/*
 * Print node info and, where appropriate, node contents
 */
/* ARGSUSED */
static fru_errno_t
process_node(fru_nodehdl_t node, const char *path, const char *name,
		void *args, end_node_fp_t *end_node, void **end_args)
{
	int		status;

	fru_node_t	fru_type = FRU_NODE_UNKNOWN;


	if ((status = fru_get_node_type(node, &fru_type)) != FRU_SUCCESS) {
		saved_status = status;
		error(gettext("Error getting node type:  %s\n"),
		    fru_strerror(status));
	}

	if (containers_only) {
		if (fru_type != FRU_NODE_CONTAINER)
			return (FRU_SUCCESS);
		name = path;
	}

	/* Introduce the node */
	assert(print_node != NULL);
	print_node(fru_type, path, name, end_node, end_args);

	if (list_only)
		return (FRU_SUCCESS);

	/* Print the contents of each packet in each segment of a container */
	if (fru_type == FRU_NODE_CONTAINER) {
		if (xml) output("<ContainerData>\n");
		if ((status =
		    fru_for_each_segment(node, print_packets_in_segment,
		    NULL))
		    != FRU_SUCCESS) {
			saved_status = status;
			error(gettext("Error  processing node \"%s\":  %s\n"),
			    name, fru_strerror(status));
		}
		if (xml) output("</ContainerData>\n");
	}

	return (FRU_SUCCESS);
}

/*
 * Process the node if its path matches the search path in "args"
 */
/* ARGSUSED */
static fru_errno_t
process_matching_node(fru_nodehdl_t node, const char *path, const char *name,
    void *args, end_node_fp_t *end_node, void **end_args)
	{
	int  status;


	if (!fru_pathmatch(path, args))
		return (FRU_SUCCESS);

	status = process_node(node, path, path, args, end_node, end_args);

	return ((status == FRU_SUCCESS) ? FRU_WALK_TERMINATE : status);
}

/*
 * Write the trailer required for well-formed DTD-compliant XML
 */
static void
terminate_xml()
{
	errno = 0;
	if (ftell(errlog) > 0) {
		char  c;

		output("<ErrorLog>\n");
		rewind(errlog);
		if (!errno)
			while ((c = getc(errlog)) != EOF)
				xputchar(c);
		output("</ErrorLog>\n");
	}

	if (errno) {
		/*NOTREACHED*/
		errlog = NULL;
		error(gettext("Error copying error messages to \"ErrorLog\""),
		    strerror(errno));
	}

	output("</FRUID_XML_Tree>\n");
}

/*
 * Print available FRU ID information
 */
int
prtfru(const char *searchpath, int containers_only_flag, int list_only_flag,
	int xml_flag)
{
	fru_errno_t    status;

	fru_nodehdl_t  frutree = 0;


	/* Copy parameter flags to global flags */
	containers_only	= containers_only_flag;
	list_only	= list_only_flag;
	xml		= xml_flag;


	/* Help arrange for correct, efficient interleaving of output */
	(void) setvbuf(stderr, NULL, _IOLBF, 0);


	/* Initialize for XML--or not */
	if (xml) {
		safeputchar = xputchar;
		safeputs    = xputs;

		print_node  = print_node_xml;

		if ((errlog = tmpfile()) == NULL) {
			(void) fprintf(stderr,
			    "Error creating error log file:  %s\n",
			    strerror(errno));
			return (1);
		}

		/* Output the XML preamble */
		output("<?xml version=\"1.0\" ?>\n"
		    "<!--\n"
		    " Copyright 2000-2002 Sun Microsystems, Inc.  "
		    "All rights reserved.\n"
		    " Use is subject to license terms.\n"
		    "-->\n\n"
		    "<!DOCTYPE FRUID_XML_Tree SYSTEM \"prtfrureg.dtd\">\n\n"
		    "<FRUID_XML_Tree>\n");

		/* Arrange to always properly terminate XML */
		if (atexit(terminate_xml))
			error(gettext("Warning:  XML will not be terminated:  "
			    "%s\n"), strerror(errno));
	} else
		print_node = print_node_path;


	/* Get the root node */
	if ((status = fru_get_root(&frutree)) == FRU_NODENOTFOUND) {
		error(gettext("This system does not provide FRU ID data\n"));
		return (1);
	} else if (status != FRU_SUCCESS) {
		error(gettext("Unable to access FRU ID data:  %s\n"),
		    fru_strerror(status));
		return (1);
	}

	/* Process the tree */
	if (searchpath == NULL) {
		status = fru_walk_tree(frutree, "", process_node, NULL);
	} else {
		status = fru_walk_tree(frutree, "", process_matching_node,
		    (void *)searchpath);
		if (status == FRU_WALK_TERMINATE) {
			status = FRU_SUCCESS;
		} else if (status == FRU_SUCCESS) {
			error(gettext("\"%s\" not found\n"), searchpath);
			return (1);
		}
	}

	if (status != FRU_SUCCESS)
		error(gettext("Error processing FRU tree:  %s\n"),
		    fru_strerror(status));

	return (((status == FRU_SUCCESS) && (saved_status == 0)) ? 0 : 1);
}
