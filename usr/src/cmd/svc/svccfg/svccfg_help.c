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


#include "svccfg.h"
#include "svccfg_grammar.h"

struct help_message help_messages[] = {
	{ SCC_VALIDATE, "validate [file | fmri]\n\n"
"Validate a manifest file without changing the repository.\n"
"Validate an instance FMRI against the template specifications."
	},
	{ SCC_IMPORT, "import [-V] file\n\n"
"Import a manifest into the repository.  With -V force strict adherence\n"
"to the template specifications."
	},
	{ SCC_EXPORT, "export [-a] {service | pattern} [> file]\n\n"
"Print a manifest for service to file, or standard output if not specified."
	},
	{ SCC_ARCHIVE, "archive [-a] [> file]\n\n"
"Print an archive to file, or standard output if not specified."
	},
	{ SCC_RESTORE, "restore file\n\n"
"Restore the contents of a previously-generated archive."
	},
	{ SCC_APPLY, "apply file\n\nApply a profile." },
	{ SCC_EXTRACT, "extract [> file]\n\n"
"Print a profile to file, or standard output if not specified." },
	{ SCC_REPOSITORY, "repository file\n\nSet the repository to modify." },
	{ SCC_INVENTORY, "inventory file\n\n"
		"Print the services and instances contained in a manifest."
	},
	{ SCC_SET, "set [-vV]\n\n"
"Without arguments, display current options.  Otherwise set the given options."
	},
	{ SCC_END, "end\n\nStop processing and exit." },
	{ SCC_HELP, "help [command]\n\nDisplay help." },
	{ SCC_LIST, "list [glob_pattern]\n\n"
		"List children of the currently selected entity."
	},
	{ SCC_ADD, "add name\n\n"
		"Add a new child entity to the currently selected entity."
	},
	{ SCC_DELETE, "delete [-f] {name | fmri | pattern}\n\n"
"Delete the named child entity or the one indicated by fmri.  With -f, delete\n"
"running services.\n"
	},
	{ SCC_SELECT, "select {name | fmri | pattern}\n\n"
		"Select the named child entity or the one indicated by fmri."
	},
	{ SCC_UNSELECT, "unselect\n\n"
		"Select the parent of the currently selected entity."
	},
	{ SCC_LISTPG, "listpg [glob_pattern]\n\n"
		"List property groups of the currently selected entity."
	},
	{ SCC_ADDPG, "addpg name type [P]\n\n"
		"Add a new property group to the currently selected entity."
	},
	{ SCC_DELPG, "delpg name\n\n"
"Delete the named property group from the currently selected entity."
	},
	{ SCC_DELHASH, "delhash [-d] manifest\n\n"
"Delete the named manifest hash entry (from smf/manifest).\n"
"With -d, manifest file doesn't need to exist."
	},
	{ SCC_LISTPROP, "listprop [glob_pattern]\n\n"
"List property groups and properties of the currently selected entity."
	},
	{ SCC_SETPROP,
		"\tsetprop pg/name = [type:] value\n"
		"\tsetprop pg/name = [type:] ([value...])\n\n"
"Set the pg/name property of the currently selected entity.  Values may be\n"
"enclosed in double-quotes.  Value lists may span multiple lines."
	},
	{ SCC_DELPROP, "delprop pg/name\n\n"
		"Delete the pg/name property of the currently selected entity."
	},
	{ SCC_EDITPROP, "editprop\n\n"
"Invoke $EDITOR to edit the properties of the currently selected entity."
	},
	{ SCC_DESCRIBE, "describe [-v] [-t] [propertygroup/property]\n\n"
"Describe the current properties.  With -v, describe verbosely.  With -t,\n"
"show only template data, not current properties."
	},
	{ SCC_ADDPROPVALUE, "addpropvalue pg/name [type:] value\n\n"
"Add the given value to the named property."
	},
	{ SCC_DELPROPVALUE, "delpropvalue pg/name glob_pattern\n\n"
"Delete all values matching the glob pattern fron the given property."
	},
	{ SCC_SETENV, "setenv [-s | -i | -m method] NAME value\n\n"
"Set an environment variable for the given service, instance, or method "
"context."
	},
	{ SCC_UNSETENV, "unsetenv [-s | -i | -m method] NAME value\n\n"
"Unset an environment variable for the given service, instance, or method "
"context."
	},
	{ SCC_LISTSNAP, "listsnap\n\n"
		"List snapshots of the currently selected instance."
	},
	{ SCC_SELECTSNAP, "selectsnap [snapshot]\n\n"
"Select a snapshot of the currently selected instance, or the Editing\n"
"snapshot by default."
	},
	{ SCC_REVERT, "revert [snapshot]\n\n"
"Change the properties of the currently selected instance and its ancestors\n"
"to those in a snapshot, or the currently selected snapshot by default."
	},
	{ SCC_REFRESH, "refresh\n\n"
"Commit the values from the current configuration to the running\n"
"snapshot, making them available for use by the currently selected\n"
"instance.  If the repository subcommand has not been used to select\n"
"a repository, inform the instance's restarter to re-read the updated\n"
"configuration."
	},
	{ 0, NULL }
};
