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
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Debug class
 */

package com.sun.admin.pm.server;

import java.util.*;

/**
 * A simple configurable debug logging class.
 * <p>
 *
 * Calling member classes <b>message()</b>, <b>warning()</b>,
 * <b>error()</b>, and <b>fatal()</b> causes a log entry to be
 * generated if the current verbosity level is greater than or equal
 * to the specified severity.
 * <p>
 *
 * Calling <b>setDebugLevel()</b> sets the verbosity level, which is a
 * threshold of severity below which messages will not be logged.  The
 * verbosity level can be set at any time.
 * <p>
 *
 * For example, setting the verbosity level to <b>Debug.ERROR</b>
 * means that only <b>error()</b> and <b>fatal()</b> calls will
 * generate log entries, while setting the level to <b>WARNING</b>
 * will log <b>warning()</b> calls as well as <b>error()</b> and
 * <b>fatal()</b> while ignoring <b>message()</b>.
 * <p>
 *
 * Setting the verbosity level to <b>ALL</b> is equivalent to setting
 * it to <b>MESSAGE</b>; all calls are logged.  The constant
 * <b>NONE</b> suppresses logging of all calls.
 * <p>
 *
 * The verbosity level can be set globally or on a class-by-class
 * basis.  Use the form of <b>setDebugLevel()</b> which takes an
 * argument of type Object to set the level for all instances of the
 * specified class.
 * <p>
 *
 * Using the forms of <b>message()</b>, <b>warning()</b>,
 * <b>error()</b>, and <b>fatal()</b> which accept an argument of type
 * Object will use the verbosity value associated with the specified
 * class.  If no value has been explicitly set for the class, the
 * global default will be used.
 * <p>
 *
 * At present log messages are written only to stdout.
 * An enhancement would be to implement an interface to the syslog facility.
 */


public class Debug {

    /**
     * Log a highest-priority message.
     * @param String s The message to be logged.
     */
    static public void fatal(String s) {
        printIf(s, FATAL);
    }

    /**
     * Log a high-priority message.
     * @param String s The message to be logged.
     */
    static public void error(String s) {
        printIf(s, ERROR);
    }

    /**
     * Log a medium-priority message.
     * @param String s The message to be logged.
     */
    static public void warning(String s) {
        printIf(s, WARNING);
    }

    /**
     * Log a low-priority message.
     * @param String s The message to be logged.
     */
    static public void message(String s) {
        printIf(s, MESSAGE);
    }


    /**
     * Log a lowest-priority message.
     * @param String s The message to be logged.
     */
    static public void info(String s) {
        printIf(s, INFO);
    }


    /**
     * Log a highest-priority message.
     * @param String s The message to be logged.
     */
    static public void fatal(Object o, String s) {
        printIf(o, s, FATAL);
    }

    /**
     * Log a high-priority message.
     * @param String s The message to be logged.
     */
    static public void error(Object o, String s) {
        printIf(o, s, ERROR);
    }

    /**
     * Log a medium-priority message.
     * @param String s The message to be logged.
     */
    static public void warning(Object o, String s) {
        printIf(o, s, WARNING);
    }

    /**
     * Log a low-priority message.
     * @param String s The message to be logged.
     */
    static public void message(Object o, String s) {
        printIf(o, s, MESSAGE);
    }

    /**
     * Log a lowest-priority message.
     * @param String s The message to be logged.
     */
    static public void info(Object o, String s) {
        printIf(o, s, INFO);
    }

    /**
     * Set the verbosity level to the specified severity.
     * @param String s The message to be logged.
     */
    static public void setDebugLevel(int lvl) {
        if (lvl < ALL || lvl > NONE)
            return;

        globalDebugLevel = lvl;
    }

    /**
     * Set the verbosity level to the specified severity.
     * @param String s The message to be logged.
     */
    static public void setDebugLevel(Object o, int lvl) {
        if (lvl < ALL || lvl > NONE)
            return;

        classDB.put(o.getClass(), new Integer(lvl));

	/*
	 * System.out.println("Debug: class " + o.getClass().getName() +
	 *		" level = " + classDB.get(o.getClass()));
	 */
    }

	static public void setDebugLevel(String classname, int lvl) {
        if (lvl < ALL || lvl > NONE)
            return;

        try {
			classDB.put(Class.forName(classname), new Integer(lvl));
		} catch (Exception x) {
			System.out.println("setDebugLevel: " + x);
		}
	}


    private static void printIf(String s, int lvl) {
        if (lvl < globalDebugLevel)
            return;
        debugPrint(s);
    }

    private static void printIf(Object o, String s, int lvl) {
        if (lvl < getLevelForClass(o))
            return;
        debugPrint(s);
    }


    /*
     * get debug level for o's class, if already there
     * otherwise create an entry for o and set it to the global level
     */
    private synchronized static int getLevelForClass(Object o) {
        int lvl = globalDebugLevel;
        Object g;
        if ((g = classDB.get(o.getClass())) != null)
            lvl = ((Integer) g).intValue();
        else
            classDB.put(o.getClass(), new Integer(lvl));

	/*
	 * System.out.println("Debug: getLevelForClass " +
	 *		o.getClass().getName() +
	 *		" = " + lvl);
	 */

        return lvl;
    }

    // here is where we could hide syslog or file destination...
    private static void debugPrint(String s) {
	System.out.println(s);	// for now
    }

	Object theInstance = null;

	public Debug(Object o) {
		theInstance = o;
	}

    public void SetDebugLevel(int lvl) {
        if (lvl < ALL || lvl > NONE)
            return;
        setDebugLevel(theInstance, lvl);
    }

	public void Fatal(String s) {
		fatal(theInstance, s);
	}

	public void Warning(String s) {
		warning(theInstance, s);
	}

	public void Error(String s) {
		error(theInstance, s);
	}

	public void Message(String s) {
		message(theInstance, s);
	}

	public void Info(String s) {
		info(theInstance, s);
	}

    /*
     * Verbosity level to suppress all messages.
     */
    static public final int NONE = 6;

    /*
     * Verbosity level to log only highest-priority messages.
     */
    static public final int FATAL = 5;

    /*
     * Verbosity level to log  high- and highest-priority messages.
     */
    static public final int ERROR = 4;

    /*
     * Verbosity level to log medium-, high-, and  highest-priority messages.
     */
    static public final int WARNING = 3;

    /*
     * Verbosity level to log low-, medium-, high-, and
     * highest-priority messages.
     */
    static public final int MESSAGE = 2;

    /*
     * Verbosity level to log lowest-, low-, medium-, high-, and
     * highest-priority messages.
     */
    static public final int INFO = 1;


    /*
     * Verbosity level to log all messages.
     */
    static public final int ALL = 0;

    private static int globalDebugLevel = FATAL;
    private static Hashtable classDB = new Hashtable();

}
