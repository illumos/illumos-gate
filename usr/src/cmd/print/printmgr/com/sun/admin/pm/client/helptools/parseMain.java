/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
import java.io.*;
import java.util.*;
import java.lang.*;


class ResourceWriter {

    BufferedWriter theWriter = null;
    String theTag = null;

    static final String NL = new String("\n");
    static final String LOCALIZE = new String("// LOCALIZE");
    static final String NOLOCALIZE = new String("// DO NOT LOCALIZE");
    static final String INDENT = new String("    ");
    static final String INDENT_2 = new String(INDENT + INDENT);
    static final String COMMENTBLOCK_START = new String("/*");
    static final String COMMENTBLOCK_END = new String(" */");
    static final String COMMENTLINE_START = new String(" * ");
    
    public ResourceWriter(BufferedWriter w) {
        theWriter = w;
    }

    public void close() throws IOException {
        theWriter.flush();
        theWriter.close();
    }

    protected void writenl(String s) throws IOException {
        theWriter.write(s, 0, s.length());
        theWriter.newLine();
    }

    protected void write(String s) throws IOException {
        theWriter.write(s, 0, s.length());
    }

    public void fileheader() throws IOException {
        writenl("/* ");
	writenl(" * GENERATED CODE");
        writenl(" *"); 
        writenl(" * Copyright 1999 Sun Microsystems, Inc.");
        writenl(" * All rights reserved.");
	writenl(" *");
        writenl(" */");
	writenl("");
        writenl("package com.sun.admin.pm.client;");
        writenl("import java.util.*;");
    }

    public void classheader(String className) throws IOException {
        writenl("public class " + className +
                " extends ListResourceBundle {");
        writenl(INDENT +
                "static final Object[][] pmHelpBundlecontents = {");
    }

    public void footer() throws IOException {
        writenl(INDENT + "};");
        writenl(INDENT + "public Object[][] getContents() {");
        writenl(INDENT_2 + "return pmHelpBundlecontents;");
        writenl(INDENT + "}");
        writenl("}");
    }


    public void setTag(String tag) throws IOException {
        theTag = new String(tag);
    }
    
    public void tag(String tag) throws IOException {
        if (tag != null) {
            writenl(NL + INDENT_2 + NOLOCALIZE);
            writenl(INDENT_2 + 
		"{\"" + theTag + ".tag\", \"" + tag + "\"},");
        }
    }

    public void title(String title) throws IOException {
        if (title != null) {
            writenl(NL + INDENT_2 + LOCALIZE);
            writenl(INDENT_2 + 
		"{\"" + theTag + ".title\", \"" + title + "\"},");
        }
    }

    public void seealso(String seealso) throws IOException {
        if (seealso != null) {
            writenl(NL + INDENT_2 + NOLOCALIZE);
            writenl(INDENT_2 + 
		"{\"" + theTag + ".seealso\", \"" + seealso + "\"},");
        }
    }

    public void keywords(String keywords) throws IOException {
        if (keywords != null) {
            writenl(NL + INDENT_2 + LOCALIZE);
            writenl(INDENT_2 + 
		"{\"" + theTag + ".keywords\", \"" + keywords + "\"},");
        }
    }

    public void content(Vector content) throws IOException {
        if (content == null)
            return;
        
        writenl(NL + INDENT_2 + LOCALIZE);
        writenl(INDENT_2 + "{\"" + theTag + ".content\",");

        Enumeration e = content.elements();
        while (e.hasMoreElements()) {
            String s = (String) e.nextElement();
            if (s.length() == 0) {
                if (e.hasMoreElements())
                    continue;
                else {
                    writenl(INDENT_2 + "  \"\"\n        },");
                    break;
                }
            }
            String endOfLine = (e.hasMoreElements() ?
                " +" :
                "\n        },");
            writenl(INDENT_2 + "  \"" + s + " \"" + endOfLine);
        }
    }

    public void delimiter() throws IOException { 
        writenl(NL);
    }
    
    public void commentStart() throws IOException {
	writenl(COMMENTBLOCK_START);
    }

    public void commentEnd() throws IOException {
	writenl(COMMENTBLOCK_END);
    }

    public void comment(String s) throws IOException {
	writenl(COMMENTLINE_START + s);
    }
}




class Article {
    String theTitle;
    String theKeywords;
    String theSeeAlso;
    Vector theContent;
    String theTag;

    Reader r;

    public void read(Reader theReader) {
        r = theReader;

        Tag theTag = null;
    
        try {
            while (true) {
                theTag = readNextTag();
                Debug.message("Article read: " + theTag);

                if (theTag instanceof CommentTag) {
                    Debug.message("Comment ignored");
                } else if (theTag instanceof TitleTag) {
                    theTitle = theTag.content;
                } else if (theTag instanceof ContentTag) {
                    theContent = theTag.contentVector;
                } else if (theTag instanceof SeeAlsoTag) {
                    theSeeAlso = theTag.content;
                } else if (theTag instanceof KeywordsTag) {
                    theKeywords = theTag.content;
                } else {
                    Debug.message("Unknown tag: " + theTag);
                }
            }
        } catch (IOException x) {
            Debug.message("Article read caught " + x);
        }

    
    }


    int localread() throws IOException {
        int ch = r.read();
        if (ch == -1) {
            Debug.message("localread: eof");
            throw new IOException();
        }
        // Debug.message("localread: " + ch);
        return ch;
    }
    

    /*
     * read the word within tagOpen/tagClose pair
     */
    String readTagName() throws IOException {
        String rv = null;
        int ch;
        StringBuffer b = new StringBuffer();

        while (true) 
            if (localread() == HelpSyntax.tagOpen)
                break;

        Debug.message("readTagName: got a tagOpen");
    
        while (true) {
            ch = localread();
            if (ch == HelpSyntax.tagClose)
                break;
            else
                b.append((char) ch);
        }
    
        Debug.message("readTagName: " + (new String(b)).trim());
        return (new String(b)).trim();
    }


    Tag readNextTag() throws IOException {
        Tag rv = null;
        int ch;
        StringBuffer b;

        String tag = readTagName();
        Debug.message("readNextTag name: " + tag);

        if (tag.equalsIgnoreCase(HelpSyntax.tagTitle)) {
            rv = new TitleTag();
            rv.read(r);
        } else if (tag.equalsIgnoreCase(HelpSyntax.tagKeywords)) {
            rv = new KeywordsTag();
            rv.read(r);
        } else if (tag.equalsIgnoreCase(HelpSyntax.tagSeeAlso)) {
            rv = new SeeAlsoTag();
            rv.read(r);
        } else if (tag.equalsIgnoreCase(HelpSyntax.tagContent)) {
            rv = new ContentTag();
            rv.readMultipleLines(r);
        } else {
            Debug.message("Bad tag: " + tag);
        }
        return rv;
    }


    public String toString() {
        return new String("Title <" + theTitle +
                          "> Keywords <" + theKeywords +
                          "> See-Also <" + theSeeAlso +
                          "> Content <" + theContent + ">");
    }
}


class HelpSyntax {
    public final static int tagOpen = '<';
    public final static int tagClose = '>';
    public final static String startComment = "!-";
    public final static String endComment = "--";
    public final static String tagContent = "CONTENT";
    public final static String tagTitle = "TITLE";
    public final static String tagSeeAlso = "SEEALSO";
    public final static String tagKeywords = "KEYWORDS";
}
  
class ParseException extends Exception {
}

class BadTagException extends ParseException {
}

class SyntaxErrorException extends ParseException {
}

abstract class Tag {
    String content;
    Vector contentVector;
    protected String name;
    protected boolean escapeQuotes = false;

    public Tag(String s) {
        content = s;
    }

    public Tag() {
        this(null);
    }

    public String toString() {
        return new String(this.getClass().getName() + ": " + content);
    }

    // respect line spacing, stuff contentVector
    public void readMultipleLines(Reader r) throws IOException {
        int ch;
        StringBuffer b = new StringBuffer();
        Vector v = new Vector();
        boolean spaced = false;

        while (true) {
            ch = r.read();
            if (ch == -1)
                break;

            if (ch == '\n') {
                v.addElement(new String(b));
                b = new StringBuffer();
                continue;
            }
            
            if (Character.isWhitespace((char) ch)) {
                if (spaced == false) {
                    b.append(" ");
                    spaced = true;
                }
                continue;
            } 

            if (escapeQuotes && ch == '\"') {
                b.append("\\\"");
                continue;
            }
        
            spaced = false;
            if (ch == HelpSyntax.tagOpen) {
                boolean localspaced = false;
                boolean localopen = true;
                Debug.message("Tag: got a tagOpen");

                StringBuffer tmp = new StringBuffer();
                while ((ch = r.read()) != HelpSyntax.tagClose) {
                    if (Character.isWhitespace((char) ch)) {
                        if (localspaced == false) {
                            tmp.append(" ");
                            localspaced = true;
                        }
                        continue;
                    } 
                    tmp.append((char) ch);
                }

                String t = new String(tmp);
    
                if ((t.trim()).equalsIgnoreCase("/" + this.name)) {
                    Debug.message("Tag: close tag = " + t);
                    break;
                } else {
                    Debug.message("Tag: ignoring bad close tag = " + t);
                    b.append((char) HelpSyntax.tagOpen);
                    b.append(t);
                    b.append((char) HelpSyntax.tagClose);
                }
            } else {
                b.append((char)ch);
            }
        }
        contentVector = v;
        Debug.message("Tag: contentVector = " + contentVector);
    }

    // catenate input lines, eliminating whitespace
    public void read(Reader r) throws IOException {
        int ch;
        StringBuffer b = new StringBuffer();
        boolean spaced = false;

        while (true) {
            ch = r.read();
            if (ch == -1)
                break;

            if (Character.isWhitespace((char) ch)) {
                if (spaced == false) {
                    b.append(" ");
                    spaced = true;
                }
                continue;
            } 

            if (escapeQuotes && ch == '\"') {
                b.append("\\\"");
                continue;
            }
        
            spaced = false;
            if (ch == HelpSyntax.tagOpen) {
                boolean localspaced = false;
                boolean localopen = true;
                Debug.message("Tag: got a tagOpen");

                StringBuffer tmp = new StringBuffer();
                while ((ch = r.read()) != HelpSyntax.tagClose) {
                    if (Character.isWhitespace((char) ch)) {
                        if (localspaced == false) {
                            tmp.append(" ");
                            localspaced = true;
                        }
                        continue;
                    } 
                    tmp.append((char) ch);
                }

                String t = new String(tmp);
    
                if ((t.trim()).equalsIgnoreCase("/" + this.name)) {
                    Debug.message("Tag: close tag = " + t);
                    break;
                } else {
                    Debug.message("Tag: ignoring bad close tag = " + t);
                    b.append((char) HelpSyntax.tagOpen);
                    b.append(t);
                    b.append((char) HelpSyntax.tagClose);
                }
            } else {
                b.append((char)ch);
            }
        }
        content = (new String(b)).trim();
        Debug.message("Tag: content = " + content);
    }
}

class TitleTag extends Tag {
    public TitleTag() {
        name = HelpSyntax.tagTitle;
    }
}

class SeeAlsoTag extends Tag {
    public SeeAlsoTag() {
        name = HelpSyntax.tagSeeAlso;
    }
}

class ContentTag extends Tag {
    public ContentTag() {
        name = HelpSyntax.tagContent;
        escapeQuotes = true;
    }
}

class CommentTag extends Tag {
    public CommentTag() {
        name = null;
    }
}

class KeywordsTag extends Tag {
    public KeywordsTag() {
        name = HelpSyntax.tagKeywords;
        escapeQuotes = true;
    }
}



class parseMain {

    static String outputFileName = "pmHelpResources.java";
    static String commentFileName = "comments.txt";
    static int firstFile = 0;

    // returns -1 if error, 0 otherwise
    protected static int parseArgs(String[] args) {
        int rv = 0;
	int i;
        
        for (i = 0; i < args.length; ++i) {
            if (args[i].compareTo("-d") == 0) {
		if (args[i].length() > 2) {
		    outputFileName = args[i].substring(2);
		} else {
		    outputFileName = args[++i];
		}
	    } else if (args[i].compareTo("-c") == 0) {
		if (args[i].length() > 2) {
		    commentFileName = args[i].substring(2);
		} else {
		    commentFileName = args[++i];
		}
	    } else if (args[i].compareTo("-v") == 0) {
		Debug.setDebugLevel(Debug.WARNING);
	    } else
		break;	// unknown arg ==> list of files starts

        }

	firstFile = i;
        
	/*
	 * System.out.println("outputFileName = " + outputFileName +
	 *		   " commentFileName = " + commentFileName  + 
	 *		   " firstFile = " + firstFile);
	 */

        return rv;
    }
    

    public static void main(String args[]) {
        FileReader f = null;
        FileWriter fw = null;
        String filename = null;
    
        Debug.setDebugLevel(Debug.ERROR);

        // validate command line
        if (args.length == 0) {
            System.err.println("At least one filename required.");
            System.exit(-1);
        }

        if (parseArgs(args) < 0)
            System.exit(-1);


        outputFileName = outputFileName.trim();

        Debug.warning("Writing to " + outputFileName);
    
        try {

            // create output file
            fw = new FileWriter(outputFileName);
            BufferedWriter w = new BufferedWriter(fw);
            ResourceWriter rw = new ResourceWriter(w);
	
	    // imports and package statement
            rw.fileheader();

	    // comment block
            File commentFile = new File(commentFileName);
	    if (commentFile.exists()) {
                rw.delimiter();
		rw.commentStart();
		BufferedReader comments = 
			new BufferedReader(new FileReader(commentFileName));
		String commentLine; 
		while ((commentLine = comments.readLine()) != null)
		    rw.comment(commentLine);
		comments.close();
		rw.commentEnd();
                rw.delimiter();
	    } else {
		Debug.error("Comment file " + commentFileName + 
								" not found.");
	    }

	    // create class name w/o extension or leading path
	    File cf = new File(outputFileName);
	    String className = cf.getName();
    
            // class name is output filename w/o extension
            int dotIndex = className.indexOf(".");
            if (dotIndex < 0)
                dotIndex = className.length();

            className = className.substring(0, dotIndex);

	    // class definition
            rw.classheader(className);
   
            // iterate over input files
            for (int i = firstFile; i < args.length; ++i) {
                filename = args[i];
                Debug.warning("Reading file " + filename);

                try {
                    f = new FileReader(filename);
                } catch (Exception x) {
                    Debug.fatal(x.toString());
                    return;
                }

                BufferedReader r = new BufferedReader(f);

                Article a = new Article();
                a.read(r);
                // System.out.println(a);

                // process the Article

                String tagName = filenameToTag(filename);
                Debug.warning("Creating tag " + tagName);

                // HTML syntax checking on content
                if (!validHTMLSyntax(a.theContent)) 
                    throw new IOException(
                        "Bad HTML syntax in article " + tagName);
            
        
                rw.setTag(tagName);
                rw.tag(tagName);
                rw.seealso(a.theSeeAlso);
                rw.title(a.theTitle);
                rw.keywords(a.theKeywords);
                rw.content(a.theContent);
                rw.delimiter();
            }
    
            rw.footer();
            rw.close();
            w.close();
        } catch (IOException x) {
            Debug.fatal(x.toString());

            // try to unlink the broken output file
            boolean unlink = true;
        
            try {
                fw.close();
            } catch (IOException xx) {
                Debug.error(xx.toString());
                unlink = false;
            } 

            if (unlink) {
                File theFile = new File(outputFileName);

                Debug.warning("Deleting file " + outputFileName);
            
                if (theFile.exists())
                    theFile.delete();
            }
        
            System.exit(-2);
        }
    }


    // return true if no syntax errors found
    static boolean validHTMLSyntax(String s) {

        if (s == null)
            return true;

        // check only for <b>..</b> pairs

        String src = s.toLowerCase();   // html tags are case-neutral

        int i;
        
        int opens = 0;
        for (i = src.indexOf("<b>");
             i != -1;
             i = src.indexOf("<b>", i + 1))
            ++opens;

        int closes = 0;
        for (i = src.indexOf("</b>");
            i != -1;
            i = src.indexOf("</b>", i + 1))
            ++closes;

        // System.out.println("syntax: " + opens + " " + closes);

        return opens == closes;
        
    }

    // return true if no syntax errors found
    static boolean validHTMLSyntax(Vector v) {
        String s = new String();
        Enumeration e = v.elements();
        while (e.hasMoreElements()) 
            s = s + (String) e.nextElement();
        return validHTMLSyntax(s);
    }

    /*
     * extract the tag name from a filename, possibly containing
     * a fully qualified path as well as a complex extension.
     */
    static String filenameToTag(String filename) {

        // the help tag is the filename exclusive of path or extensions

        File f = new File(filename);
        String s = f.getName();
        int period = s.indexOf('.');
        // System.out.println("filename: " + s);
        if (period < 0)
            period = filename.length();
        // System.out.println("period = " + period);
        return s.substring(0, period);
    }


}

class Debug {

    /**
     * Log a highest-priority message.
     * @param String s The message to be logged.
     */
    static public void fatal(String s) {
        printIf(s, FATAL);
    }

    /**
     * Log a highest-priority message.
     * @param String s The message to be logged.
     */
    static public void error(String s) {
        printIf(s, ERROR);
    }

    /**
     * Log a highest-priority message.
     * @param String s The message to be logged.
     */
    static public void warning(String s) {
        printIf(s, WARNING);
    }

    /**
     * Log a highest-priority message.
     * @param String s The message to be logged.
     */
    static public void message(String s) {
        printIf(s, MESSAGE);
    }

    /**
     * Log a highest-priority message.
     * @param String s The message to be logged.
     */
    static public void setDebugLevel(int lvl) {
        if (lvl < ALL || lvl > NONE)
            return;
        
        globalDebugLevel = lvl;
    }

    private static void printIf(String s, int lvl) {
        if (lvl < globalDebugLevel)
            return;
        DebugPrint(s);
    }

    // here is where we could hide syslog or file destination...
    private static void DebugPrint(String s) {
        System.out.println(s);         // for now
    }
    
    
    /**
     * Verbosity level to suppress all messages.
     */
    static public final int NONE = 5;

    /**
     * Verbosity level to log only highest-priority messages.
     */
    static public final int FATAL = 4;

    /**
     * Verbosity level to log  high- and highest-priority messages.
     */
    static public final int ERROR = 3;

    /**
     * Verbosity level to log medium-, high-, and
     * highest-priority messages.
     */
    static public final int WARNING = 2;

    /**
     * Verbosity level to log low-, medium-, high-, and
     *  highest-priority messages.
     */
    static public final int MESSAGE = 1;

    /**
     * Verbosity level to log all messages.
     */
    static public final int ALL = 0;
    
    private static int globalDebugLevel = ERROR;

}
