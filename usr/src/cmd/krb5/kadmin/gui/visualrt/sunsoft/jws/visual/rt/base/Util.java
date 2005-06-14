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
/*
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) Util.java 1.43 - last change made 07/16/97
 */

package sunsoft.jws.visual.rt.base;

import java.awt.*;
import java.util.*;
import java.io.*;

import java.awt.image.RGBImageFilter;
import java.awt.image.FilteredImageSource;
import java.net.URL;
import java.net.MalformedURLException;
import java.applet.Applet;

/**
 * Utilities needed by run-time.
 *
 * @version 	1.32, 03/09/97
 */
public class Util {
	// Relief constants
	public static final int RELIEF_FLAT   = 0;
	public static final int RELIEF_RAISED = 1;
	public static final int RELIEF_SUNKEN = 2;
	public static final int RELIEF_RIDGE  = 3;
	public static final int RELIEF_GROOVE = 4;
	public static final int WIN95_RAISED = 6;
	public static final int WIN95_SUNKEN = 7;
	public static final int WIN95_FIELD_BORDER = 8;
	public static final int WIN95_WINDOW_BORDER = 9;
	public static final int BLACK_BORDER = 10;
    
	// Character constants
	public static final char BACKSLASH	= /* NOI18N */ '\\';
	public static final char COLON	= /* NOI18N */ ':';
	public static final char NEWLINE	= /* NOI18N */ '\n';
	public static final char RETURN	= /* NOI18N */ '\r';
	public static final char SLASH	= /* NOI18N */ '/';
	public static final char SPACE	= /* NOI18N */ ' ';
    
    
	// codebase the user specified in the project - used at design time
	private String codebaseStr = null;
    
	// default class loader
	private CustomClassLoader classLoader;
    
	// Darkness constants
	private static final double BFACTOR = 0.82;
	private static final double DFACTOR = 0.7;
    
	// Buffer size for reading files
	private static final int BUFSIZE = 2048;
    
	public Util() {
		classLoader = new VBClassLoader();
	}
    
	/**
	 * Returns a brighter version of this color.
	 *
	 * This version is adjusted to compensate for border cases:
	 * If the base is white, the brighter color sometimes gets lost
	 * against the background, so the border of the panel (or whatever)
	 * is not seen. (Sun Bug # 4035733)
	 * The solution is to check if the "brighter" color
	 * is too bright, and if
	 * so, set it to a light grey.
	 *
	 */
    
	public Color brighter(Color c) {
		int r = c.getRed();
		int g = c.getGreen();
		int b = c.getBlue();
        
		r = Math.min((int)(r * (1/BFACTOR)), 255);
		g = Math.min((int)(g * (1/BFACTOR)), 255);
		b = Math.min((int)(b * (1/BFACTOR)), 255);
        
		if (r > 250 && g > 250 && b > 250) {
			// note: we use the JDK darker, which simply makes
			// the color darker,
			//       rather than this.darker, which will turn
			// values of 255 into
			//       128.
			return new Color(225, 225, 225);
		}
		/* JSTYLED */
		return new Color(r, g, b);
	}
    
	/**
	 * Returns a darker version of this color.
	 */
	public Color darker(Color c) {
		int r = c.getRed();
		int g = c.getGreen();
		int b = c.getBlue();
        
		if (r == 255)
			r = 128;
		else
			r = Math.max((int)(r * DFACTOR), 0);
        
		if (g == 255)
			g = 128;
		else
			g = Math.max((int)(g * DFACTOR), 0);
        
		if (b == 255)
			b = 128;
		else
			b = Math.max((int)(b * DFACTOR), 0);
        
		return new Color(r, g, b);
	}
    
	/**
	 * Draw a 3D rectable with the given relief and border width.
	 */
	public void draw3DRect(Graphics g, int x, int y, int w, int h,
			    int relief, int bd) {
		int bd2 = (bd+1)/2;
		for (int i = 0; i < bd; i++)
			draw3DRect(g, x+i, y+i, w-2*i, h-2*i, relief,
				(i < bd2));
	}
    
	/**
	 * Draw a 3D rectable with the given relief and outer boolean.
	 */
	private void draw3DRect(Graphics g, int x, int y, int w, int h,
				int relief, boolean isOuter) {
		Color color = g.getColor();
        
		g.setColor(getEdgeColor(color, relief, true, isOuter));
		g.drawLine(x, y, x+w, y);
		g.drawLine(x, y, x, y+h);
        
		g.setColor(getEdgeColor(color, relief, false, isOuter));
		g.drawLine(x, y+h, x+w, y+h);
		g.drawLine(x+w, y, x+w, y+h);
        
		g.setColor(color);
	}
    
    
	/**
	 * Returns an adjusted color for the given
	 * edge and the given relief.
	 */
	private Color getEdgeColor(Color base, int relief,
				boolean isTopEdge, boolean isOuter) {
        
		Color color = null;
        
		switch (relief) {
		case RELIEF_RAISED:
			if (isTopEdge)
				color = brighter(base);
			else
				color = darker(base);
			break;
            
		case RELIEF_SUNKEN:
			if (isTopEdge)
				color = darker(base);
			else
				color = brighter(base);
			break;
            
		case RELIEF_RIDGE:
			if (isTopEdge) {
				if (isOuter)
					color = brighter(base);
				else
					color = darker(base);
			} else {
				if (isOuter)
					color = darker(base);
				else
					color = brighter(base);
			}
			break;
            
		case RELIEF_GROOVE:
			if (isTopEdge) {
				if (isOuter)
					color = darker(base);
				else
					color = brighter(base);
			} else {
				if (isOuter)
					color = brighter(base);
				else
					color = darker(base);
			}
			break;
            
		case WIN95_RAISED:
			if (isTopEdge) {
				if (isOuter)
					color = Color.white;
				else
					color = brighter(base);
			} else {
				if (isOuter)
					color = Color.black;
				else
					color = darker(base);
			}
			break;
            
		case WIN95_SUNKEN:
			if (isTopEdge) {
				if (isOuter)
					color = Color.black;
				else
					color = darker(base);
			} else {
				if (isOuter)
					color = Color.white;
				else
					color =  brighter(base);
                
			}
			break;
            
		case WIN95_FIELD_BORDER:
			if (isTopEdge) {
				if (isOuter)
					color = darker(base);
				else
					color = Color.black;
			} else {
				if (isOuter)
					color = Color.white;
				else
					color = brighter(base);
				// was: base; // brighter(base);
			}
			break;
            
		case WIN95_WINDOW_BORDER:
			if (isTopEdge) {
				if (isOuter)
					color =  brighter(base);
				else
					color = Color.white;
			} else {
				if (isOuter)
					color = Color.black;
				else
					color = darker(base);
			}
			break;
            
		case BLACK_BORDER:
			color = Color.black;
			break;
            
		case RELIEF_FLAT:
		default:
			color = base;
			break;
		}
        
		return color;
	}
    
	/**
	 * Get an image given a url.  If we are on Windows 95, then we
	 * need to use a filter to get around the transparency bugs.
	 */
	public Image getWorkaroundImage(URL url, Component comp) {
		Image image = comp.getToolkit().getImage(url);
		return getWorkaroundImage(image, comp);
	}
    
	/**
	 * Get an image given another.  If we are on Windows 95, then we
	 * need to use a filter to get around the transparency bugs.
	 * Otherwise, just return the image directly.
	 */
	public Image getWorkaroundImage(Image image, Component comp) {
		if (image == null)
			return null;
        
		if (Global.isWindows95() && Global.javaVersion() == 1.0) {
			RGBImageFilter filter = new TransFilter(comp);
			image = comp.createImage(
				new FilteredImageSource(image.getSource(),
							filter));
		}
        
		return image;
	}
    
	/**
	 * When the user specifies/changes the codebase attribute
	 * in the project, 
	 * this method is called to update the value of "codebase" here.
	 * When  we calculate an URL relative to codebase(such as the
	 * ImageLabel "image"  attribute at design time, we use this
	 * codebase value.
	 */
	public boolean setUserCodebase(String newCodebase) {
		codebaseStr = newCodebase;
		return true;
	}
    
	public CustomClassLoader getClassLoader() {
		return (classLoader);
	}
    
	public void setClassLoader(CustomClassLoader newLoader) {
		classLoader = newLoader;
	}
    
	/**
	 * Returns a URL based on a relative path to a file or directory.
	 * If we are running under a browser, then a URL is created based
	 * off of the code base.  Otherwise, a file URL will be created
	 * by searching the CLASSPATH for the file.
	 */
	public URL pathToURL(String path, Applet applet) {
		// general info: determine delimiter and urlPrefix
		String delimiter, urlPrefix;
		if (Global.isWindows()) {
			delimiter = /* NOI18N */";";
			urlPrefix = /* NOI18N */"file:/";
		} else {
			delimiter = /* NOI18N */":";
			urlPrefix = /* NOI18N */"file:";
		}
        
		// First see if the path is a full URL path
		// Note that the user must specify "file:" for files
		try {
			URL url = new URL(path);
			// System.out.println(
			// "           detected full URL - URL=" + url);
			return url;
		}
		catch (MalformedURLException ex) {
		}
        
		// Are we running as an applet?  If running as the Visual Java
		// applet in JWS can't use applet.getCodeBase because it is the
		// codebase of Visual Java, not the users applet, so fall
		// through
		// and use the CLASSPATH
		// Note: There's probably a better way to check if we're the
		// Visual Java applet than checking for classname starting
		// with "sun.jws"
		if ((applet != null) &&
		    !(applet.getClass().getName().startsWith(/* NOI18N */
			    "sun.jws"))) {
			String s = applet.getCodeBase().toExternalForm();
			if (s.charAt(s.length()-1) != SLASH)
				path = /* NOI18N */"/" + path;
            
			URL url;
			try {
				url = new URL(applet.getCodeBase(), path);
			}
			catch (MalformedURLException ex) {
				url = null;
			}
			// System.out.println("           based on codebase="
			// + s + " URL=" + url);
			return url;
		}
        
// Search the CLASSPATH for the file
		String classpath;
		try {
			classpath = System.getProperty(
					/* NOI18N */"java.class.path");
		}
		catch (SecurityException ex) {
			throw new Error(Global.fmtMsg(
			"sunsoft.jws.visual.rt.base.Util.NeedAppletparam",
				Global.newline()));
		}
        
		classpath = DesignerAccess.getCWD() + delimiter + classpath;
        
		StringTokenizer st = new StringTokenizer(classpath, delimiter);
		boolean keepGoing = true;
		while (st.hasMoreTokens() && keepGoing) {
			String p = st.nextToken();
            
			if (p == /* NOI18N */"")
				p = /* NOI18N */".";
            
			p = makeAbsolute(p);
            
			char c = p.charAt(p.length()-1);
			if (c != SLASH && c != BACKSLASH)
				p = p + separator;
            
			p = p + path;
            
			if (Global.isWindows()) {
// Java allows the use of SLASH in the classpath,
// so we need
// convert SLASH to BACKSLASH.
				char buf[] = p.toCharArray();
				for (int i = 0; i < buf.length; i++) {
					if (buf[i] == SLASH)
						buf[i] = BACKSLASH;
				}
				p = new String(buf);
			}
            
			File f = new File(p);
			if (f.exists()) {
				try {
					URL url = new URL(urlPrefix + p);
// System.out.println("           based on
// classpath; found in " + p
//			+ "; URL=" + url +
// " classpath=" + classpath);
					return url;
				}
				catch (MalformedURLException ex) {
			// System.out.println("           based on
			// classpath=" + classpath
			//						+
			// " URL=null");
					keepGoing = false;
				}
			}
		}
        
// Search relative to project's codebase attrib
// (meant for design time only)
		if (codebaseStr != null) {
			URL url;
			String tmpPath;
			if (!codebaseStr.endsWith(/* NOI18N */"/") &&
			    !codebaseStr.endsWith(File.separator)) {
				tmpPath = codebaseStr + /* NOI18N */"/" + path;
			} else {
				tmpPath = codebaseStr + path;
			}
			File f = new File(tmpPath);
			if (f.exists()) {
				tmpPath = urlPrefix + tmpPath;
			}
			try {
				url = new URL(tmpPath);
				// System.out.println("           based on proj
				// codebase=" + codebase + " URL=" + url);
				return url;
			}
			catch (MalformedURLException e) {
				url = null;
			}
		}
        
// System.out.println("           all attempts
// failed - returning null");
		return null;
	}
    
	private static String separator;
	private static String cwd;
    
	private String makeAbsolute(String path) {
		if (separator == null) {
			separator = System.getProperty(/* NOI18N */
				"file.separator");
		}
        
		if (cwd == null) {
			cwd = System.getProperty(/* NOI18N */"user.dir");
			if (cwd.charAt(cwd.length()-1) != separator.charAt(0))
				cwd = cwd + separator;
		}
        
		if (Global.isWindows()) {
			if (path.length() < 3 ||
			    (path.charAt(1) != COLON ||
			    (path.charAt(2) != SLASH && path.charAt(2)
			    		!= BACKSLASH))) {
				path = cwd + path;
			}
		} else {
			if (path.charAt(0) != SLASH)
				path = cwd + path;
		}
        
		return path;
	}
    
/**
 * Compares two objects and returns if they are equal.
 * Will work with
 * null objects
 */
    
	public boolean isEqual(Object o1, Object o2) {
		if (o1 == null) {
			return (o2 == null);
		} else {
			return (o1.equals(o2));
		}
	}
    
/**
 * Quicksort for strings.  Could not get James Gosling's
 * example working
 * properly, or the "fixed" example, so wrote my own using
 * algorithms
 * book.
 */
    
	public void qsort(String[] list) {
		quicksort(list, 0, list.length-1);
	}
    
	private void quicksort(String[] list, int p, int r) {
		if (p < r) {
			int q = partition(list, p, r);
			if (q == r) {
				q--;
			}
			quicksort(list, p, q);
			quicksort(list, q+1, r);
		}
	}
    
	private int partition(String[] list, int p, int r) {
		String pivot = list[p];
		int lo = p;
		int hi = r;
        
		while (true) {
			while (list[hi].compareTo(pivot) >= 0 &&
			    lo < hi) {
				hi--;
			}
			while (list[lo].compareTo(pivot) < 0 &&
			    lo < hi) {
				lo++;
			}
			if (lo < hi) {
				String T = list[lo];
				list[lo] = list[hi];
				list[hi] = T;
			} else return hi;
		}
	}
    
/** 
 * Quicksort for objects.  The is a parameter for a
 * QSortCompare object that is used to do the sorting.
 */
    
	public void qsort(Object[] list, QSortCompare comp) {
		if (list != null)
			quicksort(list, 0, list.length-1, comp);
	}
    
	private void quicksort(Object[] list, int p, int r,
			    QSortCompare comp) {
		if (p < r) {
			int q = partition(list, p, r, comp);
			if (q == r) {
				q--;
			}
			quicksort(list, p, q, comp);
			quicksort(list, q+1, r, comp);
		}
	}
    
	private int partition(Object[] list, int p, int r,
			    QSortCompare comp) {
		Object pivot = list[p];
		int lo = p;
		int hi = r;
        
		while (true) {
			while (comp.qsortCompare(list[hi], pivot) >= 0 &&
			    lo < hi) {
				hi--;
			}
			while (comp.qsortCompare(list[lo], pivot) < 0 &&
			    lo < hi) {
				lo++;
			}
			if (lo < hi) {
				Object T = list[lo];
				list[lo] = list[hi];
				list[hi] = T;
			} else return hi;
		}
	}
    
/**
 * A workaround routine for the Windows95 pack bug in 1.0.2
 *
 * @param c The component to pack
 */
	static public void pack(Window c) {
		c.pack();
		if (Global.isWindows95() || Global.isWindowsNT()) {
			Thread.yield();
			c.pack();
		}
	}
}


/**
* A Work-around filter.
*
* Transparent gifs don't display properly on Windows 95. 
* The work-around
* is to replace transparent pixels with the background color of the
* component they're being displayed in before drawing them.
*/
class TransFilter extends RGBImageFilter {
	private Color bg;
	private Component comp;
    
	TransFilter(Component comp) {
		if (comp == null)
			throw new Error(Global.fmtMsg(
				"sunsoft.jws.visual.rt.base.Util.NullComp",
						    "TransWorkAroundFilter"));
        
		this.comp = comp;
		canFilterIndexColorModel = false;
	}
    
	public int filterRGB(int x, int y, int rgb) {
		if (bg == null)
			bg = comp.getBackground();
        
		if ((rgb & 0xff000000) == 0)
			return (bg.getRGB());
		else
			return (rgb);
	}
    
}
