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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *        Copyright (C) 1996  Active Software, Inc.
 *                  All rights reserved.
 *
 * @(#) ColorStore.java 1.15 - last change made 07/10/97
 */

package sunsoft.jws.visual.rt.type;

import sunsoft.jws.visual.rt.base.Global;

import java.awt.Color;
import java.util.Hashtable;
import java.util.Enumeration;

/**
 * Stores colors by name and rgb value.  Names are always stored in
 * lower case, and searches are done after converting the search key
 * into lower case.  Two hashtables are used so colors can be accessed
 * efficiently either by color or name.
 *
 * @version 1.15, 07/10/97
 */
public class ColorStore {
    // COLOR <-> NAME HASHTABLES
    
    /**
     * Storage place for Color RGB values and named colors.
     * It's like a two-way hashtable.
     */
    private static ColorStore defaultColorStore;
    
    /**
     * Returns a reference to the single global instance of ColorStore.
     */
    public static ColorStore getDefaultColorStore() {
        initColorStore();
        return (defaultColorStore);
    }
    
    private static void initColorStore() {
        if (defaultColorStore != null)
            return;
        defaultColorStore = new ColorStore();
        defaultColorStore.initDefaultColorList();
    }
    
    
    /**
     * Storage place for Color RGB values (keys) and named colors (values)
     */
    private Hashtable rgbkeys;
    
    /**
     * Storage place for named colors (keys) Color RGB values (values)
     */
    private Hashtable namekeys;
    
    /**
     * A list sorted by colorName (a-z)
     */
    
    private String[] colorNameArray;
    
    public ColorStore() {
        rgbkeys = new Hashtable();
        namekeys = new Hashtable();
    }
    
    /**
     * Returns the name of a color.  If the color name is not in
     * our table, return #RRGGBB (a string of hex numbers).
     */
    public String getColorName(Color c) {
        return (String) rgbkeys.get(c);
    }
    
    /**
     * Given the name of a color, return the Color corresponding to it.
     */
    public Color getColor(String name) {
        if (name == null) {
            return null;
        } else {
            return ((Color) namekeys.get(name.toLowerCase()));
        }
    }
    
    /**
     * Given a Color, return the name of the color listed in the
     * ColorStore closest to that color.
     */
    public String getClosestColorName(Color c) {
        
        Enumeration e;
        int difference = 255*3, newDifference;
        Color bestColor = null, cKey;
        
        if (rgbkeys.containsKey(c)) {
            return (getColorName(c));
        }
        
        e = rgbkeys.keys();
        while (e.hasMoreElements()) {
            cKey = (Color) e.nextElement();
            
            if ((newDifference =
		 (Math.abs(cKey.getRed() - c.getRed())) +
		 (Math.abs(cKey.getGreen() - c.getGreen())) +
		 (Math.abs(cKey.getBlue() - c.getBlue()))) <=
		difference)
		{
		    difference = newDifference;
		    bestColor = cKey;
		}
        }
        return getColorName(bestColor);
    }
    
    /**
     * Adds the color/name pair to the color store is it is not already
     * there and returns the name of the color.  If the color is already
     * registered, the previous name of the color is returned.
     */
    public String add(Color c, String name) {
        if (rgbkeys.containsKey(c)) {
            return (getColorName(c));
        } else {
            rgbkeys.put(c, name.toLowerCase());
            namekeys.put(name, c);
            colorNameArray = null;
            return (name);
        }
    }
    
    /**
     * Returns the list of Colors named in the ColorStore.
     */
    public String[] getColorList() {
        int index;
        
        if (colorNameArray == null) {
            colorNameArray = new String[rgbkeys.size()];
            
            index = 0;
            Enumeration e = namekeys.keys();
            
            while (e.hasMoreElements()) {
                String colorName = (String)(e.nextElement());
                colorNameArray[index] = colorName;
                index++;
            }
            
            Global.util.qsort(colorNameArray);
        }
        return colorNameArray;
    }
    
    private void initDefaultColorList() {
        // Java.awt.Color constants:
        
        add(Color.black, /* NOI18N */"black");
        add(Color.blue, /* NOI18N */"blue");
        add(Color.cyan, /* NOI18N */"cyan");
        add(Color.darkGray, "darkgray");
        add(Color.gray, /* NOI18N */"gray");
        add(Color.green, /* NOI18N */"green");
        add(Color.lightGray, "lightgray");
        add(Color.magenta, /* NOI18N */"magenta");
        add(Color.orange, /* NOI18N */"orange");
        add(Color.pink, /* NOI18N */"pink");
        add(Color.red, /* NOI18N */"red");
        add(Color.white, /* NOI18N */"white");
        add(Color.yellow, /* NOI18N */"yellow");
        
        // Colors from rgb.txt:
        
        add(new Color(133, 133, 133), /* NOI18N */"gray52");
        add(new Color(122, 122, 122), /* NOI18N */"gray48");
        add(new Color(186, 186, 186), /* NOI18N */"gray73");
        add(new Color(94, 94, 94), /* NOI18N */"gray37");
        add(new Color(196, 196, 196), /* NOI18N */"gray77");
        add(new Color(84, 84, 84), /* NOI18N */"gray33");
        add(new Color(66, 66, 66), /* NOI18N */"gray26");
        add(new Color(48, 48, 48), /* NOI18N */"gray19");
        add(new Color(92, 92, 92), /* NOI18N */"gray36");
        add(new Color(74, 74, 74), /* NOI18N */"gray29");
        add(new Color(163, 163, 163), /* NOI18N */"gray64");
        add(new Color(28, 28, 28), /* NOI18N */"gray11");
        add(new Color(46, 46, 46), /* NOI18N */"gray18");
        add(new Color(173, 173, 173), /* NOI18N */"gray68");
        add(new Color(36, 36, 36), /* NOI18N */"gray14");
        add(new Color(54, 54, 54), /* NOI18N */"gray21");
        add(new Color(194, 194, 194), /* NOI18N */"gray76");
        add(new Color(150, 150, 150), /* NOI18N */"gray59");
        add(new Color(171, 171, 171), /* NOI18N */"gray67");
        add(new Color(3, 3, 3), /* NOI18N */"gray1");
        add(new Color(181, 181, 181), /* NOI18N */"gray71");
        add(new Color(20, 20, 20), /* NOI18N */"gray8");
        add(new Color(10, 10, 10), /* NOI18N */"gray4");
        add(new Color(207, 207, 207), /* NOI18N */"gray81");
        add(new Color(99, 99, 99), /* NOI18N */"gray39");
        add(new Color(237, 237, 237), /* NOI18N */"gray93");
        add(new Color(79, 79, 79), /* NOI18N */"gray31");
        add(new Color(87, 87, 87), /* NOI18N */"gray34");
        add(new Color(204, 204, 204), /* NOI18N */"gray80");
        add(new Color(214, 214, 214), /* NOI18N */"gray84");
        add(new Color(235, 235, 235), /* NOI18N */"gray92");
        add(new Color(245, 245, 245), /* NOI18N */"gray96");
        add(new Color(8, 8, 8), /* NOI18N */"gray3");
        add(new Color(71, 71, 71), /* NOI18N */"gray28");
        add(new Color(201, 201, 201), /* NOI18N */"gray79");
        add(new Color(61, 61, 61), /* NOI18N */"gray24");
        add(new Color(51, 51, 51), /* NOI18N */"gray20");
        add(new Color(33, 33, 33), /* NOI18N */"gray13");
        add(new Color(15, 15, 15), /* NOI18N */"gray6");
        add(new Color(117, 117, 117), /* NOI18N */"gray46");
        add(new Color(31, 31, 31), /* NOI18N */"gray12");
        add(new Color(13, 13, 13), /* NOI18N */"gray5");
        add(new Color(105, 105, 105), /* NOI18N */"gray41");
        add(new Color(148, 148, 148), /* NOI18N */"gray58");
        add(new Color(252, 252, 252), /* NOI18N */"gray99");
        add(new Color(115, 115, 115), /* NOI18N */"gray45");
        add(new Color(158, 158, 158), /* NOI18N */"gray62");
        add(new Color(179, 179, 179), /* NOI18N */"gray70");
        add(new Color(240, 240, 240), /* NOI18N */"gray94");
        add(new Color(189, 189, 189), /* NOI18N */"gray74");
        add(new Color(250, 250, 250), /* NOI18N */"gray98");
        add(new Color(199, 199, 199), /* NOI18N */"gray78");
        add(new Color(145, 145, 145), /* NOI18N */"gray57");
        add(new Color(70, 130, 180), /* NOI18N */"steel blue");
        add(new Color(233, 150, 122), /* NOI18N */"darksalmon");
        add(new Color(100, 149, 237), /* NOI18N */"cornflowerblue");
        add(new Color(30, 144, 255), /* NOI18N */"dodgerblue");
        add(new Color(238, 221, 130), /* NOI18N */"lightgoldenrod");
        add(new Color(205, 133, 63), /* NOI18N */"peru");
        add(new Color(154, 205, 50), /* NOI18N */"yellow green");
        add(new Color(175, 238, 238), /* NOI18N */"paleturquoise");
        add(new Color(0, 100, 0), /* NOI18N */"darkgreen");
        add(new Color(160, 82, 45), /* NOI18N */"sienna");
        add(new Color(143, 188, 143), /* NOI18N */"darkseagreen");
        add(new Color(255, 228, 196), /* NOI18N */"bisque");
        add(new Color(147, 112, 219), /* NOI18N */"mediumpurple");
        add(new Color(148, 0, 211), /* NOI18N */"dark violet");
        add(new Color(124, 252, 0), /* NOI18N */"lawn green");
        add(new Color(119, 136, 153), /* NOI18N */"lightslategray");
        add(new Color(230, 230, 250), /* NOI18N */"lavender");
        add(new Color(248, 248, 255), /* NOI18N */"ghostwhite");
        add(new Color(176, 224, 230), /* NOI18N */"powderblue");
        add(new Color(218, 165, 32), /* NOI18N */"goldenrod");
        add(new Color(255, 228, 181), /* NOI18N */"moccasin");
        add(new Color(255, 228, 225), /* NOI18N */"mistyrose");
        add(new Color(255, 255, 224), /* NOI18N */"light yellow");
        add(new Color(255, 99, 71), /* NOI18N */"tomato");
        add(new Color(245, 255, 250), /* NOI18N */"mintcream");
        add(new Color(138, 43, 226), /* NOI18N */"blueviolet");
        add(new Color(32, 178, 170), /* NOI18N */"light sea green");
        add(new Color(255, 240, 245), /* NOI18N */"lavender blush");
        add(new Color(127, 255, 212), /* NOI18N */"aquamarine");
        add(new Color(165, 42, 42), /* NOI18N */"brown");
        add(new Color(219, 112, 147), /* NOI18N */"pale violet red");
        add(new Color(240, 255, 255), /* NOI18N */"azure");
        add(new Color(107, 142, 35), /* NOI18N */"olivedrab");
        add(new Color(47, 79, 79), /* NOI18N */"darkslategray");
        add(new Color(139, 69, 19), /* NOI18N */"saddle brown");
        add(new Color(160, 32, 240), /* NOI18N */"purple");
        add(new Color(186, 85, 211), /* NOI18N */"medium orchid");
        add(new Color(240, 255, 240), /* NOI18N */"honeydew");
        add(new Color(176, 196, 222), /* NOI18N */"lightsteelblue");
        add(new Color(64, 224, 208), /* NOI18N */"turquoise");
        add(new Color(255, 127, 80), /* NOI18N */"coral");
        add(new Color(184, 134, 11), /* NOI18N */"darkgoldenrod");
        add(new Color(60, 179, 113), /* NOI18N */"mediumseagreen");
        add(new Color(210, 180, 140), /* NOI18N */"tan");
        add(new Color(255, 222, 173), /* NOI18N */"navajo white");
        add(new Color(46, 139, 87), /* NOI18N */"sea green");
        add(new Color(123, 104, 238), /* NOI18N */"mediumslateblue");
        add(new Color(250, 250, 210), /* NOI18N */
	    "light goldenrod yellow");
        add(new Color(135, 206, 235), /* NOI18N */"sky blue");
        add(new Color(132, 112, 255), /* NOI18N */"lightslateblue");
        add(new Color(250, 240, 230), /* NOI18N */"linen");
        add(new Color(218, 112, 214), /* NOI18N */"orchid");
        add(new Color(0, 0, 128), /* NOI18N */"navy blue");
        add(new Color(253, 245, 230), /* NOI18N */"old lace");
        add(new Color(240, 248, 255), /* NOI18N */"aliceblue");
        add(new Color(72, 209, 204), /* NOI18N */"mediumturquoise");
        add(new Color(255, 140, 0), /* NOI18N */"dark orange");
        add(new Color(72, 61, 139), /* NOI18N */"dark slate blue");
        add(new Color(255, 160, 122), /* NOI18N */"light salmon");
        add(new Color(221, 160, 221), /* NOI18N */"plum");
        add(new Color(238, 130, 238), /* NOI18N */"violet");
        add(new Color(34, 139, 34), /* NOI18N */"forest green");
        add(new Color(0, 255, 127), /* NOI18N */"springgreen");
        add(new Color(85, 107, 47), /* NOI18N */"darkolivegreen");
        add(new Color(238, 232, 170), /* NOI18N */"pale goldenrod");
        add(new Color(245, 245, 220), /* NOI18N */"beige");
        add(new Color(255, 250, 240), /* NOI18N */"floralwhite");
        add(new Color(255, 218, 185), /* NOI18N */"peach puff");
        add(new Color(50, 205, 50), /* NOI18N */"limegreen");
        add(new Color(152, 251, 152), /* NOI18N */"palegreen");
        add(new Color(240, 230, 140), /* NOI18N */"khaki");
        add(new Color(188, 143, 143), /* NOI18N */"rosybrown");
        add(new Color(244, 164, 96), /* NOI18N */"sandybrown");
        add(new Color(189, 183, 107), /* NOI18N */"darkkhaki");
        add(new Color(25, 25, 112), /* NOI18N */"midnight blue");
        add(new Color(255, 235, 205), /* NOI18N */"blanched almond");
        add(new Color(224, 255, 255), /* NOI18N */"light cyan");
        add(new Color(255, 182, 193), /* NOI18N */"lightpink");
        add(new Color(95, 158, 160), /* NOI18N */"cadetblue");
        add(new Color(106, 90, 205), /* NOI18N */"slate blue");
        add(new Color(245, 222, 179), /* NOI18N */"wheat");
        add(new Color(255, 69, 0), /* NOI18N */"orangered");
        add(new Color(127, 255, 0), /* NOI18N */"chartreuse");
        add(new Color(255, 255, 255), /* NOI18N */"white");
        add(new Color(65, 105, 225), /* NOI18N */"royalblue");
        add(new Color(173, 216, 230), /* NOI18N */"light blue");
        add(new Color(255, 250, 250), /* NOI18N */"snow");
        add(new Color(255, 245, 238), /* NOI18N */"seashell");
        add(new Color(250, 128, 114), /* NOI18N */"salmon");
        add(new Color(255, 255, 240), /* NOI18N */"ivory");
        add(new Color(255, 239, 213), /* NOI18N */"papaya whip");
        add(new Color(153, 50, 204), /* NOI18N */"dark orchid");
        add(new Color(208, 32, 144), /* NOI18N */"violet red");
        add(new Color(255, 248, 220), /* NOI18N */"cornsilk");
        add(new Color(255, 105, 180), /* NOI18N */"hotpink");
        add(new Color(176, 48, 96), /* NOI18N */"maroon");
        add(new Color(178, 34, 34), /* NOI18N */"firebrick");
        add(new Color(240, 128, 128), /* NOI18N */"lightcoral");
        add(new Color(220, 220, 220), /* NOI18N */"gainsboro");
        add(new Color(216, 191, 216), /* NOI18N */"thistle");
        add(new Color(135, 206, 250), /* NOI18N */"light sky blue");
        add(new Color(210, 105, 30), /* NOI18N */"chocolate");
        add(new Color(173, 255, 47), /* NOI18N */"green yellow");
        add(new Color(112, 128, 144), /* NOI18N */"slate gray");
        add(new Color(0, 191, 255), /* NOI18N */"deepskyblue");
        add(new Color(255, 250, 205), /* NOI18N */"lemon chiffon");
        add(new Color(0, 206, 209), /* NOI18N */"dark turquoise");
        add(new Color(222, 184, 135), /* NOI18N */"burlywood");
        add(new Color(199, 21, 133), /* NOI18N */"mediumvioletred");
        add(new Color(250, 235, 215), /* NOI18N */"antique white");
        add(new Color(255, 215, 0), /* NOI18N */"gold");
        add(new Color(255, 20, 147), /* NOI18N */"deep pink");
        add(new Color(205, 92, 92), /* NOI18N */"indianred");
        add(new Color(0, 250, 154), /* NOI18N */"medium spring green");
    }
}
