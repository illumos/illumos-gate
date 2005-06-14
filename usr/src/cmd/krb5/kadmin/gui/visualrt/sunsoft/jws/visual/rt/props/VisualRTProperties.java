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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */
        
/**
 * Copyright 1996 Active Software Inc. 
 */
        
package sunsoft.jws.visual.rt.props;
        
import java.util.ListResourceBundle;
        
public class VisualRTProperties extends ListResourceBundle
{
            
    public Object[][] getContents()
	{
	    return contents;
	}
            
    public VisualRTProperties()
	{
	    super();
	}
            
    static final Object contents[][] = {
/* BEGIN JSTYLED */
	{
	    "sunsoft.jws.visual.rt.shadow.GenericComponentShadow.Class__not__found",
	    "Class not found: "
	}, {
	    "sunsoft.jws.visual.rt.shadow.GenericComponentShadow.FMT.1",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.shadow.GenericComponentShadow.NotAComponentSubclass",
	    "\" {0}\" is not a sublcass of Component"
	}, {
	    "sunsoft.jws.visual.rt.shadow.GenericComponentShadow.IllegalAccess",
	    "Illegal access: \" {0}\""
	}, {
	    "sunsoft.jws.visual.rt.shadow.GenericComponentShadow.InstantiationException",
	    "\" {0}\" could not be instantiated"
	}, {
	    "sunsoft.jws.visual.rt.shadow.GenericComponentShadow.Noconstructor",
	    "\" {0}\" does not have a null constructor"
	}, {
	    "sunsoft.jws.visual.rt.shadow.GenericWindowShadow.Class__not__found",
	    "\"Class not found: {0}"
	}, {
	    "sunsoft.jws.visual.rt.shadow.GenericWindowShadow.NotARootSubclass",
	    "\" {0}\" is not a subclass of RootFrame or RootDialog"
	}, {
	    "sunsoft.jws.visual.rt.shadow.GenericWindowShadow.IllegalAccess",
	    "Illegal access: \" {0}\""
	}, {
	    "sunsoft.jws.visual.rt.shadow.GenericWindowShadow.InstantiationException",
	    "\" {0}\" could not be instantiated"
	},
	{
	    "sunsoft.jws.visual.rt.shadow.GenericWindowShadow.Noconstructor",
	    "\" {0}\" does not have a null constructor"
	}, {
	    "sunsoft.jws.visual.rt.shadow.Error", "Error: {0}"
	}, {
	    "sunsoft.jws.visual.rt.shadow.FlowPanelShadow.DefaultText",
	    "Flow Layout"
	}, {
	    "sunsoft.jws.visual.rt.shadow.ColumnListShadow.Column__Format",
	    "\"Column format must be(l)eft, (r)ight or (c)enter only"
	}, {
	    "sunsoft.jws.visual.rt.shadow.MultiLineLabelShadow.DefaultText",
	    "MultiLineLabel"
	}, {
	    "sunsoft.jws.visual.rt.shadow.java.awt.ButtonShadow.button",
	    "button"
	}, {
	    "sunsoft.jws.visual.rt.shadow.java.awt.LabelShadow.text",
	    "label"
	}, {
	    "sunsoft.jws.visual.rt.shadow.java.awt.CheckboxShadow.text",
	    "checkbox"
	}, {
	    "sunsoft.jws.visual.rt.shadow.java.awt.DialogShadow.title",
	    "Unnamed Dialog"
	}, {
            "sunsoft.jws.visual.rt.shadow.java.awt.FileDialogShadow.title",
	    "File Dialog (not viewable)"
	},
	{
	    "sunsoft.jws.visual.rt.shadow.java.awt.FrameShadow.title",
	    "Unnamed Frame"
	}, {
	    "sunsoft.jws.visual.rt.type.AMConverter.FMT.0", "{0}{1}{2}"
	}, {
	    "sunsoft.jws.visual.rt.type.AMConverter.FMT.1", "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.AMConverter.FMT.2", "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.AMConverter.FMT.3", "{0}{1}"
	}, {
            "sunsoft.jws.visual.rt.type.AMConverter.AMConverter__convertF.0",
	    "AMConverter convertFromString needs a version"
	}, {
	    "sunsoft.jws.visual.rt.type.AMConverter.________Incomplete__attri.1",
	    "    Incomplete attribute manager line:"
	}, {
	    "sunsoft.jws.visual.rt.type.AMConverter.____________type__-eq-__",
	    "      type = "
	}, {
	    "sunsoft.jws.visual.rt.type.AMConverter.____________name__-eq-__",
	    "      name = "
	}, {
	    "sunsoft.jws.visual.rt.type.AMConverter.____________attr__-eq-__",
	    "      attr = "
	},
	{
	    "sunsoft.jws.visual.rt.type.AMConverter.Could__not__access__",
	    "Could not access "
	}, {
            "sunsoft.jws.visual.rt.type.AMConverter.Could__not__instantiat.2",
	    "Could not instantiate "
	}, {
	    "sunsoft.jws.visual.rt.type.AMConverter.________Incomplete__attri.3",
	    "    Incomplete attribute manager line:"
	}, {
	    "sunsoft.jws.visual.rt.type.AMConverter.will__not__generate__co.4",
	    "will not generate code,"
	}, {
            "sunsoft.jws.visual.rt.type.AMConverter.implementation__of__th.5",
	    "implementation of this is in the GUI builder"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeConverter.FMT.4",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeConverter.FMT.5",
	    "{0}{1}{2}{3}{4}{5}{6}{7}"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeConverter.FMT.6",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeConverter.FMT.7",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeConverter.AttributeConverter__n.6",
	    "AttributeConverter needs a shadow object "
	},
	{
	    "sunsoft.jws.visual.rt.type.AttributeConverter.argument__to__operate",
	    "argument to operate"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeConverter.internal__error__-__",
	    "internal error - "
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeConverter.convertToCode__with__m.11",
	    "convertToCode with minimal arguments cannot be called"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeListConverter.AttributeListConvert.12",
	    "AttributeListConverter cannot work without a shadow object argument"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeListConverter.________Incomplete__attri.13",
	    "    Incomplete attribute line:"
	}, {
	    "sunsoft.jws.visual.rt.type.BaseEnum.FMT.8", "{0}{1}{2}"
	}, {
	    "sunsoft.jws.visual.rt.type.BaseEnum.FMT.9", "{0}{1}{2}"
	}, {
	    "sunsoft.jws.visual.rt.type.BaseEnum.invalid__int__choice__",
	    "invalid int choice "
	}, {
            "sunsoft.jws.visual.rt.type.BaseEnum.__given__to__Enum__class.14",
	    " given to Enum class"
	}, {
            "sunsoft.jws.visual.rt.type.BaseEnum.invalid__string__choic.15",
	    "invalid string choice "
	},
	{
            "sunsoft.jws.visual.rt.type.BaseEnum.__given__to__Enum__class.16",
	    " given to Enum class"
	}, {
	    "sunsoft.jws.visual.rt.type.BooleanConverter.FMT.10", "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.BooleanConverter.Illegal__boolean__valu.17",
	    "Illegal boolean value: "
	}, {
	    "sunsoft.jws.visual.rt.type.ColorConverter.FMT.11", "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.ColorConverter.FMT.12", "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.ColorConverter.Illegal__color__value-co-.18",
	    "Illegal color value: "
	}, {
	    "sunsoft.jws.visual.rt.type.ColorConverter.Badly__formatted__colo.19",
	    "Badly formatted color value: "
	}, {
	    "sunsoft.jws.visual.rt.type.Converter.FMT.13", "{0}{1}{2}"
	}, {
	    "sunsoft.jws.visual.rt.type.Converter.FMT.14", "{0}{1}{2}"
	}, {
            "sunsoft.jws.visual.rt.type.Converter.FMT.15", "{0}{1}{2}{3}{4}"
	},
	{
	    "sunsoft.jws.visual.rt.type.Converter.FMT.16", "{0}{1}{2}"
	}, {
            "sunsoft.jws.visual.rt.type.Converter.No__converter__defined.20",
	    "No converter defined for the \"unknown\" type."
	}, {
	    "sunsoft.jws.visual.rt.type.Converter.Class__not__found__for__.21",
	    "Class not found for type \""
	}, {
            "sunsoft.jws.visual.rt.type.Converter.Sub-classes__of__Conve.22",
	    "Sub-classes of Converter MUST override at least one "
	}, {
	    "sunsoft.jws.visual.rt.type.Converter.of__the__-ba--qu-convertToSt.23",
	    "of the \"convertToString\" methods, and at least one "
	}, {
	    "sunsoft.jws.visual.rt.type.Converter.of__the__-ba--qu-convertToCo.24",
	    "of the \"convertToCode\" methods."
	}, {
            "sunsoft.jws.visual.rt.type.Converter.Convert__exit__without.25",
	    "Convert exit without enter"
	}, {
            "sunsoft.jws.visual.rt.type.Converter.isBuffered__mismatch__.26",
	    "isBuffered mismatch in exitConvert"
	}, {
	    "sunsoft.jws.visual.rt.type.DimensionConverter.FMT.17",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.DimensionConverter.FMT.18",
	    "{0}{1}"
	},
	{
	    "sunsoft.jws.visual.rt.type.DimensionConverter.Badly__formatted__dime.27",
	    "Badly formatted dimension value: "
	}, {
	    "sunsoft.jws.visual.rt.type.DoubleArrayConverter.FMT.19",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.DoubleArrayConverter.Badly__formatted__doub.28",
	    "Badly formatted double: "
	}, {
	    "sunsoft.jws.visual.rt.type.FontConverter.FMT.20", "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.FontConverter.FMT.21", "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.FontConverter.FMT.22", "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.FontConverter.FMT.23", "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.FontConverter.FMT.24", "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.FontConverter.Warning-co-__unknown__fon.29",
	    "Warning: unknown font style: "
	}, {
	    "sunsoft.jws.visual.rt.type.FontConverter.Missing__font__name-co-__",
	    "Missing font name: "
	},
	{
	    "sunsoft.jws.visual.rt.type.FontConverter.Invalid__font__style-co-__.30",
	    "Invalid font style: "
	}, {
	    "sunsoft.jws.visual.rt.type.FontConverter.Invalid__font__size-co-__",
	    "Invalid font size: "
	}, {
	    "sunsoft.jws.visual.rt.type.FontConverter.Negative__font__size-co-__.31",
	    "Negative font size: "
	}, {
            "sunsoft.jws.visual.rt.type.GBConstraintsConverter.FMT.25",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.GBConstraintsConverter.FMT.26",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.ImageRef.FMT.27", "{0}{1}{2}"
	}, {
	    "sunsoft.jws.visual.rt.type.ImageRef.FMT.28", "{0}{1}{2}"
	}, {
	    "sunsoft.jws.visual.rt.type.ImageRef.could__not__find__file__.32",
	    "could not find file \""
	}, {
	    "sunsoft.jws.visual.rt.type.ImageRef.-ba--qu-__relative__to__class.33",
	    "\" relative to classpath/codebase"
	}, {
	    "sunsoft.jws.visual.rt.type.ImageRef.Error-co-__could__not__loa.34",
	    "Error: could not load image \""
	},
	{
	    "sunsoft.jws.visual.rt.type.GBConstraintsConverter.FMT.29",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.GBConstraintsConverter.unknown__constant",
	    "unknown constant"
	}, {
	    "sunsoft.jws.visual.rt.type.BaseEnum.FMT.30", "{0}{1}{2}"
	}, {
	    "sunsoft.jws.visual.rt.type.DimensionConverter.FMT.31",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.type.DimensionConverter.illegal__dimension__value",
	    "Illegal dimension value: "
	}, {
	    "sunsoft.jws.visual.rt.type.ImageRef.FMT.32", "{0}{1}{2}"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeConverter.FMT.33",
	    "Unknown attribute {0}\n\nclass {1}\ntype {2}\nkey {3}\nvalue {4}"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeConverter.FMT.34",
	    "Unknown attribute type {0}"
	}, {
	    "sunsoft.jws.visual.rt.type.AttributeConverter.FMT.35",
	    "Type in gui file {0} \ndoes not match expected type {1}."
	}, {
	    "sunsoft.jws.visual.rt.base.AMContainerHelper.adding__container's__p.0",
	    "adding container's parent to itself"
	},
	{
	    "sunsoft.jws.visual.rt.base.BeanSerialization.serExcpt",
	    "The following error occured during serialization of \" {0}\":\n\" {1}\"."
	}, {
	    "sunsoft.jws.visual.rt.base.BeanSerialization.decoderExcpt",
	    "An error occured during deserialization of \" {0}\"."
	}, {
	    "sunsoft.jws.visual.rt.base.BeanSerialization.deserExcpt",
	    "The following error occured during deserialization of \" {0}\":\n\" {1}\"."
	}, {
	    "sunsoft.jws.visual.rt.base.Attribute.ClassNotFound",
	    "Class \" {0}\" not found"
	}, {
	    "sunsoft.jws.visual.rt.base.Attribute.IllegalAttribute",
	    "Illegal attribute value for {0}. Expected type : {1} Actual type : {2} value = {3}"
	}, {
	    "sunsoft.jws.visual.rt.base.AttributeManager.SetInvalidAttribute",
	    "Attempt to set invalid attribute {0}"
	}, {
            "sunsoft.jws.visual.rt.base.AttributeManager.ReadonlyAttribute",
	    "Attempt to set read-only attribute {0}"
	}, {
            "sunsoft.jws.visual.rt.base.AttributeManager.GetInvalidAttribute",
	    "Attempt to get invalid attribute {0}"
	}, {
	    "sunsoft.jws.visual.rt.base.Group.ExpiredVersion",
	    "This version of Visual Java GUI Builder has expired"
	}, {
	    "sunsoft.jws.visual.rt.base.Group.ExpiredVersionDate",
	    "Warning: This version of Visual Java GUI Builder has expires on {0}"
	},
	{
	    "sunsoft.jws.visual.rt.base.Group.GroupInitializationWarning",
	    "Warning: A group must be a child of another group before it can be initialized."
	}, {
            "sunsoft.jws.visual.rt.base.Group.GroupCreationWarning",
	    "Warning: A group must be a child of another group before it can be created."
	}, {
	    "sunsoft.jws.visual.rt.base.Group.RootIsNull",
	    "\"Root\" is null. {0} is returning null from initRoot."
	}, {
	    "sunsoft.jws.visual.rt.base.Group.RootIsNull2",
	    "\"Root\" is null. Make sure that initialize is called before create"
	}, {
	    "sunsoft.jws.visual.rt.base.Group.UnexpectedMainChildType",
	    "Unexpected type for main child: {0}"
	}, {
	    "sunsoft.jws.visual.rt.base.MainHelper.NeedRuntimeVersion",
	    "Warning: need runtime version {0}, version {1} is what is available, continuing..."
	}, {
	    "sunsoft.jws.visual.rt.base.MainHelper.BaseGroupMustBeNonVis",
	    "The base group cannot be a non-visual group: {0}"
	}, {
	    "sunsoft.jws.visual.rt.base.MainHelper.ClassNotFound",
	    "Could not find external class {0}"
	}, {
	    "sunsoft.jws.visual.rt.base.MainHelper.InstantiationException",
	    "Could not instantiate external class {0}"
	}, {
	    "sunsoft.jws.visual.rt.base.MainHelper.illegalAccess",
	    "Could not construct external class {0}"
	},
	{
	    "sunsoft.jws.visual.rt.base.Root.RootMissingContainer",
	    "Root {0} does not contain {1}"
	}, {
	    "sunsoft.jws.visual.rt.base.Root.NeedName",
	    "Every component must have a name."
	}, {
	    "sunsoft.jws.visual.rt.base.Root.NotUniqueName",
	    "Name {0} is not unique"
	}, {
	    "sunsoft.jws.visual.rt.base.Root.NotValidName",
	    "Name {0} isn't a valid variable name."
	}, {
	    "sunsoft.jws.visual.rt.base.Shadow.NoSuchKey",
	    "No match for {0} in getOnBody()"
	}, {
	    "sunsoft.jws.visual.rt.base.Shadow.UnknownAttribute",
	    "Unknown attribute {0} for class [1}"
	}, {
	    "sunsoft.jws.visual.rt.base.Shadow.NoSuchKey2",
	    "No match for {0} in setOnBody()"
	}, {
	    "sunsoft.jws.visual.rt.base.Shadow.InvalidAttributeSet",
	    "Attempt to set invalid attribute {0}"
	}, {
	    "sunsoft.jws.visual.rt.base.Shadow.ReadOnlyAttributeSet",
	    "Attempt to set read-only attribute {0}"
	}, {
	    "sunsoft.jws.visual.rt.base.Shadow.BodyNotDestroyed",
	    "Shadow body was not destroyed"
	},
	{
	    "sunsoft.jws.visual.rt.base.Group.ShadowCreationWarning",
	    "Warning: A shadow must be a child of another shadow before it can be created."
	}, {
	    "sunsoft.jws.visual.rt.base.Shadow.BodyNotCreated",
	    "Shadow body was not created"
	}, {
	    "sunsoft.jws.visual.rt.base.Util.NeedAppletparam",
	    "You must provide a non-null applet parameter to \"pathToURL\" {0} when running as an applet."
	}, {
	    "sunsoft.jws.visual.rt.base.Util.SecurityException",
	    "SECURITY EXCEPTION1: {0}"
	}, {
	    "sunsoft.jws.visual.rt.base.Util.NullComp",
	    "null comp argument to {0}"
	}, {
	    "sunsoft.jws.visual.rt.encoder.UCDecoder.HighByteparity",
	    "UCDecoder: High byte parity error."
	}, {
	    "sunsoft.jws.visual.rt.encoder.UCDecoder.LowByteparity",
	    "UCDecoder: Low byte parity error."
	}, {
	    "sunsoft.jws.visual.rt.encoder.UCDecoder.OutOfSequence",
	    "UCDecoder: Out of sequence line."
	}, {
	    "sunsoft.jws.visual.rt.encoder.UCDecoder.CRCFailed",
	    "UCDecoder: CRC check failed."
	}, {
	    "sunsoft.jws.visual.rt.type.InsetsConverter.BadInsets",
	    "Badly formatted insets value: {0}"
	},
	{
	    "sunsoft.jws.visual.rt.type.InsetsConverter.IllegalInsets",
	    "Illegal inset value: {0}"
	}, {
	    "sunsoft.jws.visual.rt.type.IntArrayConverter.BadFormatInteger",
	    "Badly formatted integer: {0}"
	}, {
	    "sunsoft.jws.visual.rt.type.ListParser.SpaceExpected",
	    "list element in braces followed by {0} instead of space"
	}, {
	    "sunsoft.jws.visual.rt.type.ListParser.SpaceExpected2",
	    "list element in quotes followed by \" {0}\" {1} instead of space"
	}, {
	    "sunsoft.jws.visual.rt.type.ListParser.UnmatchedBrace",
	    "unmatched open brace in list"
	}, {
	    "sunsoft.jws.visual.rt.type.ListParser.UnmatchedQuote",
	    "unmatched open quote in list"
	}, {
	    "sunsoft.jws.visual.rt.type.ListParser.ExpectingTwoElements",
	    "Expecting two list elements: {0}"
	}, {
	    "sunsoft.jws.visual.rt.type.OpAction.NumberFormatException",
	    "Number format exception: {0}"
	}, {
	    "sunsoft.jws.visual.rt.type.OpAction.ValWithoutType",
	    "Got a value without a valueType: {0}"
	}, {
	    "sunsoft.jws.visual.rt.type.OpAction.NoConverter",
	    "Could not find converter for {0}"
	},
	{
	    "sunsoft.jws.visual.rt.type.PointConverter.IllegalPoint",
	    "Illegal point value: {0}"
	}, {
	    "sunsoft.jws.visual.rt.type.PointConverter.BadFormattedValue",
	    "Badly formatted point value: {0}"
	}, {
	    "sunsoft.jws.visual.rt.type.TypeEditor.AddChildError",
	    "Adding type editor's parent to itself"
	}, {
	    "sunsoft.jws.visual.rt.type.TypeEditor.Error", "Error"
	}, {
            "sunsoft.jws.visual.rt.type.UnknownTypeConverter.NoTypeConverter",
	    "Warning: no type converter for type: {0}"
	}, {
	    "sunsoft.jws.visual.rt.type.UnknownTypeConverter.CantConvert",
	    "Warning: don't know what type to convert this to: {0}"
	}, {
	    "sunsoft.jws.visual.rt.awt.CardPanel.FMT.0", "{0}{1}{2}{3}{4}"
	}, {
	    "sunsoft.jws.visual.rt.awt.CardPanel.Card__Panel", "Card Panel"
	}, {
	    "sunsoft.jws.visual.rt.awt.CardPanel.________There__is__no__tab__.0",
	    "    There is no tab for \""
	}, {
	    "sunsoft.jws.visual.rt.awt.CardPanel.________You__must__call__ad.1",
	    "    You must call addTab before addCard."
	},
	{
	    "sunsoft.jws.visual.rt.awt.ColumnListThread.FMT.1",
	    "{0}{1}"
	}, {
	    "sunsoft.jws.visual.rt.awt.ColumnListThread.Exception__in__sleep-co-__.2",
	    "Exception in sleep: "
	}, {
	    "sunsoft.jws.visual.rt.awt.GBConstraints.FMT.2",
	    "{0}{1}{2}{3}{4}"
	}, {
	    "sunsoft.jws.visual.rt.awt.GBConstraints.-ba-r-ba-n-ba-tSyntax__error__i.3",
	    "\r\n\tSyntax error in GBConstraints string:\r\n"
	}, {
	    "sunsoft.jws.visual.rt.awt.GBLayout.illegal__anchor__value.4",
	    "illegal anchor value"
	}, {
	    "sunsoft.jws.visual.rt.awt.GBLayout.illegal__anchor__value.5",
	    "illegal anchor value"
	}, {
	    "sunsoft.jws.visual.rt.awt.GBLayout.illegal__anchor__value.6",
	    "illegal anchor value"
	}, {
	    "sunsoft.jws.visual.rt.awt.GBLayout.illegal__anchor__value.7",
	    "illegal anchor value"
	}, {
	    "sunsoft.jws.visual.rt.awt.GBPanel.null__constraints",
	    "null constraints"
	}, {
	    "sunsoft.jws.visual.rt.awt.ImageLabel.nullColor",
	    "null color argument to "
	},
	{
	    "sunsoft.jws.visual.rt.awt.ImageLabel.ImproperAlignment",
	    "Improper alignment"
	}, {
	    "sunsoft.jws.visual.rt.awt.ScrollPanel.OnlyOneInstance",
	    "Can only add an instance of Scrollable to the ScrollPanel"
	}, {
	    "sunsoft.jws.visual.rt.awt.TabbedFolder.Empty", "<Empty>"
	}, {
	    "sunsoft.jws.visual.rt.awt.TabbedFolder.NewCardLabel",
	    "TabbedFolder"
	}, {
	    "sunsoft.jws.visual.rt.awt.VJErrorDialog.OK", "OK"
	}, {
	    "sunsoft.jws.visual.rt.awt.VJPanel.UnmarkedEvent",
	    "{0} was called with an unmarked event"
	}, {
	    "sunsoft.jws.visual.rt.awt.VJScrollbar.CantAdd",
	    "Cannot add components to a VJScrollbar"
	}, {
	    "sunsoft.jws.visual.rt.awt.VJScrollbar.CantRemove",
	    "Cannot remove components from a VJScrollbar"
	}, {
	    "sunsoft.jws.visual.rt.awt.WinScrollbar.IllegalOrientation",
	    "Illegal scrollbar orientation"
	}, {
	    "sunsoft.jws.visual.rt.awt.java.awt.ComponentShadow.IllegalSetVisible",
	    "It is illegal to set a container's visible attribute to false if it is the main container for its group."
	},
	{
            "sunsoft.jws.visual.rt.awt.java.awt.DialogShadow.NullFrameShadow",
	    "FrameShadow reference is null"
	}, {
	    "sunsoft.jws.visual.rt.awt.java.awt.DialogShadow.NullFrame",
	    "Frame is null"
	}, {
            "sunsoft.jws.visual.rt.awt.java.awt.FrameShadow.AlreadyHasMenubar",
	    "frame already has a menubar while trying to add {0}"
	}, {
	    "sunsoft.jws.visual.rt.awt.java.awt.FrameShadow.MenubarNotInstalled",
	    "This menubar was never installed: {0}"
	}, {
	    "sunsoft.jws.visual.rt.awt.java.awt.MenuBarShadow.CantResolveHelpMenu",
	    "Menu bar {0} ould not resolve help menu {1}"
	}, {
	    "sunsoft.jws.visual.rt.awt.java.awt.ScrollbarShadow.NoLayoutConstraints",
	    "scrollbar does not have layout constraints!"
	}, {
	    "sunsoft.jws.visual.rt.awt.java.awt.WindowShadow.IllegalSetVisible",
	    "It is illegal to set a window's visible attribute to false if it is the main window for its group."
	}, {
            "the last line cannot have a comma so this has been added to make",
	    "automatic code generation easier.  it is never used."
	}
    };
/* END JSTYLED */            
}
