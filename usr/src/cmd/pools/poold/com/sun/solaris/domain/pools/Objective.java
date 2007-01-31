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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.domain.pools;

import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.text.DecimalFormat;
import java.util.*;
import java.util.logging.*;

import com.sun.solaris.service.logging.Severity;
import com.sun.solaris.service.locality.*;
import com.sun.solaris.service.pools.*;


/**
 * An objective interface. All classes which wish to contribute to the
 * Objective Function (OF hence) calculation must implement this
 * interface. This interface defines a strategy which can be used to
 * make a contribution to the Objective Function calculation.
 *
 * The OF calculation (which is implemented by <code>Poold</code>)
 * consists of determining all possible resource moves across all
 * resources. Once all moves are known, all registered objectives
 * (i.e. instances of this interface) are called and asked to value
 * the move.
 *
 * Note, the output of this method is constrained to be between -1 and
 * 1, representing minimum and maximum desirability of this move in
 * terms of this objective. This is enforced by <code>Poold</code> and
 * an <code>IllegalOFValueException</code> will be thrown if this
 * constraint is broken.
 */
interface Objective
{
	/**
	 * Return the contribution of this objective. The contribution
	 * is constrainted to be a value between -1 and +1 to ensure
	 * that no objective can make a disproportionate contribution
	 * to the total result.
	 *
	 * The more desirable this move appears in terms of this
	 * objective, the closer to +1 will be the value. A value of 0
	 * indicates that the move is neutral in terms of the
	 * objective. A negative value indicates that the move is
	 * undesirable.
	 *
	 * @param conf The configuration which is being examined
	 * @param move The move under consideration
	 * @param elem The element to which the objective applies
	 *
	 * @throws PoolsException if there is an error manipulating
	 * the configuration
	 */
	public double calculate(Configuration conf, Move move, Element elem)
	    throws PoolsException;

	/**
	 * Set the objective's expression to the supplied parameter.
	 *
	 * @param exp An expression for this objective.
	 */
	public void setExpression(Expression exp);

	/**
	 * Get the objective's expression.
	 */
	public Expression getExpression();
}

/**
 * This interface must be implemented by all Objectives which are
 * workload dependent. The examine method is used by a Solver to
 * determine if the objective is still being satisfied.
 */
interface WorkloadDependentObjective extends Objective
{
	/**
	 * This method returns true if the Objective is no longer
	 * satisfied. If the objective is still satisfied, then return
	 * false.
	 *
	 * @param conf The configuration to be examined
	 * @param solver The solving interface used to get utilization
	 * information
	 * @param elem The element to which the objective belongs
	 *
	 * @throws PoolsException if there is an error examining the
	 * pool configuration
	 * @throws StaleMonitorException if there is an error accessing
	 * the element's ResourceMonitor
	 */
	public boolean examine(Configuration conf, Solver solver,
	    Element elem) throws PoolsException, StaleMonitorException;
}

/**
 * This class provides a skeletal implementation of the
 * <code>Objective</code> interface to minimize the effort required
 * to implement this interface.
 *
 * To implement an objective, the programmer need only to extend this
 * class and add the name of the class into the appropriate element
 * objectives property in the <code>poold.properties</code> file.
 */
abstract class AbstractObjective implements Objective
{
	abstract public double calculate(Configuration conf, Move move,
	    Element elem) throws PoolsException;

	/**
	 * The objectives which are recognized by this class
	 */
	private static Map objectives;

	/**
	 * The expression associated with this objective
	 */
	private Expression exp;

	/**
	 * Set the objective's expression to the supplied parameter.
	 *
	 * @param exp An expression for this objective.
	 */
	public void setExpression(Expression exp)
	{
		this.exp = exp;
	}

	/**
	 * Get the objective's expression.
	 */
	public Expression getExpression()
	{
		return (exp);
	}

	/**
	 * A factory method which returns a created objective which is
	 * associated with the supplied expression. The type and the
	 * expression are used to identify valid types of objectives
	 * to which this expression may be applied. If an acceptable
	 * objective cannot be found for the supplied type, then an
	 * <code>IllegalArgumentException</code> will be thrown.
	 *
	 * @param type The element type for which an objective must be
	 * found
	 * @param exp The expression which will be associated with the
	 * objective
	 *
	 * @throws IllegalArgumentExcetion if the supplied expression
	 * cannot be associated with an objective of the supplied type
	 */
	public static Objective getInstance(String type, Expression exp)
	    throws IllegalArgumentException
	{
		Objective ret = null;
		Map typeObjs = null;

		initMapIfNecessary();
		typeObjs = (Map)objectives.get(type);
		if (typeObjs != null) {
			Class objClass = (Class)typeObjs.get(exp.getName());
			if (objClass != null) {
				try {
					ret = (Objective) objClass.
					    newInstance();
				} catch (Exception e) {
					Poold.utility.die(Poold.OPT_LOG, e,
					    true);
				}
				ret.setExpression(exp);
			}
		}
		if (ret == null)
			throw new IllegalArgumentException(
			    "unrecognized objective name for " + type + ": " +
			    exp.toString());
		return (ret);
	}

	/**
	 * Return a string representation of this objective.
	 */
	public String toString()
	{
		return (exp.toString());
	}

	/**
	 * Initialize the implementation map the first time it's
	 * called.
	 */
	private static void initMapIfNecessary()
	{
		/*
		 * Setup the objectives map for the known classes
		 */
		if (objectives == null) {
			objectives = new HashMap();
			Properties props = new Properties();
			try {
				props.load(
				    new FileInputStream(
				    Poold.POOLD_PROPERTIES_PATH));
			} catch (IOException ioe) {
				Poold.utility.die(Poold.CONF_LOG, ioe);
			}
			registerObjectives(props, objectives, "system");
			registerObjectives(props, objectives, "pset");
		}
	}

	/**
	 * Add the objectives contained in the supplied properties to
	 * the set of valid objectives. The objectives are updated
	 * with objectives of the supplied type contained in the
	 * properties.
	 *
	 * @param props The properties containing the objectives
	 * @param objectives The objectives to be updated
	 * @param type The type of objectives to be added
	 */
	private static void registerObjectives(Properties props,
	    Map objectives, String type)
	{
		Map typeObjs = new HashMap();
		String objs = props.getProperty(type + ".objectives");
		String objNames[] = objs.split(",");
		for (int i = 0; i < objNames.length; i++) {
			String objName = objNames[i].trim();
			try {
				Class clazz = Class.forName(objName);
				Field field = clazz.getDeclaredField("name");
				String key = (String) field.get(null);
				typeObjs.put(key, clazz);
			} catch (ClassNotFoundException cnfe) {
				Poold.utility.die(Poold.CONF_LOG, cnfe);
			} catch (NoSuchFieldException nsfe) {
				Poold.utility.die(Poold.CONF_LOG, nsfe);
			} catch (IllegalAccessException iae) {
				Poold.utility.die(Poold.CONF_LOG, iae);
			}
		}
		objectives.put(type, typeObjs);
	}

	/**
	 * Indicates whether some other Objective is "equal to this
	 * one.
	 * @param o the reference object with which to compare.
	 * @return <code>true</code> if this object is the same as the
	 * o argument; <code>false</code> otherwise.
	 * @see	#hashCode()
	 */
	public boolean equals(Object o)
	{
		if (o == this)
			return (true);
		if (!(o instanceof Objective))
			return (false);
		Objective other = (Objective) o;

		return (getExpression().equals(other.getExpression()));
	}

	/**
	 * Returns a hash code value for the object. This method is
	 * supported for the benefit of hashtables such as those provided by
	 * <code>java.util.Hashtable</code>.
	 *
	 * @return a hash code value for this object.
	 * @see	#equals(java.lang.Object)
	 * @see	java.util.Hashtable
	 */
	public int hashCode()
	{
		return (getExpression().hashCode());
	}
}


/**
 * The <code>WeightedLoadObjective</code> class implements a Weighted
 * Load Objective for <code>Poold</code>.
 *
 * The goal is to allocate more resources to those resource partitions
 * which are heavily loaded. The weighting is determined from the
 * objective importance and the pool.importance.
 */
final class WeightedLoadObjective extends AbstractObjective
    implements WorkloadDependentObjective
{
	/**
	 * The name of the class.
	 */
	static final String name = "wt-load";

	/**
	 * The map of calculations made during examination.
	 */
	Map calcMap;

	/**
	 * Determine whether an objective is satisfied. If the
	 * objective is still satisfied, return false; otherwise
	 * return true.
	 *
	 * This objective examination determines if all resource sets
	 * are allocated the share of resources that their utilization
	 * would indicate they should be. This attempts to ensure that
	 * highly utilized resource sets recieve the greater
	 * proportion of available resources.
	 *
	 * @param conf The configuration to be examined
	 * @param solver The solving interface used to get utilization
	 * information
	 * @param elem The element to which the objective belongs
	 *
	 * @throws PoolsException if there is an error examining the
	 * pool configuration
	 * @throws StaleMonitorException if there is an error accessing
	 * the element's ResourceMonitor
	 */
	public boolean examine(Configuration conf, Solver solver,
	    Element elem) throws PoolsException, StaleMonitorException
	{
		Monitor mon = solver.getMonitor();
		Value val = new Value("type", "pset");
		List valueList = new LinkedList();
		calcMap = new HashMap();
		valueList.add(val);

		List resList = conf.getResources(valueList);
		val.close();
		Iterator itRes = resList.iterator();

		Calculation.totalUtil = 0;
		Calculation.resQ = 0;

		while (itRes.hasNext()) {
			Resource res = (Resource) itRes.next();
			List CPUs = res.getComponents(null);

			try {
				Calculation calc = new Calculation(res, CPUs,
				    mon.getUtilization(res),
				    res.getLongProperty("pset.min"),
				    res.getLongProperty("pset.max"));
				calcMap.put(res, calc);
			} catch (StaleMonitorException sme) {
				Poold.MON_LOG.log(Severity.INFO,
				    res.toString() +
				    " not participating in " + toString() +
				    " calculatation as it has no " +
				    "available statistics.");
			}
		}
		Iterator itCalc = calcMap.values().iterator();
		while (itCalc.hasNext()) {
			Calculation calc = (Calculation) itCalc.next();
			if (calc.getShare() != calc.comp.size() &&
			    calc.getShare() >= calc.min) {
				Poold.MON_LOG.log(Severity.INFO,
				    elem.toString() +
				    " utilization objective not satisfied " +
				    toString() + " with desired share " +
				    calc.getShare() + " and actual share " +
				    calc.comp.size());
				return (true);
			}
		}
		return (false);
	}

	/**
	 * Holds data about weighted load calculations. This class is
	 * basically a structure which holds information specific to a
	 * weighted-load calculation
	 */
	static class Calculation {
		/**
		 * The resource on which this calculation is based.
		 */
		Resource res;

		/**
		 * The list of component resources held by this resource.
		 */
		List comp;

		/**
		 * The utilization of this resource.
		 */
		double util;

		/**
		 * The minimum value of this resource's size.
		 */
		long min;

		/**
		 * The maximum value of this resource's size.
		 */
		long max;

		/**
		 * The total utilization of all instances of this class.
		 */
		static double totalUtil;

		/**
		 * The total quantity of resource for all instances of
		 * this class.
		 */
		static int resQ;

		/**
		 * Constructor. The class is immutable and holds
		 * information specific to a set of calculations about
		 * load.
		 *
		 * @param res The resource set
		 * @param comp The resource components
		 * @param util The resource utilization
		 * @param min The minimum qty of resource for this set
		 * @param max The maximum qty of resource for this set
		 */
		public Calculation(Resource res, List comp, double util,
		    long min, long max)
		{
			this.res = res;
			this.comp = comp;
			this.min = min;
			this.max = max;
			this.util = (util / 100) * comp.size();
			Calculation.totalUtil += this.util;
			Calculation.resQ += comp.size();
		}

		/**
		 * Return the share of the total resource for this
		 * resource.
		 */
		long getShare()
		{
			if (util == 0)
				return (0);
			return (Math.round((util / totalUtil) * resQ));
		}

		public String toString()
		{
			StringBuffer buf = new StringBuffer();
			buf.append("res: " + res.toString());
			buf.append(" components: " + comp.toString());
			buf.append(" min: " + min);
			buf.append(" max: " + max);
			buf.append(" util: " + util);
			buf.append(" total resource: " + resQ);
			buf.append(" total utilization: " + totalUtil);
			buf.append(" share: " + getShare());
			return (buf.toString());
		}
	}

	/**
	 * Calculates the value of a configuration in terms of this
	 * objective.
	 *
	 * In the examination step, calculations of each resource's
	 * current and desired share were made. The moves can thus be
	 * assessed in terms of their impact upon the desired
	 * share. The current difference from desired is already
	 * known, so each move will serve to reduce or increase that
	 * difference. Moves that increase the difference have a
	 * negative score, those that reduce it have a positive
	 * score. All scores are normalized to return a value between
	 * -1 and 1.
	 *
	 * @param conf Configuration to be scored.
	 * @param move Move to be scored.
	 * @param elem The element to which the objective applies
	 * @throws PoolsException If an there is an error in execution.
	 */
	public double calculate(Configuration conf, Move move, Element elem)
	    throws PoolsException
	{
		double ret = 0;

		Poold.OPT_LOG.log(Severity.DEBUG,
		    "Calculating objective type: " + name);
		/*
		 * There shouldn't be any empty moves, but if there
		 * are they are rated at 0.
		 */
		if (move.getQty() == 0)
			return (0);

		/*
		 * Find the calculations that represent the source and
		 * target of the move.
		 */
		Calculation src = (Calculation) calcMap.get(move.getFrom());
		Calculation tgt = (Calculation) calcMap.get(move.getTo());

		/*
		 * Use the calculation details to determine the "gap"
		 * i.e. number of discrete resources (for a processor
		 * set these are CPUs), between the desired quantity in
		 * the set which the calculations represent. Do this
		 * both before and after the proposed move.
		 *
		 * The maximum possible improvement is equal to the
		 * total number of resources for each set participating
		 * in the calculation. Since there are two sets we
		 * know the maximum possible improvement is resQ * 2.
		 *
		 * Divide the aggregated change in gap across participating
		 * sets by the maximum possible improvement to obtain
		 * a value which scores the move and which is normalised
		 * between -1 <= ret <= 1.
		 */
		long oldGap = Math.abs(src.getShare() -
		    src.comp.size());
		long newGap = Math.abs(src.getShare() -
		    (src.comp.size() - move.getQty()));
		ret = oldGap - newGap;
		oldGap = Math.abs(tgt.getShare() -
		    tgt.comp.size());
		newGap = Math.abs(tgt.getShare() -
		    (tgt.comp.size() + move.getQty()));
		ret += oldGap - newGap;
		ret /= ((double) Calculation.resQ * 2);

		Poold.MON_LOG.log(Severity.DEBUG, "ret: " + ret);
		return (ret);
	}
}

/**
 * A locality based objective which will assess moves in terms of
 * their impact on the locality of the sets of resources which are
 * impacted.
 *
 * The objective will assess moves with respect to the type of
 * locality specified in the objective:
 *
 * <ul>
 * <li><p>
 * tight - resource locality is sought
 * <li><p>
 * loose - resource locality is avoided
 * <li><p>
 * none - resource locality has no impact
 * </ul>
 */
final class LocalityObjective extends AbstractObjective
{
	/**
	 * The name of the class.
	 */
	static final String name = "locality";

	/**
	 * The locality domain used to describe locality for this
	 * objective.
	 */
	private LocalityDomain ldom;

	/**
	 * Prepare the calculation for this objective for the resource
	 * to which it applies.
	 *
	 * @param ldom LocalityDomain containing these resources.
	 * @param res Resource to which this objective is applied.
	 *
	 * @throws PoolsException if accessing the supplied resource
	 * fails.
	 */
	public void prepare(LocalityDomain ldom, Resource res)
	    throws PoolsException
	{
		this.ldom = ldom;
	}

	/**
	 * Calculates the value of a configuration in terms of this
	 * objective.
	 *
	 * Firstly check to see if it is possible to short-cut the
	 * calculation. If not, then start to examine the disposition
	 * of CPUs and locality groups in relation to the processor
	 * set being evaluated. The objective scores moves in terms of
	 * their impact upon the quotient of cpus contained in each
	 * locality group.
	 *
	 * @param conf Configuration to be scored.
	 * @param move Move to be scored.
	 * @param elem The element to which the objective applies
	 * @throws Exception If an there is an error in execution.
	 */
	public double calculate(Configuration conf, Move move, Element elem)
	    throws PoolsException
	{
		KVExpression kve = (KVExpression) getExpression();
		double ret = 0;
		double qA = 0;
		double qB = 0;
		Resource res = (Resource) elem;
		ComponentMove cm = (ComponentMove) move;
		Poold.MON_LOG.log(Severity.DEBUG,
		    "Calculating objective type: " + name + " for: " + elem);

		/*
		 * If we are set to "none" then we don't care which
		 * configuration so just return 0
		 */
		if (kve.getValue().compareTo("none") == 0)
			return (ret);
		/*
		 * If the maximum latency is 0, we don't care about
		 * latency
		 */
		if (ldom.getMaxLatency() == 0)
			return (ret);
		/*
		 * If this element doesn't participate in the move, we
		 * should return 0.
		 */
		if (elem.equals(move.getFrom()) == false &&
		    elem.equals(move.getTo()) == false)
			return (ret);

		/*
		 * Assess the effect on lgrp quotient for all
		 * moves. Try to maximise lgrp quotient for "tight"
		 * objectives and minimize if for "loose" objectives.
		 */
		/*
		 * All contained cpus
		 */
		List contains = res.getComponents(null);
		/*
		 * All lgrps
		 */
		Set groups = ldom.foreignGroups(new HashSet(), contains);

		qB = calcQ(contains, groups);

		if (elem.equals(move.getFrom()))
			contains.removeAll(cm.getComponents());
		else
			contains.addAll(cm.getComponents());
		/*
		 * Recalculate lgrps to take account of new components
		 */
		groups = ldom.foreignGroups(new HashSet(), contains);
		qA = calcQ(contains, groups);

		ret = qA - qB;

		if (kve.getValue().compareTo("loose") == 0)
			ret = 0 - ret;

		Poold.MON_LOG.log(Severity.DEBUG, "ret: " + ret);
		return (ret);
	}

	/**
	 * Calculate a quotient using the supplied list of components
	 * and set of locality groups. The quotient represents the
	 * average (as in mean) number of CPUs (from the population in
	 * contains) present in each of the LocalityGroups contained
	 * in groups.
	 *
	 * @param contains The population of Components.
	 * @param groups The population of LocalityGroups.
	 *
	 * @throws PoolsException if there is an error accessing the
	 * CPUs.
	 */
	private double calcQ(List contains, Set groups) throws PoolsException
	{
		Iterator groupIt = groups.iterator();
		double q = 0.0;
		while (groupIt.hasNext()) {
			LocalityGroup grp = (LocalityGroup)groupIt.next();
			int cpu_ids[] = grp.getCPUIDs();
			Iterator containsIt = contains.iterator();
			int intersection = 0;
			double total = 0;
			while (containsIt.hasNext()) {
				Component comp = (Component) containsIt.next();
				for (int i = 0; i < cpu_ids.length; i++) {
					if (cpu_ids[i] == (int) comp.
					    getLongProperty("cpu.sys_id")) {
						intersection++;
						break;
					}
				}
			}
			double factor = 0;
			for (int i = 1; i <= cpu_ids.length; i++)
				factor += i;
			factor = 1 / factor;
			for (int i = 1; i <= intersection; i++)
				q += i * factor;
		}
		q /= groups.size();
		return (q);
	}
}

/**
 * A resource set utilization based objective which will assess moves
 * in terms of their (likely) impact on the future performance of a
 * resource set with respect to it's specified utilization objective.
 *
 * The utilization objective must be specified in terms of a
 * KVOpExpression, see the class definition for information about the
 * form of these expressions. The objective can be examined in terms
 * of it's compliance with the aid of a monitoring object. The actual
 * assessment of compliance is indicated by the associated monitoring
 * object, with this class simply acting as a co-ordinator of the
 * relevant information.
 */
final class UtilizationObjective extends AbstractObjective
    implements WorkloadDependentObjective
{
	/**
	 * The name of the class.
	 */
	static final String name = "utilization";

	/**
	 * Short run detection.
	 */
	private List zoneList = new LinkedList();

	/**
	 * Format for printing utilization.
	 */
	private static final DecimalFormat uf = new DecimalFormat("0.00");

	/**
	 * Solver used to calculate delta, i.e. gap, between target and
	 * actual utilization values.
	 */
	private Solver gapSolver;

	/**
	 * Determine whether an objective is satisfied. If the
	 * objective is still satisfied, return false; otherwise
	 * return true.
	 *
	 * The assessment of control is made by the monitoring class
	 * using the supplied Expression and resource.
	 *
	 * @param conf The configuration to be examined
	 * @param solver The solving interface used to get utilization
	 * information
	 * @param elem The element to which the objective belongs
	 *
	 * @throws PoolsException if there is an error examining the
	 * pool configuration
	 * @throws StaleMonitorException if there is an error accessing
	 * the element's ResourceMonitor
	 */
	public boolean examine(Configuration conf, Solver solver,
	    Element elem) throws PoolsException, StaleMonitorException
	{
		KVOpExpression kve = (KVOpExpression) getExpression();
		ResourceMonitor mon;

		/*
		 * If there is no resource monitor, then we cannot
		 * make an assessment of the objective's achievability.
		 * Log a message to make clear that this objective is
		 * not being assessed and then indicate that
		 * the objective has been achieved.
		 */
		try {
			mon = solver.getMonitor().get((Resource)elem);
		} catch (StaleMonitorException sme) {
			Poold.MON_LOG.log(Severity.INFO,
			    elem.toString() +
			    " utilization objective not measured " +
			    toString() + " as there are no available " +
			    "statistics.");
			return (false);
		}
		gapSolver = solver;

		double val = solver.getMonitor().getUtilization((Resource)elem);

		StatisticList sl = (StatisticList) mon.get("utilization");
		int zone = sl.getZone(kve, val);

		if (zoneList.size() == 9) {
			zoneList.remove(0);
		}
		zoneList.add(new Integer(sl.getZoneMean(val)));

		/*
		 * Evaluate whether or not this objective is under
		 * control.
		 */
		if ((zone & StatisticOperations.ZONEZ) ==
		    StatisticOperations.ZONEZ) {
			/*
			 * If the objective is GT or LT, then don't
			 * return true as long as the objective is
			 * satisfied.
			 */
			if (kve.getOp() == KVOpExpression.LT &&
			    (zone & StatisticOperations.ZONET) ==
			    StatisticOperations.ZONELT)
				return (false);

			if (kve.getOp() == KVOpExpression.GT &&
			    (zone & StatisticOperations.ZONET) ==
			    StatisticOperations.ZONEGT)
				return (false);
			Poold.MON_LOG.log(Severity.INFO,
			    elem.toString() +
			    " utilization objective not satisfied " +
			    toString() + " with utilization " + uf.format(val) +
			    " (control zone bounds exceeded)");
			return (true);
		}
		/*
		 * Check if our statistics need to be recalculated.
		 */
		checkShort(mon, elem, val);
		return (false);
	}

	/**
	 * Calculates the value of a configuration in terms of this
	 * objective.
	 *
	 * Every set must be classified with a control zone when this
	 * function is called. The move can be assessed in terms of
	 * the control violation type. zone violations which are minor
	 * are offered a lower contribution than more significant
	 * violations.
	 *
	 * @param conf Configuration to be scored.
	 * @param move Move to be scored.
	 * @param elem The element to which the objective applies
	 * @throws Exception If an there is an error in execution.
	 */
	public double calculate(Configuration conf, Move move, Element elem)
	    throws PoolsException
	{
		KVOpExpression kve = (KVOpExpression) getExpression();
		double ret;

		/*
		 * If the move is from the examined element, then
		 * check to see if the recipient has any
		 * objectives. If not, score the move poorly since we
		 * should never want to transfer resources to a
		 * recipient with no objectives. If there are
		 * objectives, then return the delta between target
		 * performance and actual performance for this
		 * element.
		 *
		 * If the move is to the examined element, then check
		 * to see if the donor has any objectives. If not,
		 * score the move highly, since we want to favour
		 * those resources with objectives. If there are
		 * objectives, return the delta between actual and
		 * target performance.
		 *
		 * If the element is neither the recipient or the
		 * donor of this proposed move, then score the move
		 * neutrally as 0.
		 */
		try {
			double val, gap;
			StatisticList sl;

			if (elem.equals(move.getFrom())) {
				val = gapSolver.getMonitor().
				    getUtilization(move.getFrom());
				sl = (StatisticList) gapSolver.getMonitor().
				    get(move.getFrom()).get("utilization");
				gap = sl.getGap(kve, val) / 100;

				if (gapSolver.getObjectives(move.getTo()) ==
				    null) {
					/*
					 * Moving to a resource with
					 * no objectives should always
					 * be viewed unfavourably. The
					 * degree of favourability is
					 * thus bound between 0 and
					 * -1. If the source gap is
					 * negative, then subtract it
					 * from -1 to get the
					 * score. If positive,
					 * just return -1.
					 */
					    if (gap < 0) {
						    ret = -1 - gap;
					    } else {
						    ret = -1;
					    }
				} else {
					ret = 0 - gap;
				}
			} else if (elem.equals(move.getTo())) {
				val = gapSolver.getMonitor().
				    getUtilization(move.getTo());
				sl = (StatisticList) gapSolver.getMonitor().
				    get(move.getTo()).get("utilization");
				gap = sl.getGap(kve, val) / 100;

				if (gapSolver.getObjectives(move.getFrom()) ==
				    null) {
					/*
					 * Moving from a resource with
					 * no objectives should always
					 * be viewed favourably. The
					 * degree of favourability is
					 * thus bound between 0 and
					 * 1. If the destination gap
					 * is negative, then add to 1
					 * to get the score. If
					 * positive, just return 1.
					 */
					if (gap < 0) {
						ret = 0 - gap;
					} else {
						ret = 1;
					}
				} else {
					ret = 0 + gap;
				}
			} else {
				ret = 0;
			}
		} catch (StaleMonitorException sme) {
			/*
			 * We should always find a monitor,
			 * but if we can't then just assume
			 * this is a neutral move and return
			 * 0.
			 */
			ret = 0;
		}
		Poold.MON_LOG.log(Severity.DEBUG, "ret: " + ret);
		return (ret);
	}

	/**
	 * Check whether or not a set's statistics are still useful
	 * for making decision..
	 *
	 * Each set is controlled in terms of the zones of control
	 * based in terms of standard deviations from a mean. If the
	 * utilization of the set is not fluctuating normally around a
	 * mean, these checks will cause the accumulated statistics to
	 * be discarded and control suspended until a new sufficient
	 * set of data is accumulated.
	 *
	 * @param mon Resource monitor to examine.
	 * @param elem Element to which the resource monitor belongs.
	 * @param val Latest monitored value.
	 */
	private void checkShort(ResourceMonitor mon, Element elem, double val)
	{
		boolean checkOne = true;
		int checkOnePos = 0;
		boolean doCheckOne = false;

		Iterator itZones = zoneList.iterator();
		while (itZones.hasNext()) {
			int zone = ((Integer) itZones.next()).intValue();
			if (doCheckOne) {
				if (checkOne) {
					if ((zone & StatisticOperations.ZONET)
					    != checkOnePos) {
						checkOne = false;
					}
				}
			} else {
				if (zoneList.size() >= 9) {
					checkOnePos = zone &
					    StatisticOperations.ZONET;
					doCheckOne = true;
				}
			}
		}
		if (zoneList.size() >= 9 && checkOne) {
			Poold.MON_LOG.log(Severity.INFO,
			    elem.toString() +
			    " utilization objective statistics reinitialized " +
			    toString() + " with utilization " + uf.format(val) +
			    " (nine points on same side of mean)");
			mon.resetData("utilization");
			zoneList.clear();
		}
	}
}
