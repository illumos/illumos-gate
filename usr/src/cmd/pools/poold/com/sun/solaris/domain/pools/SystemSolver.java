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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 */

package com.sun.solaris.domain.pools;

import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.util.*;
import java.util.regex.*;
import java.text.DecimalFormat;

import com.sun.solaris.service.locality.*;
import com.sun.solaris.service.logging.*;
import com.sun.solaris.service.pools.*;
import com.sun.solaris.service.exception.*;

/**
 * The <code>SystemSolver</code> class implements a dynamic resource
 * allocation solver. The Solver takes a configuration and "solves"
 * the resource allocation problem.
 *
 * This class operates upon a configuration which is suppplied during
 * initialization. Its responsibilities include:
 * <ul>
 * <li><p>
 * Maintaining decision history
 * <li><p>
 * Maintaining information about the locality domain
 * <li><p>
 * Maintaining a map of all elements and their associated set of objectives
 * <li><p>
 * Identifying objective expressions with a configuration
 * </ul>
 */
class SystemSolver implements Solver {
	/**
	 * The default location of this history file.
	 */
	public static final String DH_FILE_DEF_PATH =
	    "/var/adm/pool/history";

	/**
	 * The property overriding the default decision history path.
	 */
	public static final String DH_FILE_PROP_NAME =
	    "system.poold.history-file";

	/**
	 * The LocalityDomain extracted from the configuration.
	 */
	private LocalityDomain ldom;

	/**
	 * The objective map used to link all elements with their set
	 * of objectives.
	 */
	private Map objMap;

	/**
	 * The pattern used to identify objective expressions.
	 */
	private static final Pattern p0 = Pattern.compile(";");

	/**
	 * The configuration for which this solver is "solving".
	 */
	private Configuration conf;

	/**
	 * Monitor providing statistics for this solver.
	 */
	private final Monitor monitor;

	/**
	 * The decision history maintainer.
	 */
	private DecisionHistory dh;

	/**
	 * The path to the decision history file.
	 */
	private String dhPath;

	/**
	 * The number of CPUs on the system.
	 */
	private int cpuCount;

	/**
	 * The number of locality triggered examinations made.
	 */
	private int examineCount;

	/**
	 * Constructs a solver which initialises a decision history
	 * maintainer.  The decision history is be used during operation
	 * to veto historically-poor decisions output from the objective
	 * function.
	 */
	SystemSolver(Monitor monitor)
	{
		/*
		 * Create a HashMap to store all objectives.
		 */
		objMap = new HashMap();
		this.monitor = monitor;
	}

	/**
	 * Initialize the solver for operation upon the supplied
	 * configuration. Possible objective expressions set upon
	 * target elements are identified and stored in an objective
	 * map which associates elements with the set of their
	 * objectives.
	 *
	 * @param conf The configuration to be manipulated.
	 * @throws PoolsException If the initialization fails.
	 */
	public void initialize(Configuration conf) throws PoolsException
	{
		String oString = null;
		String exps[];

		this.conf = conf;
		/*
		 * Count the CPUs in the system, this is used to
		 * control locality objective processing in the
		 * examine() method.
		 */
		cpuCount = conf.getComponents(null).size();
		examineCount = 0;
		/*
		 * Remove any old objectives
		 */
		objMap.clear();

		/*
		 * Extract any configuration objectives
		 */
		try {
			oString = conf.getStringProperty(
			    "system.poold.objectives");
			if (oString.length() > 0) {
				Set oSet = new HashSet();
				objMap.put(conf, oSet);
				Poold.CONF_LOG.log(Severity.DEBUG,
				    "adding configuration objective " +
				    oString);
				exps = p0.split(oString);
				for (int i = 0; i < exps.length; i++) {
					try {
						Expression exp =
						    Expression.valueOf(
						    exps[i]);
						addObjective(oSet, "system",
						    exp);
					} catch (IllegalArgumentException iae) {
						Poold.utility.warn(
						    Poold.CONF_LOG, iae, false);
					}
				}
			}
		} catch (PoolsException pe) {
			/*
			 * Ignore as this means there is no objective
			 * property
			 */
		}
		/*
		 * Now extract all pset objectives
		 */
		Value typeProp = new Value("type", "pset");
		List valueList = new LinkedList();
		valueList.add(typeProp);
		Iterator resIt = conf.getResources(valueList).iterator();
		typeProp.close();
		while (resIt.hasNext()) {
			Resource resource = (Resource)resIt.next();

			try {
				oString = resource.getStringProperty(
				    "pset.poold.objectives");
				if (oString.length() > 0) {
					Set oSet = new HashSet();
					objMap.put(resource, oSet);
					Poold.CONF_LOG.log(Severity.DEBUG,
					    "adding " +
					    resource.getStringProperty(
					    "pset.name") +
					    " objective \"" + oString + "\"");
					exps = p0.split(oString);
					for (int i = 0; i < exps.length; i++) {
						Expression exp = null;
						try {
							exp = Expression.
							    valueOf(exps[i]);
							addObjective(oSet,
							    "pset", exp);
						} catch
						    (IllegalArgumentException e)
						{
							Poold.utility.warn(
							    Poold.CONF_LOG, e,
							    false);
						}
					}
				}
			} catch (PoolsException pe) {
				continue;
			}
		}
		Poold.CONF_LOG.log(Severity.DEBUG, "objective map: " +
		    objMap.toString());

		/*
		 * Capture the LocalityDomain details.
		 */
		if (ldom != null) {
			ldom.close();
		}
		try {
			ldom = new LocalityDomain(LocalityDomain.LGRP_VIEW_OS);
		} catch (Exception e) {
			Poold.utility.die(Poold.OPT_LOG, e);
		}

		/*
		 * Load or create the decision history.
		 */
		String newDhPath;
		try {
			newDhPath = conf.getStringProperty(
			    DH_FILE_PROP_NAME);
		} catch (PoolsException pe) {
			newDhPath = DH_FILE_DEF_PATH;
		}

		if (!newDhPath.equals(dhPath)) {
			try {
				dh = DecisionHistory.loadFromFile(newDhPath);
				Poold.CONF_LOG.log(Severity.DEBUG,
				    "loaded history file " + newDhPath);
			} catch (Exception e) {
				if (!(e instanceof FileNotFoundException)) {
					Poold.CONF_LOG.log(Severity.WARNING,
					    newDhPath +
					    ": contents unusable; ignoring");
					Poold.CONF_LOG.log(Severity.DEBUG,
					    newDhPath + ": contents unusable",
					    e);
				}
				/*
				 * Use current DecisionHistory instead,
				 * if any.
				 */
				if (dh == null)
					dh = new DecisionHistory();
			}

			/*
			 * Try using the new path.
			 */
			try {
				dh.syncToFile(newDhPath);
			} catch (Exception e) {
				Poold.utility.die(Poold.CONF_LOG,
				    new PooldException(newDhPath +
				    ": couldn't synchronize history file")
				    .initCause(e), false);
			}
			dhPath = newDhPath;
		}
	}

	/**
	 * Determine if the given resource has non-workload-dependent
	 * objectives.
	 * @param elem The element to examine.
	 */
	private boolean hasNonWorkloadDependentObjectives(Element elem)
	{
		Set elemObj = (Set)objMap.get(elem);

		/*
		 * This code relies upon the fact that an element with
		 * no objectives will not have an empty set, but rather
		 * no value in the objMap.
		 */

		if (elemObj == null)
			return (false);

		Iterator elemObjIt = elemObj.iterator();
		while (elemObjIt.hasNext())
			if (elemObjIt.next() instanceof
			    WorkloadDependentObjective)
				return (false);

		return (true);
	}

	/**
	 * Determine if the given resource has workload-dependent
	 * objectives.
	 * @param elem The element to examine.
	 */
	private boolean hasWorkloadDependentObjectives(Element elem)
	{
		Set elemObj = (Set)objMap.get(elem);

		/*
		 * This code relies upon the fact that an element with
		 * no objectives will not have an empty set, but rather
		 * no value in the objMap.
		 */

		if (elemObj == null)
			return (false);

		Iterator elemObjIt = elemObj.iterator();
		while (elemObjIt.hasNext())
			if (elemObjIt.next() instanceof
			    WorkloadDependentObjective)
				return (true);

		return (false);
	}

	/**
	 * Return true if the monitored configuration should be
	 * reconfigured. All workload-dependent objectives are
	 * examined to determine if the configuration is still
	 * satisfying all specified objectives on all elements. If any
	 * objectives are failing, then this method will return true.
	 *
	 * @param mon The monitoring object used to assess objective
	 * compliance.
	 */
	public boolean examine(Monitor mon) throws PoolsException,
	    StaleMonitorException
	{
		/*
		 * Take advantage of the guaranteed-valid monitor data
		 * for measuring the improvement of any past decisions.
		 */
		dh.expireAndMeasureImprovements(mon);

		Iterator objIt = objMap.keySet().iterator();
		boolean ret = false;
		boolean hasLocalityObjectives = false;
		boolean isMonitorValid = true;

		/*
		 * All objectives are examined, even though failure
		 * could be detected earlier. This is because logging
		 * of all objectives is required and the information
		 * about failure can be stored and used during
		 * solving.
		 */
		while (objIt.hasNext()) {
			Element elem = (Element) objIt.next();
			Set elemObj = (Set) objMap.get(elem);
			Iterator elemObjIt = elemObj.iterator();
			while (elemObjIt.hasNext()) {
				Objective obj = (Objective) elemObjIt.next();
				Poold.OPT_LOG.log(Severity.DEBUG,
				    "checking objective " + obj);
				if (obj instanceof WorkloadDependentObjective) {
					if (isValid()) {
						/*
						 * If any objectives
						 * are violated, then
						 * we must
						 * reconfigure, so
						 * check them all in
						 * turn.
						 */
					ret = ((WorkloadDependentObjective)
					    obj).examine(conf, this, elem) ||
					    ret;
					} else
						isMonitorValid = false;
				}
			}

			/*
			 * Check if this is the first element, seen in
			 * this pass, that has locality objectives.
			 */
			if (!hasLocalityObjectives &&
			    hasNonWorkloadDependentObjectives(elem))
				hasLocalityObjectives = true;
		}
		if (isMonitorValid == false) {
			Poold.MON_LOG.log(Severity.INFO,
			    "not evaluating workload-dependent objectives " +
			    "until sufficient statistics are collected");
		}
		/*
		 * If we don't have locality objectives, we don't force
		 * the reexamination.  This is controlled by
		 * hasLocalityObjectives.
		 *
		 * So that we don't continually trigger
		 * reconfiguration examinations for locality
		 * objectives we stop forcing recalculations when we
		 * reach cpuCount / 2. This should be enough moves to
		 * get good locality for those configurations which
		 * have no WorkloadDependentObjectives.
		 */
		return (ret || (hasLocalityObjectives && (examineCount++ <
		    cpuCount / 2)));
	}

	/**
	 * Reallocate resources in a configuration to achieve user
	 * specified objectives. Return true if the configuration has
	 * been updated, false otherwise.
	 *
	 * This method should only be invoked if a previous
	 * examination of the configuration which is monitored
	 * indicates that objectives are failing. The monitored
	 * configuration is re-opened for editing, locking that
	 * configuration for the duration of this operation.
	 *
	 * @throws Exception If the solve fails.
	 */
	public boolean solve() throws Exception
	{
		boolean madeMove = false;
		/*
		 * All solving operations must be done in an
		 * "editable" context, so create a new modifiable
		 * configuration which is at the same location as the
		 * monitored configuration
		 */
		Configuration rwConf = new Configuration(conf.getLocation(),
		    PoolInternal.PO_RDWR);

		try {
			/*
			 * Build a resource set importance map for use
			 * when propagating pool importance to each
			 * possible solution. Use the same logic as
			 * libpool and let a resource take the highest
			 * importance value from all pools associated
			 * with the set.
			 */
			Map resImp = new HashMap();
			List poolList = rwConf.getPools(null);
			Iterator itPool = poolList.iterator();
			while (itPool.hasNext()) {
				Pool pool = (Pool) itPool.next();
				long newImp = pool.
				    getLongProperty("pool.importance");
				List resList = pool.getResources(null);
				Iterator itRes = resList.iterator();
				while (itRes.hasNext()) {
					Resource res = (Resource) itRes.next();
					if (resImp.containsKey(res)) {
						Long imp = (Long) resImp.
						    get(res);
						if (newImp > imp.longValue())
							resImp.put(res,
							    new Long(newImp));
					} else
						resImp.put(res,
						    new Long(newImp));
				}
			}
			/*
			 * Consider all possible alternative
			 * configurations.  This list is generated as a
			 * series of moves.  Administrative constraints
			 * are applied to the moves to prune the list of
			 * possible configurations.
			 */
			Value val = new Value("type", "pset");
			List valueList = new LinkedList();
			valueList.add(val);


			List resList = rwConf.getResources(valueList);
			val.close();
			List donors = getDonors(resList);
			List receivers = getRecipients(resList);
			Poold.OPT_LOG.log(Severity.DEBUG, "donors: " +
			    donors);
			Poold.OPT_LOG.log(Severity.DEBUG, "receivers: " +
			    receivers);
			Iterator itDonor = donors.iterator();
			List moves = new ArrayList();
			while (itDonor.hasNext()) {
				Resource donor = (Resource) itDonor.next();
				List processors = getProcessors(donor);
				Poold.OPT_LOG.log(Severity.DEBUG,
				    "donor processors: " + processors);
				Iterator itProcessor = processors.iterator();
				while (itProcessor.hasNext()) {
					Component cpu = (Component) itProcessor.
					    next();
					Iterator itReceiver = receivers.
					    iterator();
					while (itReceiver.hasNext()) {
						Resource receiver =
						    (Resource) itReceiver.
						    next();
						/*
						 * Can't move to yourself
						 */
						if (receiver == donor)
							continue;
						moves.add(new ComponentMove(
						      donor, receiver, cpu));
					}
				}
			}
			Poold.OPT_LOG.log(Severity.DEBUG,
			    "potential moves: " + moves);
			/*
			 * Now that we have our alternative configurations,
			 * score each configuration by applying all objectives
			 * to each configuration. Hold the scores in the
			 * score set.
			 */
			HashSet scores = new HashSet();
			Iterator itMoves = moves.iterator();
			while (itMoves.hasNext()) {
				double totalContrib = 0;
				Move move = (Move) itMoves.next();
				Iterator objIt = objMap.keySet().iterator();
				while (objIt.hasNext()) {
					Element elem = (Element) objIt.next();
					Set elemObj = (Set) objMap.get(elem);
					Iterator elemObjIt = elemObj.iterator();
					while (elemObjIt.hasNext()) {
						Objective obj =
						    (Objective)elemObjIt.next();
						if (obj instanceof
						    LocalityObjective)
							((LocalityObjective)obj)
							    .prepare(ldom,
							    (Resource)elem);
						/*
						 * If the monitor is
						 * invalid, do not
						 * process
						 * WorkloadDependentObjectives
						 * since they have an
						 * implicit dependency
						 * on the monitor
						 * data.
						 */
						if (obj instanceof
						    WorkloadDependentObjective)
							if (!isValid())
								continue;
						double contrib = obj.calculate(
						    rwConf, move, elem);
						if (contrib < -1 || contrib > 1)
							throw new
							IllegalOFValueException(
						        "x: " + contrib +
							" is invalid, legal " +
							"range is -1 <= x <= " +
							"1");
						/*
						 * Modify the basic
						 * score by the
						 * importance of the
						 * objective and (if
						 * appropriate) the
						 * importance of an
						 * associated pool.
						 */
						if (resImp.containsKey(elem)) {
							contrib *= ((Long)
							    resImp.get(elem)).
							    longValue();
						}

						totalContrib += contrib *
						    obj.getExpression().
						    getImportance();
					}
				}
				Poold.OPT_LOG.log(Severity.DEBUG,
				    "scored move (" + move + ") " +
				    totalContrib);
				scores.add(new ScoreMove(move, totalContrib));
			}
			if (scores.size() != 0) {
				/*
				 * Try to find a move to apply which
				 * yields a positive contribution.
				 */
				Object scoresArray[] = scores.toArray();
				Arrays.sort(scoresArray,
				    Collections.reverseOrder());
				if ((madeMove = processMoves(rwConf,
				    scoresArray, false)) == false)
					madeMove = processMoves(rwConf,
					    scoresArray, true);
			} else
				Poold.OPT_LOG.log(Severity.INFO,
				    "no moves found");
			rwConf.close();
			Poold.OPT_LOG.log(Severity.DEBUG,
			    "synchronizing decision history");
			dh.syncToFile(dhPath);
		} catch (Exception ex) {
			rwConf.close();
			throw ex;
		}
		return (madeMove);
	}

	/*
	 * Process the supplied array of scored moves, trying to find
	 * a move to apply. Return true if a move could be applied,
	 * false otherwise.
	 *
	 * @param conf The configuration to be modified.
	 * @param scores The areay of scored moves to be tried.
	 * @param ignoreDH Ignore Decision History details.
	 */
	private boolean processMoves(Configuration rwConf, Object scores[],
	    boolean ignoreDH) throws PoolsException, StaleMonitorException
	{
		boolean madeMove = false;

		for (int i = 0; i < scores.length; i++) {
			ScoreMove move = (ScoreMove) scores[i];
			if (move.getScore() <= 0) {
				if (ignoreDH)
					Poold.OPT_LOG.log(Severity.INFO,
					    move + " not applied as " +
					    "benefit not significant");
				break;
			}
			if ((madeMove = applyMove(rwConf, move, ignoreDH)) ==
			    true)
				break;
		}
		return (madeMove);
	}

	/*
	 * Attempt to apply the supplied move to the
	 * configuration. Return true if the move could be applied,
	 * false otherwise.
	 *
	 * @param conf The configuration to be modified.
	 * @param move The move to be applied.
	 * @param ignoreDH Ignore Decision History details.
	 */
	private boolean applyMove(Configuration conf, ScoreMove move,
	    boolean ignoreDH)
	    throws PoolsException, StaleMonitorException
	{
		boolean madeMove = false;
		boolean wdpInvolved = false;
		double utilization = 0.0;

		Poold.OPT_LOG.log(Severity.DEBUG, "selected " + move);
		if (hasWorkloadDependentObjectives(move.getMove().getTo()) ||
		    hasWorkloadDependentObjectives(conf)) {
			Poold.OPT_LOG.log(Severity.DEBUG,
			    "Attempting to retrieve utilization for:" + move
			    .getMove().getTo());
			utilization = monitor.getUtilization(move
			    .getMove().getTo());
			wdpInvolved = true;
		}

		/*
		 * Unless a move can be vetoed (i.e. decision history
		 * is effective and there are is a workload-dependent
		 * involved), the move should alwways be applied.
		 */
		if (ignoreDH || !wdpInvolved || !dh.veto(move.getMove(),
		    utilization)) {
			Poold.OPT_LOG.log(Severity.INFO,
			    "applying move " + move.getMove());
			move.getMove().apply();
			ResourceMonitor mon = getMonitor().get(move.getMove().
			    getFrom());
			mon.resetData("utilization");
			mon = getMonitor().get(move.getMove().getTo());
			mon.resetData("utilization");
			try {
				Poold.OPT_LOG.log(Severity.DEBUG,
				    "committing configuration");
				conf.commit(0);
				try {
					if (move.getMove() instanceof
					    ComponentMove)
						if (wdpInvolved)
							dh.recordProcessorMove(
							    (ComponentMove)move
							    .getMove(),
							    utilization,
							    monitor
							    .getSampleCount());
						else
							Poold.OPT_LOG.log(
							    Severity.DEBUG,
							    "decision not " +
							    "recorded due to " +
							    "lack of workload-"
							    + "dependent " +
							    "objectives");
				} catch (Exception e) {
					Poold.OPT_LOG.log(Severity.INFO,
					    "couldn't update " +
					    "decision history (" +
					    e.toString() + ")");
				}
				madeMove = true;
			} catch (PoolsException pe) {
				conf.rollback();
				Poold.OPT_LOG.log(Severity.INFO,
				    "move failed, possibly due to a " +
				    "bound process in a 1-processor " +
				    "set");
			}
		} else {
			/*
			 * Move was vetoed.
			 */
			if (!ignoreDH && wdpInvolved)
				Poold.OPT_LOG.log(Severity.INFO,
				    move.getMove() + " not applied due to " +
				    "poor past results");
		}
		return (madeMove);
	}

	/**
	 * Add an objective based on the supplied expression to the
	 * supplied set of objectives.
	 *
	 * @param oSet Set of objectives to be extended
	 * @param type Type of element to which the expression is applied
	 * @param exp Expression to be used in the objective
	 * @throws IllegalArgumentException If a duplicate objective
	 * is identified or an invalid expression is supplied for this
	 * type of element
	 */
	private void addObjective(Set oSet, String type, Expression exp)
	    throws IllegalArgumentException
	{
		Objective o = AbstractObjective.getInstance(type, exp);
		Poold.CONF_LOG.log(Severity.DEBUG, "parsed objective " + o);
		/*
		 * Check the set of objectives and find contradictions.
		 */
		Iterator itObjs = oSet.iterator();
		while (itObjs.hasNext()) {
			Objective other = (Objective) itObjs.next();
			if (o.getExpression().contradicts(
			    other.getExpression()))
				throw new IllegalArgumentException(
				    "contradictory objectives:" + other +
				    ", " + o);
		}

		if (oSet.add(o) != true)
			throw new IllegalArgumentException(
			    "duplicate objective:" + o);
	}

	/**
	 * Return a list of resource sets prepared to receive
	 * resources
	 *
	 * The list consists of all resource setss (of the supplied
	 * type) whose size is < their max constraint.
	 *
	 * @param resList The list of all resource sets from which
	 * recipients will be chosen
	 * @throws PoolsException if there is an error manipulation
	 * the pool resources
	 */
	private List getRecipients(List resList) throws PoolsException
	{
		List recipientList = new ArrayList();
		long size, max;
		for (int i = 0; i < resList.size(); i++) {
			Resource res;
			res = (Resource)resList.get(i);
			String type = res.getStringProperty("type");
			size = res.getLongProperty(type+".size");
			max = res.getLongProperty(type+".max");
			if (size < max)
				recipientList.add(res);
		}
		return (recipientList);
	}

	/**
	 * Return a list of resource sets prepared to donate resources
	 *
	 * The list consists of all resource sets (of the supplied
	 * type) whose size (minus the number of pinned resources
	 * where applicable) is > their min constraint.
	 *
	 * @param resList The list of all resource sets from which
	 * recipients will be chosen
	 * @throws PoolsException if there is an error manipulation
	 * the pool resources
	 */
	private List getDonors(List resList) throws PoolsException
	{
		List donorList = new ArrayList();
		long size, min;
		for (int i = 0; i < resList.size(); i++) {
			Value bValue;
			Resource res;
			List pinned;
			ArrayList valueList = new ArrayList();

			res = (Resource)resList.get(i);
			String type = res.getStringProperty("type");
			size = res.getLongProperty(type+".size");
			bValue = new Value("cpu.pinned", true);
			valueList.add(bValue);
			pinned = res.getComponents(valueList);
			bValue.close();
			min = res.getLongProperty(type+".min");
			if (pinned.size() > min)
				size -= pinned.size() - min;
			if (size > min)
				donorList.add(res);
		}
		return (donorList);
	}

	/**
	 * Return a list of Processors for the supplied resource.
	 *
	 * The list consists of all Processors (excluding the pinned
	 * Processors) in the set.
	 *
	 * @param set The resource for which Processors should be found
	 * @throws PoolsException if there is an error manipulation
	 * the pool resources
	 */
	private List getProcessors(Resource set) throws PoolsException
	{
		Iterator it = set.getComponents(null).iterator();
		List ret = new ArrayList();

		while (it.hasNext()) {
			Component cpu = (Component) it.next();
			try
			{
				if (cpu.getBoolProperty("cpu.pinned") == false)
					ret.add(cpu);
			} catch (PoolsException pe)
			{
				ret.add(cpu);
			}
		}
		return (ret);
	}

	/**
	 * Return true if the solver is capable of working with
	 * statistically valid data.
	 */
	public boolean isValid()
	{
		return (monitor.isValid());
	}

	/**
	 * Return the monitor used by this solver.
	 */
	public Monitor getMonitor()
	{
		return (monitor);
	}

	/**
	 * Return the set of objectives associated with the supplied
	 * element.
	 *
	 * @param elem Retrieve objectives for this element.
	 */
	public Set getObjectives(Element elem)
	{
		return ((Set)objMap.get(elem));
	}

	/**
	 * Holds details about the score of a proposed configuration
	 * move. Each move must be scored so that they can ranked in
	 * terms of increasing desirability
	 */
	static class ScoreMove implements Comparable {
		/**
		 * The move which is being scored.
		 */
		private final Move m;

		/**
		 * The score of the move.
		 */
		private final double score;

		/**
		 * Score formatter.
		 */
		private static final DecimalFormat scoreFormat =
		    new DecimalFormat("0.00");

		/**
		 * Constructor.
		 *
		 * @param m The move under consideration.
		 * @param score The score of the move.
		 */
		public ScoreMove(Move m, double score)
		{
			this.m = m;
			this.score = score;
		}

		public int compareTo(Object o)
		{
			ScoreMove other = (ScoreMove) o;

			return ((score < other.getScore()) ? -1 :
			    (score > other.getScore()) ? 1 : 0);
		}

		public String toString()
		{
			return ("move (" + m + ") score "
			    + scoreFormat.format(score));
		}

		/**
		 * Return the score.
		 */
		double getScore()
		{
			return (score);
		}

		/**
		 * Return the move.
		 */
		Move getMove()
		{
			return (m);
		}
	}
}
