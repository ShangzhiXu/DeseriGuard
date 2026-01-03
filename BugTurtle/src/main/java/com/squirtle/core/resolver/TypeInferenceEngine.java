package com.squirtle.core.resolver;

import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.DominatorsFinder;
import soot.toolkits.graph.MHGDominatorsFinder;

import java.util.*;
import java.util.logging.Logger;

/**
 * 类型推断引擎
 * 
 * 负责所有的接收者类型推断逻辑，包括：
 * 1. 四条规则统一类型推断（前置强转、最近new、instanceof守卫、后置强转）
 * 2. Value比较和类型转换
 * 3. 动态距离计算
 * 
 * @author BugTurtle  
 * @version 1.0
 */
public class TypeInferenceEngine {
    
    private static final Logger logger = Logger.getLogger(TypeInferenceEngine.class.getName());
    
    /**
     * 四条规则统一类型推断：
     * 1) 前置显式强转  2) 最近定义为 new  3) instanceof 守卫（支配调用点）  4) 直接静态类型  5) 后置显式强转
     */
    public SootClass inferReceiverType(SootMethod caller, Unit callSite, InstanceInvokeExpr invokeExpr) {
        Value base = invokeExpr.getBase();
        String methodName = invokeExpr.getMethod().getName();
        
        // 添加toString调用的特殊日志
        if ("toString".equals(methodName)) {
            logger.info("🔍 类型推断-toString调用: " + caller.getName() + " | base=" + base + " | callSite=" + callSite);
        }
        
        // 计算动态搜索距离
        int maxBackDistance = calculateSearchDistance(caller);
        int maxForwardDistance = Math.max(20, maxBackDistance / 2);
        
        // 1) 前置显式强转（支持Local和字段引用）
        SootClass preCast = findPreCastType(caller, callSite, base, maxBackDistance);
        if (preCast != null) {
            if ("toString".equals(methodName)) {
                logger.info("🎯 toString前置强转推断成功: " + preCast.getName());
            }
            return preCast;
        }
        
        // 1.5) 前置强转（作为其他局部变量赋值的右值强转）：x = (T) base
        SootClass preCastFromRhs = findPreCastTypeFromRhsUse(caller, callSite, base, maxBackDistance);
        if (preCastFromRhs != null) {
            if ("toString".equals(methodName)) {
                logger.info("🎯 toString前置RHS强转推断成功: " + preCastFromRhs.getName());
            }
            return preCastFromRhs;
        }
        
        // 2) 最近定义为 new（支持Local和字段引用）
        SootClass newType = findNearestNewType(caller, callSite, base, maxBackDistance);
        if (newType != null) {
            if ("toString".equals(methodName)) {
                logger.info("🎯 toString new类型推断成功: " + newType.getName());
            }
            return newType;
        }
        
        // 3) instanceof 守卫（仅看之前且支配调用点，支持Local和字段引用）
        SootClass instType = findInstanceofGuardType(caller, callSite, base);
        if (instType != null) {
            if ("toString".equals(methodName)) {
                logger.info("🎯 toString instanceof推断成功: " + instType.getName());
            }
            return instType;
        }
        
        // 4) 后置显式强转（短距前瞻；若前置也有则前置优先）
        SootClass postCast = findPostCastType(caller, callSite, base, maxForwardDistance);
        if (postCast != null) {
            if ("toString".equals(methodName)) {
                logger.info("🎯 toString后置强转推断成功: " + postCast.getName());
            }
            return postCast;
        }

        // 5) 直接静态类型（若过于泛化则忽略）
        SootClass refType = typeFromRefType(base.getType());
        if (refType != null && !isTooGenericRefType(refType)) {
            if ("toString".equals(methodName)) {
                logger.info("🎯 toString静态类型推断: " + refType.getName());
            }
            return refType;
        }

        if ("toString".equals(methodName)) {
            logger.info("❌ toString类型推断失败，无法确定精确类型");
        }
        return null;
    }
    
    /**
     * 推断Local变量的类型（用于反序列化等场景）
     * 
     * 针对赋值语句的左侧local变量，应用5规则类型推断：
     * 1. 前置强转: target = (T) expr; <callsite>
     * 2. 最近new分配: target = new T(); <callsite>  
     * 3. instanceof守卫: if (target instanceof T) <callsite>
     * 4. 后置强转: <callsite>; target2 = (T) target;
     * 5. 静态类型: target的声明类型
     */
    public SootClass inferLocalType(SootMethod method, Unit assignUnit, Local targetLocal) {
        if (targetLocal == null) return null;
        
        try {
            // 动态计算搜索距离
            int maxBackDistance = calculateSearchDistance(method);
            int maxForwardDistance = Math.max(20, maxBackDistance / 2);
            
            // 1) 前置强转类型推断
            SootClass preCast = findPreCastType(method, assignUnit, targetLocal, maxBackDistance);
            if (preCast != null) return preCast;
            
            // 2) 最近new分配类型推断  
            SootClass newType = findNearestNewType(method, assignUnit, targetLocal, maxBackDistance);
            if (newType != null) return newType;
            
            // 3) instanceof守卫类型推断
            SootClass instType = findInstanceofGuardType(method, assignUnit, targetLocal);
            if (instType != null) return instType;
            
            // 4) 后置强转类型推断
            SootClass postCast = findPostCastType(method, assignUnit, targetLocal, maxForwardDistance);
            if (postCast != null) return postCast;
            
            // 5) 静态类型推断
            SootClass refType = typeFromRefType(targetLocal.getType());
            if (refType != null && !isTooGenericRefType(refType)) return refType;
            
            return null;
            
        } catch (Exception e) {
            logger.warning("Local变量类型推断失败: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 计算搜索距离（根据方法复杂度动态调整）
     */
    public int calculateSearchDistance(SootMethod method) {
        try {
            if (!method.hasActiveBody()) return 40; // 默认距离
            
            Body body = method.getActiveBody();
            int unitCount = body.getUnits().size();
            
            // 根据方法大小动态调整搜索距离
            if (unitCount < 20) return 15;       // 小方法
            else if (unitCount < 50) return 30;  // 中等方法  
            else if (unitCount < 100) return 50; // 大方法
            else return 80;                      // 超大方法
            
        } catch (Exception e) {
            return 40; // 异常时使用默认距离
        }
    }

    public SootClass findPreCastType(SootMethod caller, Unit callSite, Value base, int maxBack) {
        try {
            Body body = caller.hasActiveBody() ? caller.getActiveBody() : null;
            if (body == null) return null;
            List<Unit> units = new ArrayList<>();
            for (Unit u : body.getUnits()) units.add(u);
            int idx = units.indexOf(callSite);
            if (idx <= 0) return null;

            for (int i = idx - 1, steps = 0; i >= 0 && steps++ < maxBack; i--) {
                Unit u = units.get(i);
                if (u instanceof AssignStmt) {
                    AssignStmt as = (AssignStmt) u;
                    // 支持Local和字段引用的比较
                    if (isSameValue(as.getLeftOp(), base)) {
                        Value rhs = as.getRightOp();
                        if (rhs instanceof CastExpr) {
                            return typeFromRefType(((CastExpr) rhs).getCastType());
                        }
                        break; // 最近一次定义不是强转
                    }
                }
            }
        } catch (Exception e) {
            logger.warning("前置强转类型推断失败: " + e.getMessage());
        }
        return null;
    }

    /**
     * 在调用点之前，若出现过形如 target = (T) base 的强转，则可据此推断 base 的类型为 T
     */
    private SootClass findPreCastTypeFromRhsUse(SootMethod caller, Unit callSite, Value base, int maxBack) {
        try {
            Body body = caller.hasActiveBody() ? caller.getActiveBody() : null;
            if (body == null) return null;
            List<Unit> units = new ArrayList<>();
            for (Unit u : body.getUnits()) units.add(u);
            int idx = units.indexOf(callSite);
            if (idx <= 0) return null;

            for (int i = idx - 1, steps = 0; i >= 0 && steps++ < maxBack; i--) {
                Unit u = units.get(i);
                if (u instanceof AssignStmt) {
                    AssignStmt as = (AssignStmt) u;
                    // 若 base 被重定义则停止（最近性）
                    if (isSameValue(as.getLeftOp(), base)) break;

                    if (as.getRightOp() instanceof CastExpr) {
                        CastExpr ce = (CastExpr) as.getRightOp();
                        if (isSameValue(ce.getOp(), base)) {
                            return typeFromRefType(ce.getCastType());
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private SootClass findNearestNewType(SootMethod caller, Unit callSite, Value base, int maxBack) {
        try {
            Body body = caller.hasActiveBody() ? caller.getActiveBody() : null;
            if (body == null) return null;
            List<Unit> units = new ArrayList<>();
            for (Unit u : body.getUnits()) units.add(u);
            int idx = units.indexOf(callSite);
            if (idx <= 0) return null;

            for (int i = idx - 1, steps = 0; i >= 0 && steps++ < maxBack; i--) {
                Unit u = units.get(i);
                if (u instanceof AssignStmt) {
                    AssignStmt as = (AssignStmt) u;
                    // 支持Local和字段引用的比较
                    if (isSameValue(as.getLeftOp(), base)) {
                        if (as.getRightOp() instanceof NewExpr) {
                            String cls = ((NewExpr) as.getRightOp()).getBaseType().getClassName();
                            if (Scene.v().containsClass(cls)) return Scene.v().getSootClass(cls);
                            return null;
                        }
                        break; // 最近一次定义不是 new
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    private SootClass findInstanceofGuardType(SootMethod caller, Unit callSite, Value base) {
        try {
            Body body = caller.hasActiveBody() ? caller.getActiveBody() : null;
            if (body == null) return null;
            ExceptionalUnitGraph cfg = new ExceptionalUnitGraph(body);
            DominatorsFinder<Unit> dom = new MHGDominatorsFinder<>(cfg);

            for (Unit u : body.getUnits()) {
                if (u instanceof IfStmt) {
                    IfStmt ifs = (IfStmt) u;
                    Value cond = ifs.getCondition();
                    if (cond instanceof InstanceOfExpr) {
                        InstanceOfExpr ioe = (InstanceOfExpr) cond;
                        // 支持Local和字段引用的比较
                        if (isSameValue(ioe.getOp(), base)) {
                            // 需支配调用点
                            List<Unit> dominators = dom.getDominators(callSite);
                            if (dominators != null && dominators.contains(u)) {
                                return typeFromRefType(ioe.getCheckType());
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    public SootClass findPostCastType(SootMethod caller, Unit callSite, Value base, int maxFwd) {
        try {
            Body body = caller.hasActiveBody() ? caller.getActiveBody() : null;
            if (body == null) return null;
            List<Unit> units = new ArrayList<>();
            for (Unit u : body.getUnits()) units.add(u);
            int idx = units.indexOf(callSite);
            if (idx < 0) return null;

            logger.fine("🔍 后置强转推断: " + caller.getName() + " | base=" + base + " | maxFwd=" + maxFwd);
            
            for (int i = idx + 1, steps = 0; i < units.size() && steps++ < maxFwd; i++) {
                Unit u = units.get(i);
                logger.fine("  检查Unit[" + i + "]: " + u);
                
                if (u instanceof AssignStmt) {
                    AssignStmt as = (AssignStmt) u;
                    // base 被重定义则停止（支持Local和字段引用）
                    if (isSameValue(as.getLeftOp(), base)) {
                        logger.fine("  ❌ base被重定义，停止搜索: " + as);
                        break;
                    }

                    if (as.getRightOp() instanceof CastExpr) {
                        CastExpr ce = (CastExpr) as.getRightOp();
                        logger.fine("  发现强转: " + ce + " | castOp=" + ce.getOp() + " | base=" + base);
                        // 支持Local和字段引用的比较
                        if (isSameValue(ce.getOp(), base)) {
                            SootClass castType = typeFromRefType(ce.getCastType());
                            logger.info("🎯 后置强转推断成功: " + base + " -> " + (castType != null ? castType.getName() : "null"));
                            return castType;
                        }
                    }
                }
            }
            logger.fine("  ℹ️ 后置强转推断未找到匹配: " + base);
        } catch (Exception e) {
            logger.warning("后置强转类型推断失败: " + e.getMessage());
        }
        return null;
    }

    public SootClass typeFromRefType(Type t) {
        try {
            if (t instanceof RefType) {
                String cls = ((RefType) t).getClassName();
                if (Scene.v().containsClass(cls)) return Scene.v().getSootClass(cls);
                // 尝试将类型加入Scene以便后续获取
                try {
                    Scene.v().addBasicClass(cls, SootClass.SIGNATURES);
                } catch (Exception ignored) {}
                if (Scene.v().containsClass(cls)) return Scene.v().getSootClass(cls);
            }
        } catch (Exception ignored) {}
        return null;
    }

    /**
     * 比较两个Value是否相同（支持Local和字段引用）
     */
    public boolean isSameValue(Value v1, Value v2) {
        if (v1 == null || v2 == null) return false;
        
        // 如果都是Local，使用equivTo
        if (v1 instanceof Local && v2 instanceof Local) {
            return ((Local) v1).equivTo((Local) v2);
        }
        
        // 如果都是字段引用，比较字段和基对象
        if (v1 instanceof InstanceFieldRef && v2 instanceof InstanceFieldRef) {
            InstanceFieldRef f1 = (InstanceFieldRef) v1;
            InstanceFieldRef f2 = (InstanceFieldRef) v2;
            return f1.getField().equals(f2.getField()) && 
                   isSameValue(f1.getBase(), f2.getBase());
        }
        
        if (v1 instanceof StaticFieldRef && v2 instanceof StaticFieldRef) {
            StaticFieldRef f1 = (StaticFieldRef) v1;
            StaticFieldRef f2 = (StaticFieldRef) v2;
            return f1.getField().equals(f2.getField());
        }
        
        return false;
    }
    
    /**
     * 判断引用类型是否过于泛化（如 java.lang.Object），用于避免退化为大范围 CHA
     */
    private boolean isTooGenericRefType(SootClass refType) {
        try {
            String n = refType.getName();
            if ("java.lang.Object".equals(n)) return true;
            return false;
        } catch (Exception ignored) {}
        return false;
    }
}



