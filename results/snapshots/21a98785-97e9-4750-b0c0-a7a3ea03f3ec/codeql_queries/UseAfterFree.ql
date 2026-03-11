/**
 * @name Use After Free (CWE-416)
 * @description Detects potential use-after-free vulnerabilities
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id cpp/use-after-free
 * @tags security
 *       external/cwe/cwe-416
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow
import semmle.code.cpp.controlflow.Guards

/**
 * Find calls to free() that might lead to use-after-free
 */
predicate isFreeCall(FunctionCall freeCall, Expr freedExpr) {
  freeCall.getTarget().getName() = "free" and
  freedExpr = freeCall.getArgument(0)
}

/**
 * Find expressions that use a potentially freed pointer
 */
predicate isUseAfterFree(Expr useExpr, Expr freedExpr, FunctionCall freeCall) {
  isFreeCall(freeCall, freedExpr) and
  useExpr != freedExpr and
  // Same variable/pointer is used after free
  useExpr.(VariableAccess).getTarget() = freedExpr.(VariableAccess).getTarget() and
  // Use comes after free in control flow
  useExpr.getBasicBlock().strictlyDominates(freeCall.getBasicBlock())
}

from Expr useExpr, Expr freedExpr, FunctionCall freeCall
where isUseAfterFree(useExpr, freedExpr, freeCall)
select useExpr,
  "Potential use-after-free: pointer used after being freed at $@.",
  freeCall, "this free call"
