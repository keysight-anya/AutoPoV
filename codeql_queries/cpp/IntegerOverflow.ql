/**
 * @name Integer Overflow (CWE-190)
 * @description Detects potential integer overflow vulnerabilities
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/integer-overflow
 * @tags security
 *       external/cwe/cwe-190
 */

import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis

/**
 * Find arithmetic operations that might overflow
 */
predicate isPotentialOverflow(Operation op) {
  // Multiplication that could overflow
  op instanceof MulExpr and
  not op.getType().(IntegralType).isUnsigned() and
  // No bounds check before operation
  not exists(GuardCondition guard |
    guard.controls(op.getBasicBlock(), _)
  )
  or
  // Addition that could overflow
  op instanceof AddExpr and
  not op.getType().(IntegralType).isUnsigned() and
  // Large value being added
  exists(Expr operand |
    operand = op.getAnOperand() and
    not operand instanceof Literal
  )
  or
  // Left shift that could overflow
  op instanceof LShiftExpr and
  exists(Literal shiftAmount |
    shiftAmount = op.getRightOperand() and
    shiftAmount.getValue().toInt() >= 16
  )
}

/**
 * Find array index calculations that might overflow
 */
predicate isArrayIndexOverflow(ArrayExpr arr) {
  exists(AddExpr indexCalc |
    indexCalc = arr.getArrayOffset() and
    indexCalc.getAnOperand() instanceof VariableAccess and
    not exists(GuardCondition guard |
      guard.controls(arr.getBasicBlock(), _)
    )
  )
}

from Expr expr
where isPotentialOverflow(expr)
   or isArrayIndexOverflow(expr)
select expr,
  "Potential integer overflow: arithmetic operation may overflow without proper bounds checking."
