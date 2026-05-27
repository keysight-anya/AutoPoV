/**
 * @name Buffer Overflow (CWE-119)
 * @description Detects potential buffer overflow vulnerabilities
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id cpp/buffer-overflow
 * @tags security
 *       external/cwe/cwe-119
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class BufferOverflowConfig extends TaintTracking::Configuration {
  BufferOverflowConfig() { this = "BufferOverflowConfig" }

  override predicate isSource(DataFlow::Node source) {
    // User input sources
    exists(FunctionCall call |
      call.getTarget().getName() in ["gets", "scanf", "fscanf", "sscanf", "read", "recv"]
      and source.asExpr() = call
    )
    or
    // Function parameters
    exists(Parameter p |
      p.getFunction().getName() != "main" and
      source.asParameter() = p
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // Buffer write operations
    exists(FunctionCall call |
      call.getTarget().getName() in ["strcpy", "strcat", "memcpy", "memmove", "sprintf"]
      and sink.asExpr() = call.getArgument(0)
    )
    or
    // Array writes without bounds checking
    exists(ArrayExpr arr |
      sink.asExpr() = arr
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    // Bounds checking functions
    exists(FunctionCall call |
      call.getTarget().getName() in ["strlen", "sizeof", "strnlen", "strlcpy", "strlcat"]
      and sanitizer.asExpr() = call
    )
  }
}

from BufferOverflowConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink,
  "Potential buffer overflow: user input flows to buffer operation without proper bounds checking."
