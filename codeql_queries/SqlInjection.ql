/**
 * @name SQL Injection (CWE-89)
 * @description Detects potential SQL injection vulnerabilities
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id py/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import DataFlow::PathGraph

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // User input sources
    exists(ControlFlowNode node |
      node.(Call).getFunc().toString() in [
        "request.args.get", "request.form.get", "request.json.get",
        "input", "sys.argv.__getitem__", "os.environ.get"
      ] and
      source.asCfgNode() = node
    )
    or
    // String sources from HTTP
    exists(AttrNode attr |
      attr.getObject("args").getObject("request").flowsTo(source.asCfgNode()) or
      attr.getObject("form").getObject("request").flowsTo(source.asCfgNode())
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // SQL execution sinks
    exists(CallNode call |
      call.getFunction().(AttrNode).getObject("execute").getObject(_) = sink.asCfgNode() or
      call.getFunction().(NameNode).getId() in [
        "execute", "executemany", "raw", "RawSQL", "cursor.execute"
      ]
    )
    or
    // String formatting that flows to SQL
    exists(BinaryExpr expr |
      expr.getOp().toString() = "%" and
      expr.getAChildNode*().(StrConst).getText().matches("%SELECT%INSERT%UPDATE%DELETE%") and
      sink.asExpr() = expr
    )
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    // Parameterized queries
    exists(CallNode call |
      call.getFunction().(NameNode).getId() in ["escape", "mogrify"] and
      sanitizer.asCfgNode() = call
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink, source, sink,
  "Potential SQL injection: user input flows to SQL query without proper sanitization."
