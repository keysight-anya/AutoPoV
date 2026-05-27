/**
 * @name SQL Injection (CWE-89)
 * @description Building a SQL query from user-controlled sources.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/sql-injection-local
 * @tags security
 *       external/cwe/cwe-89
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.QueryInjection
import DataFlow::PathGraph

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof QueryInjectionSink
  }
}

from SqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL query built from user-controlled source $@.", source.getNode(), "user input"
