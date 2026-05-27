/**
 * @name SQL Injection (CWE-89)
 * @description Building a SQL query from user-controlled sources.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id js/sql-injection-local
 * @tags security
 *       external/cwe/cwe-89
 */

import javascript
import semmle.javascript.security.dataflow.SqlInjectionCustomizations
import DataFlow::PathGraph

class SqlInjectionConfig extends DataFlow::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SqlInjection::Source
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlInjection::Sink
  }

  override predicate isSanitizer(DataFlow::Node sanitizer) {
    sanitizer instanceof SqlInjection::Sanitizer
  }
}

from SqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL query built from user-controlled source $@.", source.getNode(), "user input"
