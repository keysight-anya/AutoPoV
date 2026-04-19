/**
 * @name SQL Injection (CWE-89)
 * @description Building a SQL query from user-controlled sources.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id cs/sql-injection-local
 * @tags security
 *       external/cwe/cwe-89
 */

import csharp
import semmle.code.csharp.security.dataflow.SqlInjectionQuery
import DataFlow::PathGraph

from SqlInjectionTaintTrackingConfiguration cfg,
     DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL query built from user-controlled source $@.", source.getNode(), "user input"
