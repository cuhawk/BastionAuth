package migrationlint

import (
	"fmt"
	"regexp"
	"strings"

	pg "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var positiveTimeout = regexp.MustCompile(`^\s*0*[1-9][0-9]*\s*(ms|s|min|h|d)?\s*$`)

type checkKey struct{ schema, table, name string }
type check struct {
	column    string
	validated bool
}

// Check lints migrations in application order. Each statement must run in autocommit.
func Check(files ...string) error {
	checks := make(map[checkKey]check)
	for file, sql := range files {
		tree, err := pg.Parse(sql)
		if err != nil {
			return fmt.Errorf("migration %d: %w", file+1, err)
		}
		timeouts := map[string]bool{}
		for _, raw := range tree.Stmts {
			fail := func(reason string) error {
				line := 1 + strings.Count(sql[:int(raw.StmtLocation)], "\n")
				return fmt.Errorf("migration %d near line %d: %s", file+1, line, reason)
			}
			n := raw.Stmt
			if set := n.GetVariableSetStmt(); set != nil {
				if set.Name == "lock_timeout" || set.Name == "statement_timeout" {
					timeouts[set.Name] = false
					if set.Kind == pg.VariableSetKind_VAR_SET_VALUE && len(set.Args) == 1 && !set.IsLocal {
						arg := set.Args[0].GetAConst()
						if arg != nil {
							timeouts[set.Name] = arg.GetIval().GetIval() > 0 || positiveTimeout.MatchString(arg.GetSval().GetSval())
						}
					}
				} else if set.Name == "" || set.Name == "search_path" {
					clear(timeouts)
					clear(checks)
				}
				continue
			}
			if n.GetTransactionStmt() != nil || n.GetDoStmt() != nil || n.GetCallStmt() != nil || n.GetExecuteStmt() != nil {
				return fail("transaction blocks and dynamic statements are unsupported")
			}
			if !timeouts["lock_timeout"] || !timeouts["statement_timeout"] {
				return fail("set positive lock_timeout and statement_timeout before migration statements")
			}
			if reason := unsafeNode(n.ProtoReflect()); reason != "" {
				return fail(reason)
			}
			alter := n.GetAlterTableStmt()
			if alter == nil {
				if n.GetRenameStmt() != nil || n.GetDropStmt() != nil || n.GetAlterObjectSchemaStmt() != nil {
					clear(checks)
				}
				continue
			}
			for _, part := range alter.Cmds {
				cmd := part.GetAlterTableCmd()
				if cmd == nil {
					continue
				}
				rel := alter.Relation
				key := checkKey{rel.Schemaname, rel.Relname, cmd.Name}
				switch cmd.Subtype {
				case pg.AlterTableType_AT_AddConstraint:
					c := cmd.Def.GetConstraint()
					if c == nil {
						continue
					}
					key.name = c.Conname
					delete(checks, key)
					if c.Contype != pg.ConstrType_CONSTR_CHECK || !c.SkipValidation || c.IsNoInherit {
						continue
					}
					test := c.RawExpr.GetNullTest()
					if test == nil || test.Nulltesttype != pg.NullTestType_IS_NOT_NULL {
						continue
					}
					col := test.Arg.GetColumnRef()
					if col != nil && len(col.Fields) == 1 && col.Fields[0].GetString_() != nil {
						checks[key] = check{column: col.Fields[0].GetString_().Sval}
					}
				case pg.AlterTableType_AT_ValidateConstraint:
					if c, ok := checks[key]; ok && len(alter.Cmds) == 1 {
						c.validated = true
						checks[key] = c
					}
				case pg.AlterTableType_AT_DropConstraint:
					delete(checks, key)
				case pg.AlterTableType_AT_SetNotNull:
					proven := false
					for k, c := range checks {
						if k.schema == key.schema && k.table == key.table && c.column == cmd.Name && c.validated {
							proven = true
							break
						}
					}
					if !proven || len(alter.Cmds) != 1 {
						return fail("SET NOT NULL requires a prior NOT VALID check and a separate VALIDATE CONSTRAINT")
					}
				default:
					// An unrelated table change could invalidate the recorded proof.
					for k := range checks {
						if k.schema == key.schema && k.table == key.table {
							delete(checks, k)
						}
					}
				}
			}
		}
	}
	return nil
}

func unsafeNode(msg protoreflect.Message) string {
	switch n := msg.Interface().(type) {
	case *pg.IndexStmt:
		if !n.Concurrent {
			return "use CREATE INDEX CONCURRENTLY"
		}
	case *pg.Constraint:
		if n.Contype == pg.ConstrType_CONSTR_NOTNULL {
			return "use a NOT VALID check, VALIDATE CONSTRAINT, then SET NOT NULL"
		}
	}
	var reason string
	msg.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Kind() != protoreflect.MessageKind {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len() && reason == ""; i++ {
				reason = unsafeNode(list.Get(i).Message())
			}
		} else {
			reason = unsafeNode(value.Message())
		}
		return reason == ""
	})
	return reason
}
