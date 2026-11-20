package migrationlint

import "testing"

func TestMigrationLinter(t *testing.T) {
	const timers = "SET lock_timeout='2s'; SET statement_timeout='30s';"
	const add = "ALTER TABLE accounts ADD CONSTRAINT accounts_email_nn CHECK (email IS NOT NULL) NOT VALID;"
	const validate = "ALTER TABLE accounts VALIDATE CONSTRAINT accounts_email_nn;"
	const promote = "ALTER TABLE accounts ALTER COLUMN email SET NOT NULL;"
	for _, tc := range []struct {
		name  string
		sql   []string
		valid bool
	}{
		{"blocking index", []string{timers + "CREATE INDEX email_idx ON accounts(email);"}, false},
		{"inline not null", []string{timers + "ALTER TABLE accounts ADD COLUMN new_email text NOT NULL;"}, false},
		{"unproven not null", []string{timers + promote}, false},
		{"unvalidated check", []string{timers + add + promote}, false},
		{"check got dropped", []string{timers + add + validate + "ALTER TABLE accounts DROP CONSTRAINT accounts_email_nn;" + promote}, false},
		{"timeouts in comment", []string{"-- " + timers + "\nCREATE INDEX CONCURRENTLY i ON accounts(email);"}, false},
		{"timeout disabled", []string{timers + "SET lock_timeout='0s'; CREATE TABLE test (i int);"}, false},
		{"sub-millisecond timeout", []string{timers + "SET lock_timeout='1us'; CREATE TABLE test (i int);"}, false},
		{"safe", []string{timers + add, timers + validate, timers + promote + "CREATE INDEX CONCURRENTLY email_idx ON accounts(email);"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Check(tc.sql...); (err == nil) != tc.valid {
				t.Fatalf("valid = %v, got %v", tc.valid, err)
			}
		})
	}
}
