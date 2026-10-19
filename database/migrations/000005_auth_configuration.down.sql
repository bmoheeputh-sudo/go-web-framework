-- Intentionally non-destructive: retain all authentication configuration history,
-- encrypted credentials, constraints and triggers. Do not raise an exception:
-- golang-migrate marks the target dirty before executing this SQL.
-- A single down step records clean version 4 but leaves the version-5 schema
-- installed. This is NOT a schema reversal or a barrier to older down migrations.
-- Do not continue down or blindly reapply 000005; see README recovery guidance.
-- Production rollback uses a compatible application version or a forward fix.
SELECT 1;
