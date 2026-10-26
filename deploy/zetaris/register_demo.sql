-- Run in the authenticated Zetaris SQL Editor after copying the public CSV.
-- Inspect existing objects first; execute CREATE only for missing objects.
-- Do not drop or replace an existing database/table.
CREATE LIGHTNING DATABASE security DESCRIBE BY "SafeGuard demonstration evidence with source provenance";
CREATE LIGHTNING FILESTORE TABLE domain_evidence FROM security FORMAT CSV OPTIONS (PATH "/home/zetaris/customer-data/shared/safeguard/domain_evidence.csv", header "true", inferSchema "false");
DESCRIBE security.domain_evidence;
SELECT * FROM security.domain_evidence WHERE domain = 'example.com';
