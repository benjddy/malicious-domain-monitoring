# Malicious Domain Monitoring

## Summary

<!-- Brief description of what this project does, how it works, and any important context. -->

## Roadmap

### Efficiency & Organization

- [ ] **Consolidate duplicate scripts** — merge `get_key_phishing_domains.py` and
  `get_pb_domains.py` into a single configurable script that accepts a feed as input
- [ ] **Remove manual pb flow** — delete `manual_pb.csv` and `pb_manual_csv.py`
- [ ] **Extract hardcoded config** — move URLScan query UUIDs, file paths, and the
  GitHub URL out of the scripts and into a shared config file or `.env`
- [ ] **Add a README** — document how to run the scripts, required env vars
  (`URLSCAN_API_KEY`), and what each component does

### Detection

- [ ] **Expand threat intelligence sources** — evaluate additional feeds beyond the
  current two URLScan saved searches (e.g. other URLScan queries, PhishTank, OpenPhish,
  community blocklists)
- [ ] **Audit and expand `skip_apex_domains.txt`** — review filtered apex domains
  periodically to catch false negatives; document criteria for inclusion

## Bug Tracking

<!-- Known bugs and issues. -->

## Notes

<!-- Miscellaneous context, decisions, and things to revisit. -->
