# Malicious Domain Monitoring

## Summary

<!-- Brief description of what this project does, how it works, and any important context. -->

## Roadmap

### Efficiency & Organization

- [x] **Consolidate duplicate scripts** — merged into `get_domains.py`, processes all feeds from `config.json`
- [x] **Remove manual pb flow** — deleted `manual_pb.csv` and `pb_manual_csv.py`
- [x] **Extract hardcoded config** — all config now lives in `config.json`
- [x] **Add a README** — documents setup, usage, how to add feeds, and output files

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
