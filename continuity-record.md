# Continuity Record

## Reuse from prior work  
This is first project, no earlier work exists to carry forward. This record instead defines the foundation being passed to the next project.

## Interface to be reused
- `engine.scope.Scope` – fail‑closed scope validation against the generated `scope.csv`.
- `engine.core.acquire_request()` – central rate‑limited, budget‑aware request counter, used by every probing function. 
- `engine.core.load_checkpoint()` / `save_checkpoint()` – JSON‑based resumable state tracking.
- `engine.parsers.parse()` – unified normalisation for `nmap_xml`, `naabu_json`, `httpx_json`, and `line` output.
- `engine.core.detect_wildcard_http()` – wildcard classification for HTTP endpoints.
- `engine.core.probe_http()`, `probe_line()`, `send_line_command()` - standard‑library network primitives.

## Evidence lineage  
Every discovery and foothold action passes through `Scope.is_allowed()` before touching the network. That guarantee is built into the request path, so future extensions automatically inherit scope enforcement and request logging (`run.json` + `errors.jsonl`) without having to rewrite the guard.

## Adaptation notes  
- Request ledger summary is emitted as `run.json` (full metadata) and `errors.jsonl` (failure entries). Later stages can consume these JSON files or adapt them to their own ledger format. 
- Checkpoint state lives in `checkpoint.json`; its simple structure can be extended with extra fields if needed.

## Handoff to Project 2  
The scope‑safe discovery layer (`Scope` + `acquire_request()`) is intended to become the shared backbone for further pentest activites.
