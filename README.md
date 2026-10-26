# posture-check

Security posture checks that produce a report an engineer can actually act on.

Most scanners hand you a list. This hands you an ordered set of things to do,
with the reason and the fix attached, and collapses the same problem across
twenty hosts into one item of work — because "fix HSTS on 14 hosts" is one
ticket, not fourteen.

```
$ posture-check --targets targets.yaml --out report/

6 distinct issue(s) across 1 target(s). 3 need attention before the next
review; start with "Second account with UID 0: backdoor" (single host).

6 finding(s) in 6 work item(s) -> report/
```

## Why I built it

At a previous job I ran a check-and-report cycle by hand every fortnight. It
took one to three hours, it produced a document nobody could act on without a
conversation, and when the fortnight was busy it got skipped — which is the
worst property a security check can have.

This is the generalised, public version of the idea: the checks are automated,
the output is written for the person who has to fix things, and it runs in CI
on a schedule so it does not depend on anybody remembering.

## What it checks

| Check | What it looks at | Needs |
| --- | --- | --- |
| `http-headers` | HSTS, CSP, nosniff, frame protection, referrer policy, version disclosure | a URL |
| `open-ports` | TCP connect scan against a policy of ports that should not be exposed | a host |
| `host-hygiene` | accounts and shells, duplicate UID 0, passwordless sudo, pending security updates, world-writable files, readable secrets | a facts file |

An open port is only a finding if policy says it should not be open. Port 443
is reported as information; port 445 is reported as critical with the reason
attached. Ports with no policy entry are reported as information rather than
guessed at.

## Install

```bash
git clone https://github.com/akshayunagar/posture-check
cd posture-check
pip install -e ".[dev]"
```

No runtime dependencies. A security tool that needs a parser library is a
security tool with a supply chain, so the YAML reader and the HTTP client are
both standard library.

## Use

```bash
cp targets.example.yaml targets.yaml   # then edit
posture-check --targets targets.yaml --out report/
```

Writes `report/report.md` for people and `report/report.json` for whatever
consumes it next.

### Host hygiene

The host checks do not log into anything. A small shell collector runs on the
host and writes a JSON facts file; the Python analyses it:

```bash
# on the host
sudo ./collect/host_facts.sh > facts/web01.json
```

```yaml
# targets.yaml
- host: web01
  facts_file: facts/web01.json
```

The thing that needs privileges is ~60 lines of auditable shell that only
reads and only writes to stdout. The thing with the judgement in it is Python
you can unit-test without a server.

### As a CI gate

```bash
posture-check --targets targets.yaml --fail-on high
```

Exit `0` if nothing is at or above the threshold, `1` if something is, `2` if
the run itself failed. The included GitHub Actions workflow runs the suite on
push and on a weekly schedule.

## The AI triage step

Grouping findings is deterministic. Writing the covering summary optionally
uses a language model:

```bash
export ANTHROPIC_API_KEY=...
posture-check --targets targets.yaml          # LLM summary
posture-check --targets targets.yaml --no-ai  # deterministic summary
```

With no key, on a timeout, on an HTTP error, or on malformed output, it falls
back to deterministic text and the report is still produced. That is
deliberate: a security report that silently depends on a third-party API being
up is not a security report. The model writes prose — it never decides a
severity, and it never invents a finding.

## Design notes

**Collection is separated from judgement.** Every check splits into a
`run()` that does I/O and an `evaluate()` that is a pure function. All 35 tests
exercise `evaluate()`, so the logic is tested without network or fixtures.

**Policy is data, not code.** The header rules and port rules are tables with
a severity, a reason and a fix on each row. Someone who does not read Python
can review which rules apply — usually the same person who has to sign off on
the exceptions.

**Adding a check changes nothing else.** A check is anything satisfying the
`Check` protocol: a name, `applies_to`, and `run`. The reporter and the triage
step only ever see `Finding` objects.

**A check that cannot run says so.** An unresolvable host is reported under
"checks that could not run", not as a host with nothing open. Silent failure
is the failure mode that matters in this kind of tool.

## Development

```bash
pytest          # 35 tests, no network
ruff check .
mypy
shellcheck collect/host_facts.sh
```

## Licence

MIT
