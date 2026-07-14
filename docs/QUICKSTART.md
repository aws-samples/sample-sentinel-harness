# Quickstart — get running in 5 minutes

**`sentinel-harness` is a reference SecOps agent platform where security agents are _configuration_, not orchestration code, running on [Amazon Bedrock AgentCore Harness](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness.html).** You declare an agent (model · prompt · tools · skills · memory · limits) and AWS runs the loop. The platform maps a common three-layer SecOps architecture onto AgentCore primitives — **L1** Strategy iteration (triage, detection-gen, multi-harness supervisor, HITL), **L2** Attack validation & simulation (Play Mode, BAS detection-replay), **L3** Foundation & governance (registry, Agent Factory, identity, Guardrail, egress), **L4** Observability (CloudWatch dashboard + Budgets) — and its north star is *an agent that builds agents*: natural language flows in and the platform auto-builds → tests → evaluates → promotes agents, HITL-gated and observable throughout. Everything here is generic SecOps content, mock data, built and tested against a **non-production** account.

---

## 60-second offline path (no AWS, no credentials)

```bash
git clone https://github.com/aws-samples/sample-sentinel-harness && cd sample-sentinel-harness
pip install -e .        # Python 3.10+ ; installs the `sentinel` CLI

make test               # 1698 offline tests — deterministic, no AWS, seconds
make demo               # the platform_demo guided tour (L1 → L4), all offline
ls evidence/            # captured live-run results (account IDs scrubbed) — the proof
```

- **`make test`** runs the full offline suite (**1698 tests**). Every AWS seam is monkeypatched with in-memory fakes; there is no network, no credential, and no wall-clock sleep.
- **`make demo`** runs [`demo/platform_demo.py`](../demo/platform_demo.py) — a single narrated tour that walks every layer, prints `BEAT 1 … BEAT 7`, and ends with a `capability → status → evidence` table. It makes zero AWS calls: live beats replay committed `evidence/*.json`, and the two L2 cores execute as pure Python.
- **`evidence/`** holds the account-scrubbed JSON each live scenario dropped — the real proof behind the tour.

If you don't have `make`, the underlying commands are `pytest tests/ -q` and `python demo/platform_demo.py`.

---

## Makefile targets

| Target | What it does |
|---|---|
| `make test` | Run the full offline test suite (1698 tests) — no AWS, deterministic. |
| `make lint` | Run the linters (ruff) over the Python sources. |
| `make synth` | `cdk synth` the eight `iac-cdk/` stacks offline (no deploy). |
| `make deploy` | Deploy the free-tier L3 foundation via `deploy/deploy.sh` (confirms account+region first). |
| `make deploy-endpoints` | Same deploy **plus** the opt-in ~$30/mo VPC PrivateLink interface endpoints. |
| `make seed-registry` | Populate the tool/skill registry allowlist from `registry/tools.yaml`. |
| `make create-harnesses` | Create the declarative `harnesses/*/harness.yaml` agents via the loader/CLI. |
| `make smoke` | Run the offline smoke suite (`tests/smoke/`); opt-in live via `SENTINEL_SMOKE_LIVE=1`. |
| `make demo` | Run the offline `platform_demo` guided tour (L1 → L4). |
| `make reset` | Clean local build/cache artifacts and tear down repo-created harnesses. |
| `make destroy` | Tear down all `sentinel-*` CDK stacks via `deploy/destroy.sh` (confirms first). |

---

## Live path (needs a non-prod AWS account)

The one-command deploy really provisions the Layer-3 foundation via the existing [`deploy/deploy.sh`](../deploy/deploy.sh) (CDK). Account and region come from your **active AWS profile / CDK env** — nothing is hardcoded, and the script prints the exact account + region and requires a typed `yes` before it touches anything.

```bash
export AWS_PROFILE=<your-non-prod-profile>     # never production
export SENTINEL_REGION=us-east-1

make deploy        # free-tier stacks: guardrail · identity (Cognito) · observability · network
```

**What it costs.** The default free-tier set is **~$0/mo standing** (idle Guardrail ≈ pennies-per-request, Cognito $0, one CloudWatch dashboard ~$3/mo, VPC with no NAT/IGW $0). The only meaningful standing cost is opt-in:

```bash
make deploy-endpoints   # adds ~$30/mo VPC PrivateLink interface endpoints (cost-gated off by default)
```

**How to verify.** Configure a harness execution role and run the live-validated scenarios, each of which writes account-scrubbed proof to `evidence/`:

```bash
export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::<acct>:role/<your-harness-role>"

python scenarios/scenario_cve_triage.py        # L1: CVE triage + mandatory HITL gate
python scenarios/scenario_multi_harness.py     # L1: multi-harness parallel + supervisor
python scenarios/scenario_hitl_resume.py       # L1: full pause → approve → resume
# ... see demo/PLATFORM.md for the full run-book

sentinel cleanup sentinel_                      # tear down every harness this repo created
```

The live Guardrail masking, Cognito JWT, observability, and egress topology are already captured in `evidence/m4_*.json` and `evidence/egress_control_result.json`.

**Tear it all down** when you are done:

```bash
make destroy        # removes all sentinel-* CDK stacks (leaves the CDKToolkit bootstrap stack)
```

---

## No lock-in

When configuration isn't enough, export a harness to editable [Strands](https://strandsagents.com/) agent code and migrate off the managed harness:

```bash
sentinel export harnesses/alert-triage/harness.yaml
```

The command reads a `harness.yaml` via the loader and emits an editable Python Strands Agent skeleton (model · system prompt · tools · memory) — a real, standalone text artifact. Strands does not need to be installed to run the export.

---

## Where to go next

- **[`docs/ROADMAP.md`](ROADMAP.md)** — the milestone plan and status (M0–M7 delivered; M4 free-tier stacks are live-deployable).
- **[`docs/FIDELITY-REPORT.md`](FIDELITY-REPORT.md)** — the honest self-audit of what is live-validated vs. built+tested vs. skeleton.
- **[`evidence/`](../evidence/)** — the captured proof: one account-scrubbed JSON per live scenario.
- **[`README.md`](../README.md)** — the full status matrix, architecture, and design principles.
