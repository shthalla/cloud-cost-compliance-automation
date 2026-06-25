# Contributing

Thanks for considering a contribution! This project aims to stay simple,
well-tested, and easy to deploy, so contributions that add scanners,
Config rules, or deployment options in the existing patterns are very
welcome.

## Development setup

```bash
git clone https://github.com/<your-username>/cloud-cost-compliance-automation.git
cd cloud-cost-compliance-automation
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running tests

The entire test suite runs against [moto](https://github.com/getmoto/moto)
(mocked AWS), so it needs **zero real AWS credentials** and costs **zero
dollars** to run:

```bash
pytest
pytest --cov=cloud_compliance_scanner --cov-report=term-missing   # with coverage
```

## Linting & formatting

```bash
black src/ tests/
ruff check src/ tests/
```

CI runs both checks and will fail the build if code isn't formatted/linted
cleanly -- run these locally before pushing.

## Adding a new scanner

1. Create `src/cloud_compliance_scanner/scanners/<your_scanner>.py` and
   subclass `BaseScanner` (see `scanners/unused_eip.py` for the smallest
   worked example).
2. Implement `scan(self, region: str) -> List[Finding]`. Never raise on a
   single resource's failure -- log and continue (the orchestrator already
   isolates whole-scanner failures, but be defensive within your scanner
   too).
3. Add a `ResourceType` enum value in `models.py` if your scanner covers a
   new resource type.
4. Register your scanner in `DEFAULT_SCANNERS` in `orchestrator.py`.
5. Add unit tests in `tests/unit/test_<your_scanner>.py`. Prefer moto for
   anything CloudWatch/EC2/ELBv2-shaped; for resource types with awkward
   moto coverage (see `tests/unit/test_stale_snapshots.py` for why), a
   lightweight stub session/client is also fine and often simpler.
6. Update the README's scanner table and the architecture diagram if it
   materially changes what the project does.

## Adding a new AWS Config rule

1. Create `src/cloud_compliance_scanner/config_rules/<your_rule>.py` with a
   `handler(event, context)` function following the existing pattern --
   use `extract_configuration_item()` and `put_evaluation()` from
   `config_evaluator.py`.
2. Add unit tests in `tests/unit/test_config_rules.py` following the
   existing stubbed-event pattern (no moto needed; AWS Config's custom
   rule Lambda contract is simple enough to construct event payloads by
   hand).
3. Wire it up in **both** `infrastructure/terraform/lambda_config_rules.tf`
   + `config_rules.tf` AND `infrastructure/cloudformation/template.yaml` --
   keeping both deployment paths in sync is important since the README
   presents them as equivalent options.

## Pull request checklist

- [ ] `pytest` passes
- [ ] `black --check src/ tests/` passes
- [ ] `ruff check src/ tests/` passes
- [ ] New scanners/rules have unit tests
- [ ] Both Terraform and CloudFormation are updated if you changed
      infrastructure
- [ ] README updated if behavior or setup steps changed

## Reporting bugs / requesting features

Open a GitHub issue with as much detail as you can: AWS region(s)
involved, relevant environment variables (redact account IDs / ARNs if
you're not comfortable sharing them), and the relevant section of
CloudWatch Logs output if you have it (this project logs structured JSON,
which usually makes root-causing fast).
