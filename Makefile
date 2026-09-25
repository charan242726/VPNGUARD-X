.PHONY: install install-all test verify smoke release api dashboard range-compile plan-pilot range-pilot evaluation-dry-run

install:
	python -m pip install -e .

install-all:
	python -m pip install -e '.[all]'

test:
	python -m unittest discover -s tests -v

verify:
	python -m compileall -q .
	python scripts/validate_repository.py
	python -m unittest discover -s tests -v

smoke:
	python scripts/smoke_demo.py

release:
	python scripts/build_release.py --output ../VPNGUARD-X_0.1.0.zip

api:
	uvicorn api.main:app --host 127.0.0.1 --port 8000

dashboard:
	streamlit run dashboard/app.py

range-compile:
	python cyber_range/range.py compile --scenario VGX-I2-V4-TUN-GCM19-NATIVE-WEB --seed 11 --output artifacts/range

plan-pilot:
	python experiments/plan_benchmark.py --profile pilot --stack strongSwan-6.1.0 --output artifacts/plans/strongswan-pilot.csv

range-pilot: plan-pilot
	python cyber_range/batch.py artifacts/plans/strongswan-pilot.csv --output artifacts/range --mode run --fail-fast

evaluation-dry-run:
	python experiments/run_evaluation.py data/generated/vpnguard_x_combined.jsonl artifacts/splits --output artifacts/results-dry-run --dry-run
