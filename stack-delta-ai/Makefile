.PHONY: setup test demo serve sandbox-image

setup:
	sh scripts/setup.sh

test:
	.venv/bin/python -m unittest discover -s tests -v

demo:
	.venv/bin/stack-delta demo --scenario suspicious

serve:
	.venv/bin/stack-delta serve

sandbox-image:
	.venv/bin/stack-delta build-sandbox

