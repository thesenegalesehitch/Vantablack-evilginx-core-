.PHONY: help install run-api run-workers run-all stop-workers

# Colors for output
GREEN=\033[0;32m
YELLOW=\033[0;33m
NC=\033[0m # No Color

help:
	@echo "${YELLOW}Available commands:${NC}"
	@echo "  ${GREEN}make install${NC}       - Install Python dependencies."
	@echo "  ${GREEN}make run-api${NC}         - Run the FastAPI API server."
	@echo "  ${GREEN}make run-workers${NC}    - Run all Celery workers (event, osint, reuse, objective, ghost)."
	@echo "  ${GREEN}make run-all${NC}         - Run the API and all workers in parallel."
	@echo "  ${GREEN}make stop-workers${NC}   - Stop all running Celery workers."

install:
	@echo "${YELLOW}--- Installing dependencies ---${NC}"
	@pip install -r requirements-v4.txt
	@echo "${GREEN}Installation complete.${NC}"

run-api:
	@echo "${YELLOW}--- Starting VANTABLACK API Server ---${NC}"
	@python api/rest_api.py

run-workers:
	@echo "${YELLOW}--- Starting Celery Workers ---${NC}"
	@celery -A workers.event_handlers worker --loglevel=info -n event_handler@%h &
	@celery -A workers.osint_worker worker --loglevel=info -n osint_worker@%h &
	@celery -A workers.credential_reuse_worker worker --loglevel=info -n reuse_worker@%h &
	@celery -A workers.objective_worker worker --loglevel=info -n objective_worker@%h &
	@celery -A workers.ghost_protocol_worker worker --loglevel=info -n ghost_worker@%h &
	@echo "${GREEN}All workers started in the background.${NC}"
	@wait

run-all:
	@echo "${YELLOW}--- Launching Full VANTABLACK Stack ---${NC}"
	@make run-api & make run-workers

stop-workers:
	@echo "${YELLOW}--- Stopping all Celery workers ---${NC}"
	@pkill -f "celery -A"
	@echo "${GREEN}Workers stopped.${NC}"
