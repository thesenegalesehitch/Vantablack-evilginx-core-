import asyncio
import logging
import os
from typing import Any, Dict, Tuple

logger = logging.getLogger("InfraManager")

TERRAFORM_DIR = "terraform/templates"

class InfrastructureManager:
    """Manages infrastructure using Terraform."""

    async def _run_terraform_command(self, cwd: str, command: str) -> tuple[bool, str]:
        """Runs a Terraform command in a specified directory."""
        process = await asyncio.create_subprocess_shell(
            f'terraform {command}',
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = stderr.decode().strip()
            logger.error(f"Terraform command '{command}' failed in {cwd}: {error_message}")
            return False, error_message
        
        output = stdout.decode().strip()
        logger.info(f"Terraform command '{command}' succeeded in {cwd}.")
        return True, output

    async def initialize_template(self, template_name: str) -> bool:
        """Initializes a Terraform template directory."""
        template_path = os.path.join(TERRAFORM_DIR, template_name)
        if not os.path.isdir(template_path):
            logger.error(f"Terraform template not found: {template_name}")
            return False
        
        success, _ = await self._run_terraform_command(template_path, "init -input=false")
        return success

    async def plan_deployment(self, template_name: str, vars: dict[str, Any]) -> tuple[bool, str]:
        """Creates an execution plan for a Terraform deployment."""
        template_path = os.path.join(TERRAFORM_DIR, template_name)
        var_args = " ".join([f'-var="{k}={v}"' for k, v in vars.items()])
        
        command = f'plan -input=false -out=tfplan {var_args}'
        return await self._run_terraform_command(template_path, command)

    async def apply_deployment(self, template_name: str) -> tuple[bool, str]:
        """Applies a Terraform deployment plan."""
        template_path = os.path.join(TERRAFORM_DIR, template_name)
        command = 'apply -input=false -auto-approve tfplan'
        return await self._run_terraform_command(template_path, command)

    async def destroy_deployment(self, template_name: str, vars: dict[str, Any]) -> tuple[bool, str]:
        """Destroys a Terraform-managed infrastructure."""
        template_path = os.path.join(TERRAFORM_DIR, template_name)
        var_args = " ".join([f'-var="{k}={v}"' for k, v in vars.items()])
        
        command = f'destroy -input=false -auto-approve {var_args}'
        return await self._run_terraform_command(template_path, command)
