import logging
from rich.logging import RichHandler
from rich.console import Console

console = Console()

def setup_vanta_logger(name="VANTABLACK"):
    """
    CONFIGURES the centralized logger for the VANTABLACK project.
    ROLE: Unify the output of all modules for clean terminal reading.
    """
    logging.basicConfig(
        level="INFO",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console, show_path=False)]
    )
    return logging.getLogger(name)

vanta_logger = setup_vanta_logger()

def log_info(msg): vanta_logger.info(f"[cyan]{msg}[/]")
def log_warn(msg): vanta_logger.warning(f"[yellow]{msg}[/]")
def log_err(msg): vanta_logger.error(f"[bold red]{msg}[/]")
def log_success(msg): vanta_logger.info(f"[bold green]✓ {msg}[/]")
