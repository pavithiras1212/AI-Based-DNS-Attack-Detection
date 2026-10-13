
"""Central configuration and project paths."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"

CAPTURES_DIR = PROJECT_ROOT / "captures"
RESEARCH_DIR = PROJECT_ROOT / "research"
MODELS_DIR = PROJECT_ROOT / "models"

RESULTS_DIR = PROJECT_ROOT / "results"
FIGURES_DIR = RESULTS_DIR / "figures"
REPORTS_DIR = RESULTS_DIR / "reports"

ATTACK_CATEGORIES = [
    "DNS Tunneling",
    "DNS Amplification",
    "DNS Cache Poisoning",
]


def create_project_directories() -> None:
    """Create the directories required by the project."""
    directories = [
        RAW_DATA_DIR,
        PROCESSED_DATA_DIR,
        CAPTURES_DIR,
        RESEARCH_DIR,
        MODELS_DIR,
        FIGURES_DIR,
        REPORTS_DIR,
    ]

    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
