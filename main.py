
"""Main entry point for the DNS Attack Detection project."""

import logging

from src.config import (
    ATTACK_CATEGORIES,
    PROJECT_ROOT,
    create_project_directories,
)


def main() -> None:
    """Display project information and verify the folder structure."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    print("\n" + "=" * 55)
    print(" AI-BASED DNS ATTACK DETECTION SYSTEM")
    print("=" * 55)

    print(f"\nProject root: {PROJECT_ROOT}")

    print("\nAttack categories under study:")
    for number, category in enumerate(ATTACK_CATEGORIES, start=1):
        print(f"  {number}. {category}")

    # Create required project directories automatically.
    create_project_directories()
    logging.info("Project directory structure is ready.")

    print("\nCurrent stage: Research and initial implementation")
    print("Basic configuration and feature utilities are available.")
    print("No attack detection has been implemented yet.")
    print("\nNext step: Research and dataset selection.")


if __name__ == "__main__":
    main()
