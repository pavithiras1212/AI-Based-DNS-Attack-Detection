from src.config import ATTACK_CATEGORIES, PROJECT_ROOT
from src.feature_extraction import (
    domain_length,
    shannon_entropy,
    subdomain_count,
)


def test_main_file_exists():
    assert (PROJECT_ROOT / "main.py").is_file()


def test_readme_exists():
    assert (PROJECT_ROOT / "README.md").is_file()


def test_requirements_exist():
    assert (PROJECT_ROOT / "requirements.txt").is_file()


def test_three_attack_categories_exist():
    assert len(ATTACK_CATEGORIES) == 3


def test_domain_length():
    assert domain_length("www.example.com") == 15


def test_subdomain_count():
    assert subdomain_count("mail.shop.example.com") == 2


def test_empty_string_entropy():
    assert shannon_entropy("") == 0.0