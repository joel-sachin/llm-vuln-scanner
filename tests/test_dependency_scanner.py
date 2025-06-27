import pytest
import os
from scanner.dependency_scanner import parse_requirements

# The 'tmp_path' argument is a special feature from pytest.
# It provides a temporary directory unique to this test function.
def test_parse_requirements_valid_file(tmp_path):
    """
    Tests if the parse_requirements function correctly parses a valid requirements.txt file.
    """
    # 1. ARRANGE: Create a fake requirements.txt file in the temporary directory.
    content = "requests==2.25.0\n# This is a comment\nPyYAML==5.1\n\n"
    # The 'd' is a temporary directory provided by pytest's tmp_path
    p = tmp_path / "requirements.txt"
    p.write_text(content)

    # 2. ACT: Call the function we want to test.
    dependencies = parse_requirements(str(p))

    # 3. ASSERT: Check if the output is what we expect.
    assert len(dependencies) == 2
    assert ('requests', '2.25.0') in dependencies
    assert ('PyYAML', '5.1') in dependencies
    assert ('# This is a comment', '') not in dependencies # Make sure comments are ignored

def test_parse_requirements_no_file():
    """
    Tests that the function handles a non-existent file gracefully.
    """
    # ARRANGE: A path that we know doesn't exist.
    non_existent_file = "non_existent_requirements.txt"
    
    # ACT & ASSERT: Use pytest.raises to assert that a specific error occurs.
    # In this case, our function should raise a FileNotFoundError.
    with pytest.raises(FileNotFoundError):
        parse_requirements(non_existent_file)