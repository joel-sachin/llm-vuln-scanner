import pytest
from typer.testing import CliRunner
from main import app # Import the Typer app from our main script
import git

# The CliRunner is a special tool from Typer that lets us
# run command-line commands programmatically for our tests.
runner = CliRunner()

def test_cli_help_command():
    """Tests if the --help command runs without errors."""
    # ARRANGE & ACT: Invoke the '--help' command on our app.
    result = runner.invoke(app, ["scan", "--help"])
    
    # ASSERT: Check that the command exited successfully (exit_code == 0)
    # and that the key part of the usage text is in the output.
    assert result.exit_code == 0
    # THIS IS THE FIX: We remove 'main' from the expected string.
    assert "Usage: scan [OPTIONS] PATH" in result.stdout

# The 'mocker' and 'tmp_path' arguments are special fixtures from our test libraries.
def test_cli_no_deps_option(mocker, tmp_path):
    """
    Tests if the --no-deps flag correctly skips the dependency scan.
    """
    # 1. ARRANGE:
    # We create a fake path. It doesn't need to exist because we will mock the check.
    test_repo_path = "/fake/repo"
    
    # THIS IS THE FIX: We now mock the directory check to always return True.
    # This isolates our test to only focus on the CLI logic, not filesystem checks.
    mocker.patch("main.os.path.isdir", return_value=True)

    # We still mock the real scanner functions.
    mock_dep_scan = mocker.patch("scanner.dependency_scanner.scan", return_value=[])
    mock_code_scan = mocker.patch("scanner.code_scanner.scan", return_value=[])
    
    # 2. ACT: Run the 'scan' command with our path and the --no-deps flag.
    result = runner.invoke(app, ["scan", str(test_repo_path), "--no-deps"])
    
    # 3. ASSERT: Check that the program ran successfully.
    assert result.exit_code == 0, f"CLI command failed with output: {result.stdout}"
    
    # Assert that the dependency scanner was NEVER called.
    mock_dep_scan.assert_not_called()
    
    # Assert that the code scanner WAS called exactly once.
    mock_code_scan.assert_called_once()