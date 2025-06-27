import yaml
import os

def load_config():
    """
    Loads the config.yaml file from the project's root directory.
    
    Returns:
        dict: A dictionary containing the configuration, or a default dict if not found.
    """
    config_path = 'config.yaml'
    
    # Define default configuration in case the file doesn't exist
    default_config = {
        'default_llm_provider': 'gemini',
        'exclusions': {
            'paths': ['.git', 'venv', 'repos', '__pycache__'],
            'files': []
        }
    }
    
    if not os.path.exists(config_path):
        print("[!] Warning: config.yaml not found. Using default settings.")
        return default_config
        
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[!] Error loading config.yaml: {e}. Using default settings.")
        return default_config
