import os
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.exceptions import OutputParserException

def get_llm_chain(llm_provider="gemini"):
    """
    Initializes and returns the LangChain chain, supporting different providers.
    """
    if llm_provider == "gemini":
        llm = ChatGoogleGenerativeAI(
            model="gemini-1.5-flash-latest",
            temperature=0.0,
            model_kwargs={"response_mime_type": "application/json"}
        )
    elif llm_provider == "openai":
        llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0.0)
    else:
        raise ValueError(f"Unsupported LLM provider: {llm_provider}. Please choose 'gemini' or 'openai'.")

    parser = JsonOutputParser()

    # The prompt template is updated with a stricter final instruction.
    prompt_template = 'You are an expert cybersecurity analyst specializing in static code analysis for Python. Your task is to identify potential security vulnerabilities in the provided code snippet. Analyze the following Python code file named `{file_name}`: ```python\n{code_content}\n``` Please adhere to the following instructions: 1. For each vulnerability you identify, provide a clear description, the line number where it occurs, the relevant code snippet, and a suggested mitigation. 2. Classify each vulnerability with its corresponding CWE (Common Weakness Enumeration) ID. 3. Provide a severity rating (Critical, High, Medium, Low). Format your response as a JSON object with a single key "vulnerabilities", which is a list of vulnerability objects. Each object must have the following keys: "file_name", "line_number", "cwe_id", "severity", "description", "vulnerable_code", "suggested_mitigation". If you find no vulnerabilities, return a JSON object with an empty list: {{\"vulnerabilities\": []}}. Your response MUST be only the JSON object, with no additional text, explanations, or conversational pleasantries before or after the JSON structure.'
    
    prompt = ChatPromptTemplate.from_template(prompt_template)
    chain = prompt | llm | parser
    return chain

def analyze_file(file_path, chain):
    """Analyzes a single source code file using the provided LLM chain."""
    file_name = os.path.basename(file_path)
    print(f"    -> Analyzing file with {chain.middle[0].__class__.__name__}: {file_name}...")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        if len(content) > 100000:
            print(f"    [!] Skipping {file_name} as it is too large.")
            return []

        # We pass the content with the key 'code_content' as defined in the prompt
        response = chain.invoke({"file_name": file_name, "code_content": content})
        return response.get("vulnerabilities", [])
            
    except OutputParserException as e:
        print(f"    [!] An unexpected error occurred while analyzing {file_name}: {e}")
        return []
    except Exception as e:
        print(f"    [!] An unexpected error occurred while analyzing {file_name}: {e}")
        return []

def scan(repo_path, llm_provider, config):
    """The main entry point for the source code scanner."""
    excluded_paths = config.get('exclusions', {}).get('paths', [])
    excluded_files = config.get('exclusions', {}).get('files', [])
    
    if llm_provider == "gemini" and not os.getenv("GOOGLE_API_KEY"):
        print("[!] Error: GOOGLE_API_KEY not found in .env file.")
        return []
    elif llm_provider == "openai" and not os.getenv("OPENAI_API_KEY"):
        print("[!] Error: OPENAI_API_KEY not found in .env file.")
        return []
        
    chain = get_llm_chain(llm_provider)
    
    all_vulnerabilities = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in excluded_paths]
        
        for file in files:
            if file in excluded_files:
                continue
            
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                vulnerabilities = analyze_file(file_path, chain)
                if vulnerabilities:
                    all_vulnerabilities.extend(vulnerabilities)

    return all_vulnerabilities