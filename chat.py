import json
import nmap
import socket
import whois
import nvdlib
from transformers import AutoModelForCausalLM, AutoTokenizer
from colorama import Fore, Style, init

# Colorama
init(autoreset=True)

# Tools
def cve_check(cveID: str):
    """
    Returns description and severity of a given CVE.

    Args:
        cveID: The CVE ID (e.g., 'CVE-2021-26855').
    Returns:
        Severity, Severity Score, CVE Description.
    """
    cve = nvdlib.searchCVE(cveId=cveID)[0]
    return ('Severity = ' + cve.v31severity + '\nSeverity Score = ' + str(cve.v31score) + '\nCVE Description = ' + cve.descriptions[0].value)

def scan_target(target: str, scan_type: str = 'basic'):
    """
    Performs a scan on a given target.

    Args:
        target: The target IP or domain (127.0.0.1).
        scan_type: The type of scan to perform ('basic', 'aggressive').
    Returns:
        Dictionary with scan results.
    """
    result = {}
    try:
        # Nmap Scan
        nm = nmap.PortScanner()
        if scan_type == 'basic':
            nm.scan(target, arguments='-sS')
        elif scan_type == 'aggressive':
            nm.scan(target, arguments='-A')
        
        result['nmap'] = nm[target] if target in nm.all_hosts() else 'No information found'

        # Whois lookup
        try:
            domain_info = whois.whois(target)
            result['whois'] = domain_info
        except Exception as e:
            result['whois'] = f"WHOIS lookup failed: {e}"

        # Basic socket check
        ports = [80, 443]
        open_ports = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                if not sock.connect_ex((target, port)):
                    open_ports.append(port)
        result['open_ports'] = open_ports

    except Exception as e:
        result['error'] = str(e)

    return result

# Mappa dei tool disponibili
tools = [cve_check, scan_target]

# Inizializzazione del modello
model_name = "Qwen/Qwen2.5-1.5B-Instruct"
print(f"{Fore.LIGHTBLACK_EX}Loading model...{Style.RESET_ALL}")
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name, device_map="cpu")
print(f"{Fore.LIGHTBLACK_EX}Model uploaded successfully.{Style.RESET_ALL}")

# Inizializzazione della chat
chat_history = [
    {"role": "system", "content": "You are a useful chatbot expert in the matter of cybersecurity."}
]

def model_response():
    # Preparazione degli input per il modello
    inputs = tokenizer.apply_chat_template(
        chat_history, 
        tokenize=True, 
        add_generation_prompt=True,
        tools=tools,
        return_tensors="pt",
        return_dict=True,
    ).to("cpu")
    inputs = {k: v.to(model.device) for k, v in inputs.items()}
    
    # Generazione della risposta
    out = model.generate(**inputs, max_new_tokens=128)
    response = tokenizer.decode(out[0][len(inputs["input_ids"][0]):]).strip()
    
    return response

def chat_loop():
    global chat_history 
    while True:
        # Input dell'utente
        user_input = input(f"{Fore.GREEN}User: {Style.RESET_ALL}")
        if user_input.lower() in ["esci", "exit", "quit"]:
            print(f"{Fore.LIGHTBLACK_EX}Exit...{Style.RESET_ALL}")
            break

        # Aggiunta del messaggio dell'utente alla cronologia
        chat_history.append({"role": "user", "content": user_input})
        
        # Preparazione degli input per il modelloFunzione esempio del tool "Tell_Time"
        response = model_response()
        
        # Verifica se è richiesta una chiamata a un tool
        if "<tool_call>" in response:
            # Estrarre il nome del tool dalla risposta
            print(response)
            tool_call_start = response.find("<tool_call>") + len("<tool_call>")
            tool_call_end = response.find("</tool_call>")
            tool_call_content = response[tool_call_start:tool_call_end].strip()
            
            try:
                tool_call = json.loads(tool_call_content) 
                tool_name = tool_call.get("name")
                tool_args = tool_call.get("arguments", {})

                func = globals()[tool_name]

                if func in tools:
                    # Esecuzione del tool
                    tool_result = func(**tool_args)
                    # Aggiunta della chiamata al tool e del risultato alla cronologia
                    chat_history.append({"role": "assistant", "tool_calls": [{"type": "function", "function": tool_call}]})
                    chat_history.append({"role": "tool", "name": tool_name, "content": tool_result})
                    
                    # Rigenerazione della risposta del modello con la cronologia aggiornata
                    response = model_response()
                    print(tool_result)
                else:
                    response = f"I'm sorry the tool '{tool_name}' is not available."
            except Exception as e:
                response = f"Error when parsing the tool call: {e}"
        
        # Stampare la risposta senza tag inutili
        clean_response = response.replace("<|im_end|>", "").strip()
        print(f"{Fore.YELLOW}PTAssistant: {Style.RESET_ALL}{clean_response}")

if __name__ == "__main__":
    chat_loop()