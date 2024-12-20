import json
import time
import os
import re
import socket
import nvdlib
import nmap
import whois
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.history import FileHistory
from prompt_toolkit.application import run_in_terminal
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from rich.console import Console
from rich.errors import LiveError
from rich.live import Live
from rich.markdown import Markdown
from rich.spinner import Spinner
from threading import Thread
from transformers import AutoTokenizer, AutoModelForCausalLM, TextIteratorStreamer

def exit_gracefully(second_time: bool = False):
    with consolex.status("[bold red]Exiting", spinner="dots") as status:
        try:
            if not second_time:
                time.sleep(1)
        except (LiveError, KeyboardInterrupt, EOFError):
            exit_gracefully(True)
    try:
        exit()
    except SystemExit:
        os._exit(0)

try:
    consolex = Console()
    with consolex.status("[bold green]Booting[/bold green]", spinner="dots") as status:
        model_name = "Qwen/Qwen2.5-1.5B-Instruct"
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForCausalLM.from_pretrained(model_name, device_map="cpu")
        chat_history = [
        {"role": "system", "content": "You are a useful chatbot expert in the matter of cybersecurity, dont tell the user to update or secure their systems."},
        ]
except (LiveError, ValueError, KeyboardInterrupt, EOFError):
    exit_gracefully()

def get_attribute(cve, v31_attr, v2_attr):
            return getattr(cve, v31_attr, getattr(cve, v2_attr, "N/A"))

# TOOLS 
def cve_more_info(cve_ID: str, second_attempt: bool=False):
    """
    Returns info and data about a given CVE. All scores are out of 10.

    Args:
        cve_ID: The CVE ID.
        second_attempt: Always False, used to prevent infinite recursion.
    Returns:
        Dictionary with CVE data, all scores returned are out of 10.
    """
    try:
        cve_ID = cve_ID.strip()
        
        # Regular expression to match valid CVE ID format
        valid_cve_regex = r"^CVE-\d{4}-\d{4,}$"
        
        # Check if the input is already valid
        if not re.match(valid_cve_regex, cve_ID):
        # Try to fix the format if possible
        # Extract numbers using regex
            match = re.findall(r"\d+", cve_ID)
            if len(match) >= 2:
                year = match[0]  # First number is the year
                id_part = match[1]  # Second number is the CVE ID part
                cve_ID = f"CVE-{year}-{id_part.zfill(4)}"  # Ensure at least 4 digits for the ID part

        cve = nvdlib.searchCVE(cveId=cve_ID)[0]
        result = {
            "CVE ID": cve.id,
            "Severity": f"{get_attribute(cve, 'v31score', 'v2score')} {get_attribute(cve, 'v31severity', 'v2severity')}",
            "Description": getattr(cve.descriptions[0], "value", "N/A"),
            "Exploitability Score": get_attribute(cve, "v31exploitability", "v2exploitability"),
            "Impact Score": get_attribute(cve, "v31impactScore", "v2impactScore"),
            "Attack Vector": get_attribute(cve, "v31attackVector", "v2attackVector"),
            "Attack Complexity": get_attribute(cve, "v31attackComplexity", "v2attackComplexity"),
            "Privileges Required": get_attribute(cve, "v31privilegesRequired", "v2privilegesRequired"),
            "User Interaction": get_attribute(cve, "v31userInteraction", "v2userInteraction"),
            "Scope": get_attribute(cve, "v31scope", "v2scope"),
            "Confidentiality Impact": get_attribute(cve, "v31confidentialityImpact", "v2confidentialityImpact"),
            "Integrity Impact": get_attribute(cve, "v31integrityImpact", "v2integrityImpact"),
            "Availability Impact": get_attribute(cve, "v31availabilityImpact", "v2availabilityImpact"),
        }
        filtered_result = {key: value for key, value in result.items() if str(value).strip() != "N/A"}
        return filtered_result
    except Exception as e:
        if ("503 Server Error" in str(e) or "Read timed out." in str(e)) and not second_attempt:
            cve_more_info(cve_ID, second_attempt=True)
        return ({"Tool Error": str(e)})
    
def nvdlib_search(service_name: str, service_version: str = '', second_attempt: bool = False):
        """
        Returns lit of CVEs related to a given service.

        Args:
            service_name: The name of the service (e.g., 'Apache').
            service_version: The version of the service (e.g., '1.0.0').
            second_attempt: Always False, used to prevent infinite recursion.
        Returns:
            List of dictionaries with CVE data.
        """
        try:
                cves = nvdlib.searchCVE(keywordSearch=(service_name.strip() + " " + service_version.strip()).strip(), limit=3)

                response = []

                for eachCVE in cves:
                        #print((eachCVE.id + ": " + eachCVE.descriptions[0].value + "\n"))
                        severity = get_attribute(eachCVE, 'v31severity', 'v2severity')
                        security = get_attribute(eachCVE, 'v31score', 'v2score')
                        response.append({"CVE ID": eachCVE.id, "Severity": severity, "Severity Score": security})
                
                if not response and service_version:
                        service_version = ''
                        return nvdlib_search(service_name)
                else:
                        response.append({"How To Give The Results": "Only the ID, severity and score, not additional text, even after."})
                        return response

        except Exception as e:
                if ("503 Server Error" in str(e) or "Read timed out." in str(e)) and not second_attempt:
                        return nvdlib_search(service_name, service_version, second_attempt=True)
                return ({"Tool Error": str(e)})

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

        return result
    except Exception as e:
        return ({"Tool Error": str(e)})

tools = [cve_more_info, scan_target, nvdlib_search]

def remove_lines_console(num_lines):
    for _ in range(num_lines):
        print("\x1b[A", end="\r", flush=True)

def estimate_lines(text):
    columns, _ = os.get_terminal_size()
    line_count = 1
    text_lines = text.splt("\n")
    for text_line in text_lines:
        lines_needed = (len(text_line) // columns) + 1

        line_count += lines_needed

    return line_count

def handle_console_input(session: PromptSession) -> str:
    return session.prompt(HTML("<b><ansigreen>User: </ansigreen></b>"), multiline=True, auto_suggest=AutoSuggestFromHistory()).strip()

class conchat:
    def __init__(self) -> None:
        self.console = Console()
        self.session = PromptSession(key_bindings=self._create_keybindings(), history=FileHistory("input.history"))


    def _create_keybindings(self) -> KeyBindings:
        kb = KeyBindings()

        # Enter to submit the message
        @kb.add(Keys.Enter)
        def _(event):
            if not event.app.current_buffer.text:  # Prevent sending an empty message
                event.app.current_buffer.text = ""
                return
            if event.app.current_buffer.text:  # Check if there's content to send
                event.app.current_buffer.validate_and_handle()  # Submit the input

        # For debugging purposes
        @kb.add(Keys.ControlL)
        def _(event):
            print(chat_history)        

        # Ctrl + Q to exit
        @kb.add("c-q")
        def _(event):
            run_in_terminal(exit_gracefully)

        return kb


    def chat_generator(self, prompt=None, live: Live=None):
        if prompt:
            chat_history.append({"role": "user", "content": prompt})

        tool_call_buffer = ""  # Buffer for accumulating tool call content
        inside_tool_call = False  # State tracking

        streamer = TextIteratorStreamer(tokenizer) # Streamer here to refresh it each generation

        inputs = tokenizer.apply_chat_template(
            chat_history,
            tools=tools,
            tokenize=True, 
            add_generation_prompt=True,
            return_tensors="pt",
            return_dict=True,
        ).to("cpu")
        inputs = {k: v.to(model.device) for k, v in inputs.items()}

        inputs.update({"streamer": streamer, "max_new_tokens": 1524, "temperature": 0.17, "top_p": 0.92})
        try:
            thread = Thread(target=model.generate, kwargs=inputs)
            thread.start()
            for i, chunk in enumerate(streamer):
                if i == 0: # Skip history chunk
                    continue
                #print(i, chunk)
                
                if "<|im_end|>" in chunk: # Remove the <|im_end|> token from the chunk
                    chunk = chunk.replace("<|im_end|>", "").strip()

                if "<tool_call>" in chunk:
                    inside_tool_call = True
                    tool_call_buffer = chunk[chunk.index("<tool_call>"):]  # Start buffering
                    chunk = chunk[:chunk.index("<tool_call>")]  # Remove from regular chunk

                    spinner = Spinner("dots", text="[yellow]Calling the tool...")
                    live.update(spinner, refresh=True)

                # Continue buffering tool call content
                if inside_tool_call:
                    tool_call_buffer += chunk
                    # Detect end of tool call
                    if "</tool_call>" in chunk:
                        spinner = Spinner("dots", text="[yellow]Processing...")
                        live.update(spinner, refresh=True)
                        inside_tool_call = False
                        tool_call_buffer = tool_call_buffer.strip()

                        # Notify the user that the tool is now running
                        # Parse and execute the tool call
                        try:
                            # Extract tool call JSON and parse it
                            tool_call_content = tool_call_buffer.replace("<tool_call>", "").replace("</tool_call>", "").strip()
                            tool_data = json.loads(tool_call_content)
                            tool_name = tool_data.get("name")
                            tool_args = tool_data.get("arguments", {})

                            func = globals()[tool_name]

                            if func in tools:
                                # Tool execution
                                tool_result = func(**tool_args)
                                # Add the tool call and result to the chat history
                                chat_history.append({"role": "assistant", "tool_calls": [{"type": "function", "function": tool_data}]})
                                chat_history.append({"role": "tool", "name": tool_name, "content": tool_result})
                                # Add the system message to the chat history if present
                                if "System Message" in tool_result:
                                    chat_history.append({"role": "system", "content": tool_result["System Message"]})
                                # Generate a response with the updated chat history
                                yield {"choices": [{"delta": {}, "finish_reason": "tool_call"}]}
                            else:
                                chat_history.append({"role": "system", "content": tool_name + " is not a valid tool."})
                        except json.JSONDecodeError as e:
                            print(f"Error parsing tool call JSON: {e}")

                        # Clear tool call buffer
                        tool_call_buffer = ""
                    continue  # Skip processing this chunk further since it's part of the tool call


                # Simulate streaming character by character
                for char in chunk:
                    time.sleep(0.05)
                    yield {"choices": [{"delta": {"content": char}, "finish_reason": None}]}
            yield {"choices": [{"delta": {}, "finish_reason": "stop"}]}
            thread.join()
        except Exception as e:
            print(f"GeneratorError: {e}")

    def response_handler(self, live: Live, prompt=None):
        text = ""
        block = "█ "
        
        for token in self.chat_generator(prompt, live):
            if "content" in token["choices"][0]["delta"]:
                text += token["choices"][0]["delta"]["content"]
            if token["choices"][0]["finish_reason"] == "tool_call":
                self.response_handler(live)
                break
            if token["choices"][0]["finish_reason"] is not None:
                block = ""
            markdown = Markdown("**PTAssistant:** " + text + block)
            live.update(markdown, refresh=True)
        if text:
            chat_history.append({"role": "assistant", "content": text})

    def handle_streaming(self, prompt=None):
        with Live(console=self.console, vertical_overflow="visible") as live:
            self.response_handler(live, prompt)


    def chat(self):
        while True:
            try:
                user_m = handle_console_input(self.session)
                self.handle_streaming(prompt=user_m)
            except (LiveError, KeyboardInterrupt, EOFError):
                exit_gracefully()
def main():
    chat = conchat()
    chat.chat()

if __name__ == "__main__":
    main()