import argparse
import json
import time
import os
import nvdlib

import requests
from prompt_toolkit import PromptSession
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.history import FileHistory
from prompt_toolkit.application import run_in_terminal
from rich.console import Console
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown

from threading import Thread
from transformers import AutoTokenizer, AutoModelForCausalLM, TextIteratorStreamer


model_name = "Qwen/Qwen2.5-1.5B-Instruct"
print(f"Loading model...")
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name, device_map="cpu")
print(f"Model uploaded successfully.")
chat_history = [
    {"role": "system", "content": "You are a useful chatbot expert in the matter of cybersecurity."},
    #{"role": "user", "content": "Hi, can you check the CVE-2021-26855 for me?"},
]




def remove_lines_console(num_lines):
    for _ in range(num_lines):
        print("\x1b[A", end="\r", flush=True)

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

tools = [cve_check]

def estimate_lines(text):
    columns, _ = os.get_terminal_size()
    line_count = 1
    text_lines = text.split("\n")
    for text_line in text_lines:
        lines_needed = (len(text_line) // columns) + 1

        line_count += lines_needed

    return line_count

def handle_console_input(session: PromptSession) -> str:
    return session.prompt("(Prompt: ⌥ + ⏎) | (Exit: ⌘ + c): ", multiline=True).strip()

class conchat:
    def __init__(
        self,
        top_k=10,
        top_p=0.95,
        temperature=0.12,
        n_predict=-1,
        stream: bool = True,
        cache_prompt: bool = True,
        model_frame_color: str = "red",
    ) -> None:
        self.model_frame_color = model_frame_color
        self.topk = top_k
        self.top_p = top_p
        self.temperature = temperature
        self.n_predict = n_predict
        self.stream = stream
        self.cache_prompt = cache_prompt
        self.headers = {"Content-Type": "application/json"}
        self.chat_history = []
        self.model_name = ""

        self.console = Console()
        self.session = PromptSession(key_bindings=self._create_keybindings(), history=FileHistory("chat_history.txt"))
        # TODO: Gracefully handle user input history file.


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

        # Shift + Enter for a new line
        @kb.add(Keys.ShiftUp)
        def _(event):
            event.app.current_buffer.insert_text("\n")  # Insert a newline

        # Super (Command) + C to exit
        @kb.add(Keys.ControlC)
        def _(event):
            def exit_gracefully():
                print("\nExiting...")
                exit()
            run_in_terminal(exit_gracefully)

        return kb


    def chat_generator(self, prompt=None):
        if prompt:
            chat_history.append({"role": "user", "content": prompt})

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,  # Progress bar disappears after completion
        ) as progress:
            waiting_task = None
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

        inputs.update({"streamer": streamer, "max_new_tokens": 50})
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

                    # Notify the user that a tool call is being constructed
                    if waiting_task is None:
                        waiting_task = progress.add_task(description="Calling the tool...", total=None)

                # Continue buffering tool call content
                if inside_tool_call:
                    tool_call_buffer += chunk
                    # Detect end of tool call
                    if "</tool_call>" in chunk:
                        inside_tool_call = False
                        tool_call_buffer = tool_call_buffer.strip()

                        # Notify the user that the tool is now running
                        progress.update(waiting_task, description="Running the tool...")
                        # Parse and execute the tool call
                        try:
                            # Extract tool call JSON and parse it
                            tool_call_content = tool_call_buffer.replace("<tool_call>", "").replace("</tool_call>", "").strip()
                            tool_data = json.loads(tool_call_content)
                            tool_name = tool_data.get("name")
                            tool_args = tool_data.get("arguments", {})

                            func = globals()[tool_name]

                            if func in tools:
                                # Esecuzione del tool
                                tool_result = func(**tool_args)
                                # Aggiunta della chiamata al tool e del risultato alla cronologia
                                chat_history.append({"role": "assistant", "tool_calls": [{"type": "function", "function": tool_data}]})
                                chat_history.append({"role": "tool", "name": tool_name, "content": tool_result})
                                #chat_history.append({"role": "system", "content": "Explain the tool output to the user."})
                                print("too") 
                                # Rigenerazione della risposta del modello con la cronologia aggiornata
                                yield {"choices": [{"delta": {}, "finish_reason": "tool_call"}]}
                            else:
                                response = f"I'm sorry the tool '{tool_name}' is not available."
                        except json.JSONDecodeError as e:
                            print(f"Error parsing tool call JSON: {e}")
                            progress.remove_task(waiting_task)
                            waiting_task = None

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
        for token in self.chat_generator(prompt):
            if "content" in token["choices"][0]["delta"]:
                text += token["choices"][0]["delta"]["content"]
            if token["choices"][0]["finish_reason"] == "tool_call":
                self.response_handler(live)
                break
            if token["choices"][0]["finish_reason"] is not None:
                block = ""
            markdown = Markdown(text + block)
            live.update(markdown, refresh=True)
        if text:
            chat_history.append({"role": "assistant", "content": text})

    def handle_streaming(self, prompt=None):
        self.console.print(Markdown("**>**"), end=" ")
        with Live(console=self.console) as live:
            self.response_handler(live, prompt)


    def chat(self):
        while True:
            try:
                user_m = handle_console_input(self.session)
                print(f"User input received: {user_m}")
                self.handle_streaming(prompt=user_m)

            # NOTE: Ctrl + c (keyboard) or Ctrl + d (eof) to exit
            # Adding EOFError prevents an exception and gracefully exits.
            except (KeyboardInterrupt, EOFError):
                exit()
def main():
    chat = conchat()
    chat.chat()

if __name__ == "__main__":
    main()