#import gradio as gr
import datetime
from transformers import AutoModelForCausalLM, AutoTokenizer

model_name = "Qwen/Qwen2.5-1.5B-Instruct"
print("Loading model...")
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name, device_map="cpu")

print("Model loaded.")

def Tell_Time():
    """
    This function returns the current time.
    """
    now = datetime.datetime.now()
    return now.strftime("%H:%M:%S")

chat = [
  {"role": "system", "content": "You are an helpful chatbot. You may call one or more functions to assist with the user query."},
  {"role": "user", "content": "Hello, can you tell me the current time?"},
]

Tools = [Tell_Time]

inputs = tokenizer.apply_chat_template(
    chat, 
    tokenize=True, 
    add_generation_prompt=True,
    tools=Tools,
    return_tensors="pt",
    return_dict=True,
).to("cpu")

inputs = {k: v.to(model.device) for k, v in inputs.items()}
out = model.generate(**inputs, max_new_tokens=128)
print(tokenizer.decode(out[0][len(inputs["input_ids"][0]):]))

tool_call = {"name": "Tell_Time", "arguments": {}}
chat.append({"role": "assistant", "tool_calls": [{"type": "function", "function": tool_call}]})
chat.append({"role": "tool", "name": "Tell_Time", "content": Tell_Time()})

inputs = tokenizer.apply_chat_template(
    chat, 
    tokenize=True, 
    add_generation_prompt=True,
    tools=Tools,
    return_tensors="pt",
    return_dict=True,
).to("cpu")
inputs = {k: v.to(model.device) for k, v in inputs.items()}
out = model.generate(**inputs, max_new_tokens=128)
print(tokenizer.decode(out[0][len(inputs["input_ids"][0]):]))

"""
print(model.config)

outputs = model.generate(
    input_ids=inputs["input_ids"],
    attention_mask=inputs["attention_mask"],
    max_new_tokens=256,
    pad_token_id=tokenizer.eos_token_id,
    #eos_token_id=tokenizer.eos_token_id,
    #repetition_penalty=1.2,  # Penalize repeating tokens
    #do_sample=True,
    #temperature=0.7,  # Adjust sampling temperature for more diverse output
    #top_p=0.9
)

print(tokenizer.decode(outputs[0]))
"""
"""
def respond(
    message,
    history: list[tuple[str, str]],
    system_message,
    max_tokens,
    temperature,
    top_p,
):
    messages = [{"role": "system", "content": system_message}]

    for val in history:
        if val[0]:
            messages.append({"role": "user", "content": val[0]})
        if val[1]:
            messages.append({"role": "assistant", "content": val[1]})

    messages.append({"role": "user", "content": message})

    response = ""

    # Tokenize the input
    inputs = tokenizer(history, return_tensors="pt", add_generation_prompt=True, tokenize=True)
    
    # Generate response
    outputs = model.generate(
        inputs["input_ids"],
        max_length=min(max_tokens + len(inputs["input_ids"][0]), 2048),
        temperature=temperature,
        top_p=top_p,
        pad_token_id=tokenizer.eos_token_id,
    )
    
    response = tokenizer.decode(outputs[0], skip_special_tokens=True)
    response = response[len(context) - len("Assistant:") :].strip()  # Extract AI response

    # Update chat history
    history.append((message, response))



    for message in client.chat_completion(
        messages,
        max_tokens=max_tokens,
        stream=True,
        temperature=temperature,
        top_p=top_p,
    ):
        token = message.choices[0].delta.content

        response += token
        yield response
"""

"""
demo = gr.ChatInterface(
    respond,
    additional_inputs=[
        gr.Textbox(value="You are a friendly Chatbot.", label="System message"),
        gr.Slider(minimum=1, maximum=2048, value=512, step=1, label="Max new tokens"),
        gr.Slider(minimum=0.1, maximum=4.0, value=0.7, step=0.1, label="Temperature"),
        gr.Slider(
            minimum=0.1,
            maximum=1.0,
            value=0.95,
            step=0.05,
            label="Top-p (nucleus sampling)",
        ),
    ],
)


if __name__ == "__main__":
    demo.launch()
"""