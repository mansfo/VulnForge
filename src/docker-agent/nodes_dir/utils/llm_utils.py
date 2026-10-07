import time
import json
from langchain_core.output_parsers import PydanticOutputParser # type: ignore
from pydantic import BaseModel # type: ignore
from langchain_core.messages import SystemMessage # type: ignore

def invoke_structured(llm, model_name: str, messages: list, output_model: type[BaseModel], max_tokens: int = 8192, config: dict | None = None) -> BaseModel:
    config = config or {}
    bound_llm = llm.bind(max_tokens=max_tokens)
    
    if model_name in ["gpt-4o", "gpt-5"]:
        structured_llm = bound_llm.with_structured_output(output_model)
        for attempt in range(3):
            try:
                result = structured_llm.invoke(messages, config=config)
                if not result:
                    raise ValueError("Empty LLM output")
                return result
            except Exception as e:
                print(f"\t[WARN] API/Parsing Error (Attempt {attempt + 1}/10): {str(e)[:100]}")
                if attempt == 10: 
                    raise e
                time.sleep(min(2 ** attempt, 20))  
    
    parser = PydanticOutputParser(pydantic_object=output_model)
    format_instructions = f"Never use Markdown. Output ONLY valid JSON.\n\n{parser.get_format_instructions()}"
    
    run_messages = list(messages)
    run_messages[0] = SystemMessage(content=run_messages[0].content + f"\n\n{format_instructions}")
    
    for attempt in range(10):
        try:
            response = bound_llm.invoke(run_messages, config=config)
            
            refusal = response.additional_kwargs.get("refusal")

            if refusal:
                raise RuntimeError(f"Model refused the request: {refusal}")
            content = response.content
            
            if isinstance(content, list):
                content = content[0].get("text", "")
                
            result = parse_llm_output(content, output_model)
            if result is not None:
                return result
                
            run_messages.append(response)
            run_messages.append(SystemMessage(content="Your previous output was not valid JSON matching the schema. Please output ONLY the raw JSON object without markdown formatting or preamble text."))
            time.sleep(min(2 ** attempt, 20)) 
            
        except Exception as e:
            print(f"\t[WARN] API Error (Attempt {attempt + 1}/10): {str(e)[:100]}")
            if attempt == 10:
                raise e
            time.sleep(min(2 ** attempt, 20)) 
            
    raise ValueError(f"Failed to extract valid JSON for {output_model.__name__} after 3 attempts.")


def parse_llm_output(text: str, model):
    decoder = json.JSONDecoder()
    for i, c in enumerate(text):
        if c != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(text[i:])
            return model.model_validate(obj)
        except Exception:
            continue

    return None