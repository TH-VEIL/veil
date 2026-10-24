from fastapi import FastAPI
import yaml

app = FastAPI()

# Load the policy engine
with open("policy.yaml", "r") as file:
    policy = yaml.safe_load(file)

@app.post("/intercept")
def intercept_tool_call(tool_name: str, requested_data_types: list[str]):
    if tool_name not in policy["tools"]:
        return {"decision": "Block", "reason": "Unknown tool"}

    allowed_types = policy["tools"][tool_name]["allowed_data"]
    
    for data_type in requested_data_types:
        if data_type not in allowed_types:
            return {
                "tool": tool_name,
                "decision": "Block", 
                "reason": f"Policy forbids sending {data_type} to this tool."
            }

    return {
        "tool": tool_name,
        "decision": "Allow", 
        "reason": "Policy permits these data types."
    }