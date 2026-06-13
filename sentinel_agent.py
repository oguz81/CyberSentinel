import anthropic
import chromadb

# 1. Initialize Clients
# Replace 'your-api-key' with your actual Claude API key
client = anthropic.Anthropic(api_key=#API_KEY HERE)

db_client = chromadb.PersistentClient(path="./sentinel_db")
attack_col = db_client.get_collection(name="linux_attack_techniques")
mitigation_col = db_client.get_collection(name="linux_mitigations")

def get_rag_context(log_entry):
    # Query for the attack description
    query_text = f"Method: {log_entry['method']} Path: {log_entry['path']} Status: {log_entry['status']}"
    print(query_text)
    attack_results = attack_col.query(query_texts=[query_text], n_results=1)
    
    context = ""
    if attack_results['ids'][0]:
        t_id = attack_results['ids'][0][0]
        attack_desc = attack_results['documents'][0][0]
        
        # Query for the specific mitigations linked to this T-ID
        mitigation_results = mitigation_col.get(where={"targets_attack": t_id})
        mitigations = "\n".join(mitigation_results['documents']) if mitigation_results['documents'] else "No specific mitigation found."
        
        context = f"DETECTED TECHNIQUE: {attack_desc}\n\nRECOMMENDED MITIGATIONS:\n{mitigations}"
    
    return context

def ask_claude(log_entry, context):
    system_prompt = "You are an expert Autonomous SOC Analyst. Your job is to analyze logs and provide a concise, actionable security report."
    
    user_message = f"""
    ANALYZING LOG ENTRY:
    {log_entry}

    RAG KNOWLEDGE BASE CONTEXT:
    {context}

    Based on the log and the context, provide:
    1. THREAT LEVEL: (Low, Medium, High, Critical)
    2. ANALYSIS: One sentence explaining why.
    3. RECOMMENDED ACTION: One specific command or step to take.
    """

    message = client.messages.create(
        model="claude-opus-4-7", # Or claude-3-haiku-20240307 for speed
        max_tokens=800,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}]
    )
    
    return message.content[0].text

# --- TEST RUN ---
if __name__ == "__main__":
    # Simulating a parsed log from your Redmine ingestor
    test_log = {
        "ip": "10.49.55.127",
        "method": "POST",
        "path": "/etc/shadow",
        "status": "403"
    }

    print("🧠 Sentinel is thinking...")
    context = get_rag_context(test_log)
    report = ask_claude(test_log, context)
    
    print("\n--- SENTINEL SECURITY REPORT ---")
    print(report)
