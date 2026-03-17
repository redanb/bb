#!/usr/bin/env python3
"""
Railway API Injector v1.0
Securely injects secrets into Railway environment variables via GraphQL API.
Bypasses GitHub repository to prevent credential leaks.
"""

import os
import requests
import json
import sys

# Constants
RAILWAY_API_URL = "https://backboard.railway.app/graphql/v2"

# Verified Credentials from Context
CREDENTIALS = {
    "TELEGRAM_BOT_TOKEN": "8626121905:AAHLzk12PZZme6UD0Z6y-B9Edr9ZJ9UGzJQ",
    "TELEGRAM_CHAT_ID": "985485272",
    "PRACTICE_MODE": "true"
}

def inject_secrets(token, project_id):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Updated Query: Railway v2 uses 'project' (singular) for direct ID lookup.
    query_project = """
    query {
      project(id: "%s") {
        id
        services {
          edges {
            node {
              id
              name
            }
          }
        }
        environments {
          edges {
            node {
              id
              name
            }
          }
        }
      }
    }
    """ % project_id

    try:
        response = requests.post(RAILWAY_API_URL, headers=headers, json={"query": query_project})
        data = response.json()
        
        if "errors" in data:
            print(f"[ERROR] API returned errors: {data['errors']}")
            return

        project = data["data"]["project"]
        if not project:
            print(f"[ERROR] Project {project_id} not found or access denied.")
            return

        services = project["services"]["edges"]
        environments = project["environments"]["edges"]

        if not services:
            print("[ERROR] No services found in project.")
            return
        
        # We'll target the first service and first environment by default
        service_id = services[0]["node"]["id"]
        env_id = environments[0]["node"]["id"]
        
        print(f"[*] Targeting Service: {services[0]['node']['name']} ({service_id})")
        print(f"[*] Targeting Environment: {environments[0]['node']['name']} ({env_id})")

        # Deep Platform Knowledge: Railway v2 requires variableCollectionUpsert for batch updates.
        # It MUST be wrapped in an "input" key.
        mutation = """
        mutation VariableCollectionUpsert($input: VariableCollectionUpsertInput!) {
          variableCollectionUpsert(input: $input)
        }
        """
        
        # Prepare the variables as a dictionary (Map), not a list
        payload = {
            "query": mutation,
            "variables": {
                "input": {
                    "projectId": project_id,
                    "environmentId": env_id,
                    "serviceId": service_id,
                    "variables": CREDENTIALS,
                    "replace": False
                }
            }
        }

        res = requests.post(RAILWAY_API_URL, headers=headers, json=payload)
        res_data = res.json()

        if res_data.get("data", {}).get("variableCollectionUpsert"):
            print("[SUCCESS] Credentials successfully injected into Railway cloud via CollectionUpsert!")
            print("[NOTE] Railway will now auto-redeploy to apply the new variables.")
        elif "errors" in res_data:
            print(f"[ERROR] GraphQL Error: {res_data['errors']}")
        else:
            print(f"[ERROR] Failed to inject variables: {res_data}")

    except Exception as e:
        print(f"[FATAL ERROR] {str(e)}")

if __name__ == "__main__":
    print("--- Railway Automated Secret Injector ---")
    
    # Try to get from args or prompt
    api_token = sys.argv[1] if len(sys.argv) > 1 else input("Enter your Railway API Token: ").strip()
    
    # We can attempt to guess the project ID if the user doesn't provide it, 
    # but it's safer to ask for the one from the URL.
    project_id = sys.argv[2] if len(sys.argv) > 2 else input("Enter your Railway Project ID (from URL): ").strip()

    if not api_token or not project_id:
        print("[ERROR] Token and Project ID are required.")
        sys.exit(1)

    inject_secrets(api_token, project_id)
