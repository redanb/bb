import requests
import json
import sys

# User's Railway configuration from previous session success
RAILWAY_TOKEN = "6ee403e4-4b1c-41ed-be26-314694a7281d"
PROJECT_ID = "0868bfd8-a2f1-4d5d-9583-f3c24e53a783"
SERVICE_NAME = "bb"

GRAPHQL_URL = "https://backboard.railway.app/graphql/v2"
headers = {
    "Authorization": f"Bearer {RAILWAY_TOKEN}",
    "Content-Type": "application/json"
}

def query_railway(query, variables=None):
    resp = requests.post(GRAPHQL_URL, json={"query": query, "variables": variables}, headers=headers)
    if resp.status_code != 200:
        print(f"[ERROR] HTTP {resp.status_code}: {resp.text}")
        return None
    return resp.json()

def get_latest_deployment():
    query = """
    query GetDeployments($projectId: String!) {
      project(id: $projectId) {
        services {
          edges {
            node {
              id
              name
              deployments(first: 5) {
                edges {
                  node {
                    id
                    status
                    createdAt
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    data = query_railway(query, {"projectId": PROJECT_ID})
    if not data or "errors" in data or "data" not in data or not data["data"]:
        print(f"[ERROR] Failed to fetch deployments: {data}")
        return None
    
    services = data["data"]["project"]["services"]["edges"]
    bb_service = next((s["node"] for s in services if s["node"]["name"] == SERVICE_NAME), None)
    
    if not bb_service:
        print(f"[ERROR] Service '{SERVICE_NAME}' not found.")
        return None
    
    deployments = bb_service["deployments"]["edges"]
    if not deployments:
        print(f"[ERROR] No deployments found for service '{SERVICE_NAME}'.")
        return None
    
    # Deployment nodes are already sorted by date usually
    print(f"[*] Found {len(deployments)} deployments. Fetching logs for the latest...")
    # Return the ID of the first (latest) deployment
    return deployments[0]["node"]["id"]

def get_logs(deployment_id):
    query = """
    query GetLogs($deploymentId: String!) {
      deploymentLogs(deploymentId: $deploymentId) {
        timestamp
        message
        severity
      }
    }
    """
    data = query_railway(query, {"deploymentId": deployment_id})
    if not data or "errors" in data:
        print(f"[ERROR] Failed to fetch logs: {data}")
        return None
    
    return data["data"]["deploymentLogs"]

if __name__ == "__main__":
    dep_id = get_latest_deployment()
    if dep_id:
        print(f"[*] Deployment ID: {dep_id}")
        logs = get_logs(dep_id)
        if logs:
            for log in logs:
                ts = log.get("timestamp", "")
                sev = log.get("severity", "INFO")
                msg = log.get("message", "")
                print(f"[{ts}] [{sev}] {msg}")
        else:
            print("[!] No logs returned.")
