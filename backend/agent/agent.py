import requests
import subprocess
import time
import uuid
import socket


#docker run --name demo-mono -d -p 8000:80 nginx
# CONTROL_PLANE = "http://localhost:8000"
CONTROL_PLANE = "https://yoi0pc6611.execute-api.us-east-1.amazonaws.com"
POLL_INTERVAL = 5


AGENT_ID = ""
USER_ID = ""
# AGENT_ID = input("Enter agent ID here : ")
verification_token = input("Enter verification token here (displayed on agent registration): ")
HOSTNAME = socket.gethostname()


def kill_container(name, duration):
    subprocess.run(["docker", "kill", name], check=False)
    print("Container Killed")
    time.sleep(duration)
    subprocess.run(["docker", "start", name], check=False)
    print("Container Restarted")


def memory_stress(container, memory_mb, duration):
    subprocess.run([
        "docker", "update",
        "--memory", f"{memory_mb}m",
        container
    ], check=False)

    time.sleep(duration)

    # Rollback
    subprocess.run([
        "docker", "update",
        "--memory", "0",
        container
    ], check=False)

def register():
    resp = requests.post(
        f"{CONTROL_PLANE}/register",
        json={
            # "agent_id": AGENT_ID,
            "verification_token": verification_token,
            "host": HOSTNAME
        }
    )

    data = resp.json()
    return data["agent_id"], data["user_id"]

def execute_experiment(exp):
    exp_id = exp["experiment_id"]
    exp_type = exp["type"]

    try:
        if exp_type == "container_kill":
            kill_container(exp["target_container"], exp["duration"])

        elif exp_type == "memory_stress":
            memory_stress(
                exp["target_container"],
                exp["memory_mb"],
                exp["duration"]
            )

        # Report success
        requests.post(
            f"{CONTROL_PLANE}/result",
            json={
                "experiment_id": exp_id,
                "status": "completed",
                "result": {"message": "Executed successfully"}
            }
        )

    except Exception as e:
        requests.post(
            f"{CONTROL_PLANE}/result",
            json={
                "experiment_id": exp_id,
                "status": "failed",
                "result": {"error": str(e)}
            }
        )

def poll_loop(AGENT_ID):
    while True:
        try:
            print("Polling Orchestrator for Experiments...")
            resp = requests.get(
                f"{CONTROL_PLANE}/poll/{AGENT_ID}"
            )

            data = resp.json()

            if "experiment_id" in data:
                execute_experiment(data)

        except Exception as e:
            print("Agent error:", e)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    # print("Starting agent:", AGENT_ID)
    AGENT_ID, USER_ID = register()
    print(f"Agent {AGENT_ID} registered and verified with the orchestrator")
    poll_loop(AGENT_ID)
