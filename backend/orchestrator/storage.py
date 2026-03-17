import json
import threading
from pathlib import Path
from datetime import datetime
import hashlib

lock = threading.Lock()

AGENTS_FILE = Path("agents.json")
EXPERIMENTS_FILE = Path("experiments.json")
USER_AGENT_MAPPING_FILE = Path("user_agent_mapping.json")

for file in [AGENTS_FILE, EXPERIMENTS_FILE]:
    if not file.exists():
        file.write_text(json.dumps({}))


def read_json(file_path):
    with lock:
        return json.loads(file_path.read_text())


def write_json(file_path, data):
    with lock:
        file_path.write_text(json.dumps(data, indent=4))

def user_agent_mapping(agent_id, user_id, verification_token):
    user_agent_mapping = read_json(USER_AGENT_MAPPING_FILE)
    user_agent_mapping[user_id] = {
        "agent_id": agent_id,
        "verification_token": hashlib.sha256(verification_token.encode()).hexdigest()
    }
    write_json(USER_AGENT_MAPPING_FILE, user_agent_mapping)

def verify_token(verification_token):
    user_agent_mapping = read_json(USER_AGENT_MAPPING_FILE)
    for user in user_agent_mapping.keys():
        if user_agent_mapping[user]["verification_token"] == hashlib.sha256(verification_token.encode()).hexdigest():
            return user, user_agent_mapping[user]["agent_id"]
    return "Invalid verification token", "Invalid verification token"


def register_agent(agent_id, host):
    agents = read_json(AGENTS_FILE)
    agents[agent_id] = {
        "host": host,
        "last_seen": datetime.utcnow().isoformat()
    }
    write_json(AGENTS_FILE, agents)


def update_agent_last_seen(agent_id):
    agents = read_json(AGENTS_FILE)
    if agent_id in agents:
        agents[agent_id]["last_seen"] = datetime.utcnow().isoformat()
        write_json(AGENTS_FILE, agents)

def create_experiment(exp_id, data):
    experiments = read_json(EXPERIMENTS_FILE)
    experiments[exp_id] = {
        **data,
        "status": "pending",
        "assigned_to": data["agent_id"]
    }
    write_json(EXPERIMENTS_FILE, experiments)


def get_experiment_for_agent(agent_id):
    experiments = read_json(EXPERIMENTS_FILE)

    for exp_id, exp in experiments.items():
        if exp["status"] == "pending" and exp["assigned_to"] == agent_id:
            exp["status"] = "assigned"
            write_json(EXPERIMENTS_FILE, experiments)
            return {"experiment_id": exp_id, **exp}

    return None



def update_experiment_status(exp_id, status, result=None):
    experiments = read_json(EXPERIMENTS_FILE)

    if exp_id in experiments:
        experiments[exp_id]["status"] = status

        if result:
            experiments[exp_id]["result"] = result

        write_json(EXPERIMENTS_FILE, experiments)


def get_all_agents():
    return read_json(AGENTS_FILE)


def get_all_experiments():
    return read_json(EXPERIMENTS_FILE)

