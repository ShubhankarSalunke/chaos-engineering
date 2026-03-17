import streamlit as st
import requests

API_URL = "https://yoi0pc6611.execute-api.us-east-1.amazonaws.com/create-experiment"

st.title("Create Chaos Experiment")

# Inputs
agent_id = st.text_input("Agent ID")

exp_type = st.selectbox(
    "Type",
    ["container_kill", "memory_stress"],
    format_func=lambda x: "Container Kill" if x == "container_kill" else "Memory Stress"
)

target_container = st.text_input("Target Container", value="demo-mono")

duration = st.number_input(
    "Duration (seconds)",
    min_value=1,
    value=10,
    step=1
)

memory_mb = None
if exp_type == "memory_stress":
    memory_mb = st.number_input(
        "Memory (MB)",
        min_value=1,
        step=1
    )

# Submit button
if st.button("Create Experiment"):

    payload = {
        "type": exp_type,
        "target_container": target_container,
        "duration": int(duration),
        "agent_id": agent_id
    }

    if exp_type == "memory_stress" and memory_mb:
        payload["memory_mb"] = int(memory_mb)

    try:
        res = requests.post(
            API_URL,
            json=payload,
            headers={"Content-Type": "application/json"}
        )

        if res.status_code != 200:
            st.error(f"Error: {res.text}")
        else:
            data = res.json()
            st.success(f"Experiment Created: {data['experiment_id']}")

    except Exception as e:
        st.error(f"Error: {str(e)}")