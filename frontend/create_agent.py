# import gradio as gr
# import requests

# API_URL = "https://js0jrg7evl.execute-api.us-east-1.amazonaws.com/create-agent"

# def create_agent(user_id, agent_id):
#     payload = {
#         "user_id": user_id,
#         "agent_id": agent_id
#     }

#     try:
#         res = requests.post(
#             API_URL,
#             json=payload,
#             headers={"Content-Type": "application/json"}
#         )

#         if res.status_code != 200:
#             return f"Error: {res.text}"

#         data = res.json()

#         return f"Agent Created: {data['agent_id']} | Verification Token: {data['verification_token']}"

#     except Exception as e:
#         return f"Error: {str(e)}"


# with gr.Blocks() as demo:
#     gr.Markdown("## Create Experiment")

#     user_id = gr.Textbox(label="User ID")
#     agent_id = gr.Textbox(label="Agent ID")

#     btn = gr.Button("Create Agent")

#     output = gr.Textbox(label="Response")

#     btn.click(
#         fn=create_agent,
#         inputs=[user_id, agent_id],
#         outputs=output
#     )

# demo.launch()


import streamlit as st
import requests

API_URL = "https://yoi0pc6611.execute-api.us-east-1.amazonaws.com/create-agent"

st.title("Create Chaos Experiment")

user_id = st.text_input("User ID")
agent_id = st.text_input("Agent ID")

if st.button("Create Agent"):
    payload = {
        "user_id": user_id,
        "agent_id": agent_id
    }

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
            st.success("Agent Created Successfully")
            st.write("Agent ID:", data["agent_id"])
            st.write("Verification Token:", data["verification_token"])

    except Exception as e:
        st.error(f"Error: {str(e)}")