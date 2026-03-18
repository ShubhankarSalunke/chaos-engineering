# This is the chaos Repo (Mai nhi banana chahta tha ye but had to keep the code modular)

## Added as a submodule to lucifer




## 🖥️ Running the System

### 1. Start the Orchestrator (Control Plane)

```bash
cd backend-go/orchestrator
go run main.go storage.go
```

Server will start at:

```
http://localhost:8000
```

---

### 2. Create Agent (Frontend)

Navigate to:

```
/frontend
```

Open:

```
create-agent.html
```

If browser blocks requests, run a local server:

```bash
python3 -m http.server 5500
```

Then visit:

```
http://localhost:5500
```

---

### 3. Register Agent

- Enter `user_id` and `agent_id`
- Click **Create Agent**
- Copy the **Verification Token**

---

### 4. Start Agent

```bash
cd backend-go/agent
go run agent.go
```

Paste the **verification token** when prompted.

---

### 5. Create Chaos Experiment

Open:

```
frontend/create-experiment.html
```

- Provide experiment details
- Submit request

---

### 6. Observe Execution

Agent will:
- Poll control plane
- Receive experiment
- Execute chaos (e.g., container kill, memory stress)
- Report results

---

## 🧪 Example Experiment

```json
{
  "type": "container_kill",
  "target_container": "nginx",
  "duration": 10,
  "agent_id": "agent1"
}
```

---

## 🛠️ Optional: Better UI (Streamlit)

```bash
cd frontend
streamlit run create-agent.py
```

Ensure backend URL is set to:

```
http://localhost:8000
```

---

## ⚠️ Common Issues

### CORS Errors

Enable CORS in backend:

```go
r.Use(cors.Default())
```

---

### NetworkError in Browser

- Ensure backend is running
- Use `http://localhost`, not `file://`
- Check correct port (8000)

---

### Agent Not Receiving Experiments

- Verify `agent_id`
- Ensure agent is running
- Check experiment assignment

---

## 🧠 Architecture Overview

```
Frontend → Orchestrator (Gin API)
                    ↓
                 Agent
                    ↓
          Chaos Execution (Docker)
```

---

## 📌 Notes

- Uses JSON files as storage (no DB)
- No authentication beyond token verification