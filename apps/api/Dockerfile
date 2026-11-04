FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --timeout 180 --retries 10 --no-cache-dir -r requirements.txt
COPY main.py system_maintenance.py host_transition_plan.py port_forward_plan.py rebind_watcher.py ./
USER 65532:65532
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
