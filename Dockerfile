FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV HOST=0.0.0.0
ENV PORT=5058
EXPOSE 5058
CMD ["python", "server.py"]
