FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY bot ./bot
RUN useradd --system --uid 10001 app && mkdir -p /data && chown app:app /data
USER app
VOLUME ["/data"]
CMD ["python", "-m", "bot"]

