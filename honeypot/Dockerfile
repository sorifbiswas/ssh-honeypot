FROM python:3.12-slim
RUN useradd -m -u 10001 honeypot
WORKDIR /app
COPY honeypot/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY honeypot/ honeypot/
RUN mkdir -p /app/data && chown honeypot /app/data
USER honeypot
EXPOSE 2222
CMD ["python", "-m", "honeypot.server"]
