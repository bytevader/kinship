FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
RUN pip install --no-cache-dir kinship starlette uvicorn
COPY demo.py dashboard.html ./
USER 10001:10001
EXPOSE 7946/tcp 7946/udp 8080/tcp
CMD ["python", "demo.py"]
