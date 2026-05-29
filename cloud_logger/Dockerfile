FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3
COPY logger.py .
EXPOSE 5001
CMD ["python", "-u", "logger.py"]
