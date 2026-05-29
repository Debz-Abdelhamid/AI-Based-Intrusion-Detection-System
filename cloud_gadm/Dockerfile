FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3 requests==2.32.3
COPY gadm.py .
EXPOSE 5000
CMD ["python", "-u", "gadm.py"]
