FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir flask==3.0.3
COPY camera.py .
EXPOSE 80
CMD ["python", "camera.py"]
