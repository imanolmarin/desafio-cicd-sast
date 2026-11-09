FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY files ./files
COPY wsgi.py .
USER nobody
EXPOSE 5000
CMD ["python", "wsgi.py"]
