FROM python:3.7

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    telnet \
    net-tools \
    openssl \
    apache2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

ENV FLASK_ENV=development
ENV DEBUG=true
ENV SECRET_KEY=admin123
ENV DB_PASSWORD=password123

USER root

CMD ["python", "app.py"]
