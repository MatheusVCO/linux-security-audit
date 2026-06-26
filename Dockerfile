FROM ubuntu:22.04
RUN apt update && apt install -y bash iproute2 procps && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
CMD ["bash", "./main.sh"]
