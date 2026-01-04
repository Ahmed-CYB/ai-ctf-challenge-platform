# FTP Server with Security Misconfiguration
FROM python:3.11-slim

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN pip install --no-cache-dir pyftpdlib

# Create FTP directory and flag
WORKDIR /ftp
COPY flag.txt /ftp/flag.txt
RUN chmod 644 /ftp/flag.txt

# Expose FTP ports
EXPOSE 21

# Start anonymous FTP server (no auth required)
CMD ["python", "-m", "pyftpdlib", "-p", "21", "-w", "-d", "/ftp"]
