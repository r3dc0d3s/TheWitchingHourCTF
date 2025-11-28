# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Install socat
RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /usr/src/app
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install pycryptodome

# Make port 9999 available to the world outside this container
EXPOSE 9999

# Run server.py when the container launches using socat
CMD ["socat", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:'python3 -u server.py'"]