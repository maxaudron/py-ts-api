# Use an official Python runtime as a parent image
FROM python:3.6.6-slim

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
ADD . /app

# Install any needed packages specified in requirements.txt
RUN pip install -r requirements.txt
RUN pip install gunicorn

# Make port 80 available to the world outside this container
EXPOSE 80

# Run app.py when the container launches
CMD ["gunicorn", "-w 4", "-b 0.0.0.0:80","py-ts-api:app"]
