# Use the official Python 3.12 image as the base
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the Poetry files (pyproject.toml, poetry.lock)
COPY pyproject.toml poetry.lock* ./

# Install Poetry and project dependencies (with caching)
RUN pip install --no-cache-dir poetry
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi

# Copy the rest of the application code
COPY . /app

# Expose the port Uvicorn will run on (default: 8000)
EXPOSE 8000

# Command to run the application (defined in docker-compose.yml)
# We *don't* put the CMD here, as we'll override it in docker-compose
