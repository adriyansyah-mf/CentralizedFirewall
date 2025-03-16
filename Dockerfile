FROM python:3.12

WORKDIR /app

# Install Poetry
RUN pip install poetry
RUN poetry config virtualenvs.create false

# Copy pyproject.toml & poetry.lock terlebih dahulu
COPY pyproject.toml poetry.lock ./

# Install dependencies
RUN poetry install --no-root

# Copy semua source code
COPY . .

CMD ["poetry", "run", "uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
