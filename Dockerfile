FROM python:3.12

WORKDIR /app

# Install Poetry
RUN pip install poetry
RUN poetry config virtualenvs.create false
RUN poetry install --no-root

# Copy source code
COPY . .

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
