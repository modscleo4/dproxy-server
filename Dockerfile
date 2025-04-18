FROM python:3.13
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . .

# Install any needed packages specified in pyproject.toml
RUN uv sync --frozen

# Run main.py when the container launches
ENTRYPOINT ["uv", "run", "main.py"]
