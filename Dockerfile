# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8501

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    software-properties-common \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone the repository
RUN git clone https://github.com/dreamfactorysoftware/df-catalog.git /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create the .streamlit directory
RUN mkdir -p .streamlit

# Copy the example secrets file if secrets.toml doesn't exist
RUN if [ ! -f .streamlit/secrets.toml ]; then \
    cp .streamlit/secrets.toml.example .streamlit/secrets.toml; \
    fi

# Expose port 8501 for Streamlit
EXPOSE 8501

# Create a non-root user
RUN useradd -m -s /bin/bash streamlit
RUN chown -R streamlit:streamlit /app
USER streamlit

# Run the application
ENTRYPOINT ["streamlit", "run", "streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"] 