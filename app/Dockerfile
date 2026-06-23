# ─────────────────────────────────────────────
# Stage 1: Build dependencies
# ─────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build deps in isolated stage
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ─────────────────────────────────────────────
# Stage 2: Runtime image (minimal attack surface)
# ─────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: create non-root user
RUN groupadd --gid 10001 appgroup && \
    useradd --uid 10001 --gid appgroup --no-create-home --shell /sbin/nologin appuser

WORKDIR /app

# Copy only installed packages from builder (no build tools in runtime)
COPY --from=builder /root/.local /home/appuser/.local

# Copy app source
COPY app.py .

# Security: set ownership + drop write perms
RUN chown -R appuser:appgroup /app && \
    chmod -R 550 /app

# Run as non-root
USER appuser

# Expose non-privileged port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

# Use gunicorn in production (not flask dev server)
ENV PATH=/home/appuser/.local/bin:$PATH
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "60", "app:app"]
