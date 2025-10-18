# Use AWS Lambda Python base image
FROM public.ecr.aws/lambda/python:3.13

# Set working directory
WORKDIR /var/task

# Copy vcert binary
COPY vcert /usr/local/bin/vcert
RUN chmod +x /usr/local/bin/vcert

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy Python handler script
COPY app.py ${LAMBDA_TASK_ROOT}

# Lambda looks for "app.handler" by default, 
# This is also our entry point
#
CMD ["app.handler"]
