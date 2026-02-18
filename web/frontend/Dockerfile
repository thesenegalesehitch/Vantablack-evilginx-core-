FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package.json .
# COPY package-lock.json . # Only if exists

RUN npm install

# Copy application code
COPY . .

# Expose port
EXPOSE 3000

# Run application
CMD ["npm", "start"]
