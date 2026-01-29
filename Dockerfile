# Use a base image with Windows tools (for Win32 C apps)
FROM mcr.microsoft.com/windows/servercore:ltsc2022

# Set working directory
WORKDIR /app

# Copy compiled sniffer executable and any required files
COPY build/sniffer.exe .
COPY stats.json . 

# Set default command to run the sniffer
CMD ["sniffer.exe"]
