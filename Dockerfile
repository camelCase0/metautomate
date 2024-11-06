# Use the latest Kali Linux rolling image
FROM kalilinux/kali-rolling

# Set environment variables to avoid prompts during package installations
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install Nmap and Metasploit Framework
RUN apt-get update && \
    apt-get install -y nano nmap metasploit-framework && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the default command to run when the container starts
CMD ["/bin/bash"]

