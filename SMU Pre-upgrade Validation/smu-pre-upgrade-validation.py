#!/usr/bin/env python3
"""
ACI SMU Pre-upgrade Validation Script

This script validates Cisco ACI switches against known SMU issues.

Check 1: Ensure correct image type (32-bit or 64-bit) based on switch memory capacity
Check 2: Ensure .repodata file does not exist

@ Author: joelebla@cisco.com
@ Version: 1.1.3
@ Date: 05/27/2025
"""

import os
import re
import sys
import time
import json
import signal
import shutil
import logging
import pexpect
import argparse
import tempfile
import threading
import traceback
import subprocess
import concurrent.futures
from getpass import getpass
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Any
from logging.handlers import RotatingFileHandler

###########################################
# Constants
###########################################

# Regular expression patterns
MEMORY_PATTERN = r'with\s+(\d{7,8})\s+kB\s+of\s+memory'
IMAGE_PATH_PATTERNS = [
    r'kickstart\s+image\s+file\s+is\s+:\s+(\S+)',
    r'kickstart image file is:\s+(\S+)',
    r'kickstart\s+image\s+file\s+is\s+(\S+)'
]
MD5_PATTERN = r'([0-9a-f]{32})'

# Thresholds and limits
MEMORY_THRESHOLD = 32000000  # 32GB in KB

# Standard memory sizes in GB with KB ranges
MEMORY_SIZES = {
    16: (0, 20000),        # Less than 20000KB = 16GB
    24: (20000, 30000),    # 20000KB to 30000KB = 24GB
    32: (30000, 40000),    # 30000KB to 40000KB = 32GB
    64: (60000, 70000)     # 60000KB to 70000KB = 64GB
}

# Result display colors
RESULT_COLORS = {
    "PASS": "\033[1;32m",     # Green
    "FAIL": "\033[1;31m",     # Red
    "WARNING": "\033[1;33m",  # Yellow
    "ERROR": "\033[1;31m",    # Red (same as FAIL)
    "RESET": "\033[0m"        # Reset to default
}

###########################################
# Output Processing and Utilities
###########################################

class CommandOutputProcessor:
    """Process command output from switches with standardized cleaning and parsing"""
    
    @staticmethod
    def clean_output(output, switch_name=None):
        """
        Clean up command output by removing switch prompts, hostnames, and irrelevant lines
        
        Args:
            output (str): Raw command output from switch
            switch_name (str, optional): Switch hostname to remove from output
            
        Returns:
            str: Cleaned output without prompts and host information
        """
        if not output:
            return ""
            
        # Process each line
        clean_lines = []
        for line in output.splitlines():
            # Skip empty lines
            if not line.strip():
                continue
                
            # Skip lines with just the switch name
            if switch_name and line.strip() == switch_name:
                continue
                
            # Skip common command echo lines
            if line.strip().startswith(("md5sum ", "ls -", "show ")):
                continue
            
            # Remove hostname if it appears at the end of a line
            if switch_name and switch_name in line:
                line = line[:line.find(switch_name)].strip()
            
            # Remove ANSI color codes
            line = re.sub(r'\033\[[0-9;]*m', '', line)
            
            # Add the cleaned line
            clean_lines.append(line.rstrip())
        
        return "\n".join(clean_lines)
    
    @staticmethod
    def extract_single_line(output, pattern=None, switch_name=None):
        """
        Extract a single relevant line from command output
        
        Args:
            output (str): Raw command output
            pattern (str, optional): Pattern to search for in the line
            switch_name (str, optional): Switch hostname to remove from output
            
        Returns:
            str: The first relevant line matching the pattern or first non-empty line
        """
        # Clean the output first
        cleaned = CommandOutputProcessor.clean_output(output, switch_name)
        
        if not cleaned:
            return ""
            
        lines = cleaned.splitlines()
        
        # If pattern specified, look for matching line
        if pattern:
            for line in lines:
                if pattern in line:
                    return line
        
        # Otherwise return first non-empty line
        for line in lines:
            if line.strip():
                return line
                
        return ""
    
    @staticmethod
    def extract_file_info(output, switch_name=None):
        """
        Extract file information from ls -l command output
        
        Args:
            output (str): Output from ls -l command
            switch_name (str, optional): Switch hostname to clean from output
            
        Returns:
            dict: Dictionary with file_owner, file_group, file_permissions, file_size
        """
        # Clean the output first
        cleaned = CommandOutputProcessor.clean_output(output, switch_name)
        
        # Initialize result dictionary
        info = {
            "file_owner": None,
            "file_group": None,
            "file_permissions": None,
            "file_size": None,
            "file_line": None
        }
        
        if not cleaned:
            return info
            
        # Find the line with the .bin file
        bin_line = None
        for line in cleaned.splitlines():
            if ".bin" in line:
                bin_line = line
                info["file_line"] = line
                break
        
        if not bin_line:
            return info
            
        # Parse the line with regex patterns
        
        # Permissions pattern: -rw-r--r-- or similar at start of line
        perm_match = re.search(r'^(-[rwx-]{9})', bin_line)
        if perm_match:
            info["file_permissions"] = perm_match.group(1)
        
        # Owner and group pattern: typically columns 3 and 4 in ls -l output
        owner_match = re.search(r'(?:-[rwx-]{9}|\S+)\s+\d+\s+(\S+)\s+(\S+)', bin_line)
        if owner_match:
            info["file_owner"] = owner_match.group(1)
            info["file_group"] = owner_match.group(2)
        
        # Size pattern: look for size before date
        size_match = re.search(r'(\d+(?:\.\d+)?[KMG]?)\s+(?:[A-Z][a-z]{2}\s+\d+|(?:\d{4}-\d{2}-\d{2}|\d{2}:\d{2}))', bin_line)
        if size_match:
            info["file_size"] = size_match.group(1)
        
        # Create a formatted details string using available info
        if info["file_permissions"] and info["file_owner"]:
            info["file_details"] = f"{info['file_permissions']} {info['file_owner']} {info['file_group']}"
            if info["file_size"]:
                info["file_details"] += f" {info['file_size']}"
        
        return info
    
    @staticmethod
    def parse_md5_output(output, switch_name=None):
        """
        Parse MD5 command output to extract hash value
        
        Args:
            output (str): Output from md5sum command
            switch_name (str, optional): Switch hostname to clean
            
        Returns:
            dict: Dictionary with success status, hash value, and error info if any
        """
        # Clean the output first
        cleaned = CommandOutputProcessor.clean_output(output, switch_name)
        
        result = {
            "success": False,
            "md5_hash": None,
            "error_type": None,
            "error_message": None
        }
        
        if not cleaned:
            result["error_type"] = "empty_output"
            result["error_message"] = "No output from md5sum command"
            return result
        
        # Check for permission denied error
        if "permission denied" in cleaned.lower():
            result["error_type"] = "permission"
            result["error_message"] = "Permission denied when accessing image file"
            return result
        
        # Check for file not found error
        if "no such file" in cleaned.lower():
            result["error_type"] = "file_not_found"
            result["error_message"] = "Image file not found"
            return result
        
        # Try to extract the MD5 hash using regex
        md5_match = re.search(r'([0-9a-f]{32})', cleaned)
        if md5_match:
            result["success"] = True
            result["md5_hash"] = md5_match.group(1)
        else:
            result["error_type"] = "extraction_failed"
            result["error_message"] = "Could not extract MD5 hash from output"
        
        return result
    
    @staticmethod
    def format_for_display(output, max_lines=3, max_line_length=80):
        """
        Format command output for compact display in reports
        
        Args:
            output (str): Command output to format
            max_lines (int): Maximum number of lines to include
            max_line_length (int): Maximum length per line
            
        Returns:
            str: Formatted output suitable for display
        """
        if not output:
            return ""
            
        lines = output.splitlines()
        if not lines:
            return ""
            
        # Limit the number of lines
        if len(lines) > max_lines:
            displayed_lines = lines[:max_lines-1]
            displayed_lines.append(f"... ({len(lines) - max_lines + 1} more lines)")
        else:
            displayed_lines = lines
        
        # Limit the length of each line
        formatted_lines = []
        for line in displayed_lines:
            if len(line) > max_line_length:
                formatted_lines.append(line[:max_line_length-3] + "...")
            else:
                formatted_lines.append(line)
        
        return "\n".join(formatted_lines)

###########################################
# Memory Management and Validation
###########################################

class MemoryCheck:
    """Handles memory threshold checking, conversions, and validation logic"""
    
    # Memory thresholds in KB
    THRESHOLD_KB = MEMORY_THRESHOLD
    
    @classmethod
    def has_high_memory(cls, memory_kb=None, memory_gb=None):
        """
        Check if memory meets high memory threshold (32GB or higher)
        
        Args:
            memory_kb (int, optional): Memory in KB
            memory_gb (int, optional): Memory in GB
            
        Returns:
            bool: True if memory is 32GB or higher
        """
        if memory_gb is not None:
            return memory_gb >= 32
        elif memory_kb is not None:
            return memory_kb >= cls.THRESHOLD_KB
        return False
    
    @classmethod
    def standardize_memory_gb(cls, memory_kb):
        """
        Convert KB memory value to standardized GB value
        
        Args:
            memory_kb (int): Memory value in KB
            
        Returns:
            int: Standardized memory value in GB (16, 24, 32, 64, or calculated value)
        """
        if memory_kb is None:
            return None
            
        try:
            kb = int(memory_kb)
            
            # Check against standard size ranges
            for gb_size, (min_kb, max_kb) in MEMORY_SIZES.items():
                if min_kb <= kb < max_kb:
                    return gb_size
            
            # If not in standard ranges, calculate from KB
            return round(kb / 1024)
            
        except (ValueError, TypeError):
            return None
    
    @classmethod
    def format_memory_display(cls, memory_kb, memory_gb=None):
        """
        Format memory for display with appropriate units
        
        Args:
            memory_kb (int, optional): Memory in KB
            memory_gb (int, optional): Memory in GB
            
        Returns:
            str: Formatted memory string (e.g., "32 GB")
        """
        if memory_gb is not None:
            return f"{memory_gb} GB"
        elif memory_kb not in ("Unknown", None):
            try:
                gb_value = cls.standardize_memory_gb(memory_kb)
                return f"{gb_value} GB" if gb_value else f"{memory_kb} KB"
            except (ValueError, TypeError):
                return f"{memory_kb} KB"
        else:
            return "Unknown"
    
    @classmethod
    def validate_image_for_memory(cls, memory_kb, memory_gb, image_type):
        """
        Validate if image type is correct for memory capacity
        
        Args:
            memory_kb (int, optional): Memory in KB
            memory_gb (int, optional): Memory in GB
            image_type (str): Either "32bit" or "64bit"
            
        Returns:
            tuple: (result, message) where result is "PASS" or "FAIL"
        """
        # First determine if this is high memory
        has_high_mem = cls.has_high_memory(memory_kb, memory_gb)
        
        # Format memory for message
        if memory_gb is not None:
            mem_display = f"{memory_gb} GB"
        elif memory_kb is not None:
            mem_gb = cls.standardize_memory_gb(memory_kb)
            mem_display = f"{mem_gb} GB" if mem_gb else f"{memory_kb} KB"
        else:
            mem_display = "Unknown"
        
        # Validate memory against image type
        if not has_high_mem:
            if image_type == "32bit":
                return "PASS", f"Running 32bit image with {mem_display} memory (correct)"
            else:
                return "FAIL", f"Running 64bit image with {mem_display} memory (should be 32bit)"
        else:
            if image_type == "64bit":
                return "PASS", f"Running 64bit image with {mem_display} memory (correct)"
            else:
                return "FAIL", f"Running 32bit image with {mem_display} memory (should be 64bit)"

###########################################
# Connection Management 
###########################################

class Connection:
    """Handles SSH connections to fabric switches"""
    
    def __init__(self, hostname, username=None, password=None, timeout=30, bind_address=None):
        """Initialize SSH connection handler"""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.child = None
        self.output = ""
        self.prompt = r'[#%>]\s*$'  # Match #, %, or > followed by optional whitespace
        self.log = get_logger(f'connection.{hostname}')
        self.log.setLevel(logging.DEBUG)
        self.log.propagate = False
        self.bind_address = bind_address
        self.auth_failure = False  # Track authentication failures
        
    def connect(self, max_attempts=1):
        """
        Establish and authenticate an SSH connection with retry mechanism.
        
        This function attempts to establish an SSH connection to the target device,
        authenticate with the provided credentials, and handle various connection
        issues like host key warnings, timeouts, and authentication failures.
        
        Args:
            max_attempts (int): Maximum number of connection attempts before giving up
                
        Returns:
            bool: True if connection established successfully, False if connection 
                failed after all retry attempts
                
        Raises:
            RuntimeError: With "AUTH_FAILURE" in the message when authentication fails
                        (special case that prevents retries)
        
        Notes:
            - Sets self.child to the pexpect.spawn object on success
            - Sets self.auth_failure to True on authentication failures
            - Uses handle_connection_error() for standardized error handling
        """
        self.log.debug(f"Connecting to {self.hostname}")
        
        # Track attempts
        attempts = 0
        
        while attempts < max_attempts:
            attempts += 1
            self.log.debug(f"Connection attempt {attempts}/{max_attempts}")
            
            try:
                # Close any existing connection first
                if self.child:
                    self.close()
                
                # Build SSH command with all options
                ssh_cmd = "ssh "
                
                # Add bind address option if specified
                if self.bind_address:
                    ssh_cmd += f"-b {self.bind_address} "
                    
                # Add standard SSH options
                ssh_cmd += (
                    f"-o StrictHostKeyChecking=no "
                    f"-o UserKnownHostsFile=/dev/null "
                    f"-o ConnectTimeout=30 "
                    f"-o ServerAliveInterval=5 "
                    f"-o ServerAliveCountMax=3 "
                    f"-o LogLevel=VERBOSE "
                )
                
                ssh_cmd += f"{self.username}@{self.hostname}"
                
                # Start SSH process with proper encoding
                self.child = pexpect.spawn(
                    ssh_cmd,
                    timeout=30,
                    encoding='utf-8'
                )
                
                # Define expected patterns
                password_prompts = ['assword:', r'\([^)]+\) Password:', 'password:', 'Password:']
                auth_failures = ['Permission denied', 'ermission denied', 'denied', 'incorrect', 'invalid', 'failure']
                success_patterns = [self.prompt, 'Cisco Nexus', 'NX-OS']
                
                # First expect: Wait for password prompt or immediate success (key-based auth)
                i = self.child.expect(password_prompts + [self.prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=30)
                
                # Case: Found a password prompt
                if i < len(password_prompts):
                    self.log.debug(f"Password prompt received, sending password")
                    self.child.sendline(self.password)
                    
                    # After password, look for success or failure
                    j = self.child.expect(
                        success_patterns + auth_failures + [pexpect.TIMEOUT, pexpect.EOF], 
                        timeout=20
                    )
                    
                    if j < len(success_patterns):  # Success pattern matched
                        self.log.debug(f"Successfully authenticated to {self.hostname}")
                        
                        # If we matched a banner but not the prompt, wait for prompt
                        if j > 0:  # Matched banner, wait for prompt
                            try:
                                self.child.expect([self.prompt], timeout=10)
                            except:
                                self.log.warning("Couldn't find prompt after banner, continuing anyway")
                        
                        return True
                        
                    else:  # Authentication failed or timeout
                        error_index = j - len(success_patterns)
                        
                        if error_index < len(auth_failures):  # Auth failure
                            error_msg = auth_failures[error_index]
                            error_type = "auth_failure"
                            self.auth_failure = True
                        elif error_index == len(auth_failures):  # Timeout
                            error_msg = "Connection timed out"
                            error_type = "timeout"
                        else:  # EOF
                            error_msg = "Connection closed unexpectedly"
                            error_type = "eof"
                        
                        # Use unified error handler
                        error_info = handle_connection_error(
                            device_name=self.hostname,
                            device_ip=self.hostname,
                            error=error_msg,
                            error_type=error_type,
                            buffer=self.child.before if hasattr(self.child, 'before') else None,
                            logger=self.log
                        )
                        
                        self.close(force=True)
                        
                        # Don't retry auth failures
                        if error_type == "auth_failure":
                            raise RuntimeError("AUTH_FAILURE")
                        
                        # For other errors, retry if attempts remain
                        if attempts < max_attempts:
                            time.sleep(1)  # Brief pause before retry
                            continue
                        
                        return False
                        
                # Case: Already at prompt (no password needed)
                elif i == len(password_prompts):
                    self.log.debug(f"Connected without password prompt")
                    return True
                    
                # Case: Timeout or EOF during initial connection
                else:
                    error_type = "timeout" if i == len(password_prompts) + 1 else "connection"
                    error_msg = f"Failed to connect: {error_type}"
                    
                    error_info = handle_connection_error(
                        device_name=self.hostname,
                        device_ip=self.hostname,
                        error=error_msg,
                        error_type=error_type,
                        logger=self.log
                    )
                    
                    self.close(force=True)
                    
                    # Retry if attempts remain
                    if attempts < max_attempts:
                        time.sleep(1)
                        continue
                    
                    return False
                    
            except Exception as e:
                error_info = handle_connection_error(
                    device_name=self.hostname,
                    device_ip=self.hostname,
                    error=e,
                    error_type="exception",
                    logger=self.log
                )
                
                self.close(force=True)
                
                # Special handling for auth failures
                if "AUTH_FAILURE" in str(e):
                    raise
                    
                # Retry other exceptions if attempts remain
                if attempts < max_attempts:
                    time.sleep(1)
                    continue
                    
                return False
        
        # If we get here, all attempts failed
        self.log.error(f"Failed to connect after {max_attempts} attempts")
        return False

    def execute_command(self, command, timeout=None, expect_prompt=None):
        """
        Execute a command and collect output with intelligent handling for different command types.
        
        This is the primary method for executing commands, with specialized handling for 
        long-running commands, commands with large output, and error conditions.
        
        Args:
            command (str): The command to execute on the target device
            timeout (int, optional): Timeout in seconds. If None, uses the instance default timeout.
                Commands like 'md5sum' and 'show version' automatically get extended timeouts.
            expect_prompt (str, optional): Pattern to match for prompt detection.
                If None, uses the instance default prompt pattern.
                
        Returns:
            tuple: (status, output) where:
                - status (str): One of "success", "timeout", "eof", or "error"
                - output (str): Command output or error message
                
        Raises:
            RuntimeError: If no active connection exists (self.child is None)
        
        Notes:
            - Also sets self.output for backward compatibility
            - Automatically chooses between standard and multiline collection strategies
            based on the command type
            - For 'md5sum' commands, automatically extends timeout to 45 seconds
            - For 'show version' commands, automatically extends timeout to 30 seconds
        """
        if not self.child:
            self.log.error("No active connection")
            raise RuntimeError("No active connection")
        
        # Set default values
        if timeout is None:
            timeout = self.timeout
        
        if expect_prompt is None:
            expect_prompt = self.prompt
            
        # Use longer timeouts for specific commands
        if command.startswith("md5sum"):
            timeout = max(timeout, 45)
            self.log.debug(f"Using extended timeout of {timeout}s for md5sum command")
        elif command.lower() == "show version":
            timeout = max(timeout, 30)
            self.log.debug(f"Using extended timeout of {timeout}s for 'show version'")
        
        try:
            # Clear any pending output
            if self.child.before:
                self.log.debug(f"Clearing buffer before command: {self.child.before[-100:]}")
            
            # Send the command
            self.log.debug(f"Sending command: {command}")
            self.child.sendline(command)
            
            # Determine the collection strategy
            if command.lower() == "show version" or command.startswith("show run"):
                # Use multiline collection for output-heavy commands
                return self._collect_multiline_output(expect_prompt, timeout)
            else:
                # Standard collection for normal commands
                return self._collect_standard_output(expect_prompt, timeout)
                
        except Exception as e:
            self.log.error(f"Error executing command: {str(e)}")
            self.close(force=True)
            return "error", f"Command execution error: {str(e)}"

    def _collect_standard_output(self, expect_prompt, timeout):
        """
        Collect command output using the standard expectation approach.
        
        Used for most commands with manageable output size. Handles prompt detection,
        timeouts, and connection termination.
        
        Args:
            expect_prompt (str): Pattern to match for prompt detection
            timeout (int): Command timeout in seconds
                
        Returns:
            tuple: (status, output) where:
                - status (str): One of "success", "timeout", "eof", or "error"
                - output (str): Command output or error message
        
        Notes:
            - Sets self.output for backward compatibility
            - On timeout, attempts recovery by sending Ctrl+C via _handle_timeout()
            - On EOF, indicates connection was closed unexpectedly
            - Preserves connection state when possible, forces close when necessary
        """
        try:
            i = self.child.expect([expect_prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
            
            if i == 0:  # Found prompt
                output = self.child.before
                self.output = CommandOutputProcessor.clean_output(output, self.hostname)
                return "success", self.output
            elif i == 1:  # Timeout
                self.output = self.child.before
                self.log.warning(f"Command timed out after {timeout}s")
                self._handle_timeout()
                return "timeout", self.output
            else:  # EOF
                self.output = self.child.before
                self.log.error("Connection closed while executing command")
                self.close(force=True)
                return "eof", self.output
        
        except Exception as e:
            self.log.error(f"Error processing command output: {str(e)}")
            return "error", str(e)

    def _collect_multiline_output(self, expect_prompt, timeout):
        """
        Collect multiline output with special handling for lengthy command output.
        
        Used for commands like 'show version' that produce substantial output.
        Implements a chunked reading approach with multiple timeout stages to
        handle very large outputs efficiently.
        
        Args:
            expect_prompt (str): Pattern to match for prompt detection
            timeout (int): Overall command timeout in seconds
                
        Returns:
            tuple: (status, output) where:
                - status (str): One of "success", "timeout", "eof", or "error"
                - output (str): Command output or error message
        
        Notes:
            - Sets self.output for backward compatibility
            - Uses multiple short timeouts instead of one long timeout
            - Limits maximum output size to 1MB for safety
            - Efficiently collects output in chunks to handle large outputs
            - Performs multiple attempts to detect the prompt at different stages
            - Logs detailed debugging information about the collection process
        """
        self.log.debug(f"Using multiline collection with timeout {timeout}s")
        output = []
        chunk_size = 4096
        total_size = 0
        max_size = 1048576  # 1MB max output for safety
        
        start_time = time.time()
        end_time = start_time + timeout
        
        try:
            while time.time() < end_time and total_size < max_size:
                # Check if prompt is already in the buffer
                matched_prompt = False
                try:
                    i = self.child.expect([expect_prompt, pexpect.TIMEOUT], timeout=0.1)
                    if i == 0:  # Found prompt
                        output.append(self.child.before)
                        total_size += len(self.child.before)
                        matched_prompt = True
                        break
                except Exception as e:
                    self.log.debug(f"Initial prompt check exception (normal): {str(e)}")
                    
                # If prompt not found, read a chunk of data
                if not matched_prompt:
                    try:
                        # Try to read more data with a short timeout
                        i = self.child.expect(['.+', pexpect.TIMEOUT], timeout=0.5)
                        if i == 0:  # Got some data
                            chunk = self.child.match.group(0)
                            if chunk:
                                output.append(chunk)
                                total_size += len(chunk)
                                self.log.debug(f"Read chunk: {len(chunk)} bytes")
                        else:  # Timeout on chunk read - try for prompt
                            try:
                                i = self.child.expect([expect_prompt, pexpect.TIMEOUT], timeout=3)
                                if i == 0:  # Found prompt after waiting
                                    if self.child.before:
                                        output.append(self.child.before)
                                        total_size += len(self.child.before)
                                    break
                            except Exception as e:
                                self.log.debug(f"Prompt check after timeout exception: {str(e)}")
                                # Continue looping until main timeout
                    except Exception as e:
                        self.log.warning(f"Exception during chunk read: {str(e)}")
            
            # Final check for prompt
            if not matched_prompt:
                try:
                    i = self.child.expect([expect_prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=5)
                    if i == 0 and self.child.before:  # Found prompt at the end
                        output.append(self.child.before)
                        total_size += len(self.child.before)
                except Exception as e:
                    self.log.debug(f"Final prompt check exception: {str(e)}")
                    
            # Join all output
            self.output = ''.join(output).strip()
            self.output = CommandOutputProcessor.clean_output(self.output, self.hostname)
            self.log.debug(f"Collected {len(output)} chunks, {total_size} bytes total")
            
            # Check if we hit timeout limit
            actual_time = time.time() - start_time
            if actual_time >= timeout:
                self.log.warning(f"Collection hit timeout limit: {actual_time:.1f}s of {timeout}s allowed")
                return "timeout", self.output
                
            # Check if we got substantial output
            if total_size > 0:
                return "success", self.output
            else:
                self.log.warning("No output collected despite successful completion")
                return "success", ""
                
        except Exception as e:
            self.log.error(f"Error collecting multiline output: {str(e)}")
            return "error", str(e)

    def _handle_timeout(self):
        """
        Handle command timeout with recovery attempt.
        
        Attempts to recover from a command timeout by sending Ctrl+C and
        waiting for the prompt to return. If recovery fails, forces the
        connection to close.
        
        Returns:
            None
            
        Side Effects:
            - May close the connection if recovery fails
            - Sends Ctrl+C to the remote device
            
        Notes:
            - Called automatically by _collect_standard_output on timeout
            - Does not raise exceptions, handles all errors internally
        """
        try:
            # Send Ctrl+C to try to recover
            self.child.sendcontrol('c')
            time.sleep(0.5)
            try:
                self.child.expect([self.prompt], timeout=5)
            except:
                # If we can't recover, force close
                self.close(force=True)
        except:
            self.close(force=True)
              
        return "timeout"

    def close(self, force=False):
        """
        Close the SSH connection with proper cleanup.
        
        Attempts a graceful exit if possible, then ensures the connection
        is fully closed and resources are released.
        
        Args:
            force (bool): Whether to skip graceful exit and force close immediately.
                Set to True when the connection is in an inconsistent state.
                
        Returns:
            None
            
        Side Effects:
            - Sets self.child to None
            - Clears self.output
            - Sends "exit" command to the device if not in force mode
            
        Notes:
            - Safe to call multiple times and on already closed connections
            - Handles exceptions internally to ensure cleanup always occurs
            - Called automatically by __exit__ and __del__ methods
        """
        if not self.child:
            return
            
        try:
            self.log.debug(f"Closing connection to {self.hostname}")
            
            if not force:
                # Try graceful exit first
                try:
                    self.child.sendline("exit")
                    self.child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=3)
                except:
                    pass
            
            # Force close regardless
            self.child.close(force=True)
            self.log.debug(f"Connection to {self.hostname} closed")
            
        except Exception as e:
            self.log.warning(f"Error closing connection: {str(e)}")
        finally:
            self.child = None
            self.output = ""

    def __del__(self):
        """Destructor to ensure connection is closed"""
        self.close()
        
    def __enter__(self):
        """Context manager entry"""
        if not self.child:
            self.connect(max_attempts=1)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

    def get_connection_info(self):
        """Return connection status information"""
        return {
            "hostname": self.hostname,
            "connected": self.child is not None and self.child.isalive(),
            "username": self.username
        }     

###########################################
# API and Data Collection
###########################################

class MD5Processor:
    """Handles MD5 hash processing, validation, and error detection"""
    
    def __init__(self):
        """Initialize the MD5 processor"""
        self.logger = get_logger('md5_processor')
    
    @staticmethod
    def process_md5_output(output, switch_name=None):
        """
        Process MD5 command output to extract hash and detect errors
        
        Args:
            output: md5sum command output
            switch_name: Optional switch name to clean from output
            
        Returns:
            dict: Dictionary with md5_hash, error_type, error_message
        """
        # Use CommandOutputProcessor to do the actual parsing
        result = CommandOutputProcessor.parse_md5_output(output, switch_name)
        
        # Transform the result format to maintain backward compatibility
        md5_result = {
            "md5_hash": result["md5_hash"],
            "error_type": result["error_type"] if not result["success"] else None,
            "error_message": result["error_message"] if not result["success"] else None
        }
        
        return md5_result
    
    @staticmethod
    def validate_md5(md5_hash, expected_32bit, expected_64bit):
        """
        Validate an MD5 hash against expected values
        
        Args:
            md5_hash: Hash to validate
            expected_32bit: Expected hash for 32-bit image
            expected_64bit: Expected hash for 64-bit image
            
        Returns:
            dict: Result with type ('32bit', '64bit', or 'unknown') and match status
        """
        if not md5_hash:
            return {"type": "unknown", "matches": False, "message": "No MD5 hash provided"}
            
        # Check against expected hashes
        if md5_hash == expected_32bit:
            return {"type": "32bit", "matches": True, "message": "Running 32-bit image"}
        elif md5_hash == expected_64bit:
            return {"type": "64bit", "matches": True, "message": "Running 64-bit image"}
        else:
            return {"type": "unknown", "matches": False, "message": "Running unrecognized image"}
    
    @classmethod
    def get_md5_hash(cls, image_name=None, system_image_name=None):
        """
        Consolidated function for MD5 hash retrieval that handles multiple methods.
        
        This function attempts three different methods to retrieve the MD5 hash:
        1. Query firmwareFirmware API using icurl (if system_image_name provided)
        2. Read from md5sum file in /firmware/fwrepos/fwrepo/md5sum/
        3. Calculate MD5 directly from the image file
        
        Args:
            image_name (str, optional): The kickstart image filename (e.g., "aci-n9000-dk9.16.0.8e.bin")
            system_image_name (str, optional): The system image name for API query 
                                            (e.g., "aci-n9000-system.16.0.8e.bin")
            
        Returns:
            str: MD5 hash or error message ("Image not found" if all methods fail)
        """
        logger = get_logger('md5_processor')
        
        if not image_name and not system_image_name:
            logger.error("No image name or system image name provided")
            return "Image not found"
            
        md5_hash = None
        
        # Method 1: Try API query if system_image_name is provided
        if system_image_name:
            logger.info(f"Method 1: Attempting to get MD5 from firmwareFirmware API for {system_image_name}")
            md5_hash = cls._get_md5_from_api(system_image_name)
            if md5_hash and md5_hash != "Image not found in API":
                logger.info(f"Successfully retrieved MD5 from API: {md5_hash}")
                return md5_hash
            logger.debug("API method failed, falling back to md5sum file")
        
        # Convert system_image_name to kickstart_image_name if needed
        if not image_name and system_image_name:
            # Convert from "aci-n9000-system.X.Y.Z.bin" to "aci-n9000-dk9.X.Y.Z.bin"
            image_name = system_image_name.replace("aci-n9000-system", "aci-n9000-dk9")
            logger.info(f"Converted system image name to kickstart image name: {image_name}")
        
        # Method 2: Try md5sum file method
        if image_name:
            logger.info(f"Method 2: Attempting to get MD5 from md5sum file for {image_name}")
            md5_hash = cls._get_md5_from_file(image_name)
            if md5_hash and md5_hash != "Image not found in fwrepo":
                logger.info(f"Successfully retrieved MD5 from file: {md5_hash}")
                return md5_hash
            logger.debug("MD5sum file method failed, falling back to direct calculation")
        
        # Method 3: Try direct calculation
        if image_name:
            logger.info(f"Method 3: Attempting to calculate MD5 directly for {image_name}")
            md5_hash = cls._calculate_md5_directly(image_name)
            if md5_hash:
                logger.info(f"Successfully calculated MD5 directly: {md5_hash}")
                return md5_hash
            logger.debug("Direct MD5 calculation failed")
        
        # If all methods failed, return consistent error message
        logger.error("All MD5 retrieval methods failed")
        return "Image not found"
    
    @staticmethod
    def _get_md5_from_api(system_image_name):
        """
        Get MD5 hash from firmwareFirmware API using icurl.
        
        Args:
            system_image_name (str): Name of the system image (e.g., aci-n9000-system.16.0.8e.bin)
            
        Returns:
            str: MD5 hash or error message
        """
        logger = get_logger('md5_api')
        logger.debug(f"Querying firmwareFirmware API for {system_image_name}")
        
        try:
            # Construct the icurl command with proper escaping
            icurl_cmd = f"icurl -gs 'http://127.0.0.1:7777/api/class/firmwareFirmware.json?query-target-filter=eq(firmwareFirmware.name,\"{system_image_name}\")'"
            logger.debug(f"Executing icurl command: {icurl_cmd}")
            
            # Execute the command with timeout
            process = subprocess.Popen(icurl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=30)
            
            if process.returncode != 0:
                logger.debug(f"icurl command failed with return code {process.returncode}")
                logger.debug(f"stderr: {stderr.decode('utf-8') if stderr else 'None'}")
                return "Image not found in API"
            
            output = stdout.decode('utf-8')
            
            # Use CommandOutputProcessor to clean the output
            cleaned_output = CommandOutputProcessor.clean_output(output)
            logger.debug(f"Cleaned API output: {cleaned_output[:200]}...")  # Log first 200 chars
            
            # Parse the JSON output
            json_data = json.loads(cleaned_output)
            
            # Check if we have the expected data structure
            if "imdata" in json_data and len(json_data["imdata"]) > 0:
                firmware_obj = json_data["imdata"][0].get("firmwareFirmware", {}).get("attributes", {})
                
                # Extract checksum from the JSON
                checksum = firmware_obj.get("checksum")
                if checksum and re.match(r'^[0-9a-f]{32}$', checksum):
                    return checksum
                else:
                    logger.debug(f"checksum not found or invalid in API response")
            else:
                logger.debug("No firmware data found in API response")
                
            return "Image not found in API"
            
        except subprocess.TimeoutExpired:
            logger.debug("icurl command timed out after 30 seconds")
            return "Image not found in API"
        except json.JSONDecodeError as e:
            logger.debug(f"Failed to parse JSON from API response: {str(e)}")
            return "Image not found in API"
        except Exception as e:
            logger.debug(f"Error getting MD5 from API: {str(e)}")
            return "Image not found in API"
    
    @staticmethod
    def _get_md5_from_file(image_filename):
        """
        Get MD5 hash from md5sum file.
        
        Args:
            image_filename (str): Name of the image file
            
        Returns:
            str: MD5 hash or error message
        """
        logger = get_logger('md5_file')
        md5sum_file = f"/firmware/fwrepos/fwrepo/md5sum/{image_filename}"
        
        # Check if the file exists without printing errors
        if not os.path.exists(md5sum_file):
            logger.debug(f"MD5 file not found: {md5sum_file}")
            return "Image not found in fwrepo"
        
        try:
            # Read the md5sum file
            with open(md5sum_file, 'r') as f:
                content = f.read().strip()
            
            # Clean the content using CommandOutputProcessor
            cleaned_content = CommandOutputProcessor.clean_output(content)
            
            # Extract MD5 hash (first field)
            if cleaned_content:
                # Try to extract using regex pattern for more reliability
                md5_match = re.search(r'([0-9a-f]{32})', cleaned_content)
                if md5_match:
                    return md5_match.group(1)
                
                # If regex fails, try traditional first field split
                md5_hash = cleaned_content.split()[0]
                if re.match(r'^[0-9a-f]{32}$', md5_hash):
                    return md5_hash
            
            logger.debug(f"Invalid content in MD5 file: {md5sum_file}")
            return "Image not found in fwrepo"
            
        except Exception as e:
            logger.debug(f"Error reading MD5 file {md5sum_file}: {str(e)}")
            return "Image not found in fwrepo"

    @staticmethod
    def _calculate_md5_directly(image_filename):
        """
        Calculate MD5 hash directly from the image file.
        
        Args:
            image_filename (str): Name of the image file
            
        Returns:
            str: MD5 hash or None if calculation fails
        """
        logger = get_logger('md5_calc')
        image_path = f"/firmware/fwrepos/fwrepo/{image_filename}"
        
        # Check if the image file exists
        if not os.path.exists(image_path):
            logger.debug(f"Image file not found: {image_path}")
            return None
        
        try:
            # Try using system md5sum command first (usually faster than Python's implementation)
            try:
                md5sum_cmd = f"md5sum {image_path}"
                output = subprocess.check_output(md5sum_cmd, shell=True, text=True)
                
                # Process the output using CommandOutputProcessor
                md5_result = CommandOutputProcessor.parse_md5_output(output)
                
                if md5_result["success"]:
                    return md5_result["md5_hash"]
                
                logger.debug("System md5sum failed, falling back to Python implementation")
            except Exception as e:
                logger.debug(f"System md5sum error: {str(e)}, falling back to Python implementation")
            
            # Fall back to Python's hashlib implementation
            import hashlib
            md5 = hashlib.md5()
            
            with open(image_path, 'rb') as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    md5.update(chunk)
                    
            return md5.hexdigest()
            
        except Exception as e:
            logger.error(f"Error calculating MD5: {str(e)}")
            return None

class SwitchInfo:
    """Handles discovery and data collection from ACI switches"""
    
    def __init__(self):
        """Initialize the switch information cache"""
        self.switch_cache = {}
        self.switch_names = {}
        self.switch_ids = {}
        self.switch_memory = {}
        self.appliance_addr = None
        self.username = None
        self.password = None
        self._fabric_node_data = None  # Cache for fabricNode API data
        self._building_cache = False  # Flag to track cache building
        
    def get_appliance_address(self):
        """
        Get the current APIC's management address for SSH connectivity
        by first determining the local APIC's serial number
        """
        if not self.appliance_addr:
            try:
                # Step 1: Get the local APIC's serial number using acidiag verifyapic
                local_sn = None
                verify_output = subprocess.check_output(['acidiag', 'verifyapic'], text=True)
                # Look for SN: in the output to identify the serial number
                sn_match = re.search(r'SN:([A-Za-z0-9]+)', verify_output)
                if sn_match:
                    local_sn = sn_match.group(1)
                    logger.info(f"Found local APIC serial number: {local_sn}")
                else:
                    raise RuntimeError("Failed to extract serial number from acidiag verifyapic output")
                    
                # Step 2: Use the serial number to find the correct APIC information
                output = subprocess.check_output(['acidiag', 'avread'], text=True)
                # Match the line containing our serial number
                apic_match = re.search(r'appliance id=\d+\s+address=([^\s]+).*' + local_sn, output)
                if apic_match:
                    self.appliance_addr = apic_match.group(1)
                    logger.info(f"Using local APIC bind address: {self.appliance_addr}")
                else:
                    raise RuntimeError("Failed to find APIC information for local serial number")
            except subprocess.CalledProcessError:
                raise RuntimeError("Failed to run acidiag command. Are you on an APIC?")
        
        return self.appliance_addr
    
    def verify_credentials(self, max_attempts=2):
        """
        Verify credentials by connecting to the APIC
        Returns True if successful, False otherwise
        """
        verify_logger = get_logger('verify_creds')
        verify_logger.setLevel(logging.DEBUG)
        verify_logger.propagate = False
        
        apic_addr = self.get_appliance_address()
        print(f"Verifying credentials against APIC ({apic_addr})...")
        
        # Preserve the original password
        actual_password = self.password
        
        # If username is root, we need to use the debug token as the password
        if self.username == "root":
            # For root login, the debug token is the password
            # Don't modify the ssh command line
            verify_logger.info("Using root authentication with debug token")
        
        # Define patterns for matching various SSH connection stages
        host_key_pattern = r'Warning: Permanently added .* to the list of known hosts.'
        banner_pattern = 'Application Policy Infrastructure Controller'
        password_patterns = ['assword:', 'Password:', 'password:']
        auth_failure_patterns = [
            'Permission denied', 'ermission denied', 'denied', 
            'incorrect', 'invalid', 'failure', 'Authentication fail'
        ]
        prompt_patterns = ['#', '%', '>']
        
        for attempt in range(max_attempts):
            try:
                verify_logger.info(f"Attempt {attempt+1}/{max_attempts} to connect to APIC at {apic_addr}")
                
                # Use simple SSH command regardless of user - don't add debugtoken parameter
                ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {self.username}@{apic_addr}"
                
                # Create SSH process with timeout
                child = pexpect.spawn(ssh_cmd, timeout=10, encoding='utf-8')
                verify_logger.info("SSH process spawned for APIC authentication")
                
                # Initial connection stage: expect host key warning, banner, or password prompt
                patterns = [host_key_pattern, banner_pattern] + password_patterns + [pexpect.TIMEOUT, pexpect.EOF]
                i = child.expect(patterns, timeout=15)
                
                # Handle host key warning
                if i == 0:  # Host key warning
                    verify_logger.info("Host key warning received, continuing...")
                    # After host key, expect banner or password prompt
                    j = child.expect([banner_pattern] + password_patterns + [pexpect.TIMEOUT, pexpect.EOF], timeout=10)
                    
                    if j == 0:  # Banner after host key
                        verify_logger.info("Banner received after host key")
                        if not self._expect_password_prompt(child, verify_logger):
                            if attempt < max_attempts - 1:
                                self._retry_with_new_password()
                            continue
                    elif j < len(password_patterns) + 1:  # Password prompt after host key
                        verify_logger.info("Password prompt received after host key")
                        pass  # Continue to password sending below
                    else:  # Timeout or EOF
                        if attempt < max_attempts - 1:
                            self._handle_connection_error(verify_logger, "after host key")
                            continue
                        return False
                
                # Handle banner found directly
                elif i == 1:  # Banner without host key warning
                    verify_logger.info("Banner received directly")
                    if not self._expect_password_prompt(child, verify_logger):
                        if attempt < max_attempts - 1:
                            self._retry_with_new_password()
                        continue
                
                # Handle immediate password prompt (position depends on number of password patterns)
                elif i < len(patterns) - 2:  # Password prompt directly
                    verify_logger.info(f"Password prompt received directly: {child.match.group(0)}")
                    pass  # Continue to password sending
                
                # Handle timeout or EOF during initial connection
                else:
                    error_type = "timeout" if i == len(patterns) - 2 else "connection closed"
                    verify_logger.error(f"Failed initial connection: {error_type}")
                    if attempt < max_attempts - 1:
                        self._handle_connection_error(verify_logger, "during initial connection")
                        continue
                    return False
                
                # Send password and check for success, prompt, or failure
                verify_logger.info("Sending password")
                child.sendline(self.password)
                
                # Add all patterns we want to match after sending password
                auth_patterns = auth_failure_patterns + ['assword:'] + prompt_patterns + [banner_pattern, pexpect.TIMEOUT, pexpect.EOF]
                auth_index = child.expect(auth_patterns, timeout=8)
                
                # Check for authentication failures (first set of patterns)
                if auth_index < len(auth_failure_patterns):
                    verify_logger.error(f"Authentication failed: {child.match.group(0) if child.match else 'Unknown'}")
                    verify_logger.debug(f"Buffer after failed auth: {child.before}")
                    
                    error_info = handle_connection_error(
                        device_name="APIC",
                        device_ip=apic_addr,
                        error="Authentication failed",
                        error_type="auth_failure",
                        buffer=child.before,
                        logger=verify_logger
                    )
                    
                    if attempt < max_attempts - 1:
                        print("\033[1;31mAuthentication failed. Please try again.\033[0m") 
                        self.password = getpass(f"Password for {self.username}: ")
                        print()
                    else:
                        print("\033[1;31mAuthentication failed. Invalid credentials.\033[0m")
                    continue
                
                # Check for password re-prompt
                elif auth_index == len(auth_failure_patterns):  # Password prompt again
                    verify_logger.error("Got password prompt again - authentication likely failed")
                    if attempt < max_attempts - 1:
                        print("\033[1;31mAuthentication failed. Please try again.\033[0m")
                        self.password = getpass(f"Password for {self.username}: ")
                        print()
                    else:
                        print("\033[1;31mAuthentication failed. Invalid credentials.\033[0m")
                    continue
                
                # Check for shell prompt (successful login)
                elif auth_index < len(auth_failure_patterns) + len(prompt_patterns) + 1:
                    prompt_idx = auth_index - len(auth_failure_patterns) - 1
                    verify_logger.info(f"Successfully authenticated - found prompt: {child.match.group(0)}")
                    print("Successfully authenticated to APIC")
                    child.sendline("exit")  # Clean exit
                    child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=5)
                    return True
                
                # Check for banner after authentication (need to find prompt)
                elif auth_index == len(auth_failure_patterns) + len(prompt_patterns) + 1:
                    verify_logger.info("Got APIC banner after authentication, looking for prompt")
                    if self._expect_shell_prompt(child, verify_logger):
                        print("Successfully authenticated to APIC")
                        child.sendline("exit")
                        return True
                
                # Timeout or EOF - check buffer for auth failures
                else:
                    buffer_content = child.before.lower() if child.before else ""
                    # Clean buffer content
                    buffer_content = CommandOutputProcessor.clean_output(buffer_content, apic_addr)
                    verify_logger.debug(f"Buffer after timeout: {buffer_content}")
                    
                    # Check for auth failure indicators in buffer
                    if any(indicator in buffer_content for indicator in auth_failure_patterns):
                        verify_logger.error("Authentication failure detected in buffer")
                        if attempt < max_attempts - 1:
                            self._retry_with_new_password()
                        else:
                            print("\033[1;31mAuthentication failed. Invalid credentials.\033[0m")
                        continue
                    
                    # If no auth failure in buffer, treat as connection issue
                    error_type = "timeout" if auth_index == len(auth_patterns) - 2 else "connection closed"
                    verify_logger.error(f"Connection issue after sending password: {error_type}")
                    if attempt < max_attempts - 1:
                        self._handle_connection_error(verify_logger, "after sending password")
                        continue
                
            except Exception as e:
                verify_logger.error(f"Exception during authentication: {str(e)}")
                verify_logger.debug(f"Exception traceback: {traceback.format_exc()}")
                if attempt < max_attempts - 1:
                    print(f"\033[1;31mError connecting to APIC: {str(e)}. Please try again.\033[0m")
                    self.password = getpass(f"Password for {self.username}: ")
                    print()
                continue
        
        # If we get here without returning True, authentication failed
        verify_logger.error("Authentication failure after multiple attempts.")
        return False

    def _expect_password_prompt(self, child, logger):
        """Helper to wait for password prompt after banner"""
        try:
            k = child.expect(['assword:', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
            if k == 0:
                logger.info("Found password prompt after banner")
                return True
            logger.error(f"Password prompt not found after banner: {k}")
            return False
        except Exception as e:
            logger.error(f"Error waiting for password prompt: {str(e)}")
            return False

    def _expect_shell_prompt(self, child, logger):
        """Helper to wait for shell prompt after banner"""
        try:
            prompt_index = child.expect(['#', '%', '>', pexpect.TIMEOUT], timeout=5)
            if prompt_index < 3:
                logger.info(f"Found prompt after banner: {child.match.group(0)}")
                return True
            logger.error("Failed to find prompt after banner")
            return False
        except Exception as e:
            logger.error(f"Error waiting for shell prompt: {str(e)}")
            return False

    def _retry_with_new_password(self):
        """Helper to ask for new password during retry"""
        print("\033[1;31mAuthentication failed. Please try again.\033[0m")
        self.password = getpass(f"Password for {self.username}: ")
        print()

    def _handle_connection_error(self, logger, context=""):
        """Helper to handle connection errors during authentication"""
        print(f"\033[1;31mConnection issue with APIC {context}. Please try again.\033[0m")
        self.password = getpass(f"Password for {self.username}: ")
        print()

    def get_credentials(self):
        """Prompt user for credentials"""
        if not self.username or not self.password:
            self.username = input("Username: ")
            self.password = getpass(f"Password for {self.username}: ")
            print()  # Print newline after password input
        
        return self.username, self.password

    def _get_fabric_node_data(self):
        """Get and cache fabricNode data for all functions to use"""
        if self._fabric_node_data is None:
            try:
                logger.info("Querying fabricNode API to collect switch information")
                cmd = "icurl -gs 'http://127.0.0.1:7777/api/class/fabricNode.json'"
                output = subprocess.check_output(cmd, shell=True, text=True)
                
                # Parse the JSON response
                try:
                    data = json.loads(output)
                    self._fabric_node_data = data
                    logger.debug(f"Collected {len(data.get('imdata', []))} nodes from fabricNode API")
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON from fabricNode API: {str(e)}")
                    raise RuntimeError("Failed to parse fabricNode API response")
                    
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to execute icurl command: {str(e)}")
                raise RuntimeError("Failed to retrieve switch information from API")
                
        return self._fabric_node_data

    def get_switches_by_role(self, role="all", filter_modular=None, active_only=True):
        """
        Get switch IPs based on role, modular status, and active state
        
        Args:
            role (str): Switch role to filter by - "leaf", "spine", or "all"
            filter_modular (bool): If True, return only modular switches.
                                If False, return only non-modular switches.
                                If None, return all switches regardless of modular status.
            active_only (bool): Whether to return only active switches
        
        Returns:
            list: List of IP addresses matching the criteria
        """
        # Generate a unique cache key based on the parameters
        cache_key = f"switches_{role}_{filter_modular}_{active_only}"
        
        if cache_key not in self.switch_cache:
            try:
                switch_ips = []
                fabric_data = self._get_fabric_node_data()
                
                logger.debug(f"Extracting switches with role={role}, modular={filter_modular}, active={active_only}")
                
                for item in fabric_data.get('imdata', []):
                    node = item.get('fabricNode', {}).get('attributes', {})
                    
                    # Apply role filter
                    if role != "all" and node.get('role') != role:
                        continue
                        
                    # Apply active state filter
                    if active_only and node.get('fabricSt') != 'active':
                        continue
                    
                    # Apply modular filter for spine switches
                    is_modular = node.get('model', '').startswith('N9K-C95')
                    if filter_modular is not None and node.get('role') == 'spine':
                        if filter_modular != is_modular:
                            continue
                    
                    ip = node.get('address')
                    node_id = node.get('id')
                    
                    if ip:
                        switch_ips.append(ip)
                        # Store the node ID mapped to the IP
                        self.switch_ids[ip] = node_id
                        logger.debug(f"Found switch: {node.get('name')} ({ip}), ID: {node_id}, role: {node.get('role')}")
                
                self.switch_cache[cache_key] = switch_ips
                logger.info(f"Found {len(switch_ips)} switches matching criteria: role={role}, modular={filter_modular}, active={active_only}")
                
            except Exception as e:
                logger.error(f"Failed to extract switch info: {str(e)}")
                self.switch_cache[cache_key] = []
                raise RuntimeError(f"Failed to retrieve switch information: {str(e)}")
                
        return self.switch_cache[cache_key]
     
    def get_switch_name(self, sw_ip):
        """Get switch name from IP using the fabricNode API data"""
        # Get a dedicated logger to avoid duplicates
        name_logger = get_logger("switch_names")
        
        # First check if we already have this switch name cached
        if sw_ip in self.switch_names:
            return self.switch_names[sw_ip]
        
        # If someone else is already building the cache, wait briefly
        if self._building_cache:
            time.sleep(0.2)  # Short sleep to let the other thread finish
            # Check again after waiting
            if sw_ip in self.switch_names:
                return self.switch_names[sw_ip]
        
        # If not in cache yet and no one is building it, extract all switch names at once from the API
        if not self.switch_names and not self._building_cache:
            try:
                self._building_cache = True  # Set flag to prevent other threads
                
                # Log only once
                name_logger.debug("Building switch name cache from fabricNode API data")
                
                # Get the fabricNode data
                fabric_data = self._get_fabric_node_data()
                
                # Extract all IP to name mappings in one pass
                for item in fabric_data.get('imdata', []):
                    node = item.get('fabricNode', {}).get('attributes', {})
                    
                    # Only process active switches (leaf and spine)
                    if node.get('fabricSt') == 'active' and node.get('role') in ['leaf', 'spine']:
                        ip = node.get('address')
                        name = node.get('name')
                        
                        if ip and name:
                            self.switch_names[ip] = name
                            
                            # Debug output only for the requested IP
                            if ip == sw_ip:
                                name_logger.debug(f"Mapped IP {ip} to name {name}")
                
                # Log how many mappings we found
                name_logger.info(f"Found {len(self.switch_names)} IP-to-name mappings in fabricNode API")
                
            except Exception as e:
                name_logger.error(f"Error building switch name cache: {str(e)}")
                name_logger.debug(f"Exception details: {traceback.format_exc()}")
            
            finally:
                self._building_cache = False  # Always reset flag when done
        
        # If we STILL don't have the name after all attempts, use IP-based fallback
        if sw_ip not in self.switch_names:
            # Extract node ID from fabricNode data to use in the fallback name
            node_id = None
            fabric_data = self._get_fabric_node_data()
            
            for item in fabric_data.get('imdata', []):
                node = item.get('fabricNode', {}).get('attributes', {})
                if node.get('address') == sw_ip:
                    node_id = node.get('id')
                    break
            
            # Use node ID in the fallback name if available
            if node_id:
                self.switch_names[sw_ip] = f"node-{node_id}"
                name_logger.debug(f"No name found for {sw_ip}, using fallback with node ID: {self.switch_names[sw_ip]}")
            else:
                self.switch_names[sw_ip] = f"switch-{sw_ip}"
                name_logger.debug(f"No name found for {sw_ip}, using fallback: {self.switch_names[sw_ip]}")
        
        return self.switch_names[sw_ip]

    def get_switch_id(self, sw_ip):
        """Get switch node ID from IP using the cached data"""
        # If we haven't built the cache yet, ensure we have all IPs
        if not self.switch_ids:
            # Force loading of all switches to build the complete ID cache
            self.get_leaf_switches()
            self.get_spine_switches()
            self.get_modular_spine_ips()
        
        # Return the ID if found, otherwise return None
        if sw_ip in self.switch_ids:
            return self.switch_ids[sw_ip]
        
        # If still not found, try to extract directly from API data
        if self._fabric_node_data:
            for item in self._fabric_node_data.get('imdata', []):
                node = item.get('fabricNode', {}).get('attributes', {})
                if node.get('address') == sw_ip:
                    node_id = node.get('id')
                    # Cache for future use
                    self.switch_ids[sw_ip] = node_id
                    return node_id
        
        # Return None if not found
        return None

    def get_switch_attributes_from_apic(self, attribute_type="memory"):
        """
        Get switch attribute data from APIC API
        
        Args:
            attribute_type (str): "memory" or "kickstart" to specify which data to retrieve
        
        Returns:
            dict: Dictionary mapping node IDs to requested attribute data
        """
        if attribute_type == "memory":
            api_class = "eqptDimm"
            logger.info("Getting switch memory capacity from APIC API")
        elif attribute_type == "kickstart":
            api_class = "firmwareRunning"
            logger.info("Getting switch kickstart images from APIC API")
        else:
            raise ValueError(f"Unsupported attribute type: {attribute_type}")
        
        # Build result dictionary
        result_data = {}
        
        try:
            # Query the API
            cmd = f"icurl -gs 'http://127.0.0.1:7777/api/class/{api_class}.json'"
            output = subprocess.check_output(cmd, shell=True, text=True)
            
            # Parse the JSON response
            try:
                data = json.loads(output)
                
                if attribute_type == "memory":
                    # Process memory data
                    for item in data.get('imdata', []):
                        dimm = item.get('eqptDimm', {}).get('attributes', {})
                        dn = dimm.get('dn', '')
                        cap = dimm.get('cap', '')
                        
                        # Extract node ID from DN
                        node_match = re.search(r'node-(\d+)', dn)
                        if node_match and cap:
                            node_id = node_match.group(1)
                            
                            # Skip APIC nodes (typically node IDs 1-30)
                            if node_id.isdigit() and 1 <= int(node_id) <= 30:
                                continue
                            
                            # Convert capacity to integer
                            try:
                                cap_value = int(cap)
                                
                                # If we already have a value for this node, sum it up
                                if node_id in result_data:
                                    result_data[node_id]['kb'] += cap_value
                                else:
                                    result_data[node_id] = {'kb': cap_value}
                                    
                                logger.debug(f"Node {node_id} DIMM from {dn}: {cap_value} KB")
                            except ValueError:
                                logger.debug(f"Invalid memory capacity value for node {node_id}: {cap}")
                    
                    # Standardize memory to GB values
                    for node_id, mem_info in result_data.items():
                        kb_value = mem_info['kb']
                        if kb_value < 20000:
                            mem_info['gb'] = 16
                        elif kb_value < 30000:
                            mem_info['gb'] = 24
                        elif kb_value < 40000:
                            mem_info['gb'] = 32
                        elif kb_value < 70000 and kb_value > 60000:
                            mem_info['gb'] = 64
                        else:
                            mem_info['gb'] = round(kb_value / 1024)
                    
                elif attribute_type == "kickstart":
                    # Process kickstart image data
                    for item in data.get('imdata', []):
                        fw_running = item.get('firmwareRunning', {}).get('attributes', {})
                        dn = fw_running.get('dn', '')
                        ks_file = fw_running.get('ksFile', '')
                        mode = fw_running.get('mode', '')
                        
                        # Extract node ID from DN
                        node_match = re.search(r'node-(\d+)', dn)
                        if node_match and ks_file:
                            node_id = node_match.group(1)
                            
                            # Skip APIC nodes (typically node IDs 1-30)
                            if node_id.isdigit() and 1 <= int(node_id) <= 30:
                                continue
                            
                            # Handle recovery and normal boot modes
                            if ks_file.startswith('recovery:'):
                                # Recovery mode pattern
                                image_match = re.search(r'recovery:(?:\/+)?([^\/]+\.bin)$', ks_file)
                                if image_match:
                                    image_name = image_match.group(1)
                                    result_data[node_id] = {
                                        'ksFile': ks_file,
                                        'image_name': image_name,
                                        'full_path': f"/recovery/{image_name}",
                                        'mode': 'recovery'
                                    }
                                    logger.debug(f"Node {node_id} kickstart image (recovery mode): {image_name}")
                                else:
                                    logger.debug(f"Could not extract image name from recovery ksFile: {ks_file}")
                            else:
                                # Normal boot mode pattern
                                image_match = re.search(r'bootflash:(?:\/+)?([^\/]+\.bin)$', ks_file)
                                if image_match:
                                    image_name = image_match.group(1)
                                    result_data[node_id] = {
                                        'ksFile': ks_file,
                                        'image_name': image_name,
                                        'full_path': f"/bootflash/{image_name}",
                                        'mode': 'normal'
                                    }
                                    logger.debug(f"Node {node_id} kickstart image (normal mode): {image_name}")
                                else:
                                    logger.debug(f"Could not extract image name from ksFile: {ks_file}")
                
                logger.info(f"Retrieved {attribute_type} data for {len(result_data)} switches")
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON from {api_class} API: {str(e)}")
                raise RuntimeError(f"Failed to parse {api_class} API response")
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to execute {api_class} API query: {str(e)}")
            raise RuntimeError(f"Failed to retrieve switch {attribute_type} information from API")
        
        return result_data

    def load_switch_memory(self):
        """Load memory data for all switches from APIC API"""
        if not hasattr(self, 'switch_memory'):
            self.switch_memory = {}
            
        if not self.switch_memory:
            try:
                self.switch_memory = self.get_switch_attributes_from_apic(attribute_type="memory")
                logger.info(f"Loaded memory data for {len(self.switch_memory)} switches")
            except Exception as e:
                logger.error(f"Failed to load switch memory data: {str(e)}")
                # Continue with empty dict - will fall back to show version
        
        return self.switch_memory

    def load_switch_kickstart_images(self):
        """Load kickstart image data for all switches from APIC API"""
        if not hasattr(self, 'switch_kickstart'):
            self.switch_kickstart = {}
            
        if not self.switch_kickstart:
            try:
                self.switch_kickstart = self.get_switch_attributes_from_apic(attribute_type="kickstart")
                logger.info(f"Loaded kickstart image data for {len(self.switch_kickstart)} switches")
            except Exception as e:
                logger.error(f"Failed to load switch kickstart image data: {str(e)}")
                # Continue with empty dict - will fall back to show version
        
        return self.switch_kickstart

###########################################
# Switch Data Collection and Processing
###########################################

class SwitchDataCollector:
    """Centralized handler for switch data collection and validation"""
    
    @staticmethod
    def extract_memory(version_output):
        """Extract memory capacity from version output"""
        memory_match = re.search(MEMORY_PATTERN, version_output)
        if memory_match:
            return int(memory_match.group(1))
        return None
    
    @staticmethod
    def extract_image_path(version_output):
        """Extract kickstart image path using multiple patterns, handling recovery mode"""
        # First check for recovery mode indicator
        recovery_mode = False
        if "boot mode is: recovery" in version_output.lower():
            recovery_mode = True
        
        # Try the standard kickstart patterns
        for pattern in IMAGE_PATH_PATTERNS:
            image_match = re.search(pattern, version_output)
            if image_match:
                image_path = image_match.group(1)
                
                # If image path contains "recovery:" or we detected recovery mode
                if "recovery:" in image_path or recovery_mode:
                    # Extract the image filename
                    filename_match = re.search(r'([^\/\\:]+\.bin)$', image_path)
                    if filename_match:
                        return f"/recovery/{filename_match.group(1)}"
                
                return image_path
        
        return None
    
    @staticmethod
    def extract_md5(md5_output, switch_name=None):
        """
        Extract MD5 hash from command output
        
        Args:
            md5_output (str): Output from md5sum command
            switch_name (str, optional): Switch hostname to clean from output
            
        Returns:
            str or None: The extracted MD5 hash if found, otherwise None
        """
        # Use CommandOutputProcessor to parse the MD5 output
        md5_result = CommandOutputProcessor.parse_md5_output(md5_output, switch_name)
        
        # Return the hash if successful, otherwise None
        return md5_result["md5_hash"] if md5_result["success"] else None

    @staticmethod
    def extract_file_info(output, switch_name=None):
        """
        Extract file information from command output.
        
        Args:
            output: Command output from ls -l command
            switch_name: Optional switch name to clean from output
            
        Returns:
            dict: Dictionary with file_owner, file_group, file_permissions, file_line
        """
        info = {
            "file_owner": None,
            "file_group": None, 
            "file_permissions": None,
            "file_line": None
        }
        
        # Process each line looking for the bin file
        for line in output.splitlines():
            if not line or line.startswith("ls ") or (switch_name and line.strip() == switch_name):
                continue
                
            if ".bin" in line:
                # Clean up hostname if present
                cleaned_line = line
                if switch_name and switch_name in line:
                    cleaned_line = line[:line.find(switch_name)].strip()
                
                # Store the raw line
                info["file_line"] = cleaned_line
                
                # Try regex extraction first
                owner_match = re.search(r'(?:-[rwx-]+)?\s+\d+\s+(\S+)\s+(\S+)', cleaned_line)
                if owner_match:
                    info["file_owner"] = owner_match.group(1)
                    info["file_group"] = owner_match.group(2)
                    
                    # Get permissions if available
                    perm_match = re.search(r'(-[rwx-]+)\s+\d+\s+', cleaned_line)
                    info["file_permissions"] = perm_match.group(1) if perm_match else "-unknown-"
                    
                    # Format complete details
                    info["file_details"] = f"{info['file_permissions']} {info['file_owner']} {info['file_group']}"
                    return info
                
                # Fallback: try simple split by whitespace
                parts = cleaned_line.split()
                if len(parts) >= 5:
                    try:
                        info["file_permissions"] = parts[0] if parts[0].startswith('-') else "-unknown-"
                        info["file_owner"] = parts[2]
                        info["file_group"] = parts[3]
                        info["file_details"] = f"{info['file_permissions']} {info['file_owner']} {info['file_group']}"
                        return info
                    except IndexError:
                        pass
        
        return info

    @staticmethod
    def extract_file_owner_info(conn, image_path, switch_data, diagnostics):
        """
        Extract file owner information for a file with permission issues
        
        Args:
            conn: Connection object
            image_path: Path to the image file
            switch_data: Dict to update with file owner info
            diagnostics: Dict to update with diagnostic info
        """
        try:
            result_type, ls_output = conn.execute_command(f"ls -lh {image_path}")
            
            # Store the raw ls output
            switch_data["raw_ls_output"] = ls_output.strip()
            diagnostics["raw_ls_output"] = ls_output.strip()
            
            # Use the centralized helper function
            get_kickstart_ownership(ls_output, switch_data.get("switch", ""), 
                                        switch_data, diagnostics)
                        
        except Exception as e:
            diagnostics["file_info_error"] = str(e)

    @staticmethod
    def collect_data(sw_name, sw_ip, conn, switch_info=None, kickstart_image=None, memory_kb=None, memory_gb=None):
        """
        Collect all required data from a switch
        
        Args:
            sw_name: Switch name for identification
            sw_ip: Switch IP address
            conn: An established SSH connection object
            switch_info: SwitchInfo instance with pre-collected data
            kickstart_image: Pre-collected kickstart image path (optional)
            memory_kb: Pre-collected memory in KB (optional)
            memory_gb: Pre-collected memory in GB (optional)
            
        Returns:
            dict: Dictionary containing collected switch data
        """
        result = {"switch": sw_name, "ip": sw_ip, "status": "unknown"}

        # If kickstart_image was provided directly, use it
        if kickstart_image:
            result["image_path"] = kickstart_image

        # If memory information was provided directly, use it
        if memory_kb is not None:
            result["memory_kb"] = memory_kb
        if memory_gb is not None:
            result["memory_gb"] = memory_gb

        try:
            # Only try to get data from switch_info if we don't already have direct values
            if switch_info and (kickstart_image is None or memory_kb is None):
                # Get node ID for this switch
                node_id = switch_info.get_switch_id(sw_ip)
                
                # Try to get memory data if not provided directly
                if memory_kb is None and memory_gb is None and node_id and hasattr(switch_info, 'switch_memory') and node_id in switch_info.switch_memory:
                    # Get both KB and GB values if available
                    mem_info = switch_info.switch_memory[node_id]
                    if isinstance(mem_info, dict) and 'kb' in mem_info and 'gb' in mem_info:
                        result["memory_kb"] = mem_info['kb']
                        result["memory_gb"] = mem_info['gb']
                        logger.debug(f"Using pre-collected memory data for {sw_name}: {mem_info['kb']} KB ({mem_info['gb']} GB)")
                    else:
                        # Handle case where mem_info is just the KB value (backward compatibility)
                        result["memory_kb"] = mem_info
                        # Convert to standardized GB value using MemoryCheck
                        result["memory_gb"] = MemoryCheck.standardize_memory_gb(mem_info)
                        logger.debug(f"Converted memory data for {sw_name}: {mem_info} KB to {result['memory_gb']} GB")
                
                # Try to get kickstart image data if not provided directly
                if kickstart_image is None and node_id and hasattr(switch_info, 'switch_kickstart') and node_id in switch_info.switch_kickstart:
                    kickstart_data = switch_info.switch_kickstart[node_id]
                    result["image_path"] = kickstart_data['full_path']
                    # Store boot mode if available
                    if 'mode' in kickstart_data:
                        result["boot_mode"] = kickstart_data['mode']
                    logger.debug(f"Using pre-collected kickstart image for {sw_name}: {result['image_path']}")
            
            # Get version info only if we couldn't get kickstart image OR memory data
            if result.get("image_path") is None or (result.get("memory_kb") is None and result.get("memory_gb") is None):
                result_type, version_output = conn.execute_command("show version")
                if result_type != "success":
                    raise RuntimeError(f"Failed to get version info: {result_type}")
                    
                # Clean output using CommandOutputProcessor
                cleaned_version_output = CommandOutputProcessor.clean_output(version_output, sw_name)
                    
                # If memory wasn't retrieved, try extracting it from show version
                if result.get("memory_kb") is None and result.get("memory_gb") is None:
                    memory_kb = SwitchDataCollector.extract_memory(cleaned_version_output)
                    # Convert to standardized GB value using MemoryCheck
                    if memory_kb:
                        result["memory_kb"] = memory_kb
                        result["memory_gb"] = MemoryCheck.standardize_memory_gb(memory_kb)
                
                # Extract kickstart image path if we don't have it yet
                if result.get("image_path") is None:
                    image_path = SwitchDataCollector.extract_image_path(cleaned_version_output)
                    result["image_path"] = image_path
            
            # Get MD5 checksum of the image if we have a path
            if result.get("image_path"):
                # Get MD5 checksum of the image
                kickstart_image = result["image_path"]
                result_type, md5_output = conn.execute_command(f"md5sum {kickstart_image}")
                
                # Process MD5 output using CommandOutputProcessor instead of MD5Processor
                md5_result = CommandOutputProcessor.parse_md5_output(md5_output, sw_name)
                
                # Store the command output to help diagnose MD5 retrieval failures
                result["md5_command_output"] = md5_output
                
                # Check if there was an error
                if not md5_result["success"]:
                    # Store error information
                    result["md5_error_type"] = md5_result["error_type"]
                    result["md5_error_message"] = md5_result["error_message"]
                    
                    # If we have a permission error, and we haven't fixed permissions yet
                    if md5_result["error_type"] == "permission" and not result.get("ownership_fixed"):
                        # Traditional retry with chmod if we didn't already fix permissions
                        conn.execute_command(f"chmod 666 {kickstart_image}")
                        result_type, retry_output = conn.execute_command(f"md5sum {kickstart_image}")
                        
                        # Process retry output using CommandOutputProcessor
                        retry_result = CommandOutputProcessor.parse_md5_output(retry_output, sw_name)
                        result["md5_command_output"] = retry_output
                        
                        if retry_result["success"]:
                            # Retry was successful
                            result["md5sum"] = retry_result["md5_hash"]
                            # Clear error information
                            result.pop("md5_error_type", None)
                            result.pop("md5_error_message", None)
                        else:
                            # Retry failed, keep error information
                            result["md5_retry_error_type"] = retry_result["error_type"]
                            result["md5_retry_error_message"] = retry_result["error_message"]
                else:
                    # No error, store the hash
                    result["md5sum"] = md5_result["md5_hash"]
                
            # Set status to success if we got the critical information
            if ((result.get("memory_kb") is not None or result.get("memory_gb") is not None) and 
                (result.get("image_path") is not None or result.get("md5sum") is not None)):
                result["status"] = "success"
            else:
                result["status"] = "incomplete"
                
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            
        return result
    
    @staticmethod
    def validate_image(switch_data, md5_32bit, md5_64bit):
        """
        Validate switch image against memory capacity
        
        Args:
            switch_data: Dictionary containing switch information
            md5_32bit: MD5 checksum for 32-bit image
            md5_64bit: MD5 checksum for 64-bit image
            
        Returns:
            tuple: (result, message) where result is one of "PASS", "FAIL", "WARNING", "ERROR"
        """
        if switch_data.get("status") != "success":
            error_details = switch_data.get("error", "unknown error")
            return "ERROR", f"Could not retrieve complete information: {error_details}"
        
        # Extract memory data
        memory_kb = switch_data.get("memory_kb")
        memory_gb = switch_data.get("memory_gb")
        md5sum = switch_data.get("md5sum")
        
        # More specific error messages based on what's missing
        if not memory_kb and not memory_gb and not md5sum:
            return "ERROR", "Could not retrieve Memory and MD5 information"
        elif not memory_kb and not memory_gb:
            return "ERROR", "Could not retrieve Memory information"
        elif not md5sum:
            return "ERROR", "Could not retrieve MD5 information"
        
        # Determine image type based on MD5
        if md5sum == md5_32bit:
            image_type = "32bit"
        elif md5sum == md5_64bit:
            image_type = "64bit"
        else:
            return "WARNING", f"Running an unexpected image (MD5: {md5sum})"
        
        # Use MemoryCheck class to validate image against memory
        return MemoryCheck.validate_image_for_memory(memory_kb, memory_gb, image_type)
    
    @staticmethod
    def categorize_error(switch_data):
        """
        Categorize errors in switch data collection
        
        Args:
            switch_data: Dictionary containing switch data
            
        Returns:
            dict: Dictionary with error categorization
        """
        diagnostics = {"error_type": None}
        
        if switch_data.get("status") != "error" and "error" not in switch_data:
            return diagnostics
            
        error_msg = switch_data.get("error", "").lower()
        
        if "memory" in error_msg:
            diagnostics["error_type"] = "memory_retrieval"
            diagnostics["memory_error"] = error_msg
        elif "md5" in error_msg or "checksum" in error_msg:
            diagnostics["error_type"] = "md5_retrieval"
            diagnostics["md5_error"] = error_msg
        elif "permission" in error_msg:
            diagnostics["error_type"] = "permission"
            diagnostics["permission_error"] = error_msg
        elif "image" in error_msg or "file" in error_msg:
            diagnostics["error_type"] = "image_file"
            diagnostics["file_error"] = error_msg
        
        # Special handling for MD5 retrieval failures
        if not switch_data.get("md5sum") and switch_data.get("md5_command_output"):
            md5_output = switch_data.get("md5_command_output", "").lower()
            
            if "permission denied" in md5_output:
                diagnostics["error_type"] = "md5_retrieval"
                diagnostics["md5_error"] = "Permission denied when accessing image file"
                diagnostics["command_output"] = md5_output
            elif "no such file" in md5_output:
                diagnostics["error_type"] = "md5_retrieval"
                diagnostics["md5_error"] = "Image file not found"
                diagnostics["command_output"] = md5_output
            else:
                diagnostics["error_type"] = "md5_retrieval"
                diagnostics["md5_error"] = "Unknown error retrieving MD5"
                diagnostics["command_output"] = md5_output
                
        return diagnostics
    
    @staticmethod
    def get_error_message(switch_data, diagnostics):
        """Generate appropriate error message based on diagnostics"""
        if not switch_data.get("memory_kb"):
            if not switch_data.get("image_path"):
                diagnostics["error_type"] = "data_collection"
                return "Could not retrieve Memory information or Image path"
            else:
                diagnostics["error_type"] = "memory_retrieval"
                return "Could not retrieve Memory information"
        elif not switch_data.get("md5sum"):
            diagnostics["error_type"] = "md5_retrieval"
            
            # If we have the command output, add it directly to diagnostics
            if "md5_command_output" in switch_data:
                # Store the full command output in diagnostics
                diagnostics["command_output"] = switch_data["md5_command_output"]
                md5_output = switch_data["md5_command_output"].lower() if switch_data["md5_command_output"] else ""
                
                # Add error details based on output content
                if "permission denied" in md5_output:
                    diagnostics["error_details"] = "Permission denied when accessing image file"
                elif "no such file" in md5_output:
                    diagnostics["error_details"] = "Image file not found"
                else:
                    diagnostics["error_details"] = "Unknown error retrieving MD5"
                    
            return "Could not retrieve MD5 information"
        else:
            diagnostics["error_type"] = "data_collection"
            return f"Data collection incomplete: {switch_data.get('error', 'unknown error')}"

###########################################
# Result Logging and Reporting
###########################################

class ResultLogger:
    """Handles logging and result summarization"""
    
    def __init__(self, filename=None):
        """Initialize the logger with an optional filename"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y-%m-%d_%H%M')
            self.filename = f"smu-check-results-{timestamp}.txt"
        else:
            self.filename = filename
            
        self.start_time = time.time()
        self.lock = threading.Lock()  # For thread-safe file operations
        self._init_file()
        
        # ANSI color codes for result types
        self.colors = RESULT_COLORS
        
    def _init_file(self):
        """Initialize the output file with header information"""
        with self.lock:
            with open(self.filename, 'w') as f:
                f.write("======================================================\n")
                f.write(" ACI Switch SMU Pre-upgrade Validation Report\n")
                f.write(f" Generated on {datetime.now()}\n")
                f.write("======================================================\n\n")
    
    def log_message(self, message):
        """Log a message to the output file in a thread-safe manner"""
        with self.lock:
            with open(self.filename, 'a') as f:
                f.write(f"{message}\n")

    def _format_memory_display(self, memory_kb, memory_gb):
        """Format memory display using GB if available, otherwise KB"""
        return MemoryCheck.format_memory_display(memory_kb, memory_gb)

    def _format_switch_data(self, file, switch_data):
        """Format switch data for output file"""
        # Use the common formatter for the basic data
        formatted_data = format_switch_data_for_output(switch_data)
        
        # Write basic switch information
        file.write(f"\nSwitch: {formatted_data['switch']} ({formatted_data['ip']})\n")
        file.write(f"Memory: {formatted_data['memory_display']}\n")
        if formatted_data['boot_mode'] == "recovery":
            file.write(f"Boot Mode: \033[1;33mRecovery\033[0m\n")
        file.write(f"Image: {formatted_data['image_path']}\n")
        file.write(f"MD5sum: {formatted_data['md5sum']}\n")
        
        # Results section
        file.write("\nResults:\n")
        file.write(f"MD5sum Check   : {formatted_data['md5_result_colored']} {formatted_data['md5_message']}\n")
        file.write(f"Repodata Check : {formatted_data['repodata_result_colored']} {formatted_data['repodata_description']}\n")
        
        # Still call the class-specific recommendation and diagnostic formatters
        # These have special formatting for the file output that's not handled by the formatter
        self._add_recommendations(file, switch_data)
        self._add_diagnostics(file, switch_data)

    def _add_recommendations(self, file, switch_data):
        """Add recommendations based on results"""
        result = switch_data.get("result", "ERROR")
        repodata_result = switch_data.get("repodata_check", "ERROR")
        cmd_output = switch_data.get("md5_command_output", "")
        diagnostics = switch_data.get("diagnostics", {})
        
        # Check for permission denied
        permission_denied = cmd_output and "permission denied" in cmd_output.lower()
        
        # Only add recommendations if needed
        recommendations_needed = (result == "FAIL" or 
                                repodata_result == "FAIL" or 
                                permission_denied)
        
        if not recommendations_needed:
            return
            
        file.write("\nRecommendations:\n")
        
        # Different recommendations based on conditions
        if permission_denied:
            file.write("Re-run the script from the owner account or root to rectify the permissions issue.\n")
            
            # Look for owner information using centralized extraction
            owner = None
            
            # Try extracting owner info from various sources
            if "raw_ls_output" in switch_data:
                file_info = get_kickstart_ownership(
                    switch_data["raw_ls_output"],
                    switch_data.get("switch", "")
                )
                if file_info["file_owner"]:
                    owner = file_info["file_owner"]
            
            # Other owner extraction logic...
            
            # If we found the owner, display it
            if owner:
                file.write(f"The owner of the file is: {owner}\n")
        
        # Add recommendations for other failure types
        if result == "FAIL" and not permission_denied:
            file.write("Contact Cisco TAC for assistance in setting boot variable to use correct switch image.\n\n")
            file.write("Defect Reference:\nhttps://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj44966\n")
            
        if repodata_result == "FAIL":
            if permission_denied or result == "FAIL":
                file.write("\n")  # Add separator line
            file.write("Contact Cisco TAC to remove .repodata file via root user.\n\n")
            file.write("Defect Reference:\nhttps://bst.cloudapps.cisco.com/bugsearch/bug/CSCwo34637\n")

    def _add_diagnostics(self, file, switch_data):
        """Add diagnostics information if there are errors"""
        result = switch_data.get("result", "ERROR")
        md5sum = switch_data.get("md5sum")
        cmd_output = switch_data.get("md5_command_output", "")
        diagnostics = switch_data.get("diagnostics", {})
        
        # Only add diagnostics for errors or missing MD5
        if result != "ERROR" and md5sum is not None:
            return
            
        file.write("\nDiagnostics:\n")
        
        # Check for permission denied in the output
        if cmd_output and "permission denied" in cmd_output.lower():
            # Use CommandOutputProcessor to extract the permission denied line
            permission_line = CommandOutputProcessor.extract_single_line(cmd_output, "permission denied", 
                                                                    switch_data.get("switch", ""))
            if permission_line:
                file.write(f"{permission_line}\n")
            
            # Now find and display the file info using centralized extraction
            file_info_displayed = False
            
            # Try getting file info from various locations
            if not file_info_displayed and "raw_ls_output" in switch_data:
                file_info = get_kickstart_ownership(
                    switch_data["raw_ls_output"], 
                    switch_data.get("switch", ""),
                    None  # Don't update any dictionaries, just get the info
                )
                if file_info["file_line"]:
                    file.write(f"{file_info['file_line']}\n")
                    file_info_displayed = True
                elif file_info["file_details"]:
                    file.write(f"{file_info['file_details']}\n")
                    file_info_displayed = True
            
            # Try diagnostics raw_ls_output if needed
            if not file_info_displayed and diagnostics and "raw_ls_output" in diagnostics:
                file_info = get_kickstart_ownership(
                    diagnostics["raw_ls_output"], 
                    switch_data.get("switch", ""),
                    None  # Don't update any dictionaries, just get the info
                )
                if file_info["file_line"]:
                    file.write(f"{file_info['file_line']}\n")
                    file_info_displayed = True
                elif file_info["file_details"]:
                    file.write(f"{file_info['file_details']}\n")
                    file_info_displayed = True
            
            # Try component parts if needed
            if not file_info_displayed and "file_details" in switch_data:
                file.write(f"{switch_data['file_details']}\n")
                file_info_displayed = True
            elif not file_info_displayed and diagnostics and "file_details" in diagnostics:
                file.write(f"{diagnostics['file_details']}\n")
                file_info_displayed = True
            elif not file_info_displayed and "file_permissions" in switch_data and "file_owner" in switch_data:
                file.write(f"{switch_data['file_permissions']} {switch_data['file_owner']} {switch_data['file_group']}\n")
                file_info_displayed = True
            elif not file_info_displayed and diagnostics and "file_permissions" in diagnostics:
                file.write(f"{diagnostics['file_permissions']} {diagnostics['file_owner']} {diagnostics['file_group']}\n")
                file_info_displayed = True
        
        # If no permission denied or no file info found, show the command output directly
        elif cmd_output:
            # Use CommandOutputProcessor to clean and format the output
            cleaned_output = CommandOutputProcessor.clean_output(cmd_output, switch_data.get("switch", ""))
            formatted_output = CommandOutputProcessor.format_for_display(cleaned_output)
            file.write(f"{formatted_output}\n")

    def log_switch_result(self, switch_data):
        """Log data for a single switch with specific error details, diagnostics, and recommendations"""
        # Use the common formatter for basic data, but not recommendations
        formatted_data = format_switch_data_for_output(switch_data, include_diagnostics=True)
        
        with self.lock:
            # Initialize the first_switch flag if it doesn't exist
            if not hasattr(self, 'first_switch_logged'):
                self.first_switch_logged = False
            
            with open(self.filename, 'a') as f:
                # Add separator line ONLY before the first switch
                if not self.first_switch_logged:
                    f.write("----------------------------------------\n")
                    self.first_switch_logged = True
                
                # Basic switch information
                f.write(f"\nSwitch: {formatted_data['switch']} ({formatted_data['ip']})\n")
                f.write(f"Memory: {formatted_data['memory_display']}\n")
                if formatted_data['boot_mode'] == "recovery":
                    f.write(f"Boot Mode: \033[1;33mRecovery\033[0m\n")
                f.write(f"Image: {formatted_data['image_path']}\n")
                f.write(f"MD5sum: {formatted_data['md5sum']}\n")
                
                # Results section
                f.write("\nResults:\n")
                f.write(f"MD5sum Check   : {formatted_data['md5_result_colored']} {formatted_data['md5_message']}\n")
                f.write(f"Repodata Check : {formatted_data['repodata_result_colored']} {formatted_data['repodata_description']}\n")
                
                # Instead of using recommendations from formatted_data, use the class method
                # This ensures consistent formatting of recommendations
                self._add_recommendations(f, switch_data)
                
                # Add diagnostics for errors or missing MD5
                if formatted_data['result'] == "ERROR" or formatted_data['md5sum'] is None:
                    f.write("\nDiagnostics:\n")
                    
                    if 'diagnostics' in formatted_data:
                        diag = formatted_data['diagnostics']
                        
                        # Handle permission denied specially
                        if formatted_data['permission_denied']:
                            if 'permission_line' in diag:
                                f.write(f"{diag['permission_line']}\n")
                            if 'file_info' in diag:
                                f.write(f"{diag['file_info']}\n")
                        
                        # Show command output for other cases
                        elif 'command_output' in diag:
                            f.write(f"{diag['command_output']}\n")
                
                # Keep the separator line at the end of each switch entry
                f.write("----------------------------------------\n")
    
    def generate_summary(self, total_switches):
        """Generate summary statistics from the log file"""
        try:
            with open(self.filename, 'r') as f:
                content = f.read()
                
            # Look for result labels in the "MD5sum Check" lines
            pass_pattern = r'MD5sum Check\s+:\s+\033\[1;32mPASS\033\[0m|MD5sum Check\s+:\s+PASS'
            fail_pattern = r'MD5sum Check\s+:\s+\033\[1;31mFAIL\033\[0m|MD5sum Check\s+:\s+FAIL'
            warning_pattern = r'MD5sum Check\s+:\s+\033\[1;33mWARNING\033\[0m|MD5sum Check\s+:\s+WARNING'
            error_pattern = r'MD5sum Check\s+:\s+\033\[1;31mERROR\033\[0m|MD5sum Check\s+:\s+ERROR'
            
            # Patterns for Repodata Check results
            repodata_pass_pattern = r'Repodata Check\s+:\s+\033\[1;32mPASS\033\[0m|Repodata Check\s+:\s+PASS'
            repodata_fail_pattern = r'Repodata Check\s+:\s+\033\[1;31mFAIL\033\[0m|Repodata Check\s+:\s+FAIL'
            repodata_error_pattern = r'Repodata Check\s+:\s+\033\[1;31mERROR\033\[0m|Repodata Check\s+:\s+ERROR'
            
            pass_count = len(re.findall(pass_pattern, content))
            fail_count = len(re.findall(fail_pattern, content))
            warning_count = len(re.findall(warning_pattern, content))
            error_count = len(re.findall(error_pattern, content))
            
            # Repodata Check counts
            repodata_pass_count = len(re.findall(repodata_pass_pattern, content))
            repodata_fail_count = len(re.findall(repodata_fail_pattern, content))
            repodata_error_count = len(re.findall(repodata_error_pattern, content))
            
            # Calculate total for averages
            sum_counted = pass_count + fail_count + warning_count + error_count
            if sum_counted == 0:
                error_count = total_switches
                sum_counted = max(total_switches, 1)  # Ensure we don't divide by zero
            
            # Calculate execution time
            exec_time = int(time.time() - self.start_time)
            avg_time = exec_time // sum_counted if sum_counted > 0 else 0
            
            def format_time(seconds):
                minutes, secs = divmod(seconds, 60)
                return f"{minutes:02d}:{secs:02d}"
                
            # Create summary text
            summary = "\n"
            summary += "======================================================\n"
            summary += " Script execution complete\n"
            summary += f" Results saved to {self.filename}\n\n"
            summary += " MD5 Check Results:\n"
            summary += f" {self.colors['PASS']}PASS{self.colors['RESET']}   : {pass_count} switches\n"
            summary += f" {self.colors['FAIL']}FAIL{self.colors['RESET']}   : {fail_count} switches\n"
            summary += f" {self.colors['WARNING']}WARNING{self.colors['RESET']}: {warning_count} switches\n"
            summary += f" {self.colors['ERROR']}ERROR{self.colors['RESET']}  : {error_count} switches\n\n"
            summary += " Repodata Check Results:\n"
            summary += f" {self.colors['PASS']}PASS{self.colors['RESET']}     : {repodata_pass_count} switches\n"
            summary += f" {self.colors['FAIL']}FAIL{self.colors['RESET']}     : {repodata_fail_count} switches\n"
            summary += f" {self.colors['ERROR']}ERROR{self.colors['RESET']}    : {repodata_error_count} switches\n\n"
            summary += " Runtime Statistics:\n"
            summary += f" Total Execution Time: {format_time(exec_time)}\n"
            summary += f" Avg Time Per Switch : {format_time(avg_time)}\n"
            summary += "======================================================\n"
            
            # Write to file with color codes
            with self.lock:
                with open(self.filename, 'a') as f:
                    f.write(summary)
            
            # For console output, colors are already applied
            print_summary = summary
            print(print_summary)
            
            return {
                "pass": pass_count,
                "fail": fail_count,
                "warning": warning_count,
                "error": error_count,
                "repodata_pass": repodata_pass_count,
                "repodata_fail": repodata_fail_count,
                "repodata_error": repodata_error_count,
                "total_time": exec_time,
                "average_time": avg_time
            }
            
        except Exception as e:
            error_message = f"Error generating summary: {str(e)}"
            self.log_message(error_message)
            print(f"\033[1;31m{error_message}\033[0m")  # Critical errors still shown
            return None
    
    def check_leftover_files(self):
        """Check for and log information about leftover temporary files"""
        import glob
        
        self.log_message("\nChecking for leftover files...")
        temp_patterns = ["/tmp/result_*", "/tmp/ssh_out_*", "/tmp/ssh_err_*", "/tmp/debug_*"]
        
        for pattern in temp_patterns:
            files = glob.glob(pattern)
            if files:
                self.log_message(f"Found {len(files)} files matching {pattern}:")
                for f in files:
                    stats = os.stat(f)
                    self.log_message(f"  {f}: {stats.st_size} bytes")
            else:
                self.log_message(f"No files found matching {pattern}")

###########################################
# UI and Progress Tracking
###########################################

class ProgressBar:
    """Terminal progress bar with real-time updates that works across different terminal types"""
    
    def __init__(self, total_items, script_start_time=None):
        """Initialize the progress bar with the total number of items"""
        self.total_items = total_items
        self.script_start_time = script_start_time or time.time()
        
        # Create a temp directory for progress files
        self.progress_dir = tempfile.mkdtemp(prefix="progress_")
        self.progress_file = os.path.join(self.progress_dir, "count")
        self.stage_file = os.path.join(self.progress_dir, "stage")
        self.control_file = os.path.join(self.progress_dir, "control")
        
        # Thread management
        self.status_thread = None
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.is_setup = False
        
        # Store original signal handlers
        self.original_sigint = None
        self.original_sigterm = None
        
        # State tracking
        self.current_count = 0
        self.current_stage = "Initializing..."
        
        # Create blank lines for the progress bar
        print("\n\n")
    
    def _init_files(self):
        """Initialize the tracking files in a single function"""
        os.makedirs(self.progress_dir, exist_ok=True)
        
        # Initialize all files at once
        with self.lock:
            with open(self.progress_file, "w") as f:
                f.write("0")
            with open(self.stage_file, "w") as f:
                f.write(self.current_stage)
            with open(self.control_file, "w") as f:
                f.write("running")
    
    def _hide_cursor(self):
        """Hide terminal cursor"""
        try:
            os.system('tput civis')
        except Exception:
            pass
    
    def _show_cursor(self):
        """Show terminal cursor"""
        try:
            os.system('tput cnorm')
        except Exception:
            pass
    
    def setup(self):
        """Set up the progress display"""
        # Initialize files and state
        self._init_files()
        self._hide_cursor()
        self.is_setup = True
        
        # Set up signal handlers
        self._setup_signal_handlers()
        
        # Start background thread for updates
        self.status_thread = threading.Thread(target=self._update_display)
        self.status_thread.daemon = True
        self.status_thread.start()
        
        # Initial display
        sys.stdout.write(f"Stage: {self.current_stage}\n")
        sys.stdout.write("[" + " " * 50 + "] 0% | Processed: 0 of {0} | Time: 00:00".format(self.total_items))
        sys.stdout.flush()
        
        time.sleep(0.5)  # Allow time for display to initialize
    
    def _setup_signal_handlers(self):
        """Set up signal handlers for graceful termination"""
        self.original_sigint = signal.getsignal(signal.SIGINT)
        self.original_sigterm = signal.getsignal(signal.SIGTERM)
        
        def signal_handler(sig, frame):
            self.log_debug(f"Received signal {sig}, cleaning up")
            self.finish()
            
            # After cleanup, call the original handler or exit
            if sig == signal.SIGINT and self.original_sigint:
                self.original_sigint(sig, frame)
            elif sig == signal.SIGTERM and self.original_sigterm:
                self.original_sigterm(sig, frame)
            else:
                sys.exit(128 + sig)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _update_display(self):
        """Background thread that continuously updates the progress display"""
        last_count = -1
        last_stage = ""
        
        try:
            while not self.stop_event.is_set():
                try:
                    # Check control file for stop signal
                    if not self._should_continue():
                        break
                    
                    # Read current progress values with a single lock
                    count, stage = self._read_progress()
                    
                    # Only update display if something changed
                    if count != last_count or stage != last_stage:
                        self._render_progress_bar(count, stage)
                        last_count = count
                        last_stage = stage
                        
                except Exception as e:
                    sys.stderr.write(f"\nProgress display error: {str(e)}\n")
                
                # Short delay between updates
                time.sleep(0.3)
                
        finally:
            # Always restore cursor 
            self._show_cursor()
    
    def _should_continue(self):
        """Check if the progress bar should continue updating"""
        if not os.path.exists(self.control_file):
            return False
        
        try:
            with open(self.control_file, "r") as f:
                return f.read().strip() != "stop"
        except:
            return False
    
    def _read_progress(self):
        """Read the current progress values with error handling"""
        count = self.current_count
        stage = self.current_stage
        
        try:
            if os.path.exists(self.progress_file):
                with open(self.progress_file, "r") as f:
                    count_str = f.read().strip()
                    if count_str:
                        count = int(count_str)
            
            if os.path.exists(self.stage_file):
                with open(self.stage_file, "r") as f:
                    stage_str = f.read().strip()
                    if stage_str:
                        stage = stage_str
        except Exception:
            pass  # Use previous values on error
        
        return count, stage
    
    def _render_progress_bar(self, count, stage):
        """Render the progress bar with the given count and stage"""
        # Every 20 updates, send a more aggressive reset sequence
        if hasattr(self, '_update_count'):
            self._update_count += 1
        else:
            self._update_count = 0
            
        if self._update_count % 20 == 0:
            # Send a more aggressive reset sequence
            sys.stdout.write("\r\033[2J\033[H")
            # Print empty lines for the progress bar
            sys.stdout.write("\n\n")

        # Calculate progress metrics
        percent = min(100, int(count * 100 / self.total_items)) if self.total_items else 0
        bar_width = 50
        filled = int(percent * bar_width / 100)
        bar = "#" * filled + " " * (bar_width - filled)
        
        # Calculate elapsed time
        elapsed = int(time.time() - self.script_start_time)
        minutes, seconds = divmod(elapsed, 60)
        elapsed_fmt = f"{minutes:02d}:{seconds:02d}"
        
        # Format the "processed / total" string
        processed_fmt = f"{count} of {self.total_items}"
        
        # Clear and rewrite display
        sys.stdout.write("\r\033[2K\033[A\033[2K\r")
        sys.stdout.write(f"Stage: {stage}\n")
        sys.stdout.write(f"[{bar}] {percent:3d}% | Processed: {processed_fmt} | Time: {elapsed_fmt}")
        sys.stdout.flush()
    
    def log_debug(self, message):
        """Log debug information"""
        sys.stderr.write(f"ProgressBar: {message}\n")
        sys.stderr.flush()
    
    def update(self, stage, completed=0):
        """Update the progress bar with current stage and completion status"""
        with self.lock:
            # Update in-memory state
            self.current_stage = stage
            if completed == 1:
                self.current_count += 1
            
            # Update files
            try:
                # Always update stage file
                with open(self.stage_file, "w") as f:
                    f.write(stage)
                
                # Update count file if an item was completed
                if completed == 1:
                    with open(self.progress_file, "w") as f:
                        f.write(str(self.current_count))
            except Exception as e:
                sys.stderr.write(f"\nError updating progress: {str(e)}\n")
    
    def finish(self):
        """Finalize the progress display"""
        # First update the files to show completion
        with self.lock:
            try:
                # Set completed state
                self.current_count = self.total_items
                self.current_stage = "Complete!"
                
                # Update files
                if os.path.exists(self.progress_file):
                    with open(self.progress_file, "w") as f:
                        f.write(str(self.total_items))
                
                if os.path.exists(self.stage_file):
                    with open(self.stage_file, "w") as f:
                        f.write("Complete!")
                
                # Signal the display thread to stop
                if os.path.exists(self.control_file):
                    with open(self.control_file, "w") as f:
                        f.write("stop")
            except:
                pass  # Ignore errors during shutdown
        
        # Short delay for final update
        time.sleep(0.5)
        self.stop_event.set()
        
        # Final display update
        if self.is_setup:
            self._render_final_state()
        
        # Cleanup
        self.cleanup()
    
    def _render_final_state(self):
        """Render the final state of the progress bar"""
        # Calculate final elapsed time
        elapsed = int(time.time() - self.script_start_time)
        minutes, seconds = divmod(elapsed, 60)
        elapsed_fmt = f"{minutes:02d}:{seconds:02d}"
        
        # Format the "processed / total" string
        processed_fmt = f"{self.total_items} of {self.total_items}"
        
        # Clear current lines and print final update
        sys.stdout.write("\r\033[K\033[A\r\033[K")
        sys.stdout.write("Stage: Complete!\n")
        sys.stdout.write(f"[{'#' * 50}] 100% | Processed: {processed_fmt} | Time: {elapsed_fmt}")
        sys.stdout.flush()
        
        # Add newline after completion
        print("\n")
    
    def cleanup(self):
        """Clean up resources"""
        # Set stop event
        self.stop_event.set()
        
        # Restore cursor
        self._show_cursor()
        
        # Remove temp directory
        try:
            if os.path.exists(self.progress_dir):
                shutil.rmtree(self.progress_dir)
        except:
            pass
        
        # Restore signal handlers
        if hasattr(self, 'original_sigint'):
            signal.signal(signal.SIGINT, self.original_sigint)
        if hasattr(self, 'original_sigterm'):
            signal.signal(signal.SIGTERM, self.original_sigterm)

###########################################
# Logging & Setup Helper Utilities
###########################################

def configure_logging(log_file='logs/smu-check-debug.log', level=logging.DEBUG):
    """Configure logging with rotation and no console output."""
    # Ensure log directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    # Create file handler with rotation
    file_handler = RotatingFileHandler(
        filename=log_file, maxBytes=10*1024*1024, backupCount=5)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    file_handler.setLevel(level)
    file_handler.id = "main_file_handler"  # Unique ID to prevent duplication
    
    # Configure root logger with NO console output
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.handlers = []  # Clear all handlers
    root_logger.addHandler(file_handler)
    
    # Create console handler with CRITICAL level to suppress normal logs
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    console_handler.setLevel(logging.CRITICAL)
    root_logger.addHandler(console_handler)
    
    # Track handler attachment for use with other loggers
    global _handler_attached_loggers
    _handler_attached_loggers = set()
    
    return file_handler  # Return for use with other loggers

def get_logger(name=None):
    """Get a properly configured logger"""
    logger = logging.getLogger(name)
    # Ensure the logger doesn't propagate duplicates
    logger.propagate = False
    return logger

# Initialize global variable for handler tracking
_handler_attached_loggers = set()

# Configure main logging setup
file_handler = configure_logging()

# Set a module-level logger and ensure it has proper setup
logger = get_logger(__name__)
logger.propagate = False  # Prevent propagation to root logger

logger.info("Script started")

def check_system_resources():
    """
    Check system resources using /proc filesystem.
    Returns a dictionary with resource information.
    """
    resources = {}
    
    # Check for CPU count via /proc/cpuinfo
    try:
        cpu_count = 0
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('processor'):
                    cpu_count += 1
        resources["cpu_count"] = cpu_count
        # Logging instead of printing
        logger.info(f"Detected {cpu_count} CPU cores")
    except Exception as e:
        resources["cpu_count"] = 2  # Conservative default
        logger.info(f"Couldn't read CPU info: {str(e)}. Assuming 2 cores.")
    
    # Check memory via /proc/meminfo
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    # Memory is in kB in /proc/meminfo
                    mem_kb = int(line.split()[1])
                    mem_gb = round(mem_kb / (1024 * 1024), 2)
                    resources["memory_gb"] = mem_gb
                    logger.info(f"Detected {mem_gb} GB memory")
                    break
    except Exception as e:
        resources["memory_gb"] = 4  # Conservative default
        logger.info(f"Couldn't read memory info: {str(e)}. Assuming 4GB.")
    
    # Check load average
    try:
        with open('/proc/loadavg', 'r') as f:
            load = f.read().strip().split()
            resources["load_1min"] = float(load[0])
            resources["load_5min"] = float(load[1])
            resources["load_15min"] = float(load[2])
            logger.info(f"Current load averages: {load[0]} (1min), {load[1]} (5min), {load[2]} (15min)")
    except Exception as e:
        resources["load_1min"] = 1.0  # Default value
        logger.info(f"Couldn't read load average: {str(e)}")
    
    # Check current SSH connections
    try:
        conn_count = int(subprocess.check_output(
            "netstat -ant | grep ESTABLISHED | grep ':22' | wc -l", 
            shell=True, text=True
        ).strip())
        resources["current_connections"] = conn_count
        logger.info(f"Currently active SSH connections: {conn_count}")
    except Exception as e:
        resources["current_connections"] = 5  # Assume moderate usage
        logger.info(f"Couldn't check SSH connections: {str(e)}")
    
    # Calculate recommended thread count based on resources
    if resources.get("cpu_count", 0) > 0:
        # Base thread count on CPU cores
        thread_base = max(2, resources["cpu_count"] - 1)
        
        # Adjust for memory (approximately 150MB per thread)
        if "memory_gb" in resources:
            memory_capacity = int(resources["memory_gb"] * 6)  # ~150MB per thread
            thread_base = min(thread_base, memory_capacity)
            
        # Adjust for current load
        if "load_5min" in resources:
            load_factor = resources["load_5min"] / resources["cpu_count"]
            if load_factor > 0.7:  # High load
                thread_base = max(2, thread_base - 2)
            elif load_factor < 0.3:  # Low load
                thread_base = min(thread_base + 2, resources["cpu_count"] * 2)
                
        # Adjust for existing SSH connections
        if "current_connections" in resources:
            conn_adjust = resources["current_connections"] // 5  # Every 5 connections reduces by 1
            thread_base = max(2, thread_base - conn_adjust)
            
        # Cap at reasonable maximum
        recommended = min(thread_base, 20)
    else:
        recommended = 5  # Default fallback
        
    resources["recommended_threads"] = recommended
    logger.info(f"Recommended thread count: {recommended}")
    
    return resources

###########################################
# Connection Helper Utilities
###########################################

def handle_connection_error(device_name, device_ip, error, error_type=None, buffer=None, diagnostics=None, logger=None):
    """
    Unified error handler for connection issues across the script
    
    Args:
        device_name: Name of the device (switch/APIC)
        device_ip: IP address of the device
        error: The exception or error string
        error_type: Type of error (timeout, auth_failure, connection, etc.)
        buffer: Any output buffer captured before the error
        diagnostics: Dictionary to update with error information
        logger: Logger instance to use (will use root logger if None)
    
    Returns:
        dict: Error information dictionary with consistent structure
    """
    if logger is None:
        logger = get_logger(__name__)
    
    error_str = str(error)
    
    # Initialize error info structure
    error_info = {
        "device": device_name,
        "ip": device_ip,
        "status": "error",
        "error_type": error_type or "unknown",
        "error_message": error_str,
        "buffer": buffer,
        "retry_recommended": False
    }
    
    # Process error types consistently
    if error_type == "auth_failure" or "AUTH_FAILURE" in error_str:
        error_info["error_type"] = "auth_failure"
        error_info["display_message"] = "Authentication failed - check credentials"
        error_info["retry_recommended"] = False
        logger.error(f"Authentication failure on {device_name} ({device_ip}): {error_str}")
        
    elif error_type == "timeout" or "timed out" in error_str.lower():
        error_info["error_type"] = "timeout"
        error_info["display_message"] = "Connection timed out - check network connectivity"
        error_info["retry_recommended"] = True
        logger.error(f"Timeout connecting to {device_name} ({device_ip}): {error_str}")
        
    elif error_type == "connection" or "connection" in error_str.lower():
        error_info["error_type"] = "connection"
        error_info["display_message"] = "Connection error - check device availability"
        error_info["retry_recommended"] = True
        logger.error(f"Connection error to {device_name} ({device_ip}): {error_str}")
    
    elif error_type == "eof" or "eof" in error_str.lower():
        error_info["error_type"] = "eof"
        error_info["display_message"] = "Connection closed unexpectedly"
        error_info["retry_recommended"] = True
        logger.error(f"Connection closed to {device_name} ({device_ip}): {error_str}")
        
    elif error_type == "permission":
        error_info["error_type"] = "permission"
        error_info["display_message"] = "Permission denied"
        error_info["retry_recommended"] = False
        logger.error(f"Permission error on {device_name} ({device_ip}): {error_str}")
        
    else:
        error_info["display_message"] = f"Error: {error_str}"
        logger.error(f"Unspecified error on {device_name} ({device_ip}): {error_str}")
    
    # Update diagnostics dict if provided
    if diagnostics is not None:
        diagnostics["error_type"] = error_info["error_type"]
        diagnostics["error_message"] = error_str
        if buffer:
            diagnostics["buffer"] = buffer
    
    # Return formatted error info
    return error_info

def clean_terminal_on_auth_failure():
    """Clear progress bar and terminal output on authentication failure"""
    # Move up 2 lines to clear progress bar display
    sys.stdout.write('\r\033[K\033[1A\033[K')
    sys.stdout.flush()
    # Add a newline for better spacing before error message
    print()

def get_dynamic_md5_hashes():
    """
    Dynamically retrieve MD5 hashes for the current APIC version's switch images
    using a three-step approach:
    1. Try firmwareFirmware API with icurl
    2. Fall back to md5sum files
    3. Calculate directly if needed
    
    Returns:
        tuple: (md5_32bit, md5_64bit, version_string, images_missing)
    """
    logger.info("Getting APIC version and MD5 hashes dynamically")
    
    try:
        # Get APIC version using icurl instead of acidiag avread
        apic_version_cmd = "icurl -gs 'http://127.0.0.1:7777/api/class/firmwareCtrlrRunning.json'"
        version_output = subprocess.check_output(apic_version_cmd, shell=True, text=True)
        
        # Parse the JSON output to find node-1 and extract version
        apic_version = None
        try:
            data = json.loads(version_output)
            for item in data.get("imdata", []):
                controller_data = item.get("firmwareCtrlrRunning", {}).get("attributes", {})
                dn = controller_data.get("dn", "")
                
                # Look for node-1 in the DN
                if "node-1" in dn:
                    apic_version = controller_data.get("version")
                    logger.info(f"Found APIC version from node-1: {apic_version}")
                    break
            
            # If node-1 not found, try to get version from any APIC node
            if not apic_version and data.get("imdata"):
                for item in data.get("imdata", []):
                    controller_data = item.get("firmwareCtrlrRunning", {}).get("attributes", {})
                    apic_version = controller_data.get("version")
                    if apic_version:
                        logger.info(f"Found APIC version from alternate node: {apic_version}")
                        break
        
        except json.JSONDecodeError:
            logger.error(f"Failed to parse JSON from icurl output: {version_output}")
            raise RuntimeError("Failed to parse APIC version JSON")
            
        if not apic_version:
            logger.error(f"Could not extract version from JSON output: {version_output}")
            raise RuntimeError("Failed to extract APIC version from JSON output")
        
        logger.info(f"Found APIC version: {apic_version}")
        
        # Convert version format from '6.0(8e)' to '16.0(8e)' for switch images
        # Handle versions with dots in the parentheses part (Usually a QA image)
        version_base = apic_version.split('(')[0]
        version_detail = apic_version.split('(')[1].rstrip(')')
        
        # The switch image version format starts with "1" prefix
        switch_version = f"1{version_base}({version_detail})"
        switch_version_dot = f"1{version_base}.{version_detail}"
        logger.info(f"Converted to switch image version: {switch_version}")
        
        # Build image filenames
        image_32bit = f"aci-n9000-dk9.{switch_version_dot}.bin"
        image_64bit = f"aci-n9000-dk9.{switch_version_dot}-cs_64.bin"
        
        # Build system image names for firmware API query
        system_image_32bit = f"aci-n9000-system.{switch_version_dot}.bin"
        system_image_64bit = f"aci-n9000-system.{switch_version_dot}-cs_64.bin"
        
        logger.info(f"32-bit image: {image_32bit}")
        logger.info(f"64-bit image: {image_64bit}")
        logger.info(f"32-bit system image name for API: {system_image_32bit}")
        logger.info(f"64-bit system image name for API: {system_image_64bit}")
        
        # STEP 1: Try using firmwareFirmware API first
        md5_32bit = MD5Processor.get_md5_hash(image_name=image_32bit, system_image_name=system_image_32bit)
        md5_64bit = MD5Processor.get_md5_hash(image_name=image_64bit, system_image_name=system_image_64bit)
        
        # Log which method was used for each image
        if md5_32bit:
            logger.info(f"Retrieved 32-bit MD5 from firmwareFirmware API: {md5_32bit}")
        
        if md5_64bit:
            logger.info(f"Retrieved 64-bit MD5 from firmwareFirmware API: {md5_64bit}")
        
        # STEP 2: If API method failed for either image, try md5sum file method
        if not md5_32bit or md5_32bit == "Image not found in API":
            logger.info("Falling back to md5sum file for 32-bit image")
            md5_32bit = MD5Processor.get_md5_hash(image_32bit)
            
            if md5_32bit and md5_32bit != "Image not found in fwrepo":
                logger.info(f"Retrieved 32-bit MD5 from md5sum file: {md5_32bit}")
        
        if not md5_64bit or md5_64bit == "Image not found in API":
            logger.info("Falling back to md5sum file for 64-bit image")
            md5_64bit = MD5Processor.get_md5_hash(image_64bit)
            
            if md5_64bit and md5_64bit != "Image not found in fwrepo":
                logger.info(f"Retrieved 64-bit MD5 from md5sum file: {md5_64bit}")
        
        # STEP 3: Both methods can fall back to direct calculation automatically
        # as it's already implemented in get_md5_from_file
        
        # Check if both images were not found
        images_missing = ((md5_32bit == "Image not found in fwrepo" or 
                          md5_32bit == "Image not found in API" or 
                          not md5_32bit) and 
                         (md5_64bit == "Image not found in fwrepo" or 
                          md5_64bit == "Image not found in API" or 
                          not md5_64bit))
        
        if images_missing:
            logger.error("Neither 32-bit nor 64-bit images were found with any method")
            # Ensure consistent return values for missing images
            md5_32bit = "Image not found" if not md5_32bit or md5_32bit.startswith("Image not found") else md5_32bit
            md5_64bit = "Image not found" if not md5_64bit or md5_64bit.startswith("Image not found") else md5_64bit
        
        return md5_32bit, md5_64bit, apic_version, images_missing
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode}: {e.output if hasattr(e, 'output') else 'no output'}")
        raise RuntimeError(f"Failed to get MD5 hashes: {str(e)}")
    except Exception as e:
        logger.error(f"Error retrieving MD5 hashes: {str(e)}")
        raise RuntimeError(f"Failed to get MD5 hashes: {str(e)}")

###########################################
# Switch Processing Functions
###########################################

def get_repodata(conn):
    """
    Check if the /bootflash/.rpmstore/patching/patchrepo/.repodata directory exists
    
    Args:
        conn: An established SSH connection object
        
    Returns:
        tuple: (result, output) where result is "PASS" if directory doesn't exist
               or "FAIL" if it does exist
    """
    repodata_path = "/bootflash/.rpmstore/patching/patchrepo/.repodata"
    
    try:
        # Run the ls command to check if the directory exists
        result_type, raw_output = conn.execute_command(f"ls -lh {repodata_path}")
        
        # Clean the output using CommandOutputProcessor
        output = CommandOutputProcessor.clean_output(raw_output, conn.hostname)
        
        # If the output contains "cannot access" or similar error, the file doesn't exist (PASS)
        if "cannot access" in output or "No such file or directory" in output:
            return "PASS", output
        
        # If the output contains file information (not empty), the file exists (FAIL)
        elif output.strip() and not ("cannot access" in output or "No such file" in output):
            return "FAIL", output
        
        # Any other case (maybe empty output or another error)
        logger.debug(f"Repodata check returned ambiguous result: '{output}'")
        # Default to PASS for ambiguous results
        return "PASS", output
    except Exception as e:
        # If there was an error executing the command, consider it inconclusive
        return "ERROR", f"Command execution error: {str(e)}"

def validate_repodata(conn, sw_name, switch_data, progress_bar=None):
    """
    Perform repodata directory check and update switch_data with results
    
    Args:
        conn: An established SSH connection object
        sw_name: Switch name for identification
        switch_data: Dictionary to update with results
        progress_bar: Optional progress bar for UI updates
        
    Returns:
        tuple: (repodata_result, cleaned_output) where
               repodata_result is "PASS", "FAIL", or "ERROR"
    """
    # Update progress bar if provided
    if progress_bar:
        progress_bar.update(f"{sw_name}: Checking Repodata", 0)
    
    # Call the collect repodata function
    repodata_result, repodata_output = get_repodata(conn)
    
    # Store the result in switch_data
    switch_data["repodata_check"] = repodata_result
    
    # Clean and format the output using CommandOutputProcessor
    if repodata_output:
        cleaned_repodata = CommandOutputProcessor.clean_output(repodata_output, sw_name)
        formatted_output = CommandOutputProcessor.format_for_display(cleaned_repodata)
        switch_data["repodata_output"] = formatted_output
    else:
        switch_data["repodata_output"] = repodata_output
    
    # Update message to include Repodata check result
    md5_message = switch_data.get("message", "")
    
    if repodata_result == "FAIL":
        new_message = f"{md5_message} | Repodata Check: FAIL - .repodata directory exists"
    elif repodata_result == "PASS":
        new_message = f"{md5_message} | Repodata Check: PASS"
    else:
        new_message = f"{md5_message} | Repodata Check: ERROR"
    
    # Update the message in switch_data
    switch_data["message"] = new_message
    
    return repodata_result, formatted_output if repodata_output else repodata_output

def get_kickstart_ownership(raw_output, switch_name, data_dict=None, diagnostics=None):
    """
    Centralized helper to extract file information using CommandOutputProcessor
    and consistently update data dictionaries.
    
    Args:
        raw_output (str): Raw output from ls command
        switch_name (str): Switch hostname for cleaning output
        data_dict (dict, optional): Dictionary to update with file info
        diagnostics (dict, optional): Diagnostics dictionary to update with file info
    
    Returns:
        dict: The extracted file information
    """
    # Use CommandOutputProcessor to extract file information
    file_info = CommandOutputProcessor.extract_file_info(raw_output, switch_name)
    
    # Update the provided dictionaries if they're given
    if data_dict is not None:
        for key, value in file_info.items():
            if value is not None:
                data_dict[key] = value
    
    if diagnostics is not None:
        for key, value in file_info.items():
            if value is not None:
                diagnostics[key] = value
    
    return file_info

def _modify_kickstart_ownership(conn, sw_name, kickstart_image, switch_data, diagnostics):
    """Proactively fix permissions on the image file."""
    if not kickstart_image:
        logger.debug(f"No kickstart image path provided for {sw_name}")
        return False
    
    try:
        # Check current file status
        ls_cmd = f"ls -l {kickstart_image}"
        ls_status, ls_output = conn.execute_command(ls_cmd)
        if ls_status != "success":
            logger.debug(f"Failed to get file info for {sw_name}: {ls_output.strip()}")
            return False
        
        # Store raw ls output
        switch_data["raw_ls_output"] = ls_output.strip()
        diagnostics["raw_ls_output"] = ls_output.strip()
        
        # Use the centralized extraction function to get file information BEFORE changes
        before_file_info = get_kickstart_ownership(ls_output, sw_name)
        
        # Store the original permissions and ownership information from the extracted data
        if before_file_info["file_permissions"]:
            switch_data["original_permissions"] = before_file_info["file_permissions"]
            diagnostics["original_permissions"] = before_file_info["file_permissions"]
        
        if before_file_info["file_owner"] and before_file_info["file_group"]:
            switch_data["original_ownership"] = f"{before_file_info['file_owner']}:{before_file_info['file_group']}"
            diagnostics["original_ownership"] = f"{before_file_info['file_owner']}:{before_file_info['file_group']}"
        
        # Execute ownership/permission commands and track results
        for cmd_type, cmd in [
            ("chown", f"chown root:admin {kickstart_image}"),
            ("chmod", f"chmod 666 {kickstart_image}")
        ]:
            logger.info(f"Sending {cmd_type.upper()} COMMAND TO {sw_name}: {cmd}")
            status, output = conn.execute_command(cmd)
            
            # Clean the output using CommandOutputProcessor
            cleaned_output = CommandOutputProcessor.clean_output(output, sw_name)
            
            result_key = f"{cmd_type}_{'success' if status == 'success' else 'failure'}"
            diagnostics[result_key] = {"status": status, "output": cleaned_output}
            
            if status != "success":
                logger.debug(f"{cmd_type.capitalize()} command failed on {sw_name}: {cleaned_output}")
        
        # Verify the changes
        verify_status, verify_output = conn.execute_command(ls_cmd)
        
        # Use CommandOutputProcessor to clean the verification output
        cleaned_verify = CommandOutputProcessor.clean_output(verify_output, sw_name)
        switch_data["verification_output"] = cleaned_verify
        diagnostics["verification_output"] = cleaned_verify
        
        # Use the centralized extraction function again to get file information AFTER changes
        after_file_info = get_kickstart_ownership(verify_output, sw_name)
        
        # Determine if permission and ownership were successfully changed
        permission_success = (after_file_info["file_permissions"] == "-rw-rw-rw-")
        ownership_success = (after_file_info["file_owner"] == "root" and 
                             after_file_info["file_group"] == "admin")
        
        switch_data["permissions_fixed"] = permission_success
        switch_data["ownership_fixed"] = ownership_success
        switch_data["ownership_fixed_attempted"] = True
        
        # Add the full file info after changes to the switch_data
        for key, value in after_file_info.items():
            if value is not None:
                switch_data[key] = value
        
        return True
    except Exception as e:
        logger.error(f"Error fixing permissions on {sw_name}: {str(e)}")
        switch_data["permission_fix_error"] = str(e)
        diagnostics["permission_fix_error"] = str(e)
        return False

def perform_switch_validation(conn, sw_name, sw_ip, progress_bar, md5_32bit, md5_64bit, 
                             switch_info=None, kickstart_image=None, memory_kb=None, memory_gb=None,
                             is_modular_spine=False):
    """
    Base function for common switch checks. Handles data collection, MD5 validation,
    permission error handling, and repodata checks.
    
    Args:
        conn: An established SSH connection object
        sw_name: Switch name for identification
        sw_ip: Switch IP address
        progress_bar: Progress bar object for updates
        md5_32bit: MD5 checksum for 32-bit image (None for modular spines)
        md5_64bit: MD5 checksum for 64-bit image
        switch_info: SwitchInfo instance with pre-collected data (optional)
        kickstart_image: Pre-collected kickstart image path (optional)
        memory_kb: Pre-collected memory in KB (optional)
        memory_gb: Pre-collected memory in GB (optional)
        is_modular_spine: Whether this is a modular spine (affects validation logic)
        
    Returns:
        dict: Switch data with validation results
    """
    # Initialize diagnostics dict
    diagnostics = {"error_type": None}
    
    # Create data structure
    switch_data = {
        "switch": sw_name,
        "ip": sw_ip,
        "status": "success",
        "memory_kb": memory_kb,
        "memory_gb": memory_gb,
        "image_path": kickstart_image,
        "md5sum": None,
        "result": "INFO",
        "message": "Modular spine" if is_modular_spine else "Fixed switch",
        "diagnostics": diagnostics
    }
    
    # Attempt to fix permissions proactively if we're root user and have image path
    if switch_info and switch_info.username == "root" and kickstart_image:
        progress_bar.update(f"{sw_name}: Fixing file permissions", 0)
        _modify_kickstart_ownership(conn, sw_name, kickstart_image, switch_data, diagnostics)
    
    # Collect data if insufficient pre-collected data is available
    if not kickstart_image or (not memory_kb and not memory_gb):
        # Only run show version if we don't already have complete data
        progress_bar.update(f"{sw_name}: Getting version information", 0)
        result_type, version_output = conn.execute_command("show version")
        if result_type == "success":
            # Clean the output using CommandOutputProcessor
            cleaned_output = CommandOutputProcessor.clean_output(version_output, sw_name)
            
            # Extract kickstart image path if we don't have it yet
            if not kickstart_image:
                image_path = SwitchDataCollector.extract_image_path(cleaned_output)
                switch_data["image_path"] = image_path
                kickstart_image = image_path
            
            # Extract memory information if not pre-collected
            if not memory_kb and not memory_gb:
                memory_kb = SwitchDataCollector.extract_memory(cleaned_output)
                if memory_kb:
                    switch_data["memory_kb"] = memory_kb
                    # Convert to standardized GB value using MemoryCheck
                    switch_data["memory_gb"] = MemoryCheck.standardize_memory_gb(memory_kb)
        else:
            switch_data["result"] = "ERROR" 
            switch_data["message"] = "Failed to retrieve version information"
            switch_data["status"] = "error"
            return switch_data
    
    # Get MD5 checksum of the image if we have the path
    if kickstart_image:
        progress_bar.update(f"{sw_name}: Retrieving MD5 hash", 0)
        result_type, md5_output = conn.execute_command(f"md5sum {kickstart_image}")
        
        # Process MD5 output using CommandOutputProcessor
        md5_result = CommandOutputProcessor.parse_md5_output(md5_output, sw_name)
        
        # Store the command output to help diagnose MD5 retrieval failures
        switch_data["md5_command_output"] = md5_output
        
        # Check if there was an error
        if not md5_result["success"]:
            # Store error information
            switch_data["md5_error_type"] = md5_result["error_type"]
            switch_data["md5_error_message"] = md5_result["error_message"]
            
            # If we have a permission error, try to fix permissions and retry
            if md5_result["error_type"] == "permission" and not switch_data.get("ownership_fixed"):
                conn.execute_command(f"chmod 666 {kickstart_image}")
                result_type, retry_output = conn.execute_command(f"md5sum {kickstart_image}")
                
                # Process retry output using CommandOutputProcessor
                retry_result = CommandOutputProcessor.parse_md5_output(retry_output, sw_name)
                switch_data["md5_command_output"] = retry_output
                
                if retry_result["success"]:
                    # Retry was successful
                    switch_data["md5sum"] = retry_result["md5_hash"]
                    # Clear error information
                    switch_data.pop("md5_error_type", None)
                    switch_data.pop("md5_error_message", None)
                else:
                    # Retry failed, keep error information
                    switch_data["md5_retry_error_type"] = retry_result["error_type"]
                    switch_data["md5_retry_error_message"] = retry_result["error_message"]
        else:
            # No error, store the hash
            switch_data["md5sum"] = md5_result["md5_hash"]
        
        # Check for permission denied in md5 output and get file owner info
        if ("md5_error_type" in switch_data and switch_data["md5_error_type"] == "permission") or \
           ("md5_command_output" in switch_data and "permission denied" in switch_data["md5_command_output"].lower()):
            progress_bar.update(f"{sw_name}: Getting file permissions", 0)
            
            # Get file information
            result_type, ls_output = conn.execute_command(f"ls -lh {kickstart_image}")
            
            # Store raw output for reference
            switch_data["raw_ls_output"] = ls_output.strip()
            diagnostics["raw_ls_output"] = ls_output.strip()
            
            # Use centralized extraction function
            get_kickstart_ownership(ls_output, sw_name, switch_data, diagnostics)
        
        # Apply appropriate validation logic based on switch type
        md5_hash = switch_data.get("md5sum")
        if md5_hash:
            if is_modular_spine:
                # Modular spines MUST use 64-bit image regardless of memory
                if md5_hash == md5_64bit:
                    switch_data["result"] = "PASS"
                    switch_data["message"] = "Running correct 64-bit image for modular spine"
                else:
                    switch_data["result"] = "FAIL"
                    switch_data["message"] = "Modular spine running incorrect image (must use 64-bit image)"
            else:
                # For regular switches, validate against memory capacity
                image_result, image_message = SwitchDataCollector.validate_image(switch_data, md5_32bit, md5_64bit)
                switch_data["result"] = image_result
                switch_data["message"] = image_message
        else:
            switch_data["result"] = "ERROR"
            switch_data["message"] = "Could not retrieve MD5 information"
    else:
        switch_data["result"] = "ERROR" 
        switch_data["message"] = "Missing kickstart image path"
        switch_data["status"] = "error"
    
    # Always perform the repodata check regardless of other results
    validate_repodata(conn, sw_name, switch_data, progress_bar)
    
    # For regular switches, additional error categorization
    if not is_modular_spine and switch_data["status"] != "success":
        diagnostics.update(SwitchDataCollector.categorize_error(switch_data))
    
    # Make sure md5_command_output is directly added to diagnostics
    if "md5_command_output" in switch_data:
        diagnostics["md5_command_output"] = switch_data["md5_command_output"]
    
    # Add diagnostics to the result
    switch_data["diagnostics"] = diagnostics
    
    return switch_data

###########################################
# Batch Processing Functions
###########################################

def process_switch(sw_ip, switch_info, progress_bar, username, password, md5_32bit, md5_64bit, bind_addr=None, is_modular_spine=False):
    """Process a single switch and collect results with robust error handling"""
    sw_name = switch_info.get_switch_name(sw_ip)
    # Create diagnostics dict with an error_type field to track the nature of the error
    diagnostics = {
        "error_type": None  # Will be set to "connection", "memory_retrieval", "md5_retrieval", etc.
    }
    
    # Common result structure with defaults
    switch_data = {
        "switch": sw_name,
        "ip": sw_ip,
        "status": "error",
        "result": "ERROR",
        "message": "Processing not started",
        "diagnostics": diagnostics
    }
    
    try:
        progress_bar.update(f"Connecting to {sw_name}", 0)
        
        # Retrieve pre-collected kickstart image data if available
        kickstart_image = None
        memory_kb = None
        memory_gb = None
        node_id = switch_info.get_switch_id(sw_ip)
        
        # Retrieve kickstart image information if available
        if node_id and hasattr(switch_info, 'switch_kickstart') and node_id in switch_info.switch_kickstart:
            kickstart_data = switch_info.switch_kickstart[node_id]
            kickstart_image = kickstart_data['full_path']
            # Store boot mode information for display
            if 'mode' in kickstart_data:
                switch_data["boot_mode"] = kickstart_data['mode']
            logger.debug(f"Using pre-collected kickstart image for {sw_name}: {kickstart_image}")
            # Add to switch_data for use in check functions
            switch_data["image_path"] = kickstart_image
            
        # Retrieve memory information if available
        if node_id and hasattr(switch_info, 'switch_memory') and node_id in switch_info.switch_memory:
            mem_info = switch_info.switch_memory[node_id]
            if isinstance(mem_info, dict) and 'kb' in mem_info and 'gb' in mem_info:
                memory_kb = mem_info['kb']
                memory_gb = mem_info['gb']
                # Add to switch_data for use in check functions
                switch_data["memory_kb"] = memory_kb
                switch_data["memory_gb"] = memory_gb
                logger.debug(f"Using pre-collected memory data for {sw_name}: {memory_kb} KB ({memory_gb} GB)")
        
        # Use context manager for connection handling
        with Connection(sw_ip, username, password, timeout=2, bind_address=bind_addr) as conn:
            # Authentication failures should be caught immediately with no retry
            try:
                # __enter__ already called connect in the context manager
                if not conn.child:  # Check if connection was established
                    # Handle connection issues
                    error_info = handle_connection_error(
                        device_name=sw_name,
                        device_ip=sw_ip,
                        error="Failed to connect",
                        error_type="connection",
                        diagnostics=diagnostics,
                        logger=get_logger(f'connection.{sw_ip}')
                    )
                    switch_data["message"] = error_info["display_message"]
                    return switch_data
            except RuntimeError as e:
                if "AUTH_FAILURE" in str(e):
                    # Handle authentication failures
                    error_info = handle_connection_error(
                        device_name=sw_name,
                        device_ip=sw_ip,
                        error=e,
                        error_type="auth_failure",
                        logger=get_logger(f'connection.{sw_ip}')
                    )
                    raise RuntimeError(f"AUTH_FAILURE on {sw_name}")
                else:
                    # Handle other runtime errors
                    error_info = handle_connection_error(
                        device_name=sw_name,
                        device_ip=sw_ip,
                        error=e,
                        error_type="exception",
                        diagnostics=diagnostics,
                        logger=get_logger(f'connection.{sw_ip}')
                    )
                    raise
            
            # Skip checking if we're root - we know we are if username is "root"
            is_root = (username == "root")
            
            # If we're running as root, handle file permissions proactively
            if is_root and kickstart_image:
                progress_bar.update(f"{sw_name}: Fixing file permissions", 0)
                logger.info(f"Attempting to fix file permissions for {kickstart_image} on {sw_name}")
                _modify_kickstart_ownership(conn, sw_name, kickstart_image, switch_data, diagnostics)
                
                # Now verify the changes
                verify_cmd = f"ls -l {kickstart_image}"
                verify_result = conn.execute_command(verify_cmd)
                if verify_result == "success":
                    logger.info(f"Final file permissions: {conn.output.strip()}")
                else:
                    logger.debug(f"Could not verify final permissions: {conn.output}")
            
            # Store any ownership data we've collected before calling base_switch_checks
            ownership_data = {}
            for key in ["ownership_fixed", "ownership_message", "original_ownership", 
                        "permissions_fixed", "original_permissions"]:
                if key in switch_data:
                    ownership_data[key] = switch_data[key]
            
            # Connection successful - directly call perform_switch_validation instead of wrappers
            switch_data = perform_switch_validation(
                conn, 
                sw_name, 
                sw_ip, 
                progress_bar,
                md5_32bit=None if is_modular_spine else md5_32bit,
                md5_64bit=md5_64bit,
                switch_info=switch_info,
                kickstart_image=kickstart_image,
                memory_kb=memory_kb,
                memory_gb=memory_gb,
                is_modular_spine=is_modular_spine
            )
            
            # If this is a fixed switch, add collection_time if missing
            if not is_modular_spine and "collection_time" not in switch_data:
                switch_data["collection_time"] = "unknown"
                
            # Ensure raw_ls_output is preserved if collected
            if "raw_ls_output" in diagnostics:
                switch_data["raw_ls_output"] = diagnostics["raw_ls_output"]
            
            # Restore ownership information we collected earlier
            for key, value in ownership_data.items():
                switch_data[key] = value
                
            # If we're root and made ownership changes, ensure that's marked
            if is_root and kickstart_image:
                # Ensure ownership flags are properly set
                if "ownership_fixed" in switch_data:
                    switch_data["ownership_fixed_attempted"] = True
                if "original_permissions" in switch_data:
                    # Check current permissions against the original to determine if fixed
                    switch_data["permissions_fixed"] = (switch_data.get("file_permissions") == "-rw-rw-rw-")
            
            # Add diagnostics reference to the result
            switch_data["diagnostics"] = diagnostics
        
    except Exception as e:
        # Handle any unexpected exceptions
        error_msg = str(e)
        diagnostics["error_type"] = "exception"
        diagnostics["exception"] = error_msg
        switch_data["message"] = f"Exception: {error_msg}"
        return switch_data
    finally:
        # Always mark as completed in progress bar
        progress_bar.update(f"Completed {sw_name}", 1)
    
    return switch_data

def process_switches_in_batches(switch_ips, mod_spine_ips, switch_info, progress_bar, 
                              md5_32bit, md5_64bit, apic_addr, batch_size=None, result_logger=None):
    """
    Process switches in batches with dynamic resource management
    """
    # Get a dedicated logger for this function to avoid duplicates
    batch_logger = get_logger("process_switches")
    
    # Check system resources to determine optimal batch size
    if batch_size is None:
        resources = check_system_resources()
        batch_size = resources.get("recommended_threads", 5)
    
    # Log but don't print to console
    batch_logger.info(f"Using batch size of {batch_size} concurrent connections")
    
    results = {}
    all_ips = switch_ips + mod_spine_ips
    total_count = len(all_ips)
    completed = 0
    
    # Process switches in batches
    with ThreadPoolExecutor(max_workers=batch_size) as executor:
        # Submit all jobs with metadata
        futures = {}
        for sw_ip in all_ips:
            is_modular_spine = sw_ip in mod_spine_ips
            future = executor.submit(
                process_switch,
                sw_ip,
                switch_info,
                progress_bar,
                switch_info.username,
                switch_info.password,
                None if is_modular_spine else md5_32bit,
                md5_64bit,  # Always pass md5_64bit regardless of switch type
                apic_addr,
                is_modular_spine
            )
            futures[future] = {
                "ip": sw_ip,
                "name": switch_info.get_switch_name(sw_ip),
                "is_modular_spine": is_modular_spine
            }
        
        # Process results as they complete
        for future in as_completed(futures, timeout=None):
            switch_info = futures[future]
            sw_ip = switch_info["ip"]
            sw_name = switch_info["name"]
            
            try:
                # Add per-switch timeout
                switch_data = future.result(timeout=120)
                
                # Store and log results
                if switch_data:
                    # Use result_logger instead of logger
                    result_logger.log_switch_result(switch_data)
                    results[sw_ip] = switch_data
                
            except concurrent.futures.TimeoutError:
                # Use result_logger instead of logger
                result_logger.log_switch_result({
                    "switch": sw_name,
                    "ip": sw_ip,
                    "status": "timeout",
                    "result": "ERROR", 
                    "message": "Operation timed out after 120 seconds"
                })
            except Exception as e:
                # Use result_logger instead of logger
                result_logger.log_switch_result({
                    "switch": sw_name,
                    "ip": sw_ip,
                    "status": "error",
                    "result": "ERROR",
                    "message": f"Exception: {str(e)}"
                })
            
            # Update progress
            completed += 1
            progress_bar.update(f"Processed {completed} of {total_count} switches", 0)
    
    return results

###########################################
# Report Utilities
###########################################

def format_switch_data_for_output(switch_data, include_diagnostics=False, for_json=False):
    """
    Format switch data consistently for various output formats
    
    Args:
        switch_data (dict): Raw switch data dictionary
        include_diagnostics (bool): Whether to include detailed diagnostics
        for_json (bool): Format for JSON export (no color codes, structured data)
        
    Returns:
        dict: A standardized formatted data dictionary for the output format
    """
    # Extract common fields
    formatted_data = {
        "switch": switch_data.get("switch", "Unknown"),
        "ip": switch_data.get("ip", "Unknown"),
        "memory_kb": switch_data.get("memory_kb"),
        "memory_gb": switch_data.get("memory_gb"),
        "image_path": switch_data.get("image_path", "Unknown"),
        "md5sum": switch_data.get("md5sum", "Unknown"),
        "result": switch_data.get("result", "ERROR"),
        "status": switch_data.get("status", "error"),
        "boot_mode": switch_data.get("boot_mode", "normal"),
        "collection_time": switch_data.get("collection_time", "unknown")
    }
    
    # Format memory display
    if formatted_data["memory_gb"] is not None:
        formatted_data["memory_display"] = f"{formatted_data['memory_gb']} GB"
    elif formatted_data["memory_kb"] not in (None, "Unknown"):
        try:
            gb_value = MemoryCheck.standardize_memory_gb(formatted_data["memory_kb"])
            formatted_data["memory_display"] = f"{gb_value} GB" if gb_value else f"{formatted_data['memory_kb']} KB"
        except (ValueError, TypeError):
            formatted_data["memory_display"] = f"{formatted_data['memory_kb']} KB"
    else:
        formatted_data["memory_display"] = "Unknown"
    
    # Process message and extract MD5 and Repodata parts
    full_message = switch_data.get("message", "No validation message")
    
    # Split the message to separate MD5 result and Repodata result
    if " | Repodata Check:" in full_message:
        md5_message = full_message.split(" | Repodata Check:")[0]
        repodata_message = full_message.split(" | Repodata Check:")[1].strip()
    else:
        md5_message = full_message
        repodata_message = ""
    
    formatted_data["md5_message"] = md5_message
    formatted_data["repodata_message"] = repodata_message
    
    # Format repodata check result if available
    repodata_result = switch_data.get("repodata_check", "ERROR")
    formatted_data["repodata_result"] = repodata_result
    
    if repodata_result == "PASS":
        formatted_data["repodata_description"] = "(.repodata file not present)"
    elif repodata_result == "FAIL":
        formatted_data["repodata_description"] = "(.repodata directory exists)"
    else:
        formatted_data["repodata_description"] = "(check failed)"
    
    # Add color codes for terminal display (unless for JSON)
    if not for_json:
        md5_color = RESULT_COLORS.get(formatted_data["result"], "")
        repodata_color = RESULT_COLORS.get(formatted_data["repodata_result"], "")
        reset = RESULT_COLORS["RESET"]
        
        formatted_data["md5_result_colored"] = f"{md5_color}{formatted_data['result']}{reset}"
        formatted_data["repodata_result_colored"] = f"{repodata_color}{formatted_data['repodata_result']}{reset}"
    
    # Check for permission denied
    permission_denied = False
    cmd_output = switch_data.get("md5_command_output", "")
    diagnostics = switch_data.get("diagnostics", {})
    
    if cmd_output and "permission denied" in cmd_output.lower():
        permission_denied = True
    
    formatted_data["permission_denied"] = permission_denied
    
    # Determine if recommendations are needed
    formatted_data["recommendations_needed"] = (
        formatted_data["result"] == "FAIL" or 
        formatted_data["repodata_result"] == "FAIL" or 
        permission_denied
    )
    
    # Only generate recommendations for JSON export
    if formatted_data["recommendations_needed"] and for_json:
        # Keep this recommendation generation ONLY for JSON export
        recommendations = []
        
        if permission_denied:
            recommendations.append("Re-run the script from the owner account or root to rectify the permissions issue.")
            
            # Look for owner information
            owner = None
            
            # Try various sources for owner info
            if "file_owner" in switch_data:
                owner = switch_data["file_owner"]
            elif diagnostics and "file_owner" in diagnostics:
                owner = diagnostics["file_owner"]
            
            if owner:
                recommendations.append(f"The owner of the file is: {owner}")
        
        if formatted_data["result"] == "FAIL" and not permission_denied:
            recommendations.append("Contact Cisco TAC for assistance in setting boot variable to use correct switch image.")
            recommendations.append("Defect Reference: https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj44966")
        
        if formatted_data["repodata_result"] == "FAIL":
            if formatted_data["result"] == "FAIL" or permission_denied:
                # Add a separator for better readability in text output
                recommendations.append("")
            recommendations.append("Contact Cisco TAC to remove .repodata file via root user.")
            recommendations.append("Defect Reference: https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwo34637")
        
        formatted_data["recommendations"] = recommendations
    
    # Include diagnostics if requested
    if include_diagnostics:
        # Build comprehensive diagnostics
        diag_data = {}
        
        # First check for MD5 retrieval errors - this is highest priority
        if switch_data.get("md5sum") is None and switch_data.get("image_path") is not None:
            diag_data["error_type"] = "md5_retrieval"
            
            # Check command output for specific error messages
            if cmd_output:
                cmd_output_lower = cmd_output.lower() if cmd_output else ""
                
                if "permission denied" in cmd_output_lower:
                    diag_data["md5_error"] = "Permission denied when accessing image file"
                    
                    # If permission denied, extract the specific output
                    permission_line = CommandOutputProcessor.extract_single_line(
                        cmd_output, "permission denied", switch_data.get("switch", "")
                    )
                    if permission_line:
                        diag_data["permission_line"] = permission_line.strip()
                    
                    # Extract file info if available
                    if "raw_ls_output" in switch_data:
                        file_info = CommandOutputProcessor.extract_file_info(
                            switch_data["raw_ls_output"], 
                            switch_data.get("switch", "")
                        )
                        if file_info["file_line"]:
                            diag_data["file_info"] = file_info["file_line"]
                        elif file_info["file_details"]:
                            diag_data["file_info"] = file_info["file_details"]
                    
                elif "no such file" in cmd_output_lower:
                    diag_data["md5_error"] = "Image file not found"
                else:
                    diag_data["md5_error"] = "Unknown error retrieving MD5"
                    
                # Clean the command output for display
                cleaned_output = CommandOutputProcessor.clean_output(
                    cmd_output, switch_data.get("switch", "")
                )
                if for_json:
                    # For JSON, just include the cleaned output
                    diag_data["command_output"] = cleaned_output.strip()
                else:
                    # For text display, format it more compactly
                    diag_data["command_output"] = CommandOutputProcessor.format_for_display(
                        cleaned_output
                    )
        
        # Next, incorporate any existing diagnostic information that's suitable for display
        if diagnostics:
            for key, value in diagnostics.items():
                # Skip raw outputs and complex nested structures for clarity
                if key not in ("raw_ls_output", "verification_output") and not isinstance(value, dict):
                    if isinstance(value, str):
                        # Remove ANSI color codes for consistent display
                        value = re.sub(r'\033\[[0-9;]*m', '', value)
                    # Don't overwrite existing error_type if we've already set it
                    if key != "error_type" or "error_type" not in diag_data:
                        diag_data[key] = value
        
        formatted_data["diagnostics"] = diag_data
    
    return formatted_data

def export_results_to_json(results, summary, filename, apic_version):
    """Export validation results to a JSON file for automation scenarios"""
    try:
        # Create a structured output format
        export_data = {
            "script_version": "1.0.0",
            "timestamp": datetime.now().isoformat(),
            "apic_version": apic_version,
            "summary": {
                "md5_check": {
                    "pass": summary.get("pass", 0),
                    "fail": summary.get("fail", 0),
                    "warning": summary.get("warning", 0),
                    "error": summary.get("error", 0)
                },
                "repodata_check": {
                    "pass": summary.get("repodata_pass", 0),
                    "fail": summary.get("repodata_fail", 0),
                    "error": summary.get("repodata_error", 0)
                },
                "performance": {
                    "total_time_seconds": summary.get("total_time", 0),
                    "average_time_per_switch_seconds": summary.get("average_time", 0)
                }
            },
            "switches": []
        }
        
        # Process each switch result
        for sw_ip, switch_data in results.items():
            # Use the common formatter with JSON-specific options
            formatted_data = format_switch_data_for_output(
                switch_data, 
                include_diagnostics=True,
                for_json=True
            )
            
            # Create JSON-friendly structure
            switch_result = {
                "name": formatted_data["switch"],
                "ip": formatted_data["ip"],
                "memory_kb": formatted_data["memory_kb"],
                "memory_display": formatted_data["memory_display"],
                "image_path": formatted_data["image_path"],
                "md5sum": formatted_data["md5sum"],
                "md5_check": {
                    "result": formatted_data["result"],
                    "message": formatted_data["md5_message"]
                },
                "repodata_check": {
                    "result": formatted_data["repodata_result"],
                    "message": formatted_data["repodata_description"]
                },
                "collection_time": formatted_data["collection_time"],
                "status": formatted_data["status"]
            }
            
            # Include the recommendations directly from the formatted data
            # This preserves the TAC references and bug IDs
            if "recommendations" in formatted_data:
                switch_result["recommendations"] = formatted_data["recommendations"]
            
            # Include complete diagnostics from the formatted data
            if "diagnostics" in formatted_data:
                switch_result["diagnostics"] = formatted_data["diagnostics"]
            
            export_data["switches"].append(switch_result)
            
        # Write the JSON file
        with open(filename, 'w') as json_file:
            json.dump(export_data, json_file)
            
    except Exception as e:
        logger.log_message(f"Error exporting to JSON: {str(e)}")
        logging.error(f"Error exporting to JSON: {str(e)}")

###########################################
# Main Program Logic
###########################################

def main():
    """Main function implementing the ACI Switch SMU Pre-upgrade Validation workflow"""
    
    # Start timing for script execution
    script_start_time = time.time()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="ACI Switch SMU Pre-upgrade Validation Script")
    parser.add_argument("--json", help="Export results to JSON file", metavar="FILENAME")
    parser.add_argument("--username", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    args = parser.parse_args()

    # Check if we're in automation mode
    automation_mode = args.json is not None

    # Print header information (only if not in automation mode)
    if not automation_mode:
        print("======================================================")
        print(" ACI Switch SMU Pre-upgrade Validation Script")
        print(f" {datetime.now()}")
        print("======================================================")
        print()

    # Create switch info handler and result logger
    switch_info = SwitchInfo()
    result_logger = ResultLogger()  # Renamed to result_logger to avoid confusion

    # Get credentials with special handling for root user
    if args.username and args.password:
        # If username and password are provided, use them
        switch_info.username = args.username
        switch_info.password = args.password
        print(f"Using provided credentials for user: {switch_info.username}")
        
        # Even with provided credentials, we still need to show debug token for root
        if switch_info.username == "root":
            try:
                # Run acidiag dbgtoken command
                result = subprocess.run(['acidiag', 'dbgtoken'], stdout=subprocess.PIPE, text=True, check=True)
                dbgtoken = result.stdout.strip()
                # Display the debug token to the user
                print(f"\nDebug Token: {dbgtoken}")
                # Note: we'll use the provided password, no need to prompt again
            except subprocess.CalledProcessError as e:
                print("\n\033[1;31mError: Failed to get debug token. Make sure you're running this script on an APIC.\033[0m")
    else:
        # Otherwise prompt for credentials with special handling for root
        print("Please enter your credentials:")
        switch_info.username = input("Username: ")
        
        # If username is root, show debug token before password prompt
        if switch_info.username == "root":
            try:
                # Run acidiag dbgtoken command
                result = subprocess.run(['acidiag', 'dbgtoken'], stdout=subprocess.PIPE, text=True, check=True)
                dbgtoken = result.stdout.strip()
                # Display the debug token to the user
                print(f"Debug Token: {dbgtoken}")
                # Now prompt for password
                switch_info.password = getpass("Root Password: ")
                print()  # Add a newline after password input
            except subprocess.CalledProcessError as e:
                print("\n\033[1;31mError: Failed to get debug token. Make sure you're running this script on an APIC.\033[0m")
                switch_info.password = getpass(f"Password for {switch_info.username}: ")
                print()
        else:
            # For non-root users, just ask for password normally
            switch_info.password = getpass(f"Password for {switch_info.username}: ")
            print()  # Print newline after password input

    # Get APIC management IP - print to console and log to file
    print("Getting APIC management address...")
    result_logger.log_message("Getting APIC management address...")
    apic_addr = switch_info.get_appliance_address()
    print(f"Using APIC management address: {apic_addr}")
    result_logger.log_message(f"Using APIC management address: {apic_addr}")

    # Verify credentials against APIC
    if not switch_info.verify_credentials():
        result_logger.log_message("Authentication failure after multiple attempts. Script exiting.")
        return 2  # Exit with auth failure code

    # Get switch memory capacity data from APIC API
    print("Getting switch memory capacity data...")
    result_logger.log_message("Getting switch memory capacity data...")
    try:
        switch_info.load_switch_memory()
        print(f"Retrieved memory data for {len(switch_info.switch_memory)} switches")
        result_logger.log_message(f"Retrieved memory data for {len(switch_info.switch_memory)} switches")
    except Exception as e:
        print(f"Warning: Could not retrieve memory data from APIC API: {str(e)}")
        print("Falling back to 'show version' method for memory detection")
        result_logger.log_message(f"Warning: Could not retrieve memory data from APIC API: {str(e)}")

    # Get switch kickstart image data from APIC API
    print("Getting switch kickstart image data...")
    result_logger.log_message("Getting switch kickstart image data...")
    try:
        switch_info.load_switch_kickstart_images()
        print(f"Retrieved kickstart image data for {len(switch_info.switch_kickstart)} switches")
        result_logger.log_message(f"Retrieved kickstart image data for {len(switch_info.switch_kickstart)} switches")
    except Exception as e:
        print(f"Warning: Could not retrieve kickstart image data from APIC API: {str(e)}")
        print("Falling back to 'show version' method for image path detection")
        result_logger.log_message(f"Warning: Could not retrieve kickstart image data from APIC API: {str(e)}")

    # Dynamically get MD5 hashes for the current APIC version - print to console and log to file
    print("Determining APIC version and MD5 hashes...")
    result_logger.log_message("Determining APIC version and MD5 hashes...")
    try:
        md5_32bit, md5_64bit, apic_version, images_missing = get_dynamic_md5_hashes()
        print(f"APIC version: {apic_version}")
        print(f"32-bit image MD5: {md5_32bit}")
        print(f"64-bit image MD5: {md5_64bit}")
        result_logger.log_message(f"APIC version: {apic_version}")
        result_logger.log_message(f"32-bit image MD5: {md5_32bit}")
        result_logger.log_message(f"64-bit image MD5: {md5_64bit}")
        
        # If both images are missing, exit with a message
        if images_missing:
            print("\n\033[1;31mSwitch images not found. Script exiting.\033[0m\n")
            result_logger.log_message("Switch images not found. Script exiting.")
            return 1
            
    except Exception as e:
        # Critical errors still show
        print(f"\033[1;31mError retrieving MD5 hashes: {str(e)}\033[0m")
        return 1
    
    # Get switch list - print to console and log to file
    print("Retrieving switch information...")
    result_logger.log_message("Retrieving switch information...")
    try:
        # Get switches using consolidated functions
        leaf_ips = switch_info.get_switches_by_role(role="leaf")
        spine_ips = switch_info.get_switches_by_role(role="spine", filter_modular=False)
        mod_spine_ips = switch_info.get_switches_by_role(role="spine", filter_modular=True)
        
        mod_spine_count = len(mod_spine_ips)
        switch_ips = leaf_ips + spine_ips
        switch_count = len(switch_ips)
        total_count = switch_count + mod_spine_count
        
        if switch_count == 0 and mod_spine_count == 0:
            # Only show critical errors
            print("\033[1;31mError: No active switches found. Check APIC connectivity.\033[0m")
            return 1
        
        # Print to console and log to file
        print(f"Found {switch_count} switches and {mod_spine_count} modular spine switches.")
        print("Starting data collection in parallel...")
        result_logger.log_message(f"Found {switch_count} switches and {mod_spine_count} modular spine switches.")
        result_logger.log_message("Starting data collection in parallel...")
        
    except Exception as e:
        # Critical errors still show
        print(f"\033[1;31mError retrieving switch information: {str(e)}\033[0m")
        return 1
    
    # Set up progress bar - this will be the main visual indicator
    # Use total count for the progress bar (including modular spines)
    progress_bar = ProgressBar(total_count, script_start_time)
    progress_bar.setup()
    
    # Process switches in parallel 
    results = {}

    try:
        # Check system resources before starting but don't print to console
        logger.info("Checking system resources for optimal concurrency...")
        resources = check_system_resources()

        batch_size = resources.get("recommended_threads", 5)
        logger.info(f"Using batch size of {batch_size} concurrent connections")

        # Use enhanced batch processing instead of simple ThreadPoolExecutor
        results = process_switches_in_batches(
            switch_ips,
            mod_spine_ips,
            switch_info,
            progress_bar,
            md5_32bit,
            md5_64bit,
            apic_addr,
            batch_size,
            result_logger
        )

        # Generate summary when all switches processed
        progress_bar.update("Generating report", 0)
        time.sleep(1)  # Brief pause for UI update
        progress_bar.finish()  # This will complete the progress bar

        # Generate and display the summary
        summary = result_logger.generate_summary(total_count)
        
    except KeyboardInterrupt:
        print("\n\033[1;31mProcess interrupted by user\033[0m")
        result_logger.log_message("Process interrupted by user")
        # Ensure progress bar is properly closed before showing summary
        progress_bar.finish()
        result_logger.generate_summary(total_count)
        return 130  # Standard exit code for SIGINT
        
    except Exception as e:
        print(f"\n\033[1;31mUnexpected error: {str(e)}\033[0m")
        result_logger.log_message(f"Unexpected error: {str(e)}")
        # Ensure progress bar is properly closed before showing summary
        progress_bar.finish()
        result_logger.generate_summary(total_count)
        return 1
        
    finally:
        pass
    
    # JSON arg
    if args.json:
        export_results_to_json(results, summary, args.json, apic_version)
        if not automation_mode:
            print(f"\nJSON results exported to: {args.json}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
