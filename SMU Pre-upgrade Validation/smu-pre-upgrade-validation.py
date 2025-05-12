#!/usr/bin/env python3
"""
ACI SMU Pre-upgrade Validation Script

This script validates Cisco ACI switches against known SMU issues.

Check 1: Ensure correct image type (32-bit or 64-bit) based on switch memory capacity
Check 2: Ensure .repodata file does not exist

@ Author: joelebla@cisco.com
@ Version: 1.1.0
@ Date: 05/11/2025
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
# Logging Configuration
###########################################

# Create logs directory if it doesn't exist
log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)

# Configure logging
log_file = os.path.join(log_dir, 'smu-check-debug.log')
log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
log_level = logging.DEBUG  # Change to INFO for production

# Configure the root logger with NO console output
logging.basicConfig(level=log_level, format=log_format, handlers=[])

# Create file handler with rotation (10 MB per file, keep 5 backup files)
file_handler = RotatingFileHandler(
    filename=log_file, 
    maxBytes=10*1024*1024,  # 10 MB
    backupCount=5
)
file_handler.setFormatter(logging.Formatter(log_format))
file_handler.setLevel(log_level)

# Create console handler with CRITICAL level to completely suppress normal logs
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(log_format))
# Set to CRITICAL to ensure only critical errors are shown
console_handler.setLevel(logging.CRITICAL)  

# Give the file handler a unique ID to prevent duplication
file_handler.id = "main_file_handler"

# Tracking system for handler attachment
_handler_attached_loggers = set()

def ensure_file_handler(logger):
    """Ensure the file handler is attached to a logger without duplication"""
    global _handler_attached_loggers
    
    # Use a combination of logger name and file handler's ID for tracking
    handler_key = f"{logger.name}:{file_handler.id}"
    
    # Check if we've already attached this exact handler to this logger
    if handler_key in _handler_attached_loggers:
        return
    
    # Check if any existing handler is the same file handler
    for handler in logger.handlers:
        if hasattr(handler, 'id') and handler.id == file_handler.id:
            # Already has this exact handler
            _handler_attached_loggers.add(handler_key)
            return
    
    # No duplicates - add handler and track
    logger.addHandler(file_handler)
    _handler_attached_loggers.add(handler_key)

def get_module_logger(name=None):
    """
    Get a properly configured logger that won't duplicate messages
    
    Args:
        name: Logger name (uses __name__ if None)
        
    Returns:
        logging.Logger: Configured logger
    """
    log_name = name or __name__
    
    # Use existing logger if possible
    module_logger = logging.getLogger(log_name)
    
    # Configure only if not already set up
    if not getattr(module_logger, '_is_configured', False):
        module_logger.setLevel(log_level)
        module_logger.propagate = False  # Prevent propagation to root logger
        ensure_file_handler(module_logger)
        module_logger._is_configured = True
        
    return module_logger

# Completely reset root logger to avoid any duplicate handlers
root_logger = logging.getLogger()
root_logger.handlers = []  # Clear ALL handlers
root_logger.addHandler(file_handler)
root_logger.addHandler(console_handler)

# Set a module-level logger and ensure it has proper setup
logger = logging.getLogger(__name__)
logger.propagate = False  # Prevent propagation to root logger
ensure_file_handler(logger)

logger.info("Script started")

###########################################
# System Resource Management
###########################################

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
# Connection Management 
###########################################

class Connection:
    """Handles SSH connections to network switches with improved reliability"""
    
    def __init__(self, hostname, username=None, password=None, timeout=30, bind_address=None):
        """Initialize SSH connection handler"""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.child = None
        self.output = ""
        self.prompt = r'[#%>]\s*$'  # Match #, %, or > followed by optional whitespace
        self.log = logging.getLogger(f'connection.{hostname}')
        self.log.setLevel(logging.DEBUG)
        self.log.propagate = False
        ensure_file_handler(self.log)
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
                    f"{self.username}@{self.hostname}"
                )
                
                self.log.debug(f"SSH command: {ssh_cmd}")
                
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
                self.output = output.strip()
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
        logger = logging.getLogger(__name__)
    
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

###########################################
# Data Collection Classes & Functions
###########################################

def get_md5_hash(image_name=None, system_image_name=None):
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
    if not image_name and not system_image_name:
        logger.error("No image name or system image name provided")
        return "Image not found"
        
    md5_hash = None
    
    # Method 1: Try API query if system_image_name is provided
    if system_image_name:
        logger.info(f"Method 1: Attempting to get MD5 from firmwareFirmware API for {system_image_name}")
        md5_hash = _get_md5_from_api(system_image_name)
        if md5_hash and md5_hash != "Image not found in API":
            logger.info(f"Successfully retrieved MD5 from API: {md5_hash}")
            return md5_hash
        logger.warning("API method failed, falling back to md5sum file")
    
    # Convert system_image_name to kickstart_image_name if needed
    if not image_name and system_image_name:
        # Convert from "aci-n9000-system.X.Y.Z.bin" to "aci-n9000-dk9.X.Y.Z.bin"
        image_name = system_image_name.replace("aci-n9000-system", "aci-n9000-dk9")
        logger.info(f"Converted system image name to kickstart image name: {image_name}")
    
    # Method 2: Try md5sum file method
    if image_name:
        logger.info(f"Method 2: Attempting to get MD5 from md5sum file for {image_name}")
        md5_hash = _get_md5_from_file(image_name)
        if md5_hash and md5_hash != "Image not found in fwrepo":
            logger.info(f"Successfully retrieved MD5 from file: {md5_hash}")
            return md5_hash
        logger.warning("MD5sum file method failed, falling back to direct calculation")
    
    # Method 3: Try direct calculation
    if image_name:
        logger.info(f"Method 3: Attempting to calculate MD5 directly for {image_name}")
        md5_hash = _calculate_md5_directly(image_name)
        if md5_hash:
            logger.info(f"Successfully calculated MD5 directly: {md5_hash}")
            return md5_hash
        logger.warning("Direct MD5 calculation failed")
    
    # If all methods failed, return consistent error message
    logger.error("All MD5 retrieval methods failed")
    return "Image not found"

def _get_md5_from_api(system_image_name):
    """
    Get MD5 hash from firmwareFirmware API using icurl.
    
    Args:
        system_image_name (str): Name of the system image (e.g., aci-n9000-system.16.0.8e.bin)
        
    Returns:
        str: MD5 hash or error message
    """
    logger.debug(f"Querying firmwareFirmware API for {system_image_name}")
    
    try:
        # Construct the icurl command with proper escaping
        icurl_cmd = f"icurl -gs 'http://127.0.0.1:7777/api/class/firmwareFirmware.json?query-target-filter=eq(firmwareFirmware.name,\"{system_image_name}\")'"
        logger.debug(f"Executing icurl command: {icurl_cmd}")
        
        # Execute the command with timeout
        process = subprocess.Popen(icurl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=30)
        
        if process.returncode != 0:
            logger.warning(f"icurl command failed with return code {process.returncode}")
            logger.debug(f"stderr: {stderr.decode('utf-8') if stderr else 'None'}")
            return "Image not found in API"
        
        output = stdout.decode('utf-8')
        logger.debug(f"icurl output: {output[:200]}...")  # Log first 200 chars
        
        # Parse the JSON output
        json_data = json.loads(output)
        
        # Check if we have the expected data structure
        if "imdata" in json_data and len(json_data["imdata"]) > 0:
            firmware_obj = json_data["imdata"][0].get("firmwareFirmware", {}).get("attributes", {})
            
            # Extract checksum from the JSON
            checksum = firmware_obj.get("checksum")
            if checksum and re.match(r'^[0-9a-f]{32}$', checksum):
                return checksum
            else:
                logger.warning(f"checksum not found or invalid in API response")
        else:
            logger.warning("No firmware data found in API response")
            
        return "Image not found in API"
        
    except subprocess.TimeoutExpired:
        logger.warning("icurl command timed out after 30 seconds")
        return "Image not found in API"
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse JSON from API response: {str(e)}")
        return "Image not found in API"
    except Exception as e:
        logger.warning(f"Error getting MD5 from API: {str(e)}")
        return "Image not found in API"

def _get_md5_from_file(image_filename):
    """
    Get MD5 hash from md5sum file.
    
    Args:
        image_filename (str): Name of the image file
        
    Returns:
        str: MD5 hash or error message
    """
    md5sum_file = f"/firmware/fwrepos/fwrepo/md5sum/{image_filename}"
    
    # Check if the file exists without printing errors
    if not os.path.exists(md5sum_file):
        logger.warning(f"MD5 file not found: {md5sum_file}")
        return "Image not found in fwrepo"
    
    try:
        # Read the md5sum file
        with open(md5sum_file, 'r') as f:
            content = f.read().strip()
            
        # Extract MD5 hash (first field)
        if content:
            md5_hash = content.split()[0]
            if re.match(r'^[0-9a-f]{32}$', md5_hash):
                return md5_hash
        
        logger.warning(f"Invalid content in MD5 file: {md5sum_file}")
        return "Image not found in fwrepo"
        
    except Exception as e:
        logger.warning(f"Error reading MD5 file {md5sum_file}: {str(e)}")
        return "Image not found in fwrepo"

def _calculate_md5_directly(image_filename):
    """
    Calculate MD5 hash directly from the image file.
    
    Args:
        image_filename (str): Name of the image file
        
    Returns:
        str: MD5 hash or None if calculation fails
    """
    image_path = f"/firmware/fwrepos/fwrepo/{image_filename}"
    
    # Check if the image file exists
    if not os.path.exists(image_path):
        logger.warning(f"Image file not found: {image_path}")
        return None
    
    try:
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
        md5_32bit = get_md5_hash(image_name=image_32bit, system_image_name=system_image_32bit)
        md5_64bit = get_md5_hash(image_name=image_64bit, system_image_name=system_image_64bit)
        
        # Log which method was used for each image
        if md5_32bit:
            logger.info(f"Retrieved 32-bit MD5 from firmwareFirmware API: {md5_32bit}")
        
        if md5_64bit:
            logger.info(f"Retrieved 64-bit MD5 from firmwareFirmware API: {md5_64bit}")
        
        # STEP 2: If API method failed for either image, try md5sum file method
        if not md5_32bit or md5_32bit == "Image not found in API":
            logger.info("Falling back to md5sum file for 32-bit image")
            md5_32bit = get_md5_hash(image_32bit)
            
            if md5_32bit and md5_32bit != "Image not found in fwrepo":
                logger.info(f"Retrieved 32-bit MD5 from md5sum file: {md5_32bit}")
        
        if not md5_64bit or md5_64bit == "Image not found in API":
            logger.info("Falling back to md5sum file for 64-bit image")
            md5_64bit = get_md5_hash(image_64bit)
            
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
        verify_logger = logging.getLogger('verify_creds')
        verify_logger.setLevel(logging.DEBUG)
        ensure_file_handler(verify_logger)
        verify_logger.propagate = False
        
        apic_addr = self.get_appliance_address()
        print(f"Verifying credentials against APIC ({apic_addr})...")
        
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
        name_logger = get_module_logger("switch_names")
        
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
                name_logger.warning(f"No name found for {sw_ip}, using fallback with node ID: {self.switch_names[sw_ip]}")
            else:
                self.switch_names[sw_ip] = f"switch-{sw_ip}"
                name_logger.warning(f"No name found for {sw_ip}, using fallback: {self.switch_names[sw_ip]}")
        
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
                                logger.warning(f"Invalid memory capacity value for node {node_id}: {cap}")
                    
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
                                    logger.warning(f"Could not extract image name from recovery ksFile: {ks_file}")
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
                                    logger.warning(f"Could not extract image name from ksFile: {ks_file}")
                
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

def check_repodata(conn):
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
        result_type = conn.execute_command(f"ls -lh {repodata_path}")
        output = conn.output
        
        # If the command was successful and doesn't contain "cannot access" or similar error
        # then the directory exists which is a FAIL condition
        if result_type == "prompt" and "cannot access" not in output and "No such file or directory" not in output:
            return "FAIL", output
        else:
            return "PASS", output
    except Exception as e:
        # If there was an error executing the command, consider it inconclusive
        return "ERROR", f"Command execution error: {str(e)}"

class SwitchDataCollector:
    """Centralized handler for switch data collection and validation"""
    
    # Common regex patterns for data extraction
    MEMORY_PATTERN = r'with\s+(\d{7,8})\s+kB\s+of\s+memory'
    IMAGE_PATH_PATTERNS = [
        r'kickstart\s+image\s+file\s+is\s+:\s+(\S+)',
        r'kickstart image file is:\s+(\S+)',
        r'kickstart\s+image\s+file\s+is\s+(\S+)'
    ]
    MD5_PATTERN = r'([0-9a-f]{32})'
    MEMORY_THRESHOLD = 32000000  # 32GB in KB
    
    @staticmethod
    def extract_memory(version_output):
        """Extract memory capacity from version output"""
        memory_match = re.search(SwitchDataCollector.MEMORY_PATTERN, version_output)
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
        for pattern in SwitchDataCollector.IMAGE_PATH_PATTERNS:
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
    def extract_md5(md5_output):
        """Extract MD5 hash from command output"""
        md5_match = re.search(SwitchDataCollector.MD5_PATTERN, md5_output)
        return md5_match.group(1) if md5_match else None
    
    @staticmethod
    def collect_data(sw_name, sw_ip, conn, switch_info=None, kickstart_image=None, memory_kb=None, memory_gb=None):
        """
        Collect all required data from a switch
        
        Args:
            sw_name: Switch name for identification
            sw_ip: Switch IP address
            connection: An established SSH connection object
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
                        kb_value = mem_info
                        # Convert to standardized GB value
                        if kb_value < 20000:
                            result["memory_gb"] = 16
                        elif kb_value < 30000:
                            result["memory_gb"] = 24
                        elif kb_value < 40000:
                            result["memory_gb"] = 32
                        elif kb_value < 70000 and kb_value > 60000:
                            result["memory_gb"] = 64
                        else:
                            result["memory_gb"] = round(kb_value / 1024)
                        logger.debug(f"Converted memory data for {sw_name}: {kb_value} KB to {result['memory_gb']} GB")
                
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
                result_type = conn.execute_command("show version")
                if result_type != "prompt":
                    raise RuntimeError(f"Failed to get version info: {result_type}")
                    
                version_output = conn.output
                
                # If memory wasn't retrieved, try extracting it from show version
                if result.get("memory_kb") is None and result.get("memory_gb") is None:
                    memory_kb = SwitchDataCollector.extract_memory(version_output)
                    # Convert to standardized GB value
                    if memory_kb:
                        result["memory_kb"] = memory_kb
                        if memory_kb < 20000:
                            result["memory_gb"] = 16
                        elif memory_kb < 30000:
                            result["memory_gb"] = 24
                        elif memory_kb < 40000:
                            result["memory_gb"] = 32
                        elif memory_kb < 70000 and memory_kb > 60000:
                            result["memory_gb"] = 64
                        else:
                            result["memory_gb"] = round(memory_kb / 1024)
                
                # Extract kickstart image path if we don't have it yet
                if result.get("image_path") is None:
                    image_path = SwitchDataCollector.extract_image_path(version_output)
                    result["image_path"] = image_path
            
            # Get MD5 checksum of the image if we have a path
            if result.get("image_path"):
                # Get MD5 checksum of the image
                kickstart_image = result["image_path"]
                result_type = conn.execute_command(f"md5sum {kickstart_image}")
                md5_output = conn.output
                md5_hash = SwitchDataCollector.extract_md5(md5_output)
                
                # Store the command output to help diagnose MD5 retrieval failures
                result["md5_command_output"] = md5_output
                
                if not md5_hash:
                    # Try to fix permissions and retry
                    conn.execute_command(f"chmod 666 {kickstart_image}")
                    result_type = conn.execute_command(f"md5sum {kickstart_image}")
                    if result_type != "prompt":
                        raise RuntimeError(f"Failed to get MD5 checksum: {result_type}")
                        
                    md5_output = conn.output
                    result["md5_command_output"] = md5_output
                    md5_hash = SwitchDataCollector.extract_md5(md5_output)
                
                result["md5sum"] = md5_hash
                
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
        
        # Prefer memory_gb if available, otherwise use memory_kb and threshold
        if "memory_gb" in switch_data and switch_data["memory_gb"] is not None:
            memory_gb = switch_data.get("memory_gb")
            # Memory threshold is 32GB
            has_high_memory = memory_gb >= 32
        else:
            memory_kb = switch_data.get("memory_kb")
            # Memory threshold is 32GB in KB (32000000)
            has_high_memory = memory_kb >= SwitchDataCollector.MEMORY_THRESHOLD if memory_kb else False
        
        md5sum = switch_data.get("md5sum")
        
        # More specific error messages based on what's missing
        if (not has_high_memory and not "memory_gb" in switch_data and 
                not "memory_kb" in switch_data) and not md5sum:
            return "ERROR", "Could not retrieve Memory and MD5 information"
        elif not has_high_memory and not "memory_gb" in switch_data and not "memory_kb" in switch_data:
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
        
        # Validate memory against image type
        if not has_high_memory:
            if image_type == "32bit":
                return "PASS", "Running 32bit image with less than 32GB memory"
            else:
                return "FAIL", "Running 64bit image with less than 32GB memory"
        else:
            if image_type == "64bit":
                return "PASS", "Running 64bit image with 32GB memory or greater"
            else:
                return "FAIL", "Running 32bit image with 32GB memory or greater"
    
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
# Switch Processing
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
                        logger=logging.getLogger(f'connection.{sw_ip}')
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
                        logger=logging.getLogger(f'connection.{sw_ip}')
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
                        logger=logging.getLogger(f'connection.{sw_ip}')
                    )
                    raise
            
            # Connection successful - now perform checks based on switch type
            if is_modular_spine:
                # Pass the pre-collected kickstart image path and memory information
                switch_data = perform_modular_spine_checks(
                    conn, sw_name, sw_ip, progress_bar, md5_64bit, 
                    kickstart_image=kickstart_image, memory_kb=memory_kb, memory_gb=memory_gb
                )
            else:
                # For regular switches, ALSO pass the kickstart_image and memory data to avoid duplicate show version
                regular_switch_data = perform_regular_switch_checks(
                    conn, sw_name, sw_ip, progress_bar, switch_info, md5_32bit, md5_64bit, 
                    kickstart_image=kickstart_image, memory_kb=memory_kb, memory_gb=memory_gb
                )
                
                # Copy everything from regular_switch_data to switch_data
                switch_data = regular_switch_data
                
                # Ensure raw_ls_output is in the main switch_data if it was collected
                if "diagnostics" in regular_switch_data and "raw_ls_output" in regular_switch_data["diagnostics"]:
                    switch_data["raw_ls_output"] = regular_switch_data["diagnostics"]["raw_ls_output"]
            
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

def perform_modular_spine_checks(conn, sw_name, sw_ip, progress_bar, md5_64bit, kickstart_image=None, 
                               memory_kb=None, memory_gb=None):
    """
    Perform checks specific to modular spine switches - always check for 64-bit image
    
    Args:
        conn: An established SSH connection object
        sw_name: Switch name for identification
        sw_ip: Switch IP address
        progress_bar: Progress bar object for updates
        md5_64bit: MD5 checksum for 64-bit image (required for modular spines)
        kickstart_image: Pre-collected kickstart image path from APIC API (optional)
        memory_kb: Pre-collected memory in KB (optional)
        memory_gb: Pre-collected memory in GB (optional)
    
    Returns:
        dict: Switch data with validation results
    """
    # Create data structure for modular spines
    switch_data = {
        "switch": sw_name,
        "ip": sw_ip,
        "status": "success",
        "memory_kb": memory_kb,  # Use pre-collected value if provided
        "memory_gb": memory_gb,  # Use pre-collected value if provided
        "image_path": kickstart_image,  # Use pre-collected path if available
        "md5sum": None,
        "result": "INFO",
        "message": "Modular spine"
    }
    
    # Only run show version if we don't already have the kickstart image path
    if not kickstart_image:
        # We need to fetch the image path using show version
        progress_bar.update(f"{sw_name}: Getting image path", 0)
        result_type = conn.execute_command("show version")
        if result_type == "prompt":
            version_output = conn.output
            
            # Extract kickstart image path
            image_path = SwitchDataCollector.extract_image_path(version_output)
            switch_data["image_path"] = image_path
            
            # Extract memory information if available (only for reporting) and not pre-collected
            if not memory_kb and not memory_gb:
                memory_kb = SwitchDataCollector.extract_memory(version_output)
                if memory_kb:
                    switch_data["memory_kb"] = memory_kb
                    # Convert to standardized GB value for display
                    if memory_kb < 20000:
                        switch_data["memory_gb"] = 16
                    elif memory_kb < 30000:
                        switch_data["memory_gb"] = 24
                    elif memory_kb < 40000:
                        switch_data["memory_gb"] = 32
                    elif memory_kb < 70000 and memory_kb > 60000:
                        switch_data["memory_gb"] = 64
                    else:
                        switch_data["memory_gb"] = round(memory_kb / 1024)
        else:
            switch_data["result"] = "ERROR" 
            switch_data["message"] = "Failed to retrieve image information"
            switch_data["status"] = "error"
    
    # Get MD5 checksum of the image if we have the path
    if switch_data["image_path"]:
        kickstart_image = switch_data["image_path"]
        progress_bar.update(f"{sw_name}: Retrieving MD5 hash", 0)
        result_type = conn.execute_command(f"md5sum {kickstart_image}")
        md5_output = conn.output
        md5_hash = SwitchDataCollector.extract_md5(md5_output)
        
        # Store the command output to help diagnose MD5 retrieval failures
        switch_data["md5_command_output"] = md5_output
        
        if not md5_hash:
            # Try to fix permissions and retry
            conn.execute_command(f"chmod 666 {kickstart_image}")
            result_type = conn.execute_command(f"md5sum {kickstart_image}")
            if result_type == "prompt":
                md5_output = conn.output
                switch_data["md5_command_output"] = md5_output
                md5_hash = SwitchDataCollector.extract_md5(md5_output)
        
        switch_data["md5sum"] = md5_hash
        
        # IMPORTANT: Modular spines MUST use 64-bit image regardless of memory
        if md5_hash:
            if md5_hash == md5_64bit:
                switch_data["result"] = "PASS"
                switch_data["message"] = "Running correct 64-bit image for modular spine"
            else:
                switch_data["result"] = "FAIL"
                switch_data["message"] = "Modular spine running incorrect image (must use 64-bit image)"
        else:
            switch_data["result"] = "ERROR"
            switch_data["message"] = "Could not retrieve MD5 information"
    else:
        switch_data["result"] = "ERROR" 
        switch_data["message"] = "Missing kickstart image path"
        switch_data["status"] = "error"
    
    # Check Repodata on modular spines
    progress_bar.update(f"{sw_name}: Checking Repodata", 0)
    repodata_result, repodata_output = check_repodata(conn)
    switch_data["repodata_check"] = repodata_result
    switch_data["repodata_output"] = repodata_output
    
    # Update message to include Repodata check result
    md5_message = switch_data["message"]
    if repodata_result == "FAIL":
        switch_data["message"] = f"{md5_message} | Repodata Check: FAIL - .repodata directory exists"
    elif repodata_result == "PASS":
        switch_data["message"] = f"{md5_message} | Repodata Check: PASS"
    else:
        switch_data["message"] = f"{md5_message} | Repodata Check: ERROR"
    
    return switch_data

def perform_regular_switch_checks(conn, sw_name, sw_ip, progress_bar, switch_info, md5_32bit, md5_64bit, 
                                kickstart_image=None, memory_kb=None, memory_gb=None):
    """
    Perform checks for leafs and non-modular spine switches
    
    Args:
        conn: An established SSH connection object
        sw_name: Switch name for identification
        sw_ip: Switch IP address
        progress_bar: Progress bar object for updates
        switch_info: SwitchInfo instance with APIC-collected data
        md5_32bit: MD5 checksum for 32-bit image
        md5_64bit: MD5 checksum for 64-bit image
        kickstart_image: Pre-collected kickstart image path (optional)
        memory_kb: Pre-collected memory in KB (optional)
        memory_gb: Pre-collected memory in GB (optional)
        
    Returns:
        dict: Switch data with validation results
    """
    # Initialize result structure and diagnostics
    diagnostics = {"error_type": None}
    
    # Collect switch data with timeout protection
    progress_bar.update(f"{sw_name}: Checking memory capacity", 0)
    
    # Start a timer to detect slow operations
    start_time = time.time()
    
    # Pass kickstart_image, memory_kb and memory_gb to collect_data to avoid unnecessary show version commands
    switch_data = SwitchDataCollector.collect_data(sw_name, sw_ip, conn, switch_info, 
                                                 kickstart_image, memory_kb, memory_gb)
    
    collection_time = time.time() - start_time
    switch_data["collection_time"] = f"{collection_time:.1f}s"
    
    # Check for permission denied in md5 output and get file owner info
    if "md5_command_output" in switch_data and "permission denied" in switch_data["md5_command_output"].lower():
        try:
            progress_bar.update(f"{sw_name}: Getting file permissions", 0)
            image_path = switch_data.get('image_path', '')
            logger.debug(f"Getting file permissions with: ls -lh {image_path}")
            
            result_type = conn.execute_command(f"ls -lh {image_path}")
            if result_type == "prompt":
                ls_output = conn.output
                logger.debug(f"Raw ls output: '{ls_output}'")
                
                # Store the raw ls output for diagnostics
                diagnostics["raw_ls_output"] = ls_output.strip()
                
                # Add some debugging to print raw output for each line 
                logger.debug(f"LS output has {len(ls_output.splitlines())} lines")
                for i, line in enumerate(ls_output.splitlines()):
                    logger.debug(f"LS Line {i}: '{line}'")
                
                # Extract the relevant line containing file information 
                file_info_line = None
                for line in ls_output.splitlines():
                    if ".bin" in line and not line.startswith(sw_name) and not "ls -lh" in line:
                        file_info_line = line.strip()
                        diagnostics["file_line"] = file_info_line
                        break
                
                # If we found a relevant line, try to parse it 
                if file_info_line:
                    # Look for pattern like: "-rw------- 1 admin admin 2.4G Mar 12 14:17 /bootflash/..."
                    # The dashes at the beginning might be mangled sometimes, so make that part optional
                    owner_match = re.search(r'(?:-[rwx-]+)?\s+\d+\s+(\S+)\s+(\S+)\s+[\d.]+[KMG]', file_info_line)
                    if owner_match:
                        owner = owner_match.group(1)
                        group = owner_match.group(2)
                        diagnostics["file_owner"] = owner
                        diagnostics["file_group"] = group
                        
                        # Extract file permissions if possible
                        perm_match = re.search(r'(-[rwx-]+)\s+\d+\s+', file_info_line)
                        permissions = perm_match.group(1) if perm_match else "-unknown-"
                        
                        # Store the parsed file details
                        diagnostics["file_permissions"] = permissions
                        diagnostics["file_details"] = f"{permissions} {owner} {group}"
                    else:
                        # If regex pattern failed, try simpler approach - extract by position
                        parts = file_info_line.split()
                        if len(parts) >= 5:  # Should have at least 5 parts
                            try:
                                owner = parts[2]
                                group = parts[3]
                                diagnostics["file_owner"] = owner
                                diagnostics["file_group"] = group
                                diagnostics["file_details"] = f"{owner} {group}"
                            except IndexError:
                                # If that fails, just store the raw line
                                diagnostics["raw_line"] = file_info_line
                        else:
                            # Not enough parts, store raw line
                            diagnostics["raw_line"] = file_info_line
                    
        except Exception as e:
            diagnostics["file_info_error"] = str(e)
    
    # Categorize any errors that occurred during data collection
    if switch_data["status"] != "success":
        diagnostics.update(SwitchDataCollector.categorize_error(switch_data))
    
    # Make sure md5_command_output is directly added to diagnostics
    if "md5_command_output" in switch_data:
        diagnostics["md5_command_output"] = switch_data["md5_command_output"]
    
    # Always check Repodata regardless of image validation status
    progress_bar.update(f"{sw_name}: Checking Repodata", 0)
    repodata_result, repodata_output = check_repodata(conn)
    switch_data["repodata_check"] = repodata_result
    switch_data["repodata_output"] = repodata_output
    
    # If data collection was successful, validate image
    if switch_data["status"] == "success":
        progress_bar.update(f"{sw_name}: Validating image", 0)
        md5_result, md5_message = SwitchDataCollector.validate_image(switch_data, md5_32bit, md5_64bit)
        switch_data["result"] = md5_result
        
        # Combine MD5 and Repodata results in the message
        if repodata_result == "PASS":
            switch_data["message"] = f"{md5_message} | Repodata Check: PASS"
        elif repodata_result == "FAIL":
            switch_data["message"] = f"{md5_message} | Repodata Check: FAIL - .repodata directory exists"
        else:
            switch_data["message"] = f"{md5_message} | Repodata Check: ERROR"
    else:
        switch_data["result"] = "ERROR"
        error_message = SwitchDataCollector.get_error_message(switch_data, diagnostics)
        
        # Combine error message with Repodata result
        if repodata_result == "PASS":
            switch_data["message"] = f"{error_message} | Repodata Check: PASS" 
        elif repodata_result == "FAIL":
            switch_data["message"] = f"{error_message} | Repodata Check: FAIL - .repodata directory exists"
        else:
            switch_data["message"] = f"{error_message} | Repodata Check: ERROR"
    
    # Add diagnostics to the result
    switch_data["diagnostics"] = diagnostics
    return switch_data

def process_switches_in_batches(switch_ips, mod_spine_ips, switch_info, progress_bar, 
                              md5_32bit, md5_64bit, apic_addr, batch_size=None, result_logger=None):
    """
    Process switches in batches with dynamic resource management
    """
    # Get a dedicated logger for this function to avoid duplicates
    batch_logger = get_module_logger("process_switches")
    
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
# Results Processing and Output
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
        self.colors = {
            "PASS": "\033[1;32m",     # Green
            "FAIL": "\033[1;31m",     # Red
            "WARNING": "\033[1;33m",  # Yellow
            "ERROR": "\033[1;31m",    # Red (same as FAIL)
            "RESET": "\033[0m"        # Reset to default
        }
        
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

    def _format_switch_data(self, file, switch_data):
        """Format switch data for output file"""
        sw_name = switch_data.get("switch", "Unknown")
        sw_ip = switch_data.get("ip", "Unknown")
        memory_gb = switch_data.get("memory_gb")
        memory_kb = switch_data.get("memory_kb")
        image_path = switch_data.get("image_path", "Unknown")
        md5sum = switch_data.get("md5sum", "Unknown")
        result = switch_data.get("result", "ERROR")
        repodata_result = switch_data.get("repodata_check", "ERROR")
        message = switch_data.get("message", "No validation message")
        
        # Format memory display - use GB if available, otherwise fall back to KB
        if memory_gb is not None:
            memory_display = f"{memory_gb} GB"
        elif memory_kb not in ("Unknown", None):
            try:
                kb_value = int(memory_kb)
                if kb_value < 20000: memory_display = "16 GB"
                elif kb_value < 30000: memory_display = "24 GB"
                elif kb_value < 40000: memory_display = "32 GB"
                elif kb_value < 70000 and kb_value > 60000: memory_display = "64 GB"
                else: memory_display = f"{round(kb_value / 1024)} GB"
            except (ValueError, TypeError):
                memory_display = f"{memory_kb} KB"
        else:
            memory_display = "Unknown"
        
        # Add boot mode information if available
        boot_mode = switch_data.get("boot_mode", "normal")
        
        # Write basic switch information
        file.write(f"\nSwitch: {sw_name} ({sw_ip})\n")
        file.write(f"Memory: {memory_display}\n")
        if boot_mode == "recovery":
            file.write(f"Boot Mode: \033[1;33mRecovery\033[0m\n")
        file.write(f"Image: {image_path}\n")
        file.write(f"MD5sum: {md5sum}\n")
        
        # Results section
        file.write("\nResults:\n")
        
        # Format the MD5 check result
        md5_status_color = self.colors[result] if result in self.colors else ""
        md5_message = message.split(" | Repodata Check:")[0] if " | Repodata Check:" in message else message
        file.write(f"MD5sum Check   : {md5_status_color}{result}{self.colors['RESET']} {md5_message}\n")
        
        # Format the Repodata Check result
        repodata_color = ""
        if repodata_result == "PASS":
            repodata_color = self.colors["PASS"]
            repodata_desc = "(.repodata file not present)"
        elif repodata_result == "FAIL":
            repodata_color = self.colors["FAIL"]
            repodata_desc = "(.repodata directory exists)"
        else:
            repodata_color = self.colors["ERROR"]
            repodata_desc = "(check failed)"
        
        file.write(f"Repodata Check : {repodata_color}{repodata_result}{self.colors['RESET']} {repodata_desc}\n")
        
        # Add recommendations if needed
        self._add_recommendations(file, switch_data)
        
        # Add diagnostics if needed
        self._add_diagnostics(file, switch_data)

    def _add_recommendations(self, file, switch_data):
        """Add recommendations based on results"""
        result = switch_data.get("result", "ERROR")
        repodata_result = switch_data.get("repodata_check", "ERROR")
        cmd_output = switch_data.get("md5_command_output", "")
        
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
            file.write("Re-run the script from the admin account to rectify the permissions issue.\n\n")
            file.write("Note: Rectification of permissions will only work from the admin account.\nIt will not work even if a non-admin user belongs to the admin group.\n")
        
        if result == "FAIL" and repodata_result == "FAIL":
            # Both checks failed
            if not permission_denied:  # Only add if not already shown for permission denied
                file.write("1. Contact Cisco TAC for assitance in setting boot variable to use correct switch image.\n")
                file.write("2. Contact Cisco TAC to remove .repodata file via root user.\n\n")
                file.write("Defect Reference:\nhttps://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj44966\nhttps://bst.cloudapps.cisco.com/bugsearch/bug/CSCwo34637\n")
        elif result == "FAIL" and not permission_denied:
            # Only MD5 check failed and not due to permissions
            file.write("Contact Cisco TAC for assitance in setting boot variable to use correct switch image.\n\n")
            file.write("Defect Reference:\nhttps://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj44966\n")
        elif repodata_result == "FAIL":
            # Only Repodata check failed
            if permission_denied:  # Add a separator if we already showed permission message
                file.write("\n")
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
            # First extract just the permission denied line
            for line in cmd_output.splitlines():
                if "permission denied" in line.lower():
                    file.write(f"{line.strip()}\n")
                    break
            
            # Use any available method to find the file permissions line
            if "raw_ls_output" in diagnostics:
                ls_output = diagnostics["raw_ls_output"]
                for line in ls_output.splitlines():
                    if line.strip() and ".bin" in line and not line.startswith("ls "):
                        file.write(f"{line.strip()}\n")
                        break
            elif "file_line" in diagnostics:
                file.write(f"{diagnostics['file_line']}\n")
            elif "file_permissions" in diagnostics and "file_owner" in diagnostics:
                file.write(f"{diagnostics['file_permissions']} {diagnostics['file_owner']} {diagnostics['file_group']}\n")
            elif "file_details" in diagnostics:
                file.write(f"{diagnostics['file_details']}\n")
            # Check if raw_ls_output exists directly in switch_data
            elif "raw_ls_output" in switch_data:
                ls_output = switch_data["raw_ls_output"]
                for line in ls_output.splitlines():
                    if line.strip() and ".bin" in line and not line.startswith("ls "):
                        file.write(f"{line.strip()}\n")
                        break
        
        # If no permission denied or no file info found, show the command output directly
        elif cmd_output:
            file.write(f"{cmd_output.strip()}\n")

    def log_switch_result(self, switch_data):
        """Log data for a single switch with specific error details, relevant diagnostics, and recommendations"""
        sw_name = switch_data.get("switch", "Unknown")
        sw_ip = switch_data.get("ip", "Unknown")
        memory_kb = switch_data.get("memory_kb", "Unknown")
        memory_gb = switch_data.get("memory_gb")
        
        # Format memory display - use GB if available, otherwise fall back to KB
        if memory_gb is not None:
            memory_display = f"{memory_gb} GB"
        elif memory_kb not in ("Unknown", None):
            # Convert KB to standardized GB value
            try:
                kb_value = int(memory_kb)
                if kb_value < 20000:
                    memory_display = "16 GB"
                elif kb_value < 30000:
                    memory_display = "24 GB"
                elif kb_value < 40000:
                    memory_display = "32 GB"
                elif kb_value < 70000 and kb_value > 60000:
                    memory_display = "64 GB"
                else:
                    memory_display = f"{round(kb_value / 1024)} GB"
            except (ValueError, TypeError):
                memory_display = f"{memory_kb} KB"
        else:
            memory_display = "Unknown"
        
        image_path = switch_data.get("image_path", "Unknown")
        md5sum = switch_data.get("md5sum", "Unknown")
        result = switch_data.get("result", "ERROR")
        message = switch_data.get("message", "No validation message")
        all_diagnostics = switch_data.get("diagnostics", {})
        
        with self.lock:
            # Initialize the first_switch flag if it doesn't exist
            if not hasattr(self, 'first_switch_logged'):
                self.first_switch_logged = False
            
            with open(self.filename, 'a') as f:
                # Add separator line ONLY before the first switch
                if not self.first_switch_logged:
                    f.write("----------------------------------------\n")
                    self.first_switch_logged = True
                
                # Basic switch information with GB memory value
                f.write(f"\nSwitch: {sw_name} ({sw_ip})\n")
                f.write(f"Memory: {memory_display}\n")
                f.write(f"Image: {image_path}\n")
                f.write(f"MD5sum: {md5sum}\n")
                
                # Results section with consolidated status
                f.write("\nResults:\n")
                
                # Parse the consolidated message to separate MD5 result and Repodata result
                md5_message = message.split(" | Repodata Check:")[0] if " | Repodata Check:" in message else message
                
                # Format the MD5sum Check result with status and message
                md5_status_color = self.colors[result] if result in self.colors else ""
                f.write(f"MD5sum Check   : {md5_status_color}{result}{self.colors['RESET']} {md5_message}\n")
                
                # Track MD5 and Repodata check status for recommendation logic
                md5_check_failed = result == "FAIL"
                permission_denied = False
                repodata_check_failed = False

                # Format the Repodata Check result
                if "repodata_check" in switch_data:
                    repodata_result = switch_data.get("repodata_check")
                    repodata_color = ""
                    if repodata_result == "PASS":
                        repodata_color = self.colors["PASS"]
                        repodata_desc = "(.repodata file not present)"
                    elif repodata_result == "FAIL":
                        repodata_color = self.colors["FAIL"]
                        repodata_desc = "(.repodata directory exists)"
                        repodata_check_failed = True
                    else:
                        repodata_color = self.colors["ERROR"]
                        repodata_desc = "(check failed)"
                    
                    f.write(f"Repodata Check : {repodata_color}{repodata_result}{self.colors['RESET']} {repodata_desc}\n")
                
                # Check for permission denied error
                cmd_output = ""
                if "md5_command_output" in switch_data:
                    cmd_output = switch_data["md5_command_output"]
                elif all_diagnostics and "md5_command_output" in all_diagnostics:
                    cmd_output = all_diagnostics["md5_command_output"]
                
                if cmd_output and "permission denied" in cmd_output.lower():
                    permission_denied = True
                
                # Add recommendations based on failure combinations and conditions
                recommendations_needed = md5_check_failed or repodata_check_failed or permission_denied
                
                if recommendations_needed:
                    f.write("\nRecommendations:\n")
                    
                    # Different recommendations based on conditions
                    if permission_denied:
                        f.write("Re-run the script from the owner account or root to rectify the permissions issue.\n")
                                            
                        owner = None
            
                        # Check various places where owner information might be stored
                        if all_diagnostics and "file_owner" in all_diagnostics:
                            owner = all_diagnostics["file_owner"]
                        elif "raw_ls_output" in switch_data:
                            # Try to extract owner from the raw_ls_output
                            ls_output = switch_data["raw_ls_output"]
                            for line in ls_output.splitlines():
                                if line.strip() and ".bin" in line:
                                    # Try to extract owner from pattern like "-rw------- 1 admin admin 2.4G"
                                    match = re.search(r'\S+\s+\d+\s+(\S+)\s+\S+', line)
                                    if match:
                                        owner = match.group(1)
                                        break
                        
                        if owner:
                            f.write(f"The owner of the file is: {owner}\n")

                    if md5_check_failed and repodata_check_failed:
                        # Both checks failed
                        if not permission_denied:  # Only add if not already shown for permission denied
                            f.write("1. Contact Cisco TAC for assitance in setting boot variable to use correct switch image.\n")
                            f.write("2. Contact Cisco TAC to remove .repodata file via root user.\n\n")
                            f.write("Defect Reference:\nhttps://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj44966\nhttps://bst.cloudapps.cisco.com/bugsearch/bug/CSCwo34637\n")
                    elif md5_check_failed and not permission_denied:
                        # Only MD5 check failed and not due to permissions
                        f.write("Contact Cisco TAC for assitance in setting boot variable to use correct switch image.\n\n")
                        f.write("Defect Reference:\nhttps://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj44966\n")
                    elif repodata_check_failed:
                        # Only Repodata check failed
                        if permission_denied:  # Add a separator if we already showed permission message
                            f.write("\n")
                        f.write("Contact Cisco TAC to remove .repodata file via root user.\n\n")
                        f.write("Defect Reference:\nhttps://bst.cloudapps.cisco.com/bugsearch/bug/CSCwo34637\n")
                
                # Simplified diagnostics display logic - only for errors or missing MD5
                if result == "ERROR" or md5sum is None:
                    f.write("\nDiagnostics:\n")
                    
                    # Check for permission denied in the output to format as requested
                    if cmd_output and "permission denied" in cmd_output.lower():
                        # Extract just the permission denied message
                        permission_line = None
                        for line in cmd_output.splitlines():
                            if "permission denied" in line.lower():
                                permission_line = line.strip()
                                f.write(f"{permission_line}\n")
                                break
                        
                        # Check for file permissions information in multiple locations
                        if "raw_ls_output" in switch_data:
                            # Direct access from switch_data
                            ls_output = switch_data["raw_ls_output"]
                            for line in ls_output.splitlines():
                                if line.strip() and ".bin" in line and not line.startswith("ls "):
                                    f.write(f"{line.strip()}\n")
                                    break
                        elif all_diagnostics and "raw_ls_output" in all_diagnostics:
                            # From diagnostics
                            ls_output = all_diagnostics["raw_ls_output"]
                            for line in ls_output.splitlines():
                                if line.strip() and ".bin" in line and not line.startswith("ls "):
                                    f.write(f"{line.strip()}\n")
                                    break
                        elif all_diagnostics:
                            # Check for other file information in diagnostics
                            if "file_line" in all_diagnostics:
                                f.write(f"{all_diagnostics['file_line']}\n")
                            elif "file_details" in all_diagnostics:
                                f.write(f"{all_diagnostics['file_details']}\n")
                            elif "file_owner" in all_diagnostics and "file_group" in all_diagnostics:
                                permissions = all_diagnostics.get("file_permissions", "")
                                if permissions:
                                    f.write(f"{permissions} {all_diagnostics['file_owner']} {all_diagnostics['file_group']}\n")
                                else:
                                    f.write(f"File is owned by: {all_diagnostics['file_owner']} (group: {all_diagnostics['file_group']})\n")
                    
                    # If no permission denied message found, show the command output directly
                    elif cmd_output:
                        f.write(f"{cmd_output.strip()}\n")
                
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

def export_results_to_json(results, summary, filename, apic_version):
    """
    Export validation results to a JSON file for automation scenarios
    
    Args:
        results: Dictionary of switch results
        summary: Summary statistics dictionary 
        filename: Output JSON filename
        apic_version: APIC version string
    """
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
            # Extract the relevant data without color codes
            switch_result = {
                "name": switch_data.get("switch", "Unknown"),
                "ip": switch_data.get("ip", "Unknown"),
                "memory_kb": switch_data.get("memory_kb", "Unknown"),
                "image_path": switch_data.get("image_path", "Unknown"),
                "md5sum": switch_data.get("md5sum", "Unknown"),
                "md5_check": {
                    "result": switch_data.get("result", "ERROR"),
                    "message": switch_data.get("message", "").split(" | Repodata Check:")[0]
                },
                "repodata_check": {
                    "result": switch_data.get("repodata_check", "ERROR"),
                    "message": (
                        "Repodata file not present" if switch_data.get("repodata_check") == "PASS" 
                        else "Repodata directory exists" if switch_data.get("repodata_check") == "FAIL"
                        else "Check failed"
                    )
                },
                "collection_time": switch_data.get("collection_time", "Unknown"),
                "status": switch_data.get("status", "error")
            }
            
            # Check for permission denied
            permission_denied = False
            cmd_output = ""
            if "md5_command_output" in switch_data:
                cmd_output = switch_data["md5_command_output"]
            elif switch_data.get("diagnostics") and "md5_command_output" in switch_data["diagnostics"]:
                cmd_output = switch_data["diagnostics"]["md5_command_output"]
            
            if cmd_output and "permission denied" in cmd_output.lower():
                permission_denied = True
            
            # Add recommendations field based on failure types and permission errors
            recommendations = []
            
            # Add permission denied recommendation first if applicable
            if permission_denied:
                recommendations.append("Re-run the script from the admin account to rectify the permissions issue.")
                recommendations.append("Note: Rectification of permissions will only work from the admin account. It will not work even if a non-admin user belongs to the admin group.")
            
            # Add other recommendations
            if switch_data.get("result") == "FAIL":
                recommendations.append("Contact Cisco TAC for assistance in setting boot variable to use correct switch image")
                recommendations.append("Defect Reference: https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj44966")
            
            if switch_data.get("repodata_check") == "FAIL":
                recommendations.append("Contact Cisco TAC to remove .repodata file via root user")
                recommendations.append("Defect Reference: https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwo34637")
            
            if recommendations:
                switch_result["recommendations"] = recommendations
            
            # Build comprehensive diagnostics
            diagnostics = {}
            
            # First check for MD5 retrieval errors - this is highest priority
            if switch_data.get("md5sum") is None and switch_data.get("image_path") is not None:
                diagnostics["error_type"] = "md5_retrieval"
                
                # Check command output for specific error messages
                if cmd_output:
                    cmd_output_lower = cmd_output.lower() if cmd_output else ""
                    
                    if "permission denied" in cmd_output_lower:
                        diagnostics["md5_error"] = "Permission denied when accessing image file"
                    elif "no such file" in cmd_output_lower:
                        diagnostics["md5_error"] = "Image file not found"
                    else:
                        diagnostics["md5_error"] = "Unknown error retrieving MD5"
            
            # Next, incorporate any existing diagnostic information
            if "diagnostics" in switch_data and switch_data["diagnostics"]:
                for key, value in switch_data["diagnostics"].items():
                    if isinstance(value, str):
                        # Remove ANSI color codes
                        value = re.sub(r'\033\[[0-9;]*m', '', value)
                    # Don't overwrite existing error_type if we've already set it
                    if key != "error_type" or "error_type" not in diagnostics:
                        diagnostics[key] = value
            
            # Clean up md5 command output if available
            if cmd_output:
                # Remove ANSI color codes
                cleaned_output = re.sub(r'\033\[[0-9;]*m', '', cmd_output)
                
                # For permission denied errors, extract just the error message
                if "permission denied" in cleaned_output.lower():
                    # Look for the specific pattern "md5sum: /path/to/file: Permission denied"
                    permission_match = re.search(r'(md5sum:\s+\/\S+:\s+Permission denied)', cleaned_output, re.IGNORECASE)
                    if permission_match:
                        diagnostics["command_output"] = permission_match.group(1).strip()
                    else:
                        # Fallback: just clean up line breaks and hostname
                        lines = [line.strip() for line in cleaned_output.splitlines() 
                                if "permission denied" in line.lower()]
                        if lines:
                            diagnostics["command_output"] = lines[0]
                        else:
                            diagnostics["command_output"] = cleaned_output.strip()
                else:
                    # For other outputs, clean up unnecessary parts
                    lines = [line.strip() for line in cleaned_output.splitlines() 
                            if line.strip() and not line.strip().startswith(switch_result["name"])]
                    diagnostics["command_output"] = lines[0] if lines else cleaned_output.strip()
            
            # Ensure we have an error_type for md5 errors
            if switch_data.get("md5sum") is None and "error_type" not in diagnostics:
                diagnostics["error_type"] = "md5_retrieval"
            
            # Add the diagnostics to the result
            switch_result["diagnostics"] = diagnostics
            
            export_data["switches"].append(switch_result)
            
        # Write the JSON file without pretty printing
        with open(filename, 'w') as json_file:
            json.dump(export_data, json_file)
            
    except Exception as e:
        logger.log_message(f"Error exporting to JSON: {str(e)}")
        logging.error(f"Error exporting to JSON: {str(e)}")

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

def clean_terminal_on_auth_failure():
    """Clear progress bar and terminal output on authentication failure"""
    # Move up 2 lines to clear progress bar display
    sys.stdout.write('\r\033[K\033[1A\033[K')
    sys.stdout.flush()
    # Add a newline for better spacing before error message
    print()

###########################################
# Main Processing Logic
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

    # Get credentials 
    if args.username and args.password:
        # If username and password are provided, use them
        switch_info.username = args.username
        switch_info.password = args.password
        print(f"Using provided credentials for user: {switch_info.username}")
    else:
        # Otherwise prompt for credentials
        print("Please enter your credentials:")
        switch_info.username, switch_info.password = switch_info.get_credentials()

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
            result_logger  # Pass result_logger here
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
