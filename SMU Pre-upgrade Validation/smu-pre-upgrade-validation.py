#!/usr/bin/env python3
"""
ACI SMU Pre-upgrade Validation Script

This script validates Cisco ACI switches against known SMU issues.

Check 1: Ensure correct image type (32-bit or 64-bit) based on switch memory capacity
Check 2: Ensure .repodata file does not exist

@ Author: joelebla@cisco.com
@ Version: 04/27/2025
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
# Connection Management Classes & Functions
###########################################

class Connection:
    """Handles SSH connections to network switches"""
    
    def __init__(self, hostname, username=None, password=None, timeout=30, bind_address=None):
        """Initialize SSH connection handler with safeguards against hanging"""
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout
        self.child = None
        self.output = ""
        self.prompt = r'[#%>]\s*$'  # Updated to match #, %, or > followed by optional whitespace
        self.log = logging.getLogger(f'connection.{hostname}')
        self.log.setLevel(logging.DEBUG)  # Log everything to file
        # Prevent log propagation to root logger to avoid console output
        self.log.propagate = False
        # Ensure the logger has a file handler but no console handler
        ensure_file_handler(self.log)
        self.bind_address = bind_address
        self.auth_failure = False  # Track authentication failures
        
    def connect(self):
        """Establish the SSH connection to the device"""
        self.log.debug(f"Connecting to {self.hostname}")
        
        try:
            # Build SSH command
            ssh_cmd = "ssh "
            
            # Add bind address option which should improve connectivity
            if self.bind_address:
                ssh_cmd += f"-b {self.bind_address} "
                
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
            
            # Start SSH connection
            start_time = time.time()
            
            # Spawn SSH process
            self.child = pexpect.spawn(
                ssh_cmd,
                timeout=30,
                encoding='utf-8'
            )
            
            # For switches, there could be multiple password prompt patterns:
            password_prompts = [
                'assword:',                    # Standard password prompt
                r'\([^)]+\) Password:',        # Switch prompt format like (user@ip) Password:
                'password:',                   # Lowercase variant
                'Password:'                    # Capitalized without username
            ]
            
            # Wait for password prompt, unexpected prompt, timeout or EOF
            i = self.child.expect(password_prompts + [self.prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=30)
            
            if i < len(password_prompts):  # One of the password prompts matched
                self.log.debug(f"Password prompt received (type {i}), sending password")
                self.child.sendline(self.password)
                
                # After sending password, look for successful connection indicators
                # For switches, look for the Cisco banner or prompt
                success_patterns = [
                    self.prompt,              # Standard prompt pattern
                    'Cisco Nexus',            # Part of the banner
                    'NX-OS'                   # Part of the banner
                ]
                
                # Combine success patterns with failure patterns
                j = self.child.expect(
                    success_patterns + ['Permission denied', 'denied', 'failed', pexpect.TIMEOUT, pexpect.EOF], 
                    timeout=20
                )
                
                elapsed_time = time.time() - start_time
                
                if j < len(success_patterns):  # Success pattern matched
                    self.log.debug(f"Successfully connected to {self.hostname} in {elapsed_time:.2f}s")
                    
                    # If we matched the banner but not the prompt, wait for the prompt
                    if j > 0:  # Matched banner, now wait for prompt
                        self.log.debug("Matched banner, waiting for prompt")
                        try:
                            self.child.expect([self.prompt], timeout=10)
                        except:
                            self.log.warning("Couldn't find prompt after banner, but continuing")
                    
                    return True
                    
                else:  # Authentication failed or timeout
                    error_code = j - len(success_patterns)
                    error_states = ["Permission denied", "denied", "failed", "Timeout", "Connection closed"]
                    error_type = "auth_failure" if error_code < 3 else "timeout" if error_code == 3 else "connection"
                    error_msg = error_states[error_code] if error_code < len(error_states) else "Unknown error"
                    
                    # Use unified error handler
                    error_info = handle_connection_error(
                        device_name=self.hostname,
                        device_ip=self.hostname,
                        error=error_msg,
                        error_type=error_type,
                        buffer=self.child.before if hasattr(self.child, 'before') else None,
                        logger=self.log
                    )
                    
                    self._force_close()
                    
                    if error_type == "auth_failure":
                        self.auth_failure = True
                    
                    return False
                    
            elif i == len(password_prompts):  # Already at prompt (no password needed)
                self.log.debug(f"Connected to {self.hostname} without password prompt")
                return True
            else:  # Timeout or EOF
                error_index = i - len(password_prompts) - 1
                error_type = "timeout" if error_index == 0 else "eof"
                
                # Use unified error handler
                error_info = handle_connection_error(
                    device_name=self.hostname,
                    device_ip=self.hostname,
                    error=f"Failed to connect: {error_type}",
                    error_type=error_type,
                    logger=self.log
                )
                
                self._force_close()
                return False
                    
        except Exception as e:
            # Use unified error handler
            error_info = handle_connection_error(
                device_name=self.hostname,
                device_ip=self.hostname,
                error=e,
                error_type="exception",
                logger=self.log
            )
            
            self._force_close()
            return False
    
    def login(self, max_attempts=1):  # Changed default to 1, only retry if explicitly requested
        """Login to device with retry mechanism and anti-hang protection"""
        attempts = 0
        
        while attempts < max_attempts:
            attempts += 1
            self.log.debug(f"Login attempt {attempts}/{max_attempts} to {self.hostname}")
            
            if self.connect():
                # Successfully connected
                return True
            
            # If authentication failure detected, return immediately without retrying
            if self.auth_failure:
                self.log.error("Authentication failure detected, not retrying")
                raise RuntimeError("AUTH_FAILURE")
            
            # Wait only a minimal time before retry
            if attempts < max_attempts:
                time.sleep(0.5)
        
        self.log.error(f"Failed to login after {max_attempts} attempts")
        
        # If the last attempt was an auth failure, raise exception immediately
        if self.auth_failure:
            raise RuntimeError("AUTH_FAILURE")
            
        return False
    
    def _force_close(self):
        """Force close the connection without graceful exit"""
        if self.child:
            try:
                self.log.debug(f"Force closing connection to {self.hostname}")
                self.child.close(force=True)
            except Exception as e:
                self.log.warning(f"Error during force close: {str(e)}")
            finally:
                self.child = None
                self.output = ""
    
    def cmd(self, command, timeout=None, expect_prompt=None, max_output_lines=1000):
        """Execute a command with strict timeout handling"""
        if not self.child:
            self.log.error("No active connection")
            raise RuntimeError("No active connection")
        
        # Default timeout to instance timeout if not specified
        if timeout is None:
            timeout = self.timeout
        
        # Set longer timeout for specific commands
        if command.startswith("md5sum"):
            # Use a much longer timeout for md5sum commands (45 seconds)
            timeout = 45
            self.log.debug(f"Using extended timeout of {timeout}s for md5sum command")
        
        # Default prompt to instance prompt if not specified
        if expect_prompt is None:
            expect_prompt = self.prompt
            
        try:
            # Clear any pending output
            if self.child.before:
                self.log.debug(f"Clearing buffer before command: {self.child.before[-100:]}")
            
            # Send the command
            self.log.debug(f"Sending command: {command}")
            self.child.sendline(command)
            
            # For "show version" command specifically, use multiline collection method
            if command.lower() == "show version":
                # Increase timeout significantly for show version
                timeout = max(timeout, 30)
                return self._process_command_output(command, timeout, expect_prompt, multiline=True)
            else:
                # Standard approach for other commands
                return self._process_command_output(command, timeout, expect_prompt, multiline=False)
                    
        except Exception as e:
            self.log.error(f"Error executing command: {str(e)}")
            self._force_close()
            raise RuntimeError(f"Command execution error: {str(e)}")

    def _process_command_output(self, command, timeout, expect_prompt, multiline=False):
        """
        Process and collect command output with common handling for different output types.
        
        Args:
            command: The command that was executed
            timeout: Timeout value in seconds
            expect_prompt: Pattern to match for prompt detection
            multiline: Whether to use enhanced multiline output collection
            
        Returns:
            str: Result status ("prompt", "timeout", "eof", or "error")
        """
        try:
            if multiline:
                return self._collect_multiline_output(command, timeout, expect_prompt)
            
            # Standard single expect approach
            i = self.child.expect([expect_prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=timeout)
            
            if i == 0:  # Found prompt
                # Get full output
                output = self.child.before
                self.log.debug(f"timeout: {timeout}, matched: '{expect_prompt}'")
                self.log.debug(f"Output length: {len(output)} bytes")
                
                # Store full output without truncation
                self.output = output.strip()
                return "prompt"
            elif i == 1:  # Timeout
                self.output = self.child.before
                self.log.warning(f"Command timed out after {timeout}s: {command}")
                # Send Ctrl+C to try to recover
                self._handle_timeout()
                return "timeout"
            else:  # EOF
                self.output = self.child.before
                self.log.error(f"Connection closed while executing command: {command}")
                self._force_close()
                return "eof"
        
        except Exception as e:
            self.log.error(f"Error processing command output: {str(e)}")
            return "error"

    def _collect_multiline_output(self, command, timeout, expect_prompt):
        """Special handling for collecting multiline output with careful chunking"""
        self.log.debug(f"Using multiline collection for command: {command}")
        output = []
        chunk_size = 4096
        total_size = 0
        max_size = 1048576  # 1MB max output for safety
        
        start_time = time.time()
        end_time = start_time + timeout
        
        # Initial read after sending command
        try:
            while time.time() < end_time and total_size < max_size:
                # Check if prompt is in the buffer already
                matched_prompt = False
                try:
                    i = self.child.expect([expect_prompt, pexpect.TIMEOUT], timeout=0.1)
                    if i == 0:  # Found prompt
                        output.append(self.child.before)
                        total_size += len(self.child.before)
                        matched_prompt = True
                        break
                except:
                    pass
                    
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
                        else:  # Timeout on chunk read - try for prompt
                            try:
                                i = self.child.expect([expect_prompt, pexpect.TIMEOUT], timeout=3)
                                if i == 0:  # Found prompt after waiting
                                    if self.child.before:
                                        output.append(self.child.before)
                                        total_size += len(self.child.before)
                                    break
                            except:
                                # If 3-second prompt check times out, keep looping until main timeout
                                pass
                    except Exception as e:
                        self.log.warning(f"Exception during chunk read: {str(e)}")
            
            # Final check for prompt
            if not matched_prompt:
                try:
                    i = self.child.expect([expect_prompt, pexpect.TIMEOUT, pexpect.EOF], timeout=5)
                    if i == 0 and self.child.before:  # Found prompt at the end
                        output.append(self.child.before)
                        total_size += len(self.child.before)
                except:
                    pass
                    
            # Join all output
            self.output = ''.join(output).strip()
            self.log.debug(f"Collected {len(output)} chunks, {total_size} bytes total")
            
            # Check if we got substantial output
            if total_size > 0:
                return "prompt"
            else:
                return "timeout"
                
        except Exception as e:
            self.log.error(f"Error collecting multiline output: {str(e)}")
            return "error"

    def _handle_timeout(self):
        """Handle command timeout with recovery attempt"""
        try:
            # Send Ctrl+C to try to recover
            self.child.sendcontrol('c')
            time.sleep(0.5)
            try:
                self.child.expect([self.prompt], timeout=5)
            except:
                # If we can't recover, force close
                self._force_close()
        except:
            self._force_close()
    
    def close(self):
        """Close the SSH connection with safety checks"""
        if self.child:
            try:
                self.log.info(f"closing current connection")
                # First try graceful exit
                self.child.sendline("exit")
                # Wait briefly for exit to complete
                time.sleep(0.5)
                # Then force close if still alive
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

def get_dynamic_md5_hashes():
    """
    Dynamically retrieve MD5 hashes for the current APIC version's switch images
    
    Returns:
        tuple: (md5_32bit, md5_64bit, version_string, images_missing)
    """
    logger.info("Getting APIC version and MD5 hashes dynamically")
    
    try:
        # Get APIC version
        apic_version_cmd = "acidiag avread | grep version"
        version_output = subprocess.check_output(apic_version_cmd, shell=True, text=True)
        
        # Extract version string like '6.0(5h)' or '6.1(3.135a)'
        version_match = re.search(r'version=apic-([0-9]+\.[0-9]+\([0-9.a-zA-Z]+\))', version_output)
        if not version_match:
            # If the first pattern doesn't match, try a more flexible pattern
            version_match = re.search(r'set to version=apic-([0-9]+\.[0-9]+\([^)]+\))', version_output)
            if not version_match:
                # If still no match, dump the output for debugging
                logger.error(f"Could not extract version from output: {version_output}")
                raise RuntimeError("Failed to extract APIC version from output")
            
        apic_version = version_match.group(1)
        logger.info(f"Found APIC version: {apic_version}")
        
        # Convert version format from '6.0(5h)' to '16.0(5h)' for switch images
        # Handle versions with dots in the parentheses part (Usually a QA image)
        version_base = apic_version.split('(')[0]
        version_detail = apic_version.split('(')[1].rstrip(')')
        
        # The switch image version format starts with "1" prefix
        switch_version = f"1{version_base}.{version_detail}"
        logger.info(f"Converted to switch image version: {switch_version}")
        
        # Build image filenames
        image_32bit = f"aci-n9000-dk9.{switch_version}.bin"
        image_64bit = f"aci-n9000-dk9.{switch_version}-cs_64.bin"
        logger.info(f"32-bit image: {image_32bit}")
        logger.info(f"64-bit image: {image_64bit}")
        
        # Get MD5 hashes from APIC fwrepo
        md5_cmd_32bit = f"cat /firmware/fwrepos/fwrepo/md5sum/{image_32bit} | awk '{{print $1}}'"
        md5_cmd_64bit = f"cat /firmware/fwrepos/fwrepo/md5sum/{image_64bit} | awk '{{print $1}}'"
        
        # Execute the md5sum commands, but handle the case where files don't exist
        try:
            md5_32bit = subprocess.check_output(md5_cmd_32bit, shell=True, text=True).strip()
            if not md5_32bit:
                md5_32bit = "Image not found in fwrepo"
                logger.warning("32-bit image hash empty (likely file not found)")
            logger.info(f"Retrieved 32-bit MD5: {md5_32bit}")
        except subprocess.CalledProcessError:
            md5_32bit = "Image not found in fwrepo"
            logger.warning("32-bit image file not found in repository")
            
        try:
            md5_64bit = subprocess.check_output(md5_cmd_64bit, shell=True, text=True).strip()
            if not md5_64bit:
                md5_64bit = "Image not found in fwrepo"
                logger.warning("64-bit image hash empty (likely file not found)")
            logger.info(f"Retrieved 64-bit MD5: {md5_64bit}")
        except subprocess.CalledProcessError:
            md5_64bit = "Image not found in fwrepo"
            logger.warning("64-bit image file not found in repository")
        
        # Check if both images were not found
        # Also check for empty strings which could happen if md5sum runs but doesn't return a hash
        images_missing = ((md5_32bit == "Image not found in fwrepo" or not md5_32bit) and 
                         (md5_64bit == "Image not found in fwrepo" or not md5_64bit))
        
        if images_missing:
            logger.error("Neither 32-bit nor 64-bit images were found in the repository")
            # Ensure consistent return values for missing images
            md5_32bit = "Image not found in fwrepo" if not md5_32bit else md5_32bit
            md5_64bit = "Image not found in fwrepo" if not md5_64bit else md5_64bit
        
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
        self.appliance_addr = None
        self.username = None
        self.password = None
        self._fnv_data = None  # Cache for fnvreadex data
        self._building_cache = False  # Flag to track cache building
        
    def get_appliance_address(self):
        """Get APIC management address for SSH connectivity"""
        if not self.appliance_addr:
            try:
                output = subprocess.check_output(['acidiag', 'avread'], text=True)
                match = re.search(r'appliance id=1.*?address=([^\s]+)', output)
                if match:
                    self.appliance_addr = match.group(1)
                else:
                    raise RuntimeError("Failed to extract appliance address from acidiag output")
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
    
    def _get_fnv_data(self):
        """Get and cache fnvreadex data for all functions to use"""
        if self._fnv_data is None:
            try:
                logger.info("Running acidiag fnvreadex to collect switch information")
                self._fnv_data = subprocess.check_output(['acidiag', 'fnvreadex'], text=True)
                logger.debug(f"Collected {len(self._fnv_data)} bytes of fnvreadex data")
            except subprocess.CalledProcessError:
                logger.error("Failed to execute fnvreadex command")
                raise RuntimeError("Failed to retrieve switch information")
        return self._fnv_data
    
    def get_leaf_switches(self):
        """Get active leaf switch IPs"""
        if 'leaf_ips' not in self.switch_cache:
            try:
                # First check if we need fnvread-specific data
                leaf_ips = []
                fnv_data = self._get_fnv_data()
                
                # Try to extract leaf switch IPs from fnvreadex data first
                for line in fnv_data.splitlines():
                    if 'nodeRole=2' in line and 'active=YES' in line:
                        match = re.search(r'address=(\d+\.\d+\.\d+\.\d+)/32', line)
                        if match:
                            ip = match.group(1)
                            leaf_ips.append(ip)
                
                # If we couldn't find any, fall back to fnvread (though this should be rare)
                if not leaf_ips:
                    logger.warning("No leaf switches found in fnvreadex data, falling back to fnvread")
                    output = subprocess.check_output(['acidiag', 'fnvread'], text=True)
                    for line in output.splitlines():
                        if 'active' in line and 'leaf' in line:
                            fields = line.split()
                            if len(fields) >= 5:
                                ip = fields[4].replace('/32', '')
                                leaf_ips.append(ip)
                
                logger.info(f"Found {len(leaf_ips)} leaf switches")
                self.switch_cache['leaf_ips'] = leaf_ips
                
            except subprocess.CalledProcessError:
                self.switch_cache['leaf_ips'] = []
                raise RuntimeError("Failed to retrieve leaf switch information")
        
        return self.switch_cache['leaf_ips']
    
    def get_spine_switches(self):
        """Get active non-modular spine switch IPs"""
        if 'spine_ips' not in self.switch_cache:
            try:
                spine_ips = []
                fnv_data = self._get_fnv_data()
                
                logger.debug("Extracting non-modular spine switch IPs")
                
                for line in fnv_data.splitlines():
                    if 'nodeRole=3' in line and 'active=YES' in line and 'N9K-C95' not in line:
                        # Use a pattern that exactly matches the address format in the output
                        match = re.search(r'address=(\d+\.\d+\.\d+\.\d+)/32', line)
                        if match:
                            ip = match.group(1)  # Already captured without /32
                            spine_ips.append(ip)
                            logger.debug(f"Found spine IP: {ip}")
                
                logger.info(f"Found {len(spine_ips)} spine switches: {', '.join(spine_ips)}")
                self.switch_cache['spine_ips'] = spine_ips
                
            except Exception as e:
                logger.error(f"Failed to extract spine switch info: {str(e)}")
                self.switch_cache['spine_ips'] = []
                raise RuntimeError(f"Failed to retrieve spine switch information: {str(e)}")
        
        return self.switch_cache['spine_ips']
    
    def get_modular_spine_switches(self):
        """Get modular spine switch IDs (which are skipped)"""
        if 'mod_spine_nodes' not in self.switch_cache:
            try:
                mod_spine_nodes = []
                fnv_data = self._get_fnv_data()
                
                for line in fnv_data.splitlines():
                    if 'nodeRole=3' in line and 'active=YES' in line and 'N9K-C95' in line:
                        match = re.search(r'id=(\d+)', line)
                        if match:
                            mod_spine_nodes.append(match.group(1))
                
                logger.info(f"Found {len(mod_spine_nodes)} modular spine switches")
                self.switch_cache['mod_spine_nodes'] = mod_spine_nodes
                
            except Exception as e:
                logger.error(f"Failed to extract modular spine info: {str(e)}")
                self.switch_cache['mod_spine_nodes'] = []
                raise RuntimeError(f"Failed to retrieve modular spine switch information: {str(e)}")
        
        return self.switch_cache['mod_spine_nodes']
    
    def get_modular_spine_ips(self):
        """Get modular spine switch IPs"""
        if 'mod_spine_ips' not in self.switch_cache:
            try:
                mod_spine_ips = []
                fnv_data = self._get_fnv_data()
                
                logger.debug("Extracting modular spine switch IPs")
                
                for line in fnv_data.splitlines():
                    if 'nodeRole=3' in line and 'active=YES' in line and 'N9K-C95' in line:
                        # Use a pattern that exactly matches the address format in the output
                        match = re.search(r'address=(\d+\.\d+\.\d+\.\d+)/32', line)
                        if match:
                            ip = match.group(1)  # Already captured without /32
                            mod_spine_ips.append(ip)
                            logger.debug(f"Found modular spine IP: {ip}")
                
                logger.info(f"Found {len(mod_spine_ips)} modular spine switches: {', '.join(mod_spine_ips)}")
                self.switch_cache['mod_spine_ips'] = mod_spine_ips
                
            except Exception as e:
                logger.error(f"Failed to extract modular spine IP info: {str(e)}")
                self.switch_cache['mod_spine_ips'] = []
                raise RuntimeError(f"Failed to retrieve modular spine switch IP information: {str(e)}")
        
        return self.switch_cache['mod_spine_ips']   
     
    def get_switch_name(self, sw_ip):
        """Get switch name from IP with improved extraction logic"""
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
        
        # If not in cache yet and no one is building it, extract all switch names at once
        if not self.switch_names and not self._building_cache:
            try:
                self._building_cache = True  # Set flag to prevent other threads
                
                # Log only once
                name_logger.debug("Building switch name cache from fnvreadex data")
                name_logger.debug("Sample of fnvreadex data first 200 chars:")

                # Get the fnvreadex data
                fnv_data = self._get_fnv_data()
                name_logger.debug(fnv_data[:200] if fnv_data else "No data")

                # First pass: Extract direct IP-to-name mappings using reliable patterns
                processed_ips = set()
                for line in fnv_data.splitlines():
                    # Look for lines that contain both an address and name
                    if 'address=' in line and 'name=' in line:
                        # Extract IP address
                        ip_match = re.search(r'address=(\d+\.\d+\.\d+\.\d+)/32', line)
                        if not ip_match:
                            continue
                        
                        sw_ip_in_line = ip_match.group(1)
                        processed_ips.add(sw_ip_in_line)
                        
                        # Extract name using simple split 
                        if "name=" in line:
                            name_part = line.split("name=")[1]
                            if " " in name_part:
                                name = name_part.split()[0]
                                self.switch_names[sw_ip_in_line] = name
                                
                                # Debug output only for the requested IP
                                if sw_ip_in_line == sw_ip:
                                    name_logger.debug(f"Mapped IP {sw_ip_in_line} to name {name}")
                
                # Log how many mappings we found directly
                name_logger.info(f"Found {len(self.switch_names)} direct IP-to-name mappings in fnvreadex data")
                
                # Second pass: For IPs that weren't mapped yet, try to correlate by node ID
                # Collect all node IDs and their associated names
                node_id_to_name = {}
                for line in fnv_data.splitlines():
                    if 'id=' in line and 'name=' in line:
                        id_match = re.search(r'id=(\d+)', line)
                        if id_match and "name=" in line:
                            node_id = id_match.group(1)
                            name_part = line.split("name=")[1]
                            if " " in name_part:
                                name = name_part.split()[0]
                                node_id_to_name[node_id] = name
                
                # For each IP not yet processed, find its node ID and look up the name
                all_ips = set(self.get_leaf_switches() + self.get_spine_switches() + self.get_modular_spine_ips())
                for sw_ip_to_check in all_ips:
                    if sw_ip_to_check in self.switch_names:
                        continue  # Skip already mapped IPs
                        
                    # Find node ID for this IP
                    for line in fnv_data.splitlines():
                        if f"address={sw_ip_to_check}/32" in line:
                            id_match = re.search(r'id=(\d+)', line)
                            if id_match:
                                node_id = id_match.group(1)
                                if node_id in node_id_to_name:
                                    self.switch_names[sw_ip_to_check] = node_id_to_name[node_id]
                                    name_logger.debug(f"Mapped IP {sw_ip_to_check} to name {node_id_to_name[node_id]} via node ID {node_id}")
                                break
                
                # Final pass: Try regex approaches for any remaining unmapped IPs
                for sw_ip_to_check in all_ips:
                    if sw_ip_to_check in self.switch_names:
                        continue  # Skip already mapped IPs
                        
                    # Search for lines containing this IP
                    for line in fnv_data.splitlines():
                        if f"address={sw_ip_to_check}/32" in line:
                            # Try multiple patterns
                            for pattern in [r'name=([^\s]+)', r'name=([^,\s]+)', r'name="([^"]+)"']:
                                name_match = re.search(pattern, line)
                                if name_match:
                                    name = name_match.group(1)
                                    self.switch_names[sw_ip_to_check] = name
                                    name_logger.debug(f"Mapped IP {sw_ip_to_check} to name {name} via regex pattern")
                                    break
                            
                            # If we found a name, no need to check more lines for this IP
                            if sw_ip_to_check in self.switch_names:
                                break
                                
                # Log final mapping count
                name_logger.info(f"Total IP-to-name mappings after all passes: {len(self.switch_names)}")

            except Exception as e:
                name_logger.error(f"Error building switch name cache: {str(e)}")
                name_logger.debug(f"Exception details: {traceback.format_exc()}")
        
            finally:
                self._building_cache = False  # Always reset flag when done   

        # If we STILL don't have the name after all attempts, use IP-based fallback
        if sw_ip not in self.switch_names:
            # Extract node ID from fnvreadex data to use in the fallback name
            node_id = None
            if self._fnv_data:
                for line in self._fnv_data.splitlines():
                    if f"address={sw_ip}/32" in line:
                        id_match = re.search(r'nodeId=(\d+)', line)
                        if id_match:
                            node_id = id_match.group(1)
                            break
            
            # Use node ID in the fallback name if available
            if node_id:
                self.switch_names[sw_ip] = f"node-{node_id}"
                name_logger.warning(f"No name found for {sw_ip}, using fallback with node ID: {self.switch_names[sw_ip]}")
            else:
                self.switch_names[sw_ip] = f"switch-{sw_ip}"
                name_logger.warning(f"No name found for {sw_ip}, using fallback: {self.switch_names[sw_ip]}")
        
        return self.switch_names[sw_ip]
    
    def collect_switch_data(self, sw_ip, connection):
        """
        Wrapper around SwitchDataCollector.collect_data for backward compatibility
        
        Args:
            sw_ip: The IP address of the switch
            connection: An established SSH connection object
            
        Returns:
            dict: Dictionary containing switch data
        """
        sw_name = self.get_switch_name(sw_ip)
        return SwitchDataCollector.collect_data(sw_name, sw_ip, connection)

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
        result_type = conn.cmd(f"ls -lh {repodata_path}")
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
        """Extract kickstart image path using multiple patterns"""
        for pattern in SwitchDataCollector.IMAGE_PATH_PATTERNS:
            image_match = re.search(pattern, version_output)
            if image_match:
                return image_match.group(1)
        return None
    
    @staticmethod
    def extract_md5(md5_output):
        """Extract MD5 hash from command output"""
        md5_match = re.search(SwitchDataCollector.MD5_PATTERN, md5_output)
        return md5_match.group(1) if md5_match else None
    
    @staticmethod
    def collect_data(sw_name, sw_ip, connection):
        """
        Collect all required data from a switch
        
        Args:
            sw_name: Switch name for identification
            sw_ip: Switch IP address
            connection: An established SSH connection object
            
        Returns:
            dict: Dictionary containing collected switch data
        """
        result = {"switch": sw_name, "ip": sw_ip, "status": "unknown"}
        
        try:
            # Get version info - works in both bash and vsh
            result_type = connection.cmd("show version")
            if result_type != "prompt":
                raise RuntimeError(f"Failed to get version info: {result_type}")
                
            version_output = connection.output
            
            # Extract memory capacity
            memory_capacity = SwitchDataCollector.extract_memory(version_output)
            result["memory_kb"] = memory_capacity
            
            # Extract kickstart image path
            kickstart_image = SwitchDataCollector.extract_image_path(version_output)
            result["image_path"] = kickstart_image
            
            if kickstart_image:
                # Get MD5 checksum of the image
                result_type = connection.cmd(f"md5sum {kickstart_image}")
                md5_output = connection.output
                md5_hash = SwitchDataCollector.extract_md5(md5_output)
                
                # Store the command output to help diagnose MD5 retrieval failures
                result["md5_command_output"] = md5_output
                
                if not md5_hash:
                    # Try to fix permissions and retry
                    connection.cmd(f"chmod 666 {kickstart_image}")
                    result_type = connection.cmd(f"md5sum {kickstart_image}")
                    if result_type != "prompt":
                        raise RuntimeError(f"Failed to get MD5 checksum: {result_type}")
                        
                    md5_output = connection.output
                    result["md5_command_output"] = md5_output
                    md5_hash = SwitchDataCollector.extract_md5(md5_output)
                
                result["md5sum"] = md5_hash
                
            # Set status to success if we got the critical information
            if memory_capacity is not None and (kickstart_image is not None or result.get("md5sum") is not None):
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
            
        memory_kb = switch_data.get("memory_kb")
        md5sum = switch_data.get("md5sum")
        
        # More specific error messages based on what's missing
        if not memory_kb and not md5sum:
            return "ERROR", "Could not retrieve Memory and MD5 information"
        elif not memory_kb:
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
        if memory_kb < SwitchDataCollector.MEMORY_THRESHOLD:
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
    
    def log_switch_result(self, switch_data):
        """Log data for a single switch with specific error details, relevant diagnostics, and recommendations"""
        sw_name = switch_data.get("switch", "Unknown")
        sw_ip = switch_data.get("ip", "Unknown")
        memory = switch_data.get("memory_kb", "Unknown")
        image_path = switch_data.get("image_path", "Unknown")
        md5sum = switch_data.get("md5sum", "Unknown")
        result = switch_data.get("result", "ERROR")
        message = switch_data.get("message", "No validation message")
        all_diagnostics = switch_data.get("diagnostics", {})
        
        with self.lock:
            with open(self.filename, 'a') as f:
                # Basic switch information
                f.write(f"\nSwitch: {sw_name} ({sw_ip})\n")
                f.write(f"Memory: {memory} KB\n")
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
                        f.write("Re-run the script from the admin account to rectify the permissions issue.\n\n")
                        f.write("Note: Rectification of permissions will only work from the admin account.\nIt will not work even if a non-admin user belongs to the admin group.\n")
                    
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
                        for line in cmd_output.splitlines():
                            if "permission denied" in line.lower():
                                f.write(f"{line.strip()}\n")
                                break
                    # If no permission denied message found, fall back to showing the command output directly
                    elif cmd_output:
                        f.write(f"{cmd_output.strip()}\n")
                
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

def process_switch(sw_ip, switch_info, progress_bar, username, password, md5_32bit, md5_64bit, bind_addr=None, is_modular_spine=False):
    """Process a single switch and collect results with robust error handling"""
    conn = None
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
        progress_bar.update(f"{sw_name}: Connecting", 0)
        
        # Use bind address for better SSH connectivity
        conn = Connection(sw_ip, username, password, timeout=2, bind_address=bind_addr)  # Reduced timeout
        
        # Authentication failures should be caught immediately with no retry
        # Use max_attempts=1 to prevent unwanted retries
        try:
            if not conn.login(max_attempts=1):
                # For connection issues, proceed with diagnostics
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
                # Use unified error handler but still raise to main thread
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
            # Pass md5_64bit to perform_modular_spine_checks
            switch_data = perform_modular_spine_checks(conn, sw_name, sw_ip, progress_bar, md5_64bit)
        else:
            switch_data = perform_regular_switch_checks(conn, sw_name, sw_ip, progress_bar, 
                                                     switch_info, md5_32bit, md5_64bit)
        
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
        # Always ensure connection is closed
        if conn:
            try:
                progress_bar.update(f"{sw_name}: Closing connection", 0)
                conn.close()
            except:
                pass
        
        # Always mark as completed in progress bar
        progress_bar.update(f"Completed {sw_name}", 1)
    
    return switch_data

def perform_modular_spine_checks(conn, sw_name, sw_ip, progress_bar, md5_64bit):
    """Perform checks specific to modular spine switches - always check for 64-bit image"""
    # Create data structure for modular spines
    switch_data = {
        "switch": sw_name,
        "ip": sw_ip,
        "status": "success",
        "memory_kb": "N/A - Modular Spine",
        "image_path": None,
        "md5sum": None,
        "result": "INFO",
        "message": "Modular spine"
    }
    
    # Get version info for image path
    progress_bar.update(f"{sw_name}: Checking image details", 0)
    result_type = conn.cmd("show version")
    if result_type == "prompt":
        version_output = conn.output
        
        # Extract kickstart image path
        kickstart_image = SwitchDataCollector.extract_image_path(version_output)
        switch_data["image_path"] = kickstart_image
        
        if kickstart_image:
            # Get MD5 checksum of the image
            progress_bar.update(f"{sw_name}: Retrieving MD5 hash", 0)
            result_type = conn.cmd(f"md5sum {kickstart_image}")
            md5_output = conn.output
            md5_hash = SwitchDataCollector.extract_md5(md5_output)
            
            # Store the command output to help diagnose MD5 retrieval failures
            switch_data["md5_command_output"] = md5_output
            
            if not md5_hash:
                # Try to fix permissions and retry
                conn.cmd(f"chmod 666 {kickstart_image}")
                result_type = conn.cmd(f"md5sum {kickstart_image}")
                if result_type == "prompt":
                    md5_output = conn.output
                    switch_data["md5_command_output"] = md5_output
                    md5_hash = SwitchDataCollector.extract_md5(md5_output)
            
            switch_data["md5sum"] = md5_hash
            
            # Validate against 64-bit image MD5 hash
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
        switch_data["message"] = "Failed to retrieve image information"
    
    # Check Repodata on modular spines
    progress_bar.update(f"{sw_name}: Checking Repodata (Modular Spine)", 0)
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

def perform_regular_switch_checks(conn, sw_name, sw_ip, progress_bar, switch_info, md5_32bit, md5_64bit):
    """Perform checks for regular leaf/spine switches"""
    # Initialize result structure and diagnostics
    diagnostics = {"error_type": None}
    
    # Collect switch data with timeout protection
    progress_bar.update(f"{sw_name}: Checking memory capacity", 0)
    
    # Start a timer to detect slow operations
    start_time = time.time()
    
    # Use the centralized collector instead of switch_info.collect_switch_data
    switch_data = SwitchDataCollector.collect_data(sw_name, sw_ip, conn)
    
    collection_time = time.time() - start_time
    switch_data["collection_time"] = f"{collection_time:.1f}s"
    
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


# Wrapper function for modular spine switches
def process_spine_repodata(sw_ip, switch_info, progress_bar, username, password, md5_64bit, bind_addr=None):
    """Process a modular spine switch for Repodata and 64-bit image check"""
    return process_switch(sw_ip, switch_info, progress_bar, username, password, None, md5_64bit, bind_addr, True)

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
        leaf_ips = switch_info.get_leaf_switches()
        spine_ips = switch_info.get_spine_switches()
        
        # Extract modular spine IPs - add a function to get modular spine IPs
        mod_spine_ips = switch_info.get_modular_spine_ips()
        
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