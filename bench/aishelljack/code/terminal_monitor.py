#!/usr/bin/env python3
"""
Terminal Monitor for Cursor Automation

This module monitors terminal activity during Cursor AI simulations to capture
what commands are executed when the AI processes atomic test payloads.
"""

import os
import time
import json
import logging
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

class TerminalMonitor:
    def __init__(self, simulation_id: str, results_dir: str):
        """Initialize terminal monitor for a simulation session"""
        self.simulation_id = simulation_id
        self.results_dir = os.path.expanduser(results_dir)
        self.session_dir = os.path.join(self.results_dir, simulation_id)
        
        # Create session directory
        os.makedirs(self.session_dir, exist_ok=True)
        
        # Monitoring state
        self.monitoring = False
        self.start_time = None
        self.end_time = None
        self.commands_executed = []
        self.initial_history = []
        
        # Files for logging
        self.command_log_file = os.path.join(self.session_dir, "commands.log")
        self.results_file = os.path.join(self.session_dir, "results.json")
        
    def start_monitoring(self):
        """Start monitoring terminal activity"""
        print(f"🔍 Starting terminal monitoring for: {self.simulation_id}")
        self.monitoring = True
        self.start_time = datetime.now()
        
        # Capture initial shell history
        self.initial_history = self._get_current_history()
        print(f"📝 Captured initial history: {len(self.initial_history)} commands")
        
        return True
    
    def stop_monitoring(self):
        """Stop monitoring and save results"""
        print(f"⏹️  Stopping terminal monitoring...")
        self.monitoring = False
        self.end_time = datetime.now()
        
        # Give a moment for any commands to be written to history
        time.sleep(2)
        
        # Compare history to find new commands
        self._compare_history()
        
        # Save final results
        self._save_results()
        
        return len(self.commands_executed)
    
    def _get_current_history(self):
        """Get current shell history"""
        # Force history to be written to file first
        try:
            subprocess.run(['bash', '-c', 'history -a'], shell=False, timeout=5)
        except:
            pass
        
        # Read from history file
        return self._read_history_file()
    
    def _read_history_file(self):
        """Fallback method to read history from file"""
        try:
            history_file = os.path.expanduser("~/.bash_history")
            if os.path.exists(history_file):
                with open(history_file, 'r', encoding='utf-8', errors='ignore') as f:
                    return [line.strip() for line in f if line.strip()]
            return []
        except Exception as e:
            print(f"⚠️  Error reading history file: {e}")
            return []
    
    def _compare_history(self):
        """Compare current history with initial history to find new commands"""
        print("🔍 Comparing shell history to detect new commands...")
        
        # Get current history
        current_history = self._get_current_history()
        print(f"📝 Current history: {len(current_history)} commands")
        
        # Find new commands by comparing
        initial_set = set(self.initial_history)
        current_set = set(current_history)
        
        # Get commands that are in current but not in initial
        new_commands = []
        
        # Method 1: Look for commands not in initial set
        for cmd in current_history:
            if cmd not in initial_set:
                new_commands.append(cmd)
        
        # Method 2: If history grew, check the last N commands
        if len(current_history) > len(self.initial_history):
            diff_count = len(current_history) - len(self.initial_history)
            last_commands = current_history[-diff_count:] if diff_count > 0 else []
            
            for cmd in last_commands:
                if cmd not in new_commands:
                    new_commands.append(cmd)
        
        # Log new commands
        for cmd in new_commands:
            if not self._is_duplicate_command(cmd):
                self._log_command(cmd)
        
        if new_commands:
            print(f"✅ Found {len(new_commands)} new commands executed by Cursor!")
        else:
            print("ℹ️  No new commands detected in history")
    
    def _is_duplicate_command(self, command):
        """Check if this command was already logged"""
        if not self.commands_executed:
            return False
        
        recent_commands = [cmd['command'] for cmd in self.commands_executed]
        return command in recent_commands

    def _log_command(self, command: str):
        """Log a command execution"""
        command_info = {
            'timestamp': datetime.now().isoformat(),
            'command': command
        }
        
        self.commands_executed.append(command_info)
        
        # Write to log file immediately
        with open(self.command_log_file, 'a') as f:
            f.write(f"{command_info['timestamp']}: {command}\n")
        
        print(f"📝 Command: {command}")
    
    def _save_results(self):
        """Save final monitoring results"""
        results = {
            'simulation_id': self.simulation_id,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'commands_count': len(self.commands_executed),
            'commands': self.commands_executed
        }
        
        with open(self.results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"💾 Results saved: {self.results_file}")
        print(f"📊 Commands captured: {len(self.commands_executed)}")
    
    def get_session_summary(self) -> Dict:
        """Get a summary of the monitoring session"""
        return {
            'simulation_id': self.simulation_id,
            'session_dir': self.session_dir,
            'commands_captured': len(self.commands_executed),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None
        }

def create_simulation_session(scenario: str, codebase: str, atomic_test_index: str = None) -> str:
    """Create a unique simulation session ID"""
    session_parts = [scenario, codebase]
    
    if atomic_test_index:
        # Clean up atomic test index for filename
        clean_index = atomic_test_index.replace('.', '_')
        session_parts.append(clean_index)
    
    return "_".join(session_parts)

def main():
    """Test the terminal monitor"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test terminal monitoring')
    parser.add_argument('--session-id', default='test_session', help='Session ID for testing')
    parser.add_argument('--duration', type=int, default=10, help='Test duration in seconds')
    
    args = parser.parse_args()
    
    # Create and test monitor
    monitor = TerminalMonitor(args.session_id)
    
    print(f"Starting test monitoring for {args.duration} seconds...")
    monitor.start_monitoring()
    
    # Run some test commands to demonstrate
    test_commands = [
        "echo 'Test command 1'",
        "whoami",
        "ls -la"
    ]
    
    for cmd in test_commands:
        subprocess.run(cmd, shell=True, capture_output=True)
        time.sleep(1)
    
    time.sleep(args.duration)
    
    monitor.stop_monitoring()
    
    # Show summary
    summary = monitor.get_session_summary()
    print(f"\nMonitoring Summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    main() 