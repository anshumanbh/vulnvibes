#!/usr/bin/env python3
"""
Hook: Save Progress

Saves investigation progress for resumability and audit trails.
Inspired by Anthropic's "Effective Harnesses for Long-Running Agents" paper.

Hook Event: Stop
Matcher: (empty - matches all)
"""
import json
import sys
import os
from datetime import datetime
from pathlib import Path


def save_progress(input_data: dict) -> None:
    """
    Save investigation progress to a JSON log file.
    
    Progress includes:
    - Timestamp
    - Session ID
    - Status
    - Findings summary
    - Tool calls made
    """
    # Determine progress file location
    progress_dir = Path(".claude")
    progress_file = progress_dir / "triage-progress.json"
    
    # Ensure directory exists
    progress_dir.mkdir(parents=True, exist_ok=True)
    
    # Build progress entry
    progress_entry = {
        "timestamp": datetime.now().isoformat(),
        "session_id": input_data.get("session_id", "unknown"),
        "status": input_data.get("status", "unknown"),
        "pr_url": input_data.get("pr_url", ""),
        "verdict": input_data.get("verdict"),
        "skills_used": input_data.get("skills_used", []),
        "tool_calls": input_data.get("tool_calls", 0),
        "duration_seconds": input_data.get("duration", 0),
    }
    
    # Load existing progress
    existing_progress = []
    if progress_file.exists():
        try:
            with open(progress_file, "r") as f:
                existing_progress = json.load(f)
                if not isinstance(existing_progress, list):
                    existing_progress = [existing_progress]
        except (json.JSONDecodeError, IOError):
            existing_progress = []
    
    # Append new entry
    existing_progress.append(progress_entry)
    
    # Keep last 100 entries to prevent unbounded growth
    if len(existing_progress) > 100:
        existing_progress = existing_progress[-100:]
    
    # Save progress
    with open(progress_file, "w") as f:
        json.dump(existing_progress, f, indent=2)


def main():
    """Main hook entry point."""
    try:
        # Read hook input from stdin
        input_data = json.load(sys.stdin)
        
        # Save progress
        save_progress(input_data)
        
        # Return empty response (don't modify agent behavior)
        print(json.dumps({}))
    
    except Exception as e:
        # Log error but don't block the agent
        sys.stderr.write(f"Progress save hook error: {e}\n")
        print(json.dumps({}))


if __name__ == "__main__":
    main()
