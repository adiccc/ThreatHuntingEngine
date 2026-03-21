# Threat Hunting Engine

A Python-based threat hunting engine that ingests authentication, process, and network telemetry, normalizes events into a unified schema, applies detection rules for suspicious attacker behavior, and generates investigation-ready alerts.

## MVP Features
- Ingest authentication, process, and network logs
- Normalize multiple log types into a unified event model
- Detect brute force activity followed by successful login
- Detect suspicious process execution
- Detect rare outbound connections
- Generate alert summaries with supporting evidence

## Project Goals
- Demonstrate threat hunting and detection engineering skills
- Analyze security telemetry across multiple sources
- Build clean, modular Python code for a realistic security workflow