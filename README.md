# AgentShield

A defensive security layer that sits between an AI agent and its tools. It checks every tool call and decides: allow, deny, or require approval, and logs the reason.

Built for Parallax 2026 (Problem Statement 1).

## The Problem
AI agents read documents and call tools. Untrusted content (emails, web pages, files) can hide instructions that trick the agent into leaking secrets or misusing a tool.

## Our Solution
A policy enforcement point that checks each tool call against its source and permissions, fails closed when unsure, and keeps an audit log.

## The Contract
check(action, args, source) returns:
{"decision": "ALLOW" | "DENY" | "REQUIRE_APPROVAL", "reason": "..."}

source is "user" or "untrusted".

## How to Run
 1. Start the Server
```bash
node src/server.js
```bash
npm run dev
Open `http://localhost:4000` in your web browser.
 or
https://parallex-roan.vercel.app/ 
open this website

## Team
- Sharvari N Prasad
- Sharanya
- sanjana
- shambavi
