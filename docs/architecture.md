# Architecture

## Goals

- provide a single entrypoint for CTF challenge analysis
- keep challenge guidance separated from executable helpers
- make every category extensible through plugins

## Core Components

### 1. Challenge Intake

Collects:

- challenge title
- challenge description
- tags
- optional files and notes

### 2. Classifier

Produces:

- likely challenge category
- confidence score
- explanation
- recommended next steps

### 3. Guidance Engine

Maps a category to:

- methodology checklist
- common traps
- tool suggestions
- manual verification prompts

### 4. Plugin System

Each plugin can expose:

- metadata
- feature flags
- safe helper commands for CTF-only analysis
- category-specific prompts/checklists

### 5. Result Workspace

Stores:

- notes
- extracted artifacts
- category decision history
- solved and unsolved observations

## Safety Boundary

The platform should only support lawful, sandboxed challenge environments such as CTF competitions and training labs. Do not add features intended for unauthorized access to real targets.

