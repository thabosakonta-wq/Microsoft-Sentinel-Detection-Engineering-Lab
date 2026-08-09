# MITRE ATT&CK Detection Mapping

## Purpose

This document maps the detection engineering and threat hunting content in this project to relevant MITRE ATT&CK techniques.

## Detection and Hunting Coverage

| Technique | Name | Project Coverage |
|---|---|---|
| T1059 | Command and Scripting Interpreter | Suspicious PowerShell and process creation detection |
| T1059.001 | PowerShell | PowerShell detection and hunting |
| T1059.003 | Windows Command Shell | Process creation monitoring |
| T1110 | Brute Force | Failed authentication hunting |
| T1110.003 | Password Spraying | Failed authentication hunting |

## T1059 - Command and Scripting Interpreter

The project monitors command and scripting activity that may indicate execution of attacker-controlled commands.

### Evidence

- Suspicious PowerShell detection
- Process creation monitoring
- Process creation hunting

## T1059.001 - PowerShell

PowerShell execution is monitored because PowerShell can be used for legitimate administration as well as post-compromise execution.

### Evidence

- Suspicious PowerShell detection rule
- Suspicious PowerShell hunting query
- Process creation monitoring

## T1059.003 - Windows Command Shell

Windows command-shell execution can be identified through process creation telemetry and command-line analysis.

### Evidence

- Process creation monitoring
- Process creation hunting

## T1110 - Brute Force

Authentication failures can provide telemetry for identifying repeated authentication attempts that may indicate brute-force activity.

### Evidence

- Failed authentication detection
- Failed authentication hunting

## T1110.003 - Password Spraying

Repeated authentication failures involving multiple accounts may indicate password-spraying activity.

### Evidence

- Failed authentication detection
- Failed authentication hunting

## Analyst Note

MITRE ATT&CK mappings are used to provide a common framework for describing adversary techniques represented by the detection and hunting content in this portfolio.

The mappings describe the detection coverage implemented in this lab and do not imply that malicious activity was actually observed.