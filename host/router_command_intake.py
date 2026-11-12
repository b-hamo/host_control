"""Pure data conversion for clipboard analysis. Unsupported forms remain held.

No subprocess, evaluation, decoding via a shell, or Host fallback is permitted.
Classification never authorizes Host execution, including apparently benign text.
"""
import base64
import re


def script_from_source(text, form, start=None, end=None):
    """Decode data only. Never evaluate fetched code on Host.

    command-literal is a deliberately narrow adapter for a single-quoted JS
    string containing PowerShell -Command. Unsupported syntax fails closed.
    The interactive NoExit switch is explicitly omitted in the returned batch
    analysis contract; the script body itself is unchanged.
    """
    if form == 'powershell-script':
        if start is not None or end is not None:
            raise ValueError('Script source must be used in full')
        return text, {'transform': 'identity'}
    if form != 'powershell-command-literal' or type(start) is not int or type(end) is not int:
        raise ValueError('Unsupported source form')
    if not 0 <= start < end <= len(text):
        raise ValueError('Invalid literal range')
    literal = text[start:end]
    if not re.fullmatch(r"'(?:[^'\\\r\n]|\\['\\])*'", literal):
        raise ValueError('Only a static single-quoted literal is supported')
    command = re.sub(r"\\(['\\])", r'\1', literal[1:-1])
    match = re.fullmatch(r'powershell(?:\.exe)? -NoProfile(?: -NoExit)? -Command "([^\r\n]+)"', command, re.I)
    if not match:
        raise ValueError('Unsupported PowerShell command form')
    return match[1], {'transform': 'powershell-command-to-batch-script-v1',
                      'original_command': command, 'interactive_noexit_removed': ' -noexit ' in command.lower()}



def decode_powershell(text):
    if not isinstance(text, str) or len(text.encode()) > 65536 or '\0' in text:
        raise ValueError('Invalid command size or content')
    match = re.fullmatch(r'\s*powershell(?:\.exe)?\s+(.*?)\s*', text, re.I | re.S)
    if not match:
        raise ValueError('Unsupported interpreter; held, no Host fallback')
    rest = match[1]
    switches = []
    while True:
        option = re.match(r'-(NoProfile|NoExit|NonInteractive)\s+', rest, re.I)
        if not option:
            break
        switches.append(option[1].lower())
        rest = rest[option.end():]
    command = re.fullmatch(r'-(Command|EncodedCommand)\s+(.+)', rest, re.I | re.S)
    if not command:
        raise ValueError('Unsupported arguments; held, no Host fallback')
    body = command[2]
    if command[1].lower() == 'encodedcommand':
        body = base64.b64decode(body, validate=True).decode('utf-16-le')
    elif body.startswith('"') and body.endswith('"'):
        body = body[1:-1]
    else:
        raise ValueError('Command must be a complete quoted body; held')
    if not body.strip() or '\0' in body:
        raise ValueError('Empty or invalid script')
    return body, {'transform': 'powershell-clipboard-to-batch-v2', 'original_command': text,
        'encoded': command[1].lower() == 'encodedcommand', 'interactive_noexit_removed': 'noexit' in switches}
