"""keyleak: incident response for a leaked AWS access key.

Safety rule, repeated everywhere on purpose: keyleak NEVER authenticates with the
leaked key. It runs with the caller's own credentials (the normal boto3 credential
chain) and only ever treats the leaked key ID as a string to look up.
"""

__version__ = "0.1.0"
