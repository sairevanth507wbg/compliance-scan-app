"""Posit Connect branch-compliance job.

Checks that every Git-backed Posit Connect application is deployed from the
required branch (default ``main``) of a repository in an approved GitHub
organization (ALLOWED_GIT_ORGS), notifies owners,
and - only when explicitly enabled - locks applications that stay
non-compliant after the configured grace period.
"""
