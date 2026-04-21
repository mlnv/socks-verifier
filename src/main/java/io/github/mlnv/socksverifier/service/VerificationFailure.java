package io.github.mlnv.socksverifier.service;

public enum VerificationFailure {
  NONE,
  INVALID_ARGUMENTS,
  AUTHENTICATION_FAILED,
  PROXY_CONNECTION_FAILED,
  TARGET_CONNECTION_FAILED,
  PROBE_FAILED,
  INTERNAL_ERROR
}
