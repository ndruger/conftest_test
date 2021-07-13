package main

deny[msg] {
  input.provider.name == "aws"
  not input.provider.runtime
  msg := "aws provider should have runtime"
}

deny[msg] {
  input.provider.name == "aws"
  not input.provider.timeout
  msg := "aws provider should have timeout"
}
