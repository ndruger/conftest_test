package main

# AWSにデプロイする場合のみ、runtimeの指定を必須とする
deny[msg] {
  input.provider.name == "aws"
  not input.provider.runtime
  msg := "aws provider should have runtime"
}

# AWSにデプロイする場合のみ、timeoutを利用用途に応じて設定するのを忘れないように指定を必須にする
deny[msg] {
  input.provider.name == "aws"
  not input.provider.timeout
  msg := "aws provider should have timeout"
}
