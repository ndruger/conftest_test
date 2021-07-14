package main

# 間違ってpublishしてしまわないようにprivate:trueを付ける
deny[msg] {
  not input.private == true
  msg := "private project should have private 'true'"
}

# privateなパッケージなのでライセンスはUNLICENSEDを付ける
deny[msg] {
  not input.license == "UNLICENSED"
  msg := "private project should have license 'UNLICENSED'"
}
