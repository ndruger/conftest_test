package main

deny[msg] {
  not input.private == true
  msg := "private project should have private 'true'"
}

deny[msg] {
  not input.license == "UNLICENSED"
  msg := "private project should have license 'UNLICENSED'"
}
