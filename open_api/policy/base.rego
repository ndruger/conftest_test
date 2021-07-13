package main

paths = input.paths

deny[msg] {
  api := paths[_][_]
  not api.operationId
  msg := "api should have operationId"
}

deny[msg] {
  api := paths[_][_]
  not re_match("^[a-z]", api.operationId)
  msg := "operationId should be camel case"
}

deny[msg] {
  api := paths[_].post
  not api.responses["400"]
  msg := "POST api should have 400 response"
}
