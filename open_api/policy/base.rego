package main

paths = input.paths

# クライアントのコードの自走生成のためにAPIのoperationIdは必須とする
deny[msg] {
  api := paths[_][_]
  not api.operationId
  msg := "api should have operationId"
}

# APIのoperationIdはキャメルケースで統一する
deny[msg] {
  api := paths[_][_]
  not re_match("^[a-z][A-Za-z0-9]*$", api.operationId)
  msg := "operationId should be camel case"
}

# POSTのAPIの場合、不正なリクエストボディに対する400エラーを返すはず
deny[msg] {
  api := paths[_].post
  not api.responses["400"]
  msg := "POST api should have 400 response"
}
