# oidc_test
OpenID ConnectのRPのjavaプロトコード。

OPとの通信やIDトークンの検証などにはNimbus OAuth 2.0 SDK with OpenID Connect extensionsを使用。

想定している構成は以下のようなWebアプリケーション。
・GUIはhtml+js, 表示する内容はajaxでWebアプリケーションのREST APIを呼び出して取得する。
・ServerはJava Servlet。REST APIを実装する。


・作りのサマリ
OidcLoginServlet:ログイン用のサーブレット。アクセスするとOPの認可URLにリダイレクト
OidcCallbackServlet:
OPからのリダイレクトバックを受け付けるサーブレット。認可コードを使ってアクセストークンを要求する。
アクセストークン/リフレッシュトークンはセッションに保存。

OidcSecurityFilter:
サーブレットフィルタ。
ブラウザ経由のアクセスの場合、アクセストークン/リフレッシュトークンがセッションに保存されているかチェックし、
また、期限切れ(or 残有効期限が120秒未満)の場合、アクセストークンをリフレッシュする。
Bearer認証の場合、アクセストークンを検証する。
