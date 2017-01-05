defmodule Ueberauth.Strategy.Basecamp do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with Basecamp.
  ### Setup
  Create an application in Basecamp for you to use.
  Register a new application at: [37 signals](https://integrate.37signals.com/) and get the `client_id` and `client_secret`.
  Include the provider in your configuration for Ueberauth
      config :ueberauth, Ueberauth,
        providers: [
          basecamp: { Ueberauth.Strategy.Basecamp, [] }
        ]
  Then include the configuration for basecamp.
      config :ueberauth, Ueberauth.Strategy.Basecamp.OAuth,
        client_id: System.get_env("BASECAMP_CLIENT_ID"),
        client_secret: System.get_env("BASECAMP_CLIENT_SECRET")
  If you haven't already, create a pipeline and setup routes for your callback handler
      pipeline :auth do
        Ueberauth.plug "/auth"
      end
      scope "/auth" do
        pipe_through [:browser, :auth]
        get "/:provider/callback", AuthController, :callback
      end
  Create an endpoint for the callback where you will handle the `Ueberauth.Auth` struct
      defmodule MyApp.AuthController do
        use MyApp.Web, :controller
        def callback_phase(%{ assigns: %{ ueberauth_failure: fails } } = conn, _params) do
          # do things with the failure
        end
        def callback_phase(%{ assigns: %{ ueberauth_auth: auth } } = conn, params) do
          # do things with the auth
        end
      end
  You can edit the behaviour of the Strategy by including some options when you register your provider.
  To set the `uid_field`
      config :ueberauth, Ueberauth,
        providers: [
          github: { Ueberauth.Strategy.Basecamp, [uid_field: :id] }
        ]
  Default is `:login`
  """
  use Ueberauth.Strategy, uid_field: :id,
                          oauth2_module: Ueberauth.Strategy.Basecamp.OAuth

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @doc """
  Handles the initial redirect to the basecamp authentication page.
  """
  def handle_request!(conn) do
    opts = [redirect_uri: callback_url(conn), type: "web_server"]

    module = option(conn, :oauth2_module)
    redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  @doc """
  Handles the callback from Basecamp. When there is a failure from Basecamp the failure is included in the
  `ueberauth_failure` struct. Otherwise the information returned from Basecamp is returned in the `Ueberauth.Auth` struct.
  """
  def handle_callback!(%Plug.Conn{ params: %{ "code" => code } } = conn) do
    module = option(conn, :oauth2_module)
    token = apply(module, :get_token!, [[code: code, type: "web_server", redirect_uri: callback_url(conn)]])

    if token.access_token == nil do
      set_errors!(conn, [error(token.other_params["error"], token.other_params["error_description"])])
    else
      fetch_user(conn, token)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw Basecamp response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:basecamp_user, nil)
    |> put_private(:basecamp_token, nil)
  end

  @doc """
  Fetches the uid field from the Basecamp response. This defaults to the option `uid_field` which in-turn defaults to `id`
  """
  def uid(conn) do
    conn.private.basecamp_user["identity"][option(conn, :uid_field) |> to_string]
    |> to_string
  end

  @doc """
  Includes the credentials from the Basecamp response.
  """
  def credentials(conn) do
    token = conn.private.basecamp_token
    scopes = (token.other_params["scope"] || "")
    |> String.split(",")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.basecamp_user

    %Info{
      first_name: user["identity"]["first_name"],
      last_name: user["identity"]["last_name"],
      name: user["identity"]["first_name"] <> user["identity"]["last_name"],
      email: user["identity"]["email_address"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the Basecamp callback.
  """
  def extra(conn) do
    %Extra {
      raw_info: %{
        token: conn.private.basecamp_token,
        user: conn.private.basecamp_user
      }
    }
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :basecamp_token, token)
    path = "/authorization.json"

    oauth_response = Ueberauth.Strategy.Basecamp.OAuth.get(token, path)

    case oauth_response do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:ok, %OAuth2.Response{status_code: status_code, body: user}}
        when status_code in 200..399 ->
        put_private(conn, :basecamp_user, user)
      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end