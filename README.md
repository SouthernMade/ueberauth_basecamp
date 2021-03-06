# Überauth Basecamp

> Basecamp OAuth2 strategy for Überauth.

## Installation

1. Setup your application at [37signals](https://integrate.37signals.com).

1. Add `:ueberauth_basecamp` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ueberauth_basecamp, "~> 0.1"}]
    end
    ```

1. Add the strategy to your applications:

    ```elixir
    def application do
      [applications: [:ueberauth_basecamp]]
    end
    ```

1. Add Basecamp to your Überauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        basecamp: {Ueberauth.Strategy.Basecamp, []}
      ]
    ```

1.  Update your provider configuration:

    ```elixir
    config :ueberauth, Ueberauth.Strategy.Basecamp.OAuth,
      client_id: System.get_env("BASECAMP_CLIENT_ID"),
      client_secret: System.get_env("BASECAMP_CLIENT_SECRET")
    ```

1.  Include the Überauth plug in your controller:

    ```elixir
    defmodule MyApp.AuthController do
      use MyApp.Web, :controller

      pipeline :browser do
        plug Ueberauth
        ...
       end
    end
    ```

1.  Create the request and callback routes if you haven't already:

    ```elixir
    scope "/auth", MyApp do
      pipe_through :browser

      get "/:provider", AuthController, :request
      get "/:provider/callback", AuthController, :callback
    end
    ```

1. You controller needs to implement callbacks to deal with `Ueberauth.Auth` and `Ueberauth.Failure` responses.

For an example implementation see the [Überauth Example](https://github.com/ueberauth/ueberauth_example) application.

## Calling

Depending on the configured url you can initial the request through:

    /auth/basecamp


## License

Please see [LICENSE](https://github.com/southernmade/ueberauth_basecamp/blob/master/LICENSE) for licensing details.