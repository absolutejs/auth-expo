# @absolutejs/auth-expo

Expo native-runtime adapter for `@absolutejs/auth`.

AbsoluteJS provisions this package automatically for `mobile.engine: 'expo'` applications that depend on `@absolutejs/auth`. It connects the existing native OAuth client to Expo WebBrowser, Linking, SecureStore, and AppState while keeping access and refresh credentials outside embedded WebViews.

Application code continues to use `@absolutejs/auth/client`; it does not import this adapter directly.

The package is experimental while AbsoluteJS Expo support remains experimental.
