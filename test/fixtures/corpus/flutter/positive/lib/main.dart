void configure(dynamic prefs, dynamic controller, dynamic client, String token) {
  prefs.setString('token', token);
  controller.setJavaScriptMode(JavaScriptMode.unrestricted);
  client.badCertificateCallback = (certificate, host, port) => true;
}
