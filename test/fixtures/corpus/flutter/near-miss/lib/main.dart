void configure(dynamic secureStorage, dynamic controller, dynamic client, String token) {
  secureStorage.write(key: 'token', value: token);
  controller.setJavaScriptMode(JavaScriptMode.disabled);
  client.badCertificateCallback = (certificate, host, port) => false;
}
