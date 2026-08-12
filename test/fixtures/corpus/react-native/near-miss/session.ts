declare const webView: { javaScriptEnabled: boolean };
declare const SecureStore: { setItemAsync(name: string, value: string): Promise<void> };
declare const accessToken: string;

webView.javaScriptEnabled = false;
export const apiEndpoint = "https://api.example.test/v1";
await SecureStore.setItemAsync("accessToken", accessToken);
