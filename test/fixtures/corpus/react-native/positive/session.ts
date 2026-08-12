declare const webView: { javaScriptEnabled: boolean };
declare const AsyncStorage: { setItem(name: string, value: string): Promise<void> };
declare const accessToken: string;

webView.javaScriptEnabled = true;
export const apiEndpoint = "http://api.aisec.invalid/v1";
await AsyncStorage.setItem("accessToken", accessToken);
