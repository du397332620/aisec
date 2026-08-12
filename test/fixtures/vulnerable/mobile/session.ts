import AsyncStorage from "@react-native-async-storage/async-storage";

export async function saveSession(refreshToken: string) {
  await AsyncStorage.setItem("refreshToken", refreshToken);
  return fetch("http://api.production.invalid/session");
}
