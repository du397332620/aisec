import type { Detector } from "./types.js";
import { createSignal, makeLocation } from "../core/utils.js";
import type { Signal } from "../schema.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";

const SOURCE_EXT = /\.(?:js|jsx|ts|tsx|dart|java|kt|swift|m|mm)$/;

export const platformDetector: Detector = {
  name: "native-platform",
  async run(context) {
    const started = Date.now();
    const signals: Signal[] = [];
    let truncated = false;
    const add = (signal: Signal): boolean => {
      if (signals.length >= MAX_SIGNALS_PER_DETECTOR) { truncated = true; return false; }
      signals.push(signal);
      return true;
    };
    for (const file of context.inventory.files) {
      if (truncated) break;
      if (/AndroidManifest\.xml$/.test(file.relativePath)) {
        const cleartext = /android:usesCleartextTraffic\s*=\s*["']true["']/g;
        for (const match of file.content.matchAll(cleartext)) {
          if (!add(createSignal({
            engine: "aisec-native", ruleId: "android.cleartext-enabled", title: "Android application permits cleartext network traffic",
            description: "The manifest enables cleartext HTTP traffic for the application.", severity: "high", evidenceLevel: "static_confirmed", confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])], cwe: ["CWE-319"], owasp: ["M5"], tags: ["android", "network"],
            remediation: "Disable cleartext traffic and use a narrowly scoped Network Security Configuration only for unavoidable development endpoints.",
          }))) break;
        }
        const backup = /android:allowBackup\s*=\s*["']true["']/g;
        for (const match of truncated ? [] : file.content.matchAll(backup)) {
          if (!add(createSignal({
            engine: "aisec-native", ruleId: "android.backup-enabled", title: "Android application data backup is enabled",
            description: "Application data may be included in device or cloud backups unless later platform controls exclude it.", severity: "medium", evidenceLevel: "static_confirmed", confidence: "medium",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])], cwe: ["CWE-200"], owasp: ["M9"], tags: ["android", "storage"],
            remediation: "Disable backup for sensitive applications or provide explicit data extraction rules that exclude credentials and private records.",
          }))) break;
        }
      }

      if (/Info\.plist$/.test(file.relativePath)) {
        const ats = /<key>NSAllowsArbitraryLoads<\/key>\s*<true\s*\/>/g;
        for (const match of truncated ? [] : file.content.matchAll(ats)) {
          if (!add(createSignal({
            engine: "aisec-native", ruleId: "ios.ats-disabled", title: "iOS App Transport Security is globally disabled",
            description: "NSAllowsArbitraryLoads permits insecure transport across the application.", severity: "high", evidenceLevel: "static_confirmed", confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])], cwe: ["CWE-319"], owasp: ["M5"], tags: ["ios", "network"],
            remediation: "Remove the global exception and use HTTPS; if necessary, add narrowly scoped domain exceptions with documented justification.",
          }))) break;
        }
      }

      if (SOURCE_EXT.test(file.relativePath)) {
        const webviewBridge = /(?:addJavascriptInterface\s*\(|javaScriptEnabled\s*=\s*true|setJavaScriptEnabled\s*\(\s*true\s*\))/g;
        for (const match of truncated ? [] : file.content.matchAll(webviewBridge)) {
          if (!add(createSignal({
            engine: "aisec-native", ruleId: "mobile.webview-javascript-bridge", title: "Mobile WebView enables an elevated JavaScript capability",
            description: "JavaScript or a native bridge is enabled. If navigation is not restricted, untrusted content may reach native capabilities.", severity: "medium", evidenceLevel: "inferred", confidence: "medium",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])], cwe: ["CWE-749"], owasp: ["M1"], tags: ["mobile", "webview"],
            remediation: "Allowlist HTTPS origins, block external navigation, expose the smallest possible bridge and validate every message schema and origin.",
          }))) break;
        }

        const insecureHttp = /["'`]http:\/\/(?!localhost\b|127\.0\.0\.1\b|10\.0\.2\.2\b|example\.(?:com|org)\b)[^"'`\s]+/g;
        for (const match of truncated ? [] : file.content.matchAll(insecureHttp)) {
          if (!add(createSignal({
            engine: "aisec-native", ruleId: "mobile.insecure-http-endpoint", title: "Mobile source references a cleartext HTTP endpoint",
            description: "Traffic to this endpoint can be observed or modified by a network attacker.", severity: "high", evidenceLevel: "static_confirmed", confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])], cwe: ["CWE-319"], owasp: ["M5"], tags: ["mobile", "network"],
            remediation: "Use HTTPS with valid certificate verification and remove production fallbacks to cleartext endpoints.",
          }))) break;
        }

        const asyncSensitive = /AsyncStorage\.setItem\s*\(\s*["'`](?:token|accessToken|refreshToken|password|secret|privateKey)["'`]/gi;
        for (const match of truncated ? [] : file.content.matchAll(asyncSensitive)) {
          if (!add(createSignal({
            engine: "aisec-native", ruleId: "react-native.sensitive-async-storage", title: "Sensitive value stored in React Native AsyncStorage",
            description: "AsyncStorage is not a secure credential vault and its contents may be exposed on a compromised or backed-up device.", severity: "high", evidenceLevel: "static_confirmed", confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])], cwe: ["CWE-922"], owasp: ["M9"], tags: ["react-native", "storage", "credential"],
            remediation: "Store credentials in Keychain/Keystore-backed secure storage and keep access tokens short-lived.",
          }))) break;
        }

        const flutterPreferences = /(?:SharedPreferences|prefs?|preferences)\.setString\s*\(\s*["'](?:token|accessToken|refreshToken|password|secret|privateKey)["']/gi;
        for (const match of truncated ? [] : file.content.matchAll(flutterPreferences)) {
          if (!add(createSignal({
            engine: "aisec-native", ruleId: "flutter.sensitive-shared-preferences", title: "Sensitive value stored in Flutter SharedPreferences",
            description: "SharedPreferences is intended for ordinary preferences, not credential storage.", severity: "high", evidenceLevel: "static_confirmed", confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])], cwe: ["CWE-922"], owasp: ["M9"], tags: ["flutter", "storage", "credential"],
            remediation: "Use platform Keychain/Keystore-backed secure storage and keep tokens short-lived and revocable.",
          }))) break;
        }

        const flutterWebview = /(?:javaScriptMode\s*:|setJavaScriptMode\s*\()\s*JavaScriptMode\.unrestricted/g;
        for (const match of truncated ? [] : file.content.matchAll(flutterWebview)) {
          if (!add(createSignal({
            engine: "aisec-native", ruleId: "flutter.webview-unrestricted-javascript", title: "Flutter WebView enables unrestricted JavaScript",
            description: "Unrestricted JavaScript increases the impact of loading or navigating to untrusted content.", severity: "medium", evidenceLevel: "inferred", confidence: "medium",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])], cwe: ["CWE-749"], owasp: ["M1"], tags: ["flutter", "webview"],
            remediation: "Disable JavaScript where possible; otherwise allowlist HTTPS origins, block external navigation and strictly validate bridge messages.",
          }))) break;
        }

        const badCertificate = /badCertificateCallback\s*=\s*(?:\([^)]*\)|[^=;]+)=>\s*true|badCertificateCallback[\s\S]{0,160}?return\s+true\s*;/g;
        for (const match of truncated ? [] : file.content.matchAll(badCertificate)) {
          if (!add(createSignal({
            engine: "aisec-native", ruleId: "flutter.accept-all-certificates", title: "Flutter networking accepts invalid TLS certificates",
            description: "The certificate callback returns true unconditionally, disabling server identity verification.", severity: "critical", evidenceLevel: "static_confirmed", confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])], cwe: ["CWE-295"], owasp: ["M5"], tags: ["flutter", "tls", "network"],
            remediation: "Remove the callback and rely on platform trust validation; use a development-only trust store rather than accepting every certificate.",
          }))) break;
        }
      }
    }

    const relevant = context.profile.mobilePlatforms.length > 0;
    return {
      signals,
      coverage: {
        domain: "mobile-source-config",
        engine: "aisec-native",
        status: relevant ? (truncated ? "partial" : "complete") : "not_run",
        required: relevant,
        reason: relevant ? (truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined) : "No supported mobile project detected",
        durationMs: Date.now() - started,
      },
    };
  },
};
