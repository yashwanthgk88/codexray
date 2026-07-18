/**
 * Provider-neutral AI client. Raw HTTP (no bundled SDK) so CodeXray stays
 * genuinely provider-agnostic and the .vsix stays small.
 *
 * Supported providers:
 *   - "anthropic": POST {base}/v1/messages                         (Claude)
 *   - "openai":    POST {base}/chat/completions  + Bearer          (OpenAI + compatible)
 *   - "azure":     POST {base}/openai/deployments/{model}/chat/completions?api-version=..
 *                  + api-key header                                 (Azure OpenAI)
 *   - "ollama":    POST {base}/chat/completions  (no key required)  (local models)
 */
import * as vscode from "vscode";

export type Provider = "anthropic" | "openai" | "azure" | "ollama";

export interface AiConfig {
  provider: Provider;
  model: string;
  baseUrl: string;
  maxTokens: number;
  azureApiVersion: string;
}

const DEFAULT_BASE: Record<Provider, string> = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com/v1",
  azure: "", // must be set by the user (https://<resource>.openai.azure.com)
  ollama: "http://localhost:11434/v1",
};

const ENV_KEY: Record<Provider, string> = {
  anthropic: "ANTHROPIC_API_KEY",
  openai: "OPENAI_API_KEY",
  azure: "AZURE_OPENAI_API_KEY",
  ollama: "", // local — no key
};

/** Ollama / local models don't require an API key. */
export const keyRequired = (p: Provider): boolean => p !== "ollama";

export function getAiConfig(): AiConfig {
  const c = vscode.workspace.getConfiguration("codexray.ai");
  const provider = (c.get<string>("provider") || "anthropic") as Provider;
  const base = (c.get<string>("baseUrl") || "").trim() || DEFAULT_BASE[provider];
  return {
    provider,
    model: c.get<string>("model") || "claude-opus-4-8",
    baseUrl: base.replace(/\/+$/, ""),
    maxTokens: c.get<number>("maxTokens") || 1024,
    azureApiVersion: (c.get<string>("azureApiVersion") || "2024-06-01").trim(),
  };
}

export const secretKeyId = (provider: string) => `codexray.ai.key.${provider}`;

/** Resolve the API key: SecretStorage first, then the provider's env var. */
export async function getApiKey(
  context: vscode.ExtensionContext,
  provider: Provider
): Promise<string | undefined> {
  const fromSecret = await context.secrets.get(secretKeyId(provider));
  if (fromSecret) return fromSecret;
  const env = ENV_KEY[provider];
  return env ? process.env[env] : undefined;
}

export function envKeyName(provider: Provider): string {
  return ENV_KEY[provider] || "(no key needed)";
}

/** Call the configured provider and return the assistant's text. Throws on error. */
export async function callProvider(
  cfg: AiConfig,
  apiKey: string,
  system: string,
  user: string
): Promise<string> {
  switch (cfg.provider) {
    case "anthropic":
      return callAnthropic(cfg, apiKey, system, user);
    case "azure":
      return callAzure(cfg, apiKey, system, user);
    case "openai":
    case "ollama":
      return callOpenAI(cfg, apiKey, system, user);
  }
}

async function callAnthropic(cfg: AiConfig, apiKey: string, system: string, user: string): Promise<string> {
  const res = await fetch(`${cfg.baseUrl}/v1/messages`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: cfg.model,
      max_tokens: cfg.maxTokens,
      system,
      messages: [{ role: "user", content: user }],
    }),
  });
  if (!res.ok) throw new Error(`Anthropic ${res.status}: ${(await res.text()).slice(0, 400)}`);
  const data: any = await res.json();
  const text = (data.content || [])
    .filter((b: any) => b && b.type === "text")
    .map((b: any) => b.text)
    .join("");
  if (!text) throw new Error("Empty response from Anthropic.");
  return text;
}

/** OpenAI and any OpenAI-compatible endpoint (incl. Ollama, OpenRouter, LM Studio). */
async function callOpenAI(cfg: AiConfig, apiKey: string, system: string, user: string): Promise<string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (apiKey) headers["authorization"] = `Bearer ${apiKey}`; // Ollama needs none
  const res = await fetch(`${cfg.baseUrl}/chat/completions`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model: cfg.model,
      max_tokens: cfg.maxTokens,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
    }),
  });
  if (!res.ok) throw new Error(`Provider ${res.status}: ${(await res.text()).slice(0, 400)}`);
  const data: any = await res.json();
  const text = data.choices?.[0]?.message?.content ?? "";
  if (!text) throw new Error("Empty response from provider.");
  return text;
}

/** Azure OpenAI — deployment in the path, api-key header, api-version query. */
async function callAzure(cfg: AiConfig, apiKey: string, system: string, user: string): Promise<string> {
  if (!cfg.baseUrl) {
    throw new Error("Azure: set codexray.ai.baseUrl to https://<resource>.openai.azure.com");
  }
  const url =
    `${cfg.baseUrl}/openai/deployments/${encodeURIComponent(cfg.model)}` +
    `/chat/completions?api-version=${encodeURIComponent(cfg.azureApiVersion)}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", "api-key": apiKey },
    body: JSON.stringify({
      max_tokens: cfg.maxTokens,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
    }),
  });
  if (!res.ok) throw new Error(`Azure ${res.status}: ${(await res.text()).slice(0, 400)}`);
  const data: any = await res.json();
  const text = data.choices?.[0]?.message?.content ?? "";
  if (!text) throw new Error("Empty response from Azure.");
  return text;
}
