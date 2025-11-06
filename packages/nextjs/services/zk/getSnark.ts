let cached: any | null = null;

export async function getSnark() {
  if (cached) return cached;
  cached = await import("snarkjs");
  return cached;
}
