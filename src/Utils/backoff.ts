export async function withBackoff<T>(fn: () => Promise<T>, attempts = 3): Promise<T> {
  let delay = 250;
  let lastErr: any;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err: any) {
      lastErr = err;
      const status = err?.response?.status || err?.statusCode;
      if (status && status < 500 && status !== 429) throw err;
      await new Promise((r) => setTimeout(r, delay));
      delay *= 2;
    }
  }
  throw lastErr;
}


