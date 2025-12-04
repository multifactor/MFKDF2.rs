
// Helper to convert Buffer/Uint8Array to ArrayBuffer for UniFFI
function toArrayBuffer(input: ArrayBuffer | Buffer | Uint8Array | undefined): ArrayBuffer | undefined {
  if (input === undefined) return undefined;
  if (input instanceof ArrayBuffer) return input;
  // Buffer and Uint8Array have .buffer property, but may be a view with offset
  const view = input as Uint8Array;
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}

// Helper to deep parse JSON strings
function deepParse(value: any): any {
  if (typeof value === 'string') {
    try {
      return deepParse(JSON.parse(value));
    } catch {
      return value;
    }
  }

  if (Array.isArray(value)) {
    return value.map(deepParse);
  }

  if (value && typeof value === 'object') {
    const parsed: any = {};
    for (const [key, nested] of Object.entries(value)) {
      parsed[key] = deepParse(nested);
    }
    return parsed;
  }

  return value;
}

// Helper to stringify policy/factor params/outputs
function stringifyFactorParams(value: any): any {
  if (value === undefined || value === null || typeof value === 'string') {
    return value;
  }

  const POLICY_ORDER = ['$id', '$schema', 'factors', 'key', 'memory', 'salt', 'threshold', 'time'];
  const FACTOR_ORDER = ['id', 'pad', 'params', 'salt', 'secret', 'type', 'hint'];

  const stringifyPolicy = (input: any): string => JSON.stringify(orderValue(input, 'policy'));

  function orderValue(input: any, context?: 'policy' | 'factor'): any {
    if (Array.isArray(input)) {
      if (context === 'policy') {
        return input.map((item) => orderValue(item, 'factor'));
      }
      return input.map((item) => orderValue(item));
    }

    if (input && typeof input === 'object') {
      const baseOrder = context === 'policy' ? POLICY_ORDER : context === 'factor' ? FACTOR_ORDER : [];
      const extras = Object.keys(input).filter((key) => !baseOrder.includes(key)).sort();
      const keys = [...baseOrder, ...extras];
      const ordered: any = {};

      for (const key of keys) {
        if (!(key in input)) continue;

        if (context === 'factor' && key === 'params') {
          ordered.params = input[key];
          continue;
        }

        if (key === 'factors' && Array.isArray(input[key])) {
          ordered.factors = input[key].map((item: any) => orderValue(item, 'factor'));
          continue;
        }

        ordered[key] = orderValue(input[key]);
      }

      return ordered;
    }

    return input;
  }

  return stringifyPolicy(value);
}

export {
  toArrayBuffer,
  deepParse,
  stringifyFactorParams,
};